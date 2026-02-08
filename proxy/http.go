package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/snail007/goproxy/auth"
	"github.com/snail007/goproxy/config"
	"github.com/snail007/goproxy/traffic"
	"github.com/snail007/goproxy/transport"
	"github.com/snail007/goproxy/utils"
)

// HTTPHandler implements HTTP and HTTPS proxy protocol
type HTTPHandler struct {
	cfg      config.HTTPConfig
	auth     auth.Authenticator
	reporter traffic.Reporter
	dialer   *transport.Dialer
	checker  utils.Checker
	outPool  *transport.Pool
}

// NewHTTPHandler creates a new HTTP proxy handler
func NewHTTPHandler(cfg config.HTTPConfig, authenticator auth.Authenticator, reporter traffic.Reporter) (*HTTPHandler, error) {
	dialer := transport.NewDialer(cfg.UpstreamConfig.Timeout)

	h := &HTTPHandler{
		cfg:      cfg,
		auth:     authenticator,
		reporter: reporter,
		dialer:   dialer,
	}

	// Initialize domain checker if parent proxy is configured
	if cfg.UpstreamConfig.Parent != "" {
		h.checker = utils.NewChecker(int(cfg.HTTPTimeout.Milliseconds()), int64(cfg.Interval.Seconds()), cfg.Blocked, cfg.Direct)
	}

	// Initialize connection pool if configured
	if cfg.UpstreamConfig.PoolSize > 0 && cfg.UpstreamConfig.Parent != "" {
		var certBytes, keyBytes []byte
		if cfg.ServerConfig.TLS != nil {
			certBytes = cfg.ServerConfig.TLS.CertBytes
			keyBytes = cfg.ServerConfig.TLS.KeyBytes
		}

		pool, err := transport.NewPool(transport.PoolConfig{
			Factory: func() (net.Conn, error) {
				if cfg.UpstreamConfig.ParentType == "tls" {
					return dialer.ConnectTLS(cfg.UpstreamConfig.Parent, certBytes, keyBytes)
				}
				return dialer.Connect(cfg.UpstreamConfig.Parent)
			},
			IsActive: func(conn net.Conn) bool { return true },
			Release: func(conn net.Conn) {
				conn.SetDeadline(time.Now().Add(time.Millisecond))
				conn.Close()
			},
			InitialCap: cfg.UpstreamConfig.PoolSize,
			MaxCap:     cfg.UpstreamConfig.PoolSize * 2,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create connection pool: %w", err)
		}
		h.outPool = pool
	}

	return h, nil
}

// Protocol returns the handler protocol name
func (h *HTTPHandler) Protocol() string {
	return "http"
}

// SupportsAuth returns true for HTTP proxy
func (h *HTTPHandler) SupportsAuth() bool {
	return true
}

// HandleConnection processes HTTP/HTTPS proxy requests
func (h *HTTPHandler) HandleConnection(ctx context.Context, conn net.Conn) {
	// Set read deadline for header parsing (slowloris protection)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Parse HTTP request - don't use built-in auth (we handle auth separately)
	req, err := utils.NewHTTPRequest(&conn, 4096, false, nil, "", nil, nil, h.cfg.Debug)
	if err != nil {
		if h.cfg.Debug {
			log.Printf("HTTP decode error from %s: %v", conn.RemoteAddr(), err)
		}
		conn.Close()
		return
	}

	// Clear deadline after successful parsing
	conn.SetReadDeadline(time.Time{})

	// Handle authentication if configured
	var user string
	if h.auth != nil {
		result, err := h.authenticate(conn, req)
		if err != nil || !result.OK {
			return
		}
		user = result.User
		if result.Upstream != "" {
			req.Upstream = result.Upstream
		}
	}

	// Determine if we should use parent proxy
	useProxy := h.shouldUseProxy(req.Host)

	// Forward the connection
	h.forward(conn, req, useProxy, user)
}

// authenticate performs HTTP Basic Auth using the configured Authenticator
func (h *HTTPHandler) authenticate(conn net.Conn, req utils.HTTPRequest) (auth.Result, error) {
	// Try Proxy-Authorization first (standard for proxy), then Authorization
	authorization, err := req.GetHeader("Proxy-Authorization")
	if err != nil {
		authorization, err = req.GetHeader("Authorization")
		if err != nil {
			fmt.Fprint(conn, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"\"\r\n\r\nUnauthorized")
			conn.Close()
			return auth.Result{OK: false}, err
		}
	}

	// Parse Basic auth header
	user, pass, ok := auth.ParseBasicAuthHeader(authorization)
	if !ok {
		fmt.Fprint(conn, "HTTP/1.1 401 Unauthorized\r\n\r\nInvalid auth header")
		conn.Close()
		return auth.Result{OK: false}, fmt.Errorf("invalid auth header")
	}

	// Authenticate using the configured authenticator
	clientIP := conn.RemoteAddr().String()
	localIP := conn.LocalAddr().String()

	result, err := h.auth.Authenticate(context.Background(), auth.Credentials{
		User:     user,
		Pass:     pass,
		ClientIP: clientIP,
		LocalIP:  localIP,
		Target:   req.Host,
	})

	if err != nil || !result.OK {
		fmt.Fprint(conn, "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized")
		conn.Close()
		return auth.Result{OK: false}, err
	}

	return result, nil
}

// shouldUseProxy determines if parent proxy should be used
func (h *HTTPHandler) shouldUseProxy(address string) bool {
	if h.cfg.UpstreamConfig.Parent == "" {
		return false
	}
	if h.cfg.UpstreamConfig.AlwaysProxy {
		return true
	}

	// Use checker for smart routing
	blocked, _, _ := h.checker.IsBlocked(address)
	return blocked
}

// forward establishes the connection and binds I/O
func (h *HTTPHandler) forward(inConn net.Conn, req utils.HTTPRequest, useProxy bool, user string) {
	address := req.Host

	// Check for dead loop
	if h.isDeadLoop(inConn.LocalAddr().String(), address) {
		log.Printf("dead loop detected for %s", address)
		return
	}

	// Get target connection
	var outConn net.Conn
	var err error

	if req.Upstream != "" {
		// Connect via upstream proxy from auth API
		outConn, err = h.connectViaUpstream(&req)
	} else if useProxy && h.outPool != nil {
		outConn, err = h.outPool.Get()
	} else {
		outConn, err = h.dialer.Connect(address)
	}

	if err != nil {
		log.Printf("connect to %s failed: %v", address, err)
		inConn.Close()
		return
	}
	// Note: outConn will be closed by IoBind callback

	// Get connection addresses for traffic reporting
	serverAddr := inConn.LocalAddr().String()
	clientAddr := inConn.RemoteAddr().String()
	var outLocalAddr, outRemoteAddr string
	if outConn != nil {
		outLocalAddr = outConn.LocalAddr().String()
		outRemoteAddr = outConn.RemoteAddr().String()
	}

	// Send appropriate response based on upstream/direct and HTTP/HTTPS
	if req.Upstream != "" {
		if req.IsHTTPS() {
			// For HTTPS via upstream: CONNECT already sent in connectViaUpstream
			fmt.Fprint(inConn, "HTTP/1.1 200 Connection established\r\n\r\n")
		} else {
			// For HTTP via upstream: forward modified request (HeadBuf already updated)
			outConn.Write(req.HeadBuf)
		}
	} else if req.IsHTTPS() {
		fmt.Fprint(inConn, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		outConn.Write(req.HeadBuf)
	}

	// Create traffic session if reporter is configured
	var session *traffic.Session
	var stopPeriodic func()
	if h.reporter != nil {
		session = traffic.NewSession(
			h.Protocol(),
			serverAddr,
			clientAddr,
			address,
			user,
			outLocalAddr,
			outRemoteAddr,
			req.Upstream,
			"", // sniff_domain - not implemented in this handler
		)
		// Start periodic reporting if in fast mode
		stopPeriodic = h.reporter.StartPeriodic(session)
	}

	// Bind I/O with traffic counting
	utils.IoBind(inConn, outConn, func(isSrcErr bool, err error) {
		// Connection closed - close both connections
		inConn.Close()
		outConn.Close()
		if h.cfg.Debug {
			log.Printf("connection released: %s", address)
		}
		// Stop periodic reporting and send final report
		if stopPeriodic != nil {
			stopPeriodic()
		}
		// For normal mode, explicitly send the report (fast mode already sends in stopPeriodic)
		if h.reporter != nil && h.reporter.Mode() == "normal" {
			h.reporter.Report(session)
		}
	}, func(n int, isOut bool) {
		if session != nil {
			session.AddBytes(int64(n))
		}
	}, 0)
}

// connectViaUpstream connects through an upstream proxy
func (h *HTTPHandler) connectViaUpstream(req *utils.HTTPRequest) (net.Conn, error) {
	upstreamURL, err := url.Parse(req.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	upstreamAddr := upstreamURL.Host
	if !strings.Contains(upstreamAddr, ":") {
		upstreamAddr += ":80"
	}

	// Build upstream Proxy-Authorization header
	var upstreamAuthHeader string
	if upstreamURL.User != nil {
		upstreamUser := upstreamURL.User.Username()
		upstreamPass, _ := upstreamURL.User.Password()
		upstreamAuth := base64.StdEncoding.EncodeToString([]byte(upstreamUser + ":" + upstreamPass))
		upstreamAuthHeader = "Proxy-Authorization: Basic " + upstreamAuth
	}

	// Connect to upstream proxy
	outConn, err := h.dialer.Connect(upstreamAddr)
	if err != nil {
		return nil, err
	}
	if h.cfg.Debug {
		log.Printf("connected to upstream proxy %s", upstreamAddr)
	}

	if req.IsHTTPS() {
		// For HTTPS: send CONNECT to upstream proxy
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", req.Host, req.Host)
		if upstreamAuthHeader != "" {
			connectReq += upstreamAuthHeader + "\r\n"
		}
		connectReq += "\r\n"
		_, err = outConn.Write([]byte(connectReq))
		if err != nil {
			outConn.Close()
			return nil, err
		}
		// Read upstream response
		reader := bufio.NewReader(outConn)
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			outConn.Close()
			return nil, fmt.Errorf("upstream CONNECT read error: %w", readErr)
		}
		if !strings.Contains(line, "200") {
			outConn.Close()
			return nil, fmt.Errorf("upstream CONNECT rejected: %s", strings.TrimSpace(line))
		}
		// Drain remaining headers
		for {
			line, readErr = reader.ReadString('\n')
			if readErr != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		// Wrap conn with buffered reader so read-ahead bytes are not lost
		outConn = utils.NewBufferedConn(outConn, reader)
	} else {
		// For HTTP: modify HeadBuf - replace client auth with upstream auth
		buf := req.HeadBuf

		// Remove existing Proxy-Authorization header
		proxyAuthKey := []byte("proxy-authorization:")
		lowerBuf := bytes.ToLower(buf)
		if idx := bytes.Index(lowerBuf, proxyAuthKey); idx >= 0 {
			endIdx := bytes.Index(buf[idx:], []byte("\r\n"))
			if endIdx >= 0 {
				buf = append(buf[:idx], buf[idx+endIdx+2:]...)
			}
		}

		// Insert upstream auth header before end of headers
		if upstreamAuthHeader != "" {
			headerEnd := []byte("\r\n\r\n")
			if idx := bytes.Index(buf, headerEnd); idx >= 0 {
				insertion := []byte(upstreamAuthHeader + "\r\n")
				newBuf := make([]byte, 0, len(buf)+len(insertion))
				newBuf = append(newBuf, buf[:idx+2]...)
				newBuf = append(newBuf, insertion...)
				newBuf = append(newBuf, buf[idx+2:]...)
				buf = newBuf
			}
		}

		req.HeadBuf = buf
	}
	return outConn, nil
}

// isDeadLoop checks if this would create a routing loop
func (h *HTTPHandler) isDeadLoop(inLocalAddr string, host string) bool {
	inIP, inPort, err := net.SplitHostPort(inLocalAddr)
	if err != nil {
		return false
	}

	outDomain, outPort, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}

	if inPort == outPort {
		outIPs, err := net.LookupIP(outDomain)
		if err == nil {
			for _, ip := range outIPs {
				if ip.String() == inIP {
					return true
				}
			}
		}
	}

	return false
}

// parseAddress extracts host and port
func parseAddress(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, _ = strconv.Atoi(p)
	return h, port, nil
}
