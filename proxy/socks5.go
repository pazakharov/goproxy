package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/snail007/goproxy/auth"
	"github.com/snail007/goproxy/config"
	"github.com/snail007/goproxy/traffic"
	"github.com/snail007/goproxy/transport"
	"github.com/snail007/goproxy/utils"
)

// SOCKS5Handler implements SOCKS5 proxy protocol (RFC 1928)
type SOCKS5Handler struct {
	cfg      config.SOCKS5Config
	auth     auth.Authenticator
	reporter traffic.Reporter
	dialer   *transport.Dialer
	outPool  *transport.Pool
}

// SOCKS5 constants
const (
	socks5Version byte = 0x05

	// Auth methods
	authNone     byte = 0x00
	authGSSAPI   byte = 0x01
	authPassword byte = 0x02
	authNoAccept byte = 0xFF

	// Commands
	cmdConnect      byte = 0x01
	cmdBind         byte = 0x02
	cmdUDPAssociate byte = 0x03

	// Address types
	addrIPv4   byte = 0x01
	addrDomain byte = 0x03
	addrIPv6   byte = 0x04

	// Reply codes
	replySuccess            byte = 0x00
	replyGeneralFailure     byte = 0x01
	replyNotAllowed         byte = 0x02
	replyNetworkUnreachable byte = 0x03
	replyHostUnreachable    byte = 0x04
	replyConnRefused        byte = 0x05
	replyTTLExpired         byte = 0x06
	replyCmdNotSupported    byte = 0x07
	replyAddrNotSupported   byte = 0x08
)

// NewSOCKS5Handler creates a new SOCKS5 proxy handler
func NewSOCKS5Handler(cfg config.SOCKS5Config, authenticator auth.Authenticator, reporter traffic.Reporter) (*SOCKS5Handler, error) {
	dialer := transport.NewDialer(cfg.UpstreamConfig.Timeout)

	h := &SOCKS5Handler{
		cfg:      cfg,
		auth:     authenticator,
		reporter: reporter,
		dialer:   dialer,
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
func (h *SOCKS5Handler) Protocol() string {
	return "socks5"
}

// SupportsAuth returns true for SOCKS5
func (h *SOCKS5Handler) SupportsAuth() bool {
	return true
}

// HandleConnection processes SOCKS5 proxy requests
func (h *SOCKS5Handler) HandleConnection(ctx context.Context, conn net.Conn) {
	// Note: conn is closed by IoBind callback in handleConnect, or explicitly on error paths

	// Set initial read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 1. Version identification / method selection
	var buf [256]byte
	n, err := io.ReadFull(conn, buf[:2])
	if err != nil || n != 2 {
		conn.Close()
		return
	}

	version := buf[0]
	if version != socks5Version {
		conn.Close()
		return
	}

	nmethods := int(buf[1])
	if nmethods > len(buf)-2 {
		conn.Close()
		return
	}

	n, err = io.ReadFull(conn, buf[2:2+nmethods])
	if err != nil || n != nmethods {
		conn.Close()
		return
	}

	methods := buf[2 : 2+nmethods]

	// Select auth method
	var selectedMethod byte = authNone
	if h.auth != nil {
		// Check if password auth is supported
		for _, m := range methods {
			if m == authPassword {
				selectedMethod = authPassword
				break
			}
		}
		if selectedMethod != authPassword {
			// Try no auth if client supports it (will fail later if auth required)
			for _, m := range methods {
				if m == authNone {
					selectedMethod = authNone
					break
				}
			}
		}
		if selectedMethod == authNone && h.auth != nil {
			// Auth required but client doesn't support password auth
			selectedMethod = authNoAccept
		}
	} else {
		// Check if no-auth is supported
		hasNoAuth := false
		for _, m := range methods {
			if m == authNone {
				hasNoAuth = true
				break
			}
		}
		if !hasNoAuth {
			selectedMethod = authNoAccept
		}
	}

	// Send method selection
	conn.Write([]byte{socks5Version, selectedMethod})

	if selectedMethod == authNoAccept {
		conn.Close()
		return
	}

	// Clear deadline after handshake
	conn.SetReadDeadline(time.Time{})

	// 2. Authenticate if required
	var user string
	var upstream string
	if selectedMethod == authPassword {
		var authResult auth.Result
		authResult, err = h.handlePasswordAuth(conn)
		if err != nil {
			conn.Close()
			return
		}
		user = authResult.User
		upstream = authResult.Upstream
	}

	// 3. Handle request
	h.handleRequest(conn, user, upstream)
}

// handlePasswordAuth handles username/password authentication (RFC 1929)
func (h *SOCKS5Handler) handlePasswordAuth(conn net.Conn) (auth.Result, error) {
	var buf [512]byte

	// Read auth version and lengths
	n, err := io.ReadFull(conn, buf[:2])
	if err != nil || n != 2 {
		return auth.Result{}, err
	}

	authVer := buf[0]
	if authVer != 0x01 {
		return auth.Result{}, fmt.Errorf("unsupported auth version: %d", authVer)
	}

	ulen := int(buf[1])
	if ulen > len(buf)-2 {
		return auth.Result{}, fmt.Errorf("username too long")
	}

	// Read username
	n, err = io.ReadFull(conn, buf[2:2+ulen])
	if err != nil || n != ulen {
		return auth.Result{}, err
	}
	username := string(buf[2 : 2+ulen])

	// Read password length
	n, err = io.ReadFull(conn, buf[2+ulen:3+ulen])
	if err != nil || n != 1 {
		return auth.Result{}, err
	}

	plen := int(buf[2+ulen])
	if plen > len(buf)-3-ulen {
		return auth.Result{}, fmt.Errorf("password too long")
	}

	// Read password
	n, err = io.ReadFull(conn, buf[3+ulen:3+ulen+plen])
	if err != nil || n != plen {
		return auth.Result{}, err
	}
	password := string(buf[3+ulen : 3+ulen+plen])

	// Authenticate
	if h.auth != nil {
		result, err := h.auth.Authenticate(context.Background(), auth.Credentials{
			User: username,
			Pass: password,
		})
		if err != nil || !result.OK {
			// Auth failed
			conn.Write([]byte{0x01, 0x01}) // version=1, status=1 (failure)
			return auth.Result{}, fmt.Errorf("authentication failed")
		}

		// Auth success
		conn.Write([]byte{0x01, 0x00}) // version=1, status=0 (success)
		return result, nil
	}

	// No auth configured, accept any
	conn.Write([]byte{0x01, 0x00})
	return auth.Result{OK: true, User: username}, nil
}

// handleRequest processes SOCKS5 requests
func (h *SOCKS5Handler) handleRequest(conn net.Conn, user string, upstream string) {
	var buf [512]byte

	// Read request header
	n, err := io.ReadFull(conn, buf[:4])
	if err != nil || n != 4 {
		return
	}

	version := buf[0]
	cmd := buf[1]
	// rsv := buf[2] // reserved
	atyp := buf[3]

	if version != socks5Version {
		return
	}

	// Read destination address
	var addr string
	switch atyp {
	case addrIPv4:
		n, err = io.ReadFull(conn, buf[4:8])
		if err != nil || n != 4 {
			return
		}
		addr = net.IP(buf[4:8]).String()

	case addrDomain:
		n, err = io.ReadFull(conn, buf[4:5])
		if err != nil || n != 1 {
			return
		}
		domainLen := int(buf[4])
		n, err = io.ReadFull(conn, buf[5:5+domainLen])
		if err != nil || n != domainLen {
			return
		}
		addr = string(buf[5 : 5+domainLen])

	case addrIPv6:
		n, err = io.ReadFull(conn, buf[4:20])
		if err != nil || n != 16 {
			return
		}
		addr = net.IP(buf[4:20]).String()

	default:
		h.sendReply(conn, replyAddrNotSupported, "")
		return
	}

	// Read port
	n, err = io.ReadFull(conn, buf[20:22])
	if err != nil || n != 2 {
		return
	}
	port := binary.BigEndian.Uint16(buf[20:22])

	targetAddr := fmt.Sprintf("%s:%d", addr, port)

	// Handle command
	switch cmd {
	case cmdConnect:
		h.handleConnect(conn, targetAddr, user, upstream)
	default:
		h.sendReply(conn, replyCmdNotSupported, "")
	}
}

// handleConnect handles CONNECT command
func (h *SOCKS5Handler) handleConnect(conn net.Conn, targetAddr string, user string, upstream string) {
	// Get outbound connection
	var outConn net.Conn
	var err error

	if upstream != "" {
		// Connect via upstream proxy from auth API
		outConn, err = h.connectViaUpstream(upstream, targetAddr)
	} else if h.outPool != nil {
		outConn, err = h.outPool.Get()
	} else {
		outConn, err = h.dialer.Connect(targetAddr)
	}

	if err != nil {
		log.Printf("SOCKS5 connect to %s failed: %v", targetAddr, err)
		h.sendReply(conn, replyNetworkUnreachable, "")
		return
	}

	// Get connection addresses for traffic reporting
	serverAddr := conn.LocalAddr().String()
	clientAddr := conn.RemoteAddr().String()
	var outLocalAddr, outRemoteAddr string
	if outConn != nil {
		outLocalAddr = outConn.LocalAddr().String()
		outRemoteAddr = outConn.RemoteAddr().String()
	}

	// Send success reply
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	h.sendReplyWithAddr(conn, replySuccess, localAddr.IP, localAddr.Port)

	if h.cfg.Debug {
		if upstream != "" {
			log.Printf("SOCKS5 %s -> upstream -> %s", user, targetAddr)
		} else {
			log.Printf("SOCKS5 %s -> direct -> %s", user, targetAddr)
		}
	}

	// Create traffic session if reporter is configured
	var session *traffic.Session
	var stopPeriodic func()
	if h.reporter != nil {
		session = traffic.NewSession(
			h.Protocol(),
			serverAddr,
			clientAddr,
			targetAddr,
			user,
			outLocalAddr,
			outRemoteAddr,
			upstream,
			"", // sniff_domain - not implemented in this handler
		)
		// Start periodic reporting if in fast mode
		stopPeriodic = h.reporter.StartPeriodic(session)
	}

	// Bind I/O with traffic counting
	utils.IoBind(conn, outConn, func(isSrcErr bool, err error) {
		conn.Close()
		outConn.Close()
		if h.cfg.Debug {
			log.Printf("SOCKS5 connection released: %s", targetAddr)
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

// connectViaUpstream connects to target through an upstream HTTP proxy using CONNECT
func (h *SOCKS5Handler) connectViaUpstream(upstreamStr string, targetAddr string) (net.Conn, error) {
	upstreamURL, err := url.Parse(upstreamStr)
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
		log.Printf("SOCKS5 connected to upstream proxy %s for target %s", upstreamAddr, targetAddr)
	}

	// Send HTTP CONNECT to upstream proxy
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
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
	return utils.NewBufferedConn(outConn, reader), nil
}

// sendReply sends a SOCKS5 reply without address
func (h *SOCKS5Handler) sendReply(conn net.Conn, code byte, addr string) {
	reply := []byte{socks5Version, code, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}

// sendReplyWithAddr sends a SOCKS5 reply with address
func (h *SOCKS5Handler) sendReplyWithAddr(conn net.Conn, code byte, ip net.IP, port int) {
	atyp := addrIPv4
	if len(ip) == 16 {
		atyp = addrIPv6
	}

	reply := []byte{socks5Version, code, 0x00, atyp}
	reply = append(reply, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	reply = append(reply, portBytes...)
	conn.Write(reply)
}
