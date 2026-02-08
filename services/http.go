package services

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/snail007/goproxy/traffic"
	"github.com/snail007/goproxy/utils"
)

type HTTP struct {
	outPool    utils.OutPool
	cfg        HTTPArgs
	checker    utils.Checker
	basicAuth  utils.BasicAuth
	authClient *http.Client
	authCache  *utils.AuthCache
	connSem    chan struct{} // semaphore for limiting concurrent connections
	reporter   traffic.Reporter
}

func NewHTTP() Service {
	return &HTTP{
		outPool:   utils.OutPool{},
		cfg:       HTTPArgs{},
		checker:   utils.Checker{},
		basicAuth: utils.BasicAuth{},
	}
}
func (s *HTTP) InitService() {
	s.InitBasicAuth()
	if *s.cfg.Parent != "" {
		s.checker = utils.NewChecker(*s.cfg.HTTPTimeout, int64(*s.cfg.Interval), *s.cfg.Blocked, *s.cfg.Direct)
	}
}
func (s *HTTP) StopService() {
	if s.outPool.Pool != nil {
		s.outPool.Pool.ReleaseAll()
	}
}
func (s *HTTP) Start(args interface{}) (err error) {
	s.cfg = args.(HTTPArgs)
	// Initialize connection semaphore if max connections limit is set
	if *s.cfg.MaxConns > 0 {
		s.connSem = make(chan struct{}, *s.cfg.MaxConns)
		log.Printf("max concurrent connections limited to %d", *s.cfg.MaxConns)
	}
	// Initialize traffic reporter if configured
	if *s.cfg.TrafficURL != "" {
		s.reporter = traffic.NewHTTPReporter(
			*s.cfg.TrafficURL,
			*s.cfg.TrafficMode,
			time.Duration(*s.cfg.TrafficInterval)*time.Second,
			*s.cfg.FastGlobal,
		)
		log.Printf("traffic reporter: url=%s, mode=%s", *s.cfg.TrafficURL, *s.cfg.TrafficMode)
	} else {
		s.reporter = traffic.NewNopReporter()
	}

	if *s.cfg.AuthURL != "" {
		s.authClient = &http.Client{
			Timeout: time.Duration(*s.cfg.AuthTimeout) * time.Millisecond,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		}
		log.Printf("auth-url: %s, timeout: %dms", *s.cfg.AuthURL, *s.cfg.AuthTimeout)
		if *s.cfg.AuthCacheTTL > 0 {
			s.authCache = utils.NewAuthCache(*s.cfg.AuthCacheTTL)
			log.Printf("auth cache enabled, TTL: %ds", *s.cfg.AuthCacheTTL)
		}
	}
	if *s.cfg.Parent != "" {
		log.Printf("use %s parent %s", *s.cfg.ParentType, *s.cfg.Parent)
		s.InitOutConnPool()
	}

	s.InitService()

	host, port, _ := net.SplitHostPort(*s.cfg.Local)
	p, _ := strconv.Atoi(port)
	sc := utils.NewServerChannel(host, p)
	if *s.cfg.LocalType == TYPE_TCP {
		err = sc.ListenTCP(s.callback)
	} else {
		err = sc.ListenTls(s.cfg.CertBytes, s.cfg.KeyBytes, s.callback)
	}
	if err != nil {
		return
	}
	log.Printf("%s http(s) proxy on %s", *s.cfg.LocalType, (*sc.Listener).Addr())
	return
}

func (s *HTTP) Clean() {
	s.StopService()
}
func (s *HTTP) callback(inConn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("http(s) conn handler crashed with err : %s \nstack: %s", err, string(debug.Stack()))
		}
	}()
	// Acquire semaphore slot if connection limit is enabled
	if s.connSem != nil {
		select {
		case s.connSem <- struct{}{}:
			// Acquired slot, will release in defer
			defer func() { <-s.connSem }()
		default:
			// Semaphore full, reject connection
			fmt.Fprint(inConn, "HTTP/1.1 503 Service Unavailable\r\n\r\nServer busy")
			utils.CloseConn(&inConn)
			return
		}
	}
	// Set read deadline to protect against slowloris attacks
	inConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := utils.NewHTTPRequest(&inConn, 4096, s.IsBasicAuth(), &s.basicAuth, *s.cfg.AuthURL, s.authClient, s.authCache, *s.cfg.Debug)
	if err != nil {
		if err != io.EOF {
			log.Printf("decoder error , form %s, ERR:%s", err, inConn.RemoteAddr())
		}
		utils.CloseConn(&inConn)
		return
	}
	// Clear deadline after successful header parsing
	inConn.SetReadDeadline(time.Time{})
	address := req.Host

	useProxy := true
	if *s.cfg.Parent == "" {
		useProxy = false
	} else if *s.cfg.Always {
		useProxy = true
	} else {
		if req.IsHTTPS() {
			s.checker.Add(address, true, req.Method, "", nil)
		} else {
			s.checker.Add(address, false, req.Method, req.URL, req.HeadBuf)
		}
		//var n, m uint
		useProxy, _, _ = s.checker.IsBlocked(req.Host)
		//log.Printf("blocked ? : %v, %s , fail:%d ,success:%d", useProxy, address, n, m)
	}
	if *s.cfg.Debug {
		log.Printf("use proxy : %v, %s", useProxy, address)
	}
	//os.Exit(0)
	err = s.OutToTCP(useProxy, address, &inConn, &req)
	if err != nil {
		if *s.cfg.Parent == "" {
			log.Printf("connect to %s fail, ERR:%s", address, err)
		} else {
			log.Printf("connect to %s parent %s fail", *s.cfg.ParentType, *s.cfg.Parent)
		}
		utils.CloseConn(&inConn)
	}
}
func (s *HTTP) OutToTCP(useProxy bool, address string, inConn *net.Conn, req *utils.HTTPRequest) (err error) {
	inAddr := (*inConn).RemoteAddr().String()
	inLocalAddr := (*inConn).LocalAddr().String()
	//防止死循环
	if s.IsDeadLoop(inLocalAddr, req.Host) {
		utils.CloseConn(inConn)
		err = fmt.Errorf("dead loop detected , %s", req.Host)
		return
	}
	var outConn net.Conn
	var _outConn interface{}

	if req.Upstream != "" {
		// Connect via upstream proxy from auth API
		outConn, err = s.connectViaUpstream(req, address)
		if err != nil {
			log.Printf("connect to upstream %s fail: %s", req.Upstream, err)
			utils.CloseConn(inConn)
			return
		}
	} else if useProxy {
		_outConn, err = s.outPool.Pool.Get()
		if err == nil {
			outConn = _outConn.(net.Conn)
		}
	} else {
		outConn, err = utils.ConnectHost(address, *s.cfg.Timeout)
	}
	if err != nil {
		log.Printf("connect to %s , err:%s", address, err)
		utils.CloseConn(inConn)
		return
	}

	outAddr := outConn.RemoteAddr().String()
	outLocalAddr := outConn.LocalAddr().String()

	// Create traffic session if reporter is configured
	var session *traffic.Session
	var stopPeriodic func()
	if s.reporter != nil {
		session = traffic.NewSession(
			"http",
			inLocalAddr,
			inAddr,
			address,
			"", // username - not easily accessible in legacy handler without parsing auth header
			outLocalAddr,
			outAddr,
			req.Upstream,
			"", // sniff_domain - not implemented in legacy handler
		)
		// Start periodic reporting if in fast mode
		stopPeriodic = s.reporter.StartPeriodic(session)
	}

	if req.Upstream != "" {
		if req.IsHTTPS() {
			// For HTTPS via upstream: CONNECT already sent in connectViaUpstream
			req.HTTPSReply()
		} else {
			// For HTTP via upstream: forward modified request
			if *s.cfg.Debug {
				log.Printf("upstream HeadBuf:\n%s", string(req.HeadBuf))
			}
			_, writeErr := outConn.Write(req.HeadBuf)
			if writeErr != nil {
				log.Printf("write to upstream failed: %s", writeErr)
				utils.CloseConn(inConn)
				utils.CloseConn(&outConn)
				err = writeErr
				return
			}
		}
	} else if req.IsHTTPS() && !useProxy {
		req.HTTPSReply()
	} else {
		_, writeErr := outConn.Write(req.HeadBuf)
		if writeErr != nil {
			log.Printf("write to target failed: %s", writeErr)
			utils.CloseConn(inConn)
			utils.CloseConn(&outConn)
			err = writeErr
			return
		}
	}
	utils.IoBind((*inConn), outConn, func(isSrcErr bool, err error) {
		if *s.cfg.Debug {
			log.Printf("conn %s - %s - %s -%s released [%s]", inAddr, inLocalAddr, outLocalAddr, outAddr, req.Host)
		}
		utils.CloseConn(inConn)
		utils.CloseConn(&outConn)
		// Stop periodic reporting and send final report
		if stopPeriodic != nil {
			stopPeriodic()
		}
		// For normal mode, explicitly send the report (fast mode already sends in stopPeriodic)
		if s.reporter != nil && s.reporter.Mode() == "normal" {
			s.reporter.Report(session)
		}
	}, func(n int, d bool) {
		if session != nil {
			session.AddBytes(int64(n))
		}
	}, 0)
	if *s.cfg.Debug {
		log.Printf("conn %s - %s - %s - %s connected [%s]", inAddr, inLocalAddr, outLocalAddr, outAddr, req.Host)
	}
	return
}

func (s *HTTP) connectViaUpstream(req *utils.HTTPRequest, targetAddress string) (outConn net.Conn, err error) {
	upstreamURL, parseErr := url.Parse(req.Upstream)
	if parseErr != nil {
		err = fmt.Errorf("invalid upstream URL: %s", parseErr)
		return
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
	outConn, err = utils.ConnectHost(upstreamAddr, *s.cfg.Timeout)
	if err != nil {
		return
	}
	if *s.cfg.Debug {
		log.Printf("connected to upstream proxy %s", upstreamAddr)
	}

	if req.IsHTTPS() {
		// For HTTPS: send CONNECT to upstream proxy
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddress, targetAddress)
		if upstreamAuthHeader != "" {
			connectReq += upstreamAuthHeader + "\r\n"
		}
		connectReq += "\r\n"
		_, err = outConn.Write([]byte(connectReq))
		if err != nil {
			utils.CloseConn(&outConn)
			return
		}
		// Read upstream response via buffered reader
		reader := bufio.NewReader(outConn)
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			utils.CloseConn(&outConn)
			err = fmt.Errorf("upstream CONNECT read error: %s", readErr)
			return
		}
		if !strings.Contains(line, "200") {
			utils.CloseConn(&outConn)
			err = fmt.Errorf("upstream CONNECT rejected: %s", strings.TrimSpace(line))
			return
		}
		// Drain remaining headers
		for {
			line, readErr = reader.ReadString('\n')
			if readErr != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		// Wrap conn with buffered reader so any read-ahead bytes are not lost
		outConn = utils.NewBufferedConn(outConn, reader)
	} else {
		// For HTTP: replace client Proxy-Authorization with upstream's in HeadBuf
		// Use byte-level operations to safely handle buffers that may contain partial body data
		buf := req.HeadBuf

		// Remove existing Proxy-Authorization header (case-insensitive)
		proxyAuthKey := []byte("proxy-authorization:")
		lowerBuf := bytes.ToLower(buf)
		if idx := bytes.Index(lowerBuf, proxyAuthKey); idx >= 0 {
			// Find the end of this header line (\r\n)
			endIdx := bytes.Index(buf[idx:], []byte("\r\n"))
			if endIdx >= 0 {
				// Remove the header line including trailing \r\n
				buf = append(buf[:idx], buf[idx+endIdx+2:]...)
			}
		}

		// Insert upstream auth header before the \r\n\r\n (end of headers)
		if upstreamAuthHeader != "" {
			headerEnd := []byte("\r\n\r\n")
			if idx := bytes.Index(buf, headerEnd); idx >= 0 {
				insertion := []byte(upstreamAuthHeader + "\r\n")
				newBuf := make([]byte, 0, len(buf)+len(insertion))
				newBuf = append(newBuf, buf[:idx+2]...) // up to and including first \r\n
				newBuf = append(newBuf, insertion...)   // new header
				newBuf = append(newBuf, buf[idx+2:]...) // remaining \r\n + body
				buf = newBuf
			}
		}

		req.HeadBuf = buf
	}
	return
}
func (s *HTTP) OutToUDP(inConn *net.Conn) (err error) {
	return
}
func (s *HTTP) InitOutConnPool() {
	if *s.cfg.ParentType == TYPE_TLS || *s.cfg.ParentType == TYPE_TCP {
		//dur int, isTLS bool, certBytes, keyBytes []byte,
		//parent string, timeout int, InitialCap int, MaxCap int
		s.outPool = utils.NewOutPool(
			*s.cfg.CheckParentInterval,
			*s.cfg.ParentType == TYPE_TLS,
			s.cfg.CertBytes, s.cfg.KeyBytes,
			*s.cfg.Parent,
			*s.cfg.Timeout,
			*s.cfg.PoolSize,
			*s.cfg.PoolSize*2,
		)
	}
}
func (s *HTTP) InitBasicAuth() (err error) {
	s.basicAuth = utils.NewBasicAuth()
	if *s.cfg.AuthFile != "" {
		var n = 0
		n, err = s.basicAuth.AddFromFile(*s.cfg.AuthFile)
		if err != nil {
			err = fmt.Errorf("auth-file ERR:%s", err)
			return
		}
		log.Printf("auth data added from file %d , total:%d", n, s.basicAuth.Total())
	}
	if len(*s.cfg.Auth) > 0 {
		n := s.basicAuth.Add(*s.cfg.Auth)
		log.Printf("auth data added %d, total:%d", n, s.basicAuth.Total())
	}
	return
}
func (s *HTTP) IsBasicAuth() bool {
	return *s.cfg.AuthFile != "" || len(*s.cfg.Auth) > 0 || *s.cfg.AuthURL != ""
}
func (s *HTTP) IsDeadLoop(inLocalAddr string, host string) bool {
	inIP, inPort, err := net.SplitHostPort(inLocalAddr)
	if err != nil {
		return false
	}
	outDomain, outPort, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if inPort == outPort {
		var outIPs []net.IP
		outIPs, err = net.LookupIP(outDomain)
		if err == nil {
			for _, ip := range outIPs {
				if ip.String() == inIP {
					return true
				}
			}
		}
		interfaceIPs, err := utils.GetAllInterfaceAddr()
		if err == nil {
			for _, localIP := range interfaceIPs {
				for _, outIP := range outIPs {
					if localIP.Equal(outIP) {
						return true
					}
				}
			}
		}
	}
	return false
}
