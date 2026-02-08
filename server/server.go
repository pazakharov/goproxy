package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/snail007/goproxy/auth"
	"github.com/snail007/goproxy/config"
	"github.com/snail007/goproxy/proxy"
	"github.com/snail007/goproxy/traffic"
	"github.com/snail007/goproxy/transport"
)

// Server is a unified proxy server that can handle multiple protocols
type Server struct {
	cfg      config.ServerConfig
	auth     auth.Authenticator
	handler  proxy.Handler
	traffic  traffic.Counter
	listener *transport.Listener
	connSem  chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

// New creates a new server with the given configuration
func New(cfg config.ServerConfig, authenticator auth.Authenticator, handler proxy.Handler, counter traffic.Counter) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		cfg:     cfg,
		auth:    authenticator,
		handler: handler,
		traffic: counter,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize connection semaphore if max connections limit is set
	if cfg.MaxConns > 0 {
		s.connSem = make(chan struct{}, cfg.MaxConns)
		log.Printf("max concurrent connections limited to %d", cfg.MaxConns)
	}

	return s
}

// Start begins listening and handling connections
func (s *Server) Start() error {
	host, port, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	p := 0
	fmt.Sscanf(port, "%d", &p)

	s.listener = transport.NewListener(host, p)
	s.listener.SetErrAcceptHandler(func(err error) {
		log.Printf("accept error: %s", err)
	})

	// Choose between TLS and TCP
	if s.cfg.TLS != nil {
		err = s.listener.ListenTLS(s.cfg.TLS.CertBytes, s.cfg.TLS.KeyBytes, s.handleConn)
	} else {
		err = s.listener.ListenTCP(s.handleConn)
	}

	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	log.Printf("%s proxy on %s", s.handler.Protocol(), s.cfg.Listen)
	return nil
}

// handleConn processes an incoming connection
func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("connection handler panic: %v", r)
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
			s.rejectConn(conn)
			return
		}
	}

	// Pass to the protocol handler
	s.handler.HandleConnection(s.ctx, conn)
}

// rejectConn sends an error response and closes the connection
func (s *Server) rejectConn(conn net.Conn) {
	// Try to send HTTP 503 (works for HTTP connections)
	// For other protocols, they will just see a closed connection
	fmt.Fprint(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\nServer busy")
	conn.Close()
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.cancel()

	if s.auth != nil {
		s.auth.Close()
	}

	if s.traffic != nil {
		s.traffic.Close()
	}

	return nil
}

// GetTrafficSnapshot returns current traffic statistics
func (s *Server) GetTrafficSnapshot() map[string]traffic.UserTraffic {
	if s.traffic == nil {
		return nil
	}
	return s.traffic.Snapshot()
}

// DefaultHTTPClient returns a pre-configured HTTP client for auth API
func DefaultHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}
