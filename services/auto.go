package services

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/snail007/goproxy/auth"
	"github.com/snail007/goproxy/config"
	"github.com/snail007/goproxy/proxy"
	"github.com/snail007/goproxy/traffic"
	"github.com/snail007/goproxy/transport"
)

// Auto implements the auto-detect proxy service (HTTP + SOCKS5)
type Auto struct {
	cfg     HTTPArgs
	server  *transport.Listener
	handler proxy.Handler
}

// NewAuto creates a new auto-detect proxy service
func NewAuto() Service {
	return &Auto{
		cfg: HTTPArgs{},
	}
}

// InitService initializes the service
func (s *Auto) InitService() {
	// Initialize auth if configured
}

// StopService stops the service
func (s *Auto) StopService() {
	if s.server != nil && s.server.Listener != nil {
		(*s.server.Listener).Close()
	}
}

// Clean performs cleanup
func (s *Auto) Clean() {
	s.StopService()
}

// Start starts the auto-detect proxy service
func (s *Auto) Start(args interface{}) (err error) {
	s.cfg = args.(HTTPArgs)

	// Build authenticator
	var authenticator auth.Authenticator
	if *s.cfg.AuthURL != "" {
		// Use external API auth
		authenticator = auth.NewAPIAuth(
			*s.cfg.AuthURL,
			time.Duration(*s.cfg.AuthTimeout)*time.Millisecond,
			time.Duration(*s.cfg.AuthCacheTTL)*time.Second,
			*s.cfg.Debug,
		)
		log.Printf("auth-url: %s, timeout: %dms", *s.cfg.AuthURL, *s.cfg.AuthTimeout)
		if *s.cfg.AuthCacheTTL > 0 {
			log.Printf("auth cache enabled, TTL: %ds", *s.cfg.AuthCacheTTL)
		}
	} else if *s.cfg.AuthFile != "" || len(*s.cfg.Auth) > 0 {
		// Use basic auth
		basicAuth := auth.NewBasicAuth()
		if *s.cfg.AuthFile != "" {
			n, err := basicAuth.AddFromFile(*s.cfg.AuthFile)
			if err != nil {
				log.Printf("auth-file error: %s", err)
			} else {
				log.Printf("auth data added from file %d, total: %d", n, basicAuth.Total())
			}
		}
		if len(*s.cfg.Auth) > 0 {
			n := basicAuth.Add(*s.cfg.Auth)
			log.Printf("auth data added %d, total: %d", n, basicAuth.Total())
		}
		authenticator = basicAuth
	}

	// Build traffic reporter if configured
	var reporter traffic.Reporter
	if *s.cfg.TrafficURL != "" {
		reporter = traffic.NewHTTPReporter(
			*s.cfg.TrafficURL,
			*s.cfg.TrafficMode,
			time.Duration(*s.cfg.TrafficInterval)*time.Second,
			*s.cfg.FastGlobal,
		)
		log.Printf("traffic reporter: url=%s, mode=%s, interval=%ds, fast-global=%v",
			*s.cfg.TrafficURL, *s.cfg.TrafficMode, *s.cfg.TrafficInterval, *s.cfg.FastGlobal)
	} else {
		reporter = traffic.NewNopReporter()
	}

	// Build config for handlers
	serverCfg := config.ServerConfig{
		Listen:   *s.cfg.Local,
		MaxConns: *s.cfg.MaxConns,
		Debug:    *s.cfg.Debug,
	}

	if s.cfg.CertBytes != nil && s.cfg.KeyBytes != nil {
		serverCfg.TLS = &config.TLSConfig{
			CertBytes: s.cfg.CertBytes,
			KeyBytes:  s.cfg.KeyBytes,
		}
	}

	authCfg := config.AuthConfig{
		Users:      *s.cfg.Auth,
		AuthFile:   *s.cfg.AuthFile,
		APIURL:     *s.cfg.AuthURL,
		APITimeout: time.Duration(*s.cfg.AuthTimeout) * time.Millisecond,
		CacheTTL:   time.Duration(*s.cfg.AuthCacheTTL) * time.Second,
	}

	upstreamCfg := config.UpstreamConfig{
		Parent:              *s.cfg.Parent,
		ParentType:          *s.cfg.ParentType,
		Timeout:             time.Duration(*s.cfg.Timeout) * time.Millisecond,
		PoolSize:            *s.cfg.PoolSize,
		CheckParentInterval: time.Duration(*s.cfg.CheckParentInterval) * time.Second,
		AlwaysProxy:         *s.cfg.Always,
	}

	httpCfg := config.HTTPConfig{
		ServerConfig:   serverCfg,
		AuthConfig:     authCfg,
		UpstreamConfig: upstreamCfg,
		TrafficConfig: config.TrafficConfig{
			URL:        *s.cfg.TrafficURL,
			Mode:       *s.cfg.TrafficMode,
			Interval:   time.Duration(*s.cfg.TrafficInterval) * time.Second,
			FastGlobal: *s.cfg.FastGlobal,
		},
		HTTPTimeout: time.Duration(*s.cfg.HTTPTimeout) * time.Millisecond,
		Interval:    time.Duration(*s.cfg.Interval) * time.Second,
		Blocked:     *s.cfg.Blocked,
		Direct:      *s.cfg.Direct,
	}

	socks5Cfg := config.SOCKS5Config{
		ServerConfig:   serverCfg,
		AuthConfig:     authCfg,
		UpstreamConfig: upstreamCfg,
		TrafficConfig: config.TrafficConfig{
			URL:        *s.cfg.TrafficURL,
			Mode:       *s.cfg.TrafficMode,
			Interval:   time.Duration(*s.cfg.TrafficInterval) * time.Second,
			FastGlobal: *s.cfg.FastGlobal,
		},
	}

	// Create handlers
	httpHandler, err := proxy.NewHTTPHandler(httpCfg, authenticator, reporter)
	if err != nil {
		return err
	}

	socks5Handler, err := proxy.NewSOCKS5Handler(socks5Cfg, authenticator, reporter)
	if err != nil {
		return err
	}

	// Create auto-detect handler
	s.handler = proxy.NewAutoDetectHandler(socks5Handler, httpHandler)

	// Start listener
	host, port, _ := net.SplitHostPort(*s.cfg.Local)
	p, _ := strconv.Atoi(port)
	s.server = transport.NewListener(host, p)
	s.server.SetErrAcceptHandler(func(err error) {
		log.Printf("accept error: %s", err)
	})

	// Start listening
	if *s.cfg.LocalType == "tls" && serverCfg.TLS != nil {
		err = s.server.ListenTLS(serverCfg.TLS.CertBytes, serverCfg.TLS.KeyBytes, s.handleConn)
	} else {
		err = s.server.ListenTCP(s.handleConn)
	}

	if err != nil {
		return err
	}

	if *s.cfg.MaxConns > 0 {
		log.Printf("max concurrent connections limited to %d", *s.cfg.MaxConns)
	}
	log.Printf("auto-detect proxy (HTTP/SOCKS5) on %s", *s.cfg.Local)
	return nil
}

func (s *Auto) handleConn(conn net.Conn) {
	// Connection semaphore check
	// (simplified - in production would use buffered channel)
	s.handler.HandleConnection(context.TODO(), conn)
}
