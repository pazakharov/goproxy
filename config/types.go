package config

import (
	"crypto/tls"
	"time"
)

// ServerConfig contains common server settings
type ServerConfig struct {
	Listen   string
	TLS      *TLSConfig
	MaxConns int
	Debug    bool
}

// TLSConfig holds TLS certificate data
type TLSConfig struct {
	CertBytes []byte
	KeyBytes  []byte
	Config    *tls.Config
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	Users      []string       // user:pass pairs from CLI
	AuthFile   string         // path to auth file
	APIURL     string         // external auth API endpoint
	APITimeout time.Duration  // auth API timeout
	CacheTTL   time.Duration  // auth cache TTL (0 = disabled)
}

// UpstreamConfig contains upstream/parent proxy settings
type UpstreamConfig struct {
	Parent              string
	ParentType          string
	Timeout             time.Duration
	PoolSize            int
	CheckParentInterval time.Duration
	AlwaysProxy         bool
}

// HTTPConfig combines all HTTP proxy settings
type HTTPConfig struct {
	ServerConfig
	AuthConfig
	UpstreamConfig
	HTTPTimeout time.Duration // check domain blocked timeout
	Interval    time.Duration // check domain blocked interval
	Blocked     string        // blocked domain file
	Direct      string        // direct domain file
}

// SOCKS5Config combines all SOCKS5 proxy settings
type SOCKS5Config struct {
	ServerConfig
	AuthConfig
	UpstreamConfig
}
