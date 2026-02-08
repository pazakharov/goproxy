package auth

import (
	"context"
)

// Credentials contains authentication data from client
type Credentials struct {
	User     string // username
	Pass     string // password
	ClientIP string // remote client IP
	LocalIP  string // local proxy IP
	Target   string // target host (for logging/metrics)
}

// Result contains authentication outcome
type Result struct {
	OK       bool   // authenticated successfully
	User     string // normalized username
	Upstream string // upstream proxy URL (empty = direct connection)
}

// Authenticator is the interface for all authentication backends
type Authenticator interface {
	// Authenticate validates credentials and returns auth result
	Authenticate(ctx context.Context, creds Credentials) (Result, error)
	
	// Close releases resources (connections, goroutines)
	Close() error
}
