package proxy

import (
	"context"
	"net"
)

// Handler is the interface for protocol-specific proxy handlers
type Handler interface {
	// HandleConnection processes a client connection
	// The handler must close the connection when done
	HandleConnection(ctx context.Context, conn net.Conn)
	
	// Protocol returns the handler protocol name (e.g., "http", "socks5")
	Protocol() string
	
	// SupportsAuth returns true if the protocol supports authentication
	SupportsAuth() bool
}
