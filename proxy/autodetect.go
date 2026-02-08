package proxy

import (
	"bufio"
	"context"
	"net"
)

// AutoDetectHandler automatically detects protocol (SOCKS5 vs HTTP) by first byte
type AutoDetectHandler struct {
	socks5Handler *SOCKS5Handler
	httpHandler   *HTTPHandler
}

// NewAutoDetectHandler creates a handler that auto-detects protocol
func NewAutoDetectHandler(socks5 *SOCKS5Handler, http *HTTPHandler) *AutoDetectHandler {
	return &AutoDetectHandler{
		socks5Handler: socks5,
		httpHandler:   http,
	}
}

// Protocol returns "auto" (SPS-like)
func (h *AutoDetectHandler) Protocol() string {
	return "auto"
}

// SupportsAuth returns true (both protocols support auth)
func (h *AutoDetectHandler) SupportsAuth() bool {
	return true
}

// HandleConnection detects protocol and delegates to appropriate handler
func (h *AutoDetectHandler) HandleConnection(ctx context.Context, conn net.Conn) {
	// Create buffered reader to peek first byte without consuming
	reader := bufio.NewReader(conn)
	
	// Peek first byte to detect protocol
	firstByte, err := reader.Peek(1)
	if err != nil {
		conn.Close()
		return
	}
	
	// Wrap conn with buffered reader so data isn't lost
	bufferedConn := &bufferedConn{
		Conn:   conn,
		reader: reader,
	}
	
	// SOCKS5 starts with 0x05
	if firstByte[0] == 0x05 {
		h.socks5Handler.HandleConnection(ctx, bufferedConn)
	} else {
		// Assume HTTP for everything else
		h.httpHandler.HandleConnection(ctx, bufferedConn)
	}
}

// bufferedConn wraps net.Conn with a buffered reader
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads from the buffered reader first
func (c *bufferedConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}
