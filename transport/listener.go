package transport

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"runtime/debug"
)

// ListenTLS creates a TLS listener
func ListenTLS(ip string, port int, certBytes, keyBytes []byte) (*net.Listener, error) {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certBytes) {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	config := &tls.Config{
		ClientCAs:    pool,
		ServerName:   "proxy",
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", ip, port), config)
	if err != nil {
		return nil, err
	}
	return &ln, nil
}

// Listener wraps TCP/TLS/UDP listeners with common accept logic
type Listener struct {
	ip               string
	port             int
	Listener         *net.Listener
	UDPListener      *net.UDPConn
	errAcceptHandler func(err error)
}

// NewListener creates a new listener configuration
func NewListener(ip string, port int) *Listener {
	return &Listener{
		ip:   ip,
		port: port,
		errAcceptHandler: func(err error) {
			fmt.Printf("accept error, ERR:%s", err)
		},
	}
}

// SetErrAcceptHandler sets the error handler for accept failures
func (l *Listener) SetErrAcceptHandler(fn func(err error)) {
	l.errAcceptHandler = fn
}

// ListenTCP starts TCP listening with the given connection handler
func (l *Listener) ListenTLS(certBytes, keyBytes []byte, handler func(conn net.Conn)) error {
	ln, err := ListenTLS(l.ip, l.port, certBytes, keyBytes)
	if err != nil {
		return err
	}

	l.Listener = ln
	go l.acceptLoop(handler)
	return nil
}

// ListenTCP starts TCP listening with the given connection handler
func (l *Listener) ListenTCP(handler func(conn net.Conn)) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", l.ip, l.port))
	if err != nil {
		return err
	}

	l.Listener = &ln
	go l.acceptLoop(handler)
	return nil
}

func (l *Listener) acceptLoop(handler func(conn net.Conn)) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Listener accept loop crashed: %s\ntrace:%s", e, string(debug.Stack()))
		}
	}()

	for {
		conn, err := (*l.Listener).Accept()
		if err != nil {
			l.errAcceptHandler(err)
			(*l.Listener).Close()
			break
		}

		go func() {
			defer func() {
				if e := recover(); e != nil {
					log.Printf("Connection handler crashed: %s\ntrace:%s", e, string(debug.Stack()))
				}
			}()
			handler(conn)
		}()
	}
}

// ListenUDP starts UDP listening
func (l *Listener) ListenUDP(handler func(packet []byte, localAddr, srcAddr *net.UDPAddr)) error {
	addr := &net.UDPAddr{IP: net.ParseIP(l.ip), Port: l.port}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	l.UDPListener = udpConn
	go l.udpLoop(handler)
	return nil
}

func (l *Listener) udpLoop(handler func(packet []byte, localAddr, srcAddr *net.UDPAddr)) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("UDP listener crashed: %s\ntrace:%s", e, string(debug.Stack()))
		}
	}()

	for {
		buf := make([]byte, 2048)
		n, srcAddr, err := l.UDPListener.ReadFromUDP(buf)
		if err != nil {
			l.errAcceptHandler(err)
			break
		}

		packet := buf[0:n]
		go func() {
			defer func() {
				if e := recover(); e != nil {
					log.Printf("UDP handler crashed: %s\ntrace:%s", e, string(debug.Stack()))
				}
			}()
			handler(packet, l.UDPListener.LocalAddr().(*net.UDPAddr), srcAddr)
		}()
	}
}

// BufferedConn wraps a net.Conn with a bufio.Reader
type BufferedConn struct {
	r *bufio.Reader
	net.Conn
}

// NewBufferedConn creates a buffered connection
func NewBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{r: r, Conn: c}
}

// Read reads from the buffered reader
func (bc *BufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}
