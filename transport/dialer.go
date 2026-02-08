package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// Dialer provides connection establishment
type Dialer struct {
	timeout time.Duration
}

// NewDialer creates a new dialer with the specified timeout
func NewDialer(timeout time.Duration) *Dialer {
	return &Dialer{timeout: timeout}
}

// Connect establishes a TCP connection to the host
func (d *Dialer) Connect(host string) (net.Conn, error) {
	return net.DialTimeout("tcp", host, d.timeout)
}

// ConnectTLS establishes a TLS connection to the host
func (d *Dialer) ConnectTLS(host string, certBytes, keyBytes []byte) (*tls.Conn, error) {
	conf, err := GetTLSConfig(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", host, d.timeout)
	if err != nil {
		return nil, err
	}

	return tls.Client(conn, conf), nil
}

// GetTLSConfig creates TLS config from cert/key bytes
func GetTLSConfig(certBytes, keyBytes []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certBytes) {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	return &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{cert},
		ServerName:         "proxy",
		InsecureSkipVerify: false,
	}, nil
}
