package traffic

import (
	"sync/atomic"
	"time"
)

// Session contains traffic statistics and metadata for a single connection
type Session struct {
	ID            string    // Service ID flag
	ServerAddr    string    // Proxy address (IP:port)
	ClientAddr    string    // Client address (IP:port)
	TargetAddr    string    // Target address (IP:port), empty for TCP/UDP proxy
	Username      string    // Proxy auth username, empty if none
	OutLocalAddr  string    // Outgoing conn local address (IP:port)
	OutRemoteAddr string    // Outgoing conn remote address (IP:port)
	Upstream      string    // Upstream proxy URL, empty if none
	SniffDomain   string    // Sniffed domain (only with SPS/sniff-domain)
	bytes         atomic.Int64
	startTime     time.Time
}

// NewSession creates a new traffic session with the given metadata
func NewSession(id, serverAddr, clientAddr, targetAddr, username, outLocalAddr, outRemoteAddr, upstream, sniffDomain string) *Session {
	return &Session{
		ID:            id,
		ServerAddr:    serverAddr,
		ClientAddr:    clientAddr,
		TargetAddr:    targetAddr,
		Username:      username,
		OutLocalAddr:  outLocalAddr,
		OutRemoteAddr: outRemoteAddr,
		Upstream:      upstream,
		SniffDomain:   sniffDomain,
		startTime:     time.Now(),
	}
}

// AddBytes atomically adds n bytes to the session total
func (s *Session) AddBytes(n int64) {
	s.bytes.Add(n)
}

// GetBytes returns the current byte count
func (s *Session) GetBytes() int64 {
	return s.bytes.Load()
}

// StartTime returns when the session was created
func (s *Session) StartTime() time.Time {
	return s.startTime
}

// SessionSnapshot is a serializable snapshot of a session for JSON batch reports
type SessionSnapshot struct {
	ID            string `json:"id"`
	ServerAddr    string `json:"server_addr"`
	ClientAddr    string `json:"client_addr"`
	TargetAddr    string `json:"target_addr"`
	Username      string `json:"username"`
	Bytes         int64  `json:"bytes"`
	OutLocalAddr  string `json:"out_local_addr"`
	OutRemoteAddr string `json:"out_remote_addr"`
	Upstream      string `json:"upstream"`
	SniffDomain   string `json:"sniff_domain"`
}

// Snapshot creates a serializable snapshot of the current session state
func (s *Session) Snapshot() SessionSnapshot {
	return SessionSnapshot{
		ID:            s.ID,
		ServerAddr:    s.ServerAddr,
		ClientAddr:    s.ClientAddr,
		TargetAddr:    s.TargetAddr,
		Username:      s.Username,
		Bytes:         s.GetBytes(),
		OutLocalAddr:  s.OutLocalAddr,
		OutRemoteAddr: s.OutRemoteAddr,
		Upstream:      s.Upstream,
		SniffDomain:   s.SniffDomain,
	}
}
