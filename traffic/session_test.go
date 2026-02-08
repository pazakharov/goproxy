package traffic

import (
	"sync"
	"testing"
)

func TestSession_NewSession(t *testing.T) {
	s := NewSession(
		"http",
		"127.0.0.1:8080",
		"192.168.1.1:54321",
		"example.com:443",
		"user1",
		"10.0.0.1:12345",
		"93.184.216.34:443",
		"",
		"example.com",
	)

	if s.ID != "http" {
		t.Errorf("expected ID 'http', got '%s'", s.ID)
	}
	if s.ServerAddr != "127.0.0.1:8080" {
		t.Errorf("expected ServerAddr '127.0.0.1:8080', got '%s'", s.ServerAddr)
	}
	if s.ClientAddr != "192.168.1.1:54321" {
		t.Errorf("expected ClientAddr '192.168.1.1:54321', got '%s'", s.ClientAddr)
	}
	if s.TargetAddr != "example.com:443" {
		t.Errorf("expected TargetAddr 'example.com:443', got '%s'", s.TargetAddr)
	}
	if s.Username != "user1" {
		t.Errorf("expected Username 'user1', got '%s'", s.Username)
	}
	if s.GetBytes() != 0 {
		t.Errorf("expected initial bytes 0, got %d", s.GetBytes())
	}
}

func TestSession_AddBytes(t *testing.T) {
	s := NewSession("http", "127.0.0.1:8080", "192.168.1.1:54321", "example.com:443", "", "", "", "", "")

	s.AddBytes(100)
	if s.GetBytes() != 100 {
		t.Errorf("expected 100 bytes, got %d", s.GetBytes())
	}

	s.AddBytes(50)
	if s.GetBytes() != 150 {
		t.Errorf("expected 150 bytes, got %d", s.GetBytes())
	}
}

func TestSession_ConcurrentAddBytes(t *testing.T) {
	s := NewSession("http", "127.0.0.1:8080", "192.168.1.1:54321", "example.com:443", "", "", "", "", "")

	var wg sync.WaitGroup
	numGoroutines := 100
	bytesPerGoroutine := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < bytesPerGoroutine; j++ {
				s.AddBytes(1)
			}
		}()
	}

	wg.Wait()

	expected := int64(numGoroutines * bytesPerGoroutine)
	if s.GetBytes() != expected {
		t.Errorf("expected %d bytes, got %d", expected, s.GetBytes())
	}
}

func TestSession_Snapshot(t *testing.T) {
	s := NewSession(
		"socks5",
		"127.0.0.1:1080",
		"192.168.1.2:54322",
		"target.example.com:80",
		"user2",
		"10.0.0.2:12346",
		"target.ip:80",
		"upstream.proxy:3128",
		"target.example.com",
	)

	s.AddBytes(1024)

	snap := s.Snapshot()

	if snap.ID != "socks5" {
		t.Errorf("snapshot ID mismatch")
	}
	if snap.ServerAddr != "127.0.0.1:1080" {
		t.Errorf("snapshot ServerAddr mismatch")
	}
	if snap.ClientAddr != "192.168.1.2:54322" {
		t.Errorf("snapshot ClientAddr mismatch")
	}
	if snap.TargetAddr != "target.example.com:80" {
		t.Errorf("snapshot TargetAddr mismatch")
	}
	if snap.Username != "user2" {
		t.Errorf("snapshot Username mismatch")
	}
	if snap.Bytes != 1024 {
		t.Errorf("snapshot Bytes mismatch, expected 1024, got %d", snap.Bytes)
	}
	if snap.OutLocalAddr != "10.0.0.2:12346" {
		t.Errorf("snapshot OutLocalAddr mismatch")
	}
	if snap.OutRemoteAddr != "target.ip:80" {
		t.Errorf("snapshot OutRemoteAddr mismatch")
	}
	if snap.Upstream != "upstream.proxy:3128" {
		t.Errorf("snapshot Upstream mismatch")
	}
	if snap.SniffDomain != "target.example.com" {
		t.Errorf("snapshot SniffDomain mismatch")
	}
}
