package traffic

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPReporter_NormalMode(t *testing.T) {
	var receivedReq *http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedReq = r
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, "normal", 5*time.Second, false)
	defer reporter.Close()

	session := NewSession(
		"http",
		"127.0.0.1:8080",
		"192.168.1.1:54321",
		"example.com:443",
		"testuser",
		"10.0.0.1:12345",
		"93.184.216.34:443",
		"",
		"example.com",
	)
	session.AddBytes(1024)

	reporter.Report(session)

	time.Sleep(100 * time.Millisecond)

	if receivedReq == nil {
		t.Fatal("expected request to be received")
	}

	if receivedReq.Method != "GET" {
		t.Errorf("expected GET method, got %s", receivedReq.Method)
	}

	query := receivedReq.URL.Query()

	if query.Get("id") != "http" {
		t.Errorf("expected id='http', got '%s'", query.Get("id"))
	}
	if query.Get("bytes") != "1024" {
		t.Errorf("expected bytes='1024', got '%s'", query.Get("bytes"))
	}
	if query.Get("username") != "testuser" {
		t.Errorf("expected username='testuser', got '%s'", query.Get("username"))
	}
	if query.Get("target_addr") != "example.com:443" {
		t.Errorf("expected target_addr='example.com:443', got '%s'", query.Get("target_addr"))
	}
	if query.Get("server_addr") != "127.0.0.1:8080" {
		t.Errorf("expected server_addr='127.0.0.1:8080', got '%s'", query.Get("server_addr"))
	}
	if query.Get("client_addr") != "192.168.1.1:54321" {
		t.Errorf("expected client_addr='192.168.1.1:54321', got '%s'", query.Get("client_addr"))
	}
	if query.Get("sniff_domain") != "example.com" {
		t.Errorf("expected sniff_domain='example.com', got '%s'", query.Get("sniff_domain"))
	}
}

func TestHTTPReporter_FastMode(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, "fast", 100*time.Millisecond, false)
	defer reporter.Close()

	session := NewSession(
		"http",
		"127.0.0.1:8080",
		"192.168.1.1:54321",
		"example.com:443",
		"",
		"",
		"",
		"",
		"",
	)
	session.AddBytes(100)

	stopPeriodic := reporter.StartPeriodic(session)

	time.Sleep(250 * time.Millisecond)

	stopPeriodic()

	time.Sleep(100 * time.Millisecond)

	if requestCount < 2 {
		t.Errorf("expected at least 2 requests in fast mode, got %d", requestCount)
	}
}

func TestHTTPReporter_FastGlobalMode(t *testing.T) {
	var batches [][]SessionSnapshot

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			var batch []SessionSnapshot
			json.Unmarshal(body, &batch)
			batches = append(batches, batch)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, "fast", 5*time.Second, true)

	session1 := NewSession("http", "127.0.0.1:8080", "192.168.1.1:54321", "example1.com:443", "", "", "", "", "")
	session1.AddBytes(100)

	session2 := NewSession("http", "127.0.0.1:8080", "192.168.1.2:54322", "example2.com:443", "", "", "", "", "")
	session2.AddBytes(200)

	stop1 := reporter.StartPeriodic(session1)
	stop2 := reporter.StartPeriodic(session2)

	time.Sleep(100 * time.Millisecond)

	stop1()
	stop2()

	reporter.Close()

	if len(batches) == 0 {
		t.Fatal("expected at least one batch request")
	}

	foundSession1 := false
	foundSession2 := false
	for _, batch := range batches {
		for _, snap := range batch {
			if snap.TargetAddr == "example1.com:443" && snap.Bytes == 100 {
				foundSession1 = true
			}
			if snap.TargetAddr == "example2.com:443" && snap.Bytes == 200 {
				foundSession2 = true
			}
		}
	}

	if !foundSession1 {
		t.Error("expected session1 to be in batch")
	}
	if !foundSession2 {
		t.Error("expected session2 to be in batch")
	}
}

func TestHTTPReporter_Non204Response(t *testing.T) {
	var logged bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, "normal", 5*time.Second, false)
	defer reporter.Close()

	session := NewSession("http", "127.0.0.1:8080", "192.168.1.1:54321", "example.com:443", "", "", "", "", "")
	session.AddBytes(100)

	reporter.Report(session)

	time.Sleep(100 * time.Millisecond)

	_ = logged
}

func TestHTTPReporter_QueryParamsEncoding(t *testing.T) {
	var receivedURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.String()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, "normal", 5*time.Second, false)
	defer reporter.Close()

	session := NewSession(
		"http",
		"127.0.0.1:8080",
		"192.168.1.1:54321",
		"example.com:443",
		"user@domain.com",
		"10.0.0.1:12345",
		"93.184.216.34:443",
		"http://upstream:3128",
		"example.com:443",
	)
	session.AddBytes(1024)

	reporter.Report(session)

	time.Sleep(100 * time.Millisecond)

	if !strings.Contains(receivedURL, "username=user%40domain.com") {
		t.Errorf("expected username to be URL encoded, got: %s", receivedURL)
	}
}

func TestNopReporter(t *testing.T) {
	reporter := NewNopReporter()
	defer reporter.Close()

	session := NewSession("http", "127.0.0.1:8080", "192.168.1.1:54321", "example.com:443", "", "", "", "", "")

	reporter.Report(session)

	stop := reporter.StartPeriodic(session)
	stop()

}
