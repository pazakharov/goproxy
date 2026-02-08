package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Reporter is the interface for traffic reporting
type Reporter interface {
	// Report sends a traffic report for the session
	// For fast mode, this also handles periodic reporting
	Report(session *Session)
	// StartPeriodic begins periodic reporting for fast mode, returns stop function
	StartPeriodic(session *Session) func()
	// Close shuts down the reporter and flushes any pending reports
	Close() error
	// Mode returns the reporting mode ("normal" or "fast")
	Mode() string
}

// HTTPReporter implements HTTP-based traffic reporting
type HTTPReporter struct {
	client     *http.Client
	url        string
	mode       string        // "normal" or "fast"
	interval   time.Duration // reporting interval for fast mode
	fastGlobal bool          // use single batch reporter

	// for fast-global mode
	batchCh   chan *SessionSnapshot
	batchStop chan struct{}
	batchWg   sync.WaitGroup
}

// NewHTTPReporter creates a new HTTP traffic reporter
func NewHTTPReporter(trafficURL, mode string, interval time.Duration, fastGlobal bool) *HTTPReporter {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	r := &HTTPReporter{
		client:     client,
		url:        trafficURL,
		mode:       mode,
		interval:   interval,
		fastGlobal: fastGlobal,
	}

	// Start batch reporter for fast-global mode
	if fastGlobal && mode == "fast" {
		r.batchCh = make(chan *SessionSnapshot, 1000)
		r.batchStop = make(chan struct{})
		r.batchWg.Add(1)
		go r.batchReporter()
	}

	return r
}

// Report sends a single traffic report for the session
func (r *HTTPReporter) Report(session *Session) {
	if r.fastGlobal && r.mode == "fast" {
		// Fast-global: queue to batch channel
		snap := session.Snapshot()
		select {
		case r.batchCh <- &snap:
		default:
			// Channel full, drop report to avoid blocking
			log.Printf("traffic reporter: batch channel full, dropping report")
		}
		return
	}

	// Normal or fast mode: send GET request
	params := r.buildQueryParams(session)
	reportURL := r.url + "?" + params.Encode()

	req, err := http.NewRequest("GET", reportURL, nil)
	if err != nil {
		log.Printf("traffic reporter: failed to build request: %v", err)
		return
	}

	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("traffic reporter: request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// Drain body to allow connection reuse
	io.Copy(io.Discard, resp.Body)

	// Check response - 204 is success, others are failures
	if resp.StatusCode != 204 {
		log.Printf("traffic reporter: unexpected status %d from %s", resp.StatusCode, r.url)
	}
}

// buildQueryParams builds the URL query parameters for the traffic report
func (r *HTTPReporter) buildQueryParams(session *Session) url.Values {
	params := url.Values{}
	params.Set("id", session.ID)
	params.Set("bytes", fmt.Sprintf("%d", session.GetBytes()))
	params.Set("client_addr", session.ClientAddr)
	params.Set("server_addr", session.ServerAddr)
	params.Set("target_addr", session.TargetAddr)
	params.Set("username", session.Username)
	params.Set("out_local_addr", session.OutLocalAddr)
	params.Set("out_remote_addr", session.OutRemoteAddr)
	params.Set("upstream", session.Upstream)
	params.Set("sniff_domain", session.SniffDomain)
	return params
}

// StartPeriodic begins periodic reporting for fast mode
// Returns a stop function that should be called when the connection closes
func (r *HTTPReporter) StartPeriodic(session *Session) func() {
	if r.mode != "fast" {
		return func() {}
	}

	// Fast-global mode uses batch reporter, no per-session ticker needed
	if r.fastGlobal {
		return func() {
			// Final report on close
			r.Report(session)
		}
	}

	// Fast mode: per-session periodic reporting
	stopCh := make(chan struct{})
	ticker := time.NewTicker(r.interval)

	go func() {
		for {
			select {
			case <-ticker.C:
				r.Report(session)
			case <-stopCh:
				ticker.Stop()
				return
			}
		}
	}()

	// Return stop function that also sends final report
	return func() {
		close(stopCh)
		// Send final report
		r.Report(session)
	}
}

// batchReporter runs the background goroutine for fast-global mode
func (r *HTTPReporter) batchReporter() {
	defer r.batchWg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	batch := make([]*SessionSnapshot, 0, 100)

	for {
		select {
		case snap := <-r.batchCh:
			batch = append(batch, snap)
			// Send immediately if batch is large
			if len(batch) >= 100 {
				r.sendBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				r.sendBatch(batch)
				batch = batch[:0]
			}

		case <-r.batchStop:
			// Final flush
			if len(batch) > 0 {
				r.sendBatch(batch)
			}
			// Drain remaining channel
			for {
				select {
				case snap := <-r.batchCh:
					batch = append(batch, snap)
				default:
					if len(batch) > 0 {
						r.sendBatch(batch)
					}
					return
				}
			}
		}
	}
}

// sendBatch sends a batch of traffic reports as JSON POST
func (r *HTTPReporter) sendBatch(batch []*SessionSnapshot) {
	if len(batch) == 0 {
		return
	}

	data, err := json.Marshal(batch)
	if err != nil {
		log.Printf("traffic reporter: failed to marshal batch: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", r.url, bytes.NewReader(data))
	if err != nil {
		log.Printf("traffic reporter: failed to build batch request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("traffic reporter: batch request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 204 {
		log.Printf("traffic reporter: batch report unexpected status %d", resp.StatusCode)
	}
}

// Close shuts down the reporter
func (r *HTTPReporter) Close() error {
	if r.fastGlobal && r.mode == "fast" && r.batchStop != nil {
		close(r.batchStop)
		r.batchWg.Wait()
	}
	return nil
}

// Mode returns the reporting mode
func (r *HTTPReporter) Mode() string {
	return r.mode
}

// NopReporter is a no-op reporter that does nothing
type NopReporter struct{}

// Mode returns "normal" for nop reporter
func (n *NopReporter) Mode() string {
	return "normal"
}

// NewNopReporter creates a no-op reporter
func NewNopReporter() *NopReporter {
	return &NopReporter{}
}

// Report does nothing
func (n *NopReporter) Report(session *Session) {}

// StartPeriodic returns empty stop function
func (n *NopReporter) StartPeriodic(session *Session) func() {
	return func() {}
}

// Close does nothing
func (n *NopReporter) Close() error {
	return nil
}
