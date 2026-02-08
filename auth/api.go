package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIAuth implements external HTTP API authentication
type APIAuth struct {
	apiURL    string
	timeout   time.Duration
	client    *http.Client
	cache     *Cache
	debug     bool
}

// NewAPIAuth creates a new external API authenticator
func NewAPIAuth(apiURL string, timeout time.Duration, cacheTTL time.Duration, debug bool) *APIAuth {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	
	var cache *Cache
	if cacheTTL > 0 {
		cache = NewCache(int(cacheTTL.Seconds()))
	}
	
	return &APIAuth{
		apiURL:  apiURL,
		timeout: timeout,
		client:  client,
		cache:   cache,
		debug:   debug,
	}
}

// Authenticate validates credentials against external API
func (a *APIAuth) Authenticate(ctx context.Context, creds Credentials) (Result, error) {
	cacheKey := creds.User + ":" + creds.Pass
	
	// Check cache first
	if a.cache != nil && a.cache.Enabled() {
		if cachedUpstream, hit := a.cache.Get(cacheKey); hit {
			if a.debug {
				log.Printf("auth cache hit for user: %s", creds.User)
			}
			return Result{
				OK:       true,
				User:     creds.User,
				Upstream: cachedUpstream,
			}, nil
		}
	}
	
	// Build auth URL with query parameters
	authReqURL := a.apiURL + "?user=" + url.QueryEscape(creds.User) +
		"&pass=" + url.QueryEscape(creds.Pass) +
		"&ip=" + url.QueryEscape(creds.ClientIP) +
		"&local_ip=" + url.QueryEscape(creds.LocalIP) +
		"&target=" + url.QueryEscape(creds.Target)
	
	req, err := http.NewRequestWithContext(ctx, "GET", authReqURL, nil)
	if err != nil {
		return Result{OK: false}, fmt.Errorf("auth request build failed: %w", err)
	}
	
	resp, err := a.client.Do(req)
	if err != nil {
		return Result{OK: false}, fmt.Errorf("auth API request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Drain body to allow connection reuse
	io.Copy(io.Discard, resp.Body)
	
	// Read upstream from response header
	upstream := strings.TrimSpace(resp.Header.Get("upstream"))
	
	// Check response status - 204 or 200 means success
	if resp.StatusCode == 204 || resp.StatusCode == 200 {
		if a.debug {
			log.Printf("auth API success for user: %s, upstream: %s", creds.User, upstream)
		}
		
		// Cache successful auth
		if a.cache != nil && a.cache.Enabled() {
			a.cache.Set(cacheKey, upstream)
		}
		
		return Result{
			OK:       true,
			User:     creds.User,
			Upstream: upstream,
		}, nil
	}
	
	if a.debug {
		log.Printf("auth API failed for user: %s, status: %d", creds.User, resp.StatusCode)
	}
	
	return Result{OK: false}, fmt.Errorf("auth API rejected credentials: status %d", resp.StatusCode)
}

// Close implements the Authenticator interface
func (a *APIAuth) Close() error {
	if a.cache != nil {
		a.cache.Stop()
	}
	return nil
}

// ParseBasicAuthHeader extracts credentials from HTTP Basic Auth header
func ParseBasicAuthHeader(header string) (user, pass string, ok bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || fields[0] != "Basic" {
		return "", "", false
	}
	
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", "", false
	}
	
	userpass := string(decoded)
	colonIdx := strings.Index(userpass, ":")
	if colonIdx == -1 {
		return "", "", false
	}
	
	return userpass[:colonIdx], userpass[colonIdx+1:], true
}
