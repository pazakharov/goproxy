package auth

import (
	"context"
	"sync"
	"time"
)

// cacheEntry stores a cached auth result
type cacheEntry struct {
	Upstream string
	ExpireAt time.Time
}

// Cache provides TTL-based caching for authentication results
type Cache struct {
	data   sync.Map
	ttl    time.Duration
	cancel context.CancelFunc
	ctx    context.Context
}

// NewCache creates a new auth cache with the given TTL in seconds
func NewCache(ttlSeconds int) *Cache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Cache{
		ttl:    time.Duration(ttlSeconds) * time.Second,
		cancel: cancel,
		ctx:    ctx,
	}
	if c.Enabled() {
		go c.cleanupLoop()
	}
	return c
}

func (c *Cache) cleanupLoop() {
	interval := c.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Cache) cleanup() {
	now := time.Now()
	c.data.Range(func(key, value interface{}) bool {
		entry := value.(cacheEntry)
		if now.After(entry.ExpireAt) {
			c.data.Delete(key)
		}
		return true
	})
}

// Stop terminates the cleanup goroutine
func (c *Cache) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Get retrieves a cached upstream for the given key
func (c *Cache) Get(key string) (upstream string, ok bool) {
	val, exists := c.data.Load(key)
	if !exists {
		return "", false
	}
	entry := val.(cacheEntry)
	if time.Now().After(entry.ExpireAt) {
		c.data.Delete(key)
		return "", false
	}
	return entry.Upstream, true
}

// Set stores an upstream for the given key
func (c *Cache) Set(key string, upstream string) {
	c.data.Store(key, cacheEntry{
		Upstream: upstream,
		ExpireAt: time.Now().Add(c.ttl),
	})
}

// Enabled returns true if caching is enabled (TTL > 0)
func (c *Cache) Enabled() bool {
	return c.ttl > 0
}
