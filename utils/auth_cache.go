package utils

import (
	"context"
	"sync"
	"time"
)

type AuthCacheEntry struct {
	Upstream string
	ExpireAt time.Time
}

type AuthCache struct {
	data   sync.Map
	ttl    time.Duration
	cancel context.CancelFunc
	ctx    context.Context
}

func NewAuthCache(ttlSeconds int) *AuthCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &AuthCache{
		ttl:    time.Duration(ttlSeconds) * time.Second,
		cancel: cancel,
		ctx:    ctx,
	}
	if c.Enabled() {
		go c.cleanupLoop()
	}
	return c
}

func (c *AuthCache) cleanupLoop() {
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

func (c *AuthCache) cleanup() {
	now := time.Now()
	c.data.Range(func(key, value interface{}) bool {
		entry := value.(AuthCacheEntry)
		if now.After(entry.ExpireAt) {
			c.data.Delete(key)
		}
		return true
	})
}

func (c *AuthCache) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *AuthCache) Get(key string) (upstream string, ok bool) {
	val, exists := c.data.Load(key)
	if !exists {
		return "", false
	}
	entry := val.(AuthCacheEntry)
	if time.Now().After(entry.ExpireAt) {
		c.data.Delete(key)
		return "", false
	}
	return entry.Upstream, true
}

func (c *AuthCache) Set(key string, upstream string) {
	c.data.Store(key, AuthCacheEntry{
		Upstream: upstream,
		ExpireAt: time.Now().Add(c.ttl),
	})
}

func (c *AuthCache) Enabled() bool {
	return c.ttl > 0
}
