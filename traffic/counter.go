package traffic

import (
	"sync/atomic"
	"time"
)

// Counter is the interface for traffic accounting
type Counter interface {
	// RecordBytes records traffic for a user session
	// user: username or client identifier
	// host: target host (for metrics)
	// bytesIn: bytes received from client
	// bytesOut: bytes sent to client
	RecordBytes(user string, host string, bytesIn int64, bytesOut int64)
	
	// GetUserTraffic returns total traffic for a user
	GetUserTraffic(user string) (bytesIn int64, bytesOut int64)
	
	// Snapshot returns all user traffic data
	Snapshot() map[string]UserTraffic
	
	// Close stops the counter and releases resources
	Close() error
}

// UserTraffic holds traffic statistics for a single user
type UserTraffic struct {
	User      string    `json:"user"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	UpdatedAt time.Time `json:"updated_at"`
}

// InMemoryCounter is a thread-safe in-memory implementation
type InMemoryCounter struct {
	data map[string]*userStats
}

type userStats struct {
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	updatedAt atomic.Value // time.Time
}

// NewInMemoryCounter creates a new in-memory traffic counter
func NewInMemoryCounter() *InMemoryCounter {
	return &InMemoryCounter{
		data: make(map[string]*userStats),
	}
}

func (c *InMemoryCounter) RecordBytes(user string, host string, bytesIn int64, bytesOut int64) {
	stats := c.getOrCreateStats(user)
	stats.bytesIn.Add(bytesIn)
	stats.bytesOut.Add(bytesOut)
	stats.updatedAt.Store(time.Now())
}

func (c *InMemoryCounter) GetUserTraffic(user string) (bytesIn int64, bytesOut int64) {
	if stats, ok := c.data[user]; ok {
		return stats.bytesIn.Load(), stats.bytesOut.Load()
	}
	return 0, 0
}

func (c *InMemoryCounter) Snapshot() map[string]UserTraffic {
	result := make(map[string]UserTraffic, len(c.data))
	for user, stats := range c.data {
		result[user] = UserTraffic{
			User:      user,
			BytesIn:   stats.bytesIn.Load(),
			BytesOut:  stats.bytesOut.Load(),
			UpdatedAt: stats.updatedAt.Load().(time.Time),
		}
	}
	return result
}

func (c *InMemoryCounter) Close() error {
	return nil
}

func (c *InMemoryCounter) getOrCreateStats(user string) *userStats {
	if stats, ok := c.data[user]; ok {
		return stats
	}
	// Create new stats entry
	stats := &userStats{}
	stats.updatedAt.Store(time.Now())
	c.data[user] = stats
	return stats
}
