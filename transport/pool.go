package transport

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Pool provides connection pooling with generics (Go 1.18+)
type Pool struct {
	factory    func() (net.Conn, error)
	isActive   func(net.Conn) bool
	release    func(net.Conn)
	conns      chan net.Conn
	lock       *sync.Mutex
	initialCap int
	maxCap     int
}

// PoolConfig contains pool configuration
type PoolConfig struct {
	Factory    func() (net.Conn, error)
	IsActive   func(net.Conn) bool
	Release    func(net.Conn)
	InitialCap int
	MaxCap     int
}

// NewPool creates a new connection pool
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.MaxCap <= 0 {
		return nil, errors.New("max capacity must be > 0")
	}
	
	p := &Pool{
		factory:    cfg.Factory,
		isActive:   cfg.IsActive,
		release:    cfg.Release,
		conns:      make(chan net.Conn, cfg.MaxCap),
		lock:       &sync.Mutex{},
		initialCap: cfg.InitialCap,
		maxCap:     cfg.MaxCap,
	}
	
	// Initial fill
	if cfg.InitialCap > 0 {
		if err := p.fill(); err != nil {
			return nil, err
		}
		// Background refill goroutine
		go p.refillLoop()
	}
	
	return p, nil
}

func (p *Pool) fill() error {
	p.lock.Lock()
	defer p.lock.Unlock()
	
	for i := 0; i < p.initialCap; i++ {
		if len(p.conns) >= p.initialCap {
			break
		}
		
		conn, err := p.factory()
		if err != nil {
			continue
		}
		
		select {
		case p.conns <- conn:
		default:
			p.release(conn)
		}
	}
	return nil
}

func (p *Pool) refillLoop() {
	if p.initialCap <= 0 {
		return
	}
	
	for {
		time.Sleep(2 * time.Second)
		
		p.lock.Lock()
		if len(p.conns) <= p.initialCap/2 {
			for i := 0; i < p.initialCap; i++ {
				if len(p.conns) >= p.initialCap {
					break
				}
				
				conn, err := p.factory()
				if err != nil {
					continue
				}
				
				select {
				case p.conns <- conn:
				default:
					p.release(conn)
				}
			}
		}
		p.lock.Unlock()
	}
}

// Get retrieves a connection from the pool
func (p *Pool) Get() (net.Conn, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	
	select {
	case conn := <-p.conns:
		if p.isActive(conn) {
			return conn, nil
		}
		p.release(conn)
	default:
		return p.factory()
	}
	
	return p.factory()
}

// Put returns a connection to the pool
func (p *Pool) Put(conn net.Conn) {
	if conn == nil {
		return
	}
	
	p.lock.Lock()
	defer p.lock.Unlock()
	
	if !p.isActive(conn) {
		p.release(conn)
		return
	}
	
	select {
	case p.conns <- conn:
	default:
		p.release(conn)
	}
}

// ReleaseAll closes all connections in the pool
func (p *Pool) ReleaseAll() {
	p.lock.Lock()
	defer p.lock.Unlock()
	
	close(p.conns)
	for conn := range p.conns {
		p.release(conn)
	}
	p.conns = make(chan net.Conn, p.maxCap)
}

// Len returns the current pool size
func (p *Pool) Len() int {
	return len(p.conns)
}
