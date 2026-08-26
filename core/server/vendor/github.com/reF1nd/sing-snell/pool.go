package snell

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	poolMaxAge  = 15 * time.Second
	poolMaxSize = 10
)

type poolEntry struct {
	conn net.Conn
	at   time.Time
}

// Pool is a connection pool for Snell v4 connection reuse.
// The factory function must return a fully-wrapped (encrypted) stream ready
// for WriteHeaderWithReuse to be called on it.
type Pool struct {
	ch        chan *poolEntry
	factory   func(context.Context) (net.Conn, error)
	closeOnce sync.Once
}

// NewPool creates a new connection pool.
func NewPool(factory func(context.Context) (net.Conn, error)) *Pool {
	return &Pool{
		ch:      make(chan *poolEntry, poolMaxSize),
		factory: factory,
	}
}

// GetContext returns a pooled connection or creates a new one via the factory.
// Expired connections are discarded and a fresh one is created instead.
func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case e := <-p.ch:
			if time.Since(e.at) > poolMaxAge {
				_ = e.conn.Close()
				continue
			}
			return e.conn, nil
		default:
			return p.factory(ctx)
		}
	}
}

// put returns a stream connection to the pool.
// If the pool is full the connection is closed instead of being queued.
func (p *Pool) put(conn net.Conn) {
	e := &poolEntry{conn: conn, at: time.Now()}
	select {
	case p.ch <- e:
	default:
		_ = conn.Close()
	}
}

// Close drains and closes all pooled connections.
func (p *Pool) Close() error {
	p.closeOnce.Do(func() {
		close(p.ch)
		for e := range p.ch {
			_ = e.conn.Close()
		}
	})
	return nil
}
