package snell

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	snellinternal "github.com/reF1nd/sing-snell/internal"
)

// Client manages client-side Snell connections.
type Client struct {
	psk     []byte
	version int
}

// NewClient creates a new Snell client.
func NewClient(psk []byte, version int) (*Client, error) {
	if len(psk) == 0 {
		return nil, errors.New("snell: psk is required")
	}
	if version == 0 {
		version = DefaultVersion
	}
	if version < Version1 || version > Version5 {
		return nil, errors.New("snell: unsupported version")
	}
	return &Client{psk: psk, version: version}, nil
}

// DialContext wraps a raw conn with Snell AEAD framing, writes the TCP request
// header, and returns a conn that reads the server's CommandTunnel reply on
// the first Read.
func (c *Client) DialContext(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	stream := c.wrapStream(conn)

	host := destination.AddrString()
	port := destination.Port

	if err := WriteHeader(stream, host, port, c.version); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &clientConn{Conn: stream}, nil
}

// DialUDP wraps a raw conn with Snell AEAD framing, writes the UDP header,
// waits for CommandTunnel, then returns the conn for UDP packet framing.
func (c *Client) DialUDP(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if c.version < Version3 {
		return nil, errors.New("snell: UDP is not supported before version 3")
	}
	stream := c.wrapStream(conn)
	if err := WriteUDPHeader(stream); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := ReadServerReply(stream); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stream, nil
}

func (c *Client) wrapStream(conn net.Conn) net.Conn {
	if c.version >= Version4 {
		// v4 and v5 share the same TCP wire format (same KDF, AEAD, frame
		// structure). v5 differs only by adding the QUIC Proxy Mode UDP socket.
		return snellinternal.NewV4Conn(conn, c.psk)
	}
	return snellinternal.NewStreamConn(conn, c.psk, c.version)
}

// WrapStream wraps a raw connection with the Snell AEAD framing for the
// client's configured version.  Use this to build pool factory functions.
func (c *Client) WrapStream(conn net.Conn) net.Conn {
	return c.wrapStream(conn)
}

// DialContextWithPool obtains a pooled (already-encrypted) stream, writes the
// request header with CommandConnectV2 (reuse), and returns a PoolConn that
// will send a zero-length frame on Close() and return the stream to the pool.
func (c *Client) DialContextWithPool(ctx context.Context, pool *Pool, destination M.Socksaddr) (net.Conn, error) {
	stream, err := pool.GetContext(ctx)
	if err != nil {
		return nil, err
	}

	host := destination.AddrString()
	port := destination.Port

	if err := WriteHeaderWithReuse(stream, host, port, c.version, true); err != nil {
		_ = stream.Close()
		return nil, err
	}

	return &reuseClientConn{conn: stream, pool: pool}, nil
}

// clientConn is a net.Conn that reads the server's CommandTunnel reply before
// forwarding any application data.
type clientConn struct {
	net.Conn
	replied bool
}

func (c *clientConn) Read(p []byte) (int, error) {
	if !c.replied {
		if err := ReadServerReply(c.Conn); err != nil {
			return 0, err
		}
		c.replied = true
	}
	return c.Conn.Read(p)
}

// reuseClientConn is used for pooled (v4 reuse) connections.  It reads the
// server's CommandTunnel reply on the first Read, converts ErrZeroChunk to
// io.EOF for the caller, and on Close sends a zero-length frame then returns
// the underlying stream to the pool.
//
// serverDone is set atomically when the server's zero-length EOF frame is
// received.  Close only puts the stream back in the pool if serverDone is
// true; otherwise the underlying conn is closed to prevent a protocol desync
// when the connection is reused before all server data has been consumed.
type reuseClientConn struct {
	conn           net.Conn
	pool           *Pool
	replied        bool
	serverDone     atomic.Bool
	closeWriteOnce sync.Once
	closeWriteErr  error
	closeOnce      sync.Once
	closeErr       error
}

func (c *reuseClientConn) Read(p []byte) (int, error) {
	if !c.replied {
		if err := ReadServerReply(c.conn); err != nil {
			return 0, err
		}
		c.replied = true
	}
	n, err := c.conn.Read(p)
	if err == ErrZeroChunk {
		c.serverDone.Store(true)
		return n, io.EOF
	}
	return n, err
}

func (c *reuseClientConn) Write(p []byte) (int, error) {
	return c.conn.Write(p)
}

// CloseWrite sends a zero-length frame to signal the end of the outgoing
// sub-stream without closing the TCP connection.
func (c *reuseClientConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		_, c.closeWriteErr = c.conn.Write([]byte{})
	})
	return c.closeWriteErr
}

// Close half-closes the write side and returns the stream to the pool only if
// the server's EOF frame (zero-length chunk) was already received.  If the
// server has not finished yet, we close the underlying connection outright so
// that subsequent pool users never see leftover data from this sub-stream.
func (c *reuseClientConn) Close() error {
	c.closeOnce.Do(func() {
		if err := c.CloseWrite(); err != nil {
			c.closeErr = err
			_ = c.conn.Close()
			return
		}
		if !c.serverDone.Load() {
			// Server hasn't sent its EOF frame yet; closing the TCP conn is
			// safer than risking a protocol desync on the next pool user.
			_ = c.conn.Close()
			return
		}
		_ = c.conn.SetReadDeadline(time.Time{})
		c.pool.put(c.conn)
	})
	return c.closeErr
}

func (c *reuseClientConn) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *reuseClientConn) RemoteAddr() net.Addr              { return c.conn.RemoteAddr() }
func (c *reuseClientConn) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *reuseClientConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }
func (c *reuseClientConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
