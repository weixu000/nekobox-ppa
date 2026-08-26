package snell

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// ClientPacketConn implements net.PacketConn over a Snell UDP stream.
// Call NewClientPacketConn after the snell UDP handshake (DialUDP) is complete.
type ClientPacketConn struct {
	conn net.Conn
	rMu  sync.Mutex
	wMu  sync.Mutex
}

// NewClientPacketConn wraps a Snell UDP stream as a net.PacketConn.
// The stream must already have completed the UDP handshake (CommandUDP + CommandTunnel reply).
func NewClientPacketConn(conn net.Conn) net.PacketConn {
	return &ClientPacketConn{conn: conn}
}

func (c *ClientPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	// M.Socksaddr implements net.Addr and carries domain names; handle it
	// directly so domain-name destinations are encoded correctly.
	if sa, ok := addr.(M.Socksaddr); ok {
		return WriteSocksaddrUDPPacket(c.conn, sa, p)
	}
	return WriteUDPPacket(c.conn, addr, p)
}

func (c *ClientPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	return readUDPResponse(c.conn, p)
}

func (c *ClientPacketConn) Close() error {
	// Send a zero-chunk to signal graceful end-of-stream to the server,
	// then close the TCP connection.
	_, _ = c.conn.Write([]byte{})
	return c.conn.Close()
}
func (c *ClientPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *ClientPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *ClientPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *ClientPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// readUDPResponse reads a Snell UDP response from the stream and parses the source address.
// Response format:
//
//	0x03 [len:1] [domain bytes] [port:2] [payload]  — domain (sing-box extension)
//	0x04 [IPv4:4]               [port:2] [payload]  — IPv4
//	0x06 [IPv6:16]              [port:2] [payload]  — IPv6
func readUDPResponse(r io.Reader, p []byte) (int, net.Addr, error) {
	buf := make([]byte, maxPacketSize)
	n, err := r.Read(buf)
	if err != nil {
		if err == ErrZeroChunk {
			return 0, nil, io.EOF
		}
		return 0, nil, err
	}
	if n < 1 {
		return 0, nil, errors.New("snell: empty UDP response")
	}

	var addr net.Addr
	var payloadStart int

	switch buf[0] {
	case 0x03:
		if n < 2 {
			return 0, nil, errors.New("snell: truncated domain UDP response")
		}
		hostLen := int(buf[1])
		if n < 2+hostLen+2 {
			return 0, nil, errors.New("snell: truncated domain UDP response")
		}
		host := string(buf[2 : 2+hostLen])
		port := binary.BigEndian.Uint16(buf[2+hostLen : 2+hostLen+2])
		addr = M.ParseSocksaddrHostPort(host, port)
		payloadStart = 2 + hostLen + 2
	case 0x04:
		if n < 1+net.IPv4len+2 {
			return 0, nil, errors.New("snell: truncated IPv4 UDP response")
		}
		ip := net.IP(buf[1 : 1+net.IPv4len])
		port := binary.BigEndian.Uint16(buf[1+net.IPv4len : 1+net.IPv4len+2])
		addr = &net.UDPAddr{IP: ip, Port: int(port)}
		payloadStart = 1 + net.IPv4len + 2
	case 0x06:
		if n < 1+net.IPv6len+2 {
			return 0, nil, errors.New("snell: truncated IPv6 UDP response")
		}
		ip := net.IP(buf[1 : 1+net.IPv6len])
		port := binary.BigEndian.Uint16(buf[1+net.IPv6len : 1+net.IPv6len+2])
		addr = &net.UDPAddr{IP: ip, Port: int(port)}
		payloadStart = 1 + net.IPv6len + 2
	default:
		return 0, nil, errors.New("snell: invalid UDP response address type")
	}

	payload := buf[payloadStart:n]
	copied := copy(p, payload)
	return copied, addr, nil
}
