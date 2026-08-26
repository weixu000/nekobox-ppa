package snell

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	snellinternal "github.com/reF1nd/sing-snell/internal"
)

// IsQUICLooking mirrors the server's QUIC-looking classifier (sub_41A48).
// Returns true when the first byte of a UDP datagram falls in 0x40..0x7f or
// 0xc0..0xff. Used to classify post-init packets in QUIC proxy mode.
func IsQUICLooking(b byte) bool {
	return snellinternal.IsQUICLooking(b)
}

// IsQUICInitial returns true if the first byte indicates a QUIC long-header
// packet (both the Header Form bit and the Fixed bit are set: byte >= 0xc0).
// Use this for outbound mode selection: route to QUIC proxy only when the
// first local UDP payload is a QUIC long-header packet.
func IsQUICInitial(b byte) bool {
	return b >= 0xc0
}

// QUICProxyPacketConn implements net.PacketConn for the client side of a
// Snell v5 QUIC proxy session.
//
// Lifecycle:
//  1. NewQUICProxyPacketConn encodes the init frame (salt + encrypted frame
//     carrying the target address and the first QUIC Initial payload) and
//     sends it synchronously to the Snell server.
//  2. Subsequent WriteTo calls check the first byte of the payload:
//     - QUIC-looking (0x40-0x7f or 0xc0-0xff): sent raw to the Snell server.
//     - Otherwise: encoded as a fresh init frame with a new salt. Each UDP
//     datagram is independently decryptable because UDP is unreliable:
//     stateful nonce tracking would desync on any dropped or reordered packet.
//  3. ReadFrom reads raw UDP datagrams from the Snell server and returns them
//     with the original QUIC target address as the source.
type QUICProxyPacketConn struct {
	// conn is a connected UDP net.Conn to the Snell server.
	conn        net.Conn
	destination M.Socksaddr // original QUIC target, returned by ReadFrom
	psk         []byte
	host        string
	port        uint16
	// handshakeDone is set to 1 after the first outgoing QUIC short-header
	// (1-RTT, first byte 0x40–0x7f) packet is sent, indicating that the QUIC
	// handshake has completed and the connection is in the data-transfer phase.
	// Once set, a subsequent QUIC Initial packet (first byte 0xc0–0xcf) means
	// the QUIC stack is starting a fresh connection and the Snell server session
	// must be re-established.
	handshakeDone atomic.Bool
}

// NewQUICProxyPacketConn establishes a Snell v5 QUIC proxy session.
//
// conn must be a connected UDP net.Conn to the Snell server (obtained from
// dialer.DialContext with network "udp").
// psk is the pre-shared key.
// destination is the ultimate QUIC target (host:port).
// initPayload is the first QUIC Initial packet to proxy.
func NewQUICProxyPacketConn(
	conn net.Conn,
	psk []byte,
	destination M.Socksaddr,
	initPayload []byte,
) (*QUICProxyPacketConn, error) {
	host := destination.AddrString()
	port := destination.Port

	initPlaintext, err := encodeQUICProxyInitPlaintext(host, port, initPayload)
	if err != nil {
		return nil, err
	}

	enc, err := snellinternal.NewQuicProxyEncCtx(psk)
	if err != nil {
		return nil, err
	}

	frame, err := enc.EncodeInitFrame(initPlaintext)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	pc := &QUICProxyPacketConn{
		conn:        conn,
		destination: destination,
		psk:         psk,
		host:        host,
		port:        port,
	}
	// If the init payload is already a 1-RTT short-header packet (fast-recovery
	// path: the QUIC handshake completed on a previous session), mark the
	// handshake as done immediately. This ensures a subsequent QUIC Initial on
	// the same QUICProxyPacketConn is correctly re-wrapped as a fresh init frame
	// rather than forwarded raw.
	if len(initPayload) > 0 && initPayload[0]&0xc0 == 0x40 {
		pc.handshakeDone.Store(true)
	}
	return pc, nil
}

// sendInitFrame wraps p in a fresh Snell QUIC proxy init frame (new salt, new
// KDF context) and writes it to the server. It is used for:
//   - Non-QUIC-looking payloads (always)
//   - QUIC Initial packets sent after the handshake has completed, which signal
//     a new QUIC connection attempt that requires re-establishing the server
//     session (the server's idle timeout is QUICProxySessionIdleTimeout).
func (c *QUICProxyPacketConn) sendInitFrame(p []byte) (int, error) {
	plaintext, err := encodeQUICProxyInitPlaintext(c.host, c.port, p)
	if err != nil {
		return 0, err
	}
	enc, err := snellinternal.NewQuicProxyEncCtx(c.psk)
	if err != nil {
		return 0, err
	}
	frame, err := enc.EncodeInitFrame(plaintext)
	if err != nil {
		return 0, err
	}
	_, err = c.conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteTo sends a UDP payload through the QUIC proxy.
//
// Forwarding rules:
//   - Short-header (1-RTT, 0x40–0x7f): forward raw; also marks handshake done.
//   - QUIC Initial (0xc0–0xcf) after handshake done: re-wrap as init frame to
//     re-establish an expired server session (fast connection recovery).
//   - Other QUIC-looking (0xc0–0xff, e.g. Handshake/0-RTT/Retry): forward raw.
//   - Non-QUIC-looking: wrap as init frame (independently decryptable).
func (c *QUICProxyPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if IsQUICLooking(p[0]) {
		if p[0]&0xc0 == 0x40 {
			// Short-header (1-RTT): QUIC handshake is complete.
			c.handshakeDone.Store(true)
		} else if p[0]&0xf0 == 0xc0 && c.handshakeDone.Load() {
			// QUIC Initial after handshake: the QUIC stack is starting a new
			// connection (e.g. after the previous one timed out). The server
			// session has likely expired; re-establish it via a fresh init frame.
			return c.sendInitFrame(p)
		}
		_, err := c.conn.Write(p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}

	// Non-QUIC-looking: wrap as a fresh init frame (independently decryptable).
	// Using a stateful nonce across datagrams would desync on any dropped or
	// reordered UDP packet.
	return c.sendInitFrame(p)
}

// ReadFrom reads a raw UDP response from the Snell server.
// Server responses carry no Snell framing or AEAD.
func (c *QUICProxyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	return n, c.destination, nil
}

// ReadPacket implements N.NetPacketConn. The source address is always
// c.destination (the QUIC target), since the Snell server acts as a proxy.
func (c *QUICProxyPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, err := c.conn.Read(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return c.destination, nil
}

// WritePacket implements N.NetPacketConn. The destination address is ignored;
// all writes are forwarded to the connected Snell server socket.
func (c *QUICProxyPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), nil)
	return err
}

func (c *QUICProxyPacketConn) Close() error {
	return c.conn.Close()
}
func (c *QUICProxyPacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }
func (c *QUICProxyPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *QUICProxyPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *QUICProxyPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// ─── Server-side session ─────────────────────────────────────────────────────

// QUICProxySession holds the server-side crypto and state for one QUIC proxy
// session, keyed by client UDP sockaddr.
type QUICProxySession struct {
	psk        []byte
	target     M.Socksaddr
	lastActive time.Time
	mu         sync.Mutex
	// UserIndex is the 0-based index of the user whose PSK authenticated this
	// session.  -1 means single-user mode (PSK not from a Users list).
	UserIndex int
}

// QUICProxySessionIdleTimeout is the server-side idle timeout matching
// snell-server v5.0.1's 60-second QUIC proxy idle timer.
const QUICProxySessionIdleTimeout = 60 * time.Second

// ParseQUICProxyInit parses an incoming init datagram.
// Layout: salt[16] + encrypted_v4_frame(0x01 client_id_len host_len host port_be payload)
func ParseQUICProxyInit(psk, data []byte) (session *QUICProxySession, firstPayload []byte, err error) {
	target, payload, err := decodeQUICProxyDatagram(psk, data)
	if err != nil {
		return nil, nil, err
	}
	return &QUICProxySession{
		psk:        psk,
		target:     target,
		lastActive: time.Now(),
		UserIndex:  -1,
	}, payload, nil
}

// quicParallelThreshold is the minimum PSK count for parallel trial
// decryption in QUIC proxy init parsing.
const quicParallelThreshold = 4

// ParseQUICProxyInitMulti is the multi-user variant of ParseQUICProxyInit.
// For small user lists it tries each PSK sequentially; for larger lists it
// runs all derivations in parallel so wall latency stays O(1×argon2).
func ParseQUICProxyInitMulti(psks [][]byte, data []byte) (session *QUICProxySession, firstPayload []byte, err error) {
	if len(psks) >= quicParallelThreshold {
		return parseQUICProxyInitMultiPar(psks, data)
	}
	return parseQUICProxyInitMultiSeq(psks, data)
}

func parseQUICProxyInitMultiSeq(psks [][]byte, data []byte) (*QUICProxySession, []byte, error) {
	for i, psk := range psks {
		target, payload, decErr := decodeQUICProxyDatagram(psk, data)
		if decErr != nil {
			continue
		}
		return &QUICProxySession{psk: psk, target: target, lastActive: time.Now(), UserIndex: i}, payload, nil
	}
	return nil, nil, errors.New("snell quic proxy: authentication failed: no matching PSK")
}

type quicMatchResult struct {
	idx     int
	psk     []byte
	target  M.Socksaddr
	payload []byte
}

func parseQUICProxyInitMultiPar(psks [][]byte, data []byte) (*QUICProxySession, []byte, error) {
	found := make(chan quicMatchResult, 1)
	var wg sync.WaitGroup

	for i, psk := range psks {
		wg.Add(1)
		go func(idx int, psk []byte) {
			defer wg.Done()
			target, payload, err := decodeQUICProxyDatagram(psk, data)
			if err != nil {
				return
			}
			select {
			case found <- quicMatchResult{idx, psk, target, payload}:
			default:
			}
		}(i, psk)
	}

	go func() { wg.Wait(); close(found) }()

	res, ok := <-found
	if !ok {
		return nil, nil, errors.New("snell quic proxy: authentication failed: no matching PSK")
	}
	return &QUICProxySession{psk: res.psk, target: res.target, lastActive: time.Now(), UserIndex: res.idx}, res.payload, nil
}

// decodeQUICProxyDatagram decodes any QUIC proxy datagram (init or duplicate
// init). Each datagram is independently decryptable: salt[16] + encrypted frame.
func decodeQUICProxyDatagram(psk, data []byte) (target M.Socksaddr, payload []byte, err error) {
	if len(data) < snellinternal.V4SaltSize+snellinternal.V4HeaderCipherSize {
		return M.Socksaddr{}, nil, errors.New("snell quic proxy: datagram too short")
	}

	salt := data[:snellinternal.V4SaltSize]
	frameData := data[snellinternal.V4SaltSize:]

	dec, err := snellinternal.NewQuicProxyDecCtx(psk, salt)
	if err != nil {
		return M.Socksaddr{}, nil, err
	}

	plaintext, err := dec.DecodeFrame(frameData)
	if err != nil {
		return M.Socksaddr{}, nil, err
	}

	return parseQUICProxyInitPlaintext(plaintext)
}

// Target returns the QUIC target address parsed from the init frame.
func (s *QUICProxySession) Target() M.Socksaddr { return s.target }

// IsExpired reports whether the session has been idle longer than QUICProxySessionIdleTimeout.
func (s *QUICProxySession) IsExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActive) > QUICProxySessionIdleTimeout
}

// Touch updates the last-active timestamp.
func (s *QUICProxySession) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActive = time.Now()
}

// DecodeDuplicateInit decrypts a duplicate-init datagram and returns the UDP payload.
// Each duplicate init carries a fresh salt so it is independently decryptable,
// matching the server's per-datagram crypto context (sub_4CD08 + sub_41308).
// No lock needed: s.psk is immutable after construction and decoding is
// entirely local (fresh KDF + AEAD context per call).
func (s *QUICProxySession) DecodeDuplicateInit(data []byte) ([]byte, error) {
	_, payload, err := decodeQUICProxyDatagram(s.psk, data)
	return payload, err
}

// ─── helpers ────────────────────────────────────────────────────────────────

func encodeQUICProxyInitPlaintext(host string, port uint16, payload []byte) ([]byte, error) {
	hostBytes := []byte(host)
	if len(hostBytes) > 255 {
		return nil, errors.New("snell quic proxy: host too long")
	}
	total := 1 + 1 + 1 + len(hostBytes) + 2 + len(payload)
	if total > snellinternal.QuicProxyMaxPayload {
		return nil, errors.New("snell quic proxy: init payload exceeds frame capacity")
	}
	buf := make([]byte, 0, total)
	buf = append(buf, ProtocolVersion)
	buf = append(buf, 0) // client_id_len = 0
	buf = append(buf, byte(len(hostBytes)))
	buf = append(buf, hostBytes...)
	buf = binary.BigEndian.AppendUint16(buf, port)
	buf = append(buf, payload...)
	return buf, nil
}

func parseQUICProxyInitPlaintext(plain []byte) (target M.Socksaddr, payload []byte, err error) {
	if len(plain) < 5 {
		return M.Socksaddr{}, nil, errors.New("snell quic proxy: init plaintext too short")
	}
	if plain[0] != ProtocolVersion {
		return M.Socksaddr{}, nil, errors.New("snell quic proxy: invalid protocol version in init")
	}
	idx := 1
	clientIDLen := int(plain[idx])
	idx++
	if idx+clientIDLen+3 > len(plain) {
		return M.Socksaddr{}, nil, errors.New("snell quic proxy: truncated client_id")
	}
	idx += clientIDLen

	hostLen := int(plain[idx])
	idx++
	if idx+hostLen+2 > len(plain) {
		return M.Socksaddr{}, nil, errors.New("snell quic proxy: truncated host/port")
	}
	host := string(plain[idx : idx+hostLen])
	idx += hostLen
	port := binary.BigEndian.Uint16(plain[idx : idx+2])
	idx += 2

	target = M.ParseSocksaddrHostPort(host, port)
	payload = plain[idx:]
	return target, payload, nil
}
