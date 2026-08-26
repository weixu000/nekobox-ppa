package snell

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	snellinternal "github.com/reF1nd/sing-snell/internal"
)

// User is a named Snell user with their own pre-shared key.
type User struct {
	Name string
	PSK  []byte
}

// ServiceConfig configures the Snell server service.
type ServiceConfig struct {
	// PSK is the pre-shared key for single-user mode.
	// Mutually exclusive with Users.
	PSK []byte
	// Users enables multi-user mode.  Each user authenticates with their
	// own PSK; the matching user index is stored in the request context
	// via auth.ContextWithUser so that the caller can identify the user.
	// Takes precedence over PSK when non-empty.
	Users      []User
	Version    int
	UDPEnabled bool
	Handler    N.TCPConnectionHandlerEx
	UDPHandler N.UDPConnectionHandlerEx
	Logger     logger.ContextLogger
}

// Service handles incoming Snell connections on the server side.
type Service struct {
	psk        []byte
	users      []User   // non-empty → multi-user mode
	psks       [][]byte // pre-extracted PSKs from users; avoids per-connection allocation
	version    int
	udpEnabled bool
	handler    N.TCPConnectionHandlerEx
	udpHandler N.UDPConnectionHandlerEx
	logger     logger.ContextLogger
}

// NewService creates a new Snell server service.
func NewService(config ServiceConfig) (*Service, error) {
	if len(config.Users) == 0 && len(config.PSK) == 0 {
		return nil, errors.New("snell: psk or users is required")
	}
	for _, u := range config.Users {
		if len(u.PSK) == 0 {
			return nil, errors.New("snell: PSK is required for user " + u.Name)
		}
	}
	if config.Version == 0 {
		config.Version = DefaultVersion
	}
	if config.Version != Version4 && config.Version != Version5 {
		return nil, errors.New("snell: inbound only supports version 4 or 5")
	}
	svc := &Service{
		psk:        config.PSK,
		users:      config.Users,
		version:    config.Version,
		udpEnabled: config.UDPEnabled,
		handler:    config.Handler,
		udpHandler: config.UDPHandler,
		logger:     config.Logger,
	}
	if len(config.Users) > 0 {
		psks := make([][]byte, len(config.Users))
		for i, u := range config.Users {
			psks[i] = u.PSK
		}
		svc.psks = psks
	}
	return svc, nil
}

// NewConnection handles a new raw TCP connection from a client.
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	var stream net.Conn
	if len(s.users) > 0 {
		var userIdx int
		var err error
		stream, userIdx, err = snellinternal.NewV4ConnMulti(conn, s.psks)
		if err != nil {
			return err
		}
		ctx = auth.ContextWithUser(ctx, userIdx)
	} else {
		stream = snellinternal.NewV4Conn(conn, s.psk)
	}

	// Allocate one buffered reader per connection and reuse it across requests.
	// Re-creating it each iteration would risk discarding bytes buffered beyond
	// the current request's EOF marker.
	br := bufio.NewReader(stream)
	for {
		reuse, err := s.handleRequest(ctx, stream, br, source, onClose)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if !reuse {
			return nil
		}
	}
}

func (s *Service) handleRequest(ctx context.Context, stream net.Conn, br *bufio.Reader, source M.Socksaddr, onClose N.CloseHandlerFunc) (bool, error) {
	version, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if version != ProtocolVersion {
		return false, errors.New("snell: invalid protocol version")
	}

	command, err := br.ReadByte()
	if err != nil {
		return false, err
	}

	if command == CommandPing {
		_, _ = stream.Write([]byte{CommandPong})
		return false, nil
	}

	// Read and discard clientID (length-prefixed).
	clientIDLen, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if clientIDLen > 0 {
		if _, err := io.ReadFull(br, make([]byte, clientIDLen)); err != nil {
			return false, err
		}
	}

	switch command {
	case CommandConnect, CommandConnectV2:
		return s.handleTCP(ctx, stream, br, command == CommandConnectV2, source, onClose)
	case CommandUDP:
		if !s.udpEnabled {
			_ = WriteServerError(stream, 0x01, "UDP is disabled")
			return false, errors.New("snell: UDP is disabled")
		}
		return false, s.handleUDP(ctx, stream, source, onClose)
	default:
		return false, errors.New("snell: unknown command")
	}
}

func (s *Service) handleTCP(ctx context.Context, stream net.Conn, br *bufio.Reader, reuse bool, source M.Socksaddr, onClose N.CloseHandlerFunc) (bool, error) {
	hostLen, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, errors.New("snell: empty host")
	}
	hostBytes := make([]byte, hostLen)
	if _, err := io.ReadFull(br, hostBytes); err != nil {
		return false, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return false, err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	host := string(hostBytes)

	var destination M.Socksaddr
	if ip := net.ParseIP(host); ip != nil {
		destination = M.SocksaddrFromNet(&net.TCPAddr{IP: ip, Port: int(port)})
	} else {
		destination = M.ParseSocksaddrHostPort(host, port)
	}

	doneCh := make(chan struct{})
	conn := &tcpConn{
		Conn:   stream,
		reader: br,
		reuse:  reuse,
		done:   doneCh,
	}

	var connOnClose N.CloseHandlerFunc
	if reuse {
		connOnClose = func(err error) {
			close(doneCh)
		}
	} else {
		connOnClose = func(err error) {
			close(doneCh)
			if onClose != nil {
				onClose(err)
			}
		}
	}

	s.handler.NewConnectionEx(ctx, conn, source, destination, connOnClose)

	if !reuse {
		return false, nil
	}
	// Wait for handler to finish before processing next request on the same stream.
	<-doneCh

	// If the handler never wrote a response (e.g. target unreachable), the
	// client may have already sent a second frame of application data beyond
	// the parsed request header. Reading those bytes as the next sub-request's
	// protocol version would produce a spurious "invalid protocol version"
	// error. Close the stream instead of attempting reuse.
	if !conn.replyWritten {
		return false, nil
	}

	// Drain any plaintext the relay left unread (e.g. the relay's upload
	// goroutine stopped early because the target write failed, leaving the
	// client's remaining data and zero-chunk unconsumed). If the relay already
	// consumed the zero-chunk normally (happy path), skip the drain entirely —
	// reading past that point would eat the start of the next sub-request.
	if !conn.zerochunkConsumed {
		discard := make([]byte, 4096)
		for {
			_, err := conn.Read(discard)
			if err == io.EOF {
				break // zero-chunk received — stream boundary is clean
			}
			if err != nil {
				return false, nil // unexpected error, do not reuse
			}
		}
	}

	return true, nil
}

func (s *Service) handleUDP(ctx context.Context, stream net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	if err := WriteServerReply(stream); err != nil {
		return err
	}

	pc := newSnellPacketConn(stream, source)

	// Peek at the first packet to extract the actual destination so the router
	// can match rules correctly (domain, port, protocol, etc.).  Without this,
	// metadata.Destination would be :0 and all domain/port rules would miss.
	firstBuf := buf.NewPacket()
	firstDest, err := pc.ReadPacket(firstBuf)
	if err != nil {
		firstBuf.Release()
		return err
	}

	s.udpHandler.NewPacketConnectionEx(ctx, &cachedPacketConn{
		PacketConn: pc,
		firstBuf:   firstBuf,
		firstDest:  firstDest,
	}, source, firstDest, onClose)
	return nil
}

// cachedPacketConn wraps a PacketConn with one pre-read packet buffered so that
// the caller can inspect the destination before handing the connection to the
// router, without losing the first packet.
type cachedPacketConn struct {
	N.PacketConn
	firstBuf  *buf.Buffer
	firstDest M.Socksaddr
	consumed  bool
}

func (c *cachedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if !c.consumed {
		c.consumed = true
		_, _ = buffer.Write(c.firstBuf.Bytes())
		c.firstBuf.Release()
		c.firstBuf = nil
		return c.firstDest, nil
	}
	return c.PacketConn.ReadPacket(buffer)
}

func (c *cachedPacketConn) Close() error {
	if c.firstBuf != nil {
		c.firstBuf.Release()
		c.firstBuf = nil
	}
	return c.PacketConn.Close()
}

// tcpConn wraps the Snell stream connection for a single TCP request.
// It prepends the CommandTunnel byte on the first Write, and handles
// connection reuse semantics (v2/v4+).
type tcpConn struct {
	net.Conn
	reader            *bufio.Reader
	reuse             bool
	writeMu           sync.Mutex
	closeOnce         sync.Once
	replyWritten      bool
	zerochunkConsumed bool // set by Read when ErrZeroChunk is seen
	done              chan struct{}
}

func (c *tcpConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err == ErrZeroChunk {
		c.zerochunkConsumed = true
		return n, io.EOF
	}
	return n, err
}

// CloseWrite implements N.WriteCloser.  It sends the Snell end-of-stream
// signal (zero-length frame for reuse, or a full TCP close otherwise) without
// blocking the caller's goroutine beyond that single write.
func (c *tcpConn) CloseWrite() error {
	return c.Close()
}

func (c *tcpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.replyWritten {
		payload := make([]byte, 1+len(p))
		payload[0] = CommandTunnel
		copy(payload[1:], p)
		if _, err := c.Conn.Write(payload); err != nil {
			return 0, err
		}
		c.replyWritten = true
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *tcpConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()

		if !c.replyWritten {
			_ = WriteServerError(c.Conn, 0x65, "Remote EOF")
		} else if c.reuse {
			// Send a zero-length frame to signal end of this sub-stream.
			// The client's PoolConn.Read will translate this ErrZeroChunk
			// into io.EOF, ending the bidirectional copy loop.
			_, _ = c.Conn.Write([]byte{})
		}
		if !c.reuse {
			err = c.Conn.Close()
		}
	})
	return err
}

// snellPacketConn implements N.PacketConn for Snell UDP-over-TCP.
// Each "packet" is a Snell UDP request/response frame carried in the stream.
type snellPacketConn struct {
	conn      net.Conn
	source    M.Socksaddr
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	// deadlineMu serialises Close()'s closed.Store + SetDeadline with any
	// concurrent SetDeadline / SetReadDeadline call from the UDP inactivity
	// timeout wrapper (canceler.TimeoutPacketConn).  Without it there is a
	// TOCTOU window where goroutine A sees closed==false, Close extends the
	// deadline to 5 minutes, and goroutine A then overrides it with a short
	// per-protocol timeout.  The race is benign (Close re-applies the original
	// deadline after acquiring readMu) but this mutex eliminates it entirely.
	deadlineMu sync.Mutex
	closed     bool // guarded by deadlineMu
}

func newSnellPacketConn(conn net.Conn, source M.Socksaddr) *snellPacketConn {
	return &snellPacketConn{
		conn:   conn,
		source: source,
	}
}

func (c *snellPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	raw := make([]byte, maxPacketSize)
	n, err := c.conn.Read(raw)
	if err != nil {
		if err == ErrZeroChunk {
			err = io.EOF
		}
		return M.Socksaddr{}, err
	}
	req, err := ParseUDPRequest(raw[:n])
	if err != nil {
		return M.Socksaddr{}, err
	}
	_, _ = buffer.Write(req.Payload)

	var dest M.Socksaddr
	if req.IP != nil {
		dest = M.SocksaddrFromNet(&net.UDPAddr{IP: req.IP, Port: int(req.Port)})
	} else {
		dest = M.ParseSocksaddrHostPort(req.Host, req.Port)
	}
	return dest, nil
}

func (c *snellPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	_, err := WriteSocksaddrUDPResponse(c.conn, destination, buffer.Bytes())
	return err
}

func (c *snellPacketConn) Close() error {
	c.closeOnce.Do(func() {
		// Hold deadlineMu while marking closed and setting the deadline so
		// that no concurrent SetDeadline / SetReadDeadline call can slip in
		// between and override the 5-minute wait-for-FIN deadline.
		c.deadlineMu.Lock()
		c.closed = true
		deadline := time.Now().Add(5 * time.Minute)
		_ = c.conn.SetDeadline(deadline)
		c.deadlineMu.Unlock()

		go func() {
			// Wait for the ReadPacket goroutine to exit by acquiring readMu.
			// This ensures we don't race on the v4Reader when draining.
			c.readMu.Lock()

			// Re-apply the SAME absolute deadline.  The last ReadPacket
			// iteration may have called SetReadDeadline with a short
			// per-protocol timeout (e.g. 10 s for DNS) just before we set
			// closed=true, leaving the deadline shorter than 5 minutes.
			// Using the original deadline (not time.Now()+5min) ensures the
			// total wait never exceeds 5 minutes from the moment Close() fired.
			_ = c.conn.SetReadDeadline(deadline)

			// Drain until Surge sends its FIN (EOF) or the deadline fires.
			// This also flushes any bytes left in the OS receive buffer
			// before Close(), preventing the kernel from sending RST.
			discard := make([]byte, 512)
			for {
				if _, err := c.conn.Read(discard); err != nil {
					break
				}
			}
			c.readMu.Unlock()
			c.conn.Close()
		}()
	})
	return nil
}

func (c *snellPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline overrides net.Conn.SetDeadline.  After Close() is called the
// snellPacketConn manages its own deadline internally; external calls are
// silently dropped to prevent the UDP inactivity timer from overriding the
// 5-minute "wait-for-client-FIN" deadline with a shorter value.
func (c *snellPacketConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed {
		return nil
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline overrides net.Conn.SetReadDeadline.  After Close() is called
// external deadline updates are silently dropped for the same reason as
// SetDeadline.
func (c *snellPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed {
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

func (c *snellPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
