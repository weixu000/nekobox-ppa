package internal

import (
	"bytes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	"math/bits"
	"net"
	"sync"
	"time"
)

const (
	v4SaltSize           = 16
	v4NonceSize          = 12
	v4HeaderPlainSize    = 7
	v4HeaderCipherSize   = v4HeaderPlainSize + 16
	v4FrameSize          = 1460
	v4InitialPaddingMin  = 0x100
	v4InitialPaddingSpan = 0x100
)

// v4Conn implements the Snell v4 frame-based encryption with connection reuse
// support (ErrZeroChunk signaling).
type v4Conn struct {
	net.Conn
	psk   []byte
	rOnce sync.Once
	rErr  error
	r     *v4Reader
	wOnce sync.Once
	wErr  error
	w     *v4Writer
}

// NewV4Conn creates a Snell v4-framed connection.  v4 and v5 TCP share the
// same wire format (same KDF, AEAD, and frame structure).  Both support
// connection reuse via ErrZeroChunk signalling.
func NewV4Conn(conn net.Conn, psk []byte) net.Conn {
	return &v4Conn{Conn: conn, psk: psk}
}

// v4MultiParallelThreshold is the minimum PSK count at which parallel
// argon2 derivation is used.  Below this value the goroutine overhead
// (~2 µs per goroutine) exceeds the potential wall-time saving.
const v4MultiParallelThreshold = 4

// NewV4ConnMulti tries each PSK to authenticate the incoming connection.
// It reads the 16-byte salt and the first encrypted frame header (23 bytes)
// from conn, then attempts to derive an AEAD and decrypt the header for each
// PSK.  For small user lists the derivations run sequentially; for larger
// lists they run in parallel so wall latency stays O(1×argon2) regardless of
// the number of users.  The returned conn must be used in place of the
// original.
func NewV4ConnMulti(conn net.Conn, psks [][]byte) (net.Conn, int, error) {
	salt := make([]byte, v4SaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, -1, err
	}
	headerCipher := make([]byte, v4HeaderCipherSize)
	if _, err := io.ReadFull(conn, headerCipher); err != nil {
		return nil, -1, err
	}

	if len(psks) >= v4MultiParallelThreshold {
		return newV4ConnMultiPar(conn, salt, headerCipher, psks)
	}
	return newV4ConnMultiSeq(conn, salt, headerCipher, psks)
}

func newV4ConnMultiSeq(conn net.Conn, salt, headerCipher []byte, psks [][]byte) (net.Conn, int, error) {
	var zeroNonce [v4NonceSize]byte
	for i, psk := range psks {
		aead, err := v4AEAD(psk, salt)
		if err != nil {
			continue
		}
		if _, err := aead.Open(make([]byte, 0, v4HeaderPlainSize), zeroNonce[:], headerCipher, nil); err == nil {
			r := &v4Reader{
				Reader: io.MultiReader(bytes.NewReader(headerCipher), conn),
				aead:   aead,
			}
			vc := &v4Conn{Conn: conn, psk: psk}
			vc.rOnce.Do(func() { vc.r = r })
			return vc, i, nil
		}
	}
	return nil, -1, errors.New("snell: authentication failed: no matching PSK")
}

type v4MatchResult struct {
	idx  int
	aead cipher.AEAD
	psk  []byte
}

// newV4ConnMultiPar runs argon2 derivations for all PSKs in parallel.
// Each goroutine derives its own AEAD and attempts the trial decryption.
// The first successful result wins; others discard their result via the
// non-blocking send.  A separate waiter goroutine closes the channel when
// all workers finish, signalling "no match" to the receiver.
func newV4ConnMultiPar(conn net.Conn, salt, headerCipher []byte, psks [][]byte) (net.Conn, int, error) {
	found := make(chan v4MatchResult, 1)
	var wg sync.WaitGroup

	for i, psk := range psks {
		wg.Add(1)
		go func(idx int, psk []byte) {
			defer wg.Done()
			aead, err := v4AEAD(psk, salt)
			if err != nil {
				return
			}
			var zn [v4NonceSize]byte // stack-local zero nonce; no sharing
			if _, err := aead.Open(make([]byte, 0, v4HeaderPlainSize), zn[:], headerCipher, nil); err == nil {
				select {
				case found <- v4MatchResult{idx, aead, psk}:
				default: // another goroutine already won
				}
			}
		}(i, psk)
	}

	// Close the channel once all workers finish.  A closed empty channel
	// unblocks the receive below with ok=false (no match).
	go func() { wg.Wait(); close(found) }()

	res, ok := <-found
	if !ok {
		return nil, -1, errors.New("snell: authentication failed: no matching PSK")
	}
	r := &v4Reader{
		Reader: io.MultiReader(bytes.NewReader(headerCipher), conn),
		aead:   res.aead,
	}
	vc := &v4Conn{Conn: conn, psk: res.psk}
	vc.rOnce.Do(func() { vc.r = r })
	return vc, res.idx, nil
}

func (c *v4Conn) initReader() error {
	salt := make([]byte, v4SaltSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := v4AEAD(c.psk, salt)
	if err != nil {
		return err
	}
	c.r = &v4Reader{Reader: c.Conn, aead: aead}
	return nil
}

func (c *v4Conn) initWriter() error {
	w, err := newV4Writer(c.Conn, c.psk)
	if err != nil {
		return err
	}
	c.w = w
	return nil
}

func (c *v4Conn) ensureReader() error {
	c.rOnce.Do(func() { c.rErr = c.initReader() })
	return c.rErr
}

func (c *v4Conn) ensureWriter() error {
	c.wOnce.Do(func() { c.wErr = c.initWriter() })
	return c.wErr
}

func (c *v4Conn) Read(b []byte) (int, error) {
	if err := c.ensureReader(); err != nil {
		return 0, err
	}
	return c.r.Read(b)
}

func (c *v4Conn) Write(b []byte) (int, error) {
	if err := c.ensureWriter(); err != nil {
		return 0, err
	}
	return c.w.Write(b)
}

// CloseWrite closes only the write side of the underlying connection,
// sending a TCP FIN without closing the read side.  If the underlying
// net.Conn does not support half-close (e.g. is not a *net.TCPConn),
// this is a no-op and returns nil.
func (c *v4Conn) CloseWrite() error {
	type halfCloser interface {
		CloseWrite() error
	}
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return nil
}

// WritePacketFrame writes b as a single atomic v4 frame so the peer's Read
// returns the entire UDP payload at once.
func (c *v4Conn) WritePacketFrame(b []byte) (int, error) {
	return c.writeFrame(b)
}

// writeFrame writes a single frame, bypassing the chunk-size limit (for UDP).
func (c *v4Conn) writeFrame(b []byte) (int, error) {
	if len(b) > MaxPacketSize {
		return 0, errors.New("snell v4: frame too large")
	}
	if err := c.ensureWriter(); err != nil {
		return 0, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	if err := c.w.writeFrameLocked(b, c.w.nextFramePaddingLength(len(b))); err != nil {
		return 0, err
	}
	return len(b), nil
}

func v4AEAD(psk, salt []byte) (cipher.AEAD, error) {
	key := snellKDF(psk, salt, 16)
	return newAES128GCM(key)
}

type v4Reader struct {
	io.Reader
	aead  cipher.AEAD
	nonce [v4NonceSize]byte
	buf   []byte
	mu    sync.Mutex
}

func (r *v4Reader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.buf) == 0 {
		payload, err := r.readFrame()
		if err != nil {
			return 0, err
		}
		r.buf = payload
	}

	n := copy(b, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *v4Reader) readFrame() ([]byte, error) {
	headerCipher := make([]byte, v4HeaderCipherSize)
	if _, err := io.ReadFull(r.Reader, headerCipher); err != nil {
		return nil, err
	}
	header, err := r.aead.Open(headerCipher[:0], r.nonce[:], headerCipher, nil)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	if len(header) != v4HeaderPlainSize || header[0] != 4 {
		return nil, errors.New("snell v4: invalid frame header")
	}

	paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
	if payloadLength == 0 {
		if paddingLength != 0 {
			return nil, errors.New("snell v4: zero chunk with padding")
		}
		return nil, ErrZeroChunk
	}
	if payloadLength > MaxPacketSize || paddingLength > MaxPacketSize {
		return nil, errors.New("snell v4: frame too large")
	}

	payloadCipherLength := payloadLength + r.aead.Overhead()
	frame := make([]byte, paddingLength+payloadCipherLength)
	if _, err := io.ReadFull(r.Reader, frame); err != nil {
		return nil, err
	}
	if paddingLength > 0 {
		swapPadding(frame[:paddingLength], frame[paddingLength:])
	}

	payloadCipher := frame[paddingLength:]
	payload, err := r.aead.Open(payloadCipher[:0], r.nonce[:], payloadCipher, nil)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

type v4Writer struct {
	io.Writer
	aead                 cipher.AEAD
	nonce                [v4NonceSize]byte
	salt                 [v4SaltSize]byte
	saltSent             bool
	initialPaddingLength uint16
	payloadLimit         uint16
	lastWrite            time.Time
	mu                   sync.Mutex
}

func newV4Writer(w io.Writer, psk []byte) (*v4Writer, error) {
	var salt [v4SaltSize]byte
	if _, err := io.ReadFull(cryptorand.Reader, salt[:]); err != nil {
		return nil, err
	}
	aead, err := v4AEAD(psk, salt[:])
	if err != nil {
		return nil, err
	}
	paddingDelta, err := cryptoRandomInt(v4InitialPaddingSpan)
	if err != nil {
		return nil, err
	}
	return &v4Writer{
		Writer:               w,
		aead:                 aead,
		salt:                 salt,
		initialPaddingLength: uint16(v4InitialPaddingMin + paddingDelta),
	}, nil
}

func (w *v4Writer) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(b) == 0 {
		return 0, w.writeFrameLocked(nil, 0)
	}

	written := 0
	for written < len(b) {
		payloadLimit := int(w.nextPayloadLimit())
		if payloadLimit <= 0 || payloadLimit > MaxPacketSize {
			payloadLimit = MaxPacketSize
		}
		end := written + payloadLimit
		if end > len(b) {
			end = len(b)
		}
		paddingLength := w.nextFramePaddingLength(end - written)
		if err := w.writeFrameLocked(b[written:end], paddingLength); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *v4Writer) nextPayloadLimit() uint16 {
	now := time.Now()
	var payloadLimit uint16
	switch {
	case w.lastWrite.IsZero():
		payloadLimit = v4FrameSize - 55 - w.initialPaddingLength
	case now.Sub(w.lastWrite) > 30*time.Second:
		payloadLimit = v4FrameSize - 39
	default:
		payloadLimit = w.payloadLimit
	}
	w.lastWrite = now

	if payloadLimit <= MaxPacketSize-1 {
		next := int(payloadLimit) + v4FrameSize - 39
		if next > MaxPacketSize {
			next = MaxPacketSize
		}
		w.payloadLimit = uint16(next)
	} else {
		w.payloadLimit = MaxPacketSize
	}
	return payloadLimit
}

func (w *v4Writer) nextFramePaddingLength(payloadLength int) int {
	if w.saltSent || payloadLength == 0 {
		return 0
	}
	return int(w.initialPaddingLength)
}

func (w *v4Writer) writeFrameLocked(payload []byte, paddingLength int) error {
	if len(payload) > MaxPacketSize || paddingLength > MaxPacketSize {
		return errors.New("snell v4: frame too large")
	}
	if len(payload) == 0 && paddingLength != 0 {
		return errors.New("snell v4: zero chunk with padding")
	}

	header := make([]byte, v4HeaderPlainSize)
	header[0] = 4
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLength))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))

	headerCipher := w.aead.Seal(nil, w.nonce[:], header, nil)
	incrementV4Nonce(w.nonce[:])

	var payloadCipher []byte
	if len(payload) > 0 {
		payloadCipher = w.aead.Seal(nil, w.nonce[:], payload, nil)
		incrementV4Nonce(w.nonce[:])
	}

	frameLength := len(headerCipher) + paddingLength + len(payloadCipher)
	if !w.saltSent {
		frameLength += v4SaltSize
	}
	frame := make([]byte, 0, frameLength)
	if !w.saltSent {
		frame = append(frame, w.salt[:]...)
		w.saltSent = true
	}
	frame = append(frame, headerCipher...)
	if paddingLength > 0 {
		padding, err := makeV4Padding(payloadCipher, paddingLength)
		if err != nil {
			return err
		}
		swapPadding(padding, payloadCipher)
		frame = append(frame, padding...)
	}
	frame = append(frame, payloadCipher...)

	return writeFull(w.Writer, frame)
}

func swapPadding(padding, payloadCipher []byte) {
	limit := len(padding)
	if len(payloadCipher) < limit {
		limit = len(payloadCipher)
	}
	for i := 0; i < limit; i += 2 {
		padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
	}
}

func makeV4Padding(payloadCipher []byte, paddingLength int) ([]byte, error) {
	if paddingLength <= 0 {
		return nil, nil
	}

	payloadOnes := countV4PayloadOnes(payloadCipher)
	payloadZeros := 8*len(payloadCipher) - payloadOnes
	if payloadZeros <= 0 {
		return makeV4RandomPadding(paddingLength)
	}

	ratio := float64(payloadOnes) / float64(payloadZeros)
	if ratio <= 0.5 || ratio >= 1.6 {
		return makeV4RandomPadding(paddingLength)
	}

	targetRatioBase := 1.6
	if payloadZeros < payloadOnes {
		targetRatioBase = 0.4
	}
	jitter, err := randomUnitFloat64()
	if err != nil {
		return nil, err
	}
	targetRatio := targetRatioBase + jitter/10
	totalBits := 8 * (paddingLength + len(payloadCipher))
	targetOnes := int(float64(totalBits)*(targetRatio/(targetRatio+1)) - float64(payloadOnes))
	if targetOnes < 0 || targetOnes > 8*paddingLength {
		return makeV4RandomPadding(paddingLength)
	}

	return makeV4BitCountPadding(paddingLength, targetOnes)
}

func countV4PayloadOnes(payloadCipher []byte) int {
	limit := len(payloadCipher) &^ 3
	ones := 0
	for _, b := range payloadCipher[:limit] {
		ones += bits.OnesCount8(b)
	}
	return ones
}

func makeV4RandomPadding(length int) ([]byte, error) {
	padding := make([]byte, length)
	_, err := io.ReadFull(cryptorand.Reader, padding)
	return padding, err
}

func makeV4BitCountPadding(length, oneBits int) ([]byte, error) {
	totalBits := 8 * length
	if oneBits < 0 || oneBits > totalBits {
		return nil, errors.New("snell v4: invalid padding bit count")
	}

	bitset := make([]byte, totalBits)
	for i := 0; i < oneBits; i++ {
		bitset[i] = 1
	}
	for i := totalBits - 1; i > 0; i-- {
		j, err := cryptoRandomInt(i + 1)
		if err != nil {
			return nil, err
		}
		bitset[i], bitset[j] = bitset[j], bitset[i]
	}

	padding := make([]byte, length)
	for i, bit := range bitset {
		if bit == 1 {
			padding[i/8] |= 1 << uint(i%8)
		}
	}
	return padding, nil
}

func cryptoRandomInt(max int) (int, error) {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randomUnitFloat64() (float64, error) {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0, err
	}
	return float64(n.Int64()) / math.Exp2(53), nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func incrementV4Nonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
