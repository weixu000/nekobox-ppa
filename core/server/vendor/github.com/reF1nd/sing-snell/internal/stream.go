package internal

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// saltSize is the size of the random salt prepended to each direction.
const saltSize = 16

// streamConn wraps a net.Conn and adds Snell's AEAD framing for v1/v2/v3.
// Each direction has its own salt and therefore its own encryption key.
type streamConn struct {
	net.Conn
	psk    []byte
	ctor   aeadConstructor
	reader *streamReader
	writer *streamWriter
	rOnce  sync.Once
	wOnce  sync.Once
}

// NewStreamConn creates a Snell AEAD stream connection (v1/v2/v3).
func NewStreamConn(conn net.Conn, psk []byte, version int) net.Conn {
	return &streamConn{
		Conn: conn,
		psk:  psk,
		ctor: cipherForVersion(version),
	}
}

func (c *streamConn) initReader() error {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	key := snellKDF(c.psk, salt, c.ctor.keySize)
	aead, err := c.ctor.makeAEAD(key)
	if err != nil {
		return err
	}
	c.reader = newStreamReader(c.Conn, aead)
	return nil
}

func (c *streamConn) initWriter() error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := c.Conn.Write(salt); err != nil {
		return err
	}
	key := snellKDF(c.psk, salt, c.ctor.keySize)
	aead, err := c.ctor.makeAEAD(key)
	if err != nil {
		return err
	}
	c.writer = newStreamWriter(c.Conn, aead)
	return nil
}

func (c *streamConn) Read(b []byte) (int, error) {
	var initErr error
	c.rOnce.Do(func() {
		initErr = c.initReader()
	})
	if initErr != nil {
		return 0, initErr
	}
	return c.reader.Read(b)
}

func (c *streamConn) Write(b []byte) (int, error) {
	var initErr error
	c.wOnce.Do(func() {
		initErr = c.initWriter()
	})
	if initErr != nil {
		return 0, initErr
	}
	return c.writer.Write(b)
}

// streamReader implements reading of AEAD-framed Snell chunks.
type streamReader struct {
	src   io.Reader
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
	index int
	end   int
}

func newStreamReader(r io.Reader, aead cipher.AEAD) *streamReader {
	return &streamReader{
		src:   r,
		aead:  aead,
		nonce: make([]byte, aead.NonceSize()),
		buf:   make([]byte, MaxPacketSize+aead.Overhead()),
	}
}

// readChunk decrypts one AEAD chunk into r.buf and updates index/end.
func (r *streamReader) readChunk() error {
	// Read and decrypt the 2-byte length field.
	lenBuf := make([]byte, 2+r.aead.Overhead())
	if _, err := io.ReadFull(r.src, lenBuf); err != nil {
		return err
	}
	lenPlain, err := r.aead.Open(lenBuf[:0], r.nonce, lenBuf, nil)
	if err != nil {
		return err
	}
	incrementNonce(r.nonce)
	length := int(binary.BigEndian.Uint16(lenPlain))

	// Read and decrypt the payload.
	payloadBuf := r.buf[:length+r.aead.Overhead()]
	if _, err := io.ReadFull(r.src, payloadBuf); err != nil {
		return err
	}
	_, err = r.aead.Open(r.buf[:0], r.nonce, payloadBuf, nil)
	if err != nil {
		return err
	}
	incrementNonce(r.nonce)
	r.index = 0
	r.end = length
	return nil
}

func (r *streamReader) Read(b []byte) (int, error) {
	for {
		if r.index < r.end {
			n := copy(b, r.buf[r.index:r.end])
			r.index += n
			return n, nil
		}
		if err := r.readChunk(); err != nil {
			return 0, err
		}
		if r.end == 0 {
			return 0, ErrZeroChunk
		}
	}
}

// streamWriter implements writing of AEAD-framed Snell chunks.
type streamWriter struct {
	dst   io.Writer
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
	mu    sync.Mutex
}

func newStreamWriter(w io.Writer, aead cipher.AEAD) *streamWriter {
	bufSize := 2 + aead.Overhead() + MaxPacketSize + aead.Overhead()
	return &streamWriter{
		dst:   w,
		aead:  aead,
		nonce: make([]byte, aead.NonceSize()),
		buf:   make([]byte, bufSize),
	}
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(p) == 0 {
		return 0, w.writeChunk(nil)
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPacketSize {
			chunk = chunk[:MaxPacketSize]
		}
		if err := w.writeChunk(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (w *streamWriter) writeChunk(p []byte) error {
	overhead := w.aead.Overhead()

	// Encrypt the 2-byte length.
	binary.BigEndian.PutUint16(w.buf[:2], uint16(len(p)))
	_ = w.aead.Seal(w.buf[:0], w.nonce, w.buf[:2], nil)
	incrementNonce(w.nonce)

	// Encrypt the payload.
	payloadCipher := w.aead.Seal(w.buf[2+overhead:2+overhead], w.nonce, p, nil)
	incrementNonce(w.nonce)

	_, err := w.dst.Write(w.buf[:2+overhead+len(payloadCipher)])
	return err
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
