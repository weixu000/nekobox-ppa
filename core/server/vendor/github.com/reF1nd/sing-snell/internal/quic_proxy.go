package internal

import (
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// IsQUICLooking returns true if the first byte of a UDP datagram matches the
// server's QUIC-looking classifier (sub_41A48): first byte in 0x40..0x7f or
// 0xc0..0xff. Used both for outgoing packet classification and QUIC proxy
// salt first-byte filtering.
func IsQUICLooking(b byte) bool {
	return (b >= 0x40 && b <= 0x7f) || b >= 0xc0
}

// NewQUICProxySalt generates a 16-byte random salt into dst, retrying until
// the first byte avoids the QUIC-looking range (0x40-0x7f, 0xc0-0xff).
// This prevents the server from discarding the init frame as a bare QUIC packet.
func NewQUICProxySalt(dst []byte) error {
	for {
		if _, err := io.ReadFull(cryptorand.Reader, dst); err != nil {
			return err
		}
		if !IsQUICLooking(dst[0]) {
			return nil
		}
	}
}

// quicProxyMaxPayload is the maximum encrypted payload size per QUIC proxy frame,
// derived from the 1472-byte UDP datagram MTU used for QUIC proxy contexts.
//
// Available for plaintext payload:
//
//	1472 (datagram) - 16 (salt, first frame only) - 23 (header cipher) - 16 (GCM tag) = 1417
//
// For subsequent frames the salt is absent but the conservative limit still applies.
const QuicProxyMaxPayload = 1417

// V4SaltSize is the per-direction salt size exported for use by the public package.
const V4SaltSize = v4SaltSize

// V4HeaderCipherSize is the encrypted frame header size exported for public use.
const V4HeaderCipherSize = v4HeaderCipherSize

// QuicProxyEncCtx holds crypto state for encoding QUIC proxy frames.
// Frames always use padding=0 per the server's QUIC proxy context (sub_41308).
type QuicProxyEncCtx struct {
	aead  cipher.AEAD
	nonce [v4NonceSize]byte
	salt  [v4SaltSize]byte
	// saltSent tracks whether the 16-byte salt prefix has been included.
	saltSent bool
}

// NewQuicProxyEncCtx generates a fresh QUIC proxy encryption context for
// the given pre-shared key.  The salt is generated with first-byte filtering.
func NewQuicProxyEncCtx(psk []byte) (*QuicProxyEncCtx, error) {
	var salt [v4SaltSize]byte
	if err := NewQUICProxySalt(salt[:]); err != nil {
		return nil, err
	}
	aead, err := v4AEAD(psk, salt[:])
	if err != nil {
		return nil, err
	}
	return &QuicProxyEncCtx{aead: aead, salt: salt}, nil
}

// Salt returns the 16-byte salt for this context.  Include it as a prefix on
// the very first frame (init frame); duplicate init frames must NOT include it.
func (c *QuicProxyEncCtx) Salt() []byte {
	return c.salt[:]
}

// EncodeInitFrame encodes payload as a QUIC proxy init frame, prepending the
// salt prefix only on the first call.  Returns the full datagram bytes.
func (c *QuicProxyEncCtx) EncodeInitFrame(payload []byte) ([]byte, error) {
	return c.encodeFrame(payload, !c.saltSent)
}

func (c *QuicProxyEncCtx) encodeFrame(payload []byte, includeSalt bool) ([]byte, error) {
	if len(payload) > MaxPacketSize {
		return nil, errors.New("snell quic proxy: payload too large")
	}

	header := [v4HeaderPlainSize]byte{4}
	// padding_len = 0 (bytes 3-4 zero), payload_len in bytes 5-6
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))

	headerCipher := c.aead.Seal(nil, c.nonce[:], header[:], nil)
	incrementV4Nonce(c.nonce[:])

	var payloadCipher []byte
	if len(payload) > 0 {
		payloadCipher = c.aead.Seal(nil, c.nonce[:], payload, nil)
		incrementV4Nonce(c.nonce[:])
	}

	totalLen := len(headerCipher) + len(payloadCipher)
	if includeSalt {
		totalLen += v4SaltSize
	}
	frame := make([]byte, 0, totalLen)
	if includeSalt {
		frame = append(frame, c.salt[:]...)
		c.saltSent = true
	}
	frame = append(frame, headerCipher...)
	frame = append(frame, payloadCipher...)
	return frame, nil
}

// QuicProxyDecCtx holds crypto state for decoding QUIC proxy frames.
// Must be created from the salt extracted from the peer's init frame.
type QuicProxyDecCtx struct {
	aead  cipher.AEAD
	nonce [v4NonceSize]byte
}

// NewQuicProxyDecCtx creates a decryption context from a pre-shared key and
// the 16-byte salt that was prepended to the peer's init frame.
func NewQuicProxyDecCtx(psk, salt []byte) (*QuicProxyDecCtx, error) {
	aead, err := v4AEAD(psk, salt)
	if err != nil {
		return nil, err
	}
	return &QuicProxyDecCtx{aead: aead}, nil
}

// DecodeInitFrame decodes a frame that starts immediately after the 16-byte
// salt (i.e., the salt must already have been stripped before calling).
// Returns the plaintext payload.
func (c *QuicProxyDecCtx) DecodeFrame(data []byte) ([]byte, error) {
	if len(data) < v4HeaderCipherSize {
		return nil, errors.New("snell quic proxy: frame too short for header")
	}

	headerCT := make([]byte, v4HeaderCipherSize)
	copy(headerCT, data[:v4HeaderCipherSize])
	header, err := c.aead.Open(headerCT[:0], c.nonce[:], headerCT, nil)
	incrementV4Nonce(c.nonce[:])
	if err != nil {
		return nil, errors.New("snell quic proxy: header decrypt failed")
	}
	if len(header) != v4HeaderPlainSize || header[0] != 4 {
		return nil, errors.New("snell quic proxy: invalid frame header")
	}

	paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(header[5:7]))

	if paddingLen != 0 {
		return nil, errors.New("snell quic proxy: unexpected padding in QUIC proxy frame")
	}
	if payloadLen == 0 {
		return nil, ErrZeroChunk
	}

	expected := v4HeaderCipherSize + payloadLen + c.aead.Overhead()
	if len(data) < expected {
		return nil, errors.New("snell quic proxy: frame truncated")
	}

	payloadCT := make([]byte, payloadLen+c.aead.Overhead())
	copy(payloadCT, data[v4HeaderCipherSize:expected])
	payload, err := c.aead.Open(payloadCT[:0], c.nonce[:], payloadCT, nil)
	incrementV4Nonce(c.nonce[:])
	if err != nil {
		return nil, errors.New("snell quic proxy: payload decrypt failed")
	}
	return payload, nil
}
