package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// ErrZeroChunk is returned by stream/v4 readers when a zero-length frame is
// received. It signals the end of one sub-stream in a connection-reuse session.
var ErrZeroChunk = errors.New("snell: zero chunk")

const (
	Version1 = 1
	Version2 = 2
	Version3 = 3
	Version4 = 4
	Version5 = 5

	// DefaultVersion is v4: the most widely deployed version and the only one
	// supported by mihomo's server. Set explicitly if you need v1–v3.
	DefaultVersion = Version4

	// MaxPacketSize is the maximum plaintext payload size per packet/chunk.
	MaxPacketSize = 0x3FFF
)

func newAES128GCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newChacha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// snellKDF derives an encryption key from psk and salt using the Snell KDF (argon2id).
func snellKDF(psk, salt []byte, keySize int) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:keySize]
}

type aeadConstructor struct {
	keySize  int
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func cipherForVersion(version int) aeadConstructor {
	if version == Version1 {
		return aeadConstructor{keySize: 32, makeAEAD: newChacha20Poly1305}
	}
	return aeadConstructor{keySize: 16, makeAEAD: newAES128GCM}
}
