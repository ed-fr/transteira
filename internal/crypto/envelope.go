package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// DEKSize is the size in bytes of a per-file data encryption key.
	DEKSize = 32

	// envelopeVersion is the first byte of a wrapped blob.
	envelopeVersion = 1
	// nonceSize is the AES-GCM nonce size.
	nonceSize = 12
	// tagSize is the AES-GCM authentication tag size.
	tagSize = 16
	// envelopeOverhead is the size of a wrapped blob minus its plaintext.
	envelopeOverhead = 1 + nonceSize + tagSize
	// maxBindingLen bounds the tenant, row and file identifiers bound in AADs.
	maxBindingLen = 256

	// envelopeLabel is the domain label of the envelope AAD.
	envelopeLabel = "transteira/v1/envelope"
)

var (
	// ErrUnwrap is returned by Unwrap for any failure. It is deliberately
	// opaque: it does not say whether the purpose, the binding or the key was
	// wrong.
	ErrUnwrap = errors.New("crypto: cannot unwrap secret")
	// ErrInvalidBinding is returned when a tenant, row or file identifier is
	// empty or longer than 256 bytes.
	ErrInvalidBinding = errors.New("crypto: binding identifiers must be non-empty and at most 256 bytes")
	// ErrKeySize is returned when a data encryption key is not DEKSize bytes.
	ErrKeySize = errors.New("crypto: data encryption key must be 32 bytes")
)

// randReader is the source of every random byte of the package. Tests replace
// it to cover failures and to produce deterministic reference vectors.
var randReader io.Reader = rand.Reader

// randomBytes fills b from randReader.
func randomBytes(b []byte) error {
	if _, err := io.ReadFull(randReader, b); err != nil {
		return fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return nil
}

// GenerateDEK returns a new random data encryption key of DEKSize bytes.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if err := randomBytes(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// newAEAD returns AES-256-GCM keyed with key. It panics if key is not 32
// bytes long: every caller validates the length beforehand.
func newAEAD(key []byte) cipher.AEAD {
	if len(key) != DEKSize {
		panic("crypto: internal error: AES-256 key must be 32 bytes")
	}
	// Neither call can fail: the key length is valid and AES has 16-byte blocks.
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

// checkBinding validates identifiers bound into an AAD.
func checkBinding(ids ...string) error {
	for _, id := range ids {
		if id == "" || len(id) > maxBindingLen {
			return ErrInvalidBinding
		}
	}
	return nil
}

// appendLP appends the big-endian uint32 length of s followed by s. Every s is
// a domain label, a purpose or a checked binding identifier, all far shorter
// than 4 GiB.
func appendLP(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, u32(len(s)))
	return append(b, s...)
}

// envelopeAAD builds the AAD of a wrapped blob.
func envelopeAAD(p Purpose, tenantID, rowID string) []byte {
	b := make([]byte, 0, 16+len(envelopeLabel)+len(p)+len(tenantID)+len(rowID))
	b = appendLP(b, envelopeLabel)
	b = appendLP(b, string(p))
	b = appendLP(b, tenantID)
	return appendLP(b, rowID)
}

// Wrap encrypts plaintext (typically a DEK or a configuration secret) with the
// wrapping key of purpose p, bound to tenantID and rowID (the database row
// that stores the blob). The result is version (1) | random nonce (12) |
// AES-256-GCM ciphertext and tag.
func (k *MasterKey) Wrap(p Purpose, tenantID, rowID string, plaintext []byte) ([]byte, error) {
	aead, err := k.wrapperFor(p)
	if err != nil {
		return nil, err
	}
	if err := checkBinding(tenantID, rowID); err != nil {
		return nil, err
	}
	var nonce [nonceSize]byte
	if err := randomBytes(nonce[:]); err != nil {
		return nil, err
	}
	out := make([]byte, 0, envelopeOverhead+len(plaintext))
	out = append(out, envelopeVersion)
	out = append(out, nonce[:]...)
	return aead.Seal(out, nonce[:], plaintext, envelopeAAD(p, tenantID, rowID)), nil
}

// Unwrap decrypts a blob produced by Wrap with the same purpose, tenantID and
// rowID. Any failure (unknown purpose, invalid identifiers, malformed blob,
// wrong key or binding) returns an error matching ErrUnwrap and nothing else
// about the cause, except ErrKeyUnavailable for a nil or destroyed key.
func (k *MasterKey) Unwrap(p Purpose, tenantID, rowID string, blob []byte) ([]byte, error) {
	aead, err := k.wrapperFor(p)
	if errors.Is(err, ErrKeyUnavailable) {
		return nil, fmt.Errorf("%w: %w", ErrUnwrap, err)
	}
	if err != nil || checkBinding(tenantID, rowID) != nil ||
		len(blob) < envelopeOverhead || blob[0] != envelopeVersion {
		return nil, ErrUnwrap
	}
	plaintext, err := aead.Open(nil, blob[1:1+nonceSize], blob[1+nonceSize:], envelopeAAD(p, tenantID, rowID))
	if err != nil {
		return nil, ErrUnwrap
	}
	return plaintext, nil
}
