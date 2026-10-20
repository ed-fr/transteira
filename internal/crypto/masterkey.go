package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// MasterKeySize is the size in bytes of a master key.
const MasterKeySize = 32

const (
	// maxMasterKeyFileSize bounds the read of a master key file.
	maxMasterKeyFileSize = 1024
	// keyIDLabel is the HMAC message used to derive the public key identifier.
	keyIDLabel = "transteira/v1/key-id"
	// keyIDPrefix starts every master key identifier.
	keyIDPrefix = "mk_"
	// keyIDBytes is the number of HMAC bytes kept in the identifier (64 bits).
	keyIDBytes = 8
	// wrapInfoPrefix is the HKDF info prefix of the per-purpose wrapping keys.
	wrapInfoPrefix = "transteira/v1/wrap/"
)

var (
	// ErrInvalidMasterKey is returned when a master key is not exactly 32 bytes
	// encoded in standard base64. The offending content is never included.
	ErrInvalidMasterKey = errors.New("crypto: invalid master key: expected 32 bytes encoded in standard base64")
	// ErrKeyUnavailable is returned when a nil or destroyed master key is used.
	ErrKeyUnavailable = errors.New("crypto: master key unavailable")
	// ErrUnknownPurpose is returned for a Purpose that is not defined by this
	// package.
	ErrUnknownPurpose = errors.New("crypto: unknown key purpose")
)

// Purpose names what a wrapped secret is used for. Each purpose has its own
// wrapping key derived from the master key, so that a blob wrapped for one
// purpose can never be unwrapped for another.
type Purpose string

const (
	// PurposeDEK wraps per-file data encryption keys.
	PurposeDEK Purpose = "dek"
	// PurposeSecret wraps configuration secrets such as SMTP passwords.
	PurposeSecret Purpose = "secret"
)

// purposes lists every valid Purpose.
var purposes = []Purpose{PurposeDEK, PurposeSecret}

// MasterKey is the master key of the instance. It never exposes its bytes:
// every textual representation (String, GoString, Format, LogValue) only shows
// its public identifier. Its methods are safe for concurrent use, except
// Destroy. Copying a MasterKey value copies a reference, never the key bytes.
type MasterKey struct {
	m *keyMaterial
}

// keyMaterial holds the secret parts of a MasterKey behind a pointer, so that
// printing a MasterKey struct value can only reveal an address.
type keyMaterial struct {
	key       [MasterKeySize]byte
	id        string
	wrap      map[Purpose]cipher.AEAD
	mac       map[MACPurpose][]byte
	destroyed bool
}

// ParseMasterKey parses a master key encoded as 32 bytes in standard base64
// (44 characters with padding). Leading and trailing whitespace, such as a
// final newline, is tolerated; anything else is refused with
// ErrInvalidMasterKey, as is a degenerate key made of a single repeated byte
// (such as all zeros).
func ParseMasterKey(b []byte) (*MasterKey, error) {
	text := bytes.TrimSpace(b)
	if len(text) != base64.StdEncoding.EncodedLen(MasterKeySize) {
		return nil, ErrInvalidMasterKey
	}
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	defer clear(raw)
	n, err := base64.StdEncoding.Strict().Decode(raw, text)
	if err != nil || n != MasterKeySize || degenerate(raw[:MasterKeySize]) {
		return nil, ErrInvalidMasterKey
	}
	return newMasterKey(raw[:MasterKeySize]), nil
}

// degenerate reports whether key is a single repeated byte (all zeros
// included): a placeholder or a broken generator, never a random key.
func degenerate(key []byte) bool {
	return bytes.Count(key, key[:1]) == len(key)
}

// LoadMasterKey reads and parses the master key file at path (see
// ParseMasterKey). Files larger than 1 KiB are refused without being read
// entirely.
func LoadMasterKey(path string) (*MasterKey, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("crypto: open master key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxMasterKeyFileSize+1))
	defer clear(data)
	if err != nil {
		return nil, fmt.Errorf("crypto: read master key file: %w", err)
	}
	if len(data) > maxMasterKeyFileSize {
		return nil, fmt.Errorf("%w: file larger than %d bytes", ErrInvalidMasterKey, maxMasterKeyFileSize)
	}
	return ParseMasterKey(data)
}

// newMasterKey builds a MasterKey from 32 raw bytes, deriving its identifier,
// its wrapping keys and its MAC keys once.
func newMasterKey(raw []byte) *MasterKey {
	m := &keyMaterial{wrap: make(map[Purpose]cipher.AEAD, len(purposes))}
	copy(m.key[:], raw)

	mac := hmac.New(sha256.New, m.key[:])
	mac.Write([]byte(keyIDLabel))
	m.id = keyIDPrefix + hex.EncodeToString(mac.Sum(nil)[:keyIDBytes])

	for _, p := range purposes {
		// hkdf.Key cannot fail here: the requested length (32 bytes) is far
		// below the HKDF-SHA256 limit and the secret is 256 bits long.
		wk, _ := hkdf.Key(sha256.New, m.key[:], nil, wrapInfoPrefix+string(p), MasterKeySize)
		m.wrap[p] = newAEAD(wk)
		clear(wk)
	}
	m.mac = deriveMACKeys(m.key[:])
	return &MasterKey{m: m}
}

// ID returns the public identifier of the key: "mk_" followed by the
// hexadecimal encoding of the first 64 bits of HMAC-SHA256(key,
// "transteira/v1/key-id"). It reveals nothing about the key and is stored next
// to every wrapped blob to select the right key. It returns an empty string for
// a nil key.
func (k *MasterKey) ID() string {
	if k == nil || k.m == nil {
		return ""
	}
	return k.m.id
}

// Destroy zeroes the key bytes and the derived MAC keys and drops the derived
// wrapping keys, on a best effort basis (the Go runtime may have copied
// them). The key is unusable afterwards; its ID remains available. Destroy
// must not be called concurrently with other methods.
func (k *MasterKey) Destroy() {
	if k == nil || k.m == nil {
		return
	}
	clear(k.m.key[:])
	k.m.wrap = nil
	for _, mk := range k.m.mac {
		clear(mk)
	}
	k.m.mac = nil
	k.m.destroyed = true
}

// The printing methods use value receivers so that they apply to MasterKey
// values as well as pointers: fmt and slog never fall back to dumping fields.

// String returns a redacted representation showing only the key identifier.
func (k MasterKey) String() string {
	if k.m == nil {
		return "MasterKey(none)"
	}
	return "MasterKey(" + k.m.id + ")"
}

// GoString returns the same redacted representation as String, for %#v.
func (k MasterKey) GoString() string { return k.String() }

// Format implements fmt.Formatter so that every verb and flag (%v, %+v, %#v,
// %s, %x, ...) prints the redacted representation.
func (k MasterKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue implements slog.LogValuer with the redacted representation.
func (k MasterKey) LogValue() slog.Value { return slog.StringValue(k.String()) }

// wrapperFor returns the wrapping key of purpose p.
func (k *MasterKey) wrapperFor(p Purpose) (cipher.AEAD, error) {
	if k == nil || k.m == nil || k.m.destroyed {
		return nil, ErrKeyUnavailable
	}
	w, ok := k.m.wrap[p]
	if !ok {
		return nil, ErrUnknownPurpose
	}
	return w, nil
}
