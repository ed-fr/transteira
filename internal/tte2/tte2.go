package tte2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	// KeySize is the size of the transfer key K, in bytes.
	KeySize = 32
	// EncodedKeySize is the length of K encoded in base64url without padding,
	// as carried by the link fragment "#k=".
	EncodedKeySize = 43
	// HeaderSize is the size of a file stream header.
	HeaderSize = 32
	// SaltSize is the size of the random salt of a file stream header.
	SaltSize = 16
	// TagSize is the size of an AES-GCM authentication tag.
	TagSize = 16
	// NonceSize is the size of an AES-GCM nonce.
	NonceSize = 12
	// Magic starts every file stream.
	Magic = "TTE2"
	// Version is the format version recorded in the header.
	Version = 1
	// KindFile is the header kind of a file stream.
	KindFile = 1
	// MinChunkSize is the smallest plaintext chunk size (64 KiB).
	MinChunkSize = 64 << 10
	// MaxChunkSize is the largest plaintext chunk size (8 MiB). It bounds the
	// memory a Reader allocates, whatever the header claims.
	MaxChunkSize = 8 << 20
	// DefaultChunkSize is the plaintext chunk size used when no WithChunkSize
	// option is given (1 MiB).
	DefaultChunkSize = 1 << 20
	// MinFileSize is the size of the smallest valid stream: the header and the
	// empty final chunk of an empty file.
	MinFileSize = HeaderSize + TagSize
	// MaxChunks is the largest number of chunks of a stream (the chunk counter
	// is a 32-bit integer).
	MaxChunks = 1 << 32
	// MaxIndex is the largest file index.
	MaxIndex = math.MaxUint32

	// MaxMetadataSize is the largest decoded size of a sealed metadata blob.
	MaxMetadataSize = 4096
	// MaxMessageRunes is the largest number of Unicode code points of a
	// message.
	MaxMessageRunes = 5000
	// MaxMessageEncodedSize is the largest length of a sealed message, in
	// base64url characters.
	MaxMessageEncodedSize = 32768

	// InfoFile is the HKDF info prefix of a file key, followed by the
	// big-endian 32-bit file index.
	InfoFile = "transteira/tte2/v1/file"
	// InfoMetadata is the HKDF info prefix of a metadata key, followed by the
	// big-endian 32-bit file index.
	InfoMetadata = "transteira/tte2/v1/metadata"
	// InfoMessage is the HKDF info of the message key.
	InfoMessage = "transteira/tte2/v1/message"
	// InfoSecret is reserved for the one-time secrets of V2.1, which will reuse
	// the sealed blob construction of messages under this info. It is not used
	// by this package.
	InfoSecret = "transteira/tte2/v1/secret" //nolint:gosec // G101: an HKDF label, not a credential.

	// sealedVersion is the first byte of a sealed metadata or message blob.
	sealedVersion = 1
	// sealedOverhead is the size of a sealed blob without its plaintext.
	sealedOverhead = 1 + NonceSize + TagSize
	// metadataAAD and messageAAD are the AAD labels of sealed blobs.
	metadataAAD = "TTE2M"
	messageAAD  = "TTE2T"
	// maxEmptyReads bounds consecutive (0, nil) reads before giving up with
	// io.ErrNoProgress, as bufio does.
	maxEmptyReads = 100
	// initialReadBuffer is the first allocation of a Reader chunk buffer.
	initialReadBuffer = 4 << 10
)

var (
	// ErrInvalidKey is returned for a transfer key that is not KeySize bytes
	// (or, from DecodeKey, not a canonical 43-character base64url string).
	ErrInvalidKey = errors.New("tte2: invalid transfer key")
	// ErrInvalidIndex is returned for a file index outside [0, MaxIndex].
	ErrInvalidIndex = errors.New("tte2: invalid file index")
	// ErrInvalidChunkSize is returned by NewWriter for a chunk size that is
	// not a power of two in [MinChunkSize, MaxChunkSize].
	ErrInvalidChunkSize = errors.New("tte2: invalid chunk size")
	// ErrBadHeader is returned when a stream header has an unknown magic,
	// version or kind, a non-zero reserved byte or an invalid chunk size.
	ErrBadHeader = errors.New("tte2: invalid header")
	// ErrAuth is returned when a chunk or a sealed blob fails authentication:
	// altered data, wrong key, wrong file index, reordered or duplicated
	// chunks.
	ErrAuth = errors.New("tte2: authentication failed")
	// ErrTruncated is returned when a stream ends before its final chunk.
	ErrTruncated = errors.New("tte2: stream is truncated")
	// ErrTrailingData is returned when data follows a chunk that
	// authenticates as the final one.
	ErrTrailingData = errors.New("tte2: trailing data after final chunk")
	// ErrFormat is returned when a stream does not follow the chunk layout,
	// whatever the key: by Validator for a header or a size that cannot be
	// valid, and by Reader for an empty final chunk after data.
	ErrFormat = errors.New("tte2: invalid stream format")
	// ErrCounterOverflow is returned when a stream would need more than
	// MaxChunks chunks.
	ErrCounterOverflow = errors.New("tte2: chunk counter overflow")
	// ErrWriterClosed is returned when a closed Writer is used.
	ErrWriterClosed = errors.New("tte2: writer closed")
	// ErrInvalidState is returned by Validator.UnmarshalBinary for a state
	// that was not produced by Validator.MarshalBinary.
	ErrInvalidState = errors.New("tte2: invalid validator state")
	// ErrEncoding is returned for a sealed blob that is not canonical
	// base64url, is too short or too long, or has an unknown version byte.
	ErrEncoding = errors.New("tte2: invalid sealed encoding")
	// ErrInvalidMetadata is returned for metadata that breaks the JSON rules
	// (unknown or missing field, wrong index or count, bad digest, ...).
	ErrInvalidMetadata = errors.New("tte2: invalid metadata")
	// ErrInvalidMessage is returned for a message that is not valid UTF-8 or
	// is longer than MaxMessageRunes.
	ErrInvalidMessage = errors.New("tte2: invalid message")
)

// randReader is the source of salts and nonces. Tests swap it to produce
// deterministic vectors; production code always uses crypto/rand.
var randReader io.Reader = rand.Reader

// randomBytes fills b from randReader.
func randomBytes(b []byte) error {
	if _, err := io.ReadFull(randReader, b); err != nil {
		return fmt.Errorf("tte2: random: %w", err)
	}
	return nil
}

// NewKey returns a fresh random transfer key of KeySize bytes.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if err := randomBytes(k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncodeKey encodes a transfer key in base64url without padding, the form
// carried by the link fragment "#k=". It returns ErrInvalidKey for a key that
// is not KeySize bytes.
func EncodeKey(key []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrInvalidKey
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// DecodeKey decodes the fragment form of a transfer key. Anything but exactly
// EncodedKeySize canonical base64url characters is ErrInvalidKey.
func DecodeKey(s string) ([]byte, error) {
	if len(s) != EncodedKeySize || !isBase64URL(s) {
		return nil, ErrInvalidKey
	}
	k, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return k, nil
}

// isBase64URL reports whether s only holds characters of the base64url
// alphabet (the standard decoder silently skips CR and LF).
func isBase64URL(s string) bool {
	for i := range len(s) {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// ValidChunkSize reports whether c is an accepted chunk size: a power of two
// in [MinChunkSize, MaxChunkSize].
func ValidChunkSize(c int) bool {
	return c >= MinChunkSize && c <= MaxChunkSize && c&(c-1) == 0
}

// checkKeyIndex validates a transfer key and a file index.
func checkKeyIndex(key []byte, index int) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}
	if index < 0 || int64(index) > MaxIndex {
		return ErrInvalidIndex
	}
	return nil
}

// indexedInfo returns label followed by the big-endian 32-bit index. index
// has been validated by checkKeyIndex.
func indexedInfo(label string, index int) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(index)) //nolint:gosec // G115: index is checked against [0, MaxIndex] by checkKeyIndex.
	return label + string(b[:])
}

// newAEAD derives a 32-byte key from the transfer key with HKDF-SHA256 and
// returns its AES-256-GCM AEAD. key has been checked to be KeySize bytes.
func newAEAD(key, salt []byte, info string) cipher.AEAD {
	// None of these calls can fail: 32 bytes is far below the HKDF-SHA256
	// output limit, the derived key is a valid AES-256 key and AES has
	// 16-byte blocks.
	sub, _ := hkdf.Key(sha256.New, key, salt, info, KeySize)
	defer clear(sub)
	block, _ := aes.NewCipher(sub)
	aead, _ := cipher.NewGCM(block)
	return aead
}

// Header is the decoded 32-byte header of a file stream:
//
//	offset size field
//	0      4    magic "TTE2"
//	4      1    version (1)
//	5      1    kind (1 = file)
//	6      2    reserved, zero
//	8      4    plaintext chunk size C, big-endian
//	12     16   random salt
//	28     4    reserved, zero
type Header struct {
	// ChunkSize is the plaintext chunk size C.
	ChunkSize int
	// Salt is the random HKDF salt of the file key.
	Salt [SaltSize]byte
}

// Bytes returns the encoded header.
func (h Header) Bytes() [HeaderSize]byte {
	var b [HeaderSize]byte
	copy(b[:4], Magic)
	b[4] = Version
	b[5] = KindFile
	binary.BigEndian.PutUint32(b[8:12], uint32(h.ChunkSize)) //nolint:gosec // G115: a Header built by this package always holds a valid chunk size (<= 8 MiB).
	copy(b[12:28], h.Salt[:])
	return b
}

// ParseHeader decodes and strictly validates a stream header: b must be
// exactly HeaderSize bytes, with the expected magic, version and kind, zero
// reserved bytes and a valid chunk size. Any violation is ErrBadHeader.
func ParseHeader(b []byte) (Header, error) {
	if len(b) != HeaderSize {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrBadHeader, len(b))
	}
	if err := checkHeaderPrefix(b); err != nil {
		return Header{}, err
	}
	var h Header
	h.ChunkSize = int(binary.BigEndian.Uint32(b[8:12]))
	copy(h.Salt[:], b[12:28])
	return h, nil
}

// checkHeaderPrefix validates every header field fully contained in the
// prefix p (len(p) <= HeaderSize), so that a bad header is refused as soon as
// its first wrong byte is known. It returns ErrBadHeader with a detail.
func checkHeaderPrefix(p []byte) error {
	for i, c := range p {
		var ok bool
		switch {
		case i < 4:
			ok = c == Magic[i]
		case i == 4:
			ok = c == Version
		case i == 5:
			ok = c == KindFile
		case i == 6 || i == 7 || i >= 28:
			ok = c == 0
		case i == 8 || i == 10 || i == 11:
			// Every valid chunk size (a power of two in [MinChunkSize,
			// MaxChunkSize], 2^16 to 2^23) is 00 xx 00 00 in big-endian, so
			// each chunk size byte is judged on arrival: no wrong byte can be
			// accepted, and stored, before the chunk size is complete.
			ok = c == 0
		case i == 9:
			ok = c != 0 && c&(c-1) == 0
		default:
			ok = true // salt
		}
		if !ok {
			return fmt.Errorf("%w: byte %d", ErrBadHeader, i)
		}
	}
	return nil
}

// prefixChunkSize returns the chunk size determined by a valid header prefix
// p, or 0 while it is unknown: byte 9 alone fixes it, since bytes 8, 10 and 11
// of a valid header are zero (see checkHeaderPrefix).
func prefixChunkSize(p []byte) int {
	if len(p) < 10 {
		return 0
	}
	return int(p[9]) << 16
}

// chunkNonce returns the nonce of chunk counter: seven zero bytes, the
// big-endian counter and the last flag.
func chunkNonce(counter uint32, last bool) [NonceSize]byte {
	var n [NonceSize]byte
	binary.BigEndian.PutUint32(n[7:11], counter)
	if last {
		n[11] = 1
	}
	return n
}

// fileAEAD derives the AEAD of file index from the transfer key and the
// header salt. key and index have been checked by checkKeyIndex.
func fileAEAD(key []byte, index int, h *Header) cipher.AEAD {
	return newAEAD(key, h.Salt[:], indexedInfo(InfoFile, index))
}
