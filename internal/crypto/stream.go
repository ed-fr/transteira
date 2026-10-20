package crypto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	// DefaultChunkSize is the plaintext size of a chunk (64 KiB) when no
	// WithChunkSize option is given.
	DefaultChunkSize = 64 << 10
	// MinChunkSize is the smallest accepted chunk size (1 KiB).
	MinChunkSize = 1 << 10
	// MaxChunkSize is the largest accepted chunk size (16 MiB). It bounds the
	// memory a Reader or ReaderAt allocates, whatever the header claims.
	MaxChunkSize = 16 << 20
	// HeaderSize is the size of the file header.
	HeaderSize = 16
	// MaxCheckpointExtra is the largest caller payload a checkpoint can seal
	// (see Writer.Checkpoint).
	MaxCheckpointExtra = 1 << 10

	// streamMagic starts every encrypted file.
	streamMagic = "TTEF"
	// streamVersion is the file format version.
	streamVersion = 1
	// noncePrefixSize is the size of the random nonce prefix of a file.
	noncePrefixSize = 7
	// chunkLabel is the domain label of the chunk AAD.
	chunkLabel = "transteira/v1/stream-chunk"
	// tailLabel is the domain label of the tail AAD and the HKDF info of the
	// tail subkey.
	tailLabel = "transteira/v1/stream-tail"
	// tailVersion is the first byte of a sealed tail.
	tailVersion = 1
	// initialReadBuffer is the first allocation of a Reader chunk buffer.
	initialReadBuffer = 4 << 10
	// maxEmptyReads bounds consecutive (0, nil) reads before giving up with
	// io.ErrNoProgress, as bufio does.
	maxEmptyReads = 100
)

var (
	// ErrBadHeader is returned when a file header has an unknown magic,
	// version or an out-of-range chunk size.
	ErrBadHeader = errors.New("crypto: invalid encrypted file header")
	// ErrAuth is returned when a chunk or a checkpoint tail fails
	// authentication: altered data, wrong key, tenant or file, reordered or
	// duplicated chunks.
	ErrAuth = errors.New("crypto: authentication failed")
	// ErrTruncated is returned when the encrypted data ends before the final
	// chunk.
	ErrTruncated = errors.New("crypto: encrypted file is truncated")
	// ErrTrailingData is returned when data follows the final chunk.
	ErrTrailingData = errors.New("crypto: trailing data after final chunk")
	// ErrCounterOverflow is returned when a file would need more than 2^32
	// chunks.
	ErrCounterOverflow = errors.New("crypto: chunk counter overflow")
	// ErrInvalidChunkSize is returned by WithChunkSize for a size outside
	// [MinChunkSize, MaxChunkSize].
	ErrInvalidChunkSize = errors.New("crypto: chunk size out of range")
	// ErrStaleCheckpoint is returned by ResumeWriter when the encrypted file on
	// disk does not have exactly the size recorded by the checkpoint. The
	// upload must be restarted with a new file ID and a new DEK.
	ErrStaleCheckpoint = errors.New("crypto: encrypted file size does not match the checkpoint")
	// ErrExtraTooLarge is returned by Writer.Checkpoint for a caller payload
	// larger than MaxCheckpointExtra.
	ErrExtraTooLarge = errors.New("crypto: checkpoint extra data too large")
	// ErrWriterClosed is returned when a closed Writer is used.
	ErrWriterClosed = errors.New("crypto: writer closed")
	// ErrNegativeOffset is returned by ReaderAt.ReadAt for a negative offset.
	ErrNegativeOffset = errors.New("crypto: negative offset")
)

// u32 converts a length that the caller has bounded far below 4 GiB.
func u32(n int) uint32 {
	return uint32(n) //nolint:gosec // G115: every caller passes a bounded length (identifiers, chunk size, checkpoint payloads).
}

// header is the 16-byte file header.
type header [HeaderSize]byte

// newHeader returns a header for chunkSize with a fresh random nonce prefix.
func newHeader(chunkSize int) (header, error) {
	var h header
	copy(h[:], streamMagic)
	h[4] = streamVersion
	binary.BigEndian.PutUint32(h[5:9], u32(chunkSize))
	if err := randomBytes(h[9:]); err != nil {
		return header{}, err
	}
	return h, nil
}

// chunkSize validates h and returns its chunk size.
func (h *header) chunkSize() (int, error) {
	if string(h[:4]) != streamMagic || h[4] != streamVersion {
		return 0, ErrBadHeader
	}
	cs := binary.BigEndian.Uint32(h[5:9])
	if cs < MinChunkSize || cs > MaxChunkSize {
		return 0, ErrBadHeader
	}
	return int(cs), nil
}

// nonce returns the nonce of chunk counter, with the last flag.
func (h *header) nonce(counter uint32, last bool) [nonceSize]byte {
	var n [nonceSize]byte
	copy(n[:noncePrefixSize], h[9:])
	binary.BigEndian.PutUint32(n[noncePrefixSize:], counter)
	if last {
		n[nonceSize-1] = 1
	}
	return n
}

// bindingAAD returns lp(label) | header | lp(tenantID) | lp(fileID).
func bindingAAD(label string, h *header, tenantID, fileID string) []byte {
	b := make([]byte, 0, 12+len(label)+HeaderSize+len(tenantID)+len(fileID)+8)
	b = appendLP(b, label)
	b = append(b, h[:]...)
	b = appendLP(b, tenantID)
	return appendLP(b, fileID)
}

// tailAAD returns the AAD of a checkpoint tail sealed after chunks complete
// chunks with an extra payload of extraLen bytes.
func tailAAD(prefix []byte, chunks, extraLen uint32) []byte {
	b := binary.BigEndian.AppendUint32(append([]byte(nil), prefix...), chunks)
	return binary.BigEndian.AppendUint32(b, extraLen)
}

// streamKey validates the DEK and the identifiers and returns the chunk AEAD.
func streamKey(dek []byte, tenantID, fileID string) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, ErrKeySize
	}
	if err := checkBinding(tenantID, fileID); err != nil {
		return nil, err
	}
	return newAEAD(dek), nil
}

// tailKey returns the AEAD of checkpoint tails, keyed with
// HKDF-SHA256(dek, salt none, info "transteira/v1/stream-tail"), so that tails
// and chunks never share a key. dek must be DEKSize bytes.
func tailKey(dek []byte) cipher.AEAD {
	// hkdf.Key cannot fail: 32 bytes is far below the HKDF-SHA256 limit.
	k, _ := hkdf.Key(sha256.New, dek, nil, tailLabel, DEKSize)
	defer clear(k)
	return newAEAD(k)
}

// EncryptedSize returns the size of the encrypted file holding plaintext bytes
// with the given chunk size: header, full chunks and the final chunk, each with
// its 16-byte tag. It returns -1 for a negative size or an invalid chunk size.
func EncryptedSize(plaintext int64, chunkSize int) int64 {
	if plaintext < 0 || chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return -1
	}
	cs := int64(chunkSize)
	return HeaderSize + (plaintext/cs)*(cs+tagSize) + plaintext%cs + tagSize
}

// PlaintextSize is the inverse of EncryptedSize: it returns the plaintext size
// of an encrypted file of ciphertextSize bytes. It returns -1 for an invalid
// chunk size or a size no valid file can have (shorter than the header and an
// empty final chunk, or ending with fewer than 16 bytes after the last full
// chunk).
func PlaintextSize(ciphertextSize int64, chunkSize int) int64 {
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize || ciphertextSize < HeaderSize+tagSize {
		return -1
	}
	block := int64(chunkSize) + tagSize
	body := ciphertextSize - HeaderSize
	full, rem := body/block, body%block
	if rem < tagSize {
		return -1
	}
	return full*int64(chunkSize) + rem - tagSize
}
