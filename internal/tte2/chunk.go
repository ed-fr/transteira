package tte2

import (
	"crypto/cipher"
	"fmt"
	"math"
)

// NewHeader returns the header of a new file stream: chunk size chunkSize and
// a fresh random salt. It returns ErrInvalidChunkSize for a chunk size that is
// not a power of two in [MinChunkSize, MaxChunkSize].
//
// A client that encrypts the same file twice (a hashing pass, then the
// upload) draws the header once and passes it to NewChunkCipher or to
// NewWriter with WithHeader, so that both passes produce the same bytes.
func NewHeader(chunkSize int) (Header, error) {
	if !ValidChunkSize(chunkSize) {
		return Header{}, ErrInvalidChunkSize
	}
	h := Header{ChunkSize: chunkSize}
	if err := randomBytes(h.Salt[:]); err != nil {
		return Header{}, err
	}
	return h, nil
}

// ChunkCipher seals and opens the individual chunks of one file stream, for a
// given transfer key, file index and header. It is the single implementation
// of the chunk encryption used by Writer and Reader, and lets a client work on
// any chunk directly: re-encrypt a stream deterministically, resume an upload
// from the chunk holding a given ciphertext offset (see ChunkAt) or resume a
// download from chunk n after re-reading the header (see ParseHeader and
// ChunkOffset).
//
// Chunk n of a stream is sealed with the nonce seven zero bytes, u32 BE(n),
// last flag, and the encoded header as AAD. The caller decides the last flag:
// it is true for chunk ChunkCount(plain, chunk)-1 only, which needs the
// plaintext size (or, for a download, the stream size and PlaintextSize).
//
// A ChunkCipher holds no mutable state and is safe for concurrent use.
type ChunkCipher struct {
	aead      cipher.AEAD
	header    Header
	aad       [HeaderSize]byte
	chunkSize int
}

// NewChunkCipher returns the ChunkCipher of file index (its 0-based position
// in the transfer) under the transfer key K and the stream header h, deriving
// the file key exactly as NewWriter and NewReader do. It returns
// ErrInvalidKey, ErrInvalidIndex, or ErrInvalidChunkSize for a header whose
// chunk size is not valid.
func NewChunkCipher(key []byte, index int, h Header) (*ChunkCipher, error) {
	if err := checkKeyIndex(key, index); err != nil {
		return nil, err
	}
	if !ValidChunkSize(h.ChunkSize) {
		return nil, ErrInvalidChunkSize
	}
	return &ChunkCipher{
		aead:      fileAEAD(key, index, &h),
		header:    h,
		aad:       h.Bytes(),
		chunkSize: h.ChunkSize,
	}, nil
}

// Header returns the stream header of the cipher. Its Bytes are the first
// HeaderSize bytes of the stream.
func (c *ChunkCipher) Header() Header { return c.header }

// ChunkSize returns the plaintext chunk size C.
func (c *ChunkCipher) ChunkSize() int { return c.chunkSize }

// Seal encrypts plain as chunk n and appends the sealed chunk (plain followed
// by its TagSize-byte tag) to dst, returning the extended slice. dst and plain
// may only overlap exactly (plain = dst[len(dst):len(dst)+len(plain)]).
//
// The layout rules of the stream are enforced: a middle chunk (last false)
// holds exactly C bytes, and the final chunk 1 to C bytes, or 0 only when it
// is chunk 0 (empty file); any other length is ErrFormat. n must be below
// MaxChunks, and a middle chunk cannot be chunk MaxChunks-1 since a final
// chunk must follow: both are ErrCounterOverflow. On error dst is returned
// unchanged with no output appended.
func (c *ChunkCipher) Seal(dst []byte, n uint64, plain []byte, last bool) ([]byte, error) {
	counter, err := c.check(n, len(plain), last)
	if err != nil {
		return dst, err
	}
	nonce := chunkNonce(counter, last)
	return c.aead.Seal(dst, nonce[:], plain, c.aad[:]), nil
}

// Open authenticates and decrypts sealed as chunk n and appends the plaintext
// to dst, returning the extended slice. dst and sealed may only overlap
// exactly (dst[:0] reusing the ciphertext buffer).
//
// sealed must follow the same layout as in Seal: C+TagSize bytes for a middle
// chunk, TagSize+1 to C+TagSize bytes for the final chunk, or exactly TagSize
// for a final chunk 0; any other length is ErrFormat, and the counter limits
// of Seal give ErrCounterOverflow. A chunk that does not authenticate (altered
// data, wrong key, index, header, chunk number or last flag) is ErrAuth. Open
// fails closed: on any error it returns a nil slice and no plaintext.
func (c *ChunkCipher) Open(dst []byte, n uint64, sealed []byte, last bool) ([]byte, error) {
	if len(sealed) < TagSize {
		return nil, fmt.Errorf("%w: chunk %d of %d bytes", ErrFormat, n, len(sealed))
	}
	counter, err := c.check(n, len(sealed)-TagSize, last)
	if err != nil {
		return nil, err
	}
	nonce := chunkNonce(counter, last)
	plain, err := c.aead.Open(dst, nonce[:], sealed, c.aad[:])
	if err != nil {
		return nil, fmt.Errorf("%w: chunk %d", ErrAuth, n)
	}
	return plain, nil
}

// check validates chunk number n and the plaintext length size of a chunk
// with the given last flag, and returns n as the 32-bit nonce counter.
func (c *ChunkCipher) check(n uint64, size int, last bool) (uint32, error) {
	if n >= MaxChunks || (!last && n == math.MaxUint32) {
		return 0, fmt.Errorf("%w: chunk %d", ErrCounterOverflow, n)
	}
	var ok bool
	switch {
	case !last:
		ok = size == c.chunkSize
	case n == 0:
		ok = size <= c.chunkSize
	default:
		ok = size >= 1 && size <= c.chunkSize
	}
	if !ok {
		return 0, fmt.Errorf("%w: chunk %d with %d plaintext bytes", ErrFormat, n, size)
	}
	return uint32(n), nil
}

// ChunkCount returns the number of chunks of a stream encrypting plain bytes
// with chunk size chunk: max(1, ceil(plain / chunk)), as in CiphertextSize.
// The final chunk is chunk ChunkCount-1. It returns -1 for a negative plain,
// an invalid chunk size or more than MaxChunks chunks.
func ChunkCount(plain int64, chunk int) int64 {
	if CiphertextSize(plain, chunk) < 0 {
		return -1
	}
	c := int64(chunk)
	return max(1, (plain+c-1)/c)
}

// ChunkOffset returns the ciphertext offset of sealed chunk n in a stream
// with chunk size chunk: HeaderSize + n*(chunk+TagSize). Chunk n holds the
// plaintext bytes from n*chunk on. It returns -1 for n outside
// [0, MaxChunks) or an invalid chunk size.
func ChunkOffset(n int64, chunk int) int64 {
	if n < 0 || n >= MaxChunks || !ValidChunkSize(chunk) {
		return -1
	}
	return HeaderSize + n*int64(chunk+TagSize)
}

// ChunkAt maps the ciphertext offset off of a stream with chunk size chunk to
// the sealed chunk n holding that byte and the number of bytes skip of that
// sealed chunk before it, so that off = ChunkOffset(n, chunk) + skip with
// 0 <= skip < chunk+TagSize. An upload resumed at off re-seals chunk n and
// sends it from byte skip on.
//
// The header is not part of any chunk: for off < HeaderSize, an invalid
// chunk size or an offset beyond chunk MaxChunks-1, ChunkAt returns (-1, -1).
// It does not know the stream size: an offset at or past the end of the
// stream maps to a chunk that does not exist.
func ChunkAt(off int64, chunk int) (n, skip int64) {
	if off < HeaderSize || !ValidChunkSize(chunk) {
		return -1, -1
	}
	block := int64(chunk + TagSize)
	n = (off - HeaderSize) / block
	if n >= MaxChunks {
		return -1, -1
	}
	return n, (off - HeaderSize) % block
}
