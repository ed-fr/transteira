package crypto

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// ReaderAt gives random access to the plaintext of an encrypted file whose
// ciphertext size is known, for HTTP Range downloads. It implements
// io.ReaderAt; io.NewSectionReader(r, 0, r.Size()) turns it into an
// io.ReadSeeker suitable for http.ServeContent.
//
// Each ReadAt decrypts and authenticates only the chunks covering the requested
// range and never returns unauthenticated bytes. The final chunk is located
// from the ciphertext size and authenticated by NewReaderAt, which binds the
// number of chunks: a truncated or extended file is refused before any byte is
// released. Memory is bounded by one chunk, which is cached. A ReaderAt is safe
// for concurrent use (calls are serialized).
type ReaderAt struct {
	src       io.ReaderAt
	aead      cipher.AEAD
	header    header
	chunkSize int
	aad       []byte
	size      int64 // plaintext size
	last      int64 // index of the final chunk
	finalLen  int   // ciphertext length of the final chunk
	mu        sync.Mutex
	buf       []byte // one encrypted chunk, decrypted in place
	cached    int64  // index of the chunk held in plain, -1 if none
	plain     []byte // authenticated plaintext of chunk cached
}

// NewReaderAt checks the header of the encrypted file src of size bytes and
// authenticates its final chunk. It returns ErrBadHeader for an invalid
// header, ErrTruncated when size is shorter than a header or cannot end with a
// valid final chunk (the remainder after the last full chunk is shorter than a
// tag), and ErrAuth when the final chunk does not authenticate, which is the
// case when bytes were appended or removed while keeping a plausible size.
func NewReaderAt(src io.ReaderAt, size int64, dek []byte, tenantID, fileID string) (*ReaderAt, error) {
	aead, err := streamKey(dek, tenantID, fileID)
	if err != nil {
		return nil, err
	}
	if size < HeaderSize {
		return nil, ErrTruncated
	}
	var h header
	if err := readAtFull(src, h[:], 0); err != nil {
		return nil, err
	}
	chunkSize, err := h.chunkSize()
	if err != nil {
		return nil, err
	}
	plain := PlaintextSize(size, chunkSize)
	if plain < 0 {
		return nil, fmt.Errorf("%w: no room for the final chunk", ErrTruncated)
	}
	last := plain / int64(chunkSize)
	if last > math.MaxUint32 {
		return nil, ErrCounterOverflow
	}
	r := &ReaderAt{
		src:       src,
		aead:      aead,
		header:    h,
		chunkSize: chunkSize,
		aad:       bindingAAD(chunkLabel, &h, tenantID, fileID),
		size:      plain,
		last:      last,
		finalLen:  int(plain%int64(chunkSize)) + tagSize,
		buf:       make([]byte, min(int64(chunkSize+tagSize), size-HeaderSize)),
		cached:    -1,
	}
	if err := r.load(last); err != nil {
		return nil, err
	}
	return r, nil
}

// readAtFull reads exactly len(p) bytes at off. A short read means the file
// shrank: ErrTruncated.
func readAtFull(src io.ReaderAt, p []byte, off int64) error {
	n, err := src.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return ErrTruncated
	}
	return fmt.Errorf("crypto: read: %w", err)
}

// Size returns the plaintext size of the file.
func (r *ReaderAt) Size() int64 { return r.size }

// ReadAt implements io.ReaderAt over the plaintext. It returns io.EOF when the
// range extends past Size, and any read or authentication error of a chunk,
// with the authenticated bytes already copied counted in n.
func (r *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cs := int64(r.chunkSize)
	n := 0
	for n < len(p) && off < r.size {
		idx := off / cs
		if idx != r.cached {
			if err := r.load(idx); err != nil {
				return n, err
			}
		}
		c := copy(p[n:], r.plain[off-idx*cs:])
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// load reads, authenticates and caches chunk idx.
func (r *ReaderAt) load(idx int64) error {
	r.cached = -1
	clear(r.plain)
	last := idx == r.last
	n := r.chunkSize + tagSize
	if last {
		n = r.finalLen
	}
	chunk := r.buf[:n]
	if err := readAtFull(r.src, chunk, HeaderSize+idx*int64(r.chunkSize+tagSize)); err != nil {
		return err
	}
	nonce := r.header.nonce(uint32(idx), last) //nolint:gosec // G115: idx <= r.last <= MaxUint32 (checked in NewReaderAt).
	plain, err := r.aead.Open(chunk[:0], nonce[:], chunk, r.aad)
	if err != nil {
		return fmt.Errorf("%w: chunk %d", ErrAuth, idx)
	}
	r.plain = plain
	r.cached = idx
	return nil
}
