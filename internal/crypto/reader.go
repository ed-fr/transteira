package crypto

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

// Reader decrypts a stream produced by Writer sequentially. Read only ever
// returns authenticated plaintext and reports a failure as soon as a chunk
// does not authenticate. Memory use is bounded by one chunk (at most
// MaxChunkSize plus the tag). A Reader is not safe for concurrent use. Use
// ReaderAt when the ciphertext size is known and random access is needed.
//
// The final chunk is recognized by being shorter than a full chunk. Data
// appended after a short final chunk therefore makes that chunk fail
// authentication (ErrAuth); ErrTrailingData is returned when the source still
// yields data after the final chunk has been authenticated. A truncation
// inside a chunk is reported as ErrAuth, or ErrTruncated when fewer than 16
// bytes remain.
type Reader struct {
	src       io.Reader
	aead      cipher.AEAD
	header    header
	chunkSize int
	aad       []byte
	buf       []byte // one encrypted chunk, grown as data actually arrives
	pending   []byte // authenticated plaintext not yet returned
	counter   uint32
	err       error // sticky error, io.EOF after the final chunk
}

// NewReader reads and checks the header from src and returns a Reader
// decrypting the file fileID of tenant tenantID with dek. It returns
// ErrBadHeader for an invalid header and ErrTruncated when src holds fewer than
// 16 bytes.
func NewReader(src io.Reader, dek []byte, tenantID, fileID string) (*Reader, error) {
	aead, err := streamKey(dek, tenantID, fileID)
	if err != nil {
		return nil, err
	}
	var h header
	if _, err := io.ReadFull(src, h[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrTruncated
		}
		return nil, fmt.Errorf("crypto: read header: %w", err)
	}
	chunkSize, err := h.chunkSize()
	if err != nil {
		return nil, err
	}
	return &Reader{
		src:       src,
		aead:      aead,
		header:    h,
		chunkSize: chunkSize,
		aad:       bindingAAD(chunkLabel, &h, tenantID, fileID),
	}, nil
}

// Read implements io.Reader. It returns io.EOF after the final chunk has been
// authenticated and fully returned.
func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.err = r.next()
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// next reads, authenticates and buffers the next chunk. It returns io.EOF once
// the final chunk is buffered.
func (r *Reader) next() error {
	n, err := r.fill()
	switch {
	case err == nil:
		// A full-size chunk is never the final one.
		if r.counter == math.MaxUint32 {
			return ErrCounterOverflow
		}
		plain, err := r.open(r.buf, false)
		if err != nil {
			return err
		}
		r.pending = plain
		r.counter++
		return nil
	case errors.Is(err, io.EOF):
		return fmt.Errorf("%w: missing final chunk %d", ErrTruncated, r.counter)
	case errors.Is(err, io.ErrUnexpectedEOF):
		if n < tagSize {
			return fmt.Errorf("%w: chunk %d", ErrTruncated, r.counter)
		}
		plain, err := r.open(r.buf[:n], true)
		if err != nil {
			return err
		}
		if err := r.expectEOF(); err != nil {
			clear(plain)
			return err
		}
		r.pending = plain
		return io.EOF
	default:
		return fmt.Errorf("crypto: read: %w", err)
	}
}

// expectEOF checks that the source has nothing after the final chunk: it
// returns nil on io.EOF, ErrTrailingData if any byte arrives, and the source
// error (or io.ErrNoProgress) otherwise.
func (r *Reader) expectEOF() error {
	var probe [1]byte
	for range maxEmptyReads {
		m, err := r.src.Read(probe[:])
		switch {
		case m > 0:
			return ErrTrailingData
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return fmt.Errorf("crypto: read: %w", err)
		}
	}
	return fmt.Errorf("crypto: read: %w", io.ErrNoProgress)
}

// fill reads one encrypted chunk (chunk size + 16 bytes) into r.buf, with
// the io.ReadFull semantics: nil when full, io.EOF when nothing was read,
// io.ErrUnexpectedEOF on a partial chunk. The buffer grows with the data
// received, so a forged header announcing a huge chunk size does not make a
// short file allocate MaxChunkSize. A source returning (0, nil) too many times
// in a row yields io.ErrNoProgress.
func (r *Reader) fill() (int, error) {
	blockLen := r.chunkSize + tagSize
	buf := r.buf[:0]
	empty := 0
	for len(buf) < blockLen {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(max(2*cap(buf), initialReadBuffer), blockLen)-len(buf))
		}
		m, err := r.src.Read(buf[len(buf):min(cap(buf), blockLen)])
		buf = buf[:len(buf)+m]
		r.buf = buf
		if err != nil && len(buf) < blockLen {
			if !errors.Is(err, io.EOF) {
				return len(buf), err
			}
			if len(buf) == 0 {
				return 0, io.EOF
			}
			return len(buf), io.ErrUnexpectedEOF
		}
		if m > 0 {
			empty = 0
		} else if empty++; empty >= maxEmptyReads {
			return len(buf), io.ErrNoProgress
		}
	}
	return len(buf), nil
}

// open authenticates and decrypts chunk r.counter in place.
func (r *Reader) open(chunk []byte, last bool) ([]byte, error) {
	nonce := r.header.nonce(r.counter, last)
	plain, err := r.aead.Open(chunk[:0], nonce[:], chunk, r.aad)
	if err != nil {
		return nil, fmt.Errorf("%w: chunk %d", ErrAuth, r.counter)
	}
	return plain, nil
}
