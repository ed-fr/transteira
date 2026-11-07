package tte2

import (
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

// Reader decrypts a TTE2 file stream sequentially. Read only ever returns
// authenticated plaintext, and returns io.EOF only once the final chunk has
// authenticated and the source is exhausted: a caller that reads to io.EOF
// without error has the complete, unaltered file. A Reader is not safe for
// concurrent use.
//
// To tell a full final chunk from a full middle chunk, the Reader reads one
// byte ahead. Its memory is bounded by one encrypted chunk plus one plaintext
// chunk (at most 2*MaxChunkSize + TagSize + 1 bytes), and the buffers grow
// with the data actually received, so a forged header announcing a large
// chunk size does not make a short stream allocate it.
//
// Error classification, applied in this order to each chunk (it is mirrored
// by the other implementations and by testdata/vectors.json):
//
//   - fewer than HeaderSize bytes: ErrTruncated; invalid header: ErrBadHeader;
//   - a chunk followed by more data is opened as a middle chunk; if that fails
//     and it opens as a final chunk: ErrTrailingData, otherwise ErrAuth;
//     a middle chunk at counter 2^32-1: ErrCounterOverflow;
//   - the chunk ending the source is opened as the final chunk: fewer than
//     TagSize bytes is ErrTruncated, exactly TagSize bytes after other chunks
//     is ErrFormat (an empty final chunk only exists for an empty file); if
//     opening fails and a full chunk opens as a middle chunk: ErrTruncated
//     (missing final chunk), otherwise ErrAuth.
type Reader struct {
	src       io.Reader
	cipher    *ChunkCipher
	chunkSize int
	buf       []byte // one encrypted chunk and the look-ahead byte
	plain     []byte // plaintext of the last authenticated chunk
	pending   []byte // authenticated plaintext not yet returned
	peek      byte   // look-ahead byte, the first byte of the next chunk
	hasPeek   bool
	counter   uint32
	err       error // sticky error, io.EOF after the final chunk
}

// NewReader reads and checks the header from src and returns a Reader
// decrypting file index with the transfer key K. It returns ErrTruncated when
// src holds fewer than HeaderSize bytes and ErrBadHeader for an invalid
// header.
func NewReader(src io.Reader, key []byte, index int) (*Reader, error) {
	if err := checkKeyIndex(key, index); err != nil {
		return nil, err
	}
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(src, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: header", ErrTruncated)
		}
		return nil, fmt.Errorf("tte2: read header: %w", err)
	}
	h, err := ParseHeader(raw[:])
	if err != nil {
		return nil, err
	}
	// ParseHeader has validated the chunk size, so NewChunkCipher cannot
	// fail: key and index are checked above.
	c, _ := NewChunkCipher(key, index, h)
	return &Reader{src: src, cipher: c, chunkSize: h.ChunkSize}, nil
}

// ChunkSize returns the plaintext chunk size recorded in the header.
func (r *Reader) ChunkSize() int { return r.chunkSize }

// Read implements io.Reader.
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
	blockLen := r.chunkSize + TagSize
	got, err := r.fill(blockLen + 1)
	if err != nil {
		return err
	}
	if got == blockLen+1 {
		// More data follows: this is a middle chunk.
		r.peek, r.hasPeek = r.buf[blockLen], true
		if r.counter == math.MaxUint32 {
			return ErrCounterOverflow
		}
		chunk := r.buf[:blockLen]
		plain, ok := r.open(chunk, false)
		if !ok {
			if _, final := r.open(chunk, true); final {
				return fmt.Errorf("%w: after chunk %d", ErrTrailingData, r.counter)
			}
			return fmt.Errorf("%w: chunk %d", ErrAuth, r.counter)
		}
		r.pending = plain
		r.counter++
		return nil
	}
	// The source is exhausted: this is the final chunk.
	chunk := r.buf[:got]
	switch {
	case got < TagSize:
		return fmt.Errorf("%w: chunk %d", ErrTruncated, r.counter)
	case got == TagSize && r.counter > 0:
		return fmt.Errorf("%w: empty final chunk %d", ErrFormat, r.counter)
	}
	plain, ok := r.open(chunk, true)
	if !ok {
		if got == blockLen {
			if _, middle := r.open(chunk, false); middle {
				return fmt.Errorf("%w: missing final chunk %d", ErrTruncated, r.counter+1)
			}
		}
		return fmt.Errorf("%w: chunk %d", ErrAuth, r.counter)
	}
	r.pending = plain
	return io.EOF
}

// fill reads into r.buf, after the look-ahead byte, until it holds limit
// bytes or the source ends. It returns the number of bytes buffered; a source
// error other than io.EOF is returned wrapped, and a source returning (0, nil)
// too many times in a row yields io.ErrNoProgress.
func (r *Reader) fill(limit int) (int, error) {
	buf := r.buf[:0]
	if r.hasPeek {
		buf = append(buf, r.peek)
		r.hasPeek = false
	}
	empty := 0
	for len(buf) < limit {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(max(2*cap(buf), initialReadBuffer), limit)-len(buf))
		}
		m, err := r.src.Read(buf[len(buf):min(cap(buf), limit)])
		buf = buf[:len(buf)+m]
		r.buf = buf
		if err != nil {
			if errors.Is(err, io.EOF) {
				return len(buf), nil
			}
			return len(buf), fmt.Errorf("tte2: read: %w", err)
		}
		if m > 0 {
			empty = 0
		} else if empty++; empty >= maxEmptyReads {
			return len(buf), fmt.Errorf("tte2: read: %w", io.ErrNoProgress)
		}
	}
	r.buf = buf
	return len(buf), nil
}

// open authenticates and decrypts chunk r.counter into r.plain, leaving the
// ciphertext intact so that a failed attempt can be retried with the other
// last flag.
func (r *Reader) open(chunk []byte, last bool) ([]byte, bool) {
	if cap(r.plain) < len(chunk)-TagSize {
		r.plain = make([]byte, 0, len(chunk)-TagSize)
	}
	// next only passes lengths that follow the chunk layout, so the only
	// possible failure is ErrAuth.
	plain, err := r.cipher.Open(r.plain[:0], uint64(r.counter), chunk, last)
	if err != nil {
		return nil, false
	}
	return plain, true
}
