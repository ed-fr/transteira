package tte2

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math"
)

// Option configures a Writer created by NewWriter.
type Option func(*writerOptions)

// writerOptions holds the NewWriter options.
type writerOptions struct {
	chunkSize int
}

// WithChunkSize sets the plaintext chunk size, a power of two in
// [MinChunkSize, MaxChunkSize]. It is recorded in the header, so readers need
// no option.
func WithChunkSize(n int) Option {
	return func(o *writerOptions) { o.chunkSize = n }
}

// Writer encrypts one file into a TTE2 stream. It buffers at most one chunk of
// plaintext: since the final chunk may be full, a full chunk is only emitted
// once the next plaintext byte arrives, and the last one on Close. A Writer is
// not safe for concurrent use.
//
// Errors are sticky: once writing to the destination fails (or the chunk
// counter overflows), Write and Close return that error.
type Writer struct {
	dst     io.Writer
	aead    cipher.AEAD
	aad     [HeaderSize]byte
	buf     []byte // pending plaintext, capacity chunkSize
	out     []byte // ciphertext scratch buffer
	counter uint32 // index of the next chunk
	closed  bool
	err     error
}

// NewWriter returns a Writer encrypting file index (its 0-based position in
// the transfer) with the transfer key K into dst. It draws a fresh salt and
// writes the 32-byte header to dst before returning. The caller must call
// Close to emit the final chunk; Close does not close dst.
func NewWriter(dst io.Writer, key []byte, index int, opts ...Option) (*Writer, error) {
	o := writerOptions{chunkSize: DefaultChunkSize}
	for _, opt := range opts {
		opt(&o)
	}
	if !ValidChunkSize(o.chunkSize) {
		return nil, ErrInvalidChunkSize
	}
	if err := checkKeyIndex(key, index); err != nil {
		return nil, err
	}
	h := Header{ChunkSize: o.chunkSize}
	if err := randomBytes(h.Salt[:]); err != nil {
		return nil, err
	}
	aead := fileAEAD(key, index, &h)
	w := &Writer{
		dst:  dst,
		aead: aead,
		aad:  h.Bytes(),
		buf:  make([]byte, 0, o.chunkSize),
		out:  make([]byte, 0, o.chunkSize+TagSize),
	}
	if err := writeFull(dst, w.aad[:]); err != nil {
		return nil, err
	}
	return w, nil
}

// Write implements io.Writer. It encrypts p and emits every chunk known not to
// be the final one.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, ErrWriterClosed
	}
	n := 0
	for len(p) > 0 {
		if len(w.buf) == cap(w.buf) {
			if err := w.emit(false); err != nil {
				return n, err
			}
		}
		m := copy(w.buf[len(w.buf):cap(w.buf)], p)
		w.buf = w.buf[:len(w.buf)+m]
		p = p[m:]
		n += m
	}
	return n, nil
}

// Close emits the final chunk (empty only for an empty file). It does not
// close the destination. Using the Writer afterwards returns ErrWriterClosed.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrWriterClosed
	}
	w.closed = true
	return w.emit(true)
}

// emit encrypts and writes the buffered plaintext as chunk w.counter.
func (w *Writer) emit(last bool) error {
	if !last && w.counter == math.MaxUint32 {
		// A final chunk must follow, and it would need counter 2^32.
		w.err = ErrCounterOverflow
		return w.err
	}
	nonce := chunkNonce(w.counter, last)
	w.out = w.aead.Seal(w.out[:0], nonce[:], w.buf, w.aad[:])
	clear(w.buf)
	w.buf = w.buf[:0]
	if err := writeFull(w.dst, w.out); err != nil {
		w.err = err
		return err
	}
	w.counter++
	return nil
}

// writeFull writes b to dst and reports short writes as io.ErrShortWrite.
func writeFull(dst io.Writer, b []byte) error {
	n, err := dst.Write(b)
	if err != nil {
		return fmt.Errorf("tte2: write: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("tte2: write: %w", io.ErrShortWrite)
	}
	return nil
}
