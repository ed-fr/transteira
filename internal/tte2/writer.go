package tte2

import (
	"fmt"
	"io"
)

// Option configures a Writer created by NewWriter.
type Option func(*writerOptions)

// writerOptions holds the NewWriter options.
type writerOptions struct {
	chunkSize int
	header    *Header
}

// WithChunkSize sets the plaintext chunk size, a power of two in
// [MinChunkSize, MaxChunkSize]. It is recorded in the header, so readers need
// no option.
func WithChunkSize(n int) Option {
	return func(o *writerOptions) { o.chunkSize = n }
}

// WithHeader makes the Writer use header h (its chunk size and salt) instead
// of drawing a fresh salt, so that the same plaintext, key and index produce
// the same stream byte for byte (see NewHeader). It takes precedence over
// WithChunkSize. A header must only ever be reused for the same file: two
// different plaintexts under one key, index and salt reuse nonces.
func WithHeader(h Header) Option {
	return func(o *writerOptions) { o.header = &h }
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
	cipher  *ChunkCipher
	buf     []byte // pending plaintext, capacity chunkSize
	out     []byte // ciphertext scratch buffer
	counter uint32 // index of the next chunk
	closed  bool
	err     error
}

// NewWriter returns a Writer encrypting file index (its 0-based position in
// the transfer) with the transfer key K into dst. It draws a fresh salt
// (unless WithHeader is given) and writes the 32-byte header to dst before returning. The caller must call
// Close to emit the final chunk; Close does not close dst.
func NewWriter(dst io.Writer, key []byte, index int, opts ...Option) (*Writer, error) {
	o := writerOptions{chunkSize: DefaultChunkSize}
	for _, opt := range opts {
		opt(&o)
	}
	if o.header == nil && !ValidChunkSize(o.chunkSize) {
		return nil, ErrInvalidChunkSize
	}
	if err := checkKeyIndex(key, index); err != nil {
		return nil, err
	}
	var h Header
	if o.header != nil {
		h = *o.header
	} else {
		var err error
		if h, err = NewHeader(o.chunkSize); err != nil {
			return nil, err
		}
	}
	c, err := NewChunkCipher(key, index, h)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		dst:    dst,
		cipher: c,
		buf:    make([]byte, 0, h.ChunkSize),
		out:    make([]byte, 0, h.ChunkSize+TagSize),
	}
	head := h.Bytes()
	if err := writeFull(dst, head[:]); err != nil {
		return nil, err
	}
	return w, nil
}

// Header returns the stream header, to reproduce the stream with WithHeader or
// to build the matching ChunkCipher.
func (w *Writer) Header() Header { return w.cipher.Header() }

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
	// Seal also refuses a middle chunk at counter 2^32-1 (a final chunk
	// would need counter 2^32) with ErrCounterOverflow. The Writer only
	// emits chunks of valid lengths: a middle chunk once the buffer is full,
	// and an empty final chunk only at counter 0.
	out, err := w.cipher.Seal(w.out[:0], uint64(w.counter), w.buf, last)
	clear(w.buf)
	if err != nil {
		w.err = err
		return err
	}
	w.out = out
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
