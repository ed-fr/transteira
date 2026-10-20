package crypto

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

// WithChunkSize sets the plaintext chunk size, which must lie in
// [MinChunkSize, MaxChunkSize]. It is recorded in the header, so readers need
// no option.
func WithChunkSize(n int) Option {
	return func(o *writerOptions) { o.chunkSize = n }
}

// Writer encrypts a stream into the chunked format. It buffers at most one
// chunk of plaintext in memory, emits only complete chunks while writing and
// the final chunk on Close. A Writer is not safe for concurrent use.
//
// Errors are sticky: once writing to the destination fails (or the chunk
// counter overflows), Write, Checkpoint and Close return that same error and
// the Writer is unusable. The destination then holds an unknown number of
// bytes; the upload must restart from the last persisted checkpoint, which
// ResumeWriter accepts only if the file still has exactly the checkpoint size,
// or from scratch with a new file ID and a new DEK.
type Writer struct {
	dst       io.Writer
	aead      cipher.AEAD // chunks, keyed with the DEK
	tailAEAD  cipher.AEAD // checkpoint tails, keyed with the tail subkey
	header    header
	chunkSize int
	aad       []byte // chunk AAD
	tailAAD   []byte // tail AAD without the chunk count and extra length
	buf       []byte // pending plaintext, capacity chunkSize
	out       []byte // ciphertext scratch buffer
	counter   uint32 // index of the next chunk
	accepted  int64  // plaintext bytes accepted so far (Offset)
	closed    bool
	err       error
}

// NewWriter returns a Writer that encrypts into dst with dek (DEKSize bytes)
// for the file fileID of tenant tenantID. The 16-byte header, holding a fresh
// random nonce prefix, is written to dst before NewWriter returns. The caller
// must call Close to emit the final chunk; Close does not close dst.
func NewWriter(dst io.Writer, dek []byte, tenantID, fileID string, opts ...Option) (*Writer, error) {
	o := writerOptions{chunkSize: DefaultChunkSize}
	for _, opt := range opts {
		opt(&o)
	}
	if o.chunkSize < MinChunkSize || o.chunkSize > MaxChunkSize {
		return nil, ErrInvalidChunkSize
	}
	aead, err := streamKey(dek, tenantID, fileID)
	if err != nil {
		return nil, err
	}
	h, err := newHeader(o.chunkSize)
	if err != nil {
		return nil, err
	}
	w := newWriter(dst, aead, tailKey(dek), h, o.chunkSize, tenantID, fileID)
	if err := writeFull(dst, h[:]); err != nil {
		return nil, err
	}
	return w, nil
}

// newWriter builds a Writer for header h without writing anything.
func newWriter(dst io.Writer, aead, tail cipher.AEAD, h header, chunkSize int, tenantID, fileID string) *Writer {
	return &Writer{
		dst:       dst,
		aead:      aead,
		tailAEAD:  tail,
		header:    h,
		chunkSize: chunkSize,
		aad:       bindingAAD(chunkLabel, &h, tenantID, fileID),
		tailAAD:   bindingAAD(tailLabel, &h, tenantID, fileID),
		buf:       make([]byte, 0, chunkSize),
		out:       make([]byte, 0, chunkSize+tagSize),
	}
}

// writeFull writes b to dst, turning a short write into an error.
func writeFull(dst io.Writer, b []byte) error {
	n, err := dst.Write(b)
	if err != nil {
		return fmt.Errorf("crypto: write: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("crypto: write: %w", io.ErrShortWrite)
	}
	return nil
}

// usable returns the sticky error, or ErrWriterClosed after Close.
func (w *Writer) usable() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrWriterClosed
	}
	return nil
}

// Write buffers p and encrypts every chunk it completes. It returns the number
// of bytes of p consumed. After an error, see the sticky-error rule on Writer.
func (w *Writer) Write(p []byte) (int, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	n := 0
	for len(p) > 0 {
		c := copy(w.buf[len(w.buf):w.chunkSize], p)
		w.buf = w.buf[:len(w.buf)+c]
		p = p[c:]
		n += c
		w.accepted += int64(c)
		if len(w.buf) == w.chunkSize {
			if err := w.emit(false); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// Offset returns the number of plaintext bytes accepted so far, across
// resumptions: the tus Upload-Offset of the upload. It equals the
// State.PlaintextSize of a Checkpoint taken now, and does not change after
// Close.
func (w *Writer) Offset() int64 { return w.accepted }

// emit seals the buffered plaintext as chunk w.counter and writes it.
func (w *Writer) emit(last bool) error {
	// The final chunk needs a counter of its own, so a non-final chunk may not
	// take the last counter value.
	if !last && w.counter == math.MaxUint32 {
		w.err = ErrCounterOverflow
		return w.err
	}
	nonce := w.header.nonce(w.counter, last)
	w.out = w.aead.Seal(w.out[:0], nonce[:], w.buf, w.aad)
	clear(w.buf)
	w.buf = w.buf[:0]
	if err := writeFull(w.dst, w.out); err != nil {
		w.err = err
		return err
	}
	w.counter++
	return nil
}

// Close encrypts the buffered plaintext, possibly empty, as the final chunk.
// Calling Close again returns nil; Write and Checkpoint return ErrWriterClosed
// afterwards. Close does not close the destination.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	err := w.emit(true)
	w.closed = true
	return err
}

// Checkpoint captures the state needed to resume this upload later with
// ResumeWriter: the header, the number of complete chunks emitted so far, and
// the incomplete tail together with extra, sealed under the tail subkey with a
// fresh random nonce. Checkpoint does not write to the destination, which then
// holds exactly State.CiphertextSize bytes, and may be called any number of
// times.
//
// extra (at most MaxCheckpointExtra bytes, otherwise ErrExtraTooLarge) is an
// opaque caller payload that may contain plaintext-derived secrets, such as a
// marshaled SHA-256 state, which holds up to 63 bytes of plaintext: it is
// encrypted and authenticated with the tail and returned by ResumeWriter. Its
// length is visible in the State.
//
// Before persisting the State (State.MarshalBinary), the caller must flush
// everything written to the destination (no unflushed bufio.Writer) and fsync
// it; otherwise a power loss can leave a file shorter than the checkpoint,
// which ResumeWriter refuses with ErrStaleCheckpoint. The State must be
// persisted before acknowledging the data it covers (each tus PATCH).
func (w *Writer) Checkpoint(extra []byte) (*State, error) {
	if len(extra) > MaxCheckpointExtra {
		return nil, ErrExtraTooLarge
	}
	if err := w.usable(); err != nil {
		return nil, err
	}
	var nonce [nonceSize]byte
	if err := randomBytes(nonce[:]); err != nil {
		return nil, err
	}
	plain := make([]byte, 0, len(extra)+len(w.buf))
	plain = append(append(plain, extra...), w.buf...)
	defer clear(plain)
	extraLen := u32(len(extra))
	tail := make([]byte, 0, envelopeOverhead+len(plain))
	tail = append(tail, tailVersion)
	tail = append(tail, nonce[:]...)
	tail = w.tailAEAD.Seal(tail, nonce[:], plain, tailAAD(w.tailAAD, w.counter, extraLen))
	return &State{header: w.header, chunks: w.counter, extraLen: extraLen, tail: tail}, nil
}

// ResumeWriter reopens an upload captured by Writer.Checkpoint and returns the
// Writer and the extra payload given to Checkpoint (nil if it was empty).
//
// existingSize is the current size of the encrypted file on disk and dst must
// be positioned at its end. It must equal st.CiphertextSize() exactly,
// otherwise ResumeWriter returns ErrStaleCheckpoint: a shorter file has lost
// data, and a longer one holds ciphertext written after the checkpoint (a full
// chunk or even a partial write) under counter nonces that resuming would use
// again for possibly different plaintext. On ErrStaleCheckpoint the caller must
// restart the upload from scratch with a new file ID and a new DEK; it must
// never truncate the file and resume. To keep this rare, the caller must
// flush and fsync the file, then persist the checkpoint, before acknowledging
// each upload request (tus PATCH); see Writer.Checkpoint.
//
// The caller must hold an exclusive lock on the upload from ResumeWriter until
// the next persisted checkpoint or Close: two Writers resumed concurrently from
// the same State would encrypt different plaintexts under the same nonces.
//
// The tail is authenticated against dek, tenantID, fileID, the header, the
// chunk count and the extra length: a tampered state or a state of another
// file returns ErrAuth, a malformed one ErrBadState. ResumeWriter writes
// nothing to dst.
func ResumeWriter(dst io.Writer, dek []byte, tenantID, fileID string, st *State, existingSize int64) (*Writer, []byte, error) {
	chunkSize, err := st.validate()
	if err != nil {
		return nil, nil, err
	}
	if existingSize != st.CiphertextSize() {
		return nil, nil, ErrStaleCheckpoint
	}
	aead, err := streamKey(dek, tenantID, fileID)
	if err != nil {
		return nil, nil, err
	}
	w := newWriter(dst, aead, tailKey(dek), st.header, chunkSize, tenantID, fileID)
	plain, err := w.tailAEAD.Open(nil, st.tail[1:1+nonceSize], st.tail[1+nonceSize:],
		tailAAD(w.tailAAD, st.chunks, st.extraLen))
	if err != nil {
		return nil, nil, ErrAuth
	}
	defer clear(plain)
	extra := append([]byte(nil), plain[:st.extraLen]...)
	w.buf = append(w.buf, plain[st.extraLen:]...)
	w.counter = st.chunks
	w.accepted = int64(st.chunks)*int64(chunkSize) + int64(len(w.buf))
	return w, extra, nil
}
