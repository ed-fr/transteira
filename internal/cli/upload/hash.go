package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"

	"github.com/ed-fr/transteira/internal/tte2"
)

// progressStep is the number of bytes between two progress reports of a
// stream.
const progressStep = 1 << 20

// progressReader counts the bytes read from r, reports them through
// report (at most every progressStep bytes, and at the end of the stream)
// and keeps the first error that is not io.EOF, so that a caller sees it
// even when net/http wraps or replaces the body error. A request body may
// be read by a transport goroutine: Read and close are serialized, and
// once closed the reader neither reads nor reports any more.
type progressReader struct {
	mu       sync.Mutex
	r        io.Reader
	done     int64
	reported int64
	report   func(done int64)
	err      error
	closed   bool
}

// Read reads from the underlying reader.
func (p *progressReader) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errBodyClosed
	}
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.report != nil && (p.done-p.reported >= progressStep || (err != nil && p.done != p.reported)) {
		p.reported = p.done
		p.report(p.done)
	}
	if err != nil && !errors.Is(err, io.EOF) && p.err == nil {
		p.err = err
	}
	return n, err
}

// close stops the reader and returns its first error.
func (p *progressReader) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return p.err
}

// errBodyClosed is returned by a request body read after its request
// ended.
var errBodyClosed = errors.New("upload: request body closed")

// ctxReader stops reading once ctx ends.
type ctxReader struct {
	ctx context.Context //nolint:containedctx // a reader bound to the run
	r   io.Reader
}

// Read reads from the underlying reader unless the context ended.
func (c ctxReader) Read(b []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(b)
}

// hashPlain computes the SHA-256 of the file f in a stream, checking that
// it still has the size and modification time of the walk.
func hashPlain(ctx context.Context, f localFile, report func(int64)) (string, error) {
	file, err := os.Open(f.Path)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	pr := &progressReader{r: ctxReader{ctx, file}, report: report}
	n, err := io.Copy(h, pr)
	if err != nil {
		return "", fmt.Errorf("upload: %s: %w", f.Path, err)
	}
	if n != f.Size {
		return "", fmt.Errorf("%w: %s was modified while it was read", ErrStateMismatch, f.Path)
	}
	if err := checkUnchanged(f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashE2E reads the file of fs once and fills its plaintext SHA-256, the
// SHA-256 of each plaintext chunk and the SHA-256 of the whole ciphertext
// stream (header and every sealed chunk), sealing the chunks with cc.
func hashE2E(ctx context.Context, fs *fileState, cc *tte2.ChunkCipher, report func(int64)) error {
	count := tte2.ChunkCount(fs.Size, fs.ChunkSize)
	if count < 0 {
		return fmt.Errorf("upload: %s is too large for end-to-end encryption", fs.Path)
	}
	file, err := os.Open(fs.Path)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer func() { _ = file.Close() }()
	plainHash, cipherHash := sha256.New(), sha256.New()
	hb := fs.header().Bytes()
	cipherHash.Write(hb[:])
	buf := make([]byte, fs.ChunkSize+tte2.TagSize)
	digests := make([]byte, 0, count*sha256.Size)
	pr := &progressReader{r: ctxReader{ctx, file}, report: report}
	for n := range count {
		plain := buf[:chunkLen(fs.Size, fs.ChunkSize, count, n)]
		if _, err := io.ReadFull(pr, plain); err != nil {
			return readError(fs.Path, err)
		}
		plainHash.Write(plain)
		d := sha256.Sum256(plain)
		digests = append(digests, d[:]...)
		sealed, err := cc.Seal(buf[:0], uint64(n), plain, n == count-1)
		if err != nil {
			return fmt.Errorf("upload: %w", err)
		}
		cipherHash.Write(sealed)
	}
	if err := atEOF(pr, fs.Path); err != nil {
		return err
	}
	if err := checkUnchanged(fs.localFile); err != nil {
		return err
	}
	fs.SHA256 = hexSum(plainHash)
	fs.CipherSHA256 = hexSum(cipherHash)
	fs.ChunkDigests = digests
	return nil
}

// atEOF returns ErrStateMismatch unless r is at its end (a read of
// nothing without error counts as the end).
func atEOF(r io.Reader, path string) error {
	var one [1]byte
	n, err := r.Read(one[:])
	if n > 0 {
		return fmt.Errorf("%w: %s grew while it was read", ErrStateMismatch, path)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("upload: %s: %w", path, err)
	}
	return nil
}

// readError turns a short read of a file into ErrStateMismatch.
func readError(path string, err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %s shrank while it was read", ErrStateMismatch, path)
	}
	return fmt.Errorf("upload: %s: %w", path, err)
}

// hexSum returns the lowercase hexadecimal digest of h.
func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

// chunkLen returns the plaintext length of chunk n of a file of size bytes
// split in count chunks of chunk bytes.
func chunkLen(size int64, chunk int, count, n int64) int64 {
	if n < count-1 {
		return int64(chunk)
	}
	return size - n*int64(chunk)
}
