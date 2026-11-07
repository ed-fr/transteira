package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/tte2"
)

// sender sends the bytes of one file to its tus upload.
type sender struct {
	c     *client.Client
	file  *os.File
	fs    *fileState
	cc    *tte2.ChunkCipher // nil for a plaintext transfer
	size  int64             // bytes to send (the ciphertext size with E2E)
	chunk int64
	// report receives the number of bytes stored on the server so far.
	report func(int64)
}

// sendFile uploads the file fs of state s through its upload URL, from
// the offset the server reports, until the server holds every byte.
func sendFile(ctx context.Context, c *client.Client, s *state, index int, chunk int64, report func(int64)) error {
	fs := &s.Files[index]
	if err := checkUnchanged(fs.localFile); err != nil {
		return err
	}
	file, err := os.Open(fs.Path)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer func() { _ = file.Close() }()
	sd := &sender{c: c, file: file, fs: fs, size: fs.wireSize(s.e2e()), chunk: chunk, report: report}
	if s.e2e() {
		if sd.cc, err = s.cipher(index); err != nil {
			return err
		}
	}
	return sd.run(ctx)
}

// run is the PATCH loop with its HEAD resume.
func (sd *sender) run(ctx context.Context) error {
	offset, err := sd.head(ctx)
	if err != nil {
		return err
	}
	failures := 0
	for offset < sd.size {
		sd.report(offset)
		next, err := sd.patch(ctx, offset, min(sd.chunk, sd.size-offset))
		if err == nil && next > offset {
			offset, failures = next, 0
			continue
		}
		if err == nil {
			err = fmt.Errorf("upload: the server did not store any byte at offset %d", offset)
		} else if !resumable(err) || ctx.Err() != nil {
			return gone(err)
		}
		failures++
		if failures >= client.DefaultMaxAttempts {
			return err
		}
		if perr := sd.c.Pause(ctx, failures, err, client.Policy{}); perr != nil {
			return perr
		}
		before := offset
		if offset, err = sd.head(ctx); err != nil {
			return err
		}
		if offset > before {
			// The failed PATCH still stored bytes: only failures in a
			// row without progress count against the limit.
			failures = 0
		}
	}
	sd.report(offset)
	return nil
}

// resumable reports whether a failed PATCH may be resumed after HEAD: a
// retryable failure, a 409 (offset or concurrency conflict) or a 400
// without a problem body (body interrupted).
func resumable(err error) bool {
	if p := problemOf(err); p != nil {
		return p.Status == http.StatusConflict || (p.Status == http.StatusBadRequest && p.Code == "") || p.Retryable()
	}
	return client.IsRetryable(err)
}

// tusRequest returns a tus request on the upload URL of the file.
func (sd *sender) tusRequest(ctx context.Context, method string, body io.Reader) (*http.Request, error) {
	req, err := sd.c.NewRequest(ctx, method, sd.fs.UploadURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	return req, nil
}

// head returns the offset of the upload (HEAD, retried by the client).
func (sd *sender) head(ctx context.Context) (int64, error) {
	req, err := sd.tusRequest(ctx, http.MethodHead, nil)
	if err != nil {
		return 0, err
	}
	resp, err := sd.c.Do(ctx, req, client.Policy{})
	if err != nil {
		return 0, gone(err)
	}
	_ = resp.Body.Close()
	offset, err := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 || offset > sd.size {
		return 0, errors.New("upload: invalid Upload-Offset in the answer of the server")
	}
	if l := resp.Header.Get("Upload-Length"); l != "" && l != strconv.FormatInt(sd.size, 10) {
		return 0, fmt.Errorf("%w: the server expects another size for %s", ErrStateMismatch, sd.fs.Path)
	}
	return offset, nil
}

// patch sends n bytes from offset and returns the new offset.
func (sd *sender) patch(ctx context.Context, offset, n int64) (int64, error) {
	var (
		mu     sync.Mutex
		bodies []*progressReader
	)
	newBody := func() *progressReader {
		b := &progressReader{r: sd.section(offset, n), report: func(done int64) { sd.report(offset + done) }}
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		return b
	}
	req, err := sd.tusRequest(ctx, http.MethodPatch, newBody())
	if err != nil {
		return 0, err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(newBody()), nil }
	req.ContentLength = n
	req.Header.Set("Content-Type", tusType)
	req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	resp, err := sd.c.Do(ctx, req, client.Policy{MaxAttempts: 1})
	if resp != nil {
		_ = resp.Body.Close()
	}
	var bodyErr error
	mu.Lock()
	for _, b := range bodies {
		if e := b.close(); e != nil && bodyErr == nil {
			bodyErr = e
		}
	}
	mu.Unlock()
	if bodyErr != nil && (err != nil || errors.Is(bodyErr, ErrStateMismatch)) {
		// The body failed (file changed, read error): never resume with it.
		return 0, bodyErr
	}
	if err != nil {
		return 0, err
	}
	next, err := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || next < offset || next > sd.size {
		return 0, errors.New("upload: invalid Upload-Offset in the answer of the server")
	}
	return next, nil
}

// section returns the n bytes of the upload stream at offset: the file
// itself, or the ciphertext produced on the fly.
func (sd *sender) section(offset, n int64) io.Reader {
	if sd.cc == nil {
		return io.NewSectionReader(sd.file, offset, n)
	}
	return &sealReader{
		file: sd.file, cc: sd.cc, fs: sd.fs, count: tte2.ChunkCount(sd.fs.Size, sd.fs.ChunkSize),
		pos: offset, end: offset + n, header: sd.fs.header().Bytes(),
	}
}

// sealReader produces the bytes [pos, end) of the TTE2 stream of a file:
// header bytes, then each chunk read from the file, checked against its
// recorded plaintext digest and sealed. Its memory is one sealed chunk.
type sealReader struct {
	file   io.ReaderAt
	cc     *tte2.ChunkCipher
	fs     *fileState
	count  int64
	pos    int64
	end    int64
	header [tte2.HeaderSize]byte
	buf    []byte
	cur    []byte
}

// Read returns the next bytes of the stream.
func (r *sealReader) Read(p []byte) (int, error) {
	if r.pos >= r.end {
		return 0, io.EOF
	}
	if len(r.cur) == 0 {
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	p = p[:min(int64(len(p)), r.end-r.pos)]
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	r.pos += int64(n)
	return n, nil
}

// fill prepares the header or the sealed chunk holding r.pos, from the
// byte at r.pos on.
func (r *sealReader) fill() error {
	if r.pos < tte2.HeaderSize {
		r.cur = r.header[r.pos:]
		return nil
	}
	chunk := r.fs.ChunkSize
	n, skip := tte2.ChunkAt(r.pos, chunk)
	if n < 0 || n >= r.count {
		return fmt.Errorf("upload: offset %d beyond the encrypted stream", r.pos)
	}
	if r.buf == nil {
		r.buf = make([]byte, chunk+tte2.TagSize)
	}
	plain := r.buf[:chunkLen(r.fs.Size, chunk, r.count, n)]
	got, err := r.file.ReadAt(plain, n*int64(chunk))
	if got < len(plain) {
		return readError(r.fs.Path, err)
	}
	d := sha256.Sum256(plain)
	if !bytes.Equal(d[:], r.fs.ChunkDigests[n*sha256.Size:(n+1)*sha256.Size]) {
		return fmt.Errorf("%w: %s was modified", ErrStateMismatch, r.fs.Path)
	}
	sealed, err := r.cc.Seal(r.buf[:0], uint64(n), plain, n == r.count-1)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	r.cur = sealed[skip:]
	return nil
}
