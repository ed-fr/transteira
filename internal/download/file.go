package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// errSizeMismatch reports a stored file whose plaintext size differs from
// the size recorded for it.
var errSizeMismatch = errors.New("download: stored file size differs from the recorded size")

// File is one deliverable file opened for download (downloadFile).
type File struct {
	// ID is the file identifier.
	ID string
	// Name is the original file name. The HTTP layer derives the
	// Content-Disposition from it (sanitized ASCII fallback and RFC 5987
	// filename*); it is never logged.
	Name string
	// Size is the size of the clear file in bytes.
	Size int64
	// SHA256 is the lowercase hexadecimal SHA-256 of the clear file.
	SHA256 string
	// Content streams the clear file. The caller must close it
	// ([Content.Close]).
	Content *Content
}

// Content is the decrypted content of a [File]: an io.ReadSeeker for
// http.ServeContent, which serves the Range requests, decrypting one chunk
// at a time.
//
// It records the byte ranges actually read, and credits them as served
// when it is closed. To never count bytes the client did not get, a read
// is credited only once it is followed by another read, which an io.Copy
// only does after writing what it read, or once [Content.Delivered] tells
// that the response was written without error. A read followed by a seek
// is not credited (http.ServeContent reads the start of the content to
// sniff its type, then seeks back, when no Content-Type is set). An empty
// file is credited only through Delivered. A Content holds a concurrent
// stream slot until it is closed. It is not safe for concurrent use.
type Content struct {
	svc   *Service
	t     *tenant.Tenant
	d     store.TransferDetails
	files []store.TransferFile
	file  store.TransferFile
	osf   *os.File
	sr    *io.SectionReader
	// track is set while the transfer has not been downloaded yet.
	track bool
	pos   int64
	// spans are the credited reads; pending is the last read, not credited
	// yet (end 0 when none).
	spans     []span
	pending   span
	delivered bool
	closed    bool
	release   func()
}

// OpenFile opens the deliverable file fileID of the transfer of the
// download token rawToken in tenant t (downloadFile), for the client
// clientIP. grantCookie is the raw value of the GrantCookieName cookie, ""
// when absent.
//
// It returns ErrNotFound and ErrGone as Resolve does, ErrDownloadLocked for
// a password-protected transfer not unlocked by this browser, ErrNotFound
// for a file that is not a deliverable file of the transfer, a
// *TooManyStreamsError (ErrTooManyStreams) over the concurrent stream
// limits, and ErrNoClientIP for an invalid clientIP.
//
// The HTTP layer sets Content-Type (so that http.ServeContent does not
// sniff) and serves File.Content with http.ServeContent. It calls
// [Content.Delivered] only for a GET answered 200 or 206 whose body was
// written without error (never for HEAD, 416 or a failed write), then
// closes the content in every case with the request context. Closing
// releases the stream slot and records the served ranges; when every byte
// of every deliverable file has been served at least once, across
// requests, the transfer counts as downloaded (see the package
// documentation).
func (s *Service) OpenFile(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie, fileID string) (*File, error) {
	a, err := s.resolve(ctx, t, rawToken, grantCookie)
	if err != nil {
		return nil, err
	}
	if !a.unlocked {
		return nil, ErrDownloadLocked
	}
	idx := slices.IndexFunc(a.files, func(f store.TransferFile) bool { return f.ID == fileID })
	if idx < 0 {
		return nil, ErrNotFound
	}
	f := a.files[idx]
	release, err := s.acquireStream(ctx, t, a.d.ID, clientIP)
	if err != nil {
		return nil, err
	}
	osf, ra, err := s.openAt(ctx, t.ID, f)
	if err != nil {
		release()
		s.log(ctx, slog.LevelError, "file not opened", t.ID, a.d.ID, slog.String("file", f.ID), slog.Any("error", err))
		return nil, err
	}
	c := &Content{
		svc: s, t: t, d: a.d, files: a.files, file: f, osf: osf, release: release,
		sr: io.NewSectionReader(ra, 0, ra.Size()), track: a.d.FirstDownloadedAt.IsZero(),
	}
	return &File{ID: f.ID, Name: f.Name, Size: f.Size, SHA256: f.SHA256, Content: c}, nil
}

// openAt opens the stored file of f for random access.
func (s *Service) openAt(ctx context.Context, tid tenant.ID, f store.TransferFile) (*os.File, *crypto.ReaderAt, error) {
	dek, err := s.vault.Open(ctx, tid, crypto.PurposeDEK, f.DEKKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("download: open data key: %w", err)
	}
	defer clear(dek)
	osf, size, err := s.files.OpenRead(tid, f.StorageName)
	if err != nil {
		return nil, nil, fmt.Errorf("download: open stored file: %w", err)
	}
	ra, err := crypto.NewReaderAt(osf, size, dek, tid.String(), f.ID)
	if err == nil && ra.Size() != f.Size {
		err = errSizeMismatch
	}
	if err != nil {
		_ = osf.Close()
		return nil, nil, fmt.Errorf("download: read stored file: %w", err)
	}
	return osf, ra, nil
}

// credit credits the pending read, if any.
func (c *Content) credit() {
	if c.pending.end == 0 {
		return
	}
	if l := len(c.spans); l > 0 && c.spans[l-1].end == c.pending.start {
		c.spans[l-1].end = c.pending.end
	} else if l < maxContentSpans {
		c.spans = append(c.spans, c.pending)
	}
	c.pending = span{}
}

// Read implements io.Reader: it reads decrypted bytes from the current
// offset.
func (c *Content) Read(p []byte) (int, error) {
	c.credit()
	n, err := c.sr.Read(p)
	if n > 0 {
		c.pending = span{start: c.pos, end: c.pos + int64(n)}
		c.pos += int64(n)
	}
	return n, err
}

// Seek implements io.Seeker. The pending read is not credited.
func (c *Content) Seek(offset int64, whence int) (int64, error) {
	c.pending = span{}
	pos, err := c.sr.Seek(offset, whence)
	if err == nil {
		c.pos = pos
	}
	return pos, err
}

// Delivered tells that the response was a GET answered 200 or 206 whose
// body was written to the client without error, so that the last read is
// credited too, and that an empty file counts as served. The HTTP layer
// never calls it for HEAD, 416 or a failed write.
func (c *Content) Delivered() {
	c.credit()
	c.delivered = true
}

// Close releases the stored file and the stream slot, and records the
// ranges served (see the type documentation). The recording is detached
// from the cancellation of ctx (the request context, done once the client
// is gone) and bounded by Options.CommitTimeout; its failures are logged,
// not returned, since the response is over. It returns the error of
// closing the file; closing twice does nothing.
func (c *Content) Close(ctx context.Context) error {
	if c.closed {
		return nil
	}
	c.closed = true
	defer c.release()
	err := c.osf.Close()
	if c.track && (len(c.spans) > 0 || (c.file.Size == 0 && c.delivered)) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.svc.opts.CommitTimeout)
		defer cancel()
		c.svc.commit(ctx, c.t, c.d, c.files, c.file, c.spans)
	}
	if err != nil {
		return fmt.Errorf("download: close stored file: %w", err)
	}
	return nil
}
