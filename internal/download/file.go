package download

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// errSizeMismatch reports a stored file whose plaintext size differs from
// the size recorded for it.
var errSizeMismatch = errors.New("download: stored file size differs from the recorded size")

// errNotBegun reports a read of a file of a transfer with a download
// limit whose [Content.Begin] allowed no GET (a HEAD request): nothing is
// read.
var errNotBegun = errors.New("download: content read without a download start")

// File is one deliverable file opened for download (downloadFile).
type File struct {
	// ID is the file identifier.
	ID string
	// Name is the original file name. The HTTP layer derives the
	// Content-Disposition from it (sanitized ASCII fallback and RFC 5987
	// filename*); it is never logged.
	Name string
	// Path is the folder of the file inside the transfer, "" at the root
	// (since 1.1). It is informational: a single file is saved under its
	// name alone.
	Path string
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
//
// The first read from offset 0 is a download start: it records the
// transfer.downloaded audit event and counts one download, before the
// bytes are read (an empty file, never read, starts with Delivered). A
// HEAD request (never read, never delivered) and a resumed range (read
// from a later offset) are no start. The HTTP layer must set Content-Type,
// so that http.ServeContent does not read the content to sniff it.
//
// For a transfer with a download limit, the start is decided before any
// byte instead, by [Content.Begin], which the HTTP layer calls when the
// response is about to be answered 200 or 206 (see [Service.claimStart]).
// Should it not, the first read begins it as a GET, and a refusal fails
// that read (fail closed).
type Content struct {
	svc *Service
	// ctx is the request context, for the recording of the download start:
	// it is kept because http.ServeContent drives Read and Seek, whose
	// signatures take no context (the recording detaches it anyway).
	ctx   context.Context
	ip    netip.Addr
	t     *tenant.Tenant
	d     store.TransferDetails
	link  *store.RecipientLink // nil for a shared link
	files []store.TransferFile
	file  store.TransferFile
	osf   *os.File
	sr    *io.SectionReader
	// track is set while the transfer (or the recipient link) has not been
	// downloaded yet.
	track bool
	pos   int64
	// spans are the credited reads; pending is the last read, not credited
	// yet (end 0 when none).
	spans     []span
	pending   span
	delivered bool
	closed    bool
	// started is set once the download start is recorded.
	started bool
	// limited is set for a transfer with a download limit; begun once
	// [Content.Begin] ran, refused holding its refusal, and allowed once it
	// allowed a GET (never set by a HEAD request).
	limited bool
	begun   bool
	allowed bool
	refused error
	// claimed is the time the start allowed by Begin was counted.
	claimed time.Time
	// served counts the credited bytes.
	served  int64
	release func()
}

// OpenFile opens the deliverable file fileID of the transfer of the
// download token rawToken in tenant t (downloadFile), for the client
// clientIP. cookies are the raw technical cookies of the request.
//
// It returns ErrNotFound and ErrGone as Resolve does,
// ErrVerificationRequired for a recipient link awaiting its verification on
// this browser, ErrDownloadLocked for a password-protected transfer not
// unlocked by this browser, ErrNotFound
// for a file that is not a deliverable file of the transfer (a transfer
// whose download limit is reached is opened: [Content.Begin] decides), a
// *TooManyStreamsError (ErrTooManyStreams) over the concurrent stream
// limits, and ErrNoClientIP for an invalid clientIP.
//
// The HTTP layer sets Content-Type (so that http.ServeContent does not
// sniff) and serves File.Content with http.ServeContent. It calls
// [Content.Delivered] only for a GET answered 200 or 206 whose body was
// written without error (never for HEAD, 416 or a failed write), then
// closes the content in every case with the request context. The first
// read from offset 0 records the download start (see [Content]). Closing
// releases the stream slot, counts the bytes served in the tenant usage and
// records the served ranges; when every byte
// of every deliverable file has been served at least once, across
// requests, the transfer counts as downloaded (see the package
// documentation).
func (s *Service) OpenFile(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, cookies Cookies, fileID string) (*File, error) {
	a, err := s.resolve(ctx, t, rawToken, cookies, false)
	if err != nil {
		return nil, err
	}
	if a.awaiting() {
		return nil, ErrVerificationRequired
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
		svc: s, ctx: ctx, ip: clientIP, t: t, d: a.d, link: a.link, files: a.files, file: f, osf: osf, release: release,
		sr: io.NewSectionReader(ra, 0, ra.Size()), track: tracked(a.d, a.link), limited: a.d.MaxDownloads != nil,
	}
	return &File{ID: f.ID, Name: f.Name, Path: f.Path, Size: f.Size, SHA256: f.SHA256, Content: c}, nil
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
	c.served += c.pending.end - c.pending.start
	if l := len(c.spans); l > 0 && c.spans[l-1].end == c.pending.start {
		c.spans[l-1].end = c.pending.end
	} else if l < maxContentSpans {
		c.spans = append(c.spans, c.pending)
	}
	c.pending = span{}
}

// Begin decides the response of a file of a transfer with a download
// limit, before its headers are written: the HTTP layer calls it once
// http.ServeContent is about to answer 200 or 206, get telling a GET
// (false for HEAD). It returns ErrMaxDownloads once the limit is reached
// for a client whose start is not remembered, ErrGone for a transfer
// deleted meanwhile, or an internal error; the response must then be that
// error, and every later read fails with it. See [Service.claimStart].
// Without download limit, it does nothing: the start is recorded at the
// first read from offset 0, as in version 1.0. Only its first call
// decides.
func (c *Content) Begin(get bool) error {
	if !c.limited || c.begun {
		return c.refused
	}
	c.begun = true
	c.claimed, c.refused = c.svc.claimStart(c.ctx, c.t, c.d, linkIDOf(c.link), c.file.ID, c.ip, get)
	c.allowed = get && c.refused == nil
	return c.refused
}

// Read implements io.Reader: it reads decrypted bytes from the current
// offset.
func (c *Content) Read(p []byte) (int, error) {
	if c.limited && !c.allowed {
		if c.begun {
			return 0, cmp.Or(c.refused, errNotBegun)
		}
		if err := c.Begin(true); err != nil {
			return 0, err
		}
	}
	c.credit()
	if c.pos == 0 {
		c.start()
	}
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
	if c.file.Size == 0 {
		c.start()
	}
}

// start records the download start, once; a start of a transfer with a
// download limit is recorded by [Content.Begin] only.
func (c *Content) start() {
	if c.started || c.limited {
		return
	}
	c.started = true
	c.svc.downloadStarted(c.ctx, c.t, c.d.ID, linkIDOf(c.link), c.file.ID, c.ip)
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
	c.svc.bytesServed(c.t.ID, c.served)
	if c.allowed && !c.delivered {
		c.svc.touchStart(c.t.ID, c.d.ID, linkIDOf(c.link), c.file.ID, c.ip, c.claimed)
	}
	err := c.osf.Close()
	if c.track && (len(c.spans) > 0 || (c.file.Size == 0 && c.delivered)) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.svc.opts.CommitTimeout)
		defer cancel()
		c.svc.commit(ctx, c.t, c.d, c.link, c.files, c.file, c.spans)
	}
	if err != nil {
		return fmt.Errorf("download: close stored file: %w", err)
	}
	return nil
}
