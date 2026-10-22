package download

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/filename"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/zipstream"
)

// archiveFormat writes ZIP64 records only where they are needed, so that
// the archive opens with the macOS Archive Utility.
var archiveFormat = zipstream.Format{Zip64Threshold: zipstream.Zip64WhenNeeded}

// archiveSize computes the size of an archive; the tests replace it to
// cover its failure, which valid entries never provoke.
var archiveSize = archiveFormat.Size

// Archive is the ZIP archive of the deliverable files of a transfer,
// prepared for streaming (downloadArchive). Create it with
// [Service.PrepareArchive], set Content-Length to [Archive.Size], then
// stream it once with [Archive.Write]. It holds a concurrent stream slot
// until Write returns or [Archive.Close] is called; the HTTP layer defers
// Close so that the slot is released even when Write is never called.
type Archive struct {
	svc     *Service
	t       *tenant.Tenant
	d       store.TransferDetails
	files   []store.TransferFile
	entries []zipstream.Entry
	size    int64
	ip      netip.Addr
	release func()
}

// PrepareArchive prepares the archive of the transfer of the download
// token rawToken in tenant t, for the client clientIP. grantCookie is the
// raw value of the GrantCookieName cookie, "" when absent. The entries are
// the deliverable files by position, named by filename.ArchiveName
// (sanitized and made unique), stored without compression.
//
// It returns ErrNotFound and ErrGone as Resolve does, ErrDownloadLocked for
// a password-protected transfer not unlocked by this browser, a
// *TooManyStreamsError (ErrTooManyStreams) over the concurrent stream
// limits, and ErrNoClientIP for an invalid clientIP.
func (s *Service) PrepareArchive(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie string) (*Archive, error) {
	a, err := s.resolve(ctx, t, rawToken, grantCookie)
	if err != nil {
		return nil, err
	}
	if !a.unlocked {
		return nil, ErrDownloadLocked
	}
	seen := map[string]int{}
	entries := make([]zipstream.Entry, 0, len(a.files))
	for _, f := range a.files {
		entries = append(entries, zipstream.Entry{Name: filename.ArchiveName(f.Name, seen), Size: f.Size, Modified: f.UploadedAt})
	}
	size, err := archiveSize(entries)
	if err != nil {
		return nil, fmt.Errorf("download: size archive: %w", err)
	}
	release, err := s.acquireStream(ctx, t, a.d.ID, clientIP)
	if err != nil {
		return nil, err
	}
	return &Archive{svc: s, t: t, d: a.d, files: a.files, entries: entries, size: size, ip: clientIP, release: release}, nil
}

// Close releases the stream slot of the archive, if Write did not already.
// It may be called any number of times.
func (a *Archive) Close() { a.release() }

// Size returns the exact length of the archive in bytes, for the
// Content-Length header.
func (a *Archive) Size() int64 { return a.size }

// Write streams the archive to w, decrypting one file at a time, one chunk
// at a time. Calling Write is a download start: it first records the
// transfer.downloaded audit event and counts one download (the HTTP layer
// never calls it for HEAD); a failure of that recording is logged and the
// archive is still written. When it returns, the plaintext bytes of the
// files written are counted in the tenant usage. When the whole archive was written without error, the
// transfer counts as downloaded (the first download mail and the deletion
// after the first download follow, see the package documentation); a
// partial write never counts; a transfer already downloaded is not
// recorded again. The output must be discarded after an error. The
// recording done after a complete write is detached from the cancellation
// of ctx; its failures are logged, not returned. Write releases the stream
// slot when it returns.
func (a *Archive) Write(ctx context.Context, w io.Writer) error {
	defer a.release()
	a.svc.downloadStarted(ctx, a.t, a.d.ID, archiveObject, a.ip)
	var served int64
	defer func() { a.svc.bytesServed(a.t.ID, served) }()
	err := archiveFormat.Write(w, a.entries, func(i int) (io.Reader, error) {
		return a.svc.openEntry(ctx, a.t.ID, a.files[i], &served)
	})
	if err != nil {
		a.svc.log(ctx, slog.LevelInfo, "archive not sent to its end", a.t.ID, a.d.ID, slog.Any("error", err))
		return fmt.Errorf("download: write archive: %w", err)
	}
	served = 0
	for _, f := range a.files {
		served += f.Size
	}
	if !a.d.FirstDownloadedAt.IsZero() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.svc.opts.CommitTimeout)
	defer cancel()
	a.svc.completeArchive(ctx, a.t, a.d)
	return nil
}

// entryReader is the decrypted content of an archive entry; Close releases
// the stored file (zipstream closes it once the entry is copied). It adds
// to served the bytes read, each read once followed by another, which
// zipstream only does after writing what it read: a failed archive never
// counts bytes the client did not get.
type entryReader struct {
	cr      *crypto.Reader
	osf     *os.File
	served  *int64
	pending int64
}

// Read implements io.Reader.
func (r *entryReader) Read(p []byte) (int, error) {
	*r.served += r.pending
	n, err := r.cr.Read(p)
	r.pending = int64(n)
	return n, err
}

// Close implements io.Closer.
func (r *entryReader) Close() error { return r.osf.Close() }

// openEntry opens the stored file of f for sequential decryption, counting
// the bytes read in served.
func (s *Service) openEntry(ctx context.Context, tid tenant.ID, f store.TransferFile, served *int64) (io.Reader, error) {
	dek, err := s.vault.Open(ctx, tid, crypto.PurposeDEK, f.DEKKeyID)
	if err != nil {
		return nil, fmt.Errorf("open data key: %w", err)
	}
	defer clear(dek)
	osf, _, err := s.files.OpenRead(tid, f.StorageName)
	if err != nil {
		return nil, fmt.Errorf("open stored file: %w", err)
	}
	cr, err := crypto.NewReader(osf, dek, tid.String(), f.ID)
	if err != nil {
		_ = osf.Close()
		return nil, fmt.Errorf("read stored file: %w", err)
	}
	return &entryReader{cr: cr, osf: osf, served: served}, nil
}
