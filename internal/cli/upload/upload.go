package upload

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/tte2"
)

// newKey and newHeader draw the end-to-end key and headers (variables for
// the tests).
var (
	newKey    = tte2.NewKey
	newHeader = tte2.NewHeader
)

// maxFinalizeRounds bounds the finalizations answered 409
// upload-incomplete, each followed by HEAD and the end of the uploads.
const maxFinalizeRounds = 3

// run holds one deposit.
type run struct {
	c         *client.Client
	o         Options
	statePath string
	st        *state
}

// Run deposits the files of o through c and returns the result; see the
// package documentation for the flow, the state file and the errors. With
// [ErrRejected] the result is returned too.
func Run(ctx context.Context, c *client.Client, o Options) (*Result, error) {
	o, err := o.normalize(c)
	if err != nil {
		return nil, err
	}
	if o.Warn == nil {
		o.Warn = func(string) {}
	}
	if o.Progress == nil {
		o.Progress = func(Progress) {}
	}
	abs, err := absolutePaths(o.Paths)
	if err != nil {
		return nil, err
	}
	id := identity(c.BaseURL(), abs, o)
	r := &run{c: c, o: o, statePath: o.StatePath}
	if r.statePath == "" {
		r.statePath = defaultStatePath(id)
	}
	if o.Restart {
		if err := r.restart(ctx); err != nil {
			return nil, err
		}
	}
	files, err := collect(abs, o.Warn)
	if err != nil {
		return nil, err
	}
	if r.st, err = loadState(r.statePath); err != nil {
		return nil, err
	}
	if r.st != nil {
		if err := r.st.matches(id, files); err != nil {
			return nil, err
		}
	} else if err := r.prepare(ctx, id, files); err != nil {
		return nil, err
	}
	res, err := r.deposit(ctx)
	if err != nil && r.definitive(err) {
		if rerr := removeState(r.statePath); rerr != nil {
			o.Warn(rerr.Error())
		}
	}
	return res, err
}

// definitive reports whether err leaves nothing to resume (the state file
// is then removed): see the package documentation.
func (r *run) definitive(err error) bool {
	if errors.Is(err, errGone) || errors.Is(err, ErrRejected) {
		return true
	}
	if r.st.TransferID != "" || errors.Is(err, ErrStateMismatch) {
		return false
	}
	// The creation failed: definitive unless it may succeed when retried.
	p := problemOf(err)
	return p != nil && !p.Retryable()
}

// restart cancels the transfer of the state file, if any, and removes it.
func (r *run) restart(ctx context.Context) error {
	st, err := loadState(r.statePath)
	if err != nil {
		r.o.Warn("ignoring the invalid state file " + r.statePath)
	}
	if st != nil && st.TransferID != "" {
		if err := cancelTransfer(ctx, r.c, st.TransferID); err != nil {
			return err
		}
	}
	return removeState(r.statePath)
}

// prepare runs the hash pass, seals the end-to-end metadata and writes
// the state file.
func (r *run) prepare(ctx context.Context, id string, files []localFile) error {
	st := &state{Version: stateVersion, Identity: id, IdempotencyKey: newIdempotencyKey(), Files: make([]fileState, len(files))}
	if r.o.E2E {
		key, err := newKey()
		if err != nil {
			return fmt.Errorf("upload: %w", err)
		}
		st.Key = key
	}
	for i, f := range files {
		fs := &st.Files[i]
		fs.localFile = f
		fs.MediaType = mediaType(f.Name)
		report := func(done int64) {
			r.o.Progress(Progress{Phase: PhaseHash, File: f.display(), Done: done, Total: f.Size})
		}
		report(0)
		if err := r.hashFile(ctx, st, i); err != nil {
			return err
		}
		report(f.Size)
	}
	if st.e2e() && r.o.Message != "" {
		sealed, err := tte2.SealMessage(st.Key, r.o.Message)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidOptions, err)
		}
		st.EncryptedMessage = sealed
	}
	r.st = st
	return st.save(r.statePath)
}

// hashFile hashes file i of st (and, with E2E, seals its metadata).
func (r *run) hashFile(ctx context.Context, st *state, i int) error {
	fs := &st.Files[i]
	report := func(done int64) {
		r.o.Progress(Progress{Phase: PhaseHash, File: fs.display(), Done: done, Total: fs.Size})
	}
	if !st.e2e() {
		sum, err := hashPlain(ctx, fs.localFile, report)
		fs.SHA256 = sum
		return err
	}
	h, err := newHeader(tte2.DefaultChunkSize)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	fs.Salt, fs.ChunkSize = h.Salt[:], h.ChunkSize
	fs.CipherSize = tte2.CiphertextSize(fs.Size, fs.ChunkSize)
	cc, err := st.cipher(i)
	if err != nil {
		return err
	}
	if err := hashE2E(ctx, fs, cc, report); err != nil {
		return err
	}
	fs.Metadata, err = tte2.SealMetadata(st.Key, i, tte2.Metadata{
		Index: i, Count: len(st.Files), Name: fs.Name, Path: fs.Folder, Type: fs.MediaType,
		Size: fs.Size, SHA256: fs.SHA256,
	})
	if err != nil {
		return fmt.Errorf("upload: %s: %w", fs.Path, err)
	}
	return nil
}

// deposit creates or reads back the transfer, uploads, finalizes and
// waits.
func (r *run) deposit(ctx context.Context) (*Result, error) {
	t, err := r.ensureTransfer(ctx)
	if err != nil {
		return nil, err
	}
	if !r.st.Finalized {
		if t.Status != statusUploading {
			// Finalized by an earlier run whose answer was lost.
			r.st.Finalized = true
			if r.o.LinkOnly && r.st.Link == "" {
				r.o.Warn("the transfer was finalized by an earlier run: its link-only download link cannot be read again (ask for a new one from My transfers)")
			}
		} else if t, err = r.finalize(ctx); err != nil {
			return nil, err
		}
	}
	if !r.o.NoWait {
		if t, err = r.wait(ctx, t); err != nil {
			return nil, err
		}
	}
	res, err := r.result(t)
	if rerr := removeState(r.statePath); rerr != nil && err == nil {
		err = rerr
	}
	return res, err
}

// ensureTransfer creates the transfer (or replays its creation) when the
// state has no identifier yet, else reads it back.
func (r *run) ensureTransfer(ctx context.Context) (*transfer, error) {
	if r.st.TransferID != "" {
		t, err := getTransfer(ctx, r.c, r.st.TransferID)
		if err != nil {
			return nil, err
		}
		switch t.Status {
		case statusExpired, statusDeleted:
			return nil, fmt.Errorf("upload: %w (status %s)", errGone, t.Status)
		}
		return t, nil
	}
	t, err := createTransfer(ctx, r.c, r.o, r.st)
	if err != nil {
		return nil, err
	}
	r.st.TransferID = t.ID
	for i, f := range t.Files {
		r.st.Files[i].UploadURL = f.UploadURL
	}
	if err := r.st.save(r.statePath); err != nil {
		return nil, err
	}
	return t, nil
}

// uploadAll sends every file.
func (r *run) uploadAll(ctx context.Context) error {
	for i := range r.st.Files {
		fs := &r.st.Files[i]
		if fs.UploadURL == "" {
			return errors.New("upload: the server gave no upload URL")
		}
		size := fs.wireSize(r.st.e2e())
		report := func(done int64) {
			r.o.Progress(Progress{Phase: PhaseUpload, File: fs.display(), Done: done, Total: size})
		}
		if err := sendFile(ctx, r.c, r.st, i, r.o.ChunkSize, report); err != nil {
			return err
		}
	}
	return nil
}

// finalize uploads the files and finalizes, completing the files again
// after a 409 upload-incomplete.
func (r *run) finalize(ctx context.Context) (*transfer, error) {
	for round := 1; ; round++ {
		if err := r.uploadAll(ctx); err != nil {
			return nil, err
		}
		t, err := finalizeTransfer(ctx, r.c, r.st.TransferID)
		if err == nil {
			r.st.Finalized, r.st.Link = true, t.DownloadURL
			if err := r.st.save(r.statePath); err != nil {
				return nil, err
			}
			return t, nil
		}
		p := problemOf(err)
		switch {
		case p != nil && p.Status == http.StatusConflict && p.Code == codeUploadIncomplete && round < maxFinalizeRounds:
			continue
		case p != nil && p.Code == codeChecksumMismatch:
			return nil, fmt.Errorf("%w: %w", ErrStateMismatch, err)
		}
		return nil, gone(err)
	}
}

// wait polls the transfer until it is available or rejected.
func (r *run) wait(ctx context.Context, t *transfer) (*transfer, error) {
	for {
		done := 0
		for _, f := range t.Files {
			if f.ScanStatus != "pending" && f.ScanStatus != "scanning" {
				done++
			}
		}
		r.o.Progress(Progress{Phase: PhaseScan, Done: int64(done), Total: int64(len(t.Files))})
		switch t.Status {
		case statusAvailable, statusRejected:
			return t, nil
		case statusExpired, statusDeleted, statusUploading:
			return nil, fmt.Errorf("upload: %w (status %s)", errGone, t.Status)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(r.o.PollInterval):
		}
		var err error
		if t, err = getTransfer(ctx, r.c, r.st.TransferID); err != nil {
			return nil, err
		}
	}
}

// result builds the result of transfer t; ErrRejected when the transfer
// was rejected or some of its files withheld.
func (r *run) result(t *transfer) (*Result, error) {
	res := &Result{TransferID: r.st.TransferID, Status: t.Status, Link: r.st.Link, Files: make([]FileResult, len(r.st.Files))}
	if r.st.e2e() {
		res.Key, _ = tte2.EncodeKey(r.st.Key) // a key of KeySize bytes, checked when loaded
	}
	if t.ExpiresAt != nil {
		res.ExpiresAt = *t.ExpiresAt
	}
	withheld := 0
	for i := range r.st.Files {
		fs := &r.st.Files[i]
		fr := FileResult{Name: fs.Name, Path: fs.Folder, Size: fs.Size, SHA256: fs.SHA256}
		if i < len(t.Files) {
			fr.ScanStatus = t.Files[i].ScanStatus
			if !r.st.e2e() && t.Files[i].SHA256 != "" {
				fr.SHA256 = t.Files[i].SHA256
			}
		}
		if fr.ScanStatus == "infected" || fr.ScanStatus == "scan_error" {
			withheld++
		}
		res.Files[i] = fr
	}
	switch {
	case t.Status == statusRejected:
		return res, ErrRejected
	case withheld > 0:
		return res, fmt.Errorf("%w: %d of %d files withheld (infected or not analyzed)", ErrRejected, withheld, len(res.Files))
	}
	return res, nil
}
