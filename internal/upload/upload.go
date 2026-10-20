package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Errors returned by the engine. Callers test them with errors.Is. The
// HTTP status each one maps to is given in its comment.
var (
	// ErrNotFound reports an unknown or malformed upload identifier, an
	// upload of another tenant, or a principal that is not the sender of
	// the transfer (T-21). HTTP 404.
	ErrNotFound = errors.New("upload: not found")
	// ErrBusy reports that another request holds the lock of the upload
	// (or, for LockFiles, of one of the files). HTTP 409.
	ErrBusy = errors.New("upload: busy")
	// ErrOffsetMismatch reports an Upload-Offset different from the durable
	// offset of the upload (including after a reset, which brings it back
	// to 0). HTTP 409.
	ErrOffsetMismatch = errors.New("upload: offset mismatch")
	// ErrTooLarge reports a request body going beyond the declared length
	// of the file (T-22). The bytes up to the declared length are saved,
	// the extra bytes are never written. HTTP 413.
	ErrTooLarge = errors.New("upload: bytes beyond the declared length")
	// ErrExpired reports an incomplete upload inactive for longer than
	// Options.UploadTTL. HTTP 410.
	ErrExpired = errors.New("upload: expired")
	// ErrFinalized reports a transfer that is no longer being uploaded
	// (finalized, rejected, expired or deleted). HTTP 409 for PATCH and
	// DELETE, 410 for HEAD (a completed file of a scanning or available
	// transfer is still reported as completed by Status).
	ErrFinalized = errors.New("upload: transfer is no longer being uploaded")
	// ErrInvalid reports an invalid argument: a negative offset or a nil
	// body. HTTP 400.
	ErrInvalid = errors.New("upload: invalid argument")
	// ErrInterrupted reports a request body that failed before its end, or
	// a canceled context. The progress was saved: the returned Status holds
	// the durable offset. The error also wraps the cause (for example
	// context.Canceled). HTTP: usually none, the client is gone; 400 if a
	// response can still be written.
	ErrInterrupted = errors.New("upload: request interrupted")
)

// errInconsistent marks a checkpoint and a file that disagree: the upload
// must be reset.
var errInconsistent = errors.New("upload: inconsistent checkpoint")

const (
	// DefaultUploadTTL is the default inactivity delay after which an
	// incomplete upload expires (TT_UPLOAD_TTL, decision P5).
	DefaultUploadTTL = 24 * time.Hour
	// DefaultMaxAge is the default longest life of an incomplete upload,
	// counted from the creation of its transfer whatever the activity
	// (TT_UPLOAD_MAX_AGE): without it, one empty PATCH a day would keep an
	// upload, and its quota reservation, alive forever.
	DefaultMaxAge = 7 * 24 * time.Hour
	// DefaultCheckpointEvery is the default number of bytes between two
	// checkpoints within a request.
	DefaultCheckpointEvery = 64 << 20
	// chunkSize is the plaintext chunk size of the files the engine
	// writes, passed explicitly to crypto.NewWriter so that a change of
	// the crypto default cannot change it silently (the worst-case
	// checkpoint must fit in storage.MaxCheckpointSize).
	chunkSize = crypto.DefaultChunkSize
	// bufferSize is the size of the read buffer of a request: the memory
	// used by an upload does not depend on the size of its body.
	bufferSize = 256 << 10
)

// emptySHA256 is the SHA-256 of the empty string.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Options configures an Engine. The zero value selects the defaults.
type Options struct {
	// UploadTTL is the inactivity delay after which an incomplete upload
	// expires; DefaultUploadTTL when zero.
	UploadTTL time.Duration
	// MaxAge is the longest life of an incomplete upload after the creation
	// of its transfer; DefaultMaxAge when zero, and never below UploadTTL.
	MaxAge time.Duration
	// CheckpointEvery is the number of bytes received between two
	// checkpoints within a request; DefaultCheckpointEvery when zero.
	CheckpointEvery int64
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Logger receives the warnings (resets, leftover files); nothing is
	// logged when nil. Data keys, upload identifiers and contents are never
	// logged.
	Logger *slog.Logger
}

// Principal is the authenticated depositor of an upload request. It is
// store.Depositor, whose Owns method is the single ownership rule shared
// with the transfers.
type Principal = store.Depositor

// Status is the state of an upload (tus HEAD and PATCH responses).
type Status struct {
	// Offset is the number of bytes durably stored (Upload-Offset).
	Offset int64
	// Length is the declared length of the file (Upload-Length).
	Length int64
	// ExpiresAt is when the incomplete upload expires (Upload-Expires);
	// zero for a completed upload.
	ExpiresAt time.Time
	// Completed reports a completed upload (Offset == Length).
	Completed bool
}

// fileStore is the part of *storage.Store the engine uses.
type fileStore interface {
	Create(tid tenant.ID, name string) (*os.File, error)
	OpenAppend(tid tenant.ID, name string) (*os.File, int64, error)
	Remove(tid tenant.ID, name string) error
	WriteCheckpoint(tid tenant.ID, name string, data []byte) error
	ReadCheckpoint(tid tenant.ID, name string) ([]byte, time.Time, error)
	CheckpointModTime(tid tenant.ID, name string) (time.Time, error)
	RemoveCheckpoint(tid tenant.ID, name string) error
	Sync(f *os.File) error
	SyncDir(tid tenant.ID) error
}

// keyVault is the part of *masterkey.Vault the engine uses.
type keyVault interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
	NewDEKTx(ctx context.Context, tx *store.ScopedTx) (string, []byte, error)
	DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error
	Scrub(ctx context.Context) error
}

// metaStore is the part of the store the engine uses.
type metaStore interface {
	GetByUploadID(ctx context.Context, tid tenant.ID, uploadID string) (store.FileUpload, error)
	ListByTransfer(ctx context.Context, tid tenant.ID, trfID string) ([]store.TransferFile, error)
	CompleteUpload(ctx context.Context, tid tenant.ID, fileID, sha256 string, ciphertextSize int64, now time.Time) error
	ReplaceDEKTx(ctx context.Context, tx *store.ScopedTx, fileID, newKeyID, newStorageName string) error
	DeleteTx(ctx context.Context, tx *store.ScopedTx, fileID string) error
	Tx(ctx context.Context, tid tenant.ID, fn func(*store.ScopedTx) error) error
}

// dbMeta implements metaStore over a *store.DB.
type dbMeta struct {
	*store.TransferFiles
	db *store.DB
}

// Tx runs fn in a write transaction of tenant tid.
func (m dbMeta) Tx(ctx context.Context, tid tenant.ID, fn func(*store.ScopedTx) error) error {
	s, err := m.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, fn)
}

// Engine runs the tus uploads of every tenant. It is safe for concurrent
// use; a single Engine must serve all the requests of the instance, since
// it holds the per-upload locks.
type Engine struct {
	meta   metaStore
	vault  keyVault
	files  fileStore
	ttl    time.Duration
	maxAge time.Duration
	every  int64
	now    func() time.Time
	log    *slog.Logger

	// newWriter and resumeWriter are crypto.NewWriter and
	// crypto.ResumeWriter; tests replace them to inject faults.
	newWriter    func(dst io.Writer, dek []byte, tenantID, fileID string, opts ...crypto.Option) (*crypto.Writer, error)
	resumeWriter func(dst io.Writer, dek []byte, tenantID, fileID string, st *crypto.State, existingSize int64) (*crypto.Writer, []byte, error)

	locks   lockSet
	buffers sync.Pool
}

// New returns an Engine storing the metadata in db, the data keys in vault
// and the encrypted files in files.
func New(db *store.DB, vault *masterkey.Vault, files *storage.Store, opts Options) *Engine {
	return newEngine(dbMeta{TransferFiles: db.TransferFiles(), db: db}, vault, files, opts)
}

// newEngine builds an Engine over the given dependencies.
func newEngine(meta metaStore, vault keyVault, files fileStore, opts Options) *Engine {
	e := &Engine{
		meta: meta, vault: vault, files: files,
		ttl: opts.UploadTTL, maxAge: opts.MaxAge, every: opts.CheckpointEvery, now: opts.Now, log: opts.Logger,
		newWriter: crypto.NewWriter, resumeWriter: crypto.ResumeWriter,
		locks: lockSet{held: map[string]struct{}{}},
	}
	if e.ttl <= 0 {
		e.ttl = DefaultUploadTTL
	}
	if e.maxAge <= 0 {
		e.maxAge = DefaultMaxAge
	}
	e.maxAge = max(e.maxAge, e.ttl)
	if e.every <= 0 {
		e.every = DefaultCheckpointEvery
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	e.buffers.New = func() any {
		b := make([]byte, bufferSize)
		return &b
	}
	return e
}

// lockSet holds the per-upload locks, keyed by file identifier, with
// try-lock semantics.
type lockSet struct {
	mu   sync.Mutex
	held map[string]struct{}
}

// tryLock takes the locks of every key, or none of them when one is held.
// The returned function releases them; it may be called more than once.
func (l *lockSet) tryLock(keys ...string) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	taken := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, held := l.held[k]; held {
			for _, t := range taken {
				delete(l.held, t)
			}
			return nil, false
		}
		l.held[k] = struct{}{}
		taken = append(taken, k)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, t := range taken {
				delete(l.held, t)
			}
		})
	}, true
}

// LockFiles takes the upload locks of every file of fileIDs, or fails with
// ErrBusy, taking none, when a request holds one of them. The caller (the
// cancellation of a transfer) deletes the files while holding the locks,
// then calls the returned function, which may be called more than once.
func (e *Engine) LockFiles(fileIDs []string) (unlock func(), err error) {
	unlock, ok := e.locks.tryLock(fileIDs...)
	if !ok {
		return nil, ErrBusy
	}
	return unlock, nil
}

// load returns the upload uploadID of tenant tid after checking that p is
// the sender of its transfer.
func (e *Engine) load(ctx context.Context, tid tenant.ID, p Principal, uploadID string) (store.FileUpload, error) {
	u, err := e.meta.GetByUploadID(ctx, tid, uploadID)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalid) {
		return store.FileUpload{}, ErrNotFound
	}
	if err != nil {
		return store.FileUpload{}, fmt.Errorf("upload: load: %w", err)
	}
	if !p.Owns(u.Transfer) || u.File.DEKKeyID == "" {
		return store.FileUpload{}, ErrNotFound
	}
	return u, nil
}

// lock loads the upload, takes its lock and loads it again under the lock,
// so that the returned upload is current.
func (e *Engine) lock(ctx context.Context, tid tenant.ID, p Principal, uploadID string) (store.FileUpload, func(), error) {
	u, err := e.load(ctx, tid, p, uploadID)
	if err != nil {
		return store.FileUpload{}, nil, err
	}
	unlock, ok := e.locks.tryLock(u.File.ID)
	if !ok {
		return store.FileUpload{}, nil, ErrBusy
	}
	if u, err = e.load(ctx, tid, p, uploadID); err != nil {
		unlock()
		return store.FileUpload{}, nil, err
	}
	return u, unlock, nil
}

// progress is the durable progress of an incomplete upload.
type progress struct {
	// state is the parsed checkpoint, nil when there is none or it is
	// unusable.
	state *crypto.State
	// corrupt reports a checkpoint that exists but cannot be used.
	corrupt bool
	// offset is the durable offset (0 without a usable checkpoint).
	offset int64
	// lastActivity is the checkpoint time, zero without a checkpoint.
	lastActivity time.Time
}

// progress reads the checkpoint of the incomplete file f. Only I/O errors
// are returned; an unusable checkpoint is reported as corrupt.
func (e *Engine) progress(tid tenant.ID, f store.TransferFile) (progress, error) {
	data, mod, err := e.files.ReadCheckpoint(tid, f.StorageName)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return progress{}, nil
	case errors.Is(err, storage.ErrInvalid):
		return progress{corrupt: true}, nil
	case err != nil:
		return progress{}, fmt.Errorf("upload: read checkpoint: %w", err)
	}
	st, err := crypto.UnmarshalState(data)
	if err != nil {
		return progress{corrupt: true, lastActivity: mod}, nil
	}
	return progress{state: st, offset: st.PlaintextSize(), lastActivity: mod}, nil
}

// expires returns when the incomplete uploads of a transfer created at
// createdAt, last active at last, expire: the earlier of last +
// Options.UploadTTL and createdAt + Options.MaxAge.
func (e *Engine) expires(createdAt, last time.Time) time.Time {
	exp := last.Add(e.ttl)
	if limit := createdAt.Add(e.maxAge); limit.Before(exp) {
		return limit
	}
	return exp
}

// TransferActivity returns the last upload activity of a transfer created
// at createdAt whose files are files, and when its incomplete uploads
// expire (see expires): lastActivity is the latest of createdAt, the
// completion time of every completed file and the checkpoint time of every
// incomplete one. Uploads expire per transfer, so that a file not started
// yet stays open while its siblings are being uploaded. Checkpoint times
// are read without opening the checkpoints. It performs no authorization
// and takes no lock.
func (e *Engine) TransferActivity(_ context.Context, tid tenant.ID, files []store.TransferFile, createdAt time.Time) (lastActivity, expiresAt time.Time, err error) {
	lastActivity = createdAt
	for _, f := range files {
		t := f.UploadedAt
		if !f.Completed() {
			t, err = e.files.CheckpointModTime(tid, f.StorageName)
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrInvalid) {
				continue
			}
			if err != nil {
				return time.Time{}, time.Time{}, fmt.Errorf("upload: transfer activity: %w", err)
			}
		}
		lastActivity = later(lastActivity, t)
	}
	return lastActivity, e.expires(createdAt, lastActivity), nil
}

// expiry returns when the incomplete upload u, whose progress is pr,
// expires: Options.UploadTTL after the later of its own checkpoint and the
// activity of its transfer, and at the latest Options.MaxAge after the
// creation of its transfer.
func (e *Engine) expiry(ctx context.Context, tid tenant.ID, u store.FileUpload, pr progress) (time.Time, error) {
	files, err := e.meta.ListByTransfer(ctx, tid, u.Transfer.ID)
	if err != nil {
		return time.Time{}, fmt.Errorf("upload: list files: %w", err)
	}
	last, _, err := e.TransferActivity(ctx, tid, files, u.Transfer.CreatedAt)
	if err != nil {
		return time.Time{}, err
	}
	return e.expires(u.Transfer.CreatedAt, later(last, pr.lastActivity)), nil
}

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Offset returns the durable offset of the file f of tenant tid and when
// its upload expires, for the transfer views. createdAt is the creation
// time of its transfer and transferActivity its last activity (see
// TransferActivity); the file's own checkpoint time is kept when it is
// later, and the expiry is capped at createdAt + Options.MaxAge. It
// performs no authorization
// (the caller checked it) and takes no lock. A completed file returns its
// length and a zero expiry; an unusable checkpoint returns 0 (the next
// Append resets the upload).
func (e *Engine) Offset(_ context.Context, tid tenant.ID, f store.TransferFile, createdAt, transferActivity time.Time) (offset int64, expiresAt time.Time, err error) {
	if f.Completed() {
		return f.Size, time.Time{}, nil
	}
	pr, err := e.progress(tid, f)
	if err != nil {
		return 0, time.Time{}, err
	}
	return pr.offset, e.expires(createdAt, later(transferActivity, pr.lastActivity)), nil
}

// completedStatus returns the Status of a completed file of length n.
func completedStatus(n int64) Status {
	return Status{Offset: n, Length: n, Completed: true}
}

// Status returns the state of the upload uploadID of tenant tid for the
// principal p (tus HEAD). It takes no lock: it reports the offset of the
// last checkpoint. A completed file of a transfer that is uploading,
// scanning or available is reported as completed.
func (e *Engine) Status(ctx context.Context, tid tenant.ID, p Principal, uploadID string) (Status, error) {
	u, err := e.load(ctx, tid, p, uploadID)
	if err != nil {
		return Status{}, err
	}
	if u.File.Completed() {
		switch u.Transfer.Status {
		case store.TransferUploading, store.TransferScanning, store.TransferAvailable:
			return completedStatus(u.File.Size), nil
		}
		return Status{}, ErrFinalized
	}
	if u.Transfer.Status != store.TransferUploading {
		return Status{}, ErrFinalized
	}
	pr, err := e.progress(tid, u.File)
	if err != nil {
		return Status{}, err
	}
	expires, err := e.expiry(ctx, tid, u, pr)
	if err != nil {
		return Status{}, err
	}
	if !e.now().Before(expires) {
		return Status{}, ErrExpired
	}
	return Status{Offset: pr.offset, Length: u.File.Size, ExpiresAt: expires}, nil
}

// countingWriter counts the bytes written to the encrypted file.
type countingWriter struct {
	w io.Writer
	n int64
}

// Write implements io.Writer.
func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// session is an open upload: the encrypted file, its writer and the hash
// of the plaintext.
type session struct {
	f       *os.File
	cw      countingWriter
	w       *crypto.Writer
	h       hash.Hash
	dst     io.Writer // h and w
	durable int64     // offset of the last persisted checkpoint
}

// newSession returns a session over f, whose current size is size.
func newSession(f *os.File, size int64) *session {
	return &session{f: f, cw: countingWriter{w: f, n: size}, h: sha256.New()}
}

// start sets the writer of the session.
func (s *session) start(w *crypto.Writer) {
	s.w = w
	s.dst = io.MultiWriter(s.h, w)
	s.durable = w.Offset()
}

// close closes the file. Durability was ensured by the explicit syncs.
func (s *session) close() { _ = s.f.Close() }

// create creates the encrypted file of f and starts a new writer.
func (e *Engine) create(tid tenant.ID, f store.TransferFile, dek []byte) (*session, error) {
	file, err := e.files.Create(tid, f.StorageName)
	if err != nil {
		return nil, fmt.Errorf("upload: create file: %w", err)
	}
	s := newSession(file, 0)
	w, err := e.newWriter(&s.cw, dek, string(tid), f.ID, crypto.WithChunkSize(chunkSize))
	if err != nil {
		s.close()
		_ = e.files.Remove(tid, f.StorageName)
		return nil, fmt.Errorf("upload: start file: %w", err)
	}
	s.start(w)
	return s, nil
}

// resume reopens the encrypted file of f from the checkpoint st. A file
// that disagrees with the checkpoint returns an error wrapping
// errInconsistent.
func (e *Engine) resume(tid tenant.ID, f store.TransferFile, dek []byte, st *crypto.State) (*session, error) {
	file, size, err := e.files.OpenAppend(tid, f.StorageName)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: file missing", errInconsistent)
	}
	if err != nil {
		return nil, fmt.Errorf("upload: open file: %w", err)
	}
	s := newSession(file, size)
	w, extra, err := e.resumeWriter(&s.cw, dek, string(tid), f.ID, st, size)
	if err != nil {
		s.close()
		if errors.Is(err, crypto.ErrStaleCheckpoint) || errors.Is(err, crypto.ErrAuth) || errors.Is(err, crypto.ErrBadState) {
			return nil, fmt.Errorf("%w: %w", errInconsistent, err)
		}
		return nil, fmt.Errorf("upload: resume file: %w", err)
	}
	if err := s.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(extra); err != nil {
		s.close()
		return nil, fmt.Errorf("%w: hash state", errInconsistent)
	}
	s.start(w)
	return s, nil
}

// checkpoint persists the progress of s: checkpoint the writer, fsync the
// file, then write the checkpoint atomically. A writer broken by a failed
// write returns its error here.
func (e *Engine) checkpoint(tid tenant.ID, name string, s *session) error {
	extra, _ := s.h.(encoding.BinaryMarshaler).MarshalBinary() // never fails for SHA-256
	st, err := s.w.Checkpoint(extra)
	if err != nil {
		return fmt.Errorf("upload: checkpoint: %w", err)
	}
	if err := e.files.Sync(s.f); err != nil {
		return fmt.Errorf("upload: checkpoint: %w", err)
	}
	data, _ := st.MarshalBinary() // never fails for a non-nil State
	if err := e.files.WriteCheckpoint(tid, name, data); err != nil {
		return fmt.Errorf("upload: checkpoint: %w", err)
	}
	s.durable = st.PlaintextSize()
	return nil
}

// prepare opens the incomplete file f from its progress pr. It returns a
// nil session for an upload that has not started (no checkpoint, no file):
// the file is created once the offset is checked. When the checkpoint and
// the file disagree, the upload is reset (f and dek are updated).
func (e *Engine) prepare(ctx context.Context, tid tenant.ID, f *store.TransferFile, dek *[]byte, pr progress) (*session, error) {
	var reason string
	switch {
	case pr.state != nil:
		s, err := e.resume(tid, *f, *dek, pr.state)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, errInconsistent) {
			return nil, err
		}
		reason = err.Error()
	case pr.corrupt:
		reason = "unreadable checkpoint"
	default:
		file, _, err := e.files.OpenAppend(tid, f.StorageName)
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("upload: open file: %w", err)
		}
		_ = file.Close()
		reason = "file without checkpoint"
	}
	return e.reset(ctx, tid, f, dek, reason)
}

// reset restarts the upload of f from scratch with a new data key and a new
// storage name (never by truncation), destroys the previous key, removes
// the previous files and creates the new file with a checkpoint at offset
// 0. f and dek are updated.
func (e *Engine) reset(ctx context.Context, tid tenant.ID, f *store.TransferFile, dek *[]byte, reason string) (*session, error) {
	oldKey, oldName, newName := f.DEKKeyID, f.StorageName, storage.NewName()
	var (
		newKey string
		newDEK []byte
	)
	err := e.meta.Tx(ctx, tid, func(tx *store.ScopedTx) error {
		k, d, err := e.vault.NewDEKTx(ctx, tx)
		if err != nil {
			return err
		}
		clear(newDEK)
		newKey, newDEK = k, d
		if err := e.meta.ReplaceDEKTx(ctx, tx, f.ID, k, newName); err != nil {
			return err
		}
		return e.vault.DestroyTx(ctx, tx, oldKey)
	})
	if err != nil {
		clear(newDEK)
		return nil, fmt.Errorf("upload: reset: %w", err)
	}
	e.log.WarnContext(ctx, "upload reset: checkpoint and file disagree, restarting from offset 0 with a new data key",
		slog.String("tenant", string(tid)), slog.String("file", f.ID), slog.String("reason", reason))
	clear(*dek)
	*dek = newDEK
	f.DEKKeyID, f.StorageName = newKey, newName
	if err := e.files.Remove(tid, oldName); err != nil {
		e.log.WarnContext(ctx, "upload reset: previous encrypted file left on disk (its key is destroyed)",
			slog.String("tenant", string(tid)), slog.String("file", f.ID), slog.Any("error", err))
	}
	e.scrub(ctx)
	s, err := e.create(tid, *f, newDEK)
	if err != nil {
		return nil, err
	}
	if err := e.checkpoint(tid, f.StorageName, s); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// scrub purges destroyed keys from the database files; a failure is only
// logged, the keys being deleted already.
func (e *Engine) scrub(ctx context.Context) {
	if err := e.vault.Scrub(ctx); err != nil {
		e.log.WarnContext(ctx, "upload: scrubbing destroyed keys failed", slog.Any("error", err))
	}
}

// Append writes body at offset to the upload uploadID of tenant tid for the
// principal p (tus PATCH) and returns the new state. offset must equal the
// durable offset (ErrOffsetMismatch otherwise). The body is read until the
// declared length; one more byte returns ErrTooLarge. When the declared
// length is reached the upload is completed. A body that fails or a
// context canceled before the end returns ErrInterrupted with the saved
// offset.
//
// On error, the returned Status is meaningful for ErrTooLarge and
// ErrInterrupted only.
func (e *Engine) Append(ctx context.Context, tid tenant.ID, p Principal, uploadID string, offset int64, body io.Reader) (Status, error) {
	if offset < 0 || body == nil {
		return Status{}, ErrInvalid
	}
	u, unlock, err := e.lock(ctx, tid, p, uploadID)
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	if u.Transfer.Status != store.TransferUploading {
		return Status{}, ErrFinalized
	}
	f := u.File
	if f.Completed() {
		if offset != f.Size {
			return Status{}, ErrOffsetMismatch
		}
		if overflows(body) {
			return completedStatus(f.Size), ErrTooLarge
		}
		return completedStatus(f.Size), nil
	}
	pr, err := e.progress(tid, f)
	if err != nil {
		return Status{}, err
	}
	expires, err := e.expiry(ctx, tid, u, pr)
	if err != nil {
		return Status{}, err
	}
	if !e.now().Before(expires) {
		return Status{}, ErrExpired
	}
	dek, err := e.vault.Open(ctx, tid, crypto.PurposeDEK, f.DEKKeyID)
	if err != nil {
		return Status{}, fmt.Errorf("upload: open data key: %w", err)
	}
	defer func() { clear(dek) }()
	s, err := e.prepare(ctx, tid, &f, &dek, pr)
	if err != nil {
		return Status{}, err
	}
	var durable int64
	if s != nil {
		durable = s.durable
	}
	if offset != durable {
		if s != nil {
			s.close()
		}
		return Status{}, ErrOffsetMismatch
	}
	if s == nil {
		// An upload not started yet is created by its first byte only, so
		// that an empty PATCH leaves no file and refreshes no activity. An
		// empty file is created at once, to be completed.
		var first []byte
		if f.Size > 0 {
			var one [1]byte
			n, rerr := io.ReadFull(body, one[:])
			if n == 0 {
				st := Status{Length: f.Size, ExpiresAt: expires}
				if errors.Is(rerr, io.EOF) {
					return st, nil
				}
				return st, fmt.Errorf("%w: %w", ErrInterrupted, rerr)
			}
			first = one[:]
		}
		if s, err = e.create(tid, f, dek); err != nil {
			return Status{}, err
		}
		body = io.MultiReader(bytes.NewReader(first), body)
	}
	defer s.close()
	return e.stream(ctx, tid, u, s, body, expires)
}

// overflows reports whether body holds at least one more byte.
func overflows(body io.Reader) bool {
	var one [1]byte
	n, _ := io.ReadFull(body, one[:])
	return n > 0
}

// stream copies body into the session until the declared length of the
// file of u, checkpointing every e.every bytes and at the end. A request
// that brought no byte writes no checkpoint, so that it does not refresh
// the activity of the upload: its Status keeps expires, the expiry before
// the request. Otherwise the expiry is computed from the time of the
// checkpoint just written, the clock HEAD reads too.
func (e *Engine) stream(ctx context.Context, tid tenant.ID, u store.FileUpload, s *session, body io.Reader, expires time.Time) (Status, error) {
	f := u.File
	bp := e.buffers.Get().(*[]byte)
	defer e.buffers.Put(bp)
	buf := *bp
	remaining := f.Size - s.w.Offset()
	var since int64
	var cause error
	broken := false
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			cause = err
			break
		}
		n, err := body.Read(buf[:min(int64(len(buf)), remaining)])
		if n > 0 {
			if _, werr := s.dst.Write(buf[:n]); werr != nil {
				// The writer is broken (sticky error): the checkpoint
				// below returns that error and nothing is saved.
				broken = true
				break
			}
			remaining -= int64(n)
			since += int64(n)
			if since >= e.every && remaining > 0 {
				if err := e.checkpoint(tid, f.StorageName, s); err != nil {
					return Status{}, err
				}
				since = 0
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cause = err
			break
		}
	}
	if remaining == 0 && cause == nil && !overflows(body) {
		return e.complete(ctx, tid, f, s)
	}
	if s.w.Offset() != s.durable || broken {
		if err := e.checkpoint(tid, f.StorageName, s); err != nil {
			return Status{}, err
		}
		mod, err := e.files.CheckpointModTime(tid, f.StorageName)
		if err != nil {
			mod = e.now()
		}
		expires = e.expires(u.Transfer.CreatedAt, mod)
	}
	st := Status{Offset: s.durable, Length: f.Size, ExpiresAt: expires}
	switch {
	case cause != nil:
		return st, fmt.Errorf("%w: %w", ErrInterrupted, cause)
	case remaining == 0:
		return st, ErrTooLarge
	}
	return st, nil
}

// complete ends the upload of f: final chunk, fsync, completion in the
// database (the only database write of the upload), then removal of the
// checkpoint. The database write is not canceled with the request.
func (e *Engine) complete(ctx context.Context, tid tenant.ID, f store.TransferFile, s *session) (Status, error) {
	if err := s.w.Close(); err != nil {
		return Status{}, fmt.Errorf("upload: finish file: %w", err)
	}
	if err := e.files.Sync(s.f); err != nil {
		return Status{}, fmt.Errorf("upload: finish file: %w", err)
	}
	sum := hex.EncodeToString(s.h.Sum(nil))
	if err := e.meta.CompleteUpload(context.WithoutCancel(ctx), tid, f.ID, sum, s.cw.n, e.now()); err != nil {
		return Status{}, fmt.Errorf("upload: complete: %w", err)
	}
	if err := e.files.RemoveCheckpoint(tid, f.StorageName); err != nil {
		e.log.WarnContext(ctx, "upload: checkpoint of a completed file left on disk",
			slog.String("tenant", string(tid)), slog.String("file", f.ID), slog.Any("error", err))
	}
	return completedStatus(f.Size), nil
}

// Terminate deletes the upload uploadID of tenant tid for the principal p
// (tus DELETE, termination extension), which must belong to a transfer
// still being uploaded (ErrFinalized otherwise). Following T-110, the data
// key and the file row are deleted in one transaction (the key first),
// which also releases the declared size from the quota; the files on disk
// are removed after the commit. A failure to remove them is only logged:
// they can no longer be decrypted.
func (e *Engine) Terminate(ctx context.Context, tid tenant.ID, p Principal, uploadID string) error {
	u, unlock, err := e.lock(ctx, tid, p, uploadID)
	if err != nil {
		return err
	}
	defer unlock()
	if u.Transfer.Status != store.TransferUploading {
		return ErrFinalized
	}
	f := u.File
	err = e.meta.Tx(ctx, tid, func(tx *store.ScopedTx) error {
		if err := e.vault.DestroyTx(ctx, tx, f.DEKKeyID); err != nil {
			return err
		}
		return e.meta.DeleteTx(ctx, tx, f.ID)
	})
	if err != nil {
		return fmt.Errorf("upload: terminate: %w", err)
	}
	if err := e.files.Remove(tid, f.StorageName); err != nil {
		e.log.WarnContext(ctx, "upload: encrypted file of a terminated upload left on disk (its key is destroyed)",
			slog.String("tenant", string(tid)), slog.String("file", f.ID), slog.Any("error", err))
	}
	e.scrub(ctx)
	return nil
}

// RemoveFile erases the file f of tenant tid: RemoveFiles for a single
// file, with its own scrub.
func (e *Engine) RemoveFile(ctx context.Context, tid tenant.ID, f store.TransferFile) error {
	return e.RemoveFiles(ctx, tid, []store.TransferFile{f})
}

// RemoveFiles erases the files of tenant tid as one batch (the
// cancellation of a transfer): it destroys their data keys in a single
// transaction (an empty or already destroyed key is not an error), then
// removes every encrypted file and its checkpoint, then scrubs the database
// ONCE for the whole batch, so the caller must not scrub again. When the
// transaction fails, nothing is removed. Every file is attempted even when
// a removal fails; the errors are joined (the keys are destroyed anyway).
// The file rows are not deleted. The caller holds the locks of the files
// (LockFiles) and checked that the transfer may be deleted.
func (e *Engine) RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error {
	err := e.meta.Tx(ctx, tid, func(tx *store.ScopedTx) error {
		for _, f := range files {
			if f.DEKKeyID == "" {
				continue
			}
			if err := e.vault.DestroyTx(ctx, tx, f.DEKKeyID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("upload: remove files: %w", err)
	}
	var errs []error
	for _, f := range files {
		if err := e.files.Remove(tid, f.StorageName); err != nil {
			errs = append(errs, fmt.Errorf("upload: remove file %s: %w", f.ID, err))
		}
	}
	e.scrub(ctx)
	return errors.Join(errs...)
}

// WriteEmpty writes the encrypted form of an empty file (the header and an
// empty final chunk) for the file fileID of tenant tid, under dek, at
// storageName, and syncs it. It returns the SHA-256 of the empty content
// and the ciphertext size, to create the file row as completed. The file is
// removed on failure.
func (e *Engine) WriteEmpty(ctx context.Context, tid tenant.ID, fileID string, dek []byte, storageName string) (sha256Hex string, ciphertextSize int64, err error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	file, err := e.files.Create(tid, storageName)
	if err != nil {
		return "", 0, fmt.Errorf("upload: write empty file: %w", err)
	}
	cw := &countingWriter{w: file}
	err = e.writeEmpty(cw, file, tid, fileID, dek)
	_ = file.Close()
	if err == nil {
		err = e.files.SyncDir(tid)
	}
	if err != nil {
		_ = e.files.Remove(tid, storageName)
		return "", 0, fmt.Errorf("upload: write empty file: %w", err)
	}
	return emptySHA256, cw.n, nil
}

// writeEmpty writes an empty encrypted file through cw and syncs file.
func (e *Engine) writeEmpty(cw *countingWriter, file *os.File, tid tenant.ID, fileID string, dek []byte) error {
	w, err := e.newWriter(cw, dek, string(tid), fileID, crypto.WithChunkSize(chunkSize))
	if err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return e.files.Sync(file)
}
