package download

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of [Options].
const (
	// DefaultCommitTimeout bounds the recording of the served ranges and of
	// the first download once a response is over.
	DefaultCommitTimeout = 30 * time.Second
)

// Vault opens the data keys of the files. *masterkey.Vault implements it.
type Vault interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// Files gives access to the encrypted files and to the state files of the
// served ranges. *storage.Store implements it.
type Files interface {
	OpenRead(tid tenant.ID, name string) (*os.File, int64, error)
	ReadState(tid tenant.ID, name string) ([]byte, error)
	WriteState(tid tenant.ID, name string, data []byte) error
	RemoveState(tid tenant.ID, name string) error
}

// Keys computes and verifies the MACs keyed by the master key.
// *masterkey.Keyring implements it.
type Keys interface {
	MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error)
	VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error)
}

// PasswordVerifier checks a password against its argon2id hash with a
// bounded concurrency. *crypto.PasswordHasher implements it.
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, encoded string, password []byte) (bool, error)
}

// Notifier builds the first download mail. *notify.Notifier implements
// it.
type Notifier interface {
	FirstDownload(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, at, deleteAt time.Time) (mail.Job, error)
}

// MailQueue queues the mails without blocking. *mail.Queue implements it.
type MailQueue = mail.Enqueuer

// SecurityLog writes security events. *securitylog.Logger implements it.
type SecurityLog interface {
	Log(ev securitylog.Event) error
}

// Deps are the components the service relies on. Every field is required.
type Deps struct {
	// DB stores the transfers and the password failure counters.
	DB *store.DB
	// Vault holds the data keys of the files.
	Vault Vault
	// Files gives access to the encrypted files and the state files.
	Files Files
	// Keys computes the MACs of the download grant cookie.
	Keys Keys
	// Passwords verifies the transfer passwords.
	Passwords PasswordVerifier
	// Notifier builds the first download mail.
	Notifier Notifier
	// Mail is the mail queue.
	Mail MailQueue
	// SecurityLog receives the wrong password and rate_limited events.
	SecurityLog SecurityLog
}

// Options tunes a [Service].
type Options struct {
	// Grace is the delay between the first complete download of a transfer
	// with the "delete after the first download" option and its deletion
	// (TT_DELETE_AFTER_DOWNLOAD_GRACE, config.Config.DeleteAfterDownloadGrace).
	// Unlike the other fields it is taken as is: zero deletes at the next
	// sweep; a negative value counts as zero.
	Grace time.Duration
	// MailRetryFor, RetryMin and RetryMax tune the retries of a mail
	// refused by the queue (full queue or open circuit); zero values select
	// the mail.RetryOptions defaults.
	MailRetryFor time.Duration
	// RetryMin is the first retry delay of a refused mail.
	RetryMin time.Duration
	// RetryMax is the longest retry delay of a refused mail.
	RetryMax time.Duration
	// CommitTimeout bounds the recording done once a response is over
	// (DefaultCommitTimeout when <= 0).
	CommitTimeout time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the operational logs, which hold identifiers only:
	// never a token, a password, an address or a file name (nil
	// discards).
	Logger *slog.Logger
}

// key identifies a transfer and its tenant.
type key struct {
	tid tenant.ID
	id  string
}

// lockEntry is the in-process lock of one transfer, shared by the
// requests that use it.
type lockEntry struct {
	mu   sync.Mutex
	refs int
}

// Service serves the download links of the recipients. It is safe for
// concurrent use; one Service must serve the whole instance, since it holds
// the per-transfer locks of the served range states, the ranges not yet
// written and the concurrent stream counters. Close it with
// [Service.Close].
type Service struct {
	repo      repo
	vault     Vault
	files     Files
	keys      Keys
	passwords PasswordVerifier
	notifier  Notifier
	mails     *mail.Retrier
	seclog    SecurityLog
	opts      Options
	logger    *slog.Logger
	clock     func() time.Time
	streams   streams
	// events throttles the download_streams security events.
	events *ratelimit.Limiter
	// flushBytes is the newly served bytes that make a range state worth
	// writing (flushBytes, replaced by the tests).
	flushBytes int64

	mu    sync.Mutex
	locks map[key]*lockEntry
	// pending holds the range states with served ranges not written yet,
	// about maxPendingTransfers (see tidy); each is used under its
	// transfer lock.
	pending map[key]*pendingState
	// tidied is when tidy last looked for idle states.
	tidied time.Time
}

// New returns a service over deps.
func New(deps Deps, opts Options) *Service {
	opts.Grace = max(opts.Grace, 0)
	if opts.CommitTimeout <= 0 {
		opts.CommitTimeout = DefaultCommitTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		repo: storeRepo{db: deps.DB}, vault: deps.Vault, files: deps.Files, keys: deps.Keys,
		passwords: deps.Passwords, notifier: deps.Notifier, seclog: deps.SecurityLog,
		mails: mail.NewRetrier(deps.Mail, mail.RetryOptions{
			For: opts.MailRetryFor, Min: opts.RetryMin, Max: opts.RetryMax, Now: opts.Now, Logger: opts.Logger,
		}),
		opts: opts, logger: opts.Logger, clock: opts.Now, streams: streams{counts: map[streamKey]int{}},
		events:     newEventThrottle(opts.Now),
		flushBytes: flushBytes, locks: map[key]*lockEntry{}, pending: map[key]*pendingState{},
	}
}

// Close writes the served ranges not written yet, then stops the pending
// mail retries (their mails are dropped) and waits for them to end, or for
// ctx to be done. Downloads keep working, but a mail refused by the queue
// after Close is dropped at once. It is safe to call more than once.
func (s *Service) Close(ctx context.Context) error {
	s.flushAll(ctx)
	return s.mails.Close(ctx)
}

// now returns the clock at the precision of the stored timestamps.
func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Millisecond)
}

// lock takes the in-process lock of the transfer k and returns its
// release.
func (s *Service) lock(k key) func() {
	s.mu.Lock()
	e := s.locks[k]
	if e == nil {
		e = &lockEntry{}
		s.locks[k] = e
	}
	e.refs++
	s.mu.Unlock()
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		if e.refs--; e.refs == 0 {
			delete(s.locks, k)
		}
	}
}

// log writes an operational log line about the transfer trfID of tenant
// tid. attrs must never hold a token, a password, an address or a file
// name.
func (s *Service) log(ctx context.Context, level slog.Level, msg string, tid tenant.ID, trfID string, attrs ...slog.Attr) {
	attrs = append([]slog.Attr{slog.String("tenant", tid.String()), slog.String("transfer", trfID)}, attrs...)
	s.logger.LogAttrs(ctx, level, msg, attrs...)
}

// FileView is a deliverable file as the download page shows it (OpenAPI
// PublicFile, without downloadUrl, which the HTTP layer builds from the
// token and ID).
type FileView struct {
	// ID is the file identifier ("fil_" + ULID).
	ID string
	// Name is the original file name, to be shown as text.
	Name string
	// Size is the size of the clear file in bytes.
	Size int64
	// MediaType is the informational media type, "" when unknown.
	MediaType string
	// SHA256 is the lowercase hexadecimal SHA-256 of the clear file.
	SHA256 string
	// ScanStatus is the antivirus status: store.ScanClean,
	// store.ScanNotScannedTooLarge or store.ScanNotScannedEncrypted (the
	// last two flagged as not scanned on the page).
	ScanStatus store.ScanStatus
}

// View is a transfer as a recipient sees it (OpenAPI PublicTransfer). The
// other recipients and the scan signatures are never part of it. While
// Locked, only SenderEmail, ExpiresAt, PasswordProtected and Locked are
// set, as the specification requires; every other field is zero.
type View struct {
	// TransferID identifies the transfer, for the logs and the audit; it is
	// not part of the response.
	TransferID string
	// SenderEmail is the verified address of the sender.
	SenderEmail string
	// Message is the plain-text message of the sender, "" when none.
	Message string
	// ExpiresAt is when the link expires.
	ExpiresAt time.Time
	// PasswordProtected tells whether a password protects the transfer.
	PasswordProtected bool
	// Locked is set when a password is required and the grant cookie holds
	// no valid grant for the transfer.
	Locked bool
	// DeleteAfterFirstDownload tells whether the transfer is deleted after
	// its first complete download.
	DeleteAfterFirstDownload bool
	// TotalBytes is the total size of the deliverable files.
	TotalBytes int64
	// ArchiveAvailable is set when the archive of the deliverable files may
	// be downloaded by this browser: the transfer is not Locked (it always
	// has a deliverable file). The HTTP layer then sets archiveUrl.
	ArchiveAvailable bool
	// Files are the deliverable files, by position.
	Files []FileView
}

// access is a resolved download link.
type access struct {
	// d is the transfer, with every file and the recipients; only files
	// may be served.
	d store.TransferDetails
	// files are the deliverable files, by position.
	files []store.TransferFile
	// unlocked is set when no password is required or the grant cookie
	// holds a valid grant.
	unlocked bool
}

// resolve looks up the download token rawToken in tenant t and checks that
// its transfer can be downloaded now. grantCookie is the raw value of the
// grant cookie ("" when absent).
func (s *Service) resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string) (access, error) {
	if !id.DownloadTokenValid(rawToken) {
		return access{}, ErrNotFound
	}
	hash := sha256.Sum256([]byte(rawToken))
	d, err := s.repo.byToken(ctx, t.ID, hash[:])
	if errors.Is(err, store.ErrNotFound) {
		return access{}, ErrNotFound
	}
	if err != nil {
		return access{}, fmt.Errorf("download: look up token: %w", err)
	}
	now := s.now()
	if d.Status != store.TransferAvailable || !now.Before(d.ExpiresAt) ||
		(!d.DeleteAfter.IsZero() && !now.Before(d.DeleteAfter)) {
		return access{}, ErrGone
	}
	a := access{d: d, unlocked: !d.PasswordProtected()}
	for _, f := range d.Files {
		if f.ScanStatus.Deliverable() {
			a.files = append(a.files, f)
		}
	}
	if len(a.files) == 0 {
		return access{}, ErrGone
	}
	if !a.unlocked {
		if a.unlocked, err = s.granted(grantCookie, t.ID, d.ID, now); err != nil {
			return access{}, err
		}
	}
	return a, nil
}

// Resolve returns the transfer of the download token rawToken in tenant t,
// as the download page shows it (getDownload). grantCookie is the raw value
// of the GrantCookieName cookie, "" when absent. It returns ErrNotFound for
// a malformed or unknown token (including one of another tenant) and
// ErrGone for a transfer that can no longer be downloaded.
func (s *Service) Resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string) (View, error) {
	a, err := s.resolve(ctx, t, rawToken, grantCookie)
	if err != nil {
		return View{}, err
	}
	v := View{
		TransferID: a.d.ID, SenderEmail: a.d.SenderEmail, ExpiresAt: a.d.ExpiresAt,
		PasswordProtected: a.d.PasswordProtected(), Locked: !a.unlocked,
	}
	if v.Locked {
		return v, nil
	}
	v.Message, v.DeleteAfterFirstDownload, v.ArchiveAvailable = a.d.Message, a.d.DeleteAfterFirstDownload, true
	for _, f := range a.files {
		v.TotalBytes += f.Size
		v.Files = append(v.Files, FileView{
			ID: f.ID, Name: f.Name, Size: f.Size, MediaType: f.MediaType, SHA256: f.SHA256, ScanStatus: f.ScanStatus,
		})
	}
	return v, nil
}
