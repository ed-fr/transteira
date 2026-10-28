package download

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
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

// Deps are the components the service relies on. Every field is required,
// except Usage.
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
	// Usage receives the download starts and the bytes served, for the
	// tenant statistics; nil counts nothing.
	Usage Usage
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
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
	// StartWindow is how long a download start of a file or of the archive
	// by a client (IPv4 address or IPv6 /64) keeps the next starts of the
	// same object by the same client from being recorded again: audit
	// event, download count and usage count (DefaultStartWindow when <=
	// 0). The bytes served are always counted.
	StartWindow time.Duration
	// MaxStarts bounds the download starts remembered for that
	// deduplication; when full, the oldest is forgotten
	// (DefaultMaxStarts when <= 0).
	MaxStarts int
	// MaxStartsPerTransfer bounds the download starts recorded for one
	// transfer within StartWindow, whatever the clients, so that a client
	// cycling many keys cannot defeat the deduplication by eviction; beyond
	// it, starts are not recorded until that window is over
	// (DefaultMaxStartsPerTransfer when <= 0).
	MaxStartsPerTransfer int
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
	usage     Usage
	opts      Options
	logger    *slog.Logger
	clock     func() time.Time
	streams   streams
	// starts deduplicates the download starts.
	starts *startDedup
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
	if opts.StartWindow <= 0 {
		opts.StartWindow = DefaultStartWindow
	}
	if opts.MaxStarts <= 0 {
		opts.MaxStarts = DefaultMaxStarts
	}
	if opts.MaxStartsPerTransfer <= 0 {
		opts.MaxStartsPerTransfer = DefaultMaxStartsPerTransfer
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	var usage Usage = noUsage{}
	if deps.Usage != nil {
		usage = deps.Usage
	}
	return &Service{
		repo: storeRepo{db: deps.DB, audit: auditWriter(deps.DB, deps.Audit)}, vault: deps.Vault, files: deps.Files, keys: deps.Keys,
		passwords: deps.Passwords, notifier: deps.Notifier, seclog: deps.SecurityLog, usage: usage,
		mails: mail.NewRetrier(deps.Mail, mail.RetryOptions{
			For: opts.MailRetryFor, Min: opts.RetryMin, Max: opts.RetryMax, Now: opts.Now, Logger: opts.Logger,
		}),
		opts: opts, logger: opts.Logger, clock: opts.Now, streams: streams{counts: map[streamKey]int{}},
		events: newEventThrottle(opts.Now), starts: newStartDedup(opts.StartWindow, opts.MaxStarts, opts.MaxStartsPerTransfer),
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
// set, as the specification requires; every other field is zero,
// including Confidentiality.
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
	// DownloadsRemaining is the number of download starts left before the
	// download limit of the transfer is reached (at least 1, since the page
	// of a transfer whose limit is reached answers ErrMaxDownloads), nil
	// without limit or while Locked.
	DownloadsRemaining *int
	// Confidentiality is the confidentiality level of the transfer, as
	// snapshotted at its creation, nil without level.
	Confidentiality *Confidentiality
}

// Confidentiality is the confidentiality level of a transfer, as
// snapshotted at its creation (OpenAPI ConfidentialityLevelRef, whose
// label the HTTP layer picks with [Confidentiality.Label]).
type Confidentiality struct {
	// Key is the key of the level.
	Key string
	// Labels are the labels of the level by language ("fr", "en").
	Labels map[string]string
	// Rules are the rules applied to the transfer, nil when unknown.
	Rules *store.ConfidentialityRules
}

// Label returns the label of the level in the first of langs that has
// one, else in the lexically first language that has one ("" when there
// is no label at all), so that a label is always shown.
func (c Confidentiality) Label(langs ...string) string {
	for _, l := range langs {
		if v := c.Labels[l]; v != "" {
			return v
		}
	}
	keys := slices.Sorted(maps.Keys(c.Labels))
	for _, k := range keys {
		if v := c.Labels[k]; v != "" {
			return v
		}
	}
	return ""
}

// confidentiality returns the confidentiality level of d, nil without
// level.
func confidentiality(d store.TransferDetails) *Confidentiality {
	if d.ConfidentialityLevel == "" {
		return nil
	}
	return &Confidentiality{Key: d.ConfidentialityLevel, Labels: maps.Clone(d.ConfidentialityLabel), Rules: d.Rules}
}

// limitReached reports whether d has a download limit that its download
// starts already reached.
func limitReached(d store.TransferDetails) bool {
	return d.MaxDownloads != nil && d.DownloadCount >= int64(*d.MaxDownloads)
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
// grant cookie ("" when absent). With gate, a transfer whose download
// limit is reached is refused with ErrMaxDownloads (the page and the
// unlock); the file and archive requests pass gate false, since a client
// whose download was already counted is still served during the grace
// period: their start decides ([Content.Begin], [Archive.Begin]).
func (s *Service) resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string, gate bool) (access, error) {
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
	if gate && limitReached(d) {
		return access{}, ErrMaxDownloads
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
// a malformed or unknown token (including one of another tenant), ErrGone
// for a transfer that can no longer be downloaded, and ErrMaxDownloads for
// a transfer whose download limit is reached (even during its grace
// period: no new download may start, and a download in progress does not
// need the page to resume).
func (s *Service) Resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string) (View, error) {
	a, err := s.resolve(ctx, t, rawToken, grantCookie, true)
	if err != nil {
		return View{}, err
	}
	v := View{
		TransferID: a.d.ID, SenderEmail: a.d.SenderEmail, ExpiresAt: a.d.ExpiresAt,
		PasswordProtected: a.d.PasswordProtected(), Locked: !a.unlocked,
	}
	if v.Locked {
		// The level is part of what the password protects: a locked view
		// keeps the 1.0 set of fields.
		return v, nil
	}
	v.Confidentiality = confidentiality(a.d)
	v.Message, v.DeleteAfterFirstDownload, v.ArchiveAvailable = a.d.Message, a.d.DeleteAfterFirstDownload, true
	if m := a.d.MaxDownloads; m != nil {
		left := int(int64(*m) - a.d.DownloadCount)
		v.DownloadsRemaining = &left
	}
	for _, f := range a.files {
		v.TotalBytes += f.Size
		v.Files = append(v.Files, FileView{
			ID: f.ID, Name: f.Name, Size: f.Size, MediaType: f.MediaType, SHA256: f.SHA256, ScanStatus: f.ScanStatus,
		})
	}
	return v, nil
}
