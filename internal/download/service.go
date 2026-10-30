package download

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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
	"github.com/ed-fr/transteira/internal/storage"
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

// Notifier builds the first download mail and the recipient verification
// code mail. *notify.Notifier implements it.
type Notifier interface {
	// FirstDownloadBy builds the first download mail, naming recipient (""
	// for a shared link).
	FirstDownloadBy(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, at, deleteAt time.Time, recipient string) (mail.Job, error)
	// RecipientVerificationCode builds the mail of the code of a recipient
	// link, sent to its own address only.
	RecipientVerificationCode(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, to, code string) (mail.Job, error)
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
	// Keys computes the MACs of the download grant cookie, of the recipient
	// verification cookie and of the verification codes.
	Keys Keys
	// Passwords verifies the transfer passwords.
	Passwords PasswordVerifier
	// Notifier builds the first download mail and the recipient
	// verification code mail.
	Notifier Notifier
	// Mail is the mail queue. The first download mails go through a
	// retrier; the verification codes are queued at once, so that a refusal
	// is answered.
	Mail MailQueue
	// SecurityLog receives the wrong password, wrong code and rate_limited
	// events.
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
	// never a token, a password, a code, an address or a file name (nil
	// discards).
	Logger *slog.Logger
	// Rand is the random source of the verification codes
	// (crypto/rand.Reader when nil).
	Rand io.Reader
	// Abuse alerts the administrators of a new abuse report (since 1.1);
	// nil alerts nobody.
	Abuse AbuseAlerter
}

// key identifies a transfer and its tenant and, for the range state of a
// recipient link, that link (link "" for the state of a shared link and for
// the lock serializing the download starts of a transfer).
type key struct {
	tid  tenant.ID
	id   string
	link string
}

// stateName returns the name of the range state file of k: one per
// recipient link, one per transfer for a shared link.
func (k key) stateName() string {
	return storage.StateName(cmp.Or(k.link, k.id))
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
	queue     MailQueue
	mails     *mail.Retrier
	seclog    SecurityLog
	usage     Usage
	opts      Options
	logger    *slog.Logger
	clock     func() time.Time
	rand      io.Reader
	// newToken generates the challenge identifiers (id.NewToken, replaced
	// by the tests).
	newToken func(prefix string, entropyBytes int) (string, error)
	streams  streams
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
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	var usage Usage = noUsage{}
	if deps.Usage != nil {
		usage = deps.Usage
	}
	return &Service{
		repo: storeRepo{db: deps.DB, audit: auditWriter(deps.DB, deps.Audit)}, vault: deps.Vault, files: deps.Files, keys: deps.Keys,
		passwords: deps.Passwords, notifier: deps.Notifier, queue: deps.Mail, seclog: deps.SecurityLog, usage: usage,
		mails: mail.NewRetrier(deps.Mail, mail.RetryOptions{
			For: opts.MailRetryFor, Min: opts.RetryMin, Max: opts.RetryMax, Now: opts.Now, Logger: opts.Logger,
		}),
		opts: opts, logger: opts.Logger, clock: opts.Now, rand: opts.Rand, newToken: id.NewToken, streams: streams{counts: map[streamKey]int{}},
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
	// Path is the folder of the file inside the transfer, "" at the root
	// (since 1.1), to be shown as text.
	Path string
	// Size is the size of the clear file in bytes.
	Size int64
	// MediaType is the informational media type, "" when unknown.
	MediaType string
	// SHA256 is the lowercase hexadecimal SHA-256 of the clear file.
	SHA256 string
	// ScanStatus is the antivirus status: store.ScanClean,
	// store.ScanNotScannedTooLarge, store.ScanNotScannedEncrypted or
	// store.ScanNotScannedDisabled (the last three flagged as not scanned
	// on the page).
	ScanStatus store.ScanStatus
}

// View is a transfer as a recipient sees it (OpenAPI PublicTransfer). The
// other recipients and the scan signatures are never part of it. While
// Locked, only SenderEmail, ExpiresAt, PasswordProtected, Locked and the
// verification fields are set, as the specification requires; every other
// field is zero, including Confidentiality.
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
	// no valid grant for the transfer (or the recipient link), or when the
	// recipient verification is required and not proved on this browser.
	Locked bool
	// VerificationRequired is set for a per-recipient link whose transfer
	// requires the recipient verification (since 1.1).
	VerificationRequired bool
	// Verified is set, with VerificationRequired, when the recipient
	// verification cookie holds a valid entry of the link.
	Verified bool
	// RecipientEmailMasked is the masked address of the recipient of the
	// link (see [MaskEmail]), set only while the verification is awaited.
	RecipientEmailMasked string
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
	// ReplyAllowed is set when the recipient may send files back to the
	// sender ([Service.ReplyAccess], since 1.1): the tenant allows replies,
	// the link is a recipient link and the transfer was sent by an internal
	// depositor (see [Service.replyEligible]). The blocklist and the
	// availability of the transfer are checked by ReplyAccess only. Never
	// set while Locked.
	ReplyAllowed bool
	// Reply is set when the transfer is itself a reply sent from outside
	// the tenant (store.DepositorReply, since 1.1): SenderEmail was verified
	// by code, but the files come from an external sender (threat model
	// T-223). Never set while Locked.
	Reply bool
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

// Cookies are the raw values of the technical cookies sent with a download
// request, "" when absent.
type Cookies struct {
	// Grant is the value of the GrantCookieName cookie.
	Grant string
	// Verification is the value of the VerificationCookieName cookie.
	Verification string
}

// access is a resolved download link.
type access struct {
	// d is the transfer, with every file and the recipients; only files
	// may be served.
	d store.TransferDetails
	// link is the recipient link of the token, nil for a shared V1 link.
	link *store.RecipientLink
	// files are the deliverable files, by position.
	files []store.TransferFile
	// unlocked is set when no password is required or the grant cookie
	// holds a valid grant.
	unlocked bool
	// verify is set when the recipient verification is required: a
	// recipient link of a transfer with the option.
	verify bool
	// verified is set when the verification cookie holds a valid entry of
	// the recipient link.
	verified bool
}

// subject returns what the grant cookie entries and the password failure
// counter of the link are bound to: the recipient link, else the
// transfer.
func (a access) subject() string {
	if a.link != nil {
		return a.link.ID
	}
	return a.d.ID
}

// awaiting reports whether the recipient verification is required and not
// proved on this browser.
func (a access) awaiting() bool { return a.verify && !a.verified }

// lookup returns the transfer of the download token hash in tenant tid:
// the recipient links first, then the shared V1 links (P9: the same
// ErrNotFound for both). link is nil for a shared link.
func (s *Service) lookup(ctx context.Context, tid tenant.ID, hash []byte) (store.TransferDetails, *store.RecipientLink, error) {
	l, err := s.repo.linkByToken(ctx, tid, hash)
	switch {
	case err == nil:
		d, err := s.repo.transfer(ctx, tid, l.TransferID)
		if err != nil {
			return store.TransferDetails{}, nil, err
		}
		return d, &l, nil
	case !errors.Is(err, store.ErrNotFound):
		return store.TransferDetails{}, nil, err
	}
	d, err := s.repo.byToken(ctx, tid, hash)
	return d, nil, err
}

// find looks up the download token rawToken in tenant t, whatever the
// state of its transfer: ErrNotFound for a malformed or unknown token
// (including one of another tenant). link is nil for a shared V1 link.
func (s *Service) find(ctx context.Context, t *tenant.Tenant, rawToken string) (store.TransferDetails, *store.RecipientLink, error) {
	if !id.DownloadTokenValid(rawToken) {
		return store.TransferDetails{}, nil, ErrNotFound
	}
	hash := sha256.Sum256([]byte(rawToken))
	d, link, err := s.lookup(ctx, t.ID, hash[:])
	if errors.Is(err, store.ErrNotFound) {
		return store.TransferDetails{}, nil, ErrNotFound
	}
	if err != nil {
		return store.TransferDetails{}, nil, fmt.Errorf("download: look up token: %w", err)
	}
	return d, link, nil
}

// deliverable returns the deliverable files of d, by position, or ErrGone
// when d can no longer be downloaded at now: not available, expired, past
// its deletion after the first download, or without any deliverable file.
// With [limitReached], it is the availability rule of a reply, which
// transfer.replyable applies again when the reply is created and
// finalized: the two must agree.
func deliverable(d store.TransferDetails, now time.Time) ([]store.TransferFile, error) {
	if d.Status != store.TransferAvailable || !now.Before(d.ExpiresAt) ||
		(!d.DeleteAfter.IsZero() && !now.Before(d.DeleteAfter)) {
		return nil, ErrGone
	}
	var files []store.TransferFile
	for _, f := range d.Files {
		if f.ScanStatus.Deliverable() {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil, ErrGone
	}
	return files, nil
}

// resolve looks up the download token rawToken in tenant t and checks that
// its transfer can be downloaded now. cookies are the raw technical cookies
// of the request. With gate, a transfer whose download limit is reached is
// refused with ErrMaxDownloads (the page and the unlock); the file and
// archive requests pass gate false, since a client whose download was
// already counted is still served during the grace period: their start
// decides ([Content.Begin], [Archive.Begin]).
func (s *Service) resolve(ctx context.Context, t *tenant.Tenant, rawToken string, cookies Cookies, gate bool) (access, error) {
	d, link, err := s.find(ctx, t, rawToken)
	if err != nil {
		return access{}, err
	}
	now := s.now()
	files, err := deliverable(d, now)
	if err != nil {
		return access{}, err
	}
	a := access{d: d, link: link, files: files, unlocked: !d.PasswordProtected(), verify: link != nil && d.RecipientVerification}
	if gate && limitReached(d) {
		return access{}, ErrMaxDownloads
	}
	if a.verify {
		if a.verified, err = s.holds(verificationSpec, cookies.Verification, t.ID, link.ID, now); err != nil {
			return access{}, err
		}
	}
	if !a.unlocked {
		if a.unlocked, err = s.granted(cookies.Grant, t.ID, a.subject(), now); err != nil {
			return access{}, err
		}
	}
	return a, nil
}

// Resolve returns the transfer of the download token rawToken in tenant t,
// as the download page shows it (getDownload). The token is a recipient
// link or a shared V1 link; cookies are the raw technical cookies of the
// request. It returns ErrNotFound for a malformed or unknown token
// (including one of another tenant), ErrGone for a transfer that can no
// longer be downloaded, and ErrMaxDownloads for a transfer whose download
// limit is reached (even during its grace period: no new download may
// start, and a download in progress does not need the page to resume).
//
// A recipient link whose transfer requires the recipient verification,
// without a valid verification cookie entry of the link, gets the minimal
// locked view: the sender, the expiry, the password flag, the verification
// flags and the masked address of the link, nothing else.
//
// An unlocked view tells whether the recipient may reply (ReplyAllowed,
// read from the current tenant settings) and whether the transfer is itself
// a reply (Reply).
func (s *Service) Resolve(ctx context.Context, t *tenant.Tenant, rawToken string, cookies Cookies) (View, error) {
	a, err := s.resolve(ctx, t, rawToken, cookies, true)
	if err != nil {
		return View{}, err
	}
	v := View{
		TransferID: a.d.ID, SenderEmail: a.d.SenderEmail, ExpiresAt: a.d.ExpiresAt,
		PasswordProtected: a.d.PasswordProtected(), Locked: !a.unlocked || a.awaiting(),
		VerificationRequired: a.verify, Verified: a.verified,
	}
	if a.awaiting() {
		v.RecipientEmailMasked = MaskEmail(a.link.Email)
		return v, nil
	}
	if v.Locked {
		// The level is part of what the password protects: a locked view
		// keeps the 1.0 set of fields.
		return v, nil
	}
	if v.ReplyAllowed, err = s.replyEligible(ctx, t.ID, a.d, a.link); err != nil {
		return View{}, err
	}
	v.Reply = a.d.SenderKind == store.DepositorReply
	v.Confidentiality = confidentiality(a.d)
	v.Message, v.DeleteAfterFirstDownload, v.ArchiveAvailable = a.d.Message, a.d.DeleteAfterFirstDownload, true
	if m := a.d.MaxDownloads; m != nil {
		left := int(int64(*m) - a.d.DownloadCount)
		v.DownloadsRemaining = &left
	}
	for _, f := range a.files {
		v.TotalBytes += f.Size
		v.Files = append(v.Files, FileView{
			ID: f.ID, Name: f.Name, Path: f.Path, Size: f.Size, MediaType: f.MediaType, SHA256: f.SHA256, ScanStatus: f.ScanStatus,
		})
	}
	return v, nil
}
