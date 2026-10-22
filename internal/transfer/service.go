package transfer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// Defaults and fixed limits of the service.
const (
	// DefaultMaxRecipients is the recipient ceiling when
	// Options.MaxRecipients is not set (TT_MAX_RECIPIENTS, decision P15).
	DefaultMaxRecipients = 50
	// DefaultMaxOpenTransfers is the cap on the unfinished transfers of an
	// internal sender when Options.MaxOpenTransfers is not set
	// (TT_MAX_OPEN_TRANSFERS).
	DefaultMaxOpenTransfers = 10
	// MaxOpenTransfersExternal is the fixed cap on the unfinished transfers
	// of an invited external sender: an invitation is meant for a handful
	// of deposits, and an external sender must not be able to hold much of
	// the tenant quota with transfers it never uploads.
	MaxOpenTransfersExternal = 3
	// OpenTransfersRetryAfter is the Retry-After hint of the open transfer
	// cap: the sender frees a slot at once by finalizing or canceling a
	// transfer, and an unfinished transfer stops counting as soon as its
	// uploads expire (TT_UPLOAD_TTL after its last activity, at most
	// TT_UPLOAD_MAX_AGE after its creation), without waiting for the
	// cleanup job.
	OpenTransfersRetryAfter = time.Hour
	// maxOpenScan bounds the unfinished transfers examined when a sender
	// reaches the cap; the ones beyond it count as active.
	maxOpenScan = 1000
	// DefaultHashConcurrency is the number of concurrent argon2id
	// computations of the default password hasher (threat T-125): at most
	// 2 x 64 MiB of memory.
	DefaultHashConcurrency = 2
)

// Uploads is the part of the tus upload engine the service uses.
// *upload.Engine implements it.
type Uploads interface {
	// TransferActivity returns the last upload activity of a transfer
	// created at createdAt whose files are files, and when its incomplete
	// uploads expire.
	TransferActivity(ctx context.Context, tid tenant.ID, files []store.TransferFile, createdAt time.Time) (lastActivity, expiresAt time.Time, err error)
	// Offset returns the durable offset of the file f of tenant tid;
	// createdAt is the creation time of its transfer and transferActivity
	// its last activity.
	Offset(ctx context.Context, tid tenant.ID, f store.TransferFile, createdAt, transferActivity time.Time) (offset int64, expiresAt time.Time, err error)
	// LockFiles takes the exclusive upload lock of every file, or none:
	// it fails with upload.ErrBusy when an upload of one of them is in
	// progress. unlock releases them.
	LockFiles(fileIDs []string) (unlock func(), err error)
	// RemoveFiles destroys the data keys of files in one transaction, then
	// their files on disk (T-110), then scrubs the database once. It
	// accepts files whose key is already destroyed, so that an interrupted
	// cancellation can be retried, and does not delete the rows. The caller
	// holds the locks of the files.
	RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error
	// WriteEmpty writes the encrypted form of an empty file under
	// storageName with dek and returns its SHA-256 and its encrypted size.
	WriteEmpty(ctx context.Context, tid tenant.ID, fileID string, dek []byte, storageName string) (sha256 string, ciphertextSize int64, err error)
}

// DataKeys creates the data key of a file in the transaction that creates
// the file (decision P6). *masterkey.Vault implements it.
//
// Open unseals a sealed secret: the download token of an available
// transfer (crypto.PurposeSecret), to give its sender the download link.
type DataKeys interface {
	NewDEKTx(ctx context.Context, tx *store.ScopedTx) (wkID string, dek []byte, err error)
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// PasswordHasher hashes transfer passwords with argon2id, bounding the
// concurrent computations. *crypto.PasswordHasher implements it.
type PasswordHasher interface {
	HashPassword(ctx context.Context, password []byte) (string, error)
}

// SecurityLog writes security events. *securitylog.Logger implements it.
type SecurityLog interface {
	Log(ev securitylog.Event) error
}

// AuditRecorder records tenant audit events. *audit.Writer implements it.
type AuditRecorder interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// UsageRecorder counts the finalized transfers in the usage statistics of
// the tenants. TransferFinalized must not block.
type UsageRecorder interface {
	TransferFinalized(tid tenant.ID, totalBytes int64, at time.Time)
}

// Audit detail values.
const (
	// originInternal is a transfer of an internal sender.
	originInternal = "internal"
	// originInvitation is a transfer of an external sender holding an
	// invitation.
	originInvitation = "invitation"
	// deletedBySender tells that the sender canceled the transfer.
	deletedBySender = "sender"
)

// Options tunes a [Service].
type Options struct {
	// MaxRecipients bounds the recipients of a transfer
	// (DefaultMaxRecipients when <= 0, at most store.MaxTransferRecipients).
	MaxRecipients int
	// MaxOpenTransfers caps the unfinished transfers of an internal sender
	// (DefaultMaxOpenTransfers when <= 0); external senders are capped at
	// MaxOpenTransfersExternal.
	MaxOpenTransfers int
	// UploadMaxAge is the longest life of an unfinished upload after the
	// creation of its transfer (TT_UPLOAD_MAX_AGE, upload.DefaultMaxAge when
	// <= 0): older unfinished transfers are expired, and the open transfer
	// cap does not look at them. Pass the value given to the upload engine.
	UploadMaxAge time.Duration
	// Hasher hashes the transfer passwords
	// (crypto.NewPasswordHasher(DefaultHashConcurrency) when nil).
	Hasher PasswordHasher
	// OnFinalized is called after the commit of every finalization, with
	// the tenant and the transfer, best effort: it must not block, and a
	// transfer whose call was lost (crash between the commit and the call)
	// stays in scanning. Step 7 plugs the antivirus queue in here, and also
	// sweeps the scanning transfers at startup to recover such losses. nil
	// does nothing.
	OnFinalized func(tid tenant.ID, transferID string)
	// OnQuota is called after the commit of every creation (refused false)
	// and when a creation is refused because the storage quota of the
	// tenant is exceeded (refused true), so that the quota alerts are
	// evaluated. It is called on the request path: the caller must make it
	// non-blocking (a buffered channel with a non-blocking send, for
	// instance). nil does nothing.
	OnQuota func(tid tenant.ID, refused bool)
	// Audit records the tenant audit events (transfer created, finalized
	// and canceled), best effort after the commit: a failure is logged,
	// never returned. nil records nothing.
	Audit AuditRecorder
	// Usage counts every finalized transfer, after the commit. nil counts
	// nothing.
	Usage UsageRecorder
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the failures that do not fail a request (security
	// log writes, empty file completion); nil discards.
	Logger *slog.Logger
}

// Sender is the authenticated depositor acting on a transfer, as the HTTP
// layer builds it from the deposit session (deposit.SessionInfo) and the
// real client IP. Its store.Depositor holds the ownership rule shared with
// the upload engine ([store.Depositor.Owns]).
type Sender struct {
	store.Depositor
	// ClientIP is the real client IP of the request (trusted-proxy aware).
	ClientIP netip.Addr
}

// Service creates, follows, cancels and finalizes transfers on behalf of
// their senders. It is safe for concurrent use.
type Service struct {
	repo          repo
	uploads       Uploads
	seclog        SecurityLog
	hasher        PasswordHasher
	logger        *slog.Logger
	maxRecipients int
	maxOpen       int
	uploadMaxAge  time.Duration
	onFinalized   func(tid tenant.ID, transferID string)
	onQuota       func(tid tenant.ID, refused bool)
	audit         AuditRecorder
	usage         UsageRecorder
	clock         func() time.Time
	newID         func(p id.Prefix) (string, error)
	newUploadID   func() (string, error)
}

// New returns a service over db, creating data keys with keys, handling
// the files on disk through uploads and writing security events to
// seclog. Every dependency is required.
func New(db *store.DB, keys DataKeys, uploads Uploads, seclog SecurityLog, opts Options) *Service {
	if opts.MaxRecipients <= 0 {
		opts.MaxRecipients = DefaultMaxRecipients
	}
	opts.MaxRecipients = min(opts.MaxRecipients, store.MaxTransferRecipients)
	if opts.MaxOpenTransfers <= 0 {
		opts.MaxOpenTransfers = DefaultMaxOpenTransfers
	}
	if opts.UploadMaxAge <= 0 {
		opts.UploadMaxAge = upload.DefaultMaxAge
	}
	if opts.Hasher == nil {
		opts.Hasher = crypto.NewPasswordHasher(DefaultHashConcurrency)
	}
	if opts.OnFinalized == nil {
		opts.OnFinalized = func(tenant.ID, string) {}
	}
	if opts.OnQuota == nil {
		opts.OnQuota = func(tenant.ID, bool) {}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		repo: storeRepo{db: db, keys: keys}, uploads: uploads, seclog: seclog, hasher: opts.Hasher,
		logger: opts.Logger, maxRecipients: opts.MaxRecipients, maxOpen: opts.MaxOpenTransfers,
		uploadMaxAge: opts.UploadMaxAge,
		onFinalized:  opts.OnFinalized, onQuota: opts.OnQuota, audit: opts.Audit, usage: opts.Usage,
		clock: opts.Now, newUploadID: id.NewUploadToken,
	}
	s.newID = id.NewGenerator(s.clock, nil).New
	return s
}

// now returns the clock at the precision of the stored timestamps, so that
// the values the service returns equal the stored ones.
func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Millisecond)
}

// normalize checks the shape of the sender and returns its normalized
// address. A malformed sender is a wiring error of the caller (the session
// holds a normalized address), not a client error.
func normalize(sender Sender) (string, error) {
	email, err := store.NormalizeEmail(sender.Email)
	if err != nil {
		return "", errors.New("transfer: malformed sender address")
	}
	ok := (sender.Kind == store.DepositorInternal && sender.InvitationID == "") ||
		(sender.Kind == store.DepositorExternal && id.Valid(id.Invitation, sender.InvitationID))
	if !ok {
		return "", errors.New("transfer: malformed sender kind or invitation")
	}
	return email, nil
}

// openCap returns the cap on the unfinished transfers of sender.
func (s *Service) openCap(sender Sender) int {
	if sender.Kind == store.DepositorExternal {
		return MaxOpenTransfersExternal
	}
	return s.maxOpen
}

// logEvent writes a security event; a write failure is only reported on the
// application log.
func (s *Service) logEvent(ctx context.Context, t *tenant.Tenant, ip netip.Addr, typ securitylog.EventType, fields ...securitylog.Field) {
	ev := securitylog.Event{Type: typ, IP: ip, Tenant: t.FQDN, Fields: fields}
	if err := s.seclog.Log(ev); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(typ)), slog.String("error", err.Error()))
	}
}

// refuse logs a deposit_refused event with reason and returns ErrForbidden.
func (s *Service) refuse(ctx context.Context, t *tenant.Tenant, ip netip.Addr, reason string) error {
	s.logEvent(ctx, t, ip, securitylog.DepositRefused, securitylog.Field{Key: securitylog.KeyReason, Value: reason})
	return ErrForbidden
}

// checkEligible checks again that the sender may deposit (threat T-25, the
// obligation of internal/deposit): neither its address nor its domain is
// blocklisted; an internal sender still satisfies the internal rule from
// the current client IP; an external sender's invitation is still active
// and names the same address. It returns the normalized address and, for
// an external sender, the invitation (whose inviter is the recipient,
// T-17). A refusal is logged as deposit_refused with reason blocklist, ip,
// domain or invitation, and returns ErrForbidden.
func (s *Service) checkEligible(ctx context.Context, t *tenant.Tenant, sender Sender) (string, store.Invitation, error) {
	email, err := normalize(sender)
	if err != nil {
		return "", store.Invitation{}, err
	}
	blocked, err := s.repo.blocked(ctx, t.ID, email, "")
	if err != nil {
		return "", store.Invitation{}, fmt.Errorf("transfer: check blocklist: %w", err)
	}
	if blocked {
		return "", store.Invitation{}, s.refuse(ctx, t, sender.ClientIP, securitylog.ReasonBlocklist)
	}
	if sender.Kind == store.DepositorInternal {
		rules, err := s.repo.networkRules(ctx, t.ID)
		if err != nil {
			return "", store.Invitation{}, fmt.Errorf("transfer: read network rules: %w", err)
		}
		v := netpolicy.Evaluate(netpolicy.Rules{CIDRs: rules.CIDRs, Domains: rules.Domains}, sender.ClientIP, email)
		switch {
		case !v.IPOK:
			return "", store.Invitation{}, s.refuse(ctx, t, sender.ClientIP, securitylog.ReasonIP)
		case !v.DomainOK:
			return "", store.Invitation{}, s.refuse(ctx, t, sender.ClientIP, securitylog.ReasonDomain)
		}
		return email, store.Invitation{}, nil
	}
	inv, err := s.repo.invitation(ctx, t.ID, sender.InvitationID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", store.Invitation{}, s.refuse(ctx, t, sender.ClientIP, securitylog.ReasonInvitation)
	case err != nil:
		return "", store.Invitation{}, fmt.Errorf("transfer: read invitation: %w", err)
	case !inv.Active(s.now()) || inv.Email != email:
		return "", store.Invitation{}, s.refuse(ctx, t, sender.ClientIP, securitylog.ReasonInvitation)
	}
	return email, inv, nil
}

// load returns the transfer trfID of tenant tid when sender owns it
// ([store.Depositor.Owns]), and ErrNotFound otherwise (unknown, malformed,
// other tenant or other sender: the cases are indistinguishable).
func (s *Service) load(ctx context.Context, tid tenant.ID, sender Sender, trfID string) (store.TransferDetails, error) {
	if !id.Valid(id.Transfer, trfID) {
		return store.TransferDetails{}, ErrNotFound
	}
	d, err := s.repo.transfer(ctx, tid, trfID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.TransferDetails{}, ErrNotFound
	case err != nil:
		return store.TransferDetails{}, fmt.Errorf("transfer: read transfer: %w", err)
	case !sender.Owns(d.Transfer):
		return store.TransferDetails{}, ErrNotFound
	}
	return d, nil
}

// lock takes the upload lock of every file of d. ErrBusy reports an upload
// in progress.
func (s *Service) lock(d store.TransferDetails) (func(), error) {
	ids := make([]string, len(d.Files))
	for i, f := range d.Files {
		ids[i] = f.ID
	}
	unlock, err := s.uploads.LockFiles(ids)
	switch {
	case errors.Is(err, upload.ErrBusy):
		return nil, ErrBusy
	case err != nil:
		return nil, fmt.Errorf("transfer: lock files: %w", err)
	}
	return unlock, nil
}

// lockUploading loads the transfer of sender, checks that it is uploading,
// takes the lock of its files and loads it again under the lock, so that
// neither its status nor its files change until unlock: the files can only
// be removed, never added, between the two reads, and every operation that
// changes the status of an uploading transfer holds these locks.
func (s *Service) lockUploading(ctx context.Context, tid tenant.ID, sender Sender, trfID string) (store.TransferDetails, func(), error) {
	d, err := s.load(ctx, tid, sender, trfID)
	if err != nil {
		return store.TransferDetails{}, nil, err
	}
	if d.Status != store.TransferUploading {
		return store.TransferDetails{}, nil, ErrConflict
	}
	unlock, err := s.lock(d)
	if err != nil {
		return store.TransferDetails{}, nil, err
	}
	d, err = s.load(ctx, tid, sender, trfID)
	if err == nil && d.Status != store.TransferUploading {
		err = ErrConflict
	}
	if err != nil {
		unlock()
		return store.TransferDetails{}, nil, err
	}
	return d, unlock, nil
}

// origin returns the audit origin of a transfer of sender.
func origin(sender Sender) string {
	if sender.Kind == store.DepositorExternal {
		return originInvitation
	}
	return originInternal
}

// record appends a tenant audit event on the transfer trfID whose actor is
// the sender address email, best effort: a failure is only reported on the
// application log. The address goes in the actor column, never in details.
func (s *Service) record(ctx context.Context, t *tenant.Tenant, sender Sender, email string,
	action audit.Action, trfID string, details map[string]any,
) {
	if s.audit == nil {
		return
	}
	ev := audit.Event{
		ActorKind: store.ActorDepositor, Actor: email, IP: sender.ClientIP,
		Action: action, ObjectKind: audit.ObjectTransfer, ObjectID: trfID, Details: details,
	}
	if err := s.audit.RecordScoped(context.WithoutCancel(ctx), t.ID, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", t.FQDN), slog.String("error", err.Error()))
	}
}
