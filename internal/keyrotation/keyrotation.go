// Package keyrotation runs the master key rotation started from the
// administration (CLAUDE.md section 16.1, OpenAPI startMasterKeyRotation,
// getMasterKeyRotation and getMasterKeyStatus; threat model T-37, T-156).
//
// The re-wrapping itself belongs to package masterkey (masterkey.Rotate),
// shared with the rotate-master-key command. This package adds what the
// administration needs around it: the super admin check, the TOTP
// re-confirmation (adminauth.Service.ConfirmTOTP), a single background
// worker per instance owning its context, the audit events
// (master_key.rotation_started, master_key.rotation_completed,
// master_key.rotation_failed) and the status of the master keys.
//
// A rotation interrupted by the shutdown is never recorded as failed: it
// stays running in the database and is resumed, with the same identifier,
// by the next start request between the same keys (or by the command).
// It is never resumed automatically at start-up, since that needs a TOTP
// re-confirmation. The application waits for the worker ([Service.Done])
// before destroying the master keys.
//
// Neither the logs nor the audit events ever hold key material: only the
// key identifiers, which are derived from the keys and are not secret.
package keyrotation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
)

// SystemActor is the system actor of the audit events written by the
// background worker (rotation completed or failed).
const SystemActor = "master-key-rotation"

// Errors returned by the [Service]. The comment of each one gives the
// problem it maps to. The service also returns, unchanged, the errors of
// adminauth: ErrUnauthenticated (401 unauthenticated), ErrForbidden (403
// forbidden), ErrInvalidCredentials (401 invalid-credentials), a
// *adminauth.RateLimitError (429 rate-limited), an *adminauth.InvalidError
// (400 validation-failed) and ErrNoClientIP (500).
var (
	// ErrNoNewKey reports a start without TT_MASTER_KEY_NEW_FILE (409
	// new-master-key-missing). It is checked before the TOTP code, so that
	// no attempt is consumed, like the state conflicts (ErrConflict).
	ErrNoNewKey = errors.New("keyrotation: no new master key configured (" + config.EnvMasterKeyNewFile + ")")
	// ErrConflict reports a start the current state does not allow (409
	// state-conflict). ErrRunning, ErrRotationMismatch and
	// ErrRestartRequired match it.
	ErrConflict = errors.New("keyrotation: not allowed in the current state")
	// ErrRunning reports a rotation already running in this instance, or
	// started meanwhile by another process (store.ErrRotationRunning).
	ErrRunning = fmt.Errorf("%w: a master key rotation is already running", ErrConflict)
	// ErrRotationMismatch reports an interrupted rotation between other keys
	// than the configured ones: configure its keys to resume it, or abandon
	// it with rotate-master-key -abandon.
	ErrRotationMismatch = fmt.Errorf("%w: an interrupted master key rotation exists between other keys", ErrConflict)
	// ErrRestartRequired reports a rotation to the configured new key that
	// has already completed: restart with the switched configuration.
	ErrRestartRequired = fmt.Errorf("%w: the rotation to the new master key is completed; restart with it as %s",
		ErrConflict, config.EnvMasterKeyFile)
	// ErrNotFound reports an unknown or malformed rotation identifier (404
	// not-found).
	ErrNotFound = errors.New("keyrotation: rotation not found")
	// ErrClosed reports a start after Close (the instance is shutting
	// down).
	ErrClosed = errors.New("keyrotation: shutting down")
)

// Confirmer re-confirms the second factor of an administrator.
// *adminauth.Service implements it.
type Confirmer interface {
	ConfirmTOTP(ctx context.Context, p adminauth.Principal, code, recoveryCode string, clientIP netip.Addr) (adminauth.Account, error)
}

// AuditRecorder records the global audit events. *audit.Writer implements
// it.
type AuditRecorder interface {
	Record(ctx context.Context, ev audit.Event) error
}

// Options tunes a [Service]. The zero value is valid.
type Options struct {
	// Rotation tunes the re-wrapping (batch size, clock, progress hook);
	// its clock also dates the start of a rotation.
	Rotation masterkey.Options
	// Logger receives the outcome of the background rotations; nil
	// discards.
	Logger *slog.Logger
	// Events receives the master_key.rotation_completed and
	// master_key.rotation_failed events of the background rotations; nil
	// publishes nothing.
	Events events.Publisher
}

// Rotation is a master key rotation, as the OpenAPI KeyRotation schema
// exposes it.
type Rotation struct {
	// ID is the identifier ("rot_" + ULID).
	ID string
	// Status is running, completed or failed.
	Status store.RotationStatus
	// FromKeyID is the master key being replaced.
	FromKeyID string
	// ToKeyID is the new master key.
	ToKeyID string
	// TotalKeys is the number of keys under the old key at the start.
	TotalKeys int64
	// RewrappedKeys is the number of keys re-wrapped so far.
	RewrappedKeys int64
	// StartedAt is the start time.
	StartedAt time.Time
	// CompletedAt is the end time, zero while running.
	CompletedAt time.Time
	// Error is the failure message of a failed rotation (row and key
	// identifiers, never key material).
	Error string
}

// viewOf returns the view of r, its times in UTC at millisecond precision
// as stored: a rotation just started (whose times come from the clock, not
// the database) reads as it will be read back.
func viewOf(r store.Rotation) Rotation {
	return Rotation{
		ID: r.ID, Status: r.Status, FromKeyID: r.FromKeyID, ToKeyID: r.ToKeyID, TotalKeys: r.TotalKeys,
		RewrappedKeys: r.RewrappedKeys, StartedAt: storedTime(r.StartedAt), CompletedAt: storedTime(r.CompletedAt),
		Error: r.Error,
	}
}

// storedTime returns t in UTC at millisecond precision; the zero time stays
// zero.
func storedTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC().Truncate(time.Millisecond)
}

// MasterKeyStatus is the state of the master keys (OpenAPI
// MasterKeyStatus).
type MasterKeyStatus struct {
	// ActiveKeyID is the key of TT_MASTER_KEY_FILE, the one this process
	// started with.
	ActiveKeyID string
	// NewKeyID is the key of TT_MASTER_KEY_NEW_FILE, "" when none is
	// configured.
	NewKeyID string
	// RestartRequired reports that a rotation to NewKeyID has completed:
	// the database records NewKeyID as the active master key (and the key
	// of TT_MASTER_KEY_FILE as retired), so the instance must restart with
	// the switched configuration (NewKeyID as TT_MASTER_KEY_FILE, no
	// TT_MASTER_KEY_NEW_FILE). It is false without a new key.
	RestartRequired bool
	// LatestRotation is the most recently started rotation, nil if none.
	LatestRotation *Rotation
}

// Service starts and follows the master key rotations of the
// administration. It is safe for concurrent use.
type Service struct {
	db      *store.DB
	keys    *masterkey.Keyring
	confirm Confirmer
	audit   AuditRecorder
	events  events.Publisher
	logger  *slog.Logger
	opts    masterkey.Options

	// ctx is the context of the worker, canceled by Close.
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	// done is the channel of the running worker, nil when none runs.
	done chan struct{}

	// The rotation engine, replaced by the tests.
	start  func(ctx context.Context, db *store.DB, kr *masterkey.Keyring, now time.Time) (store.Rotation, error)
	rotate func(ctx context.Context, db *store.DB, kr *masterkey.Keyring, logger *slog.Logger, opts masterkey.Options) (store.Rotation, error)
}

// New returns a service rotating the keys of keys over db. confirm checks
// the TOTP re-confirmation and rec records the audit events. Every
// dependency is required. The worker context is owned by the service:
// call Close at shutdown.
func New(db *store.DB, keys *masterkey.Keyring, confirm Confirmer, rec AuditRecorder, opts Options) *Service {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Rotation.Now == nil {
		opts.Rotation.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		db: db, keys: keys, confirm: confirm, audit: rec, events: events.OrDiscard(opts.Events), logger: opts.Logger,
		opts: opts.Rotation,
		ctx:  ctx, cancel: cancel, start: masterkey.StartRotation, rotate: masterkey.Rotate,
	}
}

// requireSuperAdmin checks that p is an authenticated session of a super
// admin.
func requireSuperAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// Start starts a rotation from the current to the new master key, or
// resumes the interrupted rotation between these keys (same identifier),
// for the super admin of p re-confirming with a TOTP code (code) or a
// recovery code (recoveryCode) from clientIP. It records
// master_key.rotation_started, then re-wraps the keys in the background and
// returns at once with the rotation as it starts.
//
// Checks, in this order: an authenticated super admin (ErrUnauthenticated,
// ErrForbidden); a new master key (ErrNoNewKey); the state of the rotations
// (ErrClosed during the shutdown, ErrRunning when a rotation already runs in
// this instance, ErrRotationMismatch for an interrupted rotation between
// other keys, ErrRestartRequired when the rotation to the new key has
// completed); then the TOTP re-confirmation (adminauth errors). The checks
// before the TOTP consume no attempt: neither a TOTP time step nor a
// recovery code is burnt on a refused start. The state check before the
// TOTP is only advisory: it is made again, authoritatively, under the lock
// after the confirmation, which also returns ErrRunning for a rotation
// started meanwhile by another process.
func (s *Service) Start(ctx context.Context, p adminauth.Principal, code, recoveryCode string, clientIP netip.Addr) (Rotation, error) {
	if err := requireSuperAdmin(p); err != nil {
		return Rotation{}, err
	}
	if s.keys.NewID() == "" {
		return Rotation{}, ErrNoNewKey
	}
	if err := s.precheck(ctx); err != nil {
		return Rotation{}, err
	}
	acc, err := s.confirm.ConfirmTOTP(ctx, p, code, recoveryCode, clientIP)
	if err != nil {
		return Rotation{}, err
	}
	if err := adminauth.RequireSuperAdmin(acc); err != nil {
		return Rotation{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.busy(); err != nil {
		return Rotation{}, err
	}
	rot, resumed, err := s.prepare(ctx)
	if err != nil {
		return Rotation{}, err
	}
	err = s.audit.Record(ctx, StartedEvent(store.ActorAdmin, acc.Username, clientIP, rot, resumed))
	if err != nil {
		// No unaudited rotation: the worker is not started. The rotation
		// stays running in the database and the next request resumes it.
		return Rotation{}, fmt.Errorf("keyrotation: audit rotation start: %w", err)
	}
	done := make(chan struct{})
	s.done = done
	go s.work(rot, done) //nolint:contextcheck // the worker runs under the service context, canceled by Close, not the request
	s.logger.InfoContext(ctx, "master key rotation launched from the administration", slog.String("rotation", rot.ID),
		slog.String("from", rot.FromKeyID), slog.String("to", rot.ToKeyID), slog.Bool("resumed", resumed),
		slog.String("admin_id", acc.ID))
	return viewOf(rot), nil
}

// busy returns ErrClosed after Close and ErrRunning while the worker runs,
// nil otherwise. The caller holds s.mu.
func (s *Service) busy() error {
	switch {
	case s.closed:
		return ErrClosed
	case s.done != nil:
		return ErrRunning
	}
	return nil
}

// precheck returns the error of a start the current state refuses (see
// busy and resumable), without starting anything. It runs before the TOTP
// re-confirmation so that a refused start consumes no attempt; its answer
// may be outdated by the time the rotation starts, so Start checks again
// under the lock.
func (s *Service) precheck(ctx context.Context) error {
	s.mu.Lock()
	err := s.busy()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	_, _, err = s.resumable(ctx)
	return err
}

// prepare returns the rotation to run, and whether it is resumed: the
// running rotation between the configured keys, or a new one.
func (s *Service) prepare(ctx context.Context) (store.Rotation, bool, error) {
	rot, resumed, err := s.resumable(ctx)
	if err != nil || resumed {
		return rot, resumed, err
	}
	rot, err = s.start(ctx, s.db, s.keys, s.opts.Now())
	switch {
	case errors.Is(err, store.ErrRotationRunning):
		return store.Rotation{}, false, ErrRunning
	case err != nil:
		return store.Rotation{}, false, fmt.Errorf("keyrotation: %w", err)
	}
	return rot, false, nil
}

// resumable returns the running rotation between the configured keys and
// true, or false when none runs and a new rotation may start. It returns
// ErrRotationMismatch for a running rotation between other keys and
// ErrRestartRequired when the rotation to the new key has completed.
func (s *Service) resumable(ctx context.Context) (store.Rotation, bool, error) {
	running, err := s.db.KeyRotations().Running(ctx)
	switch {
	case err == nil && running.FromKeyID == s.keys.CurrentID() && running.ToKeyID == s.keys.NewID():
		return running, true, nil
	case err == nil:
		return store.Rotation{}, false, fmt.Errorf("%w: rotation %s from %s to %s", ErrRotationMismatch,
			running.ID, running.FromKeyID, running.ToKeyID)
	case !errors.Is(err, store.ErrNotFound):
		return store.Rotation{}, false, fmt.Errorf("keyrotation: read running rotation: %w", err)
	}
	restart, err := s.restartRequired(ctx)
	if err != nil {
		return store.Rotation{}, false, err
	}
	if restart {
		return store.Rotation{}, false, ErrRestartRequired
	}
	return store.Rotation{}, false, nil
}

// restartRequired reports whether the database records the configured new
// key as the active master key (see MasterKeyStatus.RestartRequired).
func (s *Service) restartRequired(ctx context.Context) (bool, error) {
	if s.keys.NewID() == "" {
		return false, nil
	}
	active, err := s.db.MasterKeys().Active(ctx)
	if err != nil {
		return false, fmt.Errorf("keyrotation: read active master key: %w", err)
	}
	return active == s.keys.NewID(), nil
}

// work runs rot in the background under the worker context, records its
// outcome and closes done.
func (s *Service) work(rot store.Rotation, done chan struct{}) {
	defer func() {
		s.mu.Lock()
		s.done = nil
		s.mu.Unlock()
		close(done)
	}()
	ctx := s.ctx
	final, err := s.rotate(ctx, s.db, s.keys, s.logger, s.opts)
	switch {
	case final.ID == "":
		final = rot
	case final.ID != rot.ID:
		// rotate-master-key completed rot between the start request and
		// the worker, which then ran another (clean-up) rotation.
		s.logger.WarnContext(ctx, "master key rotation finished by another process before the worker started",
			slog.String("rotation", rot.ID), slog.String("ran", final.ID))
	}
	attrs := []any{
		slog.String("rotation", final.ID), slog.String("from", final.FromKeyID),
		slog.String("to", final.ToKeyID), slog.Int64("rewrapped", final.RewrappedKeys),
	}
	if ev, ok := OutcomeEvent(SystemActor, final, err, ctx.Err() != nil); ok {
		if rerr := s.audit.Record(context.WithoutCancel(ctx), ev); rerr != nil {
			s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(ev.Action)),
				slog.String("rotation", final.ID), slog.String("error", rerr.Error()))
		}
		s.publish(final, err == nil)
	}
	switch {
	case err == nil:
		s.logger.WarnContext(ctx, "master key rotation completed: restart with the switched configuration ("+
			config.EnvMasterKeyFile+" = the new key, "+config.EnvMasterKeyNewFile+" removed) and update the vault; see "+
			masterkey.DocLink, attrs...)
	case errors.Is(err, masterkey.ErrRewrap):
		s.logger.ErrorContext(ctx, "master key rotation failed", append(attrs, slog.String("error", err.Error()))...)
	case errors.Is(err, store.ErrRotationNotRunning):
		s.finishedElsewhere(ctx, final)
	case ctx.Err() != nil:
		// Canceled by Close (shutdown): never a failure.
		s.logger.InfoContext(ctx, "master key rotation interrupted by the shutdown: it stays running and is "+
			"resumed by the next start request", attrs...)
	default:
		s.logger.ErrorContext(ctx, "master key rotation stopped: it stays running and can be resumed",
			append(attrs, slog.String("error", err.Error()))...)
	}
}

// publish publishes the outcome of rot: master_key.rotation_completed
// when completed, master_key.rotation_failed otherwise.
func (s *Service) publish(rot store.Rotation, completed bool) {
	typ, sev := events.MasterKeyRotationFailed, events.SeverityCritical
	if completed {
		typ, sev = events.MasterKeyRotationCompleted, events.SeverityInfo
	}
	s.events.Publish(events.Event{
		Type: typ, Severity: sev, OccurredAt: s.opts.Now(), AdminPath: events.AdminPathMasterKey,
		Counts: map[string]float64{"totalKeys": float64(rot.TotalKeys), "rewrappedKeys": float64(rot.RewrappedKeys)},
	})
}

// finishedElsewhere handles a rotation that stopped running under the
// worker: another process (rotate-master-key) completed or abandoned it
// and recorded its own audit event, so nothing is recorded again.
func (s *Service) finishedElsewhere(ctx context.Context, rot store.Rotation) {
	attrs := []any{slog.String("rotation", rot.ID)}
	got, err := s.db.KeyRotations().Get(context.WithoutCancel(ctx), rot.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "master key rotation stopped running elsewhere; its state cannot be read",
			append(attrs, slog.String("error", err.Error()))...)
		return
	}
	s.logger.InfoContext(ctx, "master key rotation finished by another process", append(attrs,
		slog.String("status", string(got.Status)))...)
}

// StartedEvent returns the master_key.rotation_started audit event of rot,
// started (or resumed, when resumed is true) by actor of kind kind from ip
// (the zero Addr for a local command). Its details hold the key
// identifiers and counts only, never key material. It is global (no
// tenant). The rotate-master-key command records it too.
func StartedEvent(kind store.AuditActorKind, actor string, ip netip.Addr, rot store.Rotation, resumed bool) audit.Event {
	return audit.Event{
		ActorKind: kind, Actor: actor, IP: ip, Action: audit.ActionMasterKeyRotationStarted,
		ObjectKind: audit.ObjectMasterKeyRotation, ObjectID: rot.ID,
		Details: map[string]any{"from": rot.FromKeyID, "to": rot.ToKeyID, "total": rot.TotalKeys, "resumed": resumed},
	}
}

// OutcomeEvent returns the audit event recording the end of rot, run by
// the system actor actor, from err, the result of masterkey.Rotate (or
// Recover): master_key.rotation_completed on success,
// master_key.rotation_failed otherwise, with a reason ("rewrap" for a row
// that cannot be unwrapped, the rotation being marked failed;
// "keys_still_created" or "error" for a stop that leaves it running and
// resumable). It reports false, recording nothing, when canceled is true
// (an interruption is never a failure) or when the rotation stopped
// running under it (store.ErrRotationNotRunning: another process completed
// or abandoned it and records its own event). The rotate-master-key
// command records it too.
func OutcomeEvent(actor string, rot store.Rotation, err error, canceled bool) (audit.Event, bool) {
	details := map[string]any{"from": rot.FromKeyID, "to": rot.ToKeyID, "rewrapped": rot.RewrappedKeys}
	action := audit.ActionMasterKeyRotationFailed
	switch {
	case err == nil:
		action = audit.ActionMasterKeyRotationCompleted
	case errors.Is(err, masterkey.ErrRewrap):
		details["reason"], details["error"] = "rewrap", rot.Error
	case errors.Is(err, store.ErrRotationNotRunning), canceled:
		return audit.Event{}, false
	case errors.Is(err, masterkey.ErrKeysStillCreated):
		details["reason"], details["resumable"] = "keys_still_created", true
	default:
		details["reason"], details["resumable"] = "error", true
	}
	return audit.Event{
		ActorKind: store.ActorSystem, Actor: actor, Action: action,
		ObjectKind: audit.ObjectMasterKeyRotation, ObjectID: rot.ID, Details: details,
	}, true
}

// Get returns the rotation rotID for the super admin of p. It returns
// ErrNotFound for an unknown or malformed identifier.
func (s *Service) Get(ctx context.Context, p adminauth.Principal, rotID string) (Rotation, error) {
	if err := requireSuperAdmin(p); err != nil {
		return Rotation{}, err
	}
	if !id.Valid(id.Rotation, rotID) {
		return Rotation{}, ErrNotFound
	}
	rot, err := s.db.KeyRotations().Get(ctx, rotID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Rotation{}, ErrNotFound
	case err != nil:
		return Rotation{}, fmt.Errorf("keyrotation: %w", err)
	}
	return viewOf(rot), nil
}

// Status returns the state of the master keys for the super admin of p.
func (s *Service) Status(ctx context.Context, p adminauth.Principal) (MasterKeyStatus, error) {
	if err := requireSuperAdmin(p); err != nil {
		return MasterKeyStatus{}, err
	}
	st := MasterKeyStatus{ActiveKeyID: s.keys.CurrentID(), NewKeyID: s.keys.NewID()}
	var err error
	if st.RestartRequired, err = s.restartRequired(ctx); err != nil {
		return MasterKeyStatus{}, err
	}
	latest, err := s.db.KeyRotations().Latest(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return MasterKeyStatus{}, fmt.Errorf("keyrotation: %w", err)
	default:
		v := viewOf(latest)
		st.LatestRotation = &v
	}
	return st, nil
}

// WarnInterrupted logs a warning, at start-up, when a rotation between
// the configured keys was interrupted: it is not resumed automatically,
// since that needs a TOTP re-confirmation.
func (s *Service) WarnInterrupted(ctx context.Context) error {
	running, err := s.db.KeyRotations().Running(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("keyrotation: read running rotation: %w", err)
	}
	if running.FromKeyID == s.keys.CurrentID() && running.ToKeyID == s.keys.NewID() {
		s.logger.WarnContext(ctx, "an interrupted master key rotation is waiting: resume it from the administration "+
			"(TOTP re-confirmation) or with rotate-master-key", slog.String("rotation", running.ID),
			slog.String("from", running.FromKeyID), slog.String("to", running.ToKeyID),
			slog.Int64("rewrapped", running.RewrappedKeys), slog.Int64("total", running.TotalKeys))
	}
	return nil
}

// Done returns a channel closed once no rotation worker runs. After Close
// no worker can start, so the channel then tells when the master keys may
// be destroyed.
func (s *Service) Done() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		c := make(chan struct{})
		close(c)
		return c
	}
	return s.done
}

// Close refuses new rotations, cancels the running worker and waits for it
// until ctx ends. The canceled rotation stays running in the database,
// resumable. It returns an error matching ctx.Err() when the worker is
// still running then (wait for [Service.Done] before destroying the keys).
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	select {
	case <-s.Done():
		return nil
	case <-ctx.Done():
		return fmt.Errorf("keyrotation: master key rotation still stopping: %w", ctx.Err())
	}
}
