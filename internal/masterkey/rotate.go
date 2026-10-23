package masterkey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DefaultBatchSize is the number of wrapped keys re-wrapped per transaction.
const DefaultBatchSize = 500

// maxCompleteAttempts bounds the completion attempts of a rotation while
// keys keep being created under the old master key.
const maxCompleteAttempts = 5

// abandonMessage is the error recorded on a rotation abandoned by the
// operator.
const abandonMessage = "abandoned by the operator (rotate-master-key -abandon)"

var (
	// ErrNoNewKey is returned by StartRotation and Rotate when
	// TT_MASTER_KEY_NEW_FILE is not configured.
	ErrNoNewKey = errors.New("masterkey: no new master key configured: set " + config.EnvMasterKeyNewFile +
		" and restart before rotating; see " + DocLink)
	// ErrRotationMismatch is returned by Rotate and Recover when a rotation
	// between other keys than the requested ones is running.
	ErrRotationMismatch = errors.New("masterkey: the running rotation does not match the configured keys")
	// ErrRewrap is returned when a wrapped key or a system secret cannot be
	// unwrapped with the old master key; the rotation is then marked failed.
	ErrRewrap = errors.New("masterkey: cannot re-wrap a wrapped key")
	// ErrKeysStillCreated is returned when keys keep being created under the
	// old master key, which means a process still runs without the new key.
	// The rotation stays running and can be resumed.
	ErrKeysStillCreated = errors.New("masterkey: keys keep being created under the old master key")
	// ErrNoRotation is returned by Abandon when no rotation is running.
	ErrNoRotation = errors.New("masterkey: no master key rotation is running")
	// ErrCannotAbandon is returned by Abandon when keys are already wrapped
	// under the target key of a running regular rotation.
	ErrCannotAbandon = errors.New("masterkey: the running rotation cannot be abandoned")
	// ErrRecoveryKey is returned by Recover when the given old key, or the
	// keyring, does not fit a clean-up rotation.
	ErrRecoveryKey = errors.New("masterkey: invalid key for a recovery")
)

// Options tunes Rotate and Recover. The zero value is valid.
type Options struct {
	// BatchSize is the number of keys per transaction (DefaultBatchSize when
	// zero or negative).
	BatchSize int
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// OnProgress, when set, is called after every committed batch (including
	// the final empty one) with the rotation state. It runs outside any
	// transaction.
	OnProgress func(store.Rotation)
}

// withDefaults fills the zero fields of o.
func (o Options) withDefaults() Options {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// StartRotation records a new rotation from the current to the new key of
// kr, with the number of keys to re-wrap, and returns it without re-wrapping
// anything. It returns ErrNoNewKey without a new key, and an error matching
// store.ErrRotationRunning when a rotation is already running (or
// store.ErrKeyRetired when the new key is retired).
//
// It is the synchronous part of the HTTP operation startMasterKeyRotation
// (202 Accepted): package keyrotation calls StartRotation, answers with the
// rotation, then runs Rotate in a background worker under a context owned
// by its service (canceled at shutdown, not by the end of the request), as
// the rotate-master-key command does with its own.
func StartRotation(ctx context.Context, db *store.DB, kr *Keyring, now time.Time) (store.Rotation, error) {
	if kr.NewID() == "" {
		return store.Rotation{}, ErrNoNewKey
	}
	return start(ctx, db, kr.CurrentID(), kr.NewID(), now)
}

// start records a rotation from one key to another.
func start(ctx context.Context, db *store.DB, from, to string, now time.Time) (store.Rotation, error) {
	total, err := db.WrappedKeys().CountByKey(ctx, from)
	if err != nil {
		return store.Rotation{}, fmt.Errorf("masterkey: start rotation: %w", err)
	}
	rot := store.Rotation{
		ID: id.New(id.Rotation), FromKeyID: from, ToKeyID: to,
		Status: store.RotationRunning, TotalKeys: total, StartedAt: now,
	}
	if err := db.KeyRotations().Start(ctx, rot); err != nil {
		return store.Rotation{}, fmt.Errorf("masterkey: start rotation: %w", err)
	}
	return rot, nil
}

// Rotate re-wraps every wrapped key of the tenants (wrapped_keys) and every
// system secret (system_secrets, the administrator TOTP secrets) from the
// current master key to the new one (threat model T-37), then marks the new
// key active, the old one retired and the rotation completed. It returns
// the final rotation record.
//
// It resumes the running rotation when it goes from the current to the new
// key, refuses (ErrRotationMismatch) a running rotation between other keys,
// and otherwise starts one (StartRotation). Keys are re-wrapped in batches
// of short transactions, so every row stays readable with one key or the
// other at any time and the server may keep running. Keys created meanwhile
// under the old key (by a process without the new key) are caught by
// looping until none remains (at most 5 completion attempts, then
// ErrKeysStillCreated). The database files are scrubbed at the end.
//
// When ctx is canceled the rotation stays running and Rotate returns an
// error matching ctx.Err(): running Rotate again resumes it. A background
// caller (HTTP handler) must therefore pass a context that outlives the
// request, such as context.WithoutCancel. When a key cannot be unwrapped
// with the old key, the rotation is marked failed with a message naming the
// row and the keys (never key material) and the error matches ErrRewrap.
func Rotate(ctx context.Context, db *store.DB, kr *Keyring, logger *slog.Logger, opts Options) (store.Rotation, error) {
	if kr.NewID() == "" {
		return store.Rotation{}, ErrNoNewKey
	}
	logger, opts = orDiscard(logger), opts.withDefaults()
	rot, err := resumeOrStart(ctx, db, kr.CurrentID(), kr.NewID(), kr.describe(), logger, opts.Now())
	if err != nil {
		return store.Rotation{}, err
	}
	return run(ctx, db, rot, kr.current, kr.next, logger, opts)
}

// Recover runs a clean-up rotation from old, a retired master key, to the
// current key of kr, which must be the active key: it re-wraps the keys
// wrapped under old after its rotation completed (a process that still ran
// with it, or a database restored from an older backup). The master keys
// do not change. old is only used by the caller's process (the
// rotate-master-key command), never by the server. It resumes a running
// clean-up rotation between the same keys, and returns ErrRecoveryKey when
// old is not a retired key or the current key is not the active one.
func Recover(ctx context.Context, db *store.DB, kr *Keyring, old *crypto.MasterKey, logger *slog.Logger, opts Options) (store.Rotation, error) {
	logger, opts = orDiscard(logger), opts.withDefaults()
	records, err := db.MasterKeys().List(ctx)
	if err != nil {
		return store.Rotation{}, fmt.Errorf("masterkey: recover: %w", err)
	}
	status, active := map[string]store.MasterKeyStatus{}, ""
	for _, r := range records {
		status[r.ID] = r.Status
		if r.Status == store.MasterKeyActive {
			active = r.ID
		}
	}
	switch {
	case status[old.ID()] != store.MasterKeyRetired:
		return store.Rotation{}, fmt.Errorf("%w: master key %s is not recorded as retired; only the keys left under "+
			"a retired key can be recovered; see %s", ErrRecoveryKey, old.ID(), DocLink)
	case active != kr.CurrentID():
		return store.Rotation{}, fmt.Errorf("%w: %s holds %s but the active master key is %s; set it to the active "+
			"key first; see %s", ErrRecoveryKey, config.EnvMasterKeyFile, kr.CurrentID(), active, DocLink)
	}
	rot, err := resumeOrStart(ctx, db, old.ID(), kr.CurrentID(),
		"the recovery runs from "+old.ID()+" to "+kr.CurrentID(), logger, opts.Now())
	if err != nil {
		return store.Rotation{}, err
	}
	return run(ctx, db, rot, old, kr.current, logger, opts)
}

// resumeOrStart returns the running rotation from one key to another, or
// starts one. configured describes the requested keys for the mismatch
// error.
func resumeOrStart(ctx context.Context, db *store.DB, from, to, configured string, logger *slog.Logger, now time.Time) (store.Rotation, error) {
	running, err := db.KeyRotations().Running(ctx)
	switch {
	case err == nil && running.FromKeyID == from && running.ToKeyID == to:
		logger.InfoContext(ctx, "resuming master key rotation", slog.String("rotation", running.ID),
			slog.String("from", running.FromKeyID), slog.String("to", running.ToKeyID),
			slog.Int64("rewrapped", running.RewrappedKeys), slog.Int64("total", running.TotalKeys))
		return running, nil
	case err == nil:
		return store.Rotation{}, fmt.Errorf("%w: rotation %s from %s to %s is running, but %s; "+
			"configure these two keys to resume it, or abandon it (rotate-master-key -abandon); see %s",
			ErrRotationMismatch, running.ID, running.FromKeyID, running.ToKeyID, configured, DocLink)
	case !errors.Is(err, store.ErrNotFound):
		return store.Rotation{}, fmt.Errorf("masterkey: rotate: %w", err)
	}
	rot, err := start(ctx, db, from, to, now)
	if err != nil {
		return store.Rotation{}, err
	}
	logger.InfoContext(ctx, "master key rotation started", slog.String("rotation", rot.ID),
		slog.String("from", rot.FromKeyID), slog.String("to", rot.ToKeyID), slog.Int64("total", rot.TotalKeys))
	return rot, nil
}

// run re-wraps the keys of rot from one key to the other until none
// remains, then completes the rotation and scrubs the database files.
func run(ctx context.Context, db *store.DB, rot store.Rotation, from, to *crypto.MasterKey,
	logger *slog.Logger, opts Options,
) (store.Rotation, error) {
	rotations := db.KeyRotations()
	for range maxCompleteAttempts {
		if err := drain(ctx, rotations, &rot, from, to, logger, opts); err != nil {
			return rot, err
		}
		done, err := complete(ctx, rotations, &rot, opts.Now())
		if err != nil {
			return rot, err
		}
		if done {
			scrubWarn(ctx, db.ScrubDeleted, logger)
			logger.InfoContext(ctx, "master key rotation completed", slog.String("rotation", rot.ID),
				slog.String("from", rot.FromKeyID), slog.String("to", rot.ToKeyID),
				slog.Int64("rewrapped", rot.RewrappedKeys))
			return rot, nil
		}
	}
	return rot, fmt.Errorf("%w (%s): restart every TransTeira process with the current keys, then run "+
		"rotate-master-key again to resume rotation %s; see %s", ErrKeysStillCreated, from.ID(), rot.ID, DocLink)
}

// drain re-wraps, in batches, the tenant keys (wrapped_keys) and then the
// system secrets (system_secrets) still under the old key, until a batch of
// each source re-wraps nothing, updating rot. OnProgress is called after
// every batch that re-wrapped keys and after the final empty one.
func drain(ctx context.Context, rotations *store.KeyRotations, rot *store.Rotation, from, to *crypto.MasterKey,
	logger *slog.Logger, opts Options,
) error {
	rewrapKey := func(k store.WrappedKey, tid tenant.ID) ([]byte, error) {
		return rewrapBlob(from, to, crypto.Purpose(k.Purpose), string(tid), k.ID, k.Blob,
			fmt.Sprintf("wrapped key %s of tenant %s", k.ID, tid))
	}
	rewrapSecret := func(s store.SystemSecret) ([]byte, error) {
		return rewrapBlob(from, to, crypto.Purpose(s.Purpose), systemBinding, s.ID, s.Blob, "system secret "+s.ID)
	}
	sources := []func() (int, error){
		func() (int, error) {
			return rotations.RewrapBatch(ctx, rot.ID, from.ID(), to.ID(), opts.BatchSize, rewrapKey)
		},
		func() (int, error) {
			return rotations.RewrapSystemSecretsBatch(ctx, rot.ID, from.ID(), to.ID(), opts.BatchSize, rewrapSecret)
		},
	}
	for i := 0; ; {
		n, err := sources[i]()
		if err != nil && ctx.Err() != nil {
			// Canceled (shutdown): never record a failure, even for a
			// re-wrap error, which may then come from keys being destroyed
			// by the shutdown. The rotation stays running and resumable.
			logger.WarnContext(ctx, "master key rotation interrupted: run rotate-master-key again to resume it",
				slog.String("rotation", rot.ID), slog.Int64("rewrapped", rot.RewrappedKeys))
			return fmt.Errorf("masterkey: rotation %s interrupted: %w", rot.ID, ctx.Err())
		}
		if rerr, ok := errors.AsType[*rewrapError](err); ok {
			return fail(ctx, rotations, rot, rerr, logger, opts.Now())
		}
		if err != nil {
			return fmt.Errorf("masterkey: rotate: %w", err)
		}
		rot.RewrappedKeys += int64(n)
		if n == 0 && i < len(sources)-1 {
			i++ // this source is drained: go on with the next one
			continue
		}
		if opts.OnProgress != nil {
			opts.OnProgress(*rot)
		}
		if n == 0 {
			return nil
		}
		logger.InfoContext(ctx, "master key rotation progress", slog.String("rotation", rot.ID),
			slog.Int64("rewrapped", rot.RewrappedKeys), slog.Int64("total", rot.TotalKeys))
	}
}

// rewrapBlob unwraps blob with from and wraps it with to, for purpose p and
// the binding tenantID and rowID, which do not change. row names the row
// in the error (a *rewrapError), which never includes key material.
func rewrapBlob(from, to *crypto.MasterKey, p crypto.Purpose, tenantID, rowID string, blob []byte, row string) ([]byte, error) {
	plaintext, err := from.Unwrap(p, tenantID, rowID, blob)
	var out []byte
	if err == nil {
		out, err = to.Wrap(p, tenantID, rowID, plaintext)
		clear(plaintext)
	}
	if err != nil {
		return nil, &rewrapError{row: row, from: from.ID(), err: err}
	}
	return out, nil
}

// complete tries to complete rot. It reports false, without error, while
// keys are still wrapped under the old key.
func complete(ctx context.Context, rotations *store.KeyRotations, rot *store.Rotation, now time.Time) (bool, error) {
	err := rotations.Complete(ctx, rot.ID, now)
	switch {
	case errors.Is(err, store.ErrRotationIncomplete):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("masterkey: rotate: %w", err)
	}
	rot.Status, rot.CompletedAt = store.RotationCompleted, now
	return true, nil
}

// rewrapError reports a wrapped key or a system secret that could not be
// re-wrapped. Its message names the row (with its tenant for a tenant key)
// and the master key, never key material.
type rewrapError struct {
	// row names the row, such as "wrapped key wk_... of tenant ten_..." or
	// "system secret ss_...".
	row  string
	from string
	err  error
}

func (e *rewrapError) Error() string {
	return fmt.Sprintf("%s cannot be unwrapped with master key %s (wrong key or corrupted row)", e.row, e.from)
}

func (e *rewrapError) Unwrap() []error { return []error{ErrRewrap, e.err} }

// fail marks rot failed after a re-wrap error and returns the error.
func fail(ctx context.Context, rotations *store.KeyRotations, rot *store.Rotation, rerr *rewrapError,
	logger *slog.Logger, now time.Time,
) error {
	err := fmt.Errorf("masterkey: rotation %s failed: %w", rot.ID, rerr)
	logger.ErrorContext(ctx, "master key rotation failed", slog.String("rotation", rot.ID),
		slog.String("error", rerr.Error()))
	if ferr := rotations.Fail(context.WithoutCancel(ctx), rot.ID, rerr.Error(), now); ferr != nil {
		return errors.Join(err, ferr)
	}
	rot.Status, rot.Error, rot.CompletedAt = store.RotationFailed, rerr.Error(), now
	return err
}

// Abandon marks the running rotation failed, so that another one can start
// (for example after the new key was lost before any key was wrapped under
// it, or after an interrupted clean-up rotation whose old key is gone). A
// clean-up rotation, towards the active key, can always be abandoned. A
// regular rotation is refused (ErrCannotAbandon) while keys are wrapped
// under its target: abandoning it would leave them needing a key the next
// rotation does not know. The check and the update are atomic
// (store.KeyRotations.Abandon). The operator must first remove
// TT_MASTER_KEY_NEW_FILE and restart every process, so that no process
// wraps new keys under the target meanwhile. It returns ErrNoRotation when
// no rotation is running.
func Abandon(ctx context.Context, db *store.DB, now time.Time) (store.Rotation, error) {
	rot, err := db.KeyRotations().Running(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return store.Rotation{}, ErrNoRotation
	}
	if err != nil {
		return store.Rotation{}, fmt.Errorf("masterkey: abandon: %w", err)
	}
	err = db.KeyRotations().Abandon(ctx, rot.ID, abandonMessage, now)
	switch {
	case errors.Is(err, store.ErrRotationInUse):
		return rot, fmt.Errorf("%w: %w; set %s to the file of key %s and run rotate-master-key to finish "+
			"rotation %s instead; see %s", ErrCannotAbandon, err, config.EnvMasterKeyNewFile, rot.ToKeyID, rot.ID, DocLink)
	case err != nil:
		return rot, fmt.Errorf("masterkey: abandon: %w", err)
	}
	rot.Status, rot.Error, rot.CompletedAt = store.RotationFailed, abandonMessage, now
	return rot, nil
}

// scrubWarn runs scrub after a rotation and logs any failure as a warning:
// the rotation itself succeeded.
func scrubWarn(ctx context.Context, scrub func(context.Context) error, logger *slog.Logger) {
	if err := scrubDeleted(ctx, scrub, logger); err != nil {
		logger.WarnContext(ctx, "could not scrub the old wrapped keys from the database files",
			slog.String("error", err.Error()))
	}
}
