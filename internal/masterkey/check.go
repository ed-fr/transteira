package masterkey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
)

// ErrKeyCheck is matched by every refusal of Check (see CheckError).
var ErrKeyCheck = errors.New("masterkey: master key check failed")

// CheckReason tells why Check refused the configured keys.
type CheckReason string

// Reasons of a CheckError.
const (
	// ReasonMissingKey: rows of wrapped_keys or system_secrets use master
	// keys that are not provided (wrong key file, restored backup,
	// TT_MASTER_KEY_NEW_FILE removed before the rotation completed, keys
	// wrapped late under a retired key), or, on a database where no master key is registered
	// yet, rows wrapped under another key than the current one.
	ReasonMissingKey CheckReason = "missing_key"
	// ReasonActiveKeyMissing: the active master key recorded in the database
	// is neither the current nor the new key.
	ReasonActiveKeyMissing CheckReason = "active_key_missing"
	// ReasonRotationCompleted: a rotation to another key is completed but
	// TT_MASTER_KEY_FILE still holds the old key.
	ReasonRotationCompleted CheckReason = "rotation_completed"
	// ReasonRetiredKey: TT_MASTER_KEY_FILE or TT_MASTER_KEY_NEW_FILE holds a
	// key recorded as retired, which must never wrap anything again.
	ReasonRetiredKey CheckReason = "retired_key"
	// ReasonRotationMismatch: a rotation is running towards another key
	// than TT_MASTER_KEY_NEW_FILE, or TT_MASTER_KEY_NEW_FILE was removed
	// while keys are already wrapped under the target of the running
	// rotation.
	ReasonRotationMismatch CheckReason = "rotation_mismatch"
)

// CheckError is the refusal of Check. It matches ErrKeyCheck and names only
// master key IDs.
type CheckError struct {
	// Reason tells which rule refused the keys.
	Reason CheckReason
	// KeyIDs lists the master key IDs concerned: the keys needed but not
	// provided (ReasonMissingKey, ReasonActiveKeyMissing), the key the
	// rotation completed to (ReasonRotationCompleted), the retired current
	// or new key (ReasonRetiredKey), or the target of the running rotation
	// followed by the configured new key, if any (ReasonRotationMismatch).
	KeyIDs []string
	// msg is the operator message.
	msg string
}

// Error returns the operator message, which points to the documentation.
func (e *CheckError) Error() string {
	return "masterkey: " + e.msg + "; see " + DocLink
}

// Unwrap returns ErrKeyCheck.
func (e *CheckError) Unwrap() error { return ErrKeyCheck }

// Report summarizes a successful Check.
type Report struct {
	// ActiveID is the active master key recorded in the database.
	ActiveID string
	// CurrentID is the current key (TT_MASTER_KEY_FILE).
	CurrentID string
	// NewID is the new key (TT_MASTER_KEY_NEW_FILE), or "".
	NewID string
	// Registered is true when the current key was just recorded as active
	// (first start on an empty database).
	Registered bool
	// Running is the rotation in progress, or nil.
	Running *store.Rotation
}

// Check verifies the keyring against the database at startup (threat model
// T-36) and refuses, with a *CheckError, keys that would leave data
// unreadable or create data under the wrong key. In order:
//
//   - when no master key is registered, the current key is recorded as
//     active, unless rows are wrapped under other keys (ReasonMissingKey);
//   - the latest rotation completed to a key that is not the current one
//     (ReasonRotationCompleted);
//   - a current key recorded as retired (ReasonRetiredKey);
//   - a running rotation that does not match TT_MASTER_KEY_NEW_FILE
//     (ReasonRotationMismatch);
//   - a new key recorded as retired (ReasonRetiredKey);
//   - a master key used by a row of wrapped_keys or system_secrets (the
//     store's KeyIDsInUse covers both) missing from the keyring
//     (ReasonMissingKey; for a retired key the message points to
//     "rotate-master-key -recover-from");
//   - an active master key that is neither the current nor the new key
//     (ReasonActiveKeyMissing).
//
// When the new key is configured, Check logs whether a rotation is running
// or still has to be started. A nil logger discards these messages.
func Check(ctx context.Context, db *store.DB, kr *Keyring, logger *slog.Logger, now time.Time) (Report, error) {
	logger = orDiscard(logger)
	rep := Report{CurrentID: kr.CurrentID(), NewID: kr.NewID()}
	inUse, err := db.WrappedKeys().KeyIDsInUse(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("masterkey: check: %w", err)
	}
	records, err := db.MasterKeys().List(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("masterkey: check: %w", err)
	}
	registered, err := db.MasterKeys().EnsureActive(ctx, kr.CurrentID(), now)
	switch {
	case errors.Is(err, store.ErrUnregisteredKeys):
		others := slices.DeleteFunc(slices.Clone(inUse), func(s string) bool { return s == kr.CurrentID() })
		return Report{}, &CheckError{
			Reason: ReasonMissingKey, KeyIDs: others,
			msg: fmt.Sprintf("no master key is registered yet, but wrapped keys or system secrets in the database "+
				"use master key(s) %s "+
				"(%s): start with the key that wrapped them, from the vault", strings.Join(others, ", "), kr.describe()),
		}
	case err != nil:
		return Report{}, fmt.Errorf("masterkey: check: %w", err)
	case registered:
		records = append(records, store.MasterKeyRecord{ID: kr.CurrentID(), Status: store.MasterKeyActive})
	}
	rep.Registered = registered
	status := make(map[string]store.MasterKeyStatus, len(records))
	for _, r := range records {
		status[r.ID] = r.Status
		if r.Status == store.MasterKeyActive {
			rep.ActiveID = r.ID
		}
	}

	latest, err := db.KeyRotations().Latest(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return Report{}, fmt.Errorf("masterkey: check: %w", err)
	case latest.Status == store.RotationCompleted && latest.ToKeyID != kr.CurrentID():
		return Report{}, &CheckError{
			Reason: ReasonRotationCompleted, KeyIDs: []string{latest.ToKeyID},
			msg: fmt.Sprintf("the master key rotation %s from %s to %s is completed, but %s holds %s: "+
				"set %s to the file of key %s, remove %s and restart",
				latest.ID, latest.FromKeyID, latest.ToKeyID, config.EnvMasterKeyFile, kr.CurrentID(),
				config.EnvMasterKeyFile, latest.ToKeyID, config.EnvMasterKeyNewFile),
		}
	case latest.Status == store.RotationRunning:
		// Only one rotation runs at a time and none starts meanwhile, so a
		// running rotation is always the latest one.
		rep.Running = &latest
	}
	if status[kr.CurrentID()] == store.MasterKeyRetired {
		return Report{}, &CheckError{
			Reason: ReasonRetiredKey, KeyIDs: []string{kr.CurrentID()},
			msg: fmt.Sprintf("%s holds master key %s, which is recorded as retired: a retired key never wraps "+
				"anything again; set %s to the active key %s", config.EnvMasterKeyFile, kr.CurrentID(),
				config.EnvMasterKeyFile, rep.ActiveID),
		}
	}
	if err := checkRunning(rep.Running, kr, inUse); err != nil {
		return Report{}, err
	}

	if kr.NewID() != "" && status[kr.NewID()] == store.MasterKeyRetired {
		return Report{}, &CheckError{
			Reason: ReasonRetiredKey, KeyIDs: []string{kr.NewID()},
			msg: fmt.Sprintf("%s holds master key %s, which is recorded as retired: a retired key never wraps "+
				"anything again; generate a new key for the rotation", config.EnvMasterKeyNewFile, kr.NewID()),
		}
	}

	if err := checkMissing(inUse, status, kr); err != nil {
		return Report{}, err
	}

	if rep.ActiveID == "" {
		return Report{}, errors.New("masterkey: check: master keys are registered but none is active")
	}
	if !kr.has(rep.ActiveID) {
		return Report{}, &CheckError{
			Reason: ReasonActiveKeyMissing, KeyIDs: []string{rep.ActiveID},
			msg: fmt.Sprintf("the active master key recorded in the database is %s, which is not provided (%s): "+
				"provide the key with this ID from the vault", rep.ActiveID, kr.describe()),
		}
	}

	if kr.NewID() != "" {
		if rep.Running != nil {
			logger.InfoContext(ctx, "a master key rotation is in progress: run rotate-master-key to resume it",
				slog.String("rotation", rep.Running.ID), slog.String("from", rep.Running.FromKeyID),
				slog.String("to", rep.Running.ToKeyID))
		} else {
			logger.InfoContext(ctx, "new master key configured: new keys are wrapped with it; "+
				"run rotate-master-key to re-wrap the existing ones",
				slog.String("current", kr.CurrentID()), slog.String("new", kr.NewID()))
		}
	}
	return rep, nil
}

// checkRunning refuses a running rotation that does not match the keyring:
// a new key other than its target, or no new key while keys are already
// wrapped under the target of a regular rotation (from the current key).
// A clean-up rotation from a retired key to the current key needs no new
// key.
func checkRunning(running *store.Rotation, kr *Keyring, inUse []string) error {
	switch {
	case running == nil:
		return nil
	case kr.NewID() != "" && running.ToKeyID != kr.NewID():
		return &CheckError{
			Reason: ReasonRotationMismatch, KeyIDs: []string{running.ToKeyID, kr.NewID()},
			msg: fmt.Sprintf("the master key rotation %s from %s to %s is running, but %s holds %s: "+
				"set %s to the file of key %s and run rotate-master-key to finish it; or give it up with "+
				"rotate-master-key -abandon, which is allowed for a clean-up rotation towards the active key or "+
				"while no key is wrapped under %s, after removing %s and restarting every process",
				running.ID, running.FromKeyID, running.ToKeyID, config.EnvMasterKeyNewFile, kr.NewID(),
				config.EnvMasterKeyNewFile, running.ToKeyID, running.ToKeyID, config.EnvMasterKeyNewFile),
		}
	case kr.NewID() == "" && running.FromKeyID == kr.CurrentID() && slices.Contains(inUse, running.ToKeyID):
		return &CheckError{
			Reason: ReasonRotationMismatch, KeyIDs: []string{running.ToKeyID},
			msg: fmt.Sprintf("the master key rotation %s from %s to %s is running and keys are already wrapped "+
				"under %s, but %s is not set: set it to the file of key %s and run rotate-master-key to finish it",
				running.ID, running.FromKeyID, running.ToKeyID, running.ToKeyID, config.EnvMasterKeyNewFile,
				running.ToKeyID),
		}
	}
	return nil
}

// checkMissing refuses master keys used by wrapped keys but absent from the
// keyring. Retired ones point to the recovery command.
func checkMissing(inUse []string, status map[string]store.MasterKeyStatus, kr *Keyring) error {
	var missing, retired []string
	for _, keyID := range inUse {
		if kr.has(keyID) {
			continue
		}
		missing = append(missing, keyID)
		if status[keyID] == store.MasterKeyRetired {
			retired = append(retired, keyID)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	advice := fmt.Sprintf("provide the key(s) with this ID from the vault; if a rotation is unfinished, set %s "+
		"again and run rotate-master-key", config.EnvMasterKeyNewFile)
	if len(retired) == len(missing) {
		advice = fmt.Sprintf("these keys are retired: keys were wrapped under them after the rotation; run "+
			"rotate-master-key -recover-from <file of key %s> with the old key from the vault to re-wrap them "+
			"under the active key", strings.Join(retired, ", "))
	}
	return &CheckError{
		Reason: ReasonMissingKey, KeyIDs: missing,
		msg: fmt.Sprintf("wrapped keys or system secrets in the database use master key(s) %s, "+
			"which are not provided (%s): %s",
			strings.Join(missing, ", "), kr.describe(), advice),
	}
}
