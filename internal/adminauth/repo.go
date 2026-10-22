package adminauth

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
)

// repo is the part of the store the service uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation.
type repo interface {
	countAdmins(ctx context.Context) (int64, error)
	admin(ctx context.Context, adminID string) (store.Admin, error)
	adminByUsername(ctx context.Context, username string) (store.Admin, error)
	listAdmins(ctx context.Context, opts store.AdminListOptions) (store.Page[store.Admin], error)
	setPendingTOTP(ctx context.Context, adminID string, s store.SystemSecret) error
	systemSecret(ctx context.Context, secretID string) (store.SystemSecret, error)
	advanceTOTP(ctx context.Context, adminID string, counter int64) (bool, error)
	touchLogin(ctx context.Context, adminID string) error
	consumeRecovery(ctx context.Context, adminID string, hash []byte, now time.Time) (bool, error)

	session(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (store.AdminSession, error)
	touchSession(ctx context.Context, sessionID string, now time.Time, idle time.Duration) error
	rotateSession(ctx context.Context, sessionID string, oldHash, newHash []byte, state store.AdminSessionState,
		stateExpiresAt, now time.Time, idle time.Duration) error
	totpFailure(ctx context.Context, sessionID string) (int, error)
	deleteSession(ctx context.Context, sessionID string) error

	checkLogin(ctx context.Context, keys []store.AdminLoginKey, now time.Time) (time.Time, error)
	recordLogin(ctx context.Context, rules []store.AdminLoginRule, now time.Time) (store.FailureOutcome, error)
	refundLogin(ctx context.Context, rules []store.AdminLoginRule, at time.Time) error
	resetLogin(ctx context.Context, keys []store.AdminLoginKey) error

	audit(ctx context.Context, ev audit.Event) error
	tx(ctx context.Context, fn func(txRepo) error) error
}

// txRepo is the part of the store used inside a system transaction.
type txRepo interface {
	countAdmins(ctx context.Context) (int64, error)
	countUsableSuperAdmins(ctx context.Context) (int64, error)
	createAdmin(ctx context.Context, a store.Admin) (store.Admin, error)
	admin(ctx context.Context, adminID string) (store.Admin, error)
	updateAdmin(ctx context.Context, adminID string, u store.AdminUpdate) (before, after store.Admin, err error)
	deleteAdmin(ctx context.Context, adminID string) error
	setPassword(ctx context.Context, adminID, hash string) error
	setPendingTOTP(ctx context.Context, adminID string, s store.SystemSecret) error
	setTOTP(ctx context.Context, adminID, pendingSecretID string, counter int64) error
	clearTOTP(ctx context.Context, adminID string) error
	replaceRecovery(ctx context.Context, adminID string, hashes [][]byte) error
	createSession(ctx context.Context, s store.AdminSession) error
	rotateSession(ctx context.Context, sessionID string, oldHash, newHash []byte, state store.AdminSessionState,
		stateExpiresAt, now time.Time, idle time.Duration) error
	deleteSessions(ctx context.Context, adminID, exceptID string) (int64, error)
	createActivation(ctx context.Context, a store.AdminActivation) error
	consumeActivation(ctx context.Context, tokenHash []byte, now time.Time) (string, error)
	deleteActivations(ctx context.Context, adminID string) (int64, error)
	audit(ctx context.Context, ev audit.Event) error
}

// storeRepo implements repo over a *store.DB.
type storeRepo struct {
	db     *store.DB
	writer *audit.Writer
}

func (r storeRepo) countAdmins(ctx context.Context) (int64, error) {
	return r.db.Admins().CountAll(ctx)
}

func (r storeRepo) admin(ctx context.Context, adminID string) (store.Admin, error) {
	return r.db.Admins().Get(ctx, adminID)
}

func (r storeRepo) adminByUsername(ctx context.Context, username string) (store.Admin, error) {
	return r.db.Admins().GetByUsername(ctx, username)
}

func (r storeRepo) listAdmins(ctx context.Context, opts store.AdminListOptions) (store.Page[store.Admin], error) {
	return r.db.Admins().List(ctx, opts)
}

func (r storeRepo) setPendingTOTP(ctx context.Context, adminID string, s store.SystemSecret) error {
	return r.db.Admins().SetPendingTOTP(ctx, adminID, s)
}

func (r storeRepo) systemSecret(ctx context.Context, secretID string) (store.SystemSecret, error) {
	return r.db.SystemSecrets().Get(ctx, secretID)
}

func (r storeRepo) advanceTOTP(ctx context.Context, adminID string, counter int64) (bool, error) {
	return r.db.Admins().AdvanceTOTPCounter(ctx, adminID, counter)
}

func (r storeRepo) touchLogin(ctx context.Context, adminID string) error {
	return r.db.Admins().TouchLogin(ctx, adminID)
}

func (r storeRepo) consumeRecovery(ctx context.Context, adminID string, hash []byte, now time.Time) (bool, error) {
	return r.db.AdminRecoveryCodes().Consume(ctx, adminID, hash, now)
}

func (r storeRepo) session(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (store.AdminSession, error) {
	return r.db.AdminSessions().GetByTokenHash(ctx, hash, now, idle)
}

func (r storeRepo) touchSession(ctx context.Context, sessionID string, now time.Time, idle time.Duration) error {
	return r.db.AdminSessions().Touch(ctx, sessionID, now, idle)
}

func (r storeRepo) rotateSession(ctx context.Context, sessionID string, oldHash, newHash []byte,
	state store.AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	return r.db.AdminSessions().Rotate(ctx, sessionID, oldHash, newHash, state, stateExpiresAt, now, idle)
}

func (r storeRepo) totpFailure(ctx context.Context, sessionID string) (int, error) {
	return r.db.AdminSessions().IncrementTOTPFailures(ctx, sessionID)
}

func (r storeRepo) deleteSession(ctx context.Context, sessionID string) error {
	return r.db.AdminSessions().Delete(ctx, sessionID)
}

func (r storeRepo) checkLogin(ctx context.Context, keys []store.AdminLoginKey, now time.Time) (time.Time, error) {
	return r.db.AdminLoginFailures().Check(ctx, keys, now)
}

func (r storeRepo) recordLogin(ctx context.Context, rules []store.AdminLoginRule, now time.Time) (store.FailureOutcome, error) {
	return r.db.AdminLoginFailures().RecordFailure(ctx, rules, now)
}

func (r storeRepo) refundLogin(ctx context.Context, rules []store.AdminLoginRule, at time.Time) error {
	return r.db.AdminLoginFailures().Refund(ctx, rules, at)
}

func (r storeRepo) resetLogin(ctx context.Context, keys []store.AdminLoginKey) error {
	return r.db.AdminLoginFailures().Reset(ctx, keys)
}

func (r storeRepo) audit(ctx context.Context, ev audit.Event) error { return r.writer.Record(ctx, ev) }

func (r storeRepo) tx(ctx context.Context, fn func(txRepo) error) error {
	return r.db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
		return fn(storeTxRepo{db: r.db, tx: tx, writer: r.writer})
	})
}

// storeTxRepo implements txRepo over a *store.SystemTx.
type storeTxRepo struct {
	db     *store.DB
	tx     *store.SystemTx
	writer *audit.Writer
}

func (r storeTxRepo) countAdmins(ctx context.Context) (int64, error) {
	return r.db.Admins().CountAllTx(ctx, r.tx)
}

func (r storeTxRepo) countUsableSuperAdmins(ctx context.Context) (int64, error) {
	return r.db.Admins().CountUsableSuperAdminsTx(ctx, r.tx)
}

func (r storeTxRepo) createAdmin(ctx context.Context, a store.Admin) (store.Admin, error) {
	return r.db.Admins().CreateTx(ctx, r.tx, a)
}

func (r storeTxRepo) admin(ctx context.Context, adminID string) (store.Admin, error) {
	return r.db.Admins().GetTx(ctx, r.tx, adminID)
}

func (r storeTxRepo) updateAdmin(ctx context.Context, adminID string, u store.AdminUpdate) (store.Admin, store.Admin, error) {
	return r.db.Admins().UpdateTx(ctx, r.tx, adminID, u)
}

func (r storeTxRepo) deleteAdmin(ctx context.Context, adminID string) error {
	return r.db.Admins().DeleteTx(ctx, r.tx, adminID)
}

func (r storeTxRepo) setPassword(ctx context.Context, adminID, hash string) error {
	return r.db.Admins().SetPasswordTx(ctx, r.tx, adminID, hash)
}

func (r storeTxRepo) setPendingTOTP(ctx context.Context, adminID string, s store.SystemSecret) error {
	return r.db.Admins().SetPendingTOTPTx(ctx, r.tx, adminID, s)
}

func (r storeTxRepo) setTOTP(ctx context.Context, adminID, pendingSecretID string, counter int64) error {
	return r.db.Admins().SetTOTPTx(ctx, r.tx, adminID, pendingSecretID, counter)
}

func (r storeTxRepo) clearTOTP(ctx context.Context, adminID string) error {
	return r.db.Admins().ClearTOTPTx(ctx, r.tx, adminID)
}

func (r storeTxRepo) replaceRecovery(ctx context.Context, adminID string, hashes [][]byte) error {
	return r.db.AdminRecoveryCodes().ReplaceTx(ctx, r.tx, adminID, hashes)
}

func (r storeTxRepo) createSession(ctx context.Context, s store.AdminSession) error {
	return r.db.AdminSessions().CreateTx(ctx, r.tx, s)
}

func (r storeTxRepo) rotateSession(ctx context.Context, sessionID string, oldHash, newHash []byte,
	state store.AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	return r.db.AdminSessions().RotateTx(ctx, r.tx, sessionID, oldHash, newHash, state, stateExpiresAt, now, idle)
}

func (r storeTxRepo) deleteSessions(ctx context.Context, adminID, exceptID string) (int64, error) {
	return r.db.AdminSessions().DeleteByAdminTx(ctx, r.tx, adminID, exceptID)
}

func (r storeTxRepo) createActivation(ctx context.Context, a store.AdminActivation) error {
	return r.db.AdminActivations().CreateTx(ctx, r.tx, a)
}

func (r storeTxRepo) consumeActivation(ctx context.Context, tokenHash []byte, now time.Time) (string, error) {
	return r.db.AdminActivations().ConsumeTx(ctx, r.tx, tokenHash, now)
}

func (r storeTxRepo) deleteActivations(ctx context.Context, adminID string) (int64, error) {
	return r.db.AdminActivations().DeleteByAdminTx(ctx, r.tx, adminID)
}

func (r storeTxRepo) audit(ctx context.Context, ev audit.Event) error {
	return r.writer.RecordTx(ctx, r.tx, ev)
}
