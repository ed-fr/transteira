package adminauth

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
)

// faultRepo wraps a repo and fails the operations named in fails (the
// transaction operations are named "tx.<name>"). countZero makes
// countAdmins report no administrator, checkZero makes checkLogin report no
// lock, to reach the branches of concurrent requests.
type faultRepo struct {
	repo      repo
	fails     map[string]error
	countZero bool
	checkZero bool
}

func (f faultRepo) fail(op string) error { return f.fails[op] }

func (f faultRepo) countAdmins(ctx context.Context) (int64, error) {
	if err := f.fail("countAdmins"); err != nil {
		return 0, err
	}
	if f.countZero {
		return 0, nil
	}
	return f.repo.countAdmins(ctx)
}

func (f faultRepo) admin(ctx context.Context, adminID string) (store.Admin, error) {
	if err := f.fail("admin"); err != nil {
		return store.Admin{}, err
	}
	return f.repo.admin(ctx, adminID)
}

func (f faultRepo) adminByUsername(ctx context.Context, username string) (store.Admin, error) {
	if err := f.fail("adminByUsername"); err != nil {
		return store.Admin{}, err
	}
	return f.repo.adminByUsername(ctx, username)
}

func (f faultRepo) listAdmins(ctx context.Context, opts store.AdminListOptions) (store.Page[store.Admin], error) {
	if err := f.fail("listAdmins"); err != nil {
		return store.Page[store.Admin]{}, err
	}
	return f.repo.listAdmins(ctx, opts)
}

func (f faultRepo) setPendingTOTP(ctx context.Context, adminID string, s store.SystemSecret) error {
	if err := f.fail("setPendingTOTP"); err != nil {
		return err
	}
	return f.repo.setPendingTOTP(ctx, adminID, s)
}

func (f faultRepo) systemSecret(ctx context.Context, secretID string) (store.SystemSecret, error) {
	if err := f.fail("systemSecret"); err != nil {
		return store.SystemSecret{}, err
	}
	return f.repo.systemSecret(ctx, secretID)
}

func (f faultRepo) advanceTOTP(ctx context.Context, adminID string, counter int64) (bool, error) {
	if err := f.fail("advanceTOTP"); err != nil {
		return false, err
	}
	return f.repo.advanceTOTP(ctx, adminID, counter)
}

func (f faultRepo) touchLogin(ctx context.Context, adminID string) error {
	if err := f.fail("touchLogin"); err != nil {
		return err
	}
	return f.repo.touchLogin(ctx, adminID)
}

func (f faultRepo) consumeRecovery(ctx context.Context, adminID string, hash []byte, now time.Time) (bool, error) {
	if err := f.fail("consumeRecovery"); err != nil {
		return false, err
	}
	return f.repo.consumeRecovery(ctx, adminID, hash, now)
}

func (f faultRepo) session(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (store.AdminSession, error) {
	if err := f.fail("session"); err != nil {
		return store.AdminSession{}, err
	}
	return f.repo.session(ctx, hash, now, idle)
}

func (f faultRepo) touchSession(ctx context.Context, sessionID string, now time.Time, idle time.Duration) error {
	if err := f.fail("touchSession"); err != nil {
		return err
	}
	return f.repo.touchSession(ctx, sessionID, now, idle)
}

func (f faultRepo) rotateSession(ctx context.Context, sessionID string, oldHash, newHash []byte,
	state store.AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	if err := f.fail("rotateSession"); err != nil {
		return err
	}
	return f.repo.rotateSession(ctx, sessionID, oldHash, newHash, state, stateExpiresAt, now, idle)
}

func (f faultRepo) totpFailure(ctx context.Context, sessionID string) (int, error) {
	if err := f.fail("totpFailure"); err != nil {
		return 0, err
	}
	return f.repo.totpFailure(ctx, sessionID)
}

func (f faultRepo) deleteSession(ctx context.Context, sessionID string) error {
	if err := f.fail("deleteSession"); err != nil {
		return err
	}
	return f.repo.deleteSession(ctx, sessionID)
}

func (f faultRepo) checkLogin(ctx context.Context, keys []store.AdminLoginKey, now time.Time) (time.Time, error) {
	if err := f.fail("checkLogin"); err != nil {
		return time.Time{}, err
	}
	if f.checkZero {
		return time.Time{}, nil
	}
	return f.repo.checkLogin(ctx, keys, now)
}

func (f faultRepo) recordLogin(ctx context.Context, rules []store.AdminLoginRule, now time.Time) (store.FailureOutcome, error) {
	if err := f.fail("recordLogin"); err != nil {
		return store.FailureOutcome{}, err
	}
	return f.repo.recordLogin(ctx, rules, now)
}

func (f faultRepo) refundLogin(ctx context.Context, rules []store.AdminLoginRule, at time.Time) error {
	if err := f.fail("refundLogin"); err != nil {
		return err
	}
	return f.repo.refundLogin(ctx, rules, at)
}

func (f faultRepo) resetLogin(ctx context.Context, keys []store.AdminLoginKey) error {
	if err := f.fail("resetLogin"); err != nil {
		return err
	}
	return f.repo.resetLogin(ctx, keys)
}

func (f faultRepo) audit(ctx context.Context, ev audit.Event) error {
	if err := f.fail("audit"); err != nil {
		return err
	}
	return f.repo.audit(ctx, ev)
}

func (f faultRepo) tx(ctx context.Context, fn func(txRepo) error) error {
	return f.repo.tx(ctx, func(tx txRepo) error { return fn(faultTx{tx: tx, fails: f.fails}) })
}

// faultTx wraps a txRepo and fails the operations named "tx.<name>".
type faultTx struct {
	tx    txRepo
	fails map[string]error
}

func (f faultTx) fail(op string) error { return f.fails["tx."+op] }

func (f faultTx) countAdmins(ctx context.Context) (int64, error) {
	if err := f.fail("countAdmins"); err != nil {
		return 0, err
	}
	return f.tx.countAdmins(ctx)
}

func (f faultTx) countUsableSuperAdmins(ctx context.Context) (int64, error) {
	if err := f.fail("countUsableSuperAdmins"); err != nil {
		return 0, err
	}
	return f.tx.countUsableSuperAdmins(ctx)
}

func (f faultTx) createAdmin(ctx context.Context, a store.Admin) (store.Admin, error) {
	if err := f.fail("createAdmin"); err != nil {
		return store.Admin{}, err
	}
	return f.tx.createAdmin(ctx, a)
}

func (f faultTx) admin(ctx context.Context, adminID string) (store.Admin, error) {
	if err := f.fail("admin"); err != nil {
		return store.Admin{}, err
	}
	return f.tx.admin(ctx, adminID)
}

func (f faultTx) updateAdmin(ctx context.Context, adminID string, u store.AdminUpdate) (store.Admin, store.Admin, error) {
	if err := f.fail("updateAdmin"); err != nil {
		return store.Admin{}, store.Admin{}, err
	}
	return f.tx.updateAdmin(ctx, adminID, u)
}

func (f faultTx) deleteAdmin(ctx context.Context, adminID string) error {
	if err := f.fail("deleteAdmin"); err != nil {
		return err
	}
	return f.tx.deleteAdmin(ctx, adminID)
}

func (f faultTx) setPassword(ctx context.Context, adminID, hash string) error {
	if err := f.fail("setPassword"); err != nil {
		return err
	}
	return f.tx.setPassword(ctx, adminID, hash)
}

func (f faultTx) setPendingTOTP(ctx context.Context, adminID string, s store.SystemSecret) error {
	if err := f.fail("setPendingTOTP"); err != nil {
		return err
	}
	return f.tx.setPendingTOTP(ctx, adminID, s)
}

func (f faultTx) setTOTP(ctx context.Context, adminID, pendingSecretID string, counter int64) error {
	if err := f.fail("setTOTP"); err != nil {
		return err
	}
	return f.tx.setTOTP(ctx, adminID, pendingSecretID, counter)
}

func (f faultTx) clearTOTP(ctx context.Context, adminID string) error {
	if err := f.fail("clearTOTP"); err != nil {
		return err
	}
	return f.tx.clearTOTP(ctx, adminID)
}

func (f faultTx) replaceRecovery(ctx context.Context, adminID string, hashes [][]byte) error {
	if err := f.fail("replaceRecovery"); err != nil {
		return err
	}
	return f.tx.replaceRecovery(ctx, adminID, hashes)
}

func (f faultTx) createSession(ctx context.Context, s store.AdminSession) error {
	if err := f.fail("createSession"); err != nil {
		return err
	}
	return f.tx.createSession(ctx, s)
}

func (f faultTx) rotateSession(ctx context.Context, sessionID string, oldHash, newHash []byte,
	state store.AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	if err := f.fail("rotateSession"); err != nil {
		return err
	}
	return f.tx.rotateSession(ctx, sessionID, oldHash, newHash, state, stateExpiresAt, now, idle)
}

func (f faultTx) deleteSessions(ctx context.Context, adminID, exceptID string) (int64, error) {
	if err := f.fail("deleteSessions"); err != nil {
		return 0, err
	}
	return f.tx.deleteSessions(ctx, adminID, exceptID)
}

func (f faultTx) createActivation(ctx context.Context, a store.AdminActivation) error {
	if err := f.fail("createActivation"); err != nil {
		return err
	}
	return f.tx.createActivation(ctx, a)
}

func (f faultTx) consumeActivation(ctx context.Context, tokenHash []byte, now time.Time) (string, error) {
	if err := f.fail("consumeActivation"); err != nil {
		return "", err
	}
	return f.tx.consumeActivation(ctx, tokenHash, now)
}

func (f faultTx) deleteActivations(ctx context.Context, adminID string) (int64, error) {
	if err := f.fail("deleteActivations"); err != nil {
		return 0, err
	}
	return f.tx.deleteActivations(ctx, adminID)
}

func (f faultTx) audit(ctx context.Context, ev audit.Event) error {
	if err := f.fail("audit"); err != nil {
		return err
	}
	return f.tx.audit(ctx, ev)
}

// faultKeys wraps the MAC keys and fails when err is set.
type faultKeys struct {
	Keys
	err error
}

func (k *faultKeys) MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	return k.Keys.MAC(p, parts...)
}

func (k *faultKeys) VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error) {
	if k.err != nil {
		return false, k.err
	}
	return k.Keys.VerifyMAC(p, mac, parts...)
}

// withFaults replaces the repo of the service by a faultRepo failing ops
// with errFault, and returns the function restoring it.
func (ev *env) withFaults(ops ...string) func() {
	return ev.withRepo(func(r repo) faultRepo {
		f := faultRepo{repo: r, fails: map[string]error{}}
		for _, op := range ops {
			f.fails[op] = errFault
		}
		return f
	})
}

// withRepo replaces the repo of the service by build(real repo).
func (ev *env) withRepo(build func(repo) faultRepo) func() {
	real := ev.svc.repo
	ev.svc.repo = build(real)
	return func() { ev.svc.repo = real }
}

// withKeys replaces the MAC keys by failing ones and returns the restore
// function.
func (ev *env) withKeys() func() {
	real := ev.svc.keys
	ev.svc.keys = &faultKeys{Keys: real, err: errFault}
	return func() { ev.svc.keys = real }
}
