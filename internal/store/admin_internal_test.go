package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// adminTestPHC is a syntactically valid password hash.
const adminTestPHC = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA"

// adminTestNow is the time of the administration fixtures.
var adminTestNow = time.Unix(1_700_000_000, 0).UTC()

// adminFixture is a fault-injecting database holding two tenants, a super
// admin with TOTP enrolled, a pending enrollment and recovery codes, a
// second super admin, a delegated admin with an activation link, an admin
// session, audit events, a login failure counter and a running master key
// rotation over the system secrets.
type adminFixture struct {
	db           *DB
	plan         *faultPlan
	tid, tid2    tenant.ID
	super, other Admin
	del          Admin
	pending      string
	session      AdminSession
	loginRules   []AdminLoginRule
	rot          string
}

// newTestSecret returns a TOTP system secret under testMK1.
func newTestSecret() SystemSecret {
	return SystemSecret{ID: id.New(id.SystemSecret), Purpose: SecretPurposeAdminTOTP, KeyID: testMK1, Blob: []byte("s")}
}

// newAdminFixture builds an adminFixture.
func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	ctx := context.Background()
	db, plan := openFault(t, WithClock(func() time.Time { return adminTestNow }))
	f := &adminFixture{db: db, plan: plan}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, fqdn := range []string{"a.example.com", "b.example.com"} {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "T", FQDN: fqdn, DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		must(err)
		if i == 0 {
			f.tid = tn.ID
		} else {
			f.tid2 = tn.ID
		}
	}
	var err error
	f.super, err = db.Admins().Create(ctx, Admin{Username: "root", Email: "root@example.com", Role: RoleSuperAdmin, PasswordHash: adminTestPHC})
	must(err)
	// other is a second usable super admin (password and TOTP), so that the
	// last super admin guard runs and passes for either of them.
	f.other, err = db.Admins().Create(ctx, Admin{Username: "other", Email: "other@example.com", Role: RoleSuperAdmin, PasswordHash: adminTestPHC})
	must(err)
	otherTOTP := newTestSecret()
	must(db.Admins().SetPendingTOTP(ctx, f.other.ID, otherTOTP))
	must(db.Admins().SetTOTP(ctx, f.other.ID, otherTOTP.ID, 1))
	f.del, err = db.Admins().Create(ctx, Admin{Username: "delegated", Email: "d@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{f.tid}})
	must(err)
	active := newTestSecret()
	must(db.Admins().SetPendingTOTP(ctx, f.super.ID, active))
	must(db.Admins().SetTOTP(ctx, f.super.ID, active.ID, 1))
	pending := newTestSecret()
	f.pending = pending.ID
	must(db.Admins().SetPendingTOTP(ctx, f.super.ID, pending))
	must(db.AdminRecoveryCodes().Replace(ctx, f.super.ID, [][]byte{hashOf("rc1"), hashOf("rc2")}))
	f.session = AdminSession{
		ID: id.New(id.AdminSession), TokenHash: hashOf("sess"), AdminID: f.super.ID, State: SessionAuthenticated,
		CreatedAt: adminTestNow, ExpiresAt: adminTestNow.Add(time.Hour),
	}
	must(db.AdminSessions().Create(ctx, f.session))
	must(db.AdminActivations().Create(ctx, AdminActivation{
		ID: id.New(id.AdminActivation), AdminID: f.del.ID, TokenHash: hashOf("act"),
		CreatedAt: adminTestNow, ExpiresAt: adminTestNow.Add(time.Hour),
	}))
	_, err = db.AuditEvents().Append(ctx, AuditEvent{TenantID: f.tid, ActorKind: ActorAdmin, Actor: "root", Action: "admin.login", ObjectKind: "admin", ObjectID: f.super.ID})
	must(err)
	_, err = db.AuditEvents().Append(ctx, AuditEvent{ActorKind: ActorSystem, Actor: "transteira", Action: "setup.completed", ObjectKind: "admin", ObjectID: f.super.ID})
	must(err)
	f.loginRules = []AdminLoginRule{{Key: AdminLoginIPKey(netip.MustParseAddr("192.0.2.1")), MaxFailures: 5, Window: time.Hour, LockDuration: time.Hour}}
	_, err = db.AdminLoginFailures().RecordFailure(ctx, f.loginRules, adminTestNow)
	must(err)
	_, err = db.MasterKeys().EnsureActive(ctx, testMK1, adminTestNow)
	must(err)
	f.rot = id.New(id.Rotation)
	must(db.KeyRotations().Start(ctx, Rotation{ID: f.rot, FromKeyID: testMK1, ToKeyID: testMK2, TotalKeys: 2}))
	return f
}

// TestAdminDriverFaults injects a driver failure into each statement of the
// administration repositories and checks that it surfaces as an error.
func TestAdminDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := adminTestNow
	type step struct {
		name, op, match string
		after           int
		run             func(*adminFixture) error
	}
	tx := func(f *adminFixture, fn func(*SystemTx) error) error { return f.db.Admins().Tx(ctx, fn) }
	createDelegated := func(f *adminFixture) error {
		_, err := f.db.Admins().Create(ctx, Admin{Username: "new", Email: "n@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{f.tid}})
		return err
	}
	getSuper := func(f *adminFixture) error { _, err := f.db.Admins().Get(ctx, f.super.ID); return err }
	getDel := func(f *adminFixture) error { _, err := f.db.Admins().Get(ctx, f.del.ID); return err }
	list := func(f *adminFixture) error { _, err := f.db.Admins().List(ctx, AdminListOptions{}); return err }
	disableOther := func(f *adminFixture) error {
		_, err := f.db.Admins().Update(ctx, f.other.ID, AdminUpdate{Disabled: new(true)})
		return err
	}
	moveDel := func(f *adminFixture) error {
		_, err := f.db.Admins().Update(ctx, f.del.ID, AdminUpdate{TenantIDs: &[]tenant.ID{f.tid2}})
		return err
	}
	setPassword := func(f *adminFixture) error { return f.db.Admins().SetPassword(ctx, f.del.ID, adminTestPHC) }
	setPending := func(f *adminFixture) error { return f.db.Admins().SetPendingTOTP(ctx, f.super.ID, newTestSecret()) }
	setTOTP := func(f *adminFixture) error { return f.db.Admins().SetTOTP(ctx, f.super.ID, f.pending, 5) }
	clearTOTP := func(f *adminFixture) error {
		return tx(f, func(tx *SystemTx) error { return f.db.Admins().ClearTOTPTx(ctx, tx, f.super.ID) })
	}
	advance := func(f *adminFixture) error {
		ok, err := f.db.Admins().AdvanceTOTPCounter(ctx, f.super.ID, 10)
		if err == nil && !ok {
			err = errors.New("counter refused")
		}
		return err
	}
	touch := func(f *adminFixture) error { return f.db.Admins().TouchLogin(ctx, f.super.ID) }
	deleteOther := func(f *adminFixture) error { return f.db.Admins().Delete(ctx, f.other.ID) }
	deleteSuper := func(f *adminFixture) error { return f.db.Admins().Delete(ctx, f.super.ID) }
	countAllTx := func(f *adminFixture) error {
		return tx(f, func(tx *SystemTx) error { _, err := f.db.Admins().CountAllTx(ctx, tx); return err })
	}
	countAll := func(f *adminFixture) error { _, err := f.db.Admins().CountAll(ctx); return err }
	countUsable := func(f *adminFixture) error {
		return tx(f, func(tx *SystemTx) error { _, err := f.db.Admins().CountUsableSuperAdminsTx(ctx, tx); return err })
	}
	tenantIDs := func(f *adminFixture) error { _, err := f.db.Admins().TenantIDs(ctx, f.del.ID); return err }

	loginKeys := func(f *adminFixture) []AdminLoginKey { return []AdminLoginKey{f.loginRules[0].Key} }
	check := func(f *adminFixture) error {
		_, err := f.db.AdminLoginFailures().Check(ctx, loginKeys(f), now)
		return err
	}
	recordExisting := func(f *adminFixture) error {
		_, err := f.db.AdminLoginFailures().RecordFailure(ctx, f.loginRules, now.Add(time.Second))
		return err
	}
	recordNew := func(f *adminFixture) error {
		r := f.loginRules[0]
		r.Key = AdminLoginIPKey(netip.MustParseAddr("192.0.2.99"))
		_, err := f.db.AdminLoginFailures().RecordFailure(ctx, []AdminLoginRule{r}, now)
		return err
	}
	refund := func(f *adminFixture) error { return f.db.AdminLoginFailures().Refund(ctx, f.loginRules, now) }
	reset := func(f *adminFixture) error { return f.db.AdminLoginFailures().Reset(ctx, loginKeys(f)) }
	purgeLogin := func(f *adminFixture) error {
		_, err := f.db.AdminLoginFailures().Purge(ctx, now.Add(2*time.Hour), time.Hour)
		return err
	}

	touchSession := func(f *adminFixture) error { return f.db.AdminSessions().Touch(ctx, f.session.ID, now, time.Hour) }
	rotate := func(f *adminFixture) error {
		return f.db.AdminSessions().Rotate(ctx, f.session.ID, hashOf("sess"), hashOf("sess2"), SessionAuthenticated, time.Time{}, now, time.Hour)
	}
	rotateTx := func(f *adminFixture) error {
		return tx(f, func(tx *SystemTx) error {
			return f.db.AdminSessions().RotateTx(ctx, tx, f.session.ID, hashOf("sess"), hashOf("sess3"), SessionAuthenticated, time.Time{}, now, time.Hour)
		})
	}
	deleteSession := func(f *adminFixture) error { return f.db.AdminSessions().Delete(ctx, f.session.ID) }
	revoke := func(f *adminFixture) error {
		_, err := f.db.AdminSessions().DeleteByAdmin(ctx, f.super.ID, "")
		return err
	}
	revokeTx := func(f *adminFixture) error {
		return tx(f, func(tx *SystemTx) error {
			_, err := f.db.AdminSessions().DeleteByAdminTx(ctx, tx, f.super.ID, "")
			return err
		})
	}
	purgeSessions := func(f *adminFixture) error {
		_, err := f.db.AdminSessions().Purge(ctx, now.Add(2*time.Hour), time.Hour)
		return err
	}
	replaceCodes := func(f *adminFixture) error {
		return f.db.AdminRecoveryCodes().Replace(ctx, f.super.ID, [][]byte{hashOf("rc3")})
	}
	consumeCode := func(f *adminFixture) error {
		ok, err := f.db.AdminRecoveryCodes().Consume(ctx, f.super.ID, hashOf("rc1"), now)
		if err == nil && !ok {
			err = errors.New("code refused")
		}
		return err
	}
	countCodes := func(f *adminFixture) error {
		_, err := f.db.AdminRecoveryCodes().CountUnused(ctx, f.super.ID)
		return err
	}
	revokeActivations := func(f *adminFixture) error {
		_, err := f.db.AdminActivations().DeleteByAdmin(ctx, f.del.ID)
		return err
	}
	revokeActivationsTx := func(f *adminFixture) error {
		return tx(f, func(tx *SystemTx) error {
			_, err := f.db.AdminActivations().DeleteByAdminTx(ctx, tx, f.del.ID)
			return err
		})
	}
	consumeActivation := func(f *adminFixture) error {
		_, err := f.db.AdminActivations().Consume(ctx, hashOf("act"), now)
		return err
	}

	appendGlobal := func(f *adminFixture) error {
		_, err := f.db.AuditEvents().Append(ctx, AuditEvent{ActorKind: ActorSystem, Actor: "x", Action: "a.b", ObjectKind: "o", ObjectID: "i"})
		return err
	}
	appendScoped := func(f *adminFixture) error {
		s, _ := f.db.Scoped(f.tid)
		return s.Tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.AuditEvents().AppendScopedTx(ctx, tx, AuditEvent{ActorKind: ActorSystem, Actor: "x", Action: "a.b", ObjectKind: "o", ObjectID: "i"})
			return err
		})
	}
	listAll := func(f *adminFixture) error { _, err := f.db.AuditEvents().List(ctx, AuditFilter{}); return err }
	listTenant := func(f *adminFixture) error {
		_, err := f.db.AuditEvents().List(ctx, AuditFilter{TenantID: f.tid})
		return err
	}
	purgeAudit := func(f *adminFixture) error { _, err := f.db.AuditEvents().Purge(ctx, now.Add(time.Hour)); return err }

	rewrapSecrets := func(f *adminFixture) error {
		_, err := f.db.KeyRotations().RewrapSystemSecretsBatch(ctx, f.rot, testMK1, testMK2, 10, func(s SystemSecret) ([]byte, error) { return s.Blob, nil })
		return err
	}
	getSecret := func(f *adminFixture) error { _, err := f.db.SystemSecrets().Get(ctx, f.pending); return err }

	steps := []step{
		{name: "create insert", op: faultExec, match: "INSERT INTO admins", run: createDelegated},
		{name: "create tenants delete", op: faultExec, match: "DELETE FROM admin_tenants", run: createDelegated},
		{name: "create tenants insert", op: faultExec, match: "INSERT INTO admin_tenants", run: createDelegated},
		{name: "get query", op: faultQuery, match: "FROM admins WHERE id = ?", run: getSuper},
		{name: "get tenants query", op: faultQuery, match: "FROM admin_tenants WHERE admin_id = ? ORDER", run: getSuper},
		{name: "get tenants scan", op: faultScanNil, match: "FROM admin_tenants WHERE admin_id = ? ORDER", run: getDel},
		{name: "list query", op: faultQuery, match: "FROM admins WHERE id >", run: list},
		{name: "list scan", op: faultScanNil, match: "FROM admins WHERE id >", run: list},
		{name: "list tenants query", op: faultQuery, match: "admin_id <= ?", run: list},
		{name: "list tenants scan", op: faultScanNil, match: "admin_id <= ?", run: list},
		{name: "update guard", op: faultQuery, match: "role = 'super_admin'", run: disableOther},
		{name: "update exec", op: faultExec, match: "UPDATE admins SET email", run: disableOther},
		{name: "update tenants", op: faultExec, match: "INSERT INTO admin_tenants", run: moveDel},
		{name: "set password", op: faultExec, match: "UPDATE admins SET password_hash", run: setPassword},
		{name: "pending insert", op: faultExec, match: "INSERT INTO system_secrets", run: setPending},
		{name: "pending update", op: faultExec, match: "UPDATE admins SET pending", run: setPending},
		{name: "pending delete old", op: faultExec, match: "DELETE FROM system_secrets", run: setPending},
		{name: "set totp exec", op: faultExec, match: "totp_secret_id = pending_totp_secret_id", run: setTOTP},
		{name: "set totp delete old", op: faultExec, match: "DELETE FROM system_secrets", run: setTOTP},
		{name: "clear totp exec", op: faultExec, match: "totp_secret_id = NULL", run: clearTOTP},
		{name: "clear recovery codes", op: faultExec, match: "DELETE FROM admin_recovery_codes", run: clearTOTP},
		{name: "clear secrets", op: faultExec, match: "DELETE FROM system_secrets", run: clearTOTP},
		{name: "advance exec", op: faultExec, match: "SET totp_last_counter = ?", run: advance},
		{name: "advance rows", op: faultRows, match: "SET totp_last_counter = ?", run: advance},
		{name: "touch login", op: faultExec, match: "SET last_login_at", run: touch},
		{name: "delete guard", op: faultQuery, match: "role = 'super_admin'", run: deleteOther},
		{name: "delete exec", op: faultExec, match: "DELETE FROM admins", run: deleteOther},
		{name: "delete secrets", op: faultExec, match: "DELETE FROM system_secrets", run: deleteSuper},
		{name: "count all tx", op: faultQuery, match: "SELECT count(*) FROM admins", run: countAllTx},
		{name: "count all", op: faultQuery, match: "SELECT count(*) FROM admins", run: countAll},
		{name: "count usable super", op: faultQuery, match: "role = 'super_admin'", run: countUsable},
		{name: "tenant ids", op: faultQuery, match: "FROM admin_tenants", run: tenantIDs},

		{name: "login check", op: faultQuery, match: "FROM admin_login_failures WHERE scope", run: check},
		{name: "login record read", op: faultQuery, match: "FROM admin_login_failures WHERE scope", run: recordExisting},
		{name: "login record update", op: faultExec, match: "UPDATE admin_login_failures", run: recordExisting},
		{name: "login record insert", op: faultExec, match: "INSERT INTO admin_login_failures", run: recordNew},
		{name: "login refund read", op: faultQuery, match: "FROM admin_login_failures WHERE scope", run: refund},
		{name: "login refund write", op: faultExec, match: "UPDATE admin_login_failures", run: refund},
		{name: "login reset", op: faultExec, match: "DELETE FROM admin_login_failures WHERE scope", run: reset},
		{name: "login purge", op: faultExec, match: "DELETE FROM admin_login_failures WHERE (scope", run: purgeLogin},
		{name: "login purge rows", op: faultRows, match: "DELETE FROM admin_login_failures WHERE (scope", run: purgeLogin},

		{name: "session touch", op: faultExec, match: "SET last_seen_at", run: touchSession},
		{name: "session rotate", op: faultExec, match: "SET token_hash", run: rotate},
		{name: "session rotate tx", op: faultExec, match: "SET token_hash", run: rotateTx},
		{name: "session delete", op: faultExec, match: "DELETE FROM admin_sessions WHERE id = ?", run: deleteSession},
		{name: "session revoke", op: faultExec, match: "DELETE FROM admin_sessions WHERE admin_id", run: revoke},
		{name: "session revoke rows", op: faultRows, match: "DELETE FROM admin_sessions WHERE admin_id", run: revoke},
		{name: "session revoke tx", op: faultExec, match: "DELETE FROM admin_sessions WHERE admin_id", run: revokeTx},
		{name: "session purge", op: faultExec, match: "DELETE FROM admin_sessions WHERE id IN", run: purgeSessions},
		{name: "codes replace delete", op: faultExec, match: "DELETE FROM admin_recovery_codes", run: replaceCodes},
		{name: "codes replace insert", op: faultExec, match: "INSERT INTO admin_recovery_codes", run: replaceCodes},
		{name: "codes consume", op: faultExec, match: "UPDATE admin_recovery_codes", run: consumeCode},
		{name: "codes consume rows", op: faultRows, match: "UPDATE admin_recovery_codes", run: consumeCode},
		{name: "codes count", op: faultQuery, match: "FROM admin_recovery_codes", run: countCodes},
		{name: "activations revoke", op: faultExec, match: "DELETE FROM admin_activations WHERE admin_id", run: revokeActivations},
		{name: "activations revoke rows", op: faultRows, match: "DELETE FROM admin_activations WHERE admin_id", run: revokeActivations},
		{name: "activations revoke tx", op: faultExec, match: "DELETE FROM admin_activations WHERE admin_id", run: revokeActivationsTx},
		{name: "activations consume", op: faultQuery, match: "UPDATE admin_activations", run: consumeActivation},

		{name: "audit insert", op: faultExec, match: "INSERT INTO audit_events", run: appendGlobal},
		{name: "audit insert scoped", op: faultExec, match: "INSERT INTO audit_events", run: appendScoped},
		{name: "audit list query", op: faultQuery, match: "SELECT tenant_id, id, at", run: listAll},
		{name: "audit list scan", op: faultScanNil, match: "SELECT tenant_id, id, at", run: listAll},
		{name: "audit tenant query", op: faultQuery, match: "SELECT id, at, actor_kind", run: listTenant},
		{name: "audit tenant scan", op: faultScanNil, match: "SELECT id, at, actor_kind", run: listTenant},
		{name: "audit purge", op: faultExec, match: "DELETE FROM audit_events", run: purgeAudit},

		{name: "secrets rewrap query", op: faultQuery, match: "FROM system_secrets WHERE key_id", run: rewrapSecrets},
		{name: "secrets rewrap scan", op: faultScanNil, match: "FROM system_secrets WHERE key_id", run: rewrapSecrets},
		{name: "secrets rewrap exec", op: faultExec, match: "UPDATE system_secrets SET blob", run: rewrapSecrets},
		{name: "secrets rewrap rows", op: faultRows, match: "UPDATE system_secrets SET blob", run: rewrapSecrets},
		{name: "secrets rewrap progress", op: faultExec, match: "UPDATE key_rotations SET rewrapped_keys", run: rewrapSecrets},
		{name: "secrets get", op: faultQuery, match: "FROM system_secrets WHERE id", run: getSecret},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)
			f.plan.add(s.op, s.match, s.after)
			if err := s.run(f); err == nil {
				t.Errorf("%s: fault %s on %q ignored", s.name, s.op, s.match)
			}
			f.plan.reset()
			if err := s.run(f); err != nil {
				t.Errorf("%s fails without faults: %v", s.name, err)
			}
		})
	}
}

// TestAdminFaultsWithoutRetry covers the faults whose operation cannot
// simply be run again: identifier generation and a rotation whose progress
// row vanished.
func TestAdminFaultsWithoutRetry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(t)
	f.db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	f.db.newAuditID = f.db.newID
	if _, err := f.db.Admins().Create(ctx, Admin{Username: "x-new", Email: "x@example.com", Role: RoleSuperAdmin}); !errors.Is(err, errInjected) {
		t.Errorf("Create with a failing id generator: %v", err)
	}
	if _, err := f.db.AuditEvents().Append(ctx, AuditEvent{ActorKind: ActorSystem, Actor: "x", Action: "a.b", ObjectKind: "o", ObjectID: "i"}); !errors.Is(err, errInjected) {
		t.Errorf("Append with a failing id generator: %v", err)
	}

	// A corrupted failures column is reported, not misread.
	if _, err := rawSystemExec(ctx, f.db, `UPDATE admin_login_failures SET failures = 'x'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.AdminLoginFailures().Check(ctx, []AdminLoginKey{f.loginRules[0].Key}, adminTestNow); !errors.Is(err, errLoginRow) {
		t.Errorf("Check(corrupted row) = %v", err)
	}
}

// TestAdminPurgeBatches runs the system purges with a tiny batch size, so
// that they loop.
func TestAdminPurgeBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(t)
	f.db.purgeBatch = 2
	for range 4 {
		s := AdminSession{
			ID: id.New(id.AdminSession), TokenHash: hashOf(id.New(id.AdminSession)), AdminID: f.super.ID,
			State: SessionAuthenticated, CreatedAt: adminTestNow, ExpiresAt: adminTestNow.Add(time.Minute),
		}
		if err := f.db.AdminSessions().Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.db.AdminSessions().Purge(ctx, adminTestNow.Add(2*time.Hour), time.Hour); err != nil || n != 5 {
		t.Errorf("Purge = %d, %v; want 5", n, err)
	}
	if n, err := f.db.AuditEvents().Purge(ctx, adminTestNow.Add(time.Second)); err != nil || n != 2 {
		t.Errorf("Purge(audit) = %d, %v; want 2", n, err)
	}
}

// TestAdminLockStatements replaces the PostgreSQL-only system lock by a
// harmless statement, so that the code paths taking it run on SQLite, then
// makes it fail.
func TestAdminLockStatements(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(t)
	d := *f.db.dialect
	d.lockSystem = "SELECT ?"
	f.db.dialect = &d
	keys := []AdminLoginKey{f.loginRules[0].Key}
	ops := map[string]func() error{
		"count": func() error {
			return f.db.Admins().Tx(ctx, func(tx *SystemTx) error { _, err := f.db.Admins().CountAllTx(ctx, tx); return err })
		},
		"update":  func() error { _, err := f.db.Admins().Update(ctx, f.del.ID, AdminUpdate{}); return err },
		"pending": func() error { return f.db.Admins().SetPendingTOTP(ctx, f.del.ID, newTestSecret()) },
		"clear":   func() error { return f.db.Admins().ClearTOTP(ctx, f.del.ID) },
		"usable": func() error {
			return f.db.Admins().Tx(ctx, func(tx *SystemTx) error { _, err := f.db.Admins().CountUsableSuperAdminsTx(ctx, tx); return err })
		},
		"delete": func() error { return f.db.Admins().Delete(ctx, f.other.ID) },
		"check":  func() error { _, err := f.db.AdminLoginFailures().Check(ctx, keys, adminTestNow); return err },
		"purge":  func() error { _, err := f.db.AdminLoginFailures().Purge(ctx, adminTestNow, time.Hour); return err },
	}
	for name, op := range ops {
		if err := op(); err != nil {
			t.Errorf("%s with a harmless lock: %v", name, err)
		}
	}
	d.lockSystem = "SELECT bogus("
	for name, op := range ops {
		if name == "delete" {
			continue // already done
		}
		if err := op(); err == nil || !strings.Contains(err.Error(), "lock admin") {
			t.Errorf("%s with a failing lock: %v", name, err)
		}
	}
	if err := f.db.Admins().Delete(ctx, f.del.ID); err == nil || !strings.Contains(err.Error(), "lock admins") {
		t.Errorf("delete with a failing lock: %v", err)
	}
	// SetTOTP consumes the pending secret: it runs once with each lock.
	d.lockSystem = "SELECT ?"
	if err := f.db.Admins().SetTOTP(ctx, f.super.ID, f.pending, 5); err != nil {
		t.Errorf("set totp with a harmless lock: %v", err)
	}
	pending := newTestSecret()
	if err := f.db.Admins().SetPendingTOTP(ctx, f.super.ID, pending); err != nil {
		t.Fatal(err)
	}
	d.lockSystem = "SELECT bogus("
	if err := f.db.Admins().SetTOTP(ctx, f.super.ID, pending.ID, 6); err == nil || !strings.Contains(err.Error(), "lock admins") {
		t.Errorf("set totp with a failing lock: %v", err)
	}
}

// TestMigration0008Upgrade applies 0008_admin on a database at 0007
// holding a tenant and a wrapped key: the data is kept and the
// administration tables work.
func TestMigration0008Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 7)
		if n, err := db.Migrate(ctx); err != nil || n != 7 {
			t.Fatalf("Migrate to 0007 = %d, %v", n, err)
		}
		tn := &tenant.Tenant{ID: createLegacyTenant(ctx, t, db, "a.example.com", 1)} // schema before 0009
		wk := WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeSecret, KeyID: testMK1, Blob: []byte("k")}
		if err := db.WrappedKeys().Create(ctx, tn.ID, wk); err != nil {
			t.Fatal(err)
		}

		db.migrationsFS = migrationFiles
		if n, err := db.Migrate(ctx); err != nil || n != len(mustMigrations(t, db))-7 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		if got, err := db.WrappedKeys().Get(ctx, tn.ID, wk.ID); err != nil || string(got.Blob) != "k" {
			t.Errorf("wrapped key after 0008 = %+v, %v", got, err)
		}
		a, err := db.Admins().Create(ctx, Admin{Username: "admin.a", Email: "a@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{tn.ID}})
		if err != nil || len(a.TenantIDs) != 1 {
			t.Errorf("Create admin after 0008 = %+v, %v", a, err)
		}
		if n, err := db.WrappedKeys().CountByKey(ctx, testMK1); err != nil || n != 1 {
			t.Errorf("CountByKey after 0008 = %d, %v", n, err)
		}
	})
}

// TestAdminSchemaConstraints checks the guarantees the schema enforces by
// itself, on both engines.
func TestAdminSchemaConstraints(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		insert := `INSERT INTO admins (id, username, email, role, require_totp, totp_enabled, created_at, updated_at) VALUES `
		rejected := map[string]string{
			"super admin without totp": insert + `('adm_1', 'a', 'a@example.com', 'super_admin', false, false, 0, 0)`,
			"totp without secret":      insert + `('adm_2', 'b', 'b@example.com', 'delegated_admin', true, true, 0, 0)`,
			"unknown role":             insert + `('adm_3', 'c', 'c@example.com', 'auditor', true, false, 0, 0)`,
		}
		for name, q := range rejected {
			if _, err := rawSystemExec(ctx, db, q); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		if _, err := rawSystemExec(ctx, db, insert+`('adm_4', 'd', 'd@example.com', 'super_admin', true, false, 0, 0)`); err != nil {
			t.Fatal(err)
		}
		if _, err := rawSystemExec(ctx, db, insert+`('adm_5', 'd', 'e@example.com', 'super_admin', true, false, 0, 0)`); !errors.Is(classify(err), ErrConflict) {
			t.Errorf("duplicate username: %v", err)
		}
		session := `INSERT INTO admin_sessions (id, token_hash, admin_id, state, created_at, last_seen_at, expires_at, state_expires_at) VALUES `
		for name, q := range map[string]string{
			"authenticated with a state expiry": session + `('as_1', ` + hexBlob(e, "01") + `, 'adm_4', 'authenticated', 0, 0, 10, 5)`,
			"intermediate without expiry":       session + `('as_2', ` + hexBlob(e, "02") + `, 'adm_4', 'totp_required', 0, 0, 10, NULL)`,
			"expiry before creation":            session + `('as_3', ` + hexBlob(e, "03") + `, 'adm_4', 'authenticated', 10, 10, 10, NULL)`,
		} {
			if _, err := rawSystemExec(ctx, db, q); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		var n int
		err := db.runTx(ctx, db.read, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_sessions`).Scan(&n)
		})
		if err != nil || n != 0 {
			t.Errorf("sessions = %d, %v", n, err)
		}
	})
}

// hexBlob returns a blob literal for the engine.
func hexBlob(e storetest.Engine, hex string) string {
	if e.Driver == "postgres" {
		return `'\x` + hex + `'::bytea`
	}
	return `X'` + hex + `'`
}
