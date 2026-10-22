package adminauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fails expects err to wrap errFault.
func fails(t *testing.T, what string, err error) {
	t.Helper()
	wantErr(t, what, err, errFault)
}

func failToken(string, int) (string, error) { return "", errFault }
func failID(id.Prefix) (string, error)      { return "", errFault }

// with sets *ptr to v and returns the function restoring it.
func with[T any](ptr *T, v T) func() {
	old := *ptr
	*ptr = v
	return func() { *ptr = old }
}

func TestNewOptions(t *testing.T) {
	for _, u := range []string{
		"", "ftp://admin.example.com", "https://", "https://u@admin.example.com",
		"https://admin.example.com/admin", "https://admin.example.com?x=1", "https://admin.example.com#x",
		"mailto:admin@example.com", "https://admin.example.com:bad", "%zz",
	} {
		if _, err := New(nil, nil, nil, nil, nil, Options{AdminBaseURL: u}); err == nil {
			t.Errorf("New(%q) = nil error", u)
		}
	}
	s, err := New(nil, nil, nil, nil, nil, Options{AdminBaseURL: "http://admin.localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if s.idle != DefaultIdleTimeout || s.maxAge != DefaultMaxAge || s.stateTTL != DefaultStateTTL ||
		s.issuer != DefaultIssuer || s.clock == nil || s.logger == nil || s.setupToken != "" ||
		s.activationLink("act_x") != "http://admin.localhost:8080/admin/activate#act_x" {
		t.Errorf("defaults = %+v", s)
	}
	s, err = New(nil, nil, nil, nil, nil, Options{
		AdminBaseURL: "https://admin.example.com", IdleTimeout: time.Minute, MaxAge: time.Hour, StateTTL: time.Second, Issuer: "Acme",
	})
	if err != nil || s.idle != time.Minute || s.maxAge != time.Hour || s.stateTTL != time.Second || s.issuer != "Acme" {
		t.Errorf("options = %+v, %v", s, err)
	}
}

func TestErrorsAndHelpers(t *testing.T) {
	if got := invalid(FieldEmail).Error(); got != "adminauth: invalid /email" {
		t.Errorf("InvalidError = %q", got)
	}
	rl := &RateLimitError{RetryAfter: 3 * time.Second}
	if !strings.Contains(rl.Error(), "3s") || !errors.Is(rl, ErrRateLimited) || errors.Is(rl, ErrInvalid) {
		t.Errorf("RateLimitError = %q", rl.Error())
	}
	now := testStart
	for d, want := range map[time.Duration]time.Duration{
		-time.Second: time.Second, 0: time.Second, 500 * time.Millisecond: time.Second,
		2100 * time.Millisecond: 3 * time.Second, 15 * time.Minute: 15 * time.Minute,
	} {
		if got := retryAfter(now.Add(d), now); got != want {
			t.Errorf("retryAfter(%v) = %v, want %v", d, got, want)
		}
	}
	for _, c := range []error{ErrLastSuperAdmin, ErrSelfAction, ErrNoPendingEnrollment, ErrNotPromotable, ErrAccountDisabled} {
		if !errors.Is(c, ErrStateConflict) {
			t.Errorf("%v does not match ErrStateConflict", c)
		}
	}
}

func TestAuthorization(t *testing.T) {
	a, b := tenant.ID("ten_01JAB00000000000000ENT1TYA"), tenant.ID("ten_01JAB00000000000000ENT1TYB")
	super := Account{Role: store.RoleSuperAdmin}
	deleg := Account{Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{a}}
	auditor := Account{Role: "auditor", TenantIDs: []tenant.ID{a}}
	cases := []struct {
		name string
		acc  Account
		tid  tenant.ID
		want bool
	}{
		{"super any", super, b, true},
		{"super empty tenant", super, "", false},
		{"delegated own", deleg, a, true},
		{"delegated other", deleg, b, false},
		{"unknown role", auditor, a, false},
		{"disabled super", Account{Role: store.RoleSuperAdmin, Disabled: true}, a, false},
	}
	for _, tc := range cases {
		if got := CanAccessTenant(tc.acc, tc.tid); got != tc.want {
			t.Errorf("%s: CanAccessTenant = %v", tc.name, got)
		}
		// A tenant out of reach is answered as missing, never forbidden.
		for name, require := range map[string]func(Account, tenant.ID) error{
			"RequireTenantAccess": RequireTenantAccess, "RequireTenantWrite": RequireTenantWrite,
		} {
			err := require(tc.acc, tc.tid)
			if (err == nil) != tc.want || (err != nil && (!errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden))) {
				t.Errorf("%s: %s = %v", tc.name, name, err)
			}
		}
	}
	if RequireSuperAdmin(super) != nil || !errors.Is(RequireSuperAdmin(deleg), ErrForbidden) ||
		!errors.Is(RequireSuperAdmin(Account{Role: store.RoleSuperAdmin, Disabled: true}), ErrForbidden) {
		t.Error("RequireSuperAdmin")
	}
	if !errors.Is(RequireAuthenticated(Principal{State: store.SessionAuthenticated}), ErrUnauthenticated) {
		t.Error("RequireAuthenticated(zero session)")
	}
}

// TestDummyHash checks that an unknown username, a disabled account and an
// account without a password cost a password verification, against the
// dummy hash, and that the dummy hash is a well-formed argon2id hash.
func TestDummyHash(t *testing.T) {
	ctx := context.Background()
	ok, err := crypto.NewPasswordHasher(1).VerifyPassword(ctx, dummyHash, []byte(rootPassword))
	if ok || err != nil {
		t.Fatalf("real VerifyPassword(dummyHash) = %v, %v", ok, err)
	}
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	before := ev.hasher.count(dummyHash)
	_, err = ev.svc.Login(ctx, "nobody", rootPassword, ipA)
	wantErr(t, "unknown user", err, ErrInvalidCredentials)
	_, err = ev.svc.Login(ctx, "-malformed-", rootPassword, ipA)
	wantErr(t, "malformed user", err, ErrInvalidCredentials)
	page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: "admin.login_failed", Actor: "unknown"})
	if err != nil || len(page.Items) != 2 {
		t.Errorf("audit of unknown usernames = %d, %v", len(page.Items), err)
	}
	if _, _, err := ev.svc.Create(ctx, r.p, AdminCreate{
		Username: "pending", Email: "p@entity-a.example.com",
		Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{ev.a.ID},
	}, ipA); err != nil {
		t.Fatal(err)
	}
	_, err = ev.svc.Login(ctx, "pending", "", ipA)
	wantErr(t, "account without password", err, ErrInvalidCredentials)
	d := ev.mustDelegated(t, r, "disabled", false, ev.a.ID)
	if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
		t.Fatal(err)
	}
	_, err = ev.svc.Login(ctx, "disabled", rootPassword, ipA)
	wantErr(t, "disabled account", err, ErrInvalidCredentials)
	if got := ev.hasher.count(dummyHash) - before; got != 4 {
		t.Errorf("dummy verifications = %d, want 4", got)
	}
	// The activation of d opened its session without a login: no real
	// hash was verified.
	if n := ev.hasher.count(fakeHash(rootPassword)); n != 0 {
		t.Errorf("real hash verifications = %d", n)
	}
}

func TestCheckCSRF(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	tok := r.sess.Token
	for _, h := range []string{"", r.p.CSRFToken[len(CSRFPrefix):], CSRFPrefix + "!!", CSRFPrefix + "AAAA"} {
		if ev.svc.CheckCSRF(tok, h) {
			t.Errorf("CheckCSRF(%q) = true", h)
		}
	}
	if ev.svc.CheckCSRF("as_bad", r.p.CSRFToken) {
		t.Error("CheckCSRF(malformed token) = true")
	}
	defer ev.withKeys()()
	if ev.svc.CheckCSRF(tok, r.p.CSRFToken) {
		t.Error("CheckCSRF(failing keys) = true")
	}
}

func TestFaultsSetup(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	req := SetupRequest{Username: "root", Email: "it-admin@example.com", Password: rootPassword, SetupToken: setupToken}
	setup := func(what string) {
		t.Helper()
		_, err := ev.svc.CreateSuperAdmin(ctx, req, ipA)
		fails(t, what, err)
	}
	restore := ev.withFaults("countAdmins")
	_, err := ev.svc.SetupRequired(ctx)
	fails(t, "SetupRequired", err)
	setup("count")
	restore()

	ev.hasher.set(errFault, nil)
	setup("hash")
	ev.hasher.set(nil, nil)
	r := with(&ev.svc.newTOTPSecret, func() ([]byte, error) { return nil, errFault })
	setup("totp secret")
	r()
	ev.vault.set(errFault, nil)
	setup("wrap")
	ev.vault.set(nil, nil)
	r = with(&ev.svc.qrPNG, func(string) ([]byte, error) { return nil, errFault })
	setup("qr")
	r()
	r = with(&ev.svc.newToken, failToken)
	setup("session token")
	r()
	r = with(&ev.svc.newID, failID)
	setup("session id")
	r()
	r = ev.withKeys()
	setup("csrf")
	r()
	for _, op := range []string{"tx.countAdmins", "tx.createAdmin", "tx.setPendingTOTP", "tx.createSession", "tx.audit"} {
		restore := ev.withFaults(op)
		setup(op)
		restore()
	}
	if required, err := ev.svc.SetupRequired(ctx); err != nil || !required {
		t.Fatalf("a failed setup left an admin: %v, %v", required, err)
	}
	// A setup that passed the first count loses to a concurrent one.
	ev.mustSetup(t)
	restore = ev.withRepo(func(r repo) faultRepo { return faultRepo{repo: r, countZero: true} })
	_, err = ev.svc.CreateSuperAdmin(ctx, req, ipA)
	wantErr(t, "concurrent setup", err, ErrSetupDone)
	restore()
}

func TestFaultsLogin(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	login := func(password string) error {
		t.Helper()
		_, err := ev.svc.Login(ctx, rootName, password, ipA)
		return err
	}

	_, err := ev.svc.Login(ctx, strings.Repeat("a", MaxUsernameLen+1), rootPassword, ipA)
	wantInvalid(t, "long username", err, FieldUsername)
	_, err = ev.svc.Login(ctx, rootName, strings.Repeat("a", MaxPasswordLen+1), ipA)
	wantInvalid(t, "long password", err, FieldPassword)
	_, err = ev.svc.Login(ctx, rootName, rootPassword, netipZero)
	wantErr(t, "no client ip", err, ErrNoClientIP)

	for _, op := range []string{"adminByUsername", "checkLogin", "recordLogin", "resetLogin", "refundLogin", "tx.createSession"} {
		restore := ev.withFaults(op)
		fails(t, op, login(rootPassword))
		restore()
	}
	for name, restore := range map[string]func() func(){
		"token": func() func() { return with(&ev.svc.newToken, failToken) },
		"id":    func() func() { return with(&ev.svc.newID, failID) },
		"csrf":  ev.withKeys,
	} {
		undo := restore()
		fails(t, "session "+name, login(rootPassword))
		undo()
	}
	// A password that cannot be verified is refunded; a failed refund is
	// only logged.
	ev.hasher.set(nil, errFault)
	fails(t, "verify", login(rootPassword))
	restore := ev.withFaults("refundLogin")
	fails(t, "verify without refund", login(rootPassword))
	restore()
	ev.hasher.set(nil, nil)
	if !strings.Contains(ev.applog.String(), "admin login attempt not refunded") {
		t.Error("the failed refund is not logged")
	}

	// Failing security log and audit writes are logged and do not change
	// the answer.
	ev.seclog.err = errFault
	restore = ev.withFaults("audit")
	wantErr(t, "wrong password", login("wrong password"), ErrInvalidCredentials)
	restore()
	ev.seclog.err = nil
	if log := ev.applog.String(); !strings.Contains(log, "security log write failed") || !strings.Contains(log, "audit write failed") {
		t.Errorf("application log = %s", log)
	}
	// A completed login whose last login time cannot be written still
	// succeeds.
	ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)
	restore = ev.withFaults("touchLogin")
	if _, err := ev.svc.Login(ctx, "admin.a", rootPassword, ipA); err != nil {
		t.Errorf("Login(touch fault) = %v", err)
	}
	restore()
	if !strings.Contains(ev.applog.String(), "admin last login not recorded") {
		t.Error("the failed touch is not logged")
	}

	// A lock set by a concurrent attempt between the check and the count.
	for range LoginUserIPMaxFailures {
		_ = login("wrong password")
	}
	ev.clock.Advance(time.Minute)
	restore = ev.withRepo(func(r repo) faultRepo { return faultRepo{repo: r, checkZero: true} })
	_, err = ev.svc.Login(ctx, rootName, rootPassword, ipA)
	if rl := wantLimited(t, "concurrent lock", err); rl.RetryAfter != LoginLockDuration-time.Minute {
		t.Errorf("RetryAfter = %v", rl.RetryAfter)
	}
	restore()
	ev.assertNoSecretLogged(t, rootPassword, "wrong password")
}

func TestFaultsTOTP(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	pre := func() Principal {
		t.Helper()
		ev.nextStep()
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ev.svc.Resolve(ctx, sess.Token)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := pre()
	verify := func(code string) error {
		t.Helper()
		_, err := ev.svc.VerifyTOTP(ctx, p, code, "", ipA)
		return err
	}
	restore := ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"admin": store.ErrNotFound}}
	})
	wantErr(t, "deleted admin", verify(ev.code(r.secret)), ErrUnauthenticated)
	restore()
	for _, op := range []string{"admin", "checkLogin", "advanceTOTP"} {
		restore := ev.withFaults(op)
		fails(t, op, verify(ev.code(r.secret)))
		restore()
	}
	restore = ev.withFaults("consumeRecovery")
	_, err := ev.svc.VerifyTOTP(ctx, p, "", r.codes[0], ipA)
	fails(t, "consumeRecovery", err)
	restore()
	ev.vault.set(nil, errFault)
	fails(t, "open secret", verify(ev.code(r.secret)))
	_, err = ev.svc.VerifyTOTP(ctx, p, "", r.codes[0], ipA)
	fails(t, "open secret (recovery)", err)
	ev.vault.set(nil, nil)
	undo := with(&ev.svc.recoveryMAC, func([]byte, string) ([]byte, error) { return nil, errFault })
	_, err = ev.svc.VerifyTOTP(ctx, p, "", r.codes[0], ipA)
	fails(t, "recovery mac", err)
	undo()
	// Disabled without revocation (directly in the store).
	if _, err := ev.db.Admins().Update(ctx, r.p.Admin.ID, store.AdminUpdate{Disabled: ptr(true)}); !errors.Is(err, store.ErrLastSuperAdmin) {
		t.Fatalf("disable the only super admin in the store = %v", err)
	}

	// Rotation failures, each with a fresh step.
	for name, undo := range map[string]func() func(){
		"rotate": func() func() { return ev.withFaults("rotateSession") },
		"token":  func() func() { return with(&ev.svc.newToken, failToken) },
		"csrf":   ev.withKeys,
	} {
		p = pre()
		restore := undo()
		fails(t, "rotation "+name, verify(ev.code(r.secret)))
		restore()
	}
	// A recovery code login whose audit write fails still succeeds.
	p = pre()
	restore = ev.withFaults("audit")
	if _, err := ev.svc.VerifyTOTP(ctx, p, "", r.codes[0], ipA); err != nil {
		t.Errorf("VerifyTOTP(recovery, audit fault) = %v", err)
	}
	restore()

	// Failure counting errors.
	p = pre()
	wrong := ev.wrongCode(r.secret)
	restore = ev.withFaults("totpFailure")
	fails(t, "count failure", verify(wrong))
	restore()
	ev.clock.Advance(LoginLockDuration + LoginWindow)
	p = pre()
	wrong = ev.wrongCode(r.secret)
	for range MaxSessionTOTPFailures - 1 {
		wantErr(t, "wrong code", verify(wrong), ErrInvalidCredentials)
	}
	restore = ev.withFaults("deleteSession")
	fails(t, "end session", verify(wrong))
	restore()
	// The session already ended (concurrently): the failure is returned.
	ev.clock.Advance(LoginLockDuration + LoginWindow)
	p = pre()
	wrong = ev.wrongCode(r.secret)
	for range MaxSessionTOTPFailures - 1 {
		wantErr(t, "wrong code", verify(wrong), ErrInvalidCredentials)
	}
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"deleteSession": store.ErrNotFound}}
	})
	_ = wantLimited(t, "session already ended", verify(wrong))
	restore()
}

func TestFaultsDisabledSecondFactor(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	d := ev.mustDelegated(t, r, "admin.a", true, ev.a.ID)
	secret, _ := ev.mustEnroll(t, d.p)
	ev.nextStep()
	sess, err := ev.svc.Login(ctx, "admin.a", rootPassword, ipB)
	if err != nil {
		t.Fatal(err)
	}
	p := ev.mustResolve(t, sess.Token)
	// Disabled in the store without revoking the session.
	if _, err := ev.db.Admins().Update(ctx, d.account.ID, store.AdminUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	_, err = ev.svc.VerifyTOTP(ctx, p, ev.code(secret), "", ipB)
	wantErr(t, "VerifyTOTP(disabled)", err, ErrUnauthenticated)
	_, err = ev.svc.Resolve(ctx, sess.Token)
	wantErr(t, "Resolve(disabled)", err, ErrUnauthenticated)
	// TOTP cleared meanwhile.
	if _, err := ev.db.Admins().Update(ctx, d.account.ID, store.AdminUpdate{Disabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := ev.db.Admins().ClearTOTP(ctx, d.account.ID); err != nil {
		t.Fatal(err)
	}
	_, err = ev.svc.VerifyTOTP(ctx, p, ev.code(secret), "", ipB)
	wantErr(t, "VerifyTOTP(no totp)", err, ErrUnauthenticated)
}

func TestFaultsSessions(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	tok := r.sess.Token
	resolve := func() error {
		t.Helper()
		_, err := ev.svc.Resolve(ctx, tok)
		return err
	}
	for _, op := range []string{"session", "admin", "touchSession"} {
		restore := ev.withFaults(op)
		fails(t, "Resolve "+op, resolve())
		restore()
	}
	for _, op := range []string{"admin", "touchSession"} {
		restore := ev.withRepo(func(rp repo) faultRepo {
			return faultRepo{repo: rp, fails: map[string]error{op: store.ErrNotFound}}
		})
		wantErr(t, "Resolve "+op+" not found", resolve(), ErrUnauthenticated)
		restore()
	}
	restore := ev.withKeys()
	fails(t, "Resolve csrf", resolve())
	restore()

	// Logout.
	wantErr(t, "Logout(zero)", ev.svc.Logout(ctx, Principal{}, ipA), ErrUnauthenticated)
	restore = ev.withFaults("deleteSession")
	fails(t, "Logout", ev.svc.Logout(ctx, r.p, ipA))
	restore()

	// Password change.
	ev.hasher.set(errFault, nil)
	fails(t, "ChangePassword hash", ev.svc.ChangePassword(ctx, r.p, rootPassword, newPassword, ipA))
	ev.hasher.set(nil, nil)
	for _, op := range []string{"tx.setPassword", "tx.deleteSessions", "tx.audit", "admin"} {
		restore := ev.withFaults(op)
		fails(t, "ChangePassword "+op, ev.svc.ChangePassword(ctx, r.p, rootPassword, newPassword, ipA))
		restore()
	}
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"admin": store.ErrNotFound}}
	})
	wantErr(t, "ChangePassword deleted", ev.svc.ChangePassword(ctx, r.p, rootPassword, newPassword, ipA), ErrUnauthenticated)
	restore()

	// Enrollment (a re-enrollment of the super admin).
	_, err := ev.svc.StartEnrollment(ctx, Principal{}, "", ipA)
	wantErr(t, "StartEnrollment(zero)", err, ErrUnauthenticated)
	start := func(what string) {
		t.Helper()
		_, err := ev.svc.StartEnrollment(ctx, r.p, rootPassword, ipA)
		fails(t, "StartEnrollment "+what, err)
	}
	restore = ev.withFaults("admin")
	start("password check")
	restore()
	undo := with(&ev.svc.newTOTPSecret, func() ([]byte, error) { return nil, errFault })
	start("secret")
	undo()
	ev.vault.set(errFault, nil)
	start("wrap")
	ev.vault.set(nil, nil)
	undo = with(&ev.svc.qrPNG, func(string) ([]byte, error) { return nil, errFault })
	start("qr")
	undo()
	restore = ev.withFaults("setPendingTOTP")
	start("store")
	restore()
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"setPendingTOTP": store.ErrNotFound}}
	})
	_, err = ev.svc.StartEnrollment(ctx, r.p, rootPassword, ipA)
	wantErr(t, "StartEnrollment(deleted)", err, ErrUnauthenticated)
	restore()

	// Confirmation, from the enrollment state of a fresh login after a
	// local reset.
	if err := ev.svc.ResetTOTPLocal(ctx, rootName); err != nil {
		t.Fatal(err)
	}
	sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipA)
	if err != nil {
		t.Fatal(err)
	}
	p := ev.mustResolve(t, sess.Token)
	enr, err := ev.svc.StartEnrollment(ctx, p, "", ipA)
	if err != nil {
		t.Fatal(err)
	}
	secret := decodeSecret(t, enr)
	confirm := func() error {
		t.Helper()
		_, err := ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipA)
		return err
	}
	// Every failure, the rotation included, rolls the whole confirmation
	// back: the pending secret stays and the session keeps its state.
	for _, op := range []string{"admin", "systemSecret", "checkLogin", "recordLogin", "tx.setTOTP", "tx.replaceRecovery", "tx.rotateSession", "tx.audit"} {
		restore := ev.withFaults(op)
		fails(t, "ConfirmEnrollment "+op, confirm())
		restore()
		if a, err := ev.db.Admins().Get(ctx, p.Admin.ID); err != nil || a.TOTPEnabled || a.PendingTOTPSecretID == "" {
			t.Fatalf("ConfirmEnrollment %s left %+v, %v", op, a, err)
		}
	}
	for name, undo := range map[string]func() func(){
		"token": func() func() { return with(&ev.svc.newToken, failToken) },
		"csrf":  ev.withKeys,
		"mac": func() func() {
			return with(&ev.svc.recoveryMAC, func([]byte, string) ([]byte, error) { return nil, errFault })
		},
	} {
		restore := undo()
		fails(t, "ConfirmEnrollment "+name, confirm())
		restore()
	}
	if got := ev.mustResolve(t, sess.Token); got.State != store.SessionTOTPEnrollmentRequired {
		t.Fatalf("session state after the faults = %s", got.State)
	}
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"tx.rotateSession": store.ErrNotFound}}
	})
	wantErr(t, "ConfirmEnrollment(session ended)", confirm(), ErrUnauthenticated)
	restore()
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"admin": store.ErrNotFound}}
	})
	wantErr(t, "ConfirmEnrollment(deleted)", confirm(), ErrUnauthenticated)
	restore()
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"tx.setTOTP": store.ErrNotFound}}
	})
	wantErr(t, "ConfirmEnrollment(replaced)", confirm(), ErrNoPendingEnrollment)
	restore()
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"systemSecret": store.ErrNotFound}}
	})
	wantErr(t, "ConfirmEnrollment(secret replaced)", confirm(), ErrNoPendingEnrollment)
	restore()
	ev.vault.set(nil, errFault)
	fails(t, "ConfirmEnrollment open", confirm())
	ev.vault.set(nil, nil)
	undo = with(&ev.svc.newRecovery, func(int) ([]string, error) { return nil, errFault })
	fails(t, "ConfirmEnrollment recovery", confirm())
	undo()
	conf, err := ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipA)
	if err != nil || conf.Session == nil {
		t.Fatalf("ConfirmEnrollment after the faults = %+v, %v", conf, err)
	}
	// The codes returned are the ones stored.
	if n, _ := ev.db.AdminRecoveryCodes().CountUnused(ctx, p.Admin.ID); n != RecoveryCodeCount {
		t.Errorf("recovery codes = %d", n)
	}
	np := ev.mustResolve(t, conf.Session.Token)

	// Re-enrollment: revoking the other sessions can fail.
	enr, err = ev.svc.StartEnrollment(ctx, np, rootPassword, ipA)
	if err != nil {
		t.Fatal(err)
	}
	ev.nextStep()
	restore = ev.withFaults("tx.deleteSessions")
	_, err = ev.svc.ConfirmEnrollment(ctx, np, ev.code(decodeSecret(t, enr)), ipA)
	fails(t, "ConfirmEnrollment revoke", err)
	restore()

	// Disabling TOTP.
	d := ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)
	for _, op := range []string{"tx.clearTOTP", "tx.deleteSessions", "tx.audit"} {
		restore := ev.withFaults(op)
		fails(t, "DisableTOTP "+op, ev.svc.DisableTOTP(ctx, d.p, rootPassword, ipB))
		restore()
	}
}

func TestFaultsAdmins(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	d := ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)

	restore := ev.withFaults("listAdmins")
	_, err := ev.svc.List(ctx, r.p, "", 0)
	fails(t, "List", err)
	_, err = ev.svc.ListAccounts(ctx)
	fails(t, "ListAccounts", err)
	restore()
	undo := with(&listAccountsPage, 1)
	all, err := ev.svc.ListAccounts(ctx)
	undo()
	if err != nil || len(all) != 2 {
		t.Errorf("ListAccounts(paged) = %d, %v", len(all), err)
	}
	restore = ev.withFaults("admin")
	_, err = ev.svc.Get(ctx, r.p, d.account.ID)
	fails(t, "Get", err)
	restore()

	// Create.
	n := 0
	create := func(what string) {
		t.Helper()
		n++
		_, _, err := ev.svc.Create(ctx, r.p, AdminCreate{
			Username: "new" + string(rune('a'+n)), Email: "n@entity-a.example.com",
			Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{ev.a.ID},
		}, ipA)
		fails(t, "Create "+what, err)
	}
	for _, op := range []string{"tx.createAdmin", "tx.createActivation", "tx.audit"} {
		restore := ev.withFaults(op)
		create(op)
		restore()
	}
	for name, undo := range map[string]func() func(){
		"token": func() func() { return with(&ev.svc.newToken, failToken) },
		"id":    func() func() { return with(&ev.svc.newID, failID) },
	} {
		restore := undo()
		create(name)
		restore()
	}

	// Update.
	update := func(what string, u AdminUpdate) {
		t.Helper()
		_, err := ev.svc.Update(ctx, r.p, d.account.ID, u, ipA)
		fails(t, "Update "+what, err)
	}
	for _, op := range []string{"tx.admin", "tx.updateAdmin", "tx.deleteActivations", "tx.audit"} {
		restore := ev.withFaults(op)
		update(op, AdminUpdate{Email: ptr("x@entity-a.example.com")})
		restore()
	}
	restore = ev.withFaults("tx.deleteSessions")
	update("revoke", AdminUpdate{Disabled: ptr(true)})
	restore()
	restore = ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"tx.updateAdmin": store.ErrNotFound}}
	})
	_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{TenantIDs: &[]tenant.ID{ev.b.ID}}, ipA)
	wantInvalid(t, "Update(tenant vanished)", err, FieldTenantIDs)
	restore()

	// Delete.
	for _, op := range []string{"tx.admin", "tx.deleteAdmin", "tx.audit"} {
		restore := ev.withFaults(op)
		fails(t, "Delete "+op, ev.svc.Delete(ctx, r.p, d.account.ID, ipA))
		restore()
	}

	// Reset.
	reset := func() (Activation, error) {
		_, link, err := ev.svc.ResetCredentials(ctx, r.p, d.account.ID, ipA)
		return link, err
	}
	for _, op := range []string{
		"tx.countUsableSuperAdmins", "tx.admin", "tx.setPassword", "tx.clearTOTP", "tx.deleteSessions",
		"tx.deleteActivations", "tx.createActivation", "tx.audit",
	} {
		restore := ev.withFaults(op)
		_, err := reset()
		fails(t, "ResetCredentials "+op, err)
		restore()
	}
	for name, undo := range map[string]func() func(){
		"token": func() func() { return with(&ev.svc.newToken, failToken) },
		"id":    func() func() { return with(&ev.svc.newID, failID) },
	} {
		restore := undo()
		_, err := reset()
		fails(t, "ResetCredentials "+name, err)
		restore()
	}
	if _, err := ev.svc.Login(ctx, "admin.a", rootPassword, ipB); err != nil {
		t.Errorf("a failed reset changed the account: %v", err)
	}

	// Activation.
	link, err := reset()
	if err != nil {
		t.Fatal(err)
	}
	token := ev.tokenOf(t, link)
	activate := func(what string) {
		t.Helper()
		_, err := ev.svc.Activate(ctx, token, newPassword, ipB)
		fails(t, "Activate "+what, err)
	}
	ev.hasher.set(errFault, nil)
	activate("hash")
	ev.hasher.set(nil, nil)
	for _, op := range []string{
		"tx.consumeActivation", "tx.admin", "tx.setPassword", "tx.deleteActivations",
		"tx.createSession", "tx.audit",
	} {
		restore := ev.withFaults(op)
		activate(op)
		restore()
	}
	undo = with(&ev.svc.newToken, failToken)
	activate("session token")
	undo()
	if _, err := ev.svc.Activate(ctx, token, newPassword, ipB); err != nil {
		t.Errorf("Activate after the faults = %v", err)
	}

	// Local resets.
	restore = ev.withFaults("adminByUsername")
	fails(t, "ResetTOTPLocal read", ev.svc.ResetTOTPLocal(ctx, rootName))
	_, err = ev.svc.ResetPasswordLocal(ctx, rootName)
	fails(t, "ResetPasswordLocal read", err)
	restore()
	for _, op := range []string{"tx.clearTOTP", "tx.deleteSessions", "tx.audit"} {
		restore := ev.withFaults(op)
		fails(t, "ResetTOTPLocal "+op, ev.svc.ResetTOTPLocal(ctx, rootName))
		restore()
	}
	for _, op := range []string{"tx.setPassword", "tx.createActivation", "tx.audit"} {
		restore := ev.withFaults(op)
		_, err := ev.svc.ResetPasswordLocal(ctx, rootName)
		fails(t, "ResetPasswordLocal "+op, err)
		restore()
	}
}
