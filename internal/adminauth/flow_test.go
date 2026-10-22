package adminauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestSetupEnrollLoginLogout walks the whole life of the super admin:
// setup, enrollment, login, second factor, logout.
func TestSetupEnrollLoginLogout(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		required, err := ev.svc.SetupRequired(ctx)
		if err != nil || !required {
			t.Fatalf("SetupRequired = %v, %v, want true", required, err)
		}
		req := SetupRequest{Username: "Root", Email: "IT-Admin@Example.com", Password: rootPassword, SetupToken: "wrong"}
		_, err = ev.svc.CreateSuperAdmin(ctx, req, ipA)
		wantErr(t, "setup with a wrong token", err, ErrSetupTokenInvalid)
		req.SetupToken = ""
		_, err = ev.svc.CreateSuperAdmin(ctx, req, ipA)
		wantErr(t, "setup without token", err, ErrSetupTokenInvalid)
		// Each wrong setup token is a security event, counted by the
		// fail2ban and CrowdSec integrations like a wrong password.
		if lines := ev.logLines("admin_login_failed"); len(lines) != 2 || !strings.Contains(lines[0], `reason="setup_token"`) ||
			!strings.Contains(lines[0], "ip=192.0.2.10") || !strings.Contains(lines[0], "tenant=-") {
			t.Errorf("security log after wrong setup tokens = %q", lines)
		}
		for field, mutate := range map[string]func(*SetupRequest){
			FieldUsername: func(r *SetupRequest) { r.Username = "x" },
			FieldEmail:    func(r *SetupRequest) { r.Email = "not-an-address" },
			FieldPassword: func(r *SetupRequest) { r.Password = "short" },
		} {
			bad := SetupRequest{Username: "root", Email: "it-admin@example.com", Password: rootPassword, SetupToken: setupToken}
			mutate(&bad)
			_, err := ev.svc.CreateSuperAdmin(ctx, bad, ipA)
			wantInvalid(t, "setup "+field, err, field)
		}

		req.SetupToken = setupToken
		res, err := ev.svc.CreateSuperAdmin(ctx, req, ipA)
		if err != nil {
			t.Fatalf("CreateSuperAdmin = %v", err)
		}
		if res.Session.State != store.SessionTOTPEnrollmentRequired || !strings.HasPrefix(res.Session.Token, "as_") ||
			!strings.HasPrefix(res.Session.CSRFToken, CSRFPrefix) || !res.Session.ExpiresAt.Equal(testStart.Add(DefaultMaxAge)) ||
			!res.Session.StateExpiresAt.Equal(testStart.Add(DefaultStateTTL)) {
			t.Errorf("setup session = %+v", res.Session)
		}
		if !strings.HasPrefix(res.Enrollment.URI, "otpauth://totp/TransTeira:root?secret="+res.Enrollment.Secret) ||
			!bytes.HasPrefix(res.Enrollment.QRPNG, []byte("\x89PNG")) {
			t.Errorf("enrollment = %q, %d bytes of png", res.Enrollment.URI, len(res.Enrollment.QRPNG))
		}
		if required, err := ev.svc.SetupRequired(ctx); err != nil || required {
			t.Errorf("SetupRequired after setup = %v, %v", required, err)
		}
		_, err = ev.svc.CreateSuperAdmin(ctx, req, ipA)
		wantErr(t, "second setup", err, ErrSetupDone)

		// The pre-auth session only opens the enrollment.
		p := ev.mustResolve(t, res.Session.Token)
		if p.State != store.SessionTOTPEnrollmentRequired || p.CSRFToken != res.Session.CSRFToken ||
			p.Admin.Username != "root" || p.Admin.Email != "it-admin@example.com" || p.Admin.Role != store.RoleSuperAdmin ||
			!p.Admin.RequireTOTP || p.Admin.TOTPEnabled || !p.Admin.Activated {
			t.Errorf("setup principal = %+v", p)
		}
		wantErr(t, "RequireAuthenticated(enrollment)", RequireAuthenticated(p), ErrUnauthenticated)
		_, err = ev.svc.List(ctx, p, "", 0)
		wantErr(t, "List(enrollment)", err, ErrUnauthenticated)
		_, err = ev.svc.VerifyTOTP(ctx, p, "123456", "", ipA)
		wantErr(t, "VerifyTOTP(enrollment)", err, ErrUnauthenticated)
		wantErr(t, "ChangePassword(enrollment)", ev.svc.ChangePassword(ctx, p, rootPassword, newPassword, ipA), ErrUnauthenticated)

		// Restarting the enrollment replaces the pending secret.
		enr, err := ev.svc.StartEnrollment(ctx, p, "", ipA)
		if err != nil || enr.Secret == res.Enrollment.Secret {
			t.Fatalf("StartEnrollment = %v (same secret: %v)", err, enr.Secret == res.Enrollment.Secret)
		}
		old := decodeSecret(t, res.Enrollment)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, ev.code(old), ipA)
		wantErr(t, "confirm with the replaced secret", err, ErrInvalidCredentials)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, "12345", ipA)
		wantInvalid(t, "confirm with a malformed code", err, FieldCode)
		secret := decodeSecret(t, enr)
		conf, err := ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipA)
		if err != nil {
			t.Fatalf("ConfirmEnrollment = %v", err)
		}
		if len(conf.RecoveryCodes) != RecoveryCodeCount || conf.Session == nil ||
			conf.Session.State != store.SessionAuthenticated || conf.Session.Token == res.Session.Token ||
			conf.Session.CSRFToken == res.Session.CSRFToken {
			t.Fatalf("Confirmed = %+v", conf)
		}
		// Rotation: the setup token is dead, the new one is authenticated.
		_, err = ev.svc.Resolve(ctx, res.Session.Token)
		wantErr(t, "Resolve(old token)", err, ErrUnauthenticated)
		p = ev.mustResolve(t, conf.Session.Token)
		if err := RequireAuthenticated(p); err != nil || !p.Admin.TOTPEnabled || p.Admin.LastLoginAt.IsZero() {
			t.Errorf("after confirmation: %v, %+v", err, p.Admin)
		}
		if !ev.svc.CheckCSRF(conf.Session.Token, p.CSRFToken) || ev.svc.CheckCSRF(res.Session.Token, p.CSRFToken) {
			t.Error("CheckCSRF does not follow the rotation")
		}
		if n, err := ev.db.AdminRecoveryCodes().CountUnused(ctx, p.Admin.ID); err != nil || n != RecoveryCodeCount {
			t.Errorf("CountUnused = %d, %v", n, err)
		}

		// Logout, then a login asks for the second factor.
		if err := ev.svc.Logout(ctx, p, ipA); err != nil {
			t.Fatalf("Logout = %v", err)
		}
		wantErr(t, "Logout again", ev.svc.Logout(ctx, p, ipA), ErrUnauthenticated)
		_, err = ev.svc.Resolve(ctx, conf.Session.Token)
		wantErr(t, "Resolve after logout", err, ErrUnauthenticated)

		sess, err := ev.svc.Login(ctx, "ROOT", rootPassword, ipA)
		if err != nil || sess.State != store.SessionTOTPRequired {
			t.Fatalf("Login = %+v, %v", sess, err)
		}
		p = ev.mustResolve(t, sess.Token)
		wantErr(t, "RequireAuthenticated(totp_required)", RequireAuthenticated(p), ErrUnauthenticated)
		_, err = ev.svc.StartEnrollment(ctx, p, rootPassword, ipA)
		wantErr(t, "StartEnrollment(totp_required)", err, ErrUnauthenticated)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, "123456", ipA)
		wantErr(t, "ConfirmEnrollment(totp_required)", err, ErrUnauthenticated)

		// The confirmation code cannot be replayed (same step).
		_, err = ev.svc.VerifyTOTP(ctx, p, ev.code(secret), "", ipA)
		wantErr(t, "replayed code", err, ErrInvalidCredentials)
		ev.nextStep()
		auth, err := ev.svc.VerifyTOTP(ctx, p, ev.code(secret), "", ipA)
		if err != nil || auth.State != store.SessionAuthenticated || auth.Token == sess.Token || !auth.StateExpiresAt.IsZero() {
			t.Fatalf("VerifyTOTP = %+v, %v", auth, err)
		}
		_, err = ev.svc.Resolve(ctx, sess.Token)
		wantErr(t, "Resolve(pre-auth token)", err, ErrUnauthenticated)
		p = ev.mustResolve(t, auth.Token)
		if err := RequireAuthenticated(p); err != nil {
			t.Error(err)
		}
		// Replaying the code of that step on a new login fails too.
		sess2, err := ev.svc.Login(ctx, "root", rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.VerifyTOTP(ctx, ev.mustResolve(t, sess2.Token), ev.code(secret), "", ipA)
		wantErr(t, "replay on another session", err, ErrInvalidCredentials)

		for _, action := range []string{"setup.completed", "admin.totp_enrolled", "admin.logout"} {
			if n := ev.countAction(t, action); n != 1 {
				t.Errorf("audit %s: %d events, want 1", action, n)
			}
		}
		if n := ev.countAction(t, "admin.login"); n != 2 {
			t.Errorf("audit admin.login: %d events, want 2", n)
		}
		// The wrong confirmation code counts as a second factor failure.
		if n := ev.countAction(t, "admin.login_failed"); n != 3 {
			t.Errorf("audit admin.login_failed: %d events, want 3", n)
		}
		if lines := ev.logLines("admin_login_failed"); len(lines) != 5 || !strings.Contains(lines[2], `reason="totp"`) {
			t.Errorf("security log = %q", lines)
		}
		ev.assertNoSecretLogged(t, rootPassword, enr.Secret, "wrong")
	})
}

// assertNoSecretLogged fails when a log holds one of secrets.
func (ev *env) assertNoSecretLogged(t *testing.T, secrets ...string) {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	all.WriteString(ev.seclog.String())
	all.WriteString(ev.applog.String())
	for _, e := range page.Items {
		all.Write(e.Details)
	}
	for _, s := range secrets {
		if strings.Contains(all.String(), s) {
			t.Errorf("a secret appears in the logs")
		}
	}
}

// TestRecoveryCodes checks that a recovery code replaces the TOTP code
// once.
func TestRecoveryCodes(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)

		login := func() Principal {
			t.Helper()
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
		p := login()
		// Lower case and without dashes is accepted.
		typed := strings.ToLower(strings.ReplaceAll(r.codes[0], "-", ""))
		sess, err := ev.svc.VerifyTOTP(ctx, p, "", typed, ipA)
		if err != nil || sess.State != store.SessionAuthenticated {
			t.Fatalf("VerifyTOTP(recovery) = %+v, %v", sess, err)
		}
		_, err = ev.svc.VerifyTOTP(ctx, login(), "", r.codes[0], ipA)
		wantErr(t, "used recovery code", err, ErrInvalidCredentials)
		_, err = ev.svc.VerifyTOTP(ctx, login(), "", "not a code", ipA)
		wantErr(t, "malformed recovery code", err, ErrInvalidCredentials)
		if n := ev.countAction(t, "admin.recovery_code_used"); n != 1 {
			t.Errorf("audit admin.recovery_code_used: %d", n)
		}
		if lines := ev.logLines("admin_login_failed"); len(lines) != 2 || !strings.Contains(lines[0], `reason="recovery_code"`) {
			t.Errorf("security log = %q", lines)
		}
		// Input checks.
		p = login()
		_, err = ev.svc.VerifyTOTP(ctx, p, "", "", ipA)
		wantInvalid(t, "no code", err, FieldCode)
		_, err = ev.svc.VerifyTOTP(ctx, p, "123456", r.codes[1], ipA)
		wantInvalid(t, "both codes", err, FieldCode)
		_, err = ev.svc.VerifyTOTP(ctx, p, "12a456", "", ipA)
		wantInvalid(t, "malformed code", err, FieldCode)
		_, err = ev.svc.VerifyTOTP(ctx, p, "", strings.Repeat("A", MaxRecoveryCodeLen+1), ipA)
		wantInvalid(t, "long recovery code", err, FieldRecoveryCode)
		_, err = ev.svc.VerifyTOTP(ctx, p, "123456", "", netipZero)
		wantErr(t, "no client ip", err, ErrNoClientIP)
		ev.assertNoSecretLogged(t, r.codes[0], r.codes[1])

		// The stored values are MACs keyed by the TOTP secret, not plain
		// SHA-256 hashes of the codes.
		want, err := crypto.RecoveryCodeMAC(r.secret, r.codes[2])
		if err != nil {
			t.Fatal(err)
		}
		plain := sha256.Sum256([]byte(r.codes[2]))
		if ok, err := ev.db.AdminRecoveryCodes().Consume(ctx, r.p.Admin.ID, plain[:], ev.clock.Now()); err != nil || ok {
			t.Errorf("an unkeyed hash is accepted: %v, %v", ok, err)
		}
		if ok, err := ev.db.AdminRecoveryCodes().Consume(ctx, r.p.Admin.ID, want, ev.clock.Now()); err != nil || !ok {
			t.Errorf("the keyed MAC is not stored: %v, %v", ok, err)
		}
	})
}

// TestTOTPFailures checks the end of a session after 5 wrong codes and the
// lock of the second factor of an administrator across sessions.
func TestTOTPFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		ev.nextStep()
		wrong := ev.wrongCode(r.secret)
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		p := ev.mustResolve(t, sess.Token)
		for range TOTPAdminMaxFailures - 1 {
			_, err := ev.svc.VerifyTOTP(ctx, p, wrong, "", ipA)
			wantErr(t, "wrong code", err, ErrInvalidCredentials)
		}
		// The 5th failure locks the second factor of the admin and ends
		// the session.
		_, err = ev.svc.VerifyTOTP(ctx, p, wrong, "", ipA)
		rl := wantLimited(t, "5th wrong code", err)
		if rl.RetryAfter != LoginLockDuration {
			t.Errorf("RetryAfter = %v", rl.RetryAfter)
		}
		_, err = ev.svc.Resolve(ctx, sess.Token)
		wantErr(t, "Resolve after 5 wrong codes", err, ErrUnauthenticated)
		// The lock follows the admin to another session and IP, even with
		// the right code; the password step is not locked.
		sess, err = ev.svc.Login(ctx, rootName, rootPassword, ipB)
		if err != nil {
			t.Fatalf("Login from another IP = %v", err)
		}
		p = ev.mustResolve(t, sess.Token)
		_, err = ev.svc.VerifyTOTP(ctx, p, ev.code(r.secret), "", ipB)
		_ = wantLimited(t, "right code while locked", err)
		if n := len(ev.logLines("rate_limited")); n != 2 {
			t.Errorf("rate_limited events = %d, want 2", n)
		}
		// After the lock, the right code works.
		ev.clock.Advance(LoginLockDuration)
		sess, err = ev.svc.Login(ctx, rootName, rootPassword, ipB)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.VerifyTOTP(ctx, ev.mustResolve(t, sess.Token), ev.code(r.secret), "", ipB); err != nil {
			t.Errorf("VerifyTOTP after the lock = %v", err)
		}
	})
}

// TestLoginLimits checks the locks per (username, IP) and per IP.
func TestLoginLimits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.mustSetup(t)

		for range LoginUserIPMaxFailures - 1 {
			_, err := ev.svc.Login(ctx, rootName, "wrong password", ipA)
			wantErr(t, "wrong password", err, ErrInvalidCredentials)
		}
		// The 5th failure locks (root, ipA).
		_, err := ev.svc.Login(ctx, "Root", "wrong password", ipA)
		if rl := wantLimited(t, "5th failure", err); rl.RetryAfter != LoginLockDuration {
			t.Errorf("RetryAfter = %v", rl.RetryAfter)
		}
		// Locked, even with the right password, and without hashing.
		before := ev.hasher.count(fakeHash(rootPassword))
		ev.clock.Advance(time.Minute)
		_, err = ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if rl := wantLimited(t, "right password while locked", err); rl.RetryAfter != LoginLockDuration-time.Minute {
			t.Errorf("RetryAfter = %v", rl.RetryAfter)
		}
		if ev.hasher.count(fakeHash(rootPassword)) != before {
			t.Error("a locked login verified the password")
		}
		// Another IP is not locked.
		if _, err := ev.svc.Login(ctx, rootName, rootPassword, ipB); err != nil {
			t.Errorf("Login from another IP = %v", err)
		}
		if n := len(ev.logLines("admin_login_failed")); n != 5 {
			t.Errorf("admin_login_failed events = %d, want 5", n)
		}
		if lines := ev.logLines("rate_limited"); len(lines) != 2 || !strings.Contains(lines[0], `scope="admin_login"`) ||
			!strings.Contains(lines[0], "ip=192.0.2.10") {
			t.Errorf("rate_limited events = %q", lines)
		}
		// The lock ends after LoginLockDuration.
		ev.clock.Advance(LoginLockDuration)
		if _, err := ev.svc.Login(ctx, rootName, rootPassword, ipA); err != nil {
			t.Errorf("Login after the lock = %v", err)
		}

		// A success resets the (username, IP) counter: 4 more failures do
		// not lock.
		for range LoginUserIPMaxFailures - 1 {
			_, err := ev.svc.Login(ctx, rootName, "wrong password", ipA)
			wantErr(t, "wrong password after success", err, ErrInvalidCredentials)
		}
		if _, err := ev.svc.Login(ctx, rootName, rootPassword, ipA); err != nil {
			t.Errorf("Login = %v", err)
		}

		// 20 failures per IP, any usernames, lock the IP.
		ev.clock.Advance(LoginWindow)
		for i := range LoginIPMaxFailures - 1 {
			_, err := ev.svc.Login(ctx, "user"+string(rune('a'+i)), "wrong password", ipB)
			wantErr(t, "unknown user", err, ErrInvalidCredentials)
		}
		_, err = ev.svc.Login(ctx, "another-user", "wrong password", ipB)
		_ = wantLimited(t, "20th failure of the IP", err)
		_, err = ev.svc.Login(ctx, rootName, rootPassword, ipB)
		_ = wantLimited(t, "root from the locked IP", err)
		if _, err := ev.svc.Login(ctx, rootName, rootPassword, ipA); err != nil {
			t.Errorf("Login from ipA = %v", err)
		}
		// Every counted failure reaches the audit log, unknown usernames
		// included, under the actor "unknown": the typed name (often a
		// password typed in the wrong field) is never recorded.
		if n := ev.countAction(t, "admin.login_failed"); n != 2*LoginUserIPMaxFailures-1+LoginIPMaxFailures {
			t.Errorf("audit admin.login_failed = %d", n)
		}
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: "admin.login_failed", Actor: "another-user"})
		if err != nil || len(page.Items) != 0 {
			t.Errorf("audit under a typed unknown username = %+v, %v", page.Items, err)
		}
		page, err = ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: "admin.login_failed", Actor: "unknown", Limit: store.MaxPageSize})
		if err != nil || len(page.Items) != LoginIPMaxFailures {
			t.Fatalf("audit of unknown usernames = %d, %v", len(page.Items), err)
		}
		for _, it := range page.Items {
			if it.ObjectID != "unknown" || strings.Contains(string(it.Details), "user") {
				t.Errorf("audit of an unknown username = %+v (%s)", it, it.Details)
			}
		}
		ev.assertNoSecretLogged(t, "another-user", "usera")
	})
}

// TestSessionExpiry checks the idle timeout, the absolute expiry and the
// expiry of the intermediate states.
func TestSessionExpiry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)

		// Sliding idle timeout: used every 20 minutes, the session lives
		// until its maximum age.
		token := r.sess.Token
		for elapsed := time.Duration(0); elapsed+20*time.Minute < DefaultMaxAge; elapsed += 20 * time.Minute {
			ev.clock.Advance(20 * time.Minute)
			ev.mustResolve(t, token)
		}
		ev.clock.Advance(20 * time.Minute)
		_, err := ev.svc.Resolve(ctx, token)
		wantErr(t, "Resolve past the maximum age", err, ErrUnauthenticated)

		// Idle for 30 minutes: ended.
		ev.nextStep()
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		auth, err := ev.svc.VerifyTOTP(ctx, ev.mustResolve(t, sess.Token), ev.code(r.secret), "", ipA)
		if err != nil {
			t.Fatal(err)
		}
		ev.clock.Advance(DefaultIdleTimeout)
		_, err = ev.svc.Resolve(ctx, auth.Token)
		wantErr(t, "Resolve after the idle timeout", err, ErrUnauthenticated)

		// An intermediate state ends after 5 minutes, even when used.
		sess, err = ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		ev.clock.Advance(DefaultStateTTL - time.Second)
		p := ev.mustResolve(t, sess.Token)
		ev.clock.Advance(time.Second)
		_, err = ev.svc.Resolve(ctx, sess.Token)
		wantErr(t, "Resolve past the state expiry", err, ErrUnauthenticated)
		ev.nextStep()
		_, err = ev.svc.VerifyTOTP(ctx, p, ev.code(r.secret), "", ipA)
		wantErr(t, "VerifyTOTP past the state expiry", err, ErrUnauthenticated)

		// Malformed tokens.
		for _, tok := range []string{"", "as_short", "ds_" + strings.Repeat("a", 43), strings.Repeat("a", 46)} {
			_, err := ev.svc.Resolve(ctx, tok)
			wantErr(t, "Resolve(malformed)", err, ErrUnauthenticated)
		}
		_, err = ev.svc.Resolve(ctx, "as_"+strings.Repeat("a", 43))
		wantErr(t, "Resolve(unknown)", err, ErrUnauthenticated)
	})
}

// TestPasswordChange checks the password change and the revocation of the
// other sessions.
func TestPasswordChange(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		ev.nextStep()
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipB)
		if err != nil {
			t.Fatal(err)
		}
		other, err := ev.svc.VerifyTOTP(ctx, ev.mustResolve(t, sess.Token), ev.code(r.secret), "", ipB)
		if err != nil {
			t.Fatal(err)
		}

		err = ev.svc.ChangePassword(ctx, r.p, "wrong password", newPassword, ipA)
		wantErr(t, "wrong current password", err, ErrInvalidCredentials)
		wantInvalid(t, "short new password", ev.svc.ChangePassword(ctx, r.p, rootPassword, "short", ipA), FieldNewPassword)
		wantInvalid(t, "long new password",
			ev.svc.ChangePassword(ctx, r.p, rootPassword, strings.Repeat("é", MaxPasswordLen+1), ipA), FieldNewPassword)
		wantInvalid(t, "long current password",
			ev.svc.ChangePassword(ctx, r.p, strings.Repeat("x", MaxPasswordLen+1), newPassword, ipA), FieldCurrentPassword)
		wantErr(t, "no client ip", ev.svc.ChangePassword(ctx, r.p, rootPassword, newPassword, netipZero), ErrNoClientIP)
		// 12 characters, counted as runes, are enough.
		if err := ev.svc.ChangePassword(ctx, r.p, rootPassword, strings.Repeat("é", MinPasswordLen), ipA); err != nil {
			t.Fatalf("ChangePassword(12 runes) = %v", err)
		}
		if err := ev.svc.ChangePassword(ctx, r.p, strings.Repeat("é", MinPasswordLen), newPassword, ipA); err != nil {
			t.Fatalf("ChangePassword = %v", err)
		}
		ev.mustResolve(t, r.sess.Token)
		_, err = ev.svc.Resolve(ctx, other.Token)
		wantErr(t, "other session after a password change", err, ErrUnauthenticated)
		_, err = ev.svc.Login(ctx, rootName, rootPassword, ipA)
		wantErr(t, "login with the old password", err, ErrInvalidCredentials)
		if _, err := ev.svc.Login(ctx, rootName, newPassword, ipA); err != nil {
			t.Errorf("login with the new password = %v", err)
		}
		if n := ev.countAction(t, "admin.password_changed"); n != 2 {
			t.Errorf("audit admin.password_changed = %d", n)
		}
		ev.assertNoSecretLogged(t, rootPassword, newPassword)
	})
}

// TestTOTPManagement checks the TOTP disabling rules and re-enrollment.
func TestTOTPManagement(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)

		wantErr(t, "DisableTOTP(super admin)", ev.svc.DisableTOTP(ctx, r.p, rootPassword, ipA), ErrForbidden)

		// A delegated admin without TOTP requirement logs in with the
		// password only, may enroll, then disable.
		d := ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)
		if d.p.State != store.SessionAuthenticated {
			t.Fatalf("activation state = %s", d.p.State)
		}
		sess, err := ev.svc.Login(ctx, "admin.a", rootPassword, ipB)
		if err != nil || sess.State != store.SessionAuthenticated {
			t.Fatalf("Login(no totp) = %+v, %v", sess, err)
		}
		p := ev.mustResolve(t, sess.Token)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, "123456", ipB)
		wantErr(t, "confirm without enrollment", err, ErrNoPendingEnrollment)
		// A first enrollment keeps the other sessions.
		firstOther := mustToken(t, ev, "admin.a")
		_, conf := ev.mustEnroll(t, p)
		if conf.Session != nil || len(conf.RecoveryCodes) != RecoveryCodeCount {
			t.Fatalf("ConfirmEnrollment(authenticated) = %+v, %v", conf, err)
		}
		ev.mustResolve(t, sess.Token) // not rotated
		ev.mustResolve(t, firstOther)

		// Re-enrollment needs the current password and revokes the other
		// sessions once confirmed.
		p = ev.mustResolve(t, sess.Token)
		_, err = ev.svc.StartEnrollment(ctx, p, "", ipB)
		wantInvalid(t, "re-enroll without password", err, FieldCurrentPassword)
		_, err = ev.svc.StartEnrollment(ctx, p, "wrong password", ipB)
		wantErr(t, "re-enroll with a wrong password", err, ErrInvalidCredentials)
		_, err = ev.svc.StartEnrollment(ctx, p, strings.Repeat("x", MaxPasswordLen+1), ipB)
		wantInvalid(t, "re-enroll with a long password", err, FieldCurrentPassword)
		_, err = ev.svc.StartEnrollment(ctx, p, rootPassword, netipZero)
		wantErr(t, "re-enroll without client ip", err, ErrNoClientIP)
		ev.nextStep()
		otherSess, err := ev.svc.Login(ctx, "admin.a", rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		enr, err := ev.svc.StartEnrollment(ctx, p, rootPassword, ipB)
		if err != nil {
			t.Fatalf("re-enroll = %v", err)
		}
		// The old TOTP stays in use until the confirmation.
		ev.mustResolve(t, otherSess.Token)
		newSecret := decodeSecret(t, enr)
		conf, err = ev.svc.ConfirmEnrollment(ctx, p, ev.code(newSecret), ipB)
		if err != nil || conf.Session != nil || len(conf.RecoveryCodes) != RecoveryCodeCount {
			t.Fatalf("ConfirmEnrollment(re-enrollment) = %+v, %v", conf, err)
		}
		ev.mustResolve(t, sess.Token)
		for _, tok := range []string{otherSess.Token, firstOther} {
			_, err = ev.svc.Resolve(ctx, tok)
			wantErr(t, "other session after a re-enrollment", err, ErrUnauthenticated)
		}
		if lines := ev.logLines("admin_login_failed"); len(lines) != 1 || !strings.Contains(lines[0], `reason="password"`) {
			t.Errorf("security log after a wrong re-enrollment password = %q", lines)
		}
		pTok := sess.Token
		ev.nextStep()
		sess, err = ev.svc.Login(ctx, "admin.a", rootPassword, ipB)
		if err != nil || sess.State != store.SessionTOTPRequired {
			t.Fatalf("Login(totp) = %+v, %v", sess, err)
		}
		err = ev.svc.DisableTOTP(ctx, p, "wrong password", ipB)
		wantErr(t, "DisableTOTP(wrong password)", err, ErrInvalidCredentials)
		if err := ev.svc.DisableTOTP(ctx, p, rootPassword, ipB); err != nil {
			t.Fatalf("DisableTOTP = %v", err)
		}
		// The other sessions (here the pre-auth one) are revoked, p stays.
		ev.mustResolve(t, pTok)
		_, err = ev.svc.Resolve(ctx, sess.Token)
		wantErr(t, "other session after disabling totp", err, ErrUnauthenticated)
		if n, _ := ev.db.AdminRecoveryCodes().CountUnused(ctx, p.Admin.ID); n != 0 {
			t.Errorf("recovery codes after disabling = %d", n)
		}
		sess, err = ev.svc.Login(ctx, "admin.a", rootPassword, ipB)
		if err != nil || sess.State != store.SessionAuthenticated {
			t.Errorf("Login after disabling = %+v, %v", sess, err)
		}
		// Made mandatory meanwhile (stale principal): refused.
		p = ev.mustResolve(t, sess.Token)
		wantErr(t, "DisableTOTP(intermediate)", ev.svc.DisableTOTP(ctx, Principal{}, rootPassword, ipB), ErrUnauthenticated)
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{RequireTOTP: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "DisableTOTP(stale principal)", ev.svc.DisableTOTP(ctx, p, rootPassword, ipB), ErrForbidden)
		p.Admin.RequireTOTP = true
		wantErr(t, "DisableTOTP(required)", ev.svc.DisableTOTP(ctx, p, rootPassword, ipB), ErrForbidden)
		if n := ev.countAction(t, "admin.totp_disabled"); n != 1 {
			t.Errorf("audit admin.totp_disabled = %d", n)
		}
	})
}

// netipZero is the zero client IP.
var netipZero netip.Addr

func ptr[T any](v T) *T { return &v }

// TestEnrollmentProtections checks the protections of the TOTP enrollment
// from an authenticated session: the current password, the expiry of the
// pending secret and the limits of the confirmation.
func TestEnrollmentProtections(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		d := ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)
		p := d.p

		// A first enrollment from an authenticated session needs the
		// current password.
		_, err := ev.svc.StartEnrollment(ctx, p, "", ipB)
		wantInvalid(t, "first enrollment without password", err, FieldCurrentPassword)
		_, err = ev.svc.StartEnrollment(ctx, p, "wrong password", ipB)
		wantErr(t, "first enrollment with a wrong password", err, ErrInvalidCredentials)

		// The pending secret expires after PendingTOTPTTL.
		enr, err := ev.svc.StartEnrollment(ctx, p, rootPassword, ipB)
		if err != nil {
			t.Fatalf("StartEnrollment = %v", err)
		}
		secret := decodeSecret(t, enr)
		ev.clock.Advance(PendingTOTPTTL + time.Second)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipB)
		wantErr(t, "confirm an expired secret", err, ErrNoPendingEnrollment)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), netipZero)
		wantErr(t, "confirm without client ip", err, ErrNoClientIP)

		// Five wrong codes lock the second factor of the account, the
		// right code included.
		p = ev.mustResolve(t, mustToken(t, ev, "admin.a"))
		enr, err = ev.svc.StartEnrollment(ctx, p, rootPassword, ipB)
		if err != nil {
			t.Fatalf("StartEnrollment(restart) = %v", err)
		}
		secret = decodeSecret(t, enr)
		for i := 1; i < TOTPAdminMaxFailures; i++ {
			_, err = ev.svc.ConfirmEnrollment(ctx, p, ev.wrongCode(secret), ipB)
			wantErr(t, "wrong confirmation code", err, ErrInvalidCredentials)
		}
		_, err = ev.svc.ConfirmEnrollment(ctx, p, ev.wrongCode(secret), ipB)
		wantErr(t, "last wrong confirmation code", err, ErrRateLimited)
		_, err = ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipB)
		wantErr(t, "right code while locked", err, ErrRateLimited)
		if a, err := ev.db.Admins().Get(ctx, p.Admin.ID); err != nil || a.TOTPEnabled {
			t.Fatalf("admin after the lock = %+v, %v", a, err)
		}
		totp := 0
		for _, l := range ev.logLines("admin_login_failed") {
			if strings.Contains(l, `reason="totp"`) {
				totp++
			}
		}
		if totp != TOTPAdminMaxFailures || len(ev.logLines("rate_limited")) < 2 {
			t.Errorf("security log = %q", ev.seclog.String())
		}
		// The wrong password and the wrong codes are audited.
		if n := ev.countAction(t, "admin.login_failed"); n != 1+TOTPAdminMaxFailures {
			t.Errorf("audit admin.login_failed: %d events, want %d", n, 1+TOTPAdminMaxFailures)
		}

		// Once the lock is over, a new enrollment is confirmed.
		ev.clock.Advance(LoginLockDuration)
		p = ev.mustResolve(t, mustToken(t, ev, "admin.a"))
		ev.mustEnroll(t, p)
	})
}
