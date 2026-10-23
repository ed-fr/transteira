package adminauth

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// wantSessionUnchanged fails unless the session token still resolves to an
// authenticated session with the same ID and CSRF token as p.
func (ev *env) wantSessionUnchanged(t *testing.T, token string, p Principal) {
	t.Helper()
	got, err := ev.svc.Resolve(context.Background(), token)
	if err != nil || got.SessionID != p.SessionID || got.CSRFToken != p.CSRFToken || got.State != store.SessionAuthenticated {
		t.Errorf("session after ConfirmTOTP = %+v, %v; want %s unchanged", got, err, p.SessionID)
	}
}

func TestConfirmTOTP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		logins := ev.countAction(t, "admin.login")

		// The code of the enrollment step cannot be replayed.
		_, err := ev.svc.ConfirmTOTP(ctx, r.p, ev.code(r.secret), "", ipA)
		wantErr(t, "code of the login step", err, ErrInvalidCredentials)

		// The next code is accepted once.
		ev.nextStep()
		acc, err := ev.svc.ConfirmTOTP(ctx, r.p, ev.code(r.secret), "", ipA)
		if err != nil || acc.ID != r.p.Admin.ID || acc.Role != store.RoleSuperAdmin {
			t.Fatalf("ConfirmTOTP = %+v, %v", acc, err)
		}
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, ev.code(r.secret), "", ipA)
		wantErr(t, "replay within the step", err, ErrInvalidCredentials)
		ev.wantSessionUnchanged(t, r.sess.Token, r.p)

		// A recovery code is consumed and audited.
		if _, err := ev.svc.ConfirmTOTP(ctx, r.p, "", r.codes[0], ipA); err != nil {
			t.Fatalf("ConfirmTOTP(recovery) = %v", err)
		}
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, "", r.codes[0], ipA)
		wantErr(t, "used recovery code", err, ErrInvalidCredentials)
		if n := ev.countAction(t, "admin.recovery_code_used"); n != 1 {
			t.Errorf("audit admin.recovery_code_used: %d", n)
		}
		// No login is recorded and the session is untouched.
		if n := ev.countAction(t, "admin.login"); n != logins {
			t.Errorf("admin.login events = %d, want %d", n, logins)
		}
		ev.wantSessionUnchanged(t, r.sess.Token, r.p)
		lines := ev.logLines("admin_login_failed")
		if len(lines) != 3 || !strings.Contains(lines[0], `reason="totp"`) || !strings.Contains(lines[2], `reason="recovery_code"`) {
			t.Errorf("security log = %q", lines)
		}
		ev.assertNoSecretLogged(t, r.codes[0])

		// Input checks.
		_, err = ev.svc.ConfirmTOTP(ctx, Principal{}, "123456", "", ipA)
		wantErr(t, "no session", err, ErrUnauthenticated)
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.ConfirmTOTP(ctx, ev.mustResolve(t, sess.Token), "123456", "", ipA)
		wantErr(t, "intermediate session", err, ErrUnauthenticated)
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, "", "", ipA)
		wantInvalid(t, "no code", err, FieldCode)
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, "123456", r.codes[1], ipA)
		wantInvalid(t, "both codes", err, FieldCode)
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, "12a456", "", ipA)
		wantInvalid(t, "malformed code", err, FieldCode)
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, "", strings.Repeat("A", MaxRecoveryCodeLen+1), ipA)
		wantInvalid(t, "long recovery code", err, FieldRecoveryCode)
		_, err = ev.svc.ConfirmTOTP(ctx, r.p, "123456", "", netipZero)
		wantErr(t, "no client ip", err, ErrNoClientIP)

		// An administrator without TOTP cannot confirm.
		d := ev.mustDelegated(t, r, "alice", false, ev.a.ID)
		_, err = ev.svc.ConfirmTOTP(ctx, d.p, "123456", "", ipB)
		wantErr(t, "no totp", err, ErrForbidden)
	})
}

// wantSessionGone fails unless the session token no longer resolves.
func (ev *env) wantSessionGone(t *testing.T, token string) {
	t.Helper()
	_, err := ev.svc.Resolve(context.Background(), token)
	wantErr(t, "session after the last failure", err, ErrUnauthenticated)
}

// TestConfirmTOTPLockout checks that the confirmation shares the second
// factor lock of the login, and that its failures end the session like at
// the login.
func TestConfirmTOTPLockout(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		ev.nextStep()
		wrong := ev.wrongCode(r.secret)
		for range TOTPAdminMaxFailures - 1 {
			_, err := ev.svc.ConfirmTOTP(ctx, r.p, wrong, "", ipA)
			wantErr(t, "wrong code", err, ErrInvalidCredentials)
		}
		ev.wantSessionUnchanged(t, r.sess.Token, r.p)
		// The 5th failure sets the lock of the administrator and ends the
		// session (both limits are 5): it returns the lock.
		_, err := ev.svc.ConfirmTOTP(ctx, r.p, wrong, "", ipA)
		if rl := wantLimited(t, "5th wrong code", err); rl.RetryAfter != LoginLockDuration {
			t.Errorf("RetryAfter = %v", rl.RetryAfter)
		}
		ev.wantSessionGone(t, r.sess.Token)
		// Locked: even the right code is refused, at the login too.
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipB)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.VerifyTOTP(ctx, ev.mustResolve(t, sess.Token), ev.code(r.secret), "", ipB)
		_ = wantLimited(t, "login while locked", err)
		if n := len(ev.logLines("admin_login_failed")); n != TOTPAdminMaxFailures {
			t.Errorf("admin_login_failed events = %d", n)
		}
		// After the lock, a new session logs in and confirms.
		ev.clock.Advance(LoginLockDuration)
		p := ev.login(t, rootName, r.secret)
		ev.nextStep()
		if _, err := ev.svc.ConfirmTOTP(ctx, p, ev.code(r.secret), "", ipA); err != nil {
			t.Errorf("ConfirmTOTP after the lock = %v", err)
		}
	})
}

// TestConfirmTOTPEndsSession checks that MaxSessionTOTPFailures wrong
// confirmations end the session even when they are spread beyond the
// window of the per-administrator limit, so that a stolen session cannot
// guess codes for its whole lifetime.
func TestConfirmTOTPEndsSession(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		// A success does not reset the session counter.
		ev.nextStep()
		if _, err := ev.svc.ConfirmTOTP(ctx, r.p, ev.code(r.secret), "", ipA); err != nil {
			t.Fatal(err)
		}
		for i := range MaxSessionTOTPFailures {
			// Each failure falls in a new window of the administrator
			// limit; resolving keeps the session alive.
			ev.clock.Advance(LoginWindow)
			p := ev.mustResolve(t, r.sess.Token)
			_, err := ev.svc.ConfirmTOTP(ctx, p, ev.wrongCode(r.secret), "", ipA)
			wantErr(t, "wrong code", err, ErrInvalidCredentials)
			if i < MaxSessionTOTPFailures-1 {
				ev.wantSessionUnchanged(t, r.sess.Token, r.p)
			}
		}
		ev.wantSessionGone(t, r.sess.Token)
		// The second factor of the administrator is not locked.
		p := ev.login(t, rootName, r.secret)
		ev.nextStep()
		if _, err := ev.svc.ConfirmTOTP(ctx, p, ev.code(r.secret), "", ipA); err != nil {
			t.Errorf("ConfirmTOTP in a new session = %v", err)
		}
	})
}

func TestFaultsConfirmTOTP(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := ev.mustSetup(t)
	confirm := func(code, recovery string) error {
		t.Helper()
		ev.nextStep()
		_, err := ev.svc.ConfirmTOTP(ctx, r.p, code, recovery, ipA)
		return err
	}
	restore := ev.withRepo(func(rp repo) faultRepo {
		return faultRepo{repo: rp, fails: map[string]error{"admin": store.ErrNotFound}}
	})
	wantErr(t, "deleted admin", confirm("123456", ""), ErrUnauthenticated)
	restore()
	for _, op := range []string{"admin", "checkLogin", "advanceTOTP"} {
		restore := ev.withFaults(op)
		fails(t, op, confirm(ev.code(r.secret), ""))
		restore()
	}
	restore = ev.withFaults("consumeRecovery")
	fails(t, "consumeRecovery", confirm("", r.codes[0]))
	restore()
	// A failed audit write does not fail an accepted recovery code.
	restore = ev.withFaults("audit")
	if err := confirm("", r.codes[0]); err != nil {
		t.Errorf("ConfirmTOTP(recovery, audit fault) = %v", err)
	}
	restore()
	// The session counter cannot be updated.
	restore = ev.withFaults("totpFailure")
	_, err := ev.svc.ConfirmTOTP(ctx, r.p, ev.wrongCode(r.secret), "", ipA)
	fails(t, "count failure", err)
	restore()
}
