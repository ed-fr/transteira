package integration_test

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the administrator authentication through the real
// HTTP server on the admin host, with real cookies, on SQLite and
// PostgreSQL (CLAUDE.md sections 6.5, 6.6, 16.2 and 16.3; threat model
// T-58 to T-67 and T-102; docs/operations/admin.md). The time-based rules
// (session idle timeout, absolute lifetime, intermediate state lifetime)
// are exercised by aging the session rows in the database: the minimum
// TT_ADMIN_SESSION_* values (5 minutes and 1 hour) are too long for a test
// and the server exposes no clock.

// generatedTokenRE extracts the setup token the application generates and
// logs while no administrator exists and TT_SETUP_TOKEN is not set.
var generatedTokenRE = regexp.MustCompile(`Setup token: (stp_[0-9A-Za-z]+)`)

// TestAdminSetup covers the first-run setup (CLAUDE.md section 6.6) with
// the token generated and logged by the application: refused without a
// token or with a wrong one; with the token, a session that only opens the
// TOTP confirmation; the confirmation yields 8 recovery codes and a
// rotated, authenticated session; a second setup is refused.
func TestAdminSetup(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{env: map[string]string{config.EnvSetupToken: ""}}, false)
		m := generatedTokenRE.FindStringSubmatch(a.appLog.String())
		if m == nil {
			t.Fatalf("no generated setup token in the application log:\n%s", a.appLog)
		}
		token := m[1]

		status := func() bool {
			t.Helper()
			resp := a.client(nil, adminIP(1)).send(t, http.MethodGet, pathAdminSetup, nil, nil)
			if resp.status != http.StatusOK {
				t.Fatalf("getSetupStatus: %d %s", resp.status, resp.body)
			}
			var st struct {
				SetupRequired *bool `json:"setupRequired"`
			}
			mustJSON(t, resp.body, &st)
			if st.SetupRequired == nil {
				t.Fatalf("getSetupStatus without setupRequired: %s", resp.body)
			}
			if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("admin host Cache-Control = %q, want no-store", cc)
			}
			return *st.SetupRequired
		}
		if !status() {
			t.Fatal("setupRequired = false before the setup")
		}

		acct := &adminAccount{username: superName, email: "root@" + domainA, password: superPassword}
		c := a.client(acct, adminIP(10))
		for _, tc := range []struct{ name, token string }{
			{"no token", ""},
			{"wrong token", "stp_wrong-token-0123456789"},
			{"configured-looking token", adminSetupToken},
			{"token prefix", token[:len(token)-1]},
		} {
			resp := c.setup(t, acct.username, acct.email, acct.password, tc.token)
			expectProblem(t, resp, http.StatusForbidden, "setup-token-invalid")
			if _, set := sessionCookie(t, resp); set {
				t.Errorf("%s: a refused setup set a session cookie", tc.name)
			}
		}
		if !status() {
			t.Fatal("a refused setup created an administrator")
		}
		// Each wrong setup token is a security event (counted by the
		// fail2ban and CrowdSec integrations like a wrong password).
		a.waitLogLines(t, "admin_login_failed", adminIP(10), `reason="setup_token"`, 4)

		resp := c.setup(t, acct.username, acct.email, acct.password, token)
		if resp.status != http.StatusCreated {
			t.Fatalf("setup with the token: %d %s", resp.status, resp.body)
		}
		var enr enrollmentJSON
		mustJSON(t, resp.body, &enr)
		if !strings.HasPrefix(enr.OtpauthURI, "otpauth://totp/") || !strings.Contains(enr.OtpauthURI, "secret="+enr.Secret) ||
			len(enr.QRCodePNG) == 0 || !strings.HasPrefix(enr.CSRFToken, "csrf_") {
			t.Errorf("setup enrollment = uri %q, %d PNG bytes, csrf %q", enr.OtpauthURI, len(enr.QRCodePNG), enr.CSRFToken)
		}
		if ck, _ := sessionCookie(t, resp); ck != nil && ck.MaxAge > 300 {
			t.Errorf("enrollment session cookie Max-Age = %d, want at most the 5-minute state lifetime", ck.MaxAge)
		}
		c.adopt(t, resp, enr.CSRFToken, stateEnrollRequired)
		acct.secret = decodeSecret(t, enr.Secret)
		a.secret(enr.Secret)
		setupCookie := c.cookie

		// The enrollment session opens nothing but the TOTP confirmation.
		for _, r := range []struct{ method, path string }{
			{http.MethodGet, pathAdminMe},
			{http.MethodGet, pathAdmins},
			{http.MethodPost, pathAdmins},
			{http.MethodPut, pathAdminPassword},
			{http.MethodPost, pathAdminTOTP},
		} {
			var resp response
			if r.method == http.MethodGet {
				resp = c.send(t, r.method, r.path, nil, nil)
			} else {
				resp = c.call(t, r.method, r.path, map[string]string{})
			}
			expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
			// The session is valid, only not in the right state: it keeps
			// its cookie.
			if _, set := sessionCookie(t, resp); set {
				t.Errorf("%s %s in state %s touched the session cookie", r.method, r.path, stateEnrollRequired)
			}
		}
		// A wrong code keeps the session (the step may be retried).
		resp = c.confirm(t, acct.wrongCode(t))
		expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		if _, set := sessionCookie(t, resp); set {
			t.Error("a wrong enrollment code changed the session cookie")
		}

		resp = c.confirm(t, acct.nextCode(t))
		if resp.status != http.StatusOK {
			t.Fatalf("confirm: %d %s", resp.status, resp.body)
		}
		if c.cookie == setupCookie || c.state != stateAuthenticated || c.csrf == enr.CSRFToken {
			t.Fatalf("confirm did not rotate the session (state %s)", c.state)
		}
		me := c.me(t)
		acct.id = me.ID
		if me.Username != superName || me.Role != "super_admin" || !me.TOTPEnabled || len(me.Tenants) != 2 {
			t.Errorf("me after the setup = %+v, want an enrolled super admin seeing both tenants", me)
		}
		old := a.client(acct, adminIP(10))
		old.cookie = setupCookie
		old.expectUnauthenticated(t, "the pre-confirmation cookie")

		resp = a.client(nil, adminIP(11)).setup(t, "second", "second@"+domainA, superPassword, token)
		expectProblem(t, resp, http.StatusConflict, "setup-already-done")
		if status() {
			t.Error("setupRequired = true after the setup")
		}
		a.expectAudit(t, "setup.completed", "admin.totp_enrolled", "admin.login")
	})
}

// TestAdminLoginFlow covers a login (password, then TOTP), the session
// rotation at each step, the refusal of a TOTP code replayed and of a
// recovery code used twice, and the logout (T-59, T-60).
func TestAdminLoginFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		acct := sa.acct

		c := a.client(acct, adminIP(11))
		c.mustLogin(t, stateTOTPRequired)
		loginCookie, loginCSRF := c.cookie, c.csrf
		if loginCookie == sa.cookie {
			t.Fatal("login reused the cookie of another session")
		}
		if resp := c.send(t, http.MethodGet, pathAdminMe, nil, nil); resp.status != http.StatusUnauthorized {
			t.Errorf("GET /admin/me in state totp_required = %d, want 401", resp.status)
		}
		code := acct.nextCode(t)
		if resp := c.verify(t, code, ""); resp.status != http.StatusOK || c.state != stateAuthenticated {
			t.Fatalf("verify TOTP: %d %s", resp.status, resp.body)
		}
		if c.cookie == loginCookie || c.csrf == loginCSRF {
			t.Error("the TOTP step did not rotate the session token and CSRF token")
		}
		if me := c.me(t); me.ID != acct.id {
			t.Errorf("me.id = %s, want %s", me.ID, acct.id)
		}
		stale := a.client(acct, adminIP(11))
		stale.cookie, stale.csrf = loginCookie, loginCSRF
		resp := stale.verify(t, acct.wrongCode(t), "")
		expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
		stale.expectUnauthenticated(t, "the pre-rotation cookie")

		// The same TOTP code, within its window, is refused on another
		// session (T-60); the session survives the refusal.
		replay := a.client(acct, adminIP(12))
		replay.mustLogin(t, stateTOTPRequired)
		resp = replay.verify(t, code, "")
		expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		if _, set := sessionCookie(t, resp); set {
			t.Error("a refused TOTP code changed the session cookie")
		}
		recovery := acct.takeRecovery(t)
		if resp := replay.verify(t, "", recovery); resp.status != http.StatusOK || replay.state != stateAuthenticated {
			t.Fatalf("recovery code: %d %s", resp.status, resp.body)
		}
		// A recovery code works once.
		again := a.client(acct, adminIP(13))
		again.mustLogin(t, stateTOTPRequired)
		expectProblem(t, again.verify(t, "", recovery), http.StatusUnauthorized, "invalid-credentials")
		if resp := again.verify(t, "", strings.ToLower(acct.takeRecovery(t))); resp.status != http.StatusOK {
			t.Errorf("an unused recovery code typed in lower case: %d %s", resp.status, resp.body)
		}

		// Logout ends the session and clears the cookie.
		before := c.cookie
		resp = c.call(t, http.MethodPost, pathAdminLogout, nil)
		if resp.status != http.StatusNoContent {
			t.Fatalf("logout: %d %s", resp.status, resp.body)
		}
		expectCookieCleared(t, resp)
		c.cookie = before
		c.expectUnauthenticated(t, "the cookie after logout")
		expectProblem(t, c.call(t, http.MethodPost, pathAdminLogout, nil), http.StatusUnauthorized, "unauthenticated")
		// The other sessions are untouched.
		replay.me(t)

		a.waitLogLines(t, "admin_login_failed", adminIP(12), `reason="totp"`, 1)
		a.waitLogLines(t, "admin_login_failed", adminIP(13), `reason="recovery_code"`, 1)
		rows := a.expectAudit(t, "admin.login", "admin.login_failed", "admin.recovery_code_used", "admin.logout")
		for _, r := range rows {
			if r.action == "admin.login_failed" && (r.actor != superName || r.objectID != acct.id) {
				t.Errorf("admin.login_failed event = %+v, want actor %s and object %s", r, superName, acct.id)
			}
		}
	})
}

// TestAdminLoginLockouts covers the login limits kept in the database
// (T-58): 5 failures of one username from one IP lock that pair, even for
// the right password, without locking the same username from another IP;
// 20 failures from one IP across usernames lock the IP. Every failure and
// every lock is written to the security log.
func TestAdminLoginLockouts(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		acct := a.bootstrap(t, adminIP(10)).acct
		pairIP, otherIP, floodIP := adminIP(20), adminIP(21), adminIP(22)

		c := a.client(acct, pairIP)
		for i := 1; i <= 4; i++ {
			expectProblem(t, c.login(t, superName, "wrong password "+strconv.Itoa(i)), http.StatusUnauthorized, "invalid-credentials")
		}
		expectRateLimited(t, "5th wrong password", c.login(t, superName, "wrong password 5"))
		expectRateLimited(t, "right password after the lock", c.login(t, superName, superPassword))
		a.client(acct, otherIP).mustLogin(t, stateTOTPRequired)

		flood := a.client(nil, floodIP)
		for i := 1; i <= 19; i++ {
			resp := flood.login(t, fmt.Sprintf("ghost%02d", i), "wrong password")
			expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		}
		// The 20th failure from the IP sets the database lock: the in-memory
		// admin_auth limiter (burst 20) has not refused anything yet.
		expectRateLimited(t, "20th failure from one IP", flood.login(t, "ghost20", "wrong password"))
		rows := sysQuery(t, e, `SELECT locked_until FROM admin_login_failures WHERE scope = 'ip' AND key = '`+floodIP+`'`)
		if len(rows) != 1 {
			t.Fatalf("admin_login_failures rows for %s = %v, want 1", floodIP, rows)
		}
		until, err := strconv.ParseInt(rows[0][0], 10, 64)
		if err != nil || time.UnixMilli(until).Before(time.Now().Add(10*time.Minute)) {
			t.Errorf("IP lock of %s ends at %q, want about 15 minutes from now", floodIP, rows[0][0])
		}

		if n := len(a.waitLogLines(t, "admin_login_failed", pairIP, `reason="password"`, 5)); n != 5 {
			t.Errorf("admin_login_failed lines from %s = %d, want 5", pairIP, n)
		}
		a.waitLogLines(t, "rate_limited", pairIP, `scope="admin_login"`, 1)
		if n := len(a.waitLogLines(t, "admin_login_failed", floodIP, `reason="password"`, 20)); n != 20 {
			t.Errorf("admin_login_failed lines from %s = %d, want 20", floodIP, n)
		}
		a.waitLogLines(t, "rate_limited", floodIP, `scope="admin_login"`, 1)
		if n := len(a.logLinesOf(t, "admin_login_failed", otherIP, "")); n != 0 {
			t.Errorf("admin_login_failed lines from %s = %d, want 0", otherIP, n)
		}
		for _, l := range eventsOf(t, a.securityLines(t), "admin_login_failed") {
			if strings.Contains(l.raw, superName) || strings.Contains(l.raw, "ghost") {
				t.Errorf("security log line names the username: %s", l.raw)
			}
		}
		failed := 0
		for _, r := range a.expectAudit(t, "admin.login_failed") {
			if r.action != "admin.login_failed" {
				continue
			}
			failed++
			// An unknown username is never recorded as typed.
			if strings.Contains(r.actor+r.details, "ghost") || (r.actor != superName && (r.actor != "unknown" || r.objectID != "unknown")) {
				t.Errorf("admin.login_failed event = %+v", r)
			}
		}
		if failed != 25 {
			t.Errorf("admin.login_failed audit events = %d, want 25", failed)
		}
	})
}

// TestAdminTOTPBruteForce covers the second factor limits: 5 wrong codes
// end the intermediate session and lock the second factor of the account
// from any IP; the sessions already open are not affected.
func TestAdminTOTPBruteForce(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		acct := sa.acct

		c := a.client(acct, adminIP(30))
		c.mustLogin(t, stateTOTPRequired)
		for i := 1; i <= 4; i++ {
			expectProblem(t, c.verify(t, acct.wrongCode(t), ""), http.StatusUnauthorized, "invalid-credentials")
		}
		expectRateLimited(t, "5th wrong TOTP code", c.verify(t, acct.wrongCode(t), ""))
		// The session is gone: refused before any code is checked.
		resp := c.verify(t, acct.wrongCode(t), "")
		expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
		expectCookieCleared(t, resp)

		other := a.client(acct, adminIP(31))
		other.mustLogin(t, stateTOTPRequired)
		expectRateLimited(t, "right TOTP code while the second factor is locked", other.verify(t, acct.nextCode(t), ""))
		expectRateLimited(t, "recovery code while the second factor is locked", other.verify(t, "", acct.recovery[0]))
		sa.me(t)

		if n := len(a.waitLogLines(t, "admin_login_failed", adminIP(30), `reason="totp"`, 5)); n != 5 {
			t.Errorf("admin_login_failed lines from %s = %d, want 5", adminIP(30), n)
		}
		a.waitLogLines(t, "rate_limited", adminIP(30), `scope="admin_login"`, 1)
		a.waitLogLines(t, "rate_limited", adminIP(31), `scope="admin_login"`, 1)
		a.expectAudit(t, "admin.login_failed")
	})
}

// TestAdminSessionExpiry covers the session lifetimes: the sliding idle
// timeout (30 minutes by default), the absolute lifetime (12 hours) and
// the 5-minute lifetime of an intermediate login state.
func TestAdminSessionExpiry(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		acct := a.bootstrap(t, adminIP(10)).acct

		idle := a.client(acct, adminIP(40))
		idle.signInRecovery(t)
		idle.ageSession(t, "last_seen_at = "+millis(-29*time.Minute))
		idle.me(t)
		rows := sysQuery(t, e, `SELECT last_seen_at FROM admin_sessions WHERE token_hash = `+tokenHashSQL(e, idle.cookie))
		if len(rows) != 1 {
			t.Fatalf("session rows = %v", rows)
		}
		if seen, err := strconv.ParseInt(rows[0][0], 10, 64); err != nil || time.Since(time.UnixMilli(seen)) > time.Minute {
			t.Errorf("last_seen_at after a request = %q, want refreshed (sliding idle timeout)", rows[0][0])
		}
		idle.ageSession(t, "last_seen_at = "+millis(-31*time.Minute))
		idle.expectUnauthenticated(t, "a session idle for 31 minutes")

		absolute := a.client(acct, adminIP(41))
		absolute.signInRecovery(t)
		absolute.ageSession(t, "created_at = "+millis(-13*time.Hour)+", expires_at = "+millis(-time.Second))
		absolute.expectUnauthenticated(t, "a session past its absolute lifetime")

		pending := a.client(acct, adminIP(42))
		resp := pending.login(t, superName, superPassword)
		if resp.status != http.StatusOK || pending.state != stateTOTPRequired {
			t.Fatalf("login: %d %s", resp.status, resp.body)
		}
		if ck, _ := sessionCookie(t, resp); ck.MaxAge > 300 {
			t.Errorf("totp_required cookie Max-Age = %d, want at most the 5-minute state lifetime", ck.MaxAge)
		}
		pending.ageSession(t, "state_expires_at = "+millis(-time.Second))
		resp = pending.verify(t, acct.nextCode(t), "")
		expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
		expectCookieCleared(t, resp)
	})
}

// TestAdminCSRFAndOrigin covers the CSRF token of the session operations
// and the Origin and Sec-Fetch-Site checks of the open login steps (T-61).
func TestAdminCSRFAndOrigin(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		other := a.client(sa.acct, adminIP(11))
		other.signInRecovery(t)

		// A too short new password is refused after the CSRF checks and
		// before the current password is verified: 400 means "passed".
		body := map[string]string{"currentPassword": superPassword, "newPassword": "short"}
		for _, tc := range []struct {
			name   string
			header http.Header
			status int
			code   string
		}{
			{"no token", http.Header{}, http.StatusForbidden, "csrf-invalid"},
			{"malformed token", http.Header{hdrCSRF: {"not-a-token"}}, http.StatusForbidden, "csrf-invalid"},
			{"forged token", http.Header{hdrCSRF: {"csrf_" + strings.Repeat("A", 43)}}, http.StatusForbidden, "csrf-invalid"},
			{"token of another session", http.Header{hdrCSRF: {other.csrf}}, http.StatusForbidden, "csrf-invalid"},
			{"cross-site Origin", http.Header{hdrCSRF: {sa.csrf}, "Origin": {"https://evil.example.com"}}, http.StatusForbidden, "csrf-invalid"},
			{"plain http Origin", http.Header{hdrCSRF: {sa.csrf}, "Origin": {"http://" + adminHost}}, http.StatusForbidden, "csrf-invalid"},
			{"tenant Origin", http.Header{hdrCSRF: {sa.csrf}, "Origin": {"https://" + hostA}}, http.StatusForbidden, "csrf-invalid"},
			{"cross-site fetch", http.Header{hdrCSRF: {sa.csrf}, "Sec-Fetch-Site": {"cross-site"}}, http.StatusForbidden, "csrf-invalid"},
			{"same-site fetch", http.Header{hdrCSRF: {sa.csrf}, "Sec-Fetch-Site": {"same-site"}}, http.StatusForbidden, "csrf-invalid"},
			{"same origin", http.Header{hdrCSRF: {sa.csrf}, "Origin": {"https://" + adminHost}, "Sec-Fetch-Site": {"same-origin"}}, http.StatusBadRequest, "validation-failed"},
			{"token only", http.Header{hdrCSRF: {sa.csrf}}, http.StatusBadRequest, "validation-failed"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resp := sa.send(t, http.MethodPut, pathAdminPassword, body, tc.header)
				expectProblem(t, resp, tc.status, tc.code)
				if _, set := sessionCookie(t, resp); set {
					t.Error("the answer changed the session cookie")
				}
			})
		}
		// The other session operations are guarded the same way.
		expectProblem(t, sa.send(t, http.MethodPost, pathAdminLogout, nil, nil), http.StatusForbidden, "csrf-invalid")
		expectProblem(t, sa.send(t, http.MethodPost, pathAdmins, map[string]string{}, nil), http.StatusForbidden, "csrf-invalid")
		expectProblem(t, sa.send(t, http.MethodDelete, pathAdmins+"/"+other.acct.id, nil, nil), http.StatusForbidden, "csrf-invalid")
		sa.me(t)

		// The open login steps: no session, no CSRF token, but a cross-site
		// page can neither log in (login CSRF) nor burn the counters.
		anon := a.client(nil, adminIP(12))
		login := map[string]string{"username": superName, "password": superPassword}
		for _, tc := range []struct {
			name, path string
			body       any
			header     http.Header
		}{
			{"login cross-site Origin", pathAdminLogin, login, http.Header{"Origin": {"https://evil.example.com"}}},
			{"login cross-site fetch", pathAdminLogin, login, http.Header{"Sec-Fetch-Site": {"cross-site"}}},
			{"login same-site fetch", pathAdminLogin, login, http.Header{"Sec-Fetch-Site": {"same-site"}}},
			{"login null Origin", pathAdminLogin, login, http.Header{"Origin": {"null"}}},
			{"setup cross-site", pathAdminSetup, map[string]string{"username": "x", "email": "x@" + domainA, "password": superPassword, "setupToken": adminSetupToken}, http.Header{"Sec-Fetch-Site": {"cross-site"}}},
			{"activation cross-site", pathAdminActivation, map[string]string{"activationToken": "act_x", "password": superPassword}, http.Header{"Origin": {"https://evil.example.com"}}},
		} {
			resp := anon.send(t, http.MethodPost, tc.path, tc.body, tc.header)
			if resp.status != http.StatusForbidden {
				t.Errorf("%s: %d %s, want 403", tc.name, resp.status, resp.body)
				continue
			}
			expectProblem(t, resp, http.StatusForbidden, "csrf-invalid")
		}
		// Rows refunded by the successful logins may stay, empty.
		for _, r := range sysQuery(t, e, `SELECT scope, key, failures FROM admin_login_failures`) {
			if r[2] != "" {
				t.Errorf("failure counter %s/%s = %q, want no failure after refused cross-site logins", r[0], r[1], r[2])
			}
		}
		resp := anon.send(t, http.MethodPost, pathAdminLogin, login,
			http.Header{"Origin": {"https://" + adminHost}, "Sec-Fetch-Site": {"same-origin"}})
		if resp.status != http.StatusOK {
			t.Errorf("same-origin login: %d %s", resp.status, resp.body)
		}
		// A session in state totp_required needs its CSRF token too.
		anon.acct = sa.acct
		anon.mustLogin(t, stateTOTPRequired)
		expectProblem(t, anon.send(t, http.MethodPost, pathAdminTOTP, map[string]string{"recoveryCode": sa.acct.recovery[0]}, nil),
			http.StatusForbidden, "csrf-invalid")
	})
}

// TestAdminDelegated covers the life of a delegated admin, created by the
// super admin and activated from the link returned by createAdmin (never
// mailed: Mailpit receives nothing): the enrollment is imposed, the super
// admin operations are refused, only tenant A is visible, disabling
// revokes the sessions and a credentials reset returns a new link. It then
// covers the promotion, the reset of a super admin by another one, the
// protection of the last super admin and the audit log of the whole flow.
func TestAdminDelegated(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, true)
		sa := a.bootstrap(t, adminIP(10))

		acct, token := sa.createDelegated(t, "delegate-a")
		d := a.client(acct, adminIP(50))
		expectProblem(t, d.login(t, acct.username, acct.password), http.StatusUnauthorized, "invalid-credentials")
		if resp := d.activate(t, token); resp.status != http.StatusOK || d.state != stateEnrollRequired {
			t.Fatalf("activateAdmin: %d %s, want state %s", resp.status, resp.body, stateEnrollRequired)
		}
		expectProblem(t, d.send(t, http.MethodGet, pathAdminMe, nil, nil), http.StatusUnauthorized, "unauthenticated")
		expectProblem(t, a.client(acct, adminIP(51)).activate(t, token), http.StatusNotFound, "not-found")
		d.enroll(t)
		me := d.me(t)
		if me.Role != "delegated_admin" || len(me.Tenants) != 1 || me.Tenants[0].ID != string(a.tenantA.ID) ||
			me.Tenants[0].FQDN != hostA || !me.TOTPEnabled {
			t.Errorf("delegated me = %+v, want tenant A only", me)
		}

		// The super admin operations are refused.
		for _, r := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, pathAdmins, nil},
			{http.MethodPost, pathAdmins, map[string]any{"username": "intruder", "email": "intruder@" + domainA, "role": "delegated_admin", "tenantIds": []string{string(a.tenantB.ID)}}},
			{http.MethodGet, pathAdmins + "/" + sa.acct.id, nil},
			{http.MethodDelete, pathAdmins + "/" + sa.acct.id, nil},
			{http.MethodPost, pathAdmins + "/" + sa.acct.id + "/reset-credentials", nil},
		} {
			resp := d.call(t, r.method, r.path, r.body)
			if resp.status != http.StatusForbidden {
				t.Errorf("delegated %s %s = %d %s, want 403", r.method, r.path, resp.status, resp.body)
				continue
			}
			expectProblem(t, resp, http.StatusForbidden, "forbidden")
		}
		expectProblem(t, d.patch(t, acct.id, map[string]any{"role": "super_admin"}), http.StatusForbidden, "forbidden")
		// Tenant B is invisible to the admin of tenant A (the tenant
		// operations are not implemented yet: 404 for both, never data).
		resp := d.call(t, http.MethodGet, "/api/v1/admin/tenants/"+string(a.tenantB.ID), nil)
		expectProblem(t, resp, http.StatusNotFound, "not-found")
		if strings.Contains(string(resp.body), nameB) {
			t.Error("tenant B leaked to the admin of tenant A")
		}

		// Disabling revokes the sessions and blocks the logins.
		resp = sa.patch(t, acct.id, map[string]any{"disabled": true})
		if resp.status != http.StatusOK {
			t.Fatalf("disable: %d %s", resp.status, resp.body)
		}
		d.expectUnauthenticated(t, "the session of a disabled admin")
		expectProblem(t, a.client(acct, adminIP(52)).login(t, acct.username, acct.password), http.StatusUnauthorized, "invalid-credentials")
		if resp := sa.patch(t, acct.id, map[string]any{"disabled": false}); resp.status != http.StatusOK {
			t.Fatalf("enable: %d %s", resp.status, resp.body)
		}

		// A credentials reset returns a new link; the old password and link
		// are dead, and the enrollment is imposed again.
		d.signIn(t)
		resp = sa.call(t, http.MethodPost, pathAdmins+"/"+acct.id+"/reset-credentials", nil)
		if resp.status != http.StatusOK {
			t.Fatalf("resetAdminCredentials: %d %s", resp.status, resp.body)
		}
		reset, token2 := a.activationOf(t, resp)
		if reset.ID != acct.id || reset.TOTPEnabled || token2 == token {
			t.Errorf("reset admin = %+v", reset)
		}
		d.expectUnauthenticated(t, "the session of a reset admin")
		expectProblem(t, a.client(acct, adminIP(53)).login(t, acct.username, acct.password), http.StatusUnauthorized, "invalid-credentials")
		expectProblem(t, a.client(acct, adminIP(53)).activate(t, token), http.StatusNotFound, "not-found")
		acct.password = "a new delegated password"
		a.secret(acct.password)
		d = a.client(acct, adminIP(54))
		if resp := d.activate(t, token2); resp.status != http.StatusOK || d.state != stateEnrollRequired {
			t.Fatalf("activate after the reset: %d %s, want state %s", resp.status, resp.body, stateEnrollRequired)
		}
		d.enroll(t)

		// The last super admin can neither delete nor disable itself.
		expectProblem(t, sa.call(t, http.MethodDelete, pathAdmins+"/"+sa.acct.id, nil), http.StatusConflict, "state-conflict")
		expectProblem(t, sa.patch(t, sa.acct.id, map[string]any{"disabled": true}), http.StatusConflict, "state-conflict")
		expectProblem(t, sa.patch(t, sa.acct.id, map[string]any{"role": "delegated_admin", "tenantIds": []string{string(a.tenantA.ID)}}),
			http.StatusConflict, "state-conflict")
		expectProblem(t, sa.call(t, http.MethodDelete, pathAdmins+"/adm_01JZZZZZZZZZZZZZZZZZZZZZZZ", nil), http.StatusNotFound, "not-found")

		// Promoted, the delegated admin can delete the first super admin.
		resp = sa.patch(t, acct.id, map[string]any{"role": "super_admin"})
		if resp.status != http.StatusOK {
			t.Fatalf("promote: %d %s", resp.status, resp.body)
		}
		var promoted adminJSON
		mustJSON(t, resp.body, &promoted)
		if promoted.Role != "super_admin" || len(promoted.TenantIDs) != 0 {
			t.Errorf("promoted admin = %+v, want a super admin without tenants", promoted)
		}
		d.expectUnauthenticated(t, "the session of a promoted admin")
		d.signIn(t)
		if me := d.me(t); me.Role != "super_admin" || len(me.Tenants) != 2 {
			t.Errorf("promoted me = %+v, want a super admin seeing both tenants", me)
		}
		resp = d.call(t, http.MethodGet, pathAdmins, nil)
		if resp.status != http.StatusOK {
			t.Fatalf("listAdmins as the promoted admin: %d %s", resp.status, resp.body)
		}
		var list struct {
			Items []adminJSON `json:"items"`
		}
		mustJSON(t, resp.body, &list)
		if len(list.Items) != 2 || strings.Contains(string(resp.body), "assword") {
			t.Errorf("listAdmins = %s, want 2 accounts without credentials", resp.body)
		}
		// A super admin can be reset by another one: no mail is involved.
		expectProblem(t, d.call(t, http.MethodPost, pathAdmins+"/"+acct.id+"/reset-credentials", nil), http.StatusConflict, "state-conflict")
		sa.me(t)
		resp = d.call(t, http.MethodPost, pathAdmins+"/"+sa.acct.id+"/reset-credentials", nil)
		if resp.status != http.StatusOK {
			t.Fatalf("reset the first super admin: %d %s", resp.status, resp.body)
		}
		if reset, _ := a.activationOf(t, resp); reset.Role != "super_admin" {
			t.Errorf("reset super admin = %+v", reset)
		}
		sa.expectUnauthenticated(t, "the session of a reset super admin")
		if resp := d.call(t, http.MethodDelete, pathAdmins+"/"+sa.acct.id, nil); resp.status != http.StatusNoContent {
			t.Fatalf("delete the first super admin: %d %s", resp.status, resp.body)
		}
		expectProblem(t, a.client(sa.acct, adminIP(55)).login(t, superName, superPassword), http.StatusUnauthorized, "invalid-credentials")
		expectProblem(t, d.call(t, http.MethodDelete, pathAdmins+"/"+acct.id, nil), http.StatusConflict, "state-conflict")
		// No activation mail was ever sent.
		a.expectNoMail(t, acct.email)
		a.expectNoMail(t, sa.acct.email)

		rows := a.expectAudit(t, "setup.completed", "admin.login", "admin.login_failed", "admin.totp_enrolled",
			"admin.created", "admin.activated", "admin.updated", "admin.credentials_reset", "admin.deleted")
		for _, r := range rows {
			if r.action == "admin.created" && (r.actor != superName || r.objectID != acct.id || strings.Contains(r.details, acct.email)) {
				t.Errorf("admin.created event = %+v, want actor %s, object %s and no mail address", r, superName, acct.id)
			}
			if r.action == "admin.deleted" && (r.actor != acct.username || r.objectID != sa.acct.id) {
				t.Errorf("admin.deleted event = %+v", r)
			}
		}
	})
}

// TestAdminPasswordChange covers the password change: it revokes the other
// sessions of the account, and a wrong current password counts towards the
// login limits.
func TestAdminPasswordChange(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		acct := sa.acct
		other := a.client(acct, adminIP(60))
		other.signInRecovery(t)

		const newPassword = "a brand new admin passphrase"
		a.secret(newPassword)
		resp := sa.call(t, http.MethodPut, pathAdminPassword, map[string]string{"currentPassword": superPassword, "newPassword": newPassword})
		if resp.status != http.StatusNoContent {
			t.Fatalf("changeAdminPassword: %d %s", resp.status, resp.body)
		}
		other.expectUnauthenticated(t, "another session after a password change")
		sa.me(t)
		expectProblem(t, a.client(acct, adminIP(61)).login(t, superName, superPassword), http.StatusUnauthorized, "invalid-credentials")
		acct.password = newPassword
		a.client(acct, adminIP(61)).mustLogin(t, stateTOTPRequired)

		// Wrong current passwords count like failed logins of the account
		// from the session's IP.
		for i := 1; i <= 4; i++ {
			resp := sa.call(t, http.MethodPut, pathAdminPassword, map[string]string{"currentPassword": "wrong " + strconv.Itoa(i), "newPassword": "never applied passphrase"})
			expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		}
		expectRateLimited(t, "5th wrong current password",
			sa.call(t, http.MethodPut, pathAdminPassword, map[string]string{"currentPassword": "wrong 5", "newPassword": "never applied passphrase"}))
		expectRateLimited(t, "login from the locked IP", a.client(acct, adminIP(10)).login(t, superName, newPassword))
		a.client(acct, adminIP(62)).mustLogin(t, stateTOTPRequired)
		sa.me(t)

		a.waitLogLines(t, "admin_login_failed", adminIP(10), `reason="password"`, 5)
		a.waitLogLines(t, "rate_limited", adminIP(10), `scope="admin_login"`, 1)
		a.expectAudit(t, "admin.password_changed", "admin.login_failed")
	})
}

// TestAdminLocalRecoveryAndKeyRotation runs the real binary: "admin
// reset-totp" revokes the sessions and imposes a new enrollment (audited),
// then "rotate-master-key" re-wraps the TOTP secrets, and after a restart
// with the new master key alone the login with TOTP still works.
func TestAdminLocalRecoveryAndKeyRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the transteira binary")
	}
	t.Parallel()
	bin := buildBinary(t, t.TempDir())
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		k1, k2 := newKeyFile(t, "admin-K1"), newKeyFile(t, "admin-K2")
		a := startAdmin(t, e, serverOptions{env: map[string]string{config.EnvMasterKeyFile: k1.path}}, false)
		sa := a.bootstrap(t, adminIP(10))
		acct := sa.acct
		other := a.client(acct, adminIP(70))
		other.signInRecovery(t)
		oldRecovery := acct.recovery[0]
		cliEnv := testEnv(t, e, a.o)

		code, out, errOut := runCLI(t, bin, cliEnv, "admin", "reset-totp", "SuperAdmin")
		if code != 0 || !strings.Contains(out, `"`+superName+`" removed`) {
			t.Fatalf("admin reset-totp: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		assertNoKeyMaterial(t, "admin reset-totp output", out+errOut, k1)
		sa.expectUnauthenticated(t, "a session after reset-totp")
		other.expectUnauthenticated(t, "another session after reset-totp")
		code, out, errOut = runCLI(t, bin, cliEnv, "admin", "reset-totp", "nobody")
		if code != 1 || !strings.Contains(errOut, `no administrator named "nobody"`) {
			t.Errorf("admin reset-totp of an unknown admin: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}

		c := a.client(acct, adminIP(71))
		c.mustLogin(t, stateEnrollRequired)
		c.enroll(t)
		stale := a.client(acct, adminIP(72))
		stale.mustLogin(t, stateTOTPRequired)
		expectProblem(t, stale.verify(t, "", oldRecovery), http.StatusUnauthorized, "invalid-credentials")

		code, out, errOut = runCLI(t, bin, cliEnv, "admin", "list")
		if code != 0 || !strings.Contains(out, superName) || !strings.Contains(out, "super_admin") {
			t.Errorf("admin list: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		var reset []auditRow
		for _, r := range a.expectAudit(t, "admin.totp_reset_local", "admin.totp_enrolled") {
			if r.action == "admin.totp_reset_local" {
				reset = append(reset, r)
			}
		}
		if len(reset) != 1 || reset[0].actorKind != "system" || reset[0].actor != "cli" || reset[0].objectID != acct.id ||
			!strings.Contains(reset[0].details, superName) {
			t.Errorf("admin.totp_reset_local events = %+v, want one by the system actor cli on %s", reset, acct.id)
		}

		// Rotate the master key with the server stopped, then restart with
		// the new key alone.
		if err := a.stop(); err != nil {
			t.Fatalf("stop: %v\napp log:\n%s", err, a.appLog)
		}
		code, out, errOut = runRotateCommand(t, bin, withKeys(cliEnv, k1, &k2))
		if code != 0 || !strings.Contains(out, "completed") {
			t.Fatalf("rotate-master-key: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		assertNoKeyMaterial(t, "rotate-master-key output", out+errOut, k1, k2)
		keyIDs := sysQuery(t, e, `SELECT key_id FROM system_secrets`)
		if len(keyIDs) == 0 {
			t.Fatal("no system secret after the enrollment")
		}
		for _, r := range keyIDs {
			if r[0] != k2.id {
				t.Errorf("system secret under %s after the rotation, want %s", r[0], k2.id)
			}
		}
		cfg := *a.cfg
		cfg.MasterKeyFile, cfg.MasterKeyNewFile = k2.path, ""
		a.server = launchServer(t, &cfg, a.tenantA, a.tenantB, a.o)

		after := a.client(acct, adminIP(73))
		after.signIn(t)
		if me := after.me(t); me.ID != acct.id || !me.TOTPEnabled {
			t.Errorf("me after the rotation = %+v", me)
		}
		// Recovery codes issued before the rotation still verify after it:
		// their MAC key derives from the TOTP secret, which was rewrapped.
		a.client(acct, adminIP(74)).signInRecovery(t)

		// "admin reset-password" clears the password, the TOTP and the
		// recovery codes of the last super admin, revokes its sessions and
		// prints a new activation link, once.
		cliEnv = withKeys(cliEnv, k2, nil)
		code, out, errOut = runCLI(t, bin, cliEnv, "admin", "reset-password", "SuperAdmin")
		if code != 0 || !strings.Contains(out, `"`+superName+`" removed`) {
			t.Fatalf("admin reset-password: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		links := activationLineRE.FindAllString(out, -1)
		if len(links) != 1 || strings.Count(out+errOut, "act_") != 1 {
			t.Fatalf("admin reset-password printed %d links: %s", len(links), out)
		}
		token := activationRE.FindStringSubmatch(links[0])[1]
		a.secret(token)
		assertNoKeyMaterial(t, "admin reset-password output", out+errOut, k2)
		after.expectUnauthenticated(t, "a session after reset-password")
		expectProblem(t, a.client(acct, adminIP(75)).login(t, superName, acct.password), http.StatusUnauthorized, "invalid-credentials")
		code, out, errOut = runCLI(t, bin, cliEnv, "admin", "reset-password", "nobody")
		if code != 1 || !strings.Contains(errOut, `no administrator named "nobody"`) {
			t.Errorf("admin reset-password of an unknown admin: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		code, out, errOut = runCLI(t, bin, cliEnv, "admin", "reset-password", "not a name")
		if code != 2 || !strings.Contains(errOut, "invalid username") {
			t.Errorf("admin reset-password of a malformed name: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		acct.password = "a new super admin passphrase"
		a.secret(acct.password)
		fresh := a.client(acct, adminIP(76))
		if resp := fresh.activate(t, token); resp.status != http.StatusOK || fresh.state != stateEnrollRequired {
			t.Fatalf("activate after reset-password: %d %s", resp.status, resp.body)
		}
		fresh.enroll(t)
		a.client(acct, adminIP(77)).signIn(t)
		var resets []auditRow
		for _, r := range a.expectAudit(t, "admin.password_reset_local", "admin.activated") {
			if r.action == "admin.password_reset_local" {
				resets = append(resets, r)
			}
		}
		if len(resets) != 1 || resets[0].actorKind != "system" || resets[0].actor != "cli" || resets[0].objectID != acct.id {
			t.Errorf("admin.password_reset_local events = %+v, want one by the system actor cli on %s", resets, acct.id)
		}
	})
}

// TestAdminReenrollment covers the TOTP re-enrollment of an authenticated
// admin: it needs the current password (400 without it, 401 when wrong,
// counted on the login limits), keeps the old TOTP until the confirmation,
// and the confirmation revokes the other sessions of the account.
func TestAdminReenrollment(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		acct := sa.acct
		other := a.client(acct, adminIP(80))
		other.signInRecovery(t)

		expectProblem(t, sa.call(t, http.MethodPost, pathAdminEnroll, nil), http.StatusBadRequest, "validation-failed")
		expectProblem(t, sa.call(t, http.MethodPost, pathAdminEnroll, map[string]string{}), http.StatusBadRequest, "validation-failed")
		resp := sa.call(t, http.MethodPost, pathAdminEnroll, map[string]string{"currentPassword": "wrong password"})
		expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		a.waitLogLines(t, "admin_login_failed", adminIP(10), `reason="password"`, 1)
		other.me(t)

		oldSecret := acct.secret
		sa.enrollWith(t, map[string]string{"currentPassword": superPassword})
		sa.me(t)
		other.expectUnauthenticated(t, "another session after a re-enrollment")
		// The new secret is in use, the old one is not.
		stale := &adminAccount{username: acct.username, password: acct.password, secret: oldSecret}
		c := a.client(stale, adminIP(81))
		c.mustLogin(t, stateTOTPRequired)
		expectProblem(t, c.verify(t, stale.nextCode(t), ""), http.StatusUnauthorized, "invalid-credentials")
		a.client(acct, adminIP(82)).signIn(t)
		a.expectAudit(t, "admin.totp_enrolled")
	})
}

// TestAdminEnrollmentProtections covers the TOTP enrollment of an
// authenticated admin without TOTP: the first enrollment needs the current
// password too (400 without it, 401 when wrong), a pending secret older
// than 15 minutes cannot be confirmed (409), and 5 wrong confirmation codes
// lock the second factor of the account (429), each one written to the
// security log.
func TestAdminEnrollmentProtections(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))

		acct := &adminAccount{username: "delegate-free", email: uniqueEmail(t, "delegate-free", domainA), password: "delegated password free"}
		resp := sa.call(t, http.MethodPost, pathAdmins, map[string]any{
			"username": acct.username, "email": acct.email, "role": "delegated_admin",
			"tenantIds": []string{string(a.tenantA.ID)}, "requireTotp": false,
		})
		if resp.status != http.StatusCreated {
			t.Fatalf("createAdmin: %d %s", resp.status, resp.body)
		}
		created, token := a.activationOf(t, resp)
		acct.id = created.ID
		a.secret(acct.password)
		d := a.client(acct, adminIP(90))
		if resp := d.activate(t, token); resp.status != http.StatusOK || d.state != stateAuthenticated {
			t.Fatalf("activateAdmin: %d %s, want state %s", resp.status, resp.body, stateAuthenticated)
		}

		// The first enrollment of an authenticated session needs the
		// current password.
		expectProblem(t, d.call(t, http.MethodPost, pathAdminEnroll, nil), http.StatusBadRequest, "validation-failed")
		resp = d.call(t, http.MethodPost, pathAdminEnroll, map[string]string{"currentPassword": "wrong password"})
		expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		a.waitLogLines(t, "admin_login_failed", adminIP(90), `reason="password"`, 1)

		start := func() {
			t.Helper()
			resp := d.call(t, http.MethodPost, pathAdminEnroll, map[string]string{"currentPassword": acct.password})
			if resp.status != http.StatusOK {
				t.Fatalf("startTotpEnrollment: %d %s", resp.status, resp.body)
			}
			var enr enrollmentJSON
			mustJSON(t, resp.body, &enr)
			acct.secret, acct.haveStep = decodeSecret(t, enr.Secret), false
			a.secret(enr.Secret)
		}

		// An expired pending secret is refused.
		start()
		execSystem(t, e, "UPDATE system_secrets SET created_at = "+millis(-16*time.Minute)+
			" WHERE id = (SELECT pending_totp_secret_id FROM admins WHERE id = '"+acct.id+"')")
		expectProblem(t, d.confirm(t, acct.nextCode(t)), http.StatusConflict, "state-conflict")

		// Five wrong codes lock the second factor, the right code included.
		start()
		for i := 1; i <= 4; i++ {
			expectProblem(t, d.confirm(t, acct.wrongCode(t)), http.StatusUnauthorized, "invalid-credentials")
		}
		expectRateLimited(t, "5th wrong confirmation code", d.confirm(t, acct.wrongCode(t)))
		expectRateLimited(t, "right confirmation code while locked", d.confirm(t, acct.nextCode(t)))
		if me := d.me(t); me.TOTPEnabled {
			t.Error("TOTP enabled despite the lock")
		}
		if n := len(a.waitLogLines(t, "admin_login_failed", adminIP(90), `reason="totp"`, 5)); n != 5 {
			t.Errorf("admin_login_failed lines from %s = %d, want 5", adminIP(90), n)
		}
		a.waitLogLines(t, "rate_limited", adminIP(90), `scope="admin_login"`, 1)
		a.expectAudit(t, "admin.login_failed")
	})
}

// TestAdminHostIsolation covers the separation of the admin host and the
// tenant hosts (T-102): the administration is absent from every tenant
// FQDN, even with a valid admin cookie, the admin cookie opens nothing on
// a tenant host, and the public API is absent from the admin host.
func TestAdminHostIsolation(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		adminCookie := http.Header{
			"Cookie":  {adminCookieName + "=" + sa.cookie},
			hdrCSRF:   {sa.csrf},
			hdrXFF:    {adminIP(10)},
			"Accept":  {contentJSON},
			"Origin":  {"https://" + adminHost},
			"Referer": {"https://" + adminHost + "/admin/"},
		}
		login := []byte(`{"username":"` + superName + `","password":"` + superPassword + `"}`)
		for _, host := range []string{hostA, hostB} {
			for _, r := range []request{
				{method: http.MethodGet, path: pathAdminMe},
				{method: http.MethodGet, path: pathAdmins},
				{method: http.MethodGet, path: pathAdminSetup},
				{method: http.MethodPost, path: pathAdminLogin, body: login},
				{method: http.MethodPost, path: pathAdminLogout},
				{method: http.MethodDelete, path: pathAdmins + "/" + sa.acct.id},
				{method: http.MethodGet, path: "/api/v1/admin/tenants/" + string(a.tenantA.ID)},
			} {
				r.host, r.headers = host, adminCookie
				resp := a.do(t, r)
				if resp.status != http.StatusNotFound {
					t.Errorf("%s %s on %s = %d %s, want 404", r.method, r.path, host, resp.status, resp.body)
					continue
				}
				expectProblem(t, resp, http.StatusNotFound, "not-found")
				if strings.Contains(string(resp.body), superName) || strings.Contains(string(resp.body), sa.acct.id) {
					t.Errorf("%s %s on %s leaked the admin account: %s", r.method, r.path, host, resp.body)
				}
				if _, set := sessionCookie(t, resp); set {
					t.Errorf("%s %s on %s touched the admin cookie", r.method, r.path, host)
				}
			}
		}
		// The admin session token is not a deposit session, under either
		// cookie name.
		for _, cookie := range []string{adminCookieName + "=" + sa.cookie, depositCookieName + "=" + sa.cookie} {
			resp := a.do(t, request{host: hostA, path: pathCurrentSession, headers: http.Header{"Cookie": {cookie}, hdrXFF: {insideA}}})
			expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
		}
		// The public API is absent from the admin host.
		for _, r := range []request{
			{method: http.MethodGet, path: pathCurrentSession},
			{method: http.MethodPost, path: pathSessions, body: []byte(`{"email":"someone@` + domainA + `"}`)},
			{method: http.MethodGet, path: "/api/v1/tenant"},
			{method: http.MethodGet, path: pathDownloads + "dl_0123456789"},
		} {
			r.host, r.headers = adminHost, adminCookie
			resp := a.do(t, r)
			if resp.status != http.StatusNotFound {
				t.Errorf("%s %s on the admin host = %d %s, want 404", r.method, r.path, resp.status, resp.body)
				continue
			}
			expectProblem(t, resp, http.StatusNotFound, "not-found")
		}
		sa.me(t)
		if cc := sa.send(t, http.MethodGet, pathAdminMe, nil, nil).header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("admin answer Cache-Control = %q, want no-store", cc)
		}
	})
}
