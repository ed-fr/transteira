package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Helpers of the administrator authentication tests (CLAUDE.md sections
// 6.5, 6.6 and 16.2; api/openapi.yaml "Admin auth" and "Admins"; threat
// model T-58 to T-67, T-102).

// Admin API paths, cookie and fixed values.
const (
	pathAdminSetup      = "/api/v1/admin/setup"
	pathAdminLogin      = "/api/v1/admin/auth/login"
	pathAdminTOTP       = "/api/v1/admin/auth/totp"
	pathAdminLogout     = "/api/v1/admin/auth/logout"
	pathAdminMe         = "/api/v1/admin/me"
	pathAdminPassword   = "/api/v1/admin/me/password"
	pathAdminEnroll     = "/api/v1/admin/me/totp"
	pathAdminConfirm    = "/api/v1/admin/me/totp/confirm"
	pathAdmins          = "/api/v1/admin/admins"
	pathAdminActivation = "/api/v1/admin/activation"
	adminCookieName     = "__Host-tt_admin"
	// adminSetupToken is TT_SETUP_TOKEN of the admin tests.
	adminSetupToken = "stp_integration-setup-token-0123456789"
	// superName and superPassword are the first super admin's credentials.
	superName     = "superadmin"
	superPassword = "correct horse battery staple"
	// adminNet prefixes the X-Forwarded-For addresses of the admin
	// clients: a documentation range (RFC 5737).
	adminNet = "198.51.100."
	// Login states (OpenAPI LoginState.status).
	stateTOTPRequired   = "totp_required"
	stateEnrollRequired = "totp_enrollment_required"
	stateAuthenticated  = "authenticated"
	// mergePatch is the media type of updateAdmin.
	mergePatch = "application/merge-patch+json"
	// lockRetryMin is a lower bound of the Retry-After of a database lock
	// of the admin logins (15 minutes), well above the 3-second refill of
	// the in-memory admin_auth limiter, so that the two cannot be confused.
	lockRetryMin = 60
)

// adminIP returns the client IP adminNet+n.
func adminIP(n int) string { return adminNet + strconv.Itoa(n) }

// activationRE extracts the activation token from an activation link (the
// token is in the fragment).
var activationRE = regexp.MustCompile(`^https://` + regexp.QuoteMeta(adminHost) + `/admin/activate#(act_[0-9A-Za-z]{43})$`)

// activationLineRE finds the activation link printed by "admin
// reset-password".
var activationLineRE = regexp.MustCompile(`(?m)^https://` + regexp.QuoteMeta(adminHost) + `/admin/activate#act_[0-9A-Za-z]{43}$`)

// adminEnv is a running server with an admin host, the database handle of
// its engine and, for the delegated admin tests, tenant A sending its
// mails to Mailpit (where no activation mail may ever arrive: the links
// are returned by the API only).
type adminEnv struct {
	*depositEnv
	e storetest.Engine
	o serverOptions
	// secrets collects every password, token and code the test used: none
	// may appear in the audit log, the security log or the application
	// log.
	secrets []string
}

// startAdmin starts a server for the admin tests: TT_SETUP_TOKEN is
// adminSetupToken unless o.env sets it, and the loopback is the trusted
// proxy, so that every client gets its own X-Forwarded-For address.
func startAdmin(t *testing.T, e storetest.Engine, o serverOptions, withMail bool) *adminEnv {
	t.Helper()
	env := map[string]string{config.EnvSetupToken: adminSetupToken}
	for k, v := range o.env {
		env[k] = v
	}
	if env[config.EnvSetupToken] == "" {
		delete(env, config.EnvSetupToken)
	}
	o.env = env
	if o.trustedProxies == "" {
		o.trustedProxies = loopbackProxy
	}
	if o.clamd == "" {
		o.clamd = fakeClamd(t)
	}
	a := &adminEnv{depositEnv: startDeposit(t, e, o, withMail), e: e, o: o}
	a.secrets = append(a.secrets, adminSetupToken, superPassword)
	return a
}

// secret records s as a secret that must never be logged.
func (a *adminEnv) secret(s ...string) { a.secrets = append(a.secrets, s...) }

// adminAccount is an administrator known to the test, with its TOTP
// secret and the last TOTP step used, shared by all its clients.
type adminAccount struct {
	id, username, email, password string
	secret                        []byte
	lastStep                      uint64
	haveStep                      bool
	recovery                      []string
}

// nextCode returns a TOTP code of acct for a time step never used yet:
// the current step, or the step after the last one used. The server
// accepts one step of drift on each side, so the step after the current
// one is still valid; beyond it, the test waits for the clock.
func (acct *adminAccount) nextCode(t *testing.T) string {
	t.Helper()
	if len(acct.secret) == 0 {
		t.Fatalf("account %s has no TOTP secret", acct.username)
	}
	step := crypto.TOTPCounter(time.Now())
	if acct.haveStep && acct.lastStep >= step {
		step = acct.lastStep + 1
	}
	if step > crypto.TOTPCounter(time.Now())+1 {
		eventually(t, "next TOTP time step", func() bool { return crypto.TOTPCounter(time.Now())+1 >= step })
	}
	acct.lastStep, acct.haveStep = step, true
	return crypto.TOTPCode(acct.secret, step)
}

// wrongCode returns a well-formed TOTP code that matches no step the
// server accepts now (nor the steps used so far).
func (acct *adminAccount) wrongCode(t *testing.T) string {
	t.Helper()
	cur := crypto.TOTPCounter(time.Now())
	valid := map[string]bool{}
	for s := cur - 2; s <= cur+3; s++ {
		valid[crypto.TOTPCode(acct.secret, s)] = true
	}
	for n := uint64(1000); ; n++ {
		if c := crypto.TOTPCode(acct.secret, cur+n); !valid[c] {
			return c
		}
	}
}

// takeRecovery removes and returns an unused recovery code of acct.
func (acct *adminAccount) takeRecovery(t *testing.T) string {
	t.Helper()
	if len(acct.recovery) == 0 {
		t.Fatalf("account %s has no recovery code left", acct.username)
	}
	c := acct.recovery[0]
	acct.recovery = acct.recovery[1:]
	return c
}

// adminClient is one browser of the admin host: a client IP sent through
// the trusted proxy, its session cookie and CSRF token.
type adminClient struct {
	a      *adminEnv
	acct   *adminAccount
	ip     string
	cookie string // raw session token; "" sends no cookie
	csrf   string
	state  string // login state of the last login step
}

// client returns a new client of acct (nil for an anonymous one) from ip.
func (a *adminEnv) client(acct *adminAccount, ip string) *adminClient {
	return &adminClient{a: a, acct: acct, ip: ip}
}

// send sends a request to the admin host with the client's IP and cookie
// plus extra headers; body is marshaled to JSON unless it is a string or
// nil. It never adds the CSRF token (see call) and never changes the
// client's cookie (see keep).
func (c *adminClient) send(t *testing.T, method, path string, body any, extra http.Header) response {
	t.Helper()
	h := http.Header{}
	if c.ip != "" {
		h.Set(hdrXFF, c.ip)
	}
	if c.cookie != "" {
		h.Set("Cookie", adminCookieName+"="+c.cookie)
	}
	for k, vs := range extra {
		h[k] = vs
	}
	r := request{method: method, path: path, host: adminHost, headers: h}
	switch b := body.(type) {
	case nil:
	case string:
		r.body = []byte(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		r.body = raw
	}
	return c.a.do(t, r)
}

// call is send with the client's CSRF token on unsafe methods.
func (c *adminClient) call(t *testing.T, method, path string, body any) response {
	t.Helper()
	var extra http.Header
	if method != http.MethodGet && method != http.MethodHead && c.csrf != "" {
		extra = http.Header{hdrCSRF: {c.csrf}}
	}
	return c.send(t, method, path, body, extra)
}

// patch sends updateAdmin for adminID with the merge patch body.
func (c *adminClient) patch(t *testing.T, adminID string, body any) response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return c.send(t, http.MethodPatch, pathAdmins+"/"+adminID, string(raw),
		http.Header{hdrCSRF: {c.csrf}, "Content-Type": {mergePatch}})
}

// sessionCookie returns the admin session cookie set by resp, if any.
func sessionCookie(t *testing.T, resp response) (*http.Cookie, bool) {
	t.Helper()
	var found *http.Cookie
	for _, line := range resp.header.Values("Set-Cookie") {
		ck, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatalf("invalid Set-Cookie %q: %v", line, err)
		}
		if ck.Name == adminCookieName {
			if found != nil {
				t.Errorf("two admin Set-Cookie headers: %v", resp.header.Values("Set-Cookie"))
			}
			found = ck
		}
	}
	return found, found != nil
}

// expectSessionCookie asserts that resp sets a new admin session cookie
// with the __Host- attributes and returns its value.
func expectSessionCookie(t *testing.T, resp response) string {
	t.Helper()
	ck, ok := sessionCookie(t, resp)
	if !ok {
		t.Fatalf("no %s cookie set; headers: %v", adminCookieName, resp.header)
	}
	if !strings.HasPrefix(ck.Value, "as_") || ck.MaxAge <= 0 || !ck.Secure || !ck.HttpOnly ||
		ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" {
		t.Errorf("admin cookie %q lacks the __Host- session attributes", resp.header.Values("Set-Cookie"))
	}
	return ck.Value
}

// expectCookieCleared asserts that resp expires the admin session cookie.
func expectCookieCleared(t *testing.T, resp response) {
	t.Helper()
	ck, ok := sessionCookie(t, resp)
	if !ok || ck.Value != "" || ck.MaxAge >= 0 {
		t.Errorf("admin cookie not cleared; Set-Cookie: %v", resp.header.Values("Set-Cookie"))
	}
}

// loginStateJSON is the LoginState schema.
type loginStateJSON struct {
	Status    string `json:"status"`
	CSRFToken string `json:"csrfToken"`
}

// enrollmentJSON is the TotpEnrollment schema (setup adds csrfToken).
type enrollmentJSON struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauthUri"`
	QRCodePNG  []byte `json:"qrCodePng"`
	CSRFToken  string `json:"csrfToken"`
}

// confirmedJSON is the TotpConfirmed schema.
type confirmedJSON struct {
	RecoveryCodes []string `json:"recoveryCodes"`
	CSRFToken     string   `json:"csrfToken"`
}

// meJSON is the AdminMe schema.
type meJSON struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totpEnabled"`
	CSRFToken   string `json:"csrfToken"`
	Tenants     []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		FQDN string `json:"fqdn"`
	} `json:"tenants"`
}

// adminJSON is the Admin schema, with the fields of AdminWithActivation
// (createAdmin and resetAdminCredentials).
type adminJSON struct {
	ID                  string    `json:"id"`
	Username            string    `json:"username"`
	Email               string    `json:"email"`
	Role                string    `json:"role"`
	TenantIDs           []string  `json:"tenantIds"`
	TOTPEnabled         bool      `json:"totpEnabled"`
	Activated           bool      `json:"activated"`
	Disabled            bool      `json:"disabled"`
	ActivationURL       string    `json:"activationUrl"`
	ActivationExpiresAt time.Time `json:"activationExpiresAt"`
}

// activationOf returns the token of the activation link of an
// AdminWithActivation answer, checking the link format and its 72-hour
// validity.
func (a *adminEnv) activationOf(t *testing.T, resp response) (adminJSON, string) {
	t.Helper()
	var body adminJSON
	mustJSON(t, resp.body, &body)
	m := activationRE.FindStringSubmatch(body.ActivationURL)
	if m == nil {
		t.Fatalf("activationUrl = %q, want https://%s/admin/activate#act_...", body.ActivationURL, adminHost)
	}
	if left := time.Until(body.ActivationExpiresAt); left < 71*time.Hour || left > 72*time.Hour {
		t.Errorf("activationExpiresAt = %v, want 72 hours from now", body.ActivationExpiresAt)
	}
	if body.Activated {
		t.Errorf("an account with a fresh activation link is activated: %+v", body)
	}
	a.secret(m[1])
	return body, m[1]
}

// expectNoMail asserts that Mailpit holds no mail to addr: activation
// links are never mailed.
func (a *adminEnv) expectNoMail(t *testing.T, addr string) {
	t.Helper()
	if msgs := a.mp.messagesTo(t, addr); len(msgs) != 0 {
		t.Errorf("%d mails to %s, want none (activation links are never mailed)", len(msgs), addr)
	}
}

// decodeSecret decodes the base32 TOTP secret of an enrollment.
func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(b) < 16 {
		t.Fatalf("invalid TOTP secret %q: %v", s, err)
	}
	return b
}

// adopt takes the session cookie and the CSRF token of a successful login
// step.
func (c *adminClient) adopt(t *testing.T, resp response, csrf, state string) {
	t.Helper()
	c.cookie = expectSessionCookie(t, resp)
	c.csrf, c.state = csrf, state
	c.a.secret(c.cookie, csrf)
}

// setup sends createSuperAdmin with token ("" omits it).
func (c *adminClient) setup(t *testing.T, username, email, password, token string) response {
	t.Helper()
	body := map[string]string{"username": username, "email": email, "password": password}
	if token != "" {
		body["setupToken"] = token
	}
	return c.send(t, http.MethodPost, pathAdminSetup, body, nil)
}

// confirm sends confirmTotpEnrollment with code; on 200 it records the
// recovery codes and, when the session was rotated, the new cookie.
func (c *adminClient) confirm(t *testing.T, code string) response {
	t.Helper()
	resp := c.call(t, http.MethodPost, pathAdminConfirm, map[string]string{"code": code})
	if resp.status == http.StatusOK {
		var conf confirmedJSON
		mustJSON(t, resp.body, &conf)
		if len(conf.RecoveryCodes) != 8 {
			t.Fatalf("confirm returned %d recovery codes, want 8: %s", len(conf.RecoveryCodes), resp.body)
		}
		c.acct.recovery = conf.RecoveryCodes
		c.a.secret(conf.RecoveryCodes...)
		if _, rotated := sessionCookie(t, resp); rotated {
			c.adopt(t, resp, conf.CSRFToken, stateAuthenticated)
		}
	}
	return resp
}

// bootstrap runs the first-run setup and the TOTP enrollment of the super
// admin from ip, and returns the authenticated client.
func (a *adminEnv) bootstrap(t *testing.T, ip string) *adminClient {
	t.Helper()
	acct := &adminAccount{username: superName, email: "root@" + domainA, password: superPassword}
	c := a.client(acct, ip)
	resp := c.setup(t, acct.username, acct.email, acct.password, adminSetupToken)
	if resp.status != http.StatusCreated {
		t.Fatalf("setup: %d %s", resp.status, resp.body)
	}
	var enr enrollmentJSON
	mustJSON(t, resp.body, &enr)
	c.adopt(t, resp, enr.CSRFToken, stateEnrollRequired)
	acct.secret = decodeSecret(t, enr.Secret)
	a.secret(enr.Secret)
	if resp := c.confirm(t, acct.nextCode(t)); resp.status != http.StatusOK || c.state != stateAuthenticated {
		t.Fatalf("confirm the super admin enrollment: %d %s", resp.status, resp.body)
	}
	acct.id = c.me(t).ID
	return c
}

// login sends adminLogin with the account's username and password; a 200
// sets the client's cookie.
func (c *adminClient) login(t *testing.T, username, password string) response {
	t.Helper()
	resp := c.send(t, http.MethodPost, pathAdminLogin, map[string]string{"username": username, "password": password}, nil)
	if resp.status == http.StatusOK {
		var st loginStateJSON
		mustJSON(t, resp.body, &st)
		c.adopt(t, resp, st.CSRFToken, st.Status)
	}
	return resp
}

// verify sends adminVerifyTotp with a TOTP code or a recovery code; a 200
// sets the client's rotated cookie.
func (c *adminClient) verify(t *testing.T, code, recovery string) response {
	t.Helper()
	body := map[string]string{}
	if code != "" {
		body["code"] = code
		c.a.secret(code)
	}
	if recovery != "" {
		body["recoveryCode"] = recovery
	}
	resp := c.call(t, http.MethodPost, pathAdminTOTP, body)
	if resp.status == http.StatusOK {
		var st loginStateJSON
		mustJSON(t, resp.body, &st)
		c.adopt(t, resp, st.CSRFToken, st.Status)
	}
	return resp
}

// mustLogin logs in with the account's password and expects state.
func (c *adminClient) mustLogin(t *testing.T, state string) {
	t.Helper()
	resp := c.login(t, c.acct.username, c.acct.password)
	if resp.status != http.StatusOK || c.state != state {
		t.Fatalf("login of %s: %d %s, want state %s", c.acct.username, resp.status, resp.body, state)
	}
}

// signIn logs in with the password and a fresh TOTP code.
func (c *adminClient) signIn(t *testing.T) {
	t.Helper()
	c.mustLogin(t, stateTOTPRequired)
	if resp := c.verify(t, c.acct.nextCode(t), ""); resp.status != http.StatusOK || c.state != stateAuthenticated {
		t.Fatalf("TOTP of %s: %d %s", c.acct.username, resp.status, resp.body)
	}
}

// signInRecovery logs in with the password and a recovery code, which
// spares a TOTP time step.
func (c *adminClient) signInRecovery(t *testing.T) {
	t.Helper()
	c.mustLogin(t, stateTOTPRequired)
	if resp := c.verify(t, "", c.acct.takeRecovery(t)); resp.status != http.StatusOK || c.state != stateAuthenticated {
		t.Fatalf("recovery code of %s: %d %s", c.acct.username, resp.status, resp.body)
	}
}

// me sends getAdminMe and expects 200.
func (c *adminClient) me(t *testing.T) meJSON {
	t.Helper()
	resp := c.send(t, http.MethodGet, pathAdminMe, nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("GET /admin/me: %d %s", resp.status, resp.body)
	}
	var me meJSON
	mustJSON(t, resp.body, &me)
	if me.CSRFToken != c.csrf {
		t.Errorf("me.csrfToken = %q, want the CSRF token of the login step %q", me.CSRFToken, c.csrf)
	}
	return me
}

// expectUnauthenticated asserts that the client's session is refused:
// 401 unauthenticated, and the cookie cleared.
func (c *adminClient) expectUnauthenticated(t *testing.T, what string) {
	t.Helper()
	resp := c.send(t, http.MethodGet, pathAdminMe, nil, nil)
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("%s: GET /admin/me = %d %s, want 401", what, resp.status, resp.body)
	}
	expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
	expectCookieCleared(t, resp)
}

// expectRateLimited asserts a 429 rate-limited answer of a database lock
// of the admin logins (Retry-After of minutes, at most 15).
func expectRateLimited(t *testing.T, what string, resp response) {
	t.Helper()
	if resp.status != http.StatusTooManyRequests {
		t.Fatalf("%s: %d %s, want 429", what, resp.status, resp.body)
	}
	expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
	ra, err := strconv.Atoi(resp.header.Get(hdrRetryAfter))
	if err != nil || ra < lockRetryMin || ra > 15*60 {
		t.Errorf("%s: Retry-After = %q, want the remaining lock (%d s to 900 s)", what, resp.header.Get(hdrRetryAfter), lockRetryMin)
	}
}

// createDelegated creates, as the super admin c, a delegated admin of
// tenant A and returns its account (id set, no password yet) and the
// activation token of the link returned by createAdmin.
func (c *adminClient) createDelegated(t *testing.T, username string) (*adminAccount, string) {
	t.Helper()
	acct := &adminAccount{username: username, email: uniqueEmail(t, username, domainA), password: "delegated password " + username}
	resp := c.call(t, http.MethodPost, pathAdmins, map[string]any{
		"username": username, "email": acct.email, "role": "delegated_admin", "tenantIds": []string{string(c.a.tenantA.ID)},
	})
	if resp.status != http.StatusCreated {
		t.Fatalf("createAdmin %s: %d %s", username, resp.status, resp.body)
	}
	created, token := c.a.activationOf(t, resp)
	if created.Role != "delegated_admin" || len(created.TenantIDs) != 1 || created.TenantIDs[0] != string(c.a.tenantA.ID) || created.TOTPEnabled {
		t.Errorf("created admin = %+v", created)
	}
	acct.id = created.ID
	c.a.secret(acct.password)
	return acct, token
}

// activate uses an activation link with the account's password; a 200
// sets the client's cookie.
func (c *adminClient) activate(t *testing.T, token string) response {
	t.Helper()
	resp := c.send(t, http.MethodPost, pathAdminActivation, map[string]string{"activationToken": token, "password": c.acct.password}, nil)
	if resp.status == http.StatusOK {
		var st loginStateJSON
		mustJSON(t, resp.body, &st)
		c.adopt(t, resp, st.CSRFToken, st.Status)
	}
	return resp
}

// enroll runs the first TOTP enrollment of a session in state
// totp_enrollment_required (or authenticated) to its end.
func (c *adminClient) enroll(t *testing.T) {
	t.Helper()
	c.enrollWith(t, nil)
}

// enrollWith is enroll with the request body of startTotpEnrollment (the
// current password of a re-enrollment).
func (c *adminClient) enrollWith(t *testing.T, body any) {
	t.Helper()
	resp := c.call(t, http.MethodPost, pathAdminEnroll, body)
	if resp.status != http.StatusOK {
		t.Fatalf("startTotpEnrollment: %d %s", resp.status, resp.body)
	}
	var enr enrollmentJSON
	mustJSON(t, resp.body, &enr)
	if !strings.HasPrefix(enr.OtpauthURI, "otpauth://totp/") || !bytes.HasPrefix(enr.QRCodePNG, []byte("\x89PNG")) {
		t.Errorf("enrollment lacks its otpauth URI or QR code: %q", enr.OtpauthURI)
	}
	c.acct.secret, c.acct.haveStep = decodeSecret(t, enr.Secret), false
	c.a.secret(enr.Secret)
	if resp := c.confirm(t, c.acct.nextCode(t)); resp.status != http.StatusOK {
		t.Fatalf("confirmTotpEnrollment: %d %s", resp.status, resp.body)
	}
	if c.state != stateAuthenticated {
		t.Fatalf("state after the enrollment = %s, want authenticated", c.state)
	}
}

// sysQuery runs a read query on the database of e in the system scope (on
// PostgreSQL, app.system_scope = 'on') and returns every row, each column
// as a string ("" for NULL).
func sysQuery(t *testing.T, e storetest.Engine, query string) [][]string {
	t.Helper()
	driver, dsn := "sqlite", e.DSN
	if e.Driver == config.DriverPostgres {
		driver = "pgx"
	} else {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "_pragma=busy_timeout(10000)"
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	ctx := context.Background()
	tx, err := raw.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if driver == "pgx" {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', 'on', true)`); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out
}

// tokenHashSQL returns the SQL literal of the SHA-256 of a session token,
// as admin_sessions.token_hash stores it.
func tokenHashSQL(e storetest.Engine, token string) string {
	h := sha256.Sum256([]byte(token))
	if e.Driver == config.DriverPostgres {
		return "decode('" + hex.EncodeToString(h[:]) + "', 'hex')"
	}
	return "X'" + hex.EncodeToString(h[:]) + "'"
}

// ageSession runs set (a SET clause of admin_sessions) on the session of
// the client's cookie, as if time had passed.
func (c *adminClient) ageSession(t *testing.T, set string) {
	t.Helper()
	execSystem(t, c.a.e, "UPDATE admin_sessions SET "+set+" WHERE token_hash = "+tokenHashSQL(c.a.e, c.cookie))
}

// millis returns the Unix milliseconds of now+d (the timestamp format of
// the admin tables).
func millis(d time.Duration) string { return strconv.FormatInt(time.Now().Add(d).UnixMilli(), 10) }

// auditRow is an audit_events row.
type auditRow struct {
	actorKind, actor, ip, action, objectID, details string
}

// auditRows returns the global audit events (tenant_id NULL), oldest
// first.
func (a *adminEnv) auditRows(t *testing.T) []auditRow {
	t.Helper()
	rows := sysQuery(t, a.e, `SELECT actor_kind, actor, ip, action, object_id, details FROM audit_events WHERE tenant_id IS NULL ORDER BY at, id`)
	out := make([]auditRow, len(rows))
	for i, r := range rows {
		out[i] = auditRow{actorKind: r[0], actor: r[1], ip: r[2], action: r[3], objectID: r[4], details: r[5]}
	}
	return out
}

// expectAudit asserts that the audit log holds at least one event of each
// action and that no audit event, security log line or application log
// line carries one of the secrets the test used.
func (a *adminEnv) expectAudit(t *testing.T, actions ...string) []auditRow {
	t.Helper()
	rows := a.auditRows(t)
	seen := map[string]int{}
	for _, r := range rows {
		seen[r.action]++
	}
	for _, act := range actions {
		if seen[act] == 0 {
			t.Errorf("no %s audit event; audit actions: %v", act, seen)
		}
	}
	a.expectNoSecrets(t, rows)
	return rows
}

// expectNoSecrets asserts that none of the secrets used appears in rows,
// in the security log or in the application log. The setup token is
// tolerated in the application log only when the application generated
// it (it is then printed on purpose).
func (a *adminEnv) expectNoSecrets(t *testing.T, rows []auditRow) {
	t.Helper()
	logs := map[string]string{
		"security log":    strings.Join(a.securityLines(t), "\n"),
		"application log": a.appLog.String(),
	}
	for _, r := range rows {
		logs["audit event "+r.action] = strings.Join([]string{r.actor, r.ip, r.objectID, r.details}, " ")
	}
	for where, text := range logs {
		for _, s := range a.secrets {
			if len(s) < 6 {
				continue
			}
			if digitsRE.MatchString(s) {
				// A TOTP code: matched as a whole number, and not in the
				// application log, whose timestamps and durations hold
				// arbitrary digit runs.
				if where != "application log" && regexp.MustCompile(`\b`+s+`\b`).MatchString(text) {
					t.Errorf("%s contains the TOTP code %s", where, s)
				}
				continue
			}
			if strings.Contains(text, s) {
				t.Errorf("%s contains the secret %.12s...", where, s)
			}
		}
	}
}

// digitsRE matches a TOTP code.
var digitsRE = regexp.MustCompile(`^[0-9]{6}$`)

// logLinesOf returns the security log lines of event from ip whose fields
// contain field (for example scope="admin_login").
func (a *adminEnv) logLinesOf(t *testing.T, event, ip, field string) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range eventsOf(t, a.securityLines(t), event) {
		if l.ip == ip && strings.Contains(l.fields, field) {
			out = append(out, l)
		}
	}
	return out
}

// waitLogLines waits until the security log holds at least n lines of
// event from ip with field, and checks that they belong to no tenant.
func (a *adminEnv) waitLogLines(t *testing.T, event, ip, field string, n int) []logLine {
	t.Helper()
	var lines []logLine
	eventually(t, event+" "+field+" from "+ip+" in the security log", func() bool {
		lines = a.logLinesOf(t, event, ip, field)
		return len(lines) >= n
	})
	for _, l := range lines {
		if l.tenant != "-" {
			t.Errorf("admin security event with tenant %q, want -: %s", l.tenant, l.raw)
		}
	}
	return lines
}

// runCLI runs the transteira binary with args and env (and no other TT_
// variable of the test process), and returns its exit code and outputs.
func runCLI(t *testing.T, bin string, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "TT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String(), stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	default:
		t.Fatalf("run transteira %v: %v", args, err)
		return -1, "", ""
	}
}
