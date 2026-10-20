package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Network rules of the deposit tests (CLAUDE.md section 6.2). Every
// address is a documentation range (RFC 5737) sent in X-Forwarded-For by
// the loopback, declared as the trusted proxy.
const (
	domainA      = "entity-a.localhost"
	domainB      = "entity-b.localhost"
	internalNetA = "192.0.2.0/24"
	internalNetB = "203.0.113.0/24"
	// insideA is an internal IP of tenant A.
	insideA = "192.0.2.10"
	// outside is in no range of either tenant.
	outside = "198.51.100.20"
	// externalDomain is the domain of invited external depositors.
	externalDomain = "partner.example.org"
	// loopbackProxy is TT_TRUSTED_PROXIES for the deposit tests.
	loopbackProxy = "127.0.0.1"
)

// Deposit API paths.
const (
	pathSessions        = "/api/v1/deposit-sessions"
	pathCurrentSession  = "/api/v1/deposit-sessions/current"
	pathInvitations     = "/api/v1/invitations"
	depositCookieName   = "__Host-tt_deposit"
	knownCookieName     = "__Host-tt_known"
	knownCookieMaxAge   = 365 * 24 * 60 * 60
	hdrCSRF             = "X-CSRF-Token"
	hdrXFF              = "X-Forwarded-For"
	defaultSessionTTL   = 4 * time.Hour
	mailpitPollInterval = 100 * time.Millisecond
)

// Mailpit environment variables (exported by make test).
const (
	envMailpitSMTP = "TT_TEST_MAILPIT_SMTP"
	envMailpitAPI  = "TT_TEST_MAILPIT_API"
)

// mailpit is the shared Mailpit server capturing the mails of the tests.
type mailpit struct {
	host string
	port int
	api  string
}

// mailpitEnv returns the Mailpit server, or skips the test when it is not
// configured. Under make check (TT_TEST_REQUIRE_POSTGRES=1, which also
// starts Mailpit) a missing Mailpit is a failure, never a silent skip.
func mailpitEnv(t *testing.T) *mailpit {
	t.Helper()
	smtpAddr, api := os.Getenv(envMailpitSMTP), os.Getenv(envMailpitAPI)
	if smtpAddr == "" || api == "" {
		if os.Getenv(storetest.EnvRequirePostgres) == "1" {
			t.Fatalf("%s and %s must be set when %s=1", envMailpitSMTP, envMailpitAPI, storetest.EnvRequirePostgres)
		}
		t.Skipf("%s and %s not set", envMailpitSMTP, envMailpitAPI)
	}
	h, p, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		t.Fatalf("%s: %v", envMailpitSMTP, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("%s: %v", envMailpitSMTP, err)
	}
	return &mailpit{host: h, port: port, api: strings.TrimSuffix(api, "/")}
}

// mpAddress is a Mailpit address.
type mpAddress struct {
	Name    string `json:"Name"`
	Address string `json:"Address"`
}

// mpMessage is a Mailpit message (summary and detail share these fields).
type mpMessage struct {
	ID      string      `json:"ID"`
	Subject string      `json:"Subject"`
	From    mpAddress   `json:"From"`
	To      []mpAddress `json:"To"`
	Text    string      `json:"Text"`
	HTML    string      `json:"HTML"`
}

// get decodes a JSON response of the Mailpit API.
func (m *mailpit) get(t *testing.T, path string, out any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, m.api+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: waitTimeout, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatalf("Mailpit GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Mailpit GET %s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("Mailpit GET %s: %v", path, err)
	}
}

// messagesTo returns the summaries of the messages whose recipients include
// addr. Each test uses unique recipient addresses, so that the parallel
// tests sharing Mailpit never see each other's mails.
func (m *mailpit) messagesTo(t *testing.T, addr string) []mpMessage {
	t.Helper()
	var list struct {
		Messages []mpMessage `json:"messages"`
	}
	m.get(t, "/api/v1/search?limit=50&query="+url.QueryEscape(`to:"`+addr+`"`), &list)
	var out []mpMessage
	for _, msg := range list.Messages {
		if slices.ContainsFunc(msg.To, func(a mpAddress) bool { return strings.EqualFold(a.Address, addr) }) {
			out = append(out, msg)
		}
	}
	return out
}

// find polls Mailpit until a message to addr satisfies match, and returns
// it with its bodies. Mails are delivered asynchronously by the queue: the
// bounded polling of the external Mailpit is the only way to observe them.
func (m *mailpit) find(t *testing.T, addr string, match func(mpMessage) bool) mpMessage {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	tick := time.NewTicker(mailpitPollInterval)
	defer tick.Stop()
	for {
		for _, msg := range m.messagesTo(t, addr) {
			if match(msg) {
				var full mpMessage
				m.get(t, "/api/v1/message/"+url.PathEscape(msg.ID), &full)
				return full
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching message for %s in Mailpit within %s", addr, waitTimeout)
		}
		<-tick.C
	}
}

// only returns the single message sent to addr, with its bodies. Callers
// first wait for its delivery (see depositEnv.waitMailSent).
func (m *mailpit) only(t *testing.T, addr string) mpMessage {
	t.Helper()
	full := m.find(t, addr, func(mpMessage) bool { return true })
	if n := len(m.messagesTo(t, addr)); n != 1 {
		t.Fatalf("Mailpit holds %d messages for %s, want exactly 1", n, addr)
	}
	return full
}

// depositEnv is a running server whose tenants are configured for
// deposits, with a store handle to configure them further as an operator
// would.
type depositEnv struct {
	*server
	db *store.DB
	mp *mailpit // nil when tenant A has no SMTP settings
}

// startDeposit starts a server (TT_TRUSTED_PROXIES defaults to the
// loopback) and configures the network rules of both tenants: tenant A
// accepts internalNetA and domainA, tenant B internalNetB and domainB.
// With withMail, tenant A sends its mails to Mailpit through a plain
// relay without authentication (CLAUDE.md section 12.1); tenant B never
// has SMTP settings.
func startDeposit(t *testing.T, e storetest.Engine, o serverOptions, withMail bool) *depositEnv {
	t.Helper()
	var mp *mailpit
	if withMail {
		mp = mailpitEnv(t)
	}
	if o.trustedProxies == "" {
		o.trustedProxies = loopbackProxy
	}
	s := startServer(t, e, o)
	db, err := store.Open(context.Background(), e.Config())
	if err != nil {
		t.Fatalf("store.Open(%s): %v", e.Name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d := &depositEnv{server: s, db: db, mp: mp}
	d.setRules(t, true, []string{internalNetA}, domainA)
	d.setRules(t, false, []string{internalNetB}, domainB)
	if mp != nil {
		err := db.SMTPSettings().Put(context.Background(), s.tenantA.ID, store.SMTPConfig{
			Host: mp.host, Port: mp.port, Security: store.SMTPSecurityNone,
			FromAddress: "noreply@" + domainA, FromName: nameA,
		})
		if err != nil {
			t.Fatalf("put SMTP settings: %v", err)
		}
	}
	return d
}

// setRules replaces the network rules of tenant A (onA) or B.
func (d *depositEnv) setRules(t *testing.T, onA bool, cidrs []string, domains ...string) {
	t.Helper()
	tid := d.tenantB.ID
	if onA {
		tid = d.tenantA.ID
	}
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		prefixes[i] = netip.MustParsePrefix(c)
	}
	if _, err := d.db.NetworkRules().Replace(context.Background(), tid, prefixes, domains); err != nil {
		t.Fatalf("replace network rules: %v", err)
	}
}

// block adds a blocklist entry to tenant A.
func (d *depositEnv) block(t *testing.T, kind store.BlocklistKind, value string) {
	t.Helper()
	_, err := d.db.Blocklist().Create(context.Background(), d.tenantA.ID, store.BlocklistEntry{
		Kind: kind, Value: value, CreatedBy: "admin@" + domainA,
	})
	if err != nil {
		t.Fatalf("create blocklist entry: %v", err)
	}
}

// mailSentLines returns the "mail sent" lines of the application log whose
// recipients are exactly addr (the queue logs a pseudonym, never the
// address).
func (d *depositEnv) mailSentLines(t *testing.T, addr string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(d.appLog.String(), "\n") {
		var rec struct {
			Msg        string   `json:"msg"`
			Recipients []string `json:"recipients"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Msg == "mail sent" && slices.Equal(rec.Recipients, []string{mail.AddressHash(addr)}) {
			n++
		}
	}
	return n
}

// waitMailSent waits until the mail queue reports the delivery of the
// first mail to addr (the queue has a single worker, so every mail queued
// before it was handled too), then fails if that delivery failed.
func (d *depositEnv) waitMailSent(t *testing.T, addr string) {
	t.Helper()
	select {
	case <-d.appLog.wait(`"recipients":["` + mail.AddressHash(addr) + `"]`):
	case <-time.After(waitTimeout):
		t.Fatalf("no mail handled for %s within %s\napp log:\n%s", addr, waitTimeout, d.appLog)
	}
	if d.mailSentLines(t, addr) == 0 {
		t.Fatalf("mail to %s was not delivered\napp log:\n%s", addr, d.appLog)
	}
}

// codeRE extracts the verification code from the text part of the mail.
var codeRE = regexp.MustCompile(`(?m)^\s+(\d{6})\s*$`)

// codeMail waits for the single code mail sent to addr and returns the
// message and its code.
func (d *depositEnv) codeMail(t *testing.T, addr string) (mpMessage, string) {
	t.Helper()
	d.waitMailSent(t, addr)
	msg := d.mp.only(t, addr)
	m := codeRE.FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("no code in the mail to %s:\n%s", addr, msg.Text)
	}
	if !strings.Contains(msg.HTML, m[1]) {
		t.Errorf("the HTML part of the mail to %s lacks the code", addr)
	}
	return msg, m[1]
}

// uniqueEmail returns local-<random>@domain: the random part only keeps
// the recipients of the parallel tests apart in the shared Mailpit.
func uniqueEmail(t *testing.T, local, domain string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return local + "-" + hex.EncodeToString(b[:]) + "@" + domain
}

// depositor is one HTTP client of the deposit API: a tenant host, a client
// IP sent through the trusted proxy, a language and, once identified, its
// session cookie and CSRF token.
type depositor struct {
	d      *depositEnv
	host   string
	ip     string // X-Forwarded-For; "" sends none
	lang   string // Accept-Language; "" sends none
	cookie string // raw session token; "" sends no cookie
	csrf   string
	known  string // recognition cookie value; "" sends none
}

// newDepositor returns a depositor of tenant A from insideA.
func (d *depositEnv) newDepositor() *depositor {
	return &depositor{d: d, host: hostA, ip: insideA}
}

// send sends a request with the depositor's headers plus extra.
func (c *depositor) send(t *testing.T, method, path, body string, extra http.Header) response {
	t.Helper()
	h := http.Header{}
	if c.ip != "" {
		h.Set(hdrXFF, c.ip)
	}
	if c.lang != "" {
		h.Set("Accept-Language", c.lang)
	}
	var cookies []string
	if c.cookie != "" {
		cookies = append(cookies, depositCookieName+"="+c.cookie)
	}
	if c.known != "" {
		cookies = append(cookies, knownCookieName+"="+c.known)
	}
	if len(cookies) > 0 {
		h.Set("Cookie", strings.Join(cookies, "; "))
	}
	for k, vs := range extra {
		h[k] = vs
	}
	r := request{method: method, path: path, host: c.host, headers: h}
	if body != "" {
		r.body = []byte(body)
	}
	return c.d.do(t, r)
}

// withCSRF returns extra headers carrying the depositor's CSRF token.
func (c *depositor) withCSRF(kv ...string) http.Header {
	h := http.Header{hdrCSRF: {c.csrf}}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func (c *depositor) start(t *testing.T, email, invitation string) response {
	t.Helper()
	body := map[string]string{"email": email}
	if invitation != "" {
		body["invitationToken"] = invitation
	}
	b, _ := json.Marshal(body)
	return c.send(t, http.MethodPost, pathSessions, string(b), nil)
}

func (c *depositor) confirm(t *testing.T, challengeID, code string) response {
	t.Helper()
	return c.send(t, http.MethodPost, "/api/v1/verification-challenges/"+challengeID+"/confirm", `{"code":"`+code+`"}`, nil)
}

func (c *depositor) current(t *testing.T) response {
	t.Helper()
	return c.send(t, http.MethodGet, pathCurrentSession, "", nil)
}

func (c *depositor) end(t *testing.T, extra http.Header) response {
	t.Helper()
	return c.send(t, http.MethodDelete, pathCurrentSession, "", extra)
}

func (c *depositor) invite(t *testing.T, body string, extra http.Header) response {
	t.Helper()
	return c.send(t, http.MethodPost, pathInvitations, body, extra)
}

// challengeJSON is the VerificationChallenge schema.
type challengeJSON struct {
	ChallengeID       string    `json:"challengeId"`
	Email             string    `json:"email"`
	ExpiresAt         time.Time `json:"expiresAt"`
	AttemptsRemaining int       `json:"attemptsRemaining"`
}

// sessionJSON is the DepositSession schema.
type sessionJSON struct {
	Email     string    `json:"email"`
	Kind      string    `json:"kind"`
	CSRFToken string    `json:"csrfToken"`
	ExpiresAt time.Time `json:"expiresAt"`
	Limits    struct {
		MaxTransferBytes int64 `json:"maxTransferBytes"`
		ExpiryDays       []int `json:"expiryDays"`
	} `json:"limits"`
	CanInvite  bool `json:"canInvite"`
	Invitation *struct {
		InvitedBy string    `json:"invitedBy"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"invitation"`
}

// sessionMembers are the members the DepositSession schema allows.
var sessionMembers = []string{"email", "kind", "csrfToken", "expiresAt", "limits", "canInvite", "invitation"}

// expectChallenge asserts a 202 VerificationChallenge for email.
func expectChallenge(t *testing.T, resp response, email string) challengeJSON {
	t.Helper()
	if resp.status != http.StatusAccepted {
		t.Fatalf("start: status %d, want 202; body %s", resp.status, resp.body)
	}
	if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("202 sets a cookie: %q", sc)
	}
	var ch challengeJSON
	mustJSON(t, resp.body, &ch)
	if !strings.HasPrefix(ch.ChallengeID, "vch_") || ch.Email != strings.ToLower(email) || ch.AttemptsRemaining != 2 {
		t.Errorf("challenge = %+v, want vch_ id, email %s, 2 attempts", ch, email)
	}
	if d := time.Until(ch.ExpiresAt); d <= 14*time.Minute || d > 15*time.Minute+5*time.Second {
		t.Errorf("challenge expires in %s, want 15 minutes", d)
	}
	return ch
}

// expectSession asserts a response opening a session (201 with the
// session cookie) for email, and returns the body and the cookie token.
// The recognition cookie, when set, is checked by expectSessionCookies.
func expectSession(t *testing.T, resp response, email string) (sessionJSON, string) {
	t.Helper()
	s, token, _ := expectSessionWithKnown(t, resp, email)
	return s, token
}

// expectSessionWithKnown is expectSession also returning the recognition
// cookie value ("" when the response does not set it).
func expectSessionWithKnown(t *testing.T, resp response, email string) (sessionJSON, string, string) {
	t.Helper()
	if resp.status != http.StatusCreated {
		t.Fatalf("status %d, want 201; body %s", resp.status, resp.body)
	}
	token, known := expectSessionCookies(t, resp.header, email)
	s := expectSessionBody(t, resp.body, email)
	if strings.Contains(string(resp.body), token) {
		t.Error("the session body contains the cookie token")
	}
	return s, token, known
}

// expectSessionCookies asserts the Set-Cookie headers opening a session
// (CLAUDE.md section 16.2, threat T-93): exactly one session cookie and at
// most one recognition cookie, each in its own header, both technical
// (Secure, HttpOnly, SameSite=Strict, Path=/, no Domain). It returns the
// session token and the recognition value ("" when absent). The
// recognition cookie never contains the address.
func expectSessionCookies(t *testing.T, h http.Header, email string) (token, known string) {
	t.Helper()
	values := h.Values("Set-Cookie")
	if len(values) == 0 || len(values) > 2 {
		t.Fatalf("Set-Cookie = %q, want the session cookie and at most the recognition cookie", values)
	}
	seen := map[string]bool{}
	for _, v := range values {
		c, err := http.ParseSetCookie(v)
		if err != nil {
			t.Fatalf("parse Set-Cookie %q: %v", v, err)
		}
		if seen[c.Name] {
			t.Errorf("cookie %s set twice: %q", c.Name, values)
		}
		seen[c.Name] = true
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
			t.Errorf("cookie attributes of %q: want Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain", v)
		}
		switch c.Name {
		case depositCookieName:
			if !strings.HasPrefix(c.Value, "ds_") || len(c.Value) < 40 {
				t.Errorf("cookie %s=%q, want a ds_ token of 256 bits", c.Name, c.Value)
			}
			// Derived from the session expiry: the remaining lifetime.
			if want := int(defaultSessionTTL / time.Second); c.MaxAge > want || c.MaxAge < want-60 {
				t.Errorf("session cookie Max-Age = %d, want about %d", c.MaxAge, want)
			}
			token = c.Value
		case knownCookieName:
			// The entry format is the deposit service's business: only
			// the bound the service parses (1024 bytes) is checked.
			if c.MaxAge != knownCookieMaxAge || c.Value == "" || len(c.Value) > 1024 {
				t.Errorf("recognition cookie %q: want a value of at most 1024 bytes and Max-Age %d", v, knownCookieMaxAge)
			}
			lower := strings.ToLower(c.Value)
			local, domain, _ := strings.Cut(strings.ToLower(email), "@")
			if strings.Contains(lower, local) || strings.Contains(lower, domain) || strings.Contains(c.Value, "@") {
				t.Errorf("recognition cookie %q contains the address %s", c.Value, email)
			}
			known = c.Value
		default:
			t.Errorf("unexpected cookie %q", v)
		}
	}
	if token == "" {
		t.Fatalf("Set-Cookie = %q, want the session cookie", values)
	}
	return token, known
}

// expectSessionBody asserts a DepositSession body for email.
func expectSessionBody(t *testing.T, body []byte, email string) sessionJSON {
	t.Helper()
	var members map[string]json.RawMessage
	mustJSON(t, body, &members)
	for k := range members {
		if !slices.Contains(sessionMembers, k) {
			t.Errorf("DepositSession has the unexpected member %q: %s", k, body)
		}
	}
	var s sessionJSON
	mustJSON(t, body, &s)
	if s.Email != strings.ToLower(email) || !strings.HasPrefix(s.CSRFToken, "csrf_") {
		t.Errorf("session = %s, want email %s and a csrf_ token", body, email)
	}
	if s.Limits.MaxTransferBytes != 1<<30 || !slices.Equal(s.Limits.ExpiryDays, []int{1, 7, 30}) {
		t.Errorf("limits = %+v, want the tenant limit and 1, 7, 30 days", s.Limits)
	}
	if d := time.Until(s.ExpiresAt); d <= defaultSessionTTL-time.Minute || d > defaultSessionTTL+5*time.Second {
		t.Errorf("session expires in %s, want %s", d, defaultSessionTTL)
	}
	return s
}

// openSession runs the code flow for email (start, code from Mailpit,
// confirm) and stores the session in c, with the recognition cookie set
// for an internal depositor (an invited one keeps its cookie).
func (c *depositor) openSession(t *testing.T, email, invitation string) sessionJSON {
	t.Helper()
	ch := expectChallenge(t, c.start(t, email, invitation), email)
	_, code := c.d.codeMail(t, email)
	s, token, known := expectSessionWithKnown(t, c.confirm(t, ch.ChallengeID, code), email)
	if (known == "") != (invitation != "") {
		t.Errorf("recognition cookie %q after confirming with invitation %q: want one for internal depositors only", known, invitation)
	}
	c.cookie, c.csrf = token, s.CSRFToken
	if known != "" {
		c.known = known
	}
	return s
}

// problemWithoutInstance returns the Problem body without its instance
// member, which differs on every response.
func problemWithoutInstance(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	mustJSON(t, body, &m)
	delete(m, "instance")
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// reasons returns the reason of every deposit_refused line, in order.
func reasons(t *testing.T, s *server) []string {
	t.Helper()
	var out []string
	for _, l := range eventsOf(t, s.securityLines(t), "deposit_refused") {
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(l.fields, ` reason="`), `"`))
	}
	return out
}

// noSecretInLogs asserts that neither log contains any of secrets (codes,
// tokens): CLAUDE.md section 16.2, threat T-101.
func noSecretInLogs(t *testing.T, s *server, secrets ...string) {
	t.Helper()
	sec := strings.Join(s.securityLines(t), "\n")
	app := s.appLog.String()
	for _, v := range secrets {
		if v == "" {
			continue
		}
		if strings.Contains(sec, v) {
			t.Errorf("the security log contains the secret %q", v)
		}
		if strings.Contains(app, v) {
			t.Errorf("the application log contains the secret %q", v)
		}
	}
}

// waitCode waits until addr has received n code mails and returns the code
// of the newest one.
func (d *depositEnv) waitCode(t *testing.T, addr string, n int) string {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		var codes []mpMessage
		for _, m := range d.mp.messagesTo(t, addr) {
			if strings.Contains(m.Subject, "code") {
				codes = append(codes, m)
			}
		}
		if len(codes) >= n {
			msg := d.mp.find(t, addr, func(m mpMessage) bool { return m.ID == codes[0].ID })
			c := codeRE.FindStringSubmatch(msg.Text)
			if c == nil {
				t.Fatalf("no code in the mail to %s:\n%s", addr, msg.Text)
			}
			return c[1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d code mails to %s within %s, want %d", len(codes), addr, waitTimeout, n)
		}
		time.Sleep(mailpitPollInterval)
	}
}
