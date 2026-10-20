package deposit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool, and make test runs every
// package at once against a server limited to 100 connections.

// Fixed values of the tests. Domains are fictitious.
const (
	hostA        = "transfer.entity-a.example.com"
	hostB        = "transfer.entity-b.example.com"
	hostC        = "transfer.entity-c.example.com"
	alice        = "Alice@Entity-A.example.com" // internal user of A, as typed
	aliceNorm    = "alice@entity-a.example.com"
	bob          = "bob@partner.example.org" // external user
	smtpPassword = "smtp-test-password"
)

var (
	testStart  = time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	internalIP = netip.MustParseAddr("10.1.2.3")
	externalIP = netip.MustParseAddr("203.0.113.7")
	errFault   = errors.New("injected fault")
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeQueue captures the jobs. It validates them like the real queue (the
// whole message is built), then returns err when set.
type fakeQueue struct {
	mu   sync.Mutex
	jobs []mail.Job
	err  error
}

func (q *fakeQueue) Enqueue(job mail.Job) error {
	if err := job.Settings.Validate(); err != nil {
		return err
	}
	if _, err := mail.Build(job.Settings, job.Message); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.jobs = append(q.jobs, job)
	return nil
}

func (q *fakeQueue) setErr(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.err = err
}

func (q *fakeQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}

// last returns the last job queued.
func (q *fakeQueue) last(t *testing.T) mail.Job {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) == 0 {
		t.Fatal("no mail queued")
	}
	return q.jobs[len(q.jobs)-1]
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// env is a service over a migrated database with tenants A and B sharing
// the same network rules (so that only the tenant differs in the isolation
// tests) and tenant C without SMTP settings.
type env struct {
	db     *store.DB
	svc    *Service
	clock  *fakeClock
	queue  *fakeQueue
	seclog *syncBuffer
	vault  *masterkey.Vault
	a, b   *tenant.Tenant
	c      *tenant.Tenant
	// known is the recognition cookie of the test browser, updated by
	// mustSession.
	known string
}

// newEnv builds an env on engine e.
func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	clock := &fakeClock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "deposit"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &env{db: db, clock: clock, queue: &fakeQueue{}, seclog: &syncBuffer{}, vault: masterkey.NewVault(db, kr, nil)}
	ev.svc = New(db, kr, ev.vault, ev.queue, securitylog.New(ev.seclog), Options{Now: clock.Now, SessionTTL: 4 * time.Hour})
	ev.a = ev.newTenant(t, hostA, "en")
	ev.b = ev.newTenant(t, hostB, "fr")
	ev.c = ev.newTenant(t, hostC, "en")

	// A: authenticated server with a sealed password; B: open relay.
	wk, err := ev.vault.Seal(ctx, ev.a.ID, crypto.PurposeSecret, []byte(smtpPassword))
	if err != nil {
		t.Fatal(err)
	}
	ev.putSMTP(t, ev.a, store.SMTPConfig{
		Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: "mailer",
		PasswordKeyID: wk, FromAddress: "noreply@entity-a.example.com", FromName: "Entity A",
	})
	ev.putSMTP(t, ev.b, store.SMTPConfig{
		Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-b.example.com",
	})
	return ev
}

// newTenant creates a tenant whose internal users are 10.0.0.0/8 with the
// domain entity-a.example.com.
func (ev *env) newTenant(t *testing.T, fqdn, lang string) *tenant.Tenant {
	t.Helper()
	ctx := context.Background()
	tn, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: lang,
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	_, err = ev.db.NetworkRules().Replace(ctx, tn.ID,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func (ev *env) putSMTP(t *testing.T, tn *tenant.Tenant, c store.SMTPConfig) {
	t.Helper()
	if err := ev.db.SMTPSettings().Put(context.Background(), tn.ID, c); err != nil {
		t.Fatal(err)
	}
}

// block adds a blocklist entry to tn.
func (ev *env) block(t *testing.T, tn *tenant.Tenant, kind store.BlocklistKind, value string) store.BlocklistEntry {
	t.Helper()
	e, err := ev.db.Blocklist().Create(context.Background(), tn.ID, store.BlocklistEntry{Kind: kind, Value: value, CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var (
	codeRe = regexp.MustCompile(`(?m)^ {4}([0-9]{6})\r?$`)
	linkRe = regexp.MustCompile(`https://([a-z0-9.-]+)/i/(inv_[A-Za-z0-9]+)`)
)

// codeOf extracts the code of a verification mail. Failures never print it.
func codeOf(t *testing.T, job mail.Job) string {
	t.Helper()
	m := codeRe.FindStringSubmatch(job.Message.Text)
	if m == nil {
		t.Fatal("no code in the verification mail")
	}
	return m[1]
}

// wrongCodeFor returns a well-formed code different from code.
func wrongCodeFor(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

// linkOf extracts the host and token of an invitation mail.
func linkOf(t *testing.T, job mail.Job) (host, token string) {
	t.Helper()
	m := linkRe.FindStringSubmatch(job.Message.Text)
	if m == nil {
		t.Fatal("no invitation link in the mail")
	}
	return m[1], m[2]
}

// mustChallenge starts a session and expects a challenge.
func (ev *env) mustChallenge(t *testing.T, tn *tenant.Tenant, ip netip.Addr, email, invToken string) *Challenge {
	t.Helper()
	res, err := ev.svc.Start(context.Background(), tn, ip, "", email, invToken, "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Challenge == nil || res.Session != nil {
		t.Fatalf("Start: got session=%v challenge=%v, want a challenge", res.Session != nil, res.Challenge != nil)
	}
	return res.Challenge
}

// mustSession opens a session for email from the test browser: at once
// when its recognition cookie allows it, otherwise through the code. The
// cookie of the browser is updated.
func (ev *env) mustSession(t *testing.T, tn *tenant.Tenant, ip netip.Addr, email, invToken string) Session {
	t.Helper()
	ctx := context.Background()
	res, err := ev.svc.Start(ctx, tn, ip, "", email, invToken, ev.known)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s := res.Session
	if s == nil {
		confirmed, err := ev.svc.Confirm(ctx, tn, ip, res.Challenge.ID, codeOf(t, ev.queue.last(t)), ev.known)
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		s = &confirmed
	}
	if s.Recognition != "" {
		ev.known = s.Recognition
	}
	return *s
}

// mustInvite has the internal user alice of A invite email and returns the
// link token.
func (ev *env) mustInvite(t *testing.T, email string) (Invitation, string) {
	t.Helper()
	s := ev.mustSession(t, ev.a, internalIP, alice, "")
	inv, err := ev.svc.Invite(context.Background(), ev.a, s.SessionInfo, internalIP, "", email, "Please send the contract.", "en")
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	_, token := linkOf(t, ev.queue.last(t))
	return inv, token
}

// wantErr fails unless errors.Is(err, target).
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("%s: err = %v, want %v", what, err, target)
	}
}

// wantInvalid fails unless err is an *InvalidError on field.
func wantInvalid(t *testing.T, what string, err error, field string) {
	t.Helper()
	var ie *InvalidError
	if !errors.As(err, &ie) || ie.Field != field || !errors.Is(err, ErrInvalid) {
		t.Errorf("%s: err = %v, want invalid %s", what, err, field)
	}
}

// logLines returns the security log lines containing event.
func (ev *env) logLines(event string) []string {
	var out []string
	for _, l := range strings.Split(ev.seclog.String(), "\n") {
		if strings.Contains(l, "event="+event) {
			out = append(out, l)
		}
	}
	return out
}

// wantLogged fails unless the security log has n lines with event and
// reason/scope value (field may be "").
func (ev *env) wantLogged(t *testing.T, event, field string, n int) {
	t.Helper()
	got := 0
	for _, l := range ev.logLines(event) {
		if field == "" || strings.Contains(l, field) {
			got++
		}
	}
	if got != n {
		t.Errorf("security log: %d %s lines with %q, want %d\n%s", got, event, field, n, ev.seclog.String())
	}
}

// netipZero returns the zero (invalid) address, an unknown client.
func netipZero() netip.Addr { return netip.Addr{} }

// unknownToken returns a well-formed token that nothing references.
func unknownToken(t *testing.T, prefix string) string {
	t.Helper()
	tok, err := id.NewToken(prefix, 32)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// entryFor returns a recognition cookie entry of email in tenant tn issued
// daysAgo days before the clock, with the current salt of the address (the
// zero salt when it is not verified).
func (ev *env) entryFor(t *testing.T, tn *tenant.Tenant, email string, daysAgo int) string {
	t.Helper()
	return ev.entryWith(t, tn.ID, email, ev.saltOf(t, tn, email), daysAgo)
}

// saltOf returns the recognition salt of email in tn, zero when the address
// is not verified.
func (ev *env) saltOf(t *testing.T, tn *tenant.Tenant, email string) [store.RecognitionSaltSize]byte {
	t.Helper()
	v, err := ev.db.VerifiedAddresses().Get(context.Background(), tn.ID, email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return v.RecognitionSalt
}

// entryWith returns a recognition entry of email in tenant tid with salt,
// issued daysAgo days before the clock (negative: in the future).
func (ev *env) entryWith(t *testing.T, tid tenant.ID, email string, salt [store.RecognitionSaltSize]byte, daysAgo int) string {
	t.Helper()
	day := binary.BigEndian.AppendUint32(nil, uint32(int(dayOf(ev.clock.Now()))-daysAgo))
	norm, err := store.NormalizeEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := ev.svc.keys.MAC(crypto.MACPurposeRecognition, recognitionParts(tid, norm, salt, day)...)
	if err != nil {
		t.Fatal(err)
	}
	return recognitionEncoding.EncodeToString(append(day, mac...))
}
