package adminauth

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
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
	baseURL      = "https://admin.transfer.example.com"
	setupToken   = "stp_test-setup-token-0123456789"
	rootName     = "root"
	rootPassword = "correct horse battery staple"
	newPassword  = "an even longer passphrase 2026"
)

var (
	// testStart is aligned on a TOTP step, 10 s into it.
	testStart = time.Date(2026, 10, 22, 9, 30, 10, 0, time.UTC)
	ipA       = netip.MustParseAddr("192.0.2.10")
	ipB       = netip.MustParseAddr("198.51.100.20")
	errFault  = errors.New("injected fault")
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

// fakeHasher is a fast PasswordHasher (see fakeHash) counting its
// verifications per hash; it fails with err when set.
type fakeHasher struct {
	mu       sync.Mutex
	verified map[string]int
	hashErr  error
	verifErr error
}

func (h *fakeHasher) HashPassword(_ context.Context, password []byte) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hashErr != nil {
		return "", h.hashErr
	}
	return fakeHash(string(password)), nil
}

// fakeHash is the hash of password by the fakeHasher (printable ASCII, as
// the store requires).
func fakeHash(password string) string { return "$fake$" + hex.EncodeToString([]byte(password)) }

func (h *fakeHasher) VerifyPassword(_ context.Context, encoded string, password []byte) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.verifErr != nil {
		return false, h.verifErr
	}
	if h.verified == nil {
		h.verified = map[string]int{}
	}
	h.verified[encoded]++
	return encoded == fakeHash(string(password)), nil
}

func (h *fakeHasher) count(encoded string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verified[encoded]
}

func (h *fakeHasher) set(hashErr, verifErr error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hashErr, h.verifErr = hashErr, verifErr
}

// fakeVault seals the system secrets with a marker instead of the master
// key (the real sealing belongs to package masterkey).
type fakeVault struct {
	db      *store.DB
	keyID   string
	mu      sync.Mutex
	wrapErr error
	openErr error
}

const sealedMarker = "sealed:"

func (v *fakeVault) WrapSystem(p crypto.Purpose, plaintext []byte) (store.SystemSecret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.wrapErr != nil {
		return store.SystemSecret{}, v.wrapErr
	}
	if p != crypto.PurposeAdminTOTP {
		return store.SystemSecret{}, errors.New("unexpected purpose")
	}
	return store.SystemSecret{
		ID: id.New(id.SystemSecret), Purpose: store.SecretPurposeAdminTOTP, KeyID: v.keyID,
		Blob: append([]byte(sealedMarker), plaintext...),
	}, nil
}

func (v *fakeVault) OpenSystem(ctx context.Context, p crypto.Purpose, secretID string) ([]byte, error) {
	v.mu.Lock()
	err := v.openErr
	v.mu.Unlock()
	if err != nil {
		return nil, err
	}
	s, err := v.db.SystemSecrets().Get(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if p != crypto.PurposeAdminTOTP || !bytes.HasPrefix(s.Blob, []byte(sealedMarker)) {
		return nil, errors.New("not a sealed totp secret")
	}
	return bytes.Clone(s.Blob[len(sealedMarker):]), nil
}

func (v *fakeVault) set(wrapErr, openErr error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.wrapErr, v.openErr = wrapErr, openErr
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	err error
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return 0, b.err
	}
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// env is a service over a migrated database with tenants A, B and C.
type env struct {
	db      *store.DB
	svc     *Service
	clock   *fakeClock
	hasher  *fakeHasher
	vault   *fakeVault
	seclog  *syncBuffer
	applog  *syncBuffer
	a, b, c *tenant.Tenant
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
	kr, err := masterkey.New(masterkeytest.Key(t, "adminauth"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Close)
	ev := &env{
		db: db, clock: clock, hasher: &fakeHasher{}, seclog: &syncBuffer{}, applog: &syncBuffer{},
		vault: &fakeVault{db: db, keyID: kr.CurrentID()},
	}
	ev.svc, err = New(db, kr, ev.vault, ev.hasher, securitylog.New(ev.seclog), Options{
		SetupToken: setupToken, AdminBaseURL: baseURL + "/", Now: clock.Now, Logger: newLogger(ev.applog),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.a = ev.newTenant(t, hostA, "en")
	ev.b = ev.newTenant(t, hostB, "fr")
	ev.c = ev.newTenant(t, hostC, "en")
	return ev
}

func (ev *env) newTenant(t *testing.T, fqdn, lang string) *tenant.Tenant {
	t.Helper()
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: lang,
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// newLogger returns an application logger writing to buf.
func newLogger(buf *syncBuffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

// decodeSecret decodes the base32 secret of an enrollment.
func decodeSecret(t *testing.T, enr Enrollment) []byte {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return secret
}

// code returns the TOTP code of secret at the current time of the env.
func (ev *env) code(secret []byte) string {
	return crypto.TOTPCode(secret, crypto.TOTPCounter(ev.clock.Now()))
}

// wrongCode returns a well-formed code that matches none of the steps
// accepted at the current time.
func (ev *env) wrongCode(secret []byte) string {
	step := crypto.TOTPCounter(ev.clock.Now())
	for _, c := range []string{"000000", "000001", "000002", "000003"} {
		if c != crypto.TOTPCode(secret, step-1) && c != crypto.TOTPCode(secret, step) && c != crypto.TOTPCode(secret, step+1) {
			return c
		}
	}
	panic("no wrong code")
}

// nextStep moves the clock to the next TOTP step.
func (ev *env) nextStep() { ev.clock.Advance(crypto.TOTPPeriod * time.Second) }

// root is the super admin of a completed setup.
type root struct {
	sess   Session // the authenticated session
	secret []byte
	codes  []string
	p      Principal
}

// mustSetup performs the setup and the TOTP confirmation of the super admin.
func (ev *env) mustSetup(t *testing.T) root {
	t.Helper()
	ctx := context.Background()
	res, err := ev.svc.CreateSuperAdmin(ctx, SetupRequest{
		Username: "Root", Email: "it-admin@example.com", Password: rootPassword, SetupToken: setupToken,
	}, ipA)
	if err != nil {
		t.Fatalf("CreateSuperAdmin: %v", err)
	}
	p := ev.mustResolve(t, res.Session.Token)
	secret := decodeSecret(t, res.Enrollment)
	conf, err := ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipA)
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	if conf.Session == nil {
		t.Fatal("ConfirmEnrollment: no rotated session")
	}
	return root{sess: *conf.Session, secret: secret, codes: conf.RecoveryCodes, p: ev.mustResolve(t, conf.Session.Token)}
}

// mustResolve resolves a session token.
func (ev *env) mustResolve(t *testing.T, token string) Principal {
	t.Helper()
	p, err := ev.svc.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return p
}

var linkRe = regexp.MustCompile("^" + regexp.QuoteMeta(baseURL+ActivationPath+"#") + `(act_[A-Za-z0-9]{43})$`)

// tokenOf extracts the token of an activation link, checking its format and
// validity.
func (ev *env) tokenOf(t *testing.T, link Activation) string {
	t.Helper()
	m := linkRe.FindStringSubmatch(link.URL)
	if m == nil {
		t.Fatalf("malformed activation link %q", link.URL)
	}
	if !link.ExpiresAt.Equal(ev.svc.now().Add(ActivationTTL)) {
		t.Errorf("activation link expires at %v", link.ExpiresAt)
	}
	return m[1]
}

// delegated is an activated delegated admin of tenant A without TOTP
// requirement, logged in.
type delegated struct {
	account Account
	p       Principal
}

// mustDelegated creates a delegated admin of tenants tids, activates it and
// returns its session.
func (ev *env) mustDelegated(t *testing.T, r root, username string, requireTOTP bool, tids ...tenant.ID) delegated {
	t.Helper()
	ctx := context.Background()
	acc, link, err := ev.svc.Create(ctx, r.p, AdminCreate{
		Username: username, Email: username + "@entity-a.example.com", Role: store.RoleDelegatedAdmin,
		TenantIDs: tids, RequireTOTP: &requireTOTP,
	}, ipA)
	if err != nil {
		t.Fatalf("Create(%s): %v", username, err)
	}
	sess, err := ev.svc.Activate(ctx, ev.tokenOf(t, link), rootPassword, ipB)
	if err != nil {
		t.Fatalf("Activate(%s): %v", username, err)
	}
	return delegated{account: acc, p: ev.mustResolve(t, sess.Token)}
}

// mustEnroll enrolls and confirms TOTP for the session p (first
// enrollment, with the current password of an authenticated session) and
// returns the secret and the confirmation.
func (ev *env) mustEnroll(t *testing.T, p Principal) ([]byte, Confirmed) {
	t.Helper()
	ctx := context.Background()
	enr, err := ev.svc.StartEnrollment(ctx, p, rootPassword, ipB)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret := decodeSecret(t, enr)
	conf, err := ev.svc.ConfirmEnrollment(ctx, p, ev.code(secret), ipB)
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	return secret, conf
}

// mustSuper creates a second usable super admin: a delegated admin
// activated with TOTP, then promoted. It returns its account and TOTP
// secret; its sessions were revoked by the promotion.
func (ev *env) mustSuper(t *testing.T, r root, username string) (Account, []byte) {
	t.Helper()
	d := ev.mustDelegated(t, r, username, true, ev.a.ID)
	secret, _ := ev.mustEnroll(t, d.p)
	acc, err := ev.svc.Update(context.Background(), r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
	if err != nil {
		t.Fatalf("promote %s: %v", username, err)
	}
	return acc, secret
}

// login logs username in with its password and, when asked, its TOTP code
// (at the next step, so that no code is replayed), and returns the session.
func (ev *env) login(t *testing.T, username string, secret []byte) Principal {
	t.Helper()
	ctx := context.Background()
	sess, err := ev.svc.Login(ctx, username, rootPassword, ipB)
	if err != nil {
		t.Fatalf("Login(%s): %v", username, err)
	}
	if secret != nil {
		ev.nextStep()
		if sess, err = ev.svc.VerifyTOTP(ctx, ev.mustResolve(t, sess.Token), ev.code(secret), "", ipB); err != nil {
			t.Fatalf("VerifyTOTP(%s): %v", username, err)
		}
	}
	return ev.mustResolve(t, sess.Token)
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

// wantLimited fails unless err is a *RateLimitError.
func wantLimited(t *testing.T, what string, err error) *RateLimitError {
	t.Helper()
	var rl *RateLimitError
	if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("%s: err = %v, want a rate limit", what, err)
	}
	return rl
}

// logLines returns the security log lines of event.
func (ev *env) logLines(event string) []string {
	var out []string
	for _, l := range strings.Split(ev.seclog.String(), "\n") {
		if strings.Contains(l, "event="+event) {
			out = append(out, l)
		}
	}
	return out
}

// auditActions returns the actions of the audit log, oldest first.
func (ev *env) auditActions(t *testing.T) []string {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(page.Items))
	for i := len(page.Items) - 1; i >= 0; i-- {
		out = append(out, page.Items[i].Action)
	}
	return out
}

// countAction returns how many audit events have action.
func (ev *env) countAction(t *testing.T, action string) int {
	t.Helper()
	n := 0
	for _, a := range ev.auditActions(t) {
		if a == action {
			n++
		}
	}
	return n
}
