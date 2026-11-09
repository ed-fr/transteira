package secret

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/tte2"
)

const (
	alice = "alice@entity-a.example.com"
	bob   = "bob@partner.example.org"
)

var (
	internalIP = netip.MustParseAddr("10.1.2.3")
	errBoom    = errors.New("boom")
	testNow    = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	testTenant = &tenant.Tenant{ID: "ten_a", FQDN: "transfer.entity-a.example.com", Secrets: tenant.DefaultSecretSettings()}
)

// sealed is a secret sealed as a browser would.
type sealed struct {
	text, verifier, keyVerifier, keyProof, proof string
}

// seal seals text with a new key, with a passphrase when pass is not "".
func seal(t *testing.T, text, pass string) (sealed, tte2.PassphraseDescriptor) {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var d tte2.PassphraseDescriptor
	if pass != "" {
		if d, err = tte2.NewPassphraseDescriptor(); err != nil {
			t.Fatal(err)
		}
	}
	root, err := tte2.DeriveSecretKey(key, pass, d)
	if err != nil {
		t.Fatal(err)
	}
	s, err := tte2.SealSecret(root, text)
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := tte2.SecretKeyProof(key)
	p, _ := tte2.SecretProof(root)
	return sealed{
		text: s, keyProof: tte2.EncodeProof(kp), proof: tte2.EncodeProof(p),
		verifier: tte2.EncodeProof(tte2.SecretVerifier(p)), keyVerifier: tte2.EncodeProof(tte2.SecretVerifier(kp)),
	}, d
}

// request returns a valid link creation request of s.
func (s sealed) request() CreateRequest {
	return CreateRequest{
		EncryptedText: s.text, Verifier: s.verifier, KeyVerifier: s.keyVerifier, ExpiresIn: "1d", Delivery: DeliveryLink,
	}
}

func ptr[T any](v T) *T { return &v }

// internalSender is alice from the internal network.
func internalSender() transfer.Sender {
	return transfer.Sender{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternal}, ClientIP: internalIP}
}

// fakeRepo records its calls and answers with the configured values.
type fakeRepo struct {
	mu sync.Mutex

	createErr error
	created   store.CreatedSecret
	gotCreate store.CreateSecret

	status    store.Secret
	statusErr error

	revealed  store.RevealedSecret
	revealErr error
	gotKey    [32]byte
	gotProof  [32]byte

	ended     store.EndedSecret
	deleteErr error
	gotActor  store.SecretActor

	page    store.Page[store.Secret]
	listErr error
	gotOpts store.SecretListOptions
}

func (r *fakeRepo) Create(_ context.Context, _ tenant.ID, c store.CreateSecret) (store.CreatedSecret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gotCreate = c
	if r.createErr != nil {
		return store.CreatedSecret{}, r.createErr
	}
	out := r.created
	if out.Secret.ID == "" {
		out = store.CreatedSecret{Token: "tts_tok", Secret: store.Secret{
			ID: id.New(id.Secret), State: store.SecretActive, CreatorKind: c.CreatorKind, Delivery: c.Delivery,
			Duration: c.Duration, ExpiresAt: c.Now.Add(c.Duration.Duration()),
		}}
	}
	return out, nil
}

func (r *fakeRepo) StatusByToken(_ context.Context, _ tenant.ID, _ string, _ time.Time) (store.Secret, error) {
	return r.status, r.statusErr
}

func (r *fakeRepo) Reveal(_ context.Context, _ tenant.ID, _ string, keyProof, proof [32]byte, _ time.Time) (store.RevealedSecret, error) {
	r.gotKey, r.gotProof = keyProof, proof
	return r.revealed, r.revealErr
}

func (r *fakeRepo) DeleteByCreator(_ context.Context, _ tenant.ID, _ string, actor store.SecretActor, _ time.Time) (store.EndedSecret, error) {
	r.gotActor = actor
	return r.ended, r.deleteErr
}

func (r *fakeRepo) ListBySender(_ context.Context, _ tenant.ID, _ string, opts store.SecretListOptions) (store.Page[store.Secret], error) {
	r.gotOpts = opts
	return r.page, r.listErr
}

// fakeCreators returns its address or error.
type fakeCreators struct {
	err    error
	sender transfer.Sender
	calls  int
}

func (f *fakeCreators) CheckCreator(_ context.Context, _ *tenant.Tenant, s transfer.Sender) (string, error) {
	f.calls++
	f.sender = s
	if f.err != nil {
		return "", f.err
	}
	return s.Email, nil
}

// fakeScrubber counts its calls.
type fakeScrubber struct {
	err   error
	calls int
}

func (f *fakeScrubber) Scrub(context.Context) error {
	f.calls++
	return f.err
}

// fakeFiles records the removed files.
type fakeFiles struct {
	err     error
	removed []string
}

func (f *fakeFiles) RemoveSecretFile(_ tenant.ID, name string) error {
	f.removed = append(f.removed, name)
	return f.err
}

// fakeSeclog captures the security events.
type fakeSeclog struct {
	err    error
	events []securitylog.Event
}

func (l *fakeSeclog) Log(ev securitylog.Event) error {
	l.events = append(l.events, ev)
	return l.err
}

// types returns the event types, with their reason or scope.
func (l *fakeSeclog) types() []string {
	out := make([]string, 0, len(l.events))
	for _, ev := range l.events {
		s := string(ev.Type)
		for _, f := range ev.Fields {
			s += " " + f.Key + "=" + f.Value
		}
		out = append(out, s)
	}
	return out
}

// fakeAudit captures the audit events.
type fakeAudit struct {
	err    error
	events []audit.Event
}

func (a *fakeAudit) RecordScoped(_ context.Context, _ tenant.ID, ev audit.Event) error {
	a.events = append(a.events, ev)
	return a.err
}

// actions returns the recorded actions.
func (a *fakeAudit) actions() []audit.Action {
	out := make([]audit.Action, 0, len(a.events))
	for _, ev := range a.events {
		out = append(out, ev.Action)
	}
	return out
}

// fakeLimiter allows while ok.
type fakeLimiter struct{ refuse bool }

func (l *fakeLimiter) Allow(string) (bool, time.Duration) {
	if l.refuse {
		return false, 3 * time.Second
	}
	return true, 0
}

// fakeFailures counts the failures and reports locked while lock.
type fakeFailures struct {
	lock  bool
	fails int
}

func (f *fakeFailures) Locked(string) (bool, time.Duration) {
	return f.lock, time.Minute
}

func (f *fakeFailures) Fail(string) (bool, time.Duration) {
	f.fails++
	return false, 0
}

// env is a service over fakes.
type env struct {
	svc      *Service
	repo     *fakeRepo
	creators *fakeCreators
	scrubber *fakeScrubber
	files    *fakeFiles
	seclog   *fakeSeclog
	audit    *fakeAudit
	requests *fakeLimiter
	failures *fakeFailures
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		repo: &fakeRepo{}, creators: &fakeCreators{}, scrubber: &fakeScrubber{}, files: &fakeFiles{},
		seclog: &fakeSeclog{}, audit: &fakeAudit{}, requests: &fakeLimiter{}, failures: &fakeFailures{},
	}
	svc, err := New(Deps{
		Secrets: e.repo, Creators: e.creators, Scrubber: e.scrubber, Files: e.files, SecurityLog: e.seclog,
	}, Options{Audit: e.audit, Requests: e.requests, Failures: e.failures, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// fieldsOf returns the "pointer code" pairs of a *ValidationError or a
// *FormatError.
func fieldsOf(t *testing.T, err error) []string {
	t.Helper()
	var (
		v  *ValidationError
		f  *FormatError
		fs []FieldError
	)
	switch {
	case errors.As(err, &v):
		fs = v.Fields
	case errors.As(err, &f):
		fs = f.Fields
	default:
		t.Fatalf("err = %v, want field errors", err)
	}
	out := make([]string, len(fs))
	for i, x := range fs {
		out[i] = x.Pointer + " " + x.Code
	}
	return out
}
