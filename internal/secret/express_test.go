package secret

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/abuse"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

const expressToken = "tok_01JABCT1V2W3X4Y5Z6A7B8C9D0"

// The implementations the application wires.
var (
	_ Repo             = (*store.Secrets)(nil)
	_ AbuseReportStore = (*store.AbuseReports)(nil)
	_ AbuseNotifier    = (*abuse.Detector)(nil)
	_ ExpressLimiter   = (*ExpressWindow)(nil)
)

var remoteIP = netip.MustParseAddr("203.0.113.9")

// expressTenant returns the test tenant with its anonymous mode set to
// enabled and the default express limits.
func expressTenant(enabled bool) *tenant.Tenant {
	tn := *testTenant
	tn.Express = tenant.DefaultExpressSettings()
	tn.Express.Enabled = enabled
	return &tn
}

// expressRequest returns a valid express creation request of s.
func (s sealed) expressRequest() ExpressCreateRequest {
	return ExpressCreateRequest{EncryptedText: s.text, Verifier: s.verifier, KeyVerifier: s.keyVerifier, ExpiresIn: "1h"}
}

// anonymousCreator is a caller without credential from remoteIP.
func anonymousCreator() ExpressCreator { return ExpressCreator{ClientIP: remoteIP} }

// tokenCreator is an API token allowed for the express secrets.
func tokenCreator() ExpressCreator {
	return ExpressCreator{ClientIP: remoteIP, APITokenID: expressToken, ExpressAllowed: true}
}

func TestCreateExpressAnonymous(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the wifi password", "")
	e := newEnv(t)
	u := newFakeUsage()
	e.svc.usage = u
	tn := expressTenant(true)
	tn.Express.PerHourPerIP = 25
	out, err := e.svc.CreateExpress(context.Background(), tn, anonymousCreator(), s.expressRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !id.Valid(id.Secret, out.ID) || out.Token != "tts_express" || out.State != store.SecretActive ||
		!out.ExpiresAt.Equal(testNow.Add(time.Hour)) {
		t.Errorf("created = %+v", out)
	}
	c := e.repo.gotExpress
	if c.APITokenID != "" || c.SealedText != s.text || c.Duration != tenant.SecretDuration1h || !c.Now.Equal(testNow) ||
		tte2.EncodeProof(c.Verifier) != s.verifier || tte2.EncodeProof(c.KeyVerifier) != s.keyVerifier {
		t.Errorf("store input = %+v", c)
	}
	if !slices.Equal(e.perIP.keys, []string{"ten_a 203.0.113.9"}) || !slices.Equal(e.perIP.limits, []int{25}) {
		t.Errorf("per-IP limiter keys %v limits %v", e.perIP.keys, e.perIP.limits)
	}
	if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionSecretCreated}) {
		t.Fatalf("audit = %v", got)
	}
	ev := e.audit.events[0]
	if ev.ActorKind != store.ActorAnonymous || ev.Actor != "-" || ev.IP != remoteIP || ev.ObjectKind != audit.ObjectSecret ||
		ev.ObjectID != out.ID || ev.Details["creatorKind"] != "anonymous" || ev.Details["express"] != true ||
		ev.Details["delivery"] != "link" || ev.Details["hasFile"] != false || ev.Details["expiresIn"] != "1h" {
		t.Errorf("audit event = %+v", ev)
	}
	if u.created[tn.ID] != 1 || len(e.seclog.events) != 0 || len(e.abuse.facts) != 0 {
		t.Errorf("usage %v, security log %v, abuse %v", u.created, e.seclog.types(), e.abuse.facts)
	}
	// The limits of a tenant read without them take the defaults.
	tn.Express.PerHourPerIP = 0
	if _, err := e.svc.CreateExpress(context.Background(), tn, anonymousCreator(), s.expressRequest()); err != nil {
		t.Fatal(err)
	}
	if e.perIP.limits[1] != tenant.DefaultExpressPerHourPerIP {
		t.Errorf("default limit = %d", e.perIP.limits[1])
	}
}

func TestCreateExpressByToken(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the vault key", "")
	e := newEnv(t)
	// The anonymous mode does not apply to a token.
	out, err := e.svc.CreateExpress(context.Background(), expressTenant(false), tokenCreator(), s.expressRequest())
	if err != nil {
		t.Fatal(err)
	}
	if e.repo.gotExpress.APITokenID != expressToken || len(e.perIP.keys) != 0 {
		t.Errorf("store input %+v, per-IP keys %v", e.repo.gotExpress, e.perIP.keys)
	}
	want := []audit.Action{audit.ActionSecretCreated, audit.ActionAPITokenUsed}
	if got := e.audit.actions(); !slices.Equal(got, want) {
		t.Fatalf("audit = %v", got)
	}
	created, used := e.audit.events[0], e.audit.events[1]
	if created.ActorKind != store.ActorAPIToken || created.Actor != expressToken || created.Details["creatorKind"] != "api_token" ||
		created.Details["express"] != true {
		t.Errorf("secret.created = %+v", created)
	}
	if used.ActorKind != store.ActorAPIToken || used.Actor != expressToken || used.ObjectKind != audit.ObjectAPIToken ||
		used.ObjectID != expressToken || used.IP != remoteIP || used.Details["objectId"] != out.ID ||
		used.Details["object"] != audit.ObjectSecret {
		t.Errorf("api_token.used = %+v", used)
	}
}

// TestCreateExpressSwitches checks the switches, before the limits and the
// body: nothing is counted, validated nor stored.
func TestCreateExpressSwitches(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		kill    bool
		enabled bool
		creator ExpressCreator
		want    error
		event   string
	}{
		"kill switch, anonymous":   {kill: true, enabled: true, creator: anonymousCreator(), want: ErrExpressDisabled, event: "disabled"},
		"kill switch, token":       {kill: true, enabled: true, creator: tokenCreator(), want: ErrExpressDisabled, event: "disabled"},
		"anonymous mode off":       {creator: anonymousCreator(), want: ErrExpressDisabled, event: "disabled"},
		"token without the opt-in": {enabled: true, creator: ExpressCreator{ClientIP: remoteIP, APITokenID: expressToken}, want: ErrExpressTokenNotAllowed, event: "token"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.svc.killSwitch = tc.kill
			if _, err := e.svc.CreateExpress(context.Background(), expressTenant(tc.enabled), tc.creator, ExpressCreateRequest{}); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got := e.seclog.types(); !slices.Equal(got, []string{"express_refused reason=" + tc.event}) {
				t.Errorf("security log = %v", got)
			}
			if ev := e.seclog.events[0]; ev.IP != remoteIP || ev.Tenant != testTenant.FQDN {
				t.Errorf("event = %+v", ev)
			}
			if e.repo.expressCalls != 0 || len(e.perIP.keys) != 0 || len(e.audit.events) != 0 {
				t.Errorf("store calls %d, per-IP %v, audit %v", e.repo.expressCalls, e.perIP.keys, e.audit.events)
			}
		})
	}
}

func TestCreateExpressRateLimit(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	e.perIP.refuse = true
	var rl *RateLimitError
	_, err := e.svc.CreateExpress(context.Background(), expressTenant(true), ExpressCreator{ClientIP: netip.MustParseAddr("2001:db8:1:2::9")}, s.expressRequest())
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("err = %v", err)
	}
	if got := e.seclog.types(); !slices.Equal(got, []string{"rate_limited scope=express_ip"}) {
		t.Errorf("security log = %v", got)
	}
	if !slices.Equal(e.perIP.keys, []string{"ten_a 2001:db8:1:2::/64"}) || e.repo.expressCalls != 0 {
		t.Errorf("keys %v, store calls %d", e.perIP.keys, e.repo.expressCalls)
	}
}

// TestCreateExpressLimiterSaturated checks that a new client refused
// because the per-client limiter of the tenant is saturated is not written
// as rate_limited express_ip (counted by the shipped fail2ban and CrowdSec
// rules), but as express_refused reason limit, answered ErrExpressLimit.
func TestCreateExpressLimiterSaturated(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	e.perIP.saturated = true
	if _, err := e.svc.CreateExpress(context.Background(), expressTenant(true), anonymousCreator(), s.expressRequest()); !errors.Is(err, ErrExpressLimit) {
		t.Fatalf("err = %v", err)
	}
	if got := e.seclog.types(); !slices.Equal(got, []string{"express_refused reason=limit"}) {
		t.Errorf("security log = %v", got)
	}
	if e.repo.expressCalls != 0 || len(e.audit.events) != 0 {
		t.Errorf("store calls %d, audit %v", e.repo.expressCalls, e.audit.actions())
	}
}

// TestCreateExpressPerIPTenants checks the default per-client limiter
// through the service (threat model T-390, T-405): one tenant whose table
// is full of clients below their limit still admits a new client; a
// tenant whose table is full of clients at their limit refuses a new one
// as saturated (express_refused reason limit, never rate_limited
// express_ip), and another tenant is not affected.
func TestCreateExpressPerIPTenants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	e.svc.perIP = NewExpressWindow(ExpressIPWindow, 2, e.svc.now)
	a, b := expressTenant(true), expressTenant(true)
	b.ID = "ten_b"
	create := func(tn *tenant.Tenant, ip string) error {
		_, err := e.svc.CreateExpress(ctx, tn, ExpressCreator{ClientIP: netip.MustParseAddr(ip)}, s.expressRequest())
		return err
	}
	// A full table of single-event clients (limit 10): a new client takes
	// the place of the least recently seen one.
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if err := create(a, ip); err != nil {
			t.Fatalf("%s on A: %v", ip, err)
		}
	}
	// Every client of A at its limit (1): A refuses a new client.
	a.Express.PerHourPerIP = 1
	if err := create(a, "192.0.2.4"); !errors.Is(err, ErrExpressLimit) {
		t.Fatalf("new client of a saturated A: %v", err)
	}
	var rl *RateLimitError
	if err := create(a, "192.0.2.3"); !errors.As(err, &rl) {
		t.Errorf("known client of A over its limit: %v", err)
	}
	// B is not affected by A's table.
	b.Express.PerHourPerIP = 1
	for _, ip := range []string{"192.0.2.4", "192.0.2.5"} {
		if err := create(b, ip); err != nil {
			t.Errorf("%s on B: %v", ip, err)
		}
	}
	want := []string{"express_refused reason=limit", "rate_limited scope=express_ip"}
	if got := e.seclog.types(); !slices.Equal(got, want) {
		t.Errorf("security log = %v, want %v", got, want)
	}
	if ev := e.seclog.events[0]; ev.IP != netip.MustParseAddr("192.0.2.4") || ev.TenantID != "ten_a" {
		t.Errorf("saturation event = %+v", ev)
	}
}

func TestValidateExpress(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "x", "")
	ok := s.expressRequest()
	for name, tc := range map[string]struct {
		mutate func(*ExpressCreateRequest)
		want   []string
	}{
		"empty": {func(r *ExpressCreateRequest) { *r = ExpressCreateRequest{} }, []string{
			"/encryptedText required", "/verifier required", "/keyVerifier required", "/expiresIn required",
		}},
		"too long":        {func(r *ExpressCreateRequest) { r.EncryptedText = strings.Repeat("A", store.MaxSecretSealedTextLen+1) }, []string{"/encryptedText too-long"}},
		"too short":       {func(r *ExpressCreateRequest) { r.EncryptedText = "AQ" }, []string{"/encryptedText invalid-format"}},
		"not base64url":   {func(r *ExpressCreateRequest) { r.EncryptedText = strings.Repeat("A+", 30) }, []string{"/encryptedText invalid-format"}},
		"bad verifiers":   {func(r *ExpressCreateRequest) { r.Verifier, r.KeyVerifier = "AB", strings.Repeat("G", 64) }, []string{"/verifier invalid-format", "/keyVerifier invalid-format"}},
		"2.1 duration":    {func(r *ExpressCreateRequest) { r.ExpiresIn = "12h" }, []string{"/expiresIn not-allowed"}},
		"unknown":         {func(r *ExpressCreateRequest) { r.ExpiresIn = "1y" }, []string{"/expiresIn not-allowed"}},
		"extra members":   {func(r *ExpressCreateRequest) { r.Extra = []string{"/passphrase", "/file"} }, []string{"/passphrase not-allowed", "/file not-allowed"}},
		"seven days":      {func(r *ExpressCreateRequest) { r.ExpiresIn = "7d" }, nil},
		"one day, as is":  {func(r *ExpressCreateRequest) { r.ExpiresIn = "1d" }, nil},
		"one hour, as is": {func(*ExpressCreateRequest) {}, nil},
	} {
		req := ok
		tc.mutate(&req)
		p, err := validateExpress(req)
		if tc.want == nil {
			if err != nil || p.duration != tenant.SecretDuration(req.ExpiresIn) || len(p.verifier) != 32 || len(p.keyVerifier) != 32 {
				t.Errorf("%s: %+v, %v", name, p, err)
			}
			continue
		}
		if got := fieldsOf(t, err); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	var v *ValidationError
	_, err := validateExpress(ExpressCreateRequest{EncryptedText: s.text, Verifier: s.verifier, KeyVerifier: s.keyVerifier, ExpiresIn: "30d"})
	if !errors.As(err, &v) || !slices.Equal(v.Fields[0].Allowed, []string{"1h", "1d", "7d"}) {
		t.Errorf("allowed durations: %+v", v)
	}
}

// TestCreateExpressBody checks that the body is refused after the switches
// and before the limit and the store: the schema, then the keyless
// framing (an empty text included). A malformed call counts against no
// limit.
func TestCreateExpressBody(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	s, _ := seal(t, "x", "")
	bad := s.expressRequest()
	bad.ExpiresIn = "30d"
	if got := fieldsOf(t, mustExpressErr(e.svc.CreateExpress(ctx, expressTenant(true), anonymousCreator(), bad))); !slices.Equal(got, []string{"/expiresIn not-allowed"}) {
		t.Errorf("schema: %v", got)
	}
	empty, _ := seal(t, "", "")
	var fe *FormatError
	if _, err := e.svc.CreateExpress(ctx, expressTenant(true), tokenCreator(), empty.expressRequest()); !errors.As(err, &fe) ||
		!slices.Equal(fieldsOf(t, err), []string{"/encryptedText invalid-format"}) {
		t.Errorf("empty text: %v", err)
	}
	wrongVersion := s.expressRequest()
	wrongVersion.EncryptedText = "Ag" + wrongVersion.EncryptedText[2:]
	if _, err := e.svc.CreateExpress(ctx, expressTenant(true), anonymousCreator(), wrongVersion); !errors.As(err, &fe) {
		t.Errorf("wrong version: %v", err)
	}
	if e.repo.expressCalls != 0 || len(e.perIP.keys) != 0 || len(e.seclog.events) != 0 {
		t.Errorf("store calls %d, per-IP %v, security log %v", e.repo.expressCalls, e.perIP.keys, e.seclog.types())
	}
}

func mustExpressErr(_ Created, err error) error { return err }

// TestCreateExpressStoreErrors checks the mapping of the refusals of the
// store and their security events.
func TestCreateExpressStoreErrors(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "x", "")
	for name, tc := range map[string]struct {
		err     error
		creator ExpressCreator
		check   func(error) bool
		events  []string
	}{
		"token rate": {
			&store.ExpressTokenRateError{RetryAfter: 5 * time.Minute}, tokenCreator(),
			func(err error) bool {
				var rl *RateLimitError
				return errors.As(err, &rl) && rl.RetryAfter == 5*time.Minute
			},
			[]string{"rate_limited scope=express_token"},
		},
		"cap":          {store.ErrExpressLimit, anonymousCreator(), is(ErrExpressLimit), []string{"express_refused reason=limit"}},
		"closed since": {store.ErrExpressDisabled, anonymousCreator(), is(ErrExpressDisabled), []string{"express_refused reason=disabled"}},
		"opt-in withdrawn": {
			store.ErrExpressTokenNotAllowed, tokenCreator(), is(ErrExpressTokenNotAllowed), []string{"express_refused reason=token"},
		},
		"setup": {store.ErrTenantInSetup, anonymousCreator(), is(ErrTenantInSetup), nil},
		// A token revoked or expired since its authentication is an
		// invalid credential (401), never a missing opt-in.
		"token revoked": {
			fmt.Errorf("store: create express secret: %w", store.ErrExpressTokenUnusable), tokenCreator(),
			func(err error) bool {
				return errors.Is(err, ErrTokenInvalid) && !errors.Is(err, ErrExpressTokenNotAllowed)
			},
			[]string{"api_token_invalid"},
		},
		"tenant gone":        {store.ErrNotFound, anonymousCreator(), is(ErrExpressDisabled), []string{"express_refused reason=disabled"}},
		"tenant gone, token": {store.ErrNotFound, tokenCreator(), is(ErrExpressDisabled), []string{"express_refused reason=disabled"}},
		"failure":            {errBoom, anonymousCreator(), is(errBoom), nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.repo.expressErr = tc.err
			_, err := e.svc.CreateExpress(context.Background(), expressTenant(true), tc.creator, s.expressRequest())
			if !tc.check(err) {
				t.Fatalf("err = %v", err)
			}
			if got := e.seclog.types(); !slices.Equal(got, tc.events) {
				t.Errorf("security log = %v, want %v", got, tc.events)
			}
			if len(e.audit.events) != 0 {
				t.Errorf("audit = %v", e.audit.actions())
			}
		})
	}
}

// is returns a check of errors.Is(err, target).
func is(target error) func(error) bool {
	return func(err error) bool { return errors.Is(err, target) }
}

// TestExpressEventThrottle checks the default throttle of the security
// events: one line per client key (or token), event and reason or scope
// every ExpressEventInterval.
func TestExpressEventThrottle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := testNow
	seclog := &fakeSeclog{}
	svc, err := New(Deps{
		Secrets: &fakeRepo{expressErr: store.ErrExpressLimit}, Creators: &fakeCreators{}, Scrubber: &fakeScrubber{}, Files: &fakeFiles{},
		SecurityLog: seclog, Directory: &fakeDirectory{}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
	}, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := seal(t, "x", "")
	closed, open := expressTenant(false), expressTenant(true)
	// Twice the same refusal, then another reason, another client, and a
	// token without the opt-in.
	other := ExpressCreator{ClientIP: netip.MustParseAddr("198.51.100.1")}
	noOptIn := ExpressCreator{ClientIP: remoteIP, APITokenID: expressToken}
	calls := []struct {
		tn      *tenant.Tenant
		creator ExpressCreator
	}{{closed, anonymousCreator()}, {closed, anonymousCreator()}, {open, anonymousCreator()}, {closed, other}, {open, noOptIn}, {open, noOptIn}}
	for _, c := range calls {
		if _, err := svc.CreateExpress(ctx, c.tn, c.creator, s.expressRequest()); err == nil {
			t.Fatal("created")
		}
	}
	want := []string{"express_refused reason=disabled", "express_refused reason=limit", "express_refused reason=disabled", "express_refused reason=token"}
	if got := seclog.types(); !slices.Equal(got, want) {
		t.Errorf("security log = %v, want %v", got, want)
	}
	now = now.Add(ExpressEventInterval)
	if _, err := svc.CreateExpress(ctx, closed, anonymousCreator(), s.expressRequest()); !errors.Is(err, ErrExpressDisabled) {
		t.Fatal(err)
	}
	if got := len(seclog.events); got != 5 {
		t.Errorf("after the interval: %d events", got)
	}
	if _, ok := svc.throttle.(*ratelimit.Limiter); !ok {
		t.Errorf("default throttle = %T", svc.throttle)
	}
}

// TestExpressTokenEventThrottle checks that the express_token events are
// throttled per token, whatever the client IP.
func TestExpressTokenEventThrottle(t *testing.T) {
	t.Parallel()
	seclog := &fakeSeclog{}
	svc, err := New(Deps{
		Secrets: &fakeRepo{expressErr: &store.ExpressTokenRateError{RetryAfter: time.Minute}}, Creators: &fakeCreators{},
		Scrubber: &fakeScrubber{}, Files: &fakeFiles{}, SecurityLog: seclog, Directory: &fakeDirectory{}, Notifier: &fakeNotifier{},
		Mailer: &fakeMailer{},
	}, Options{Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := seal(t, "x", "")
	other := tokenCreator()
	other.ClientIP = netip.MustParseAddr("192.0.2.77")
	for _, c := range []ExpressCreator{tokenCreator(), other} {
		var rl *RateLimitError
		if _, err := svc.CreateExpress(context.Background(), expressTenant(true), c, s.expressRequest()); !errors.As(err, &rl) {
			t.Fatalf("err = %v", err)
		}
	}
	if got := seclog.types(); !slices.Equal(got, []string{"rate_limited scope=express_token"}) || seclog.events[0].IP != remoteIP {
		t.Errorf("security log = %v", seclog.events)
	}
}

// TestExpressReadGate checks the read gate: the kill switch is passed to
// the store, and a closed secret answers ErrExpressDisabled without event
// nor failure.
func TestExpressReadGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	e.repo.status = store.Secret{ID: "sec_1", State: store.SecretActive, ExpiresAt: testNow.Add(time.Hour), Express: true, CreatorKind: store.SecretCreatorAnonymous}
	st, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok")
	if err != nil || !st.Express || !st.Anonymous || e.repo.gotGate.KillSwitch {
		t.Fatalf("status = %+v, %v, gate %+v", st, err, e.repo.gotGate)
	}
	e.repo.status.CreatorKind, e.repo.status.APITokenID = store.SecretCreatorAPIToken, expressToken
	if st, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok"); err != nil || !st.Express || st.Anonymous {
		t.Errorf("token secret: %+v, %v", st, err)
	}
	e.repo.status = store.Secret{ID: "sec_2", State: store.SecretActive, ExpiresAt: testNow.Add(time.Hour), SenderEmail: alice}
	if st, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok"); err != nil || st.Express || st.Anonymous {
		t.Errorf("2.1 secret: %+v, %v", st, err)
	}
	e.svc.killSwitch = true
	e.repo.statusErr, e.repo.revealErr = store.ErrExpressClosed, store.ErrExpressClosed
	if _, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok"); !errors.Is(err, ErrExpressDisabled) || !e.repo.gotGate.KillSwitch {
		t.Errorf("closed status: %v, gate %+v", err, e.repo.gotGate)
	}
	e.repo.gotGate = store.ExpressGate{}
	if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_tok", s.keyProof, s.proof); !errors.Is(err, ErrExpressDisabled) || !e.repo.gotGate.KillSwitch {
		t.Errorf("closed reveal: %v, gate %+v", err, e.repo.gotGate)
	}
	if len(e.seclog.events) != 0 || e.failures.fails != 0 || len(e.audit.events) != 0 || e.scrubber.calls != 0 {
		t.Errorf("security log %v, failures %d, audit %v, scrubs %d", e.seclog.types(), e.failures.fails, e.audit.actions(), e.scrubber.calls)
	}
}

func TestTokenOfLink(t *testing.T) {
	t.Parallel()
	tok, err := id.NewSecretToken()
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("k", 43)
	for _, link := range []string{
		tok,
		"  " + tok + "\n",
		"https://transfer.entity-a.example.com/s/" + tok + "#k=" + key,
		"https://transfer.entity-b.example.com/s/" + tok,
		"http://transfer.entity-a.example.com:8443/s/" + tok + "/",
		"https://transfer.entity-a.example.com/s/" + tok + "?utm=x#k=" + key,
		"transfer.entity-a.example.com/s/" + tok,
		"/s/" + tok + "#k=" + key,
		tok + "#k=" + key,
	} {
		if got, err := tokenOfLink(link); err != nil || got != tok {
			t.Errorf("tokenOfLink(%q) = %q, %v", link, got, err)
		}
	}
	for link, code := range map[string]string{
		"":    CodeRequired,
		"   ": CodeRequired,
		"https://transfer.entity-a.example.com/s/" + tok + strings.Repeat("x", MaxLookupLinkLen): CodeTooLong,
		"https://transfer.entity-a.example.com/x/" + tok:                                         CodeInvalidFormat,
		"https://transfer.entity-a.example.com/api/s/" + tok:                                     CodeInvalidFormat,
		"https://transfer.entity-a.example.com/s/" + tok + "/more":                               CodeInvalidFormat,
		"https://transfer.entity-a.example.com/s/tts_short":                                      CodeInvalidFormat,
		"https://transfer.entity-a.example.com/s/" + id.New(id.Secret):                           CodeInvalidFormat,
		"#k=" + tok:       CodeInvalidFormat,
		"tts_" + key[:42]: CodeInvalidFormat,
	} {
		_, err := tokenOfLink(link)
		if got := fieldsOf(t, err); !slices.Equal(got, []string{FieldLink + " " + code}) {
			t.Errorf("tokenOfLink(%.60q) = %v, want %s", link, got, code)
		}
		if err != nil && strings.Contains(err.Error(), "tts_") {
			t.Errorf("the error text holds the link: %v", err)
		}
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tok, _ := id.NewSecretToken()
	link := "https://transfer.entity-a.example.com/s/" + tok + "#k=" + strings.Repeat("k", 43)
	admin := AdminActor{Username: "delegate", IP: internalIP}
	e := newEnv(t)
	e.repo.lookup = store.Secret{ID: "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2", State: store.SecretRead, Express: true}
	sec, err := e.svc.Lookup(ctx, testTenant, admin, link)
	if err != nil || sec.ID != e.repo.lookup.ID || e.repo.gotLookup != tok {
		t.Fatalf("lookup = %+v, %v (token %q)", sec, err, e.repo.gotLookup)
	}
	if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionSecretLookedUp}) {
		t.Fatalf("audit = %v", got)
	}
	ev := e.audit.events[0]
	if ev.ActorKind != store.ActorAdmin || ev.Actor != "delegate" || ev.IP != internalIP || ev.ObjectKind != audit.ObjectSecret ||
		ev.ObjectID != sec.ID || len(ev.Details) != 0 {
		t.Errorf("audit event = %+v", ev)
	}
	if strings.Contains(fmt.Sprintf("%+v", e.audit.events), tok) {
		t.Error("the audit holds the token")
	}
	// Unknown: not found, not audited; a malformed link never reaches the
	// store; a failure is wrapped.
	e.repo.lookupErr = fmt.Errorf("store: lookup secret: %w", store.ErrNotFound)
	if _, err := e.svc.Lookup(ctx, testTenant, admin, tok); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	e.repo.gotLookup = ""
	if _, err := e.svc.Lookup(ctx, testTenant, admin, "https://transfer.entity-a.example.com/"); fieldsOf(t, err)[0] != "/link invalid-format" || e.repo.gotLookup != "" {
		t.Errorf("malformed: %v", err)
	}
	e.repo.lookupErr = errBoom
	if _, err := e.svc.Lookup(ctx, testTenant, admin, tok); !errors.Is(err, errBoom) {
		t.Errorf("failure: %v", err)
	}
	if len(e.audit.events) != 1 || len(e.seclog.events) != 0 {
		t.Errorf("audit %v, security log %v", e.audit.actions(), e.seclog.types())
	}
}

func TestPurgeExpress(t *testing.T) {
	t.Parallel()
	admin := AdminActor{Username: "delegate", IP: internalIP}
	for name, tc := range map[string]struct {
		n      int
		err    error
		scrubs int
		audits int
	}{
		"some":           {n: 3, scrubs: 1, audits: 1},
		"none":           {n: 0, audits: 1},
		"failed midway":  {n: 2, err: errBoom, scrubs: 1, audits: 1},
		"failed at once": {n: 0, err: errBoom},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.repo.purged, e.repo.purgeErr = tc.n, tc.err
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // the purge goes on after a cancellation
			n, err := e.svc.PurgeExpress(ctx, testTenant, admin)
			if n != tc.n || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
				t.Fatalf("purge = %d, %v", n, err)
			}
			if e.scrubber.calls != tc.scrubs || len(e.audit.events) != tc.audits || e.repo.purges != 1 {
				t.Errorf("scrubs %d, audit %v, purges %d", e.scrubber.calls, e.audit.actions(), e.repo.purges)
			}
			if tc.audits == 0 {
				return
			}
			ev := e.audit.events[0]
			if ev.Action != audit.ActionSecretExpressPurged || ev.ActorKind != store.ActorAdmin || ev.Actor != "delegate" ||
				ev.IP != internalIP || ev.ObjectKind != audit.ObjectTenant || ev.ObjectID != "ten_a" || ev.Details["count"] != tc.n {
				t.Errorf("audit event = %+v", ev)
			}
		})
	}
}

// expressRead is a read express secret, as LookupByToken returns it.
func expressRead() store.Secret {
	return store.Secret{
		ID: "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2", State: store.SecretRead, EndReason: store.SecretEndRead, Express: true,
		CreatorKind: store.SecretCreatorAnonymous, ExpiresAt: testNow.Add(time.Hour),
	}
}

func TestReportAbuse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, sec := range map[string]store.Secret{
		"read": expressRead(),
		"active": {
			ID: "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2", State: store.SecretActive, Express: true, CreatorKind: store.SecretCreatorAPIToken,
			ExpiresAt: testNow.Add(time.Minute),
		},
	} {
		e := newEnv(t)
		e.repo.lookup = sec
		// Not blocked by a closed service.
		e.svc.killSwitch = true
		err := e.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", AbuseReportRequest{
			Category: "phishing", Message: "fake\u202ebank\r\nsite\u200b",
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(e.reports.got) != 1 {
			t.Fatalf("%s: reports %v", name, e.reports.got)
		}
		r := e.reports.got[0]
		if r.SecretID != sec.ID || r.TransferID != "" || r.SenderEmail != "" || r.ReporterIP != remoteIP ||
			r.Category != store.AbuseCategoryPhishing || r.Message != "fakebank\nsite" || r.ReporterVerified ||
			e.reports.gotLimits != store.DefaultAbuseReportLimits() || !e.reports.gotNow.Equal(testNow) {
			t.Errorf("%s: report %+v, limits %+v", name, r, e.reports.gotLimits)
		}
		if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionAbuseReported}) {
			t.Fatalf("%s: audit = %v", name, got)
		}
		ev := e.audit.events[0]
		if ev.ActorKind != store.ActorRecipient || ev.Actor != linkActor || ev.IP != remoteIP || ev.ObjectKind != audit.ObjectAbuseReport ||
			!id.Valid(id.AbuseReport, ev.ObjectID) || ev.Details["secretId"] != sec.ID || ev.Details["category"] != "phishing" {
			t.Errorf("%s: audit event = %+v", name, ev)
		}
		if len(e.alerts.reports) != 1 || e.alerts.reports[0].ID != ev.ObjectID || e.alerts.reports[0].SecretID != sec.ID {
			t.Errorf("%s: alerts = %+v", name, e.alerts.reports)
		}
		if len(e.seclog.events) != 0 || e.failures.fails != 0 {
			t.Errorf("%s: security log %v, failures %d", name, e.seclog.types(), e.failures.fails)
		}
		if !slices.Equal(e.reportsIP.keys, []string{"ten_a 203.0.113.9"}) || !slices.Equal(e.reportsIP.limits, []int{store.DefaultAbuseReportsPerIP}) {
			t.Errorf("%s: per-client limiter keys %v limits %v", name, e.reportsIP.keys, e.reportsIP.limits)
		}
	}
}

// TestReportAbusePerClient checks the in-memory limit of the reports per
// tenant and client key (threat model T-407): addresses rotating within
// one IPv6 /64 share 5 reports per hour, whatever the per-address count
// of the store says; another /64 and another tenant are other clients. A
// saturated limiter refuses without security event.
func TestReportAbusePerClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	e.repo.lookup = expressRead()
	e.svc.reportsPerIP = NewExpressWindow(store.AbuseReportIPWindow, ExpressIPMaxKeys, e.svc.now)
	report := func(tn *tenant.Tenant, ip string) error {
		return e.svc.ReportAbuse(ctx, tn, netip.MustParseAddr(ip), "tts_tok", AbuseReportRequest{Category: "spam"})
	}
	for i := 1; i <= store.DefaultAbuseReportsPerIP; i++ {
		if err := report(testTenant, fmt.Sprintf("2001:db8:1:2::%x", i)); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	var rl *RateLimitError
	if err := report(testTenant, "2001:db8:1:2:ffff::1"); !errors.As(err, &rl) || rl.RetryAfter != store.AbuseReportIPWindow {
		t.Fatalf("6th report of the /64: %v", err)
	}
	if got := e.seclog.types(); !slices.Equal(got, []string{"rate_limited scope=abuse_report_ip"}) {
		t.Errorf("security log = %v", got)
	}
	other := *testTenant
	other.ID = "ten_b"
	for _, c := range []struct {
		tn *tenant.Tenant
		ip string
	}{{testTenant, "2001:db8:1:3::1"}, {&other, "2001:db8:1:2::1"}} {
		if err := report(c.tn, c.ip); err != nil {
			t.Errorf("%s on %s: %v", c.ip, c.tn.ID, err)
		}
	}
	if n := len(e.reports.got); n != store.DefaultAbuseReportsPerIP+2 {
		t.Errorf("%d reports stored", n)
	}

	s := newEnv(t)
	s.repo.lookup = expressRead()
	s.reportsIP.saturated = true
	if err := s.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", AbuseReportRequest{Category: "spam"}); !errors.As(err, &rl) || rl.RetryAfter != 9*time.Second {
		t.Fatalf("saturated limiter: %v", err)
	}
	if len(s.seclog.events) != 0 || len(s.reports.got) != 0 || len(s.audit.events) != 0 {
		t.Errorf("saturated limiter: security log %v, reports %v, audit %v", s.seclog.types(), s.reports.got, s.audit.actions())
	}
}

func TestReportAbuseRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ok := AbuseReportRequest{Category: "spam"}
	gone := func(reason string) func(error) bool {
		return func(err error) bool {
			var g *GoneError
			return errors.As(err, &g) && g.Reason == reason
		}
	}
	tombstone := func(state store.SecretState, reason store.SecretEndReason) store.Secret {
		s := expressRead()
		s.State, s.EndReason = state, reason
		return s
	}
	expiredActive := expressRead()
	expiredActive.State, expiredActive.ExpiresAt = store.SecretActive, testNow
	for name, tc := range map[string]struct {
		lookup    store.Secret
		lookupErr error
		req       AbuseReportRequest
		check     func(error) bool
		events    []string
		fails     int
	}{
		"unknown token":   {lookupErr: store.ErrNotFound, req: ok, check: is(ErrNotFound), events: []string{"secret_invalid"}, fails: 1},
		"2.1 secret":      {lookup: store.Secret{ID: "sec_1", State: store.SecretPending, SenderEmail: alice}, req: ok, check: is(ErrNotFound)},
		"lookup failure":  {lookupErr: errBoom, req: ok, check: is(errBoom)},
		"past its expiry": {lookup: expiredActive, req: ok, check: gone(ReasonExpired)},
		"expired":         {lookup: tombstone(store.SecretExpired, store.SecretEndExpired), req: ok, check: gone(ReasonExpired)},
		"deleted":         {lookup: tombstone(store.SecretDeleted, store.SecretEndDeletedByAdmin), req: ok, check: gone(ReasonDeleted)},
		"locked":          {lookup: tombstone(store.SecretLocked, store.SecretEndLocked), req: ok, check: gone(ReasonLocked)},
		"no category": {lookup: expressRead(), req: AbuseReportRequest{}, check: func(err error) bool {
			return slices.Equal(fieldsOf(t, err), []string{"/category required"})
		}},
		"bad body": {lookup: expressRead(), req: AbuseReportRequest{Category: "rude", Message: "\xff"}, check: func(err error) bool {
			return slices.Equal(fieldsOf(t, err), []string{"/category invalid-format", "/message invalid-format"})
		}},
		"message too long": {lookup: expressRead(), req: AbuseReportRequest{Category: "other", Message: strings.Repeat("é", MaxReportMessageRunes+1)}, check: func(err error) bool {
			return slices.Equal(fieldsOf(t, err), []string{"/message too-long"})
		}},
	} {
		e := newEnv(t)
		e.repo.lookup, e.repo.lookupErr = tc.lookup, tc.lookupErr
		err := e.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", tc.req)
		if !tc.check(err) {
			t.Errorf("%s: err = %v", name, err)
		}
		if got := e.seclog.types(); !slices.Equal(got, tc.events) || e.failures.fails != tc.fails {
			t.Errorf("%s: security log %v, failures %d", name, got, e.failures.fails)
		}
		if len(e.reports.got) != 0 || len(e.audit.events) != 0 || len(e.alerts.reports) != 0 || len(e.reportsIP.keys) != 0 {
			t.Errorf("%s: reports %v, audit %v, alerts %v, per-client %v", name, e.reports.got, e.audit.actions(), e.alerts.reports, e.reportsIP.keys)
		}
	}
	// The limits of the secret links come first.
	e := newEnv(t)
	e.requests.refuse = true
	var rl *RateLimitError
	if err := e.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", ok); !errors.As(err, &rl) || e.repo.gotLookup != "" {
		t.Errorf("link limit: %v", err)
	}
}

func TestReportAbuseStoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	limited := func(d time.Duration) func(error) bool {
		return func(err error) bool {
			var rl *RateLimitError
			return errors.As(err, &rl) && rl.RetryAfter == d
		}
	}
	for name, tc := range map[string]struct {
		err    error
		check  func(error) bool
		events []string
	}{
		"per secret": {store.ErrAbuseReportLinkLimit, limited(store.AbuseReportLinkWindow), []string{
			"rate_limited transfer=sec_01JABCS3T4 scope=abuse_report_link",
		}},
		"per ip":       {store.ErrAbuseReportIPLimit, limited(store.AbuseReportIPWindow), []string{"rate_limited scope=abuse_report_ip"}},
		"purged since": {store.ErrNotFound, is(ErrNotFound), nil},
		"failure":      {errBoom, is(errBoom), nil},
	} {
		e := newEnv(t)
		e.repo.lookup, e.reports.err = expressRead(), tc.err
		if err := e.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", AbuseReportRequest{Category: "other"}); !tc.check(err) {
			t.Errorf("%s: err = %v", name, err)
		}
		if got := e.seclog.types(); !slices.Equal(got, tc.events) {
			t.Errorf("%s: security log = %v, want %v", name, got, tc.events)
		}
		if len(e.audit.events) != 0 || len(e.alerts.reports) != 0 {
			t.Errorf("%s: audit %v, alerts %v", name, e.audit.actions(), e.alerts.reports)
		}
	}
	// Without a report store: a wiring error; without a notifier: no
	// alert, no failure.
	e := newEnv(t)
	e.repo.lookup = expressRead()
	e.svc.reports = nil
	if err := e.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", AbuseReportRequest{Category: "other"}); !errors.Is(err, errNoAbuseReports) {
		t.Errorf("no store: %v", err)
	}
	svc, err := New(Deps{
		Secrets: &fakeRepo{lookup: expressRead()}, Creators: &fakeCreators{}, Scrubber: &fakeScrubber{}, Files: &fakeFiles{},
		SecurityLog: &fakeSeclog{}, Directory: &fakeDirectory{}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
	}, Options{AbuseReports: &fakeReports{}, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_tok", AbuseReportRequest{Category: "other"}); err != nil {
		t.Errorf("without notifier: %v", err)
	}
	if _, ok := svc.reportAlerts.(noAbuseNotifier); !ok {
		t.Errorf("default notifier = %T", svc.reportAlerts)
	}
	if _, ok := svc.perIP.(*ExpressWindow); !ok {
		t.Errorf("default per-IP limiter = %T", svc.perIP)
	}
	if w, ok := svc.reportsPerIP.(*ExpressWindow); !ok || w.period != store.AbuseReportIPWindow || w.maxKeys != ExpressIPMaxKeys {
		t.Errorf("default per-client report limiter = %T", svc.reportsPerIP)
	}
}

// TestExpressNothingSecretLogged checks that no refusal of the express
// paths writes the token, the sealed text or the verifiers to the security
// log.
func TestExpressNothingSecretLogged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "the secret text", "")
	e := newEnv(t)
	for _, err := range []error{store.ErrExpressLimit, &store.ExpressTokenRateError{RetryAfter: time.Second}} {
		e.repo.expressErr = err
		_, _ = e.svc.CreateExpress(ctx, expressTenant(true), anonymousCreator(), s.expressRequest())
		_, _ = e.svc.CreateExpress(ctx, expressTenant(true), tokenCreator(), s.expressRequest())
	}
	e.repo.lookupErr = store.ErrNotFound
	_ = e.svc.ReportAbuse(ctx, testTenant, remoteIP, "tts_reported", AbuseReportRequest{Category: "other"})
	logged := fmt.Sprintf("%+v %+v", e.seclog.events, e.audit.events)
	for _, needle := range []string{s.text, s.verifier, s.keyVerifier, "tts_reported", "the secret text"} {
		if strings.Contains(logged, needle) {
			t.Errorf("the logs hold %q", needle)
		}
	}
	if len(e.seclog.events) == 0 {
		t.Fatal("no event")
	}
	for _, ev := range e.seclog.events {
		for _, f := range ev.Fields {
			if f.Key != securitylog.KeyReason && f.Key != securitylog.KeyScope {
				t.Errorf("unexpected field %+v", f)
			}
		}
	}
}
