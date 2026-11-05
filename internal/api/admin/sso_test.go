package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Test values of the single sign-on handlers.
const (
	ssoIssuer  = "https://login.example.com/11111111-2222-3333-4444-555555555555/v2.0"
	ssoIssuer2 = "https://idp.entity-a.example.com/realms/staff"
	ssoApp     = "7f3c9a10-0000-4000-8000-00000000c0de"
	ssoApp2    = "7f3c9a10-0000-4000-8000-00000000beef"
	ssoSecret  = "client-secret-from-the-provider"
	ssoSecret2 = "second-client-secret-value"
)

var ssoA = tenantadmin.SSOView{
	Enabled: true, Issuer: ssoIssuer, ClientID: ssoApp, HasClientSecret: true,
	EmailDomains: []string{"entity-a.example.com"}, RequireMFA: true, CreatedAt: created, UpdatedAt: now,
}

func (f *fakeTenantService) GetSSO(_ context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.SSOView, error) {
	return ssoA, f.record("GetSSO", p.SessionID, tid)
}

func (f *fakeTenantService) PutSSO(_ context.Context, p adminauth.Principal, tid tenant.ID, in tenantadmin.SSOUpdate, ip netip.Addr) (tenantadmin.SSOView, error) {
	v := ssoA
	v.Enabled, v.Issuer, v.ClientID, v.EmailDomains, v.Enforced, v.RequireMFA = in.Enabled, in.Issuer, in.ClientID, in.EmailDomains, in.Enforced, in.RequireMFA
	return v, f.record("PutSSO", p.SessionID, tid, in, ip)
}

func (f *fakeTenantService) DeleteSSO(_ context.Context, p adminauth.Principal, tid tenant.ID, ip netip.Addr) error {
	return f.record("DeleteSSO", p.SessionID, tid, ip)
}

func (f *fakeTenantService) TestSSO(_ context.Context, p adminauth.Principal, tid tenant.ID) (oidc.TestResult, error) {
	return oidc.TestResult{Duration: 41 * time.Millisecond, Stage: "tls", Error: oidc.CategoryTLS}, f.record("TestSSO", p.SessionID, tid)
}

// ssoOps calls the four single sign-on operations on tenant ten_a.
func ssoOps(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	_, out["GetSSO"] = s.GetTenantSso(ctx, gen.GetTenantSsoRequestObject{TenantId: "ten_a"})
	_, out["PutSSO"] = s.PutTenantSso(ctx, gen.PutTenantSsoRequestObject{TenantId: "ten_a", Body: &gen.TenantSsoUpdate{}})
	_, out["DeleteSSO"] = s.DeleteTenantSso(ctx, gen.DeleteTenantSsoRequestObject{TenantId: "ten_a"})
	_, out["TestSSO"] = s.TestTenantSso(ctx, gen.TestTenantSsoRequestObject{TenantId: "ten_a"})
	return out
}

func TestSSOWiring(t *testing.T) {
	t.Parallel()
	for name, err := range ssoOps(ctxWith(store.SessionAuthenticated, superRoot), NewServer()) {
		if !errors.Is(err, errNoTenantService) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	svc := &fakeTenantService{}
	for name, err := range ssoOps(ctxWith("", superRoot), tenantServer(svc)) {
		if p := expectProblem(t, err, problem.CodeUnauthenticated); p.Code == "" {
			t.Error(name)
		}
	}
	if len(svc.calls) != 0 {
		t.Errorf("service called without session: %v", svc.calls)
	}
	// Each service error is mapped.
	for target, code := range map[error]problem.Code{
		tenantadmin.ErrSSOIssuerNotAllowed: problem.CodeSSOIssuerNotAllowed,
		tenantadmin.ErrSSODomainConflict:   problem.CodeSSODomainConflict,
		tenantadmin.ErrSSONothingToTest:    problem.CodeStateConflict,
		tenantadmin.ErrForbidden:           problem.CodeForbidden,
		adminauth.ErrReadOnlyRole:          problem.CodeReadOnlyRole,
		tenantadmin.ErrNotFound:            problem.CodeNotFound,
		tenantadmin.ErrUnauthenticated:     problem.CodeUnauthenticated,
	} {
		svc := &fakeTenantService{err: target}
		for name, err := range ssoOps(ctxWith(store.SessionAuthenticated, superRoot), tenantServer(svc)) {
			p := expectProblem(t, err, code)
			if code == problem.CodeSSOIssuerNotAllowed &&
				(len(p.Errors) != 1 || p.Errors[0].Field != "/issuer" || p.Errors[0].Code != "not-allowed") {
				t.Errorf("%s: issuer errors %+v", name, p.Errors)
			}
		}
	}
	// An internal error keeps its cause.
	boom := errors.New("boom")
	for name, err := range ssoOps(ctxWith(store.SessionAuthenticated, superRoot), tenantServer(&fakeTenantService{err: boom})) {
		if !errors.Is(err, boom) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Field errors: the code of the service, else invalid-format.
	for _, tc := range []struct {
		err   *tenantadmin.InvalidError
		field string
		code  string
	}{
		{&tenantadmin.InvalidError{Field: tenantadmin.FieldSSOClientSecret, Code: tenantadmin.CodeRequired}, "/clientSecret", "required"},
		{&tenantadmin.InvalidError{Field: "/emailDomains/1", Code: tenantadmin.CodeNotInternalDomain}, "/emailDomains/1", "not-internal-domain"},
		{&tenantadmin.InvalidError{Field: tenantadmin.FieldSSOIssuer}, "/issuer", "invalid-format"},
	} {
		svc := &fakeTenantService{err: tc.err, errAt: "PutSSO"}
		_, err := tenantServer(svc).PutTenantSso(ctxWith(store.SessionAuthenticated, superRoot),
			gen.PutTenantSsoRequestObject{TenantId: "ten_a", Body: &gen.TenantSsoUpdate{}})
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != tc.code {
			t.Errorf("%s: errors %+v", tc.field, p.Errors)
		}
	}
}

func TestSSOHandlers(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	svc := &fakeTenantService{}
	s := tenantServer(svc)

	got, err := s.GetTenantSso(ctx, gen.GetTenantSsoRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	want := gen.GetTenantSso200JSONResponse{
		Enabled: true, Issuer: ssoIssuer, ClientId: ssoApp, HasClientSecret: true, EmailDomains: []string{"entity-a.example.com"},
		RequireMfa: true, CreatedAt: created, UpdatedAt: now,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("get = %+v", got)
	}

	// The defaults of the optional members: enforced false, requireMfa
	// true; explicit values are kept.
	secret := ssoSecret
	body := gen.TenantSsoUpdate{Enabled: true, Issuer: ssoIssuer, ClientId: ssoApp, ClientSecret: &secret, EmailDomains: []string{"entity-a.example.com"}}
	put, err := s.PutTenantSso(ctx, gen.PutTenantSsoRequestObject{TenantId: "ten_a", Body: &body})
	if err != nil {
		t.Fatal(err)
	}
	in := svc.args["PutSSO"][2].(tenantadmin.SSOUpdate)
	if in.Enforced || !in.RequireMFA || in.ClientSecret == nil || *in.ClientSecret != ssoSecret || in.Issuer != ssoIssuer ||
		in.ClientID != ssoApp || !in.Enabled || svc.args["PutSSO"][3] != clientIP || svc.args["PutSSO"][1] != tenant.ID("ten_a") {
		t.Errorf("put args %+v", svc.args["PutSSO"])
	}
	assertNoSecret(t, "put", put)
	yes, no := true, false
	body.Enforced, body.RequireMfa, body.ClientSecret = &yes, &no, nil
	if _, err := s.PutTenantSso(ctx, gen.PutTenantSsoRequestObject{TenantId: "ten_a", Body: &body}); err != nil {
		t.Fatal(err)
	}
	if in := svc.args["PutSSO"][2].(tenantadmin.SSOUpdate); !in.Enforced || in.RequireMFA || in.ClientSecret != nil {
		t.Errorf("explicit put args %+v", in)
	}
	_, err = s.PutTenantSso(ctx, gen.PutTenantSsoRequestObject{TenantId: "ten_a"})
	if p := expectProblem(t, err, problem.CodeValidationFailed); len(p.Errors) != 1 || p.Errors[0].Field != "/issuer" {
		t.Errorf("no body: %+v", p.Errors)
	}

	del, err := s.DeleteTenantSso(ctx, gen.DeleteTenantSsoRequestObject{TenantId: "ten_a"})
	if err != nil || del != (gen.DeleteTenantSso204Response{}) {
		t.Errorf("delete = %v, %v", del, err)
	}
	if !reflect.DeepEqual(svc.args["DeleteSSO"], []any{"as_01", tenant.ID("ten_a"), clientIP}) {
		t.Errorf("delete args %v", svc.args["DeleteSSO"])
	}

	res, err := s.TestTenantSso(ctx, gen.TestTenantSsoRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	tlsErr := gen.SsoTestResultError(oidc.CategoryTLS)
	if !reflect.DeepEqual(res, gen.TestTenantSso200JSONResponse{DurationMs: 41, Stage: "tls", Error: &tlsErr}) {
		t.Errorf("test = %+v", res)
	}
}

// assertNoSecret fails when the JSON rendering of resp holds a client
// secret or a clientSecret member.
func assertNoSecret(t *testing.T, what string, resp any) {
	t.Helper()
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{ssoSecret, ssoSecret2, `"clientSecret"`} {
		if bytes.Contains(b, []byte(s)) {
			t.Errorf("%s: response holds %s: %s", what, s, b)
		}
	}
}

// --- Through the real service ------------------------------------------------

// nopAssets, nopEraser and nopMailer complete the tenantadmin options; the
// single sign-on operations never use them.
type (
	nopAssets struct{}
	nopEraser struct{}
	nopMailer struct{}
)

func (nopAssets) Put(tenant.ID, branding.Kind, []byte) error              { return nil }
func (nopAssets) Get(tenant.ID, branding.Kind) ([]byte, error)            { return nil, io.EOF }
func (nopAssets) Delete(tenant.ID, branding.Kind) error                   { return nil }
func (nopEraser) EraseTenant(context.Context, tenant.ID) error            { return nil }
func (nopMailer) Send(context.Context, mail.Settings, mail.Message) error { return nil }

// discoveryTester answers a successful discovery for any issuer.
type discoveryTester struct{ issuers []string }

func (d *discoveryTester) Test(_ context.Context, issuer string) oidc.TestResult {
	d.issuers = append(d.issuers, issuer)
	return oidc.TestResult{Success: true, Duration: 182 * time.Millisecond, Stage: oidc.StageDone}
}

// ssoEnv is a server over the real tenant configuration service and
// database, with tenants A and B and a delegated admin account of A.
type ssoEnv struct {
	db     *store.DB
	srv    *Server
	tester *discoveryTester
	a, b   *tenant.Tenant
	alice  store.Admin
}

func newSSOEnv(t *testing.T, e storetest.Engine) *ssoEnv {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "admin-sso"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &ssoEnv{db: db, tester: &discoveryTester{}}
	svc, err := tenantadmin.New(db, tenantadmin.Options{
		Vault: masterkey.NewVault(db, kr, nil), Assets: nopAssets{}, Eraser: nopEraser{}, Mailer: nopMailer{},
		SSOTester: ev.tester,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.srv = tenantServer(svc)
	for i, host := range []string{"transfer.entity-a.example.com", "transfer.entity-b.example.com"} {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: host, FQDN: host, DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
		})
		if err != nil {
			t.Fatal(err)
		}
		domain := strings.TrimPrefix(host, "transfer.")
		if _, err := db.NetworkRules().Replace(ctx, tn.ID, nil, []string{domain}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			ev.a = tn
		} else {
			ev.b = tn
		}
	}
	ev.alice, err = db.Admins().Create(ctx, store.Admin{
		Username: "alice.sso", Email: "alice@entity-a.example.com", Role: store.RoleDelegatedAdmin,
		TenantIDs: []tenant.ID{ev.a.ID}, RequireTOTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// put stores the configuration of A as admin a.
func (ev *ssoEnv) put(a adminauth.Account, tid tenant.ID, b gen.TenantSsoUpdate) (gen.PutTenantSsoResponseObject, error) {
	return ev.srv.PutTenantSso(ctxWith(store.SessionAuthenticated, a), gen.PutTenantSsoRequestObject{TenantId: string(tid), Body: &b})
}

// session creates a single sign-on session of alice through the pair and
// returns its token hash.
func (ev *ssoEnv) session(t *testing.T, token, issuer, clientID string) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(token))
	at := time.Now().Truncate(time.Millisecond)
	if err := ev.db.AdminSessions().Create(context.Background(), store.AdminSession{
		ID: id.New(id.AdminSession), TokenHash: h[:], AdminID: ev.alice.ID, State: store.SessionAuthenticated,
		CreatedAt: at, ExpiresAt: at.Add(12 * time.Hour),
		AuthMethod: store.AuthOIDC, SSOIssuer: issuer, SSOClientID: clientID, SSOMFA: true,
	}); err != nil {
		t.Fatal(err)
	}
	return h[:]
}

// alive reports whether the session of hash still exists.
func (ev *ssoEnv) alive(t *testing.T, hash []byte) bool {
	t.Helper()
	_, err := ev.db.AdminSessions().GetByTokenHash(context.Background(), hash, time.Now(), time.Hour)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

// TestSSOThroughService runs the operations through the real service on
// both engines: the role of each caller (T-287), the validation and
// conflict answers, the revocations after a change of client ID, a
// disabling and a deletion (P57), and the secret never in an answer nor
// in the audit.
func TestSSOThroughService(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newSSOEnv(t, e)
		a, b := ev.a.ID, ev.b.ID
		super := adminauth.Account{ID: "adm_root", Username: "root", Role: store.RoleSuperAdmin}
		delegA := adminauth.Account{ID: ev.alice.ID, Username: "alice.sso", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{a}}
		delegB := adminauth.Account{ID: "adm_bob", Username: "bob", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{b}}
		auditA := adminauth.Account{ID: "adm_audit_a", Username: "audrey", Role: store.RoleAuditor, TenantIDs: []tenant.ID{a}}
		auditB := adminauth.Account{ID: "adm_audit_b", Username: "boris", Role: store.RoleAuditor, TenantIDs: []tenant.ID{b}}
		secret := ssoSecret
		body := gen.TenantSsoUpdate{Enabled: true, Issuer: ssoIssuer, ClientId: ssoApp, ClientSecret: &secret, EmailDomains: []string{"entity-a.example.com"}}

		// Before any configuration.
		_, err := ev.srv.GetTenantSso(ctxWith(store.SessionAuthenticated, super), gen.GetTenantSsoRequestObject{TenantId: string(a)})
		expectProblem(t, err, problem.CodeNotFound)
		_, err = ev.srv.TestTenantSso(ctxWith(store.SessionAuthenticated, super), gen.TestTenantSsoRequestObject{TenantId: string(a)})
		expectProblem(t, err, problem.CodeStateConflict)

		// Writes: super admin only, 404 outside the caller's tenants.
		for _, tc := range []struct {
			who  adminauth.Account
			code problem.Code
		}{
			{delegA, problem.CodeForbidden}, {auditA, problem.CodeReadOnlyRole}, {delegB, problem.CodeNotFound}, {auditB, problem.CodeNotFound},
		} {
			_, err := ev.put(tc.who, a, body)
			expectProblem(t, err, tc.code)
			ctx := ctxWith(store.SessionAuthenticated, tc.who)
			_, err = ev.srv.DeleteTenantSso(ctx, gen.DeleteTenantSsoRequestObject{TenantId: string(a)})
			expectProblem(t, err, tc.code)
			_, err = ev.srv.TestTenantSso(ctx, gen.TestTenantSsoRequestObject{TenantId: string(a)})
			expectProblem(t, err, tc.code)
		}
		resp, err := ev.put(super, a, body)
		if err != nil {
			t.Fatal(err)
		}
		if r := resp.(gen.PutTenantSso200JSONResponse); !r.HasClientSecret || r.Enforced || !r.RequireMfa {
			t.Errorf("put = %+v", r)
		}
		assertNoSecret(t, "put", resp)

		// Reads: super admin, delegated admin and auditor of A; 404 for B's.
		for _, tc := range []struct {
			who adminauth.Account
			ok  bool
		}{{super, true}, {delegA, true}, {auditA, true}, {delegB, false}, {auditB, false}} {
			who := tc.who
			got, err := ev.srv.GetTenantSso(ctxWith(store.SessionAuthenticated, who), gen.GetTenantSsoRequestObject{TenantId: string(a)})
			if !tc.ok {
				expectProblem(t, err, problem.CodeNotFound)
				continue
			}
			if err != nil {
				t.Fatalf("get by %s: %v", who.Username, err)
			}
			assertNoSecret(t, "get", got)
		}
		res, err := ev.srv.TestTenantSso(ctxWith(store.SessionAuthenticated, super), gen.TestTenantSsoRequestObject{TenantId: string(a)})
		if err != nil || !res.(gen.TestTenantSso200JSONResponse).Success || ev.tester.issuers[0] != ssoIssuer {
			t.Fatalf("test = %+v, %v (%v)", res, err, ev.tester.issuers)
		}

		// Validation and conflict.
		for name, tc := range map[string]struct {
			change func(*gen.TenantSsoUpdate)
			code   problem.Code
			field  string
			fcode  string
		}{
			"multi-tenant": {
				func(u *gen.TenantSsoUpdate) { u.Issuer = "https://login.microsoftonline.com/common/v2.0" },
				problem.CodeSSOIssuerNotAllowed, "/issuer", "not-allowed",
			},
			"malformed issuer": {func(u *gen.TenantSsoUpdate) { u.Issuer = "not a url" }, problem.CodeValidationFailed, "/issuer", "invalid-format"},
			"new client without secret": {
				func(u *gen.TenantSsoUpdate) { u.ClientId, u.ClientSecret = ssoApp2, nil },
				problem.CodeValidationFailed, "/clientSecret", "required",
			},
			"not internal": {
				func(u *gen.TenantSsoUpdate) {
					u.EmailDomains = []string{"entity-a.example.com", "entity-b.example.com"}
				},
				problem.CodeValidationFailed, "/emailDomains/1", "not-internal-domain",
			},
		} {
			u := body
			tc.change(&u)
			_, err := ev.put(super, a, u)
			p := expectProblem(t, err, tc.code)
			if len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != tc.fcode {
				t.Errorf("%s: errors %+v", name, p.Errors)
			}
		}
		if _, err := ev.db.NetworkRules().Replace(ctx, b, nil, []string{"entity-a.example.com"}); err != nil {
			t.Fatal(err)
		}
		_, err = ev.put(super, b, body)
		expectProblem(t, err, problem.CodeSSODomainConflict)

		// Revocations.
		h1 := ev.session(t, "s1", ssoIssuer, ssoApp)
		if _, err := ev.db.AdminIdentities().Link(ctx, store.AdminIdentity{
			AdminID: ev.alice.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "subject-alice-0001",
		}); err != nil {
			t.Fatal(err)
		}
		secret2 := ssoSecret2
		changed := body
		changed.ClientId, changed.ClientSecret = ssoApp2, &secret2
		if _, err := ev.put(super, a, changed); err != nil {
			t.Fatal(err)
		}
		ids, err := ev.db.AdminIdentities().List(ctx, ev.alice.ID)
		if err != nil || len(ids) != 0 || ev.alive(t, h1) {
			t.Fatalf("client change: identities %v (%v), session alive %v", ids, err, ev.alive(t, h1))
		}
		h2 := ev.session(t, "s2", ssoIssuer, ssoApp2)
		changed.Enabled, changed.ClientSecret = false, nil
		if _, err := ev.put(super, a, changed); err != nil {
			t.Fatal(err)
		}
		if ev.alive(t, h2) {
			t.Fatal("disabling kept the session")
		}
		h3 := ev.session(t, "s3", ssoIssuer, ssoApp2)
		del, err := ev.srv.DeleteTenantSso(ctxWith(store.SessionAuthenticated, super), gen.DeleteTenantSsoRequestObject{TenantId: string(a)})
		if err != nil || del != (gen.DeleteTenantSso204Response{}) || ev.alive(t, h3) {
			t.Fatalf("delete = %v, %v; session alive %v", del, err, ev.alive(t, h3))
		}

		// The audit never holds a secret.
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{TenantID: a})
		if err != nil {
			t.Fatal(err)
		}
		actions := map[string]int{}
		for _, e := range page.Items {
			actions[e.Action]++
			if bytes.Contains(e.Details, []byte(ssoSecret)) || bytes.Contains(e.Details, []byte(ssoSecret2)) {
				t.Errorf("%s holds a secret: %s", e.Action, e.Details)
			}
		}
		if actions["tenant.sso_updated"] != 3 || actions["tenant.sso_deleted"] != 1 || actions["admin.identity_unlinked"] != 1 {
			t.Errorf("audit actions %v", actions)
		}
	})
}
