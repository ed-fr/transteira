package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/provisioning"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// fakeProvisioning records the calls of the provisioning service and
// answers err, or canned values.
type fakeProvisioning struct {
	err   error
	calls []string
	// Last arguments received.
	admin     adminauth.Principal
	principal provisioning.Principal
	create    provisioning.TokenCreate
	code      string
	recovery  string
	tokID     string
	request   provisioning.TenantRequest
	tid       tenant.ID
	ip        netip.Addr
	// noTenants makes ListTenants answer an empty list.
	noTenants bool
}

var (
	provToken = provisioning.Token{
		ID: "prv_01JABCT1V2W3X4Y5Z6A7B8C9D0", Name: "Managed service provider", Prefix: "ttp_EXAM",
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, AllowedFQDNSuffixes: []string{".transfer.example.com"},
		MaxStorageQuotaBytes: 1 << 40, MaxTenants: 50, TenantsCreated: 3, CreatedBy: "adm_root", CreatedAt: now.Add(-time.Hour),
		LastUsedAt: now.Add(-time.Minute),
	}
	provTenant = provisioning.Tenant{
		ID: "ten_01JAB00000000000000ENT1TYC", Name: "Entity C", FQDN: "entity-c.transfer.example.com",
		SetupState: tenant.SetupStateSetup, CreatedAt: now, DelegatedAdminActivated: true,
	}
	provPrincipal = provisioning.Principal{TokenID: provToken.ID, Name: provToken.Name, Prefix: provToken.Prefix}
)

func (f *fakeProvisioning) CreateToken(_ context.Context, p adminauth.Principal, in provisioning.TokenCreate, code, recoveryCode string,
	ip netip.Addr,
) (provisioning.CreatedToken, error) {
	f.calls = append(f.calls, "CreateToken")
	f.admin, f.create, f.code, f.recovery, f.ip = p, in, code, recoveryCode, ip
	if f.err != nil {
		return provisioning.CreatedToken{}, f.err
	}
	tok := provToken
	cap := int64(20 << 30)
	tok.MaxTransferBytes, tok.ExpiresAt = cap, now.Add(24*time.Hour)
	return provisioning.CreatedToken{Token: tok, Secret: "ttp_EXAMPLE4fK2xQ8mL1zV4bN7cR0tY3wE6uI9oP2aS5"}, nil
}

func (f *fakeProvisioning) ListTokens(_ context.Context, p adminauth.Principal) ([]provisioning.Token, error) {
	f.calls = append(f.calls, "ListTokens")
	f.admin = p
	if f.err != nil {
		return nil, f.err
	}
	revoked := provToken
	revoked.ID, revoked.AllowedFQDNSuffixes, revoked.RevokedAt = "prv_01JABCT1V2W3X4Y5Z6A7B8C9D1", nil, now
	return []provisioning.Token{provToken, revoked}, nil
}

func (f *fakeProvisioning) RevokeToken(_ context.Context, p adminauth.Principal, tokID string, ip netip.Addr) error {
	f.calls = append(f.calls, "RevokeToken")
	f.admin, f.tokID, f.ip = p, tokID, ip
	return f.err
}

func (f *fakeProvisioning) ProvisionTenant(_ context.Context, p provisioning.Principal, in provisioning.TenantRequest, ip netip.Addr) (provisioning.Tenant, error) {
	f.calls = append(f.calls, "ProvisionTenant")
	f.principal, f.request, f.ip = p, in, ip
	if f.err != nil {
		return provisioning.Tenant{}, f.err
	}
	t := provTenant
	t.DelegatedAdminActivated = false
	return t, nil
}

func (f *fakeProvisioning) ListTenants(_ context.Context, p provisioning.Principal) ([]provisioning.Tenant, error) {
	f.calls = append(f.calls, "ListTenants")
	f.principal = p
	if f.err != nil {
		return nil, f.err
	}
	if f.noTenants {
		return nil, nil
	}
	return []provisioning.Tenant{provTenant}, nil
}

func (f *fakeProvisioning) GetTenant(_ context.Context, p provisioning.Principal, tid tenant.ID) (provisioning.Tenant, error) {
	f.calls = append(f.calls, "GetTenant")
	f.principal, f.tid = p, tid
	if f.err != nil {
		return provisioning.Tenant{}, f.err
	}
	return provTenant, nil
}

// provServer returns a server over svc.
func provServer(svc *fakeProvisioning) *Server { return NewServer(WithProvisioningService(svc)) }

// withRaw returns ctx carrying raw as CaptureRawBody does.
func withRaw(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, rawBodyKey{}, []byte(raw))
}

// provCtx returns the context of a provisioning request authenticated by
// provPrincipal, from clientIP.
func provCtx() context.Context { return provisioning.NewContext(ctxWith("", superRoot), provPrincipal) }

// fieldErrors returns the field errors of a Problem as "field code".
func fieldErrors(p problem.Problem) []string {
	out := make([]string, len(p.Errors))
	for i, e := range p.Errors {
		out[i] = e.Field + " " + e.Code
	}
	return out
}

// expectField checks a single field error.
func expectField(t *testing.T, p problem.Problem, want string) {
	t.Helper()
	if got := fieldErrors(p); len(got) != 1 || got[0] != want {
		t.Errorf("errors %v, want [%s]", got, want)
	}
}

const tokenCreateJSON = `{"name":"Managed service provider","allowedCidrs":["198.51.100.0/24"],` +
	`"allowedFqdnSuffixes":[".transfer.example.com"],"maxStorageQuotaBytes":1099511627776,"maxTransferBytes":null,` +
	`"maxTenants":50,"expiresAt":null,"code":"204816"}`

// decodeBody decodes raw like the generated handler.
func decodeBody[T any](t *testing.T, raw string) *T {
	t.Helper()
	var b T
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestProvisioningWithoutService(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	s := NewServer()
	errs := []error{}
	_, err := s.ListProvisioningTokens(ctx, gen.ListProvisioningTokensRequestObject{})
	errs = append(errs, err)
	_, err = s.CreateProvisioningToken(ctx, gen.CreateProvisioningTokenRequestObject{})
	errs = append(errs, err)
	_, err = s.RevokeProvisioningToken(ctx, gen.RevokeProvisioningTokenRequestObject{})
	errs = append(errs, err)
	_, err = s.ListProvisionedTenants(provCtx(), gen.ListProvisionedTenantsRequestObject{})
	errs = append(errs, err)
	_, err = s.ProvisionTenant(provCtx(), gen.ProvisionTenantRequestObject{})
	errs = append(errs, err)
	_, err = s.GetProvisionedTenant(provCtx(), gen.GetProvisionedTenantRequestObject{})
	errs = append(errs, err)
	for i, err := range errs {
		if !errors.Is(err, errNoProvisioningService) {
			t.Errorf("operation %d: %v", i, err)
		}
	}
}

func TestProvisioningTokensWithoutSession(t *testing.T) {
	t.Parallel()
	svc := &fakeProvisioning{}
	s, ctx := provServer(svc), ctxWith("", superRoot)
	_, err := s.ListProvisioningTokens(ctx, gen.ListProvisioningTokensRequestObject{})
	expectProblem(t, err, problem.CodeUnauthenticated)
	_, err = s.CreateProvisioningToken(ctx, gen.CreateProvisioningTokenRequestObject{})
	expectProblem(t, err, problem.CodeUnauthenticated)
	_, err = s.RevokeProvisioningToken(ctx, gen.RevokeProvisioningTokenRequestObject{TokenId: provToken.ID})
	expectProblem(t, err, problem.CodeUnauthenticated)
	if len(svc.calls) != 0 {
		t.Errorf("service called: %v", svc.calls)
	}
}

func TestListProvisioningTokens(t *testing.T) {
	t.Parallel()
	svc := &fakeProvisioning{}
	resp, err := provServer(svc).ListProvisioningTokens(ctxWith(store.SessionAuthenticated, superRoot), gen.ListProvisioningTokensRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	list := resp.(gen.ListProvisioningTokens200JSONResponse)
	if len(list) != 2 || svc.admin.Admin.ID != superRoot.ID {
		t.Fatalf("list %+v", list)
	}
	got := list[0]
	if got.Id != provToken.ID || got.Name != provToken.Name || got.Prefix != "ttp_EXAM" ||
		len(got.AllowedCidrs) != 1 || got.AllowedCidrs[0] != "198.51.100.0/24" || got.AllowedFqdnSuffixes[0] != ".transfer.example.com" ||
		got.MaxStorageQuotaBytes != 1<<40 || got.MaxTransferBytes != nil || got.MaxTenants != 50 || got.TenantsCreated != 3 ||
		got.CreatedBy != "adm_root" || !got.CreatedAt.Equal(provToken.CreatedAt) || got.LastUsedAt == nil ||
		got.ExpiresAt != nil || got.RevokedAt != nil {
		t.Errorf("token %+v", got)
	}
	if list[1].AllowedFqdnSuffixes == nil || len(list[1].AllowedFqdnSuffixes) != 0 || list[1].RevokedAt == nil {
		t.Errorf("revoked token %+v", list[1])
	}
	b, err := json.Marshal(list[0])
	if err != nil || strings.Contains(string(b), "token\"") {
		t.Errorf("listed token %s %v", b, err)
	}
	svc.err = adminauth.ErrForbidden
	_, err = provServer(svc).ListProvisioningTokens(ctxWith(store.SessionAuthenticated, delegated), gen.ListProvisioningTokensRequestObject{})
	expectProblem(t, err, problem.CodeForbidden)
}

func TestCreateProvisioningToken(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	svc := &fakeProvisioning{}
	body := decodeBody[gen.ProvisioningTokenCreate](t, tokenCreateJSON)
	resp, err := provServer(svc).CreateProvisioningToken(withRaw(ctx, tokenCreateJSON), gen.CreateProvisioningTokenRequestObject{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.CreateProvisioningToken201JSONResponse)
	if got.Token != "ttp_EXAMPLE4fK2xQ8mL1zV4bN7cR0tY3wE6uI9oP2aS5" || got.Id != provToken.ID ||
		got.MaxTransferBytes == nil || *got.MaxTransferBytes != 20<<30 || got.ExpiresAt == nil || got.TenantsCreated != 3 {
		t.Errorf("created %+v", got)
	}
	in := svc.create
	if in.Name != "Managed service provider" || in.AllowedCIDRs[0] != "198.51.100.0/24" || in.AllowedFQDNSuffixes[0] != ".transfer.example.com" ||
		in.MaxStorageQuotaBytes != 1<<40 || in.MaxTransferBytes != nil || in.MaxTenants != 50 || in.ExpiresAt != nil ||
		svc.code != "204816" || svc.recovery != "" || svc.ip != clientIP {
		t.Errorf("service input %+v code %q recovery %q ip %v", in, svc.code, svc.recovery, svc.ip)
	}
	// Optional members given.
	raw := `{"name":"n","allowedCidrs":[],"allowedFqdnSuffixes":[],"maxStorageQuotaBytes":1,"maxTenants":1,` +
		`"maxTransferBytes":5,"expiresAt":"2030-01-01T00:00:00Z","recoveryCode":"abcd-efgh"}`
	if _, err := provServer(svc).CreateProvisioningToken(withRaw(ctx, raw),
		gen.CreateProvisioningTokenRequestObject{Body: decodeBody[gen.ProvisioningTokenCreate](t, raw)}); err != nil {
		t.Fatal(err)
	}
	if svc.create.MaxTransferBytes == nil || *svc.create.MaxTransferBytes != 5 || svc.create.ExpiresAt == nil ||
		svc.code != "" || svc.recovery != "abcd-efgh" {
		t.Errorf("service input %+v code %q recovery %q", svc.create, svc.code, svc.recovery)
	}
	// No body: the service checks the role, then refuses the empty input.
	svc = &fakeProvisioning{err: &provisioning.InvalidError{Field: provisioning.FieldName, Reason: "x"}}
	_, err = provServer(svc).CreateProvisioningToken(ctx, gen.CreateProvisioningTokenRequestObject{})
	expectField(t, expectProblem(t, err, problem.CodeValidationFailed), "/name invalid-format")
	if svc.create.Name != "" || svc.code != "" {
		t.Errorf("input without body %+v", svc.create)
	}
	// A body without its raw copy: a wiring error.
	_, err = provServer(svc).CreateProvisioningToken(ctx, gen.CreateProvisioningTokenRequestObject{Body: body})
	if !errors.Is(err, errNoProvisioningBody) {
		t.Errorf("without raw body: %v", err)
	}
}

// The body is checked strictly, after the role: no TOTP attempt is ever
// consumed by a refused body, and another administrator learns nothing.
func TestCreateProvisioningTokenStrictBody(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"unknown member", `{"name":"n","role":"super_admin","code":"123456"}`, "/role invalid-format"},
		{"several unknown members", `{"zeta":1,"setupState":"active"}`, "/setupState invalid-format"},
		{"long unknown member", `{"` + strings.Repeat("x", maxEchoedMemberLen+1) + `":1}`, " invalid-format"},
		{"null code", `{"name":"n","code":null}`, "/code invalid-format"},
		{"null recovery code", `{"name":"n","recoveryCode":null}`, "/recoveryCode invalid-format"},
		{"not an object", `[]`, " invalid-format"},
		{"null", `null`, " invalid-format"},
	} {
		svc := &fakeProvisioning{}
		body := &gen.ProvisioningTokenCreate{Name: "n"}
		_, err := provServer(svc).CreateProvisioningToken(withRaw(super, tc.raw), gen.CreateProvisioningTokenRequestObject{Body: body})
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if got := fieldErrors(p); len(got) != 1 || got[0] != strings.TrimSpace(tc.want) && got[0] != tc.want {
			t.Errorf("%s: errors %v, want %q", tc.name, got, tc.want)
		}
		if len(svc.calls) != 0 {
			t.Errorf("%s: service called %v", tc.name, svc.calls)
		}
		// Another administrator, or a session not authenticated yet, gets
		// the refusal of the role first.
		_, err = provServer(svc).CreateProvisioningToken(withRaw(ctxWith(store.SessionAuthenticated, delegated), tc.raw),
			gen.CreateProvisioningTokenRequestObject{Body: body})
		expectProblem(t, err, problem.CodeForbidden)
		_, err = provServer(svc).CreateProvisioningToken(withRaw(ctxWith(store.SessionTOTPRequired, superRoot), tc.raw),
			gen.CreateProvisioningTokenRequestObject{Body: body})
		expectProblem(t, err, problem.CodeUnauthenticated)
		if len(svc.calls) != 0 {
			t.Errorf("%s: service called %v", tc.name, svc.calls)
		}
	}
}

func TestCreateProvisioningTokenErrors(t *testing.T) {
	t.Parallel()
	ctx := withRaw(ctxWith(store.SessionAuthenticated, superRoot), tokenCreateJSON)
	body := decodeBody[gen.ProvisioningTokenCreate](t, tokenCreateJSON)
	internal := errors.New("database is locked")
	for _, tc := range []struct {
		err  error
		code problem.Code
	}{
		{&provisioning.InvalidError{Field: provisioning.FieldAllowedCIDRs, Reason: "x"}, problem.CodeValidationFailed},
		{adminauth.ErrInvalidCredentials, problem.CodeInvalidCredentials},
		{&adminauth.RateLimitError{RetryAfter: time.Minute}, problem.CodeRateLimited},
		{&adminauth.InvalidError{Field: "/code"}, problem.CodeValidationFailed},
		{adminauth.ErrForbidden, problem.CodeForbidden},
		{adminauth.ErrUnauthenticated, problem.CodeUnauthenticated},
	} {
		_, err := provServer(&fakeProvisioning{err: tc.err}).CreateProvisioningToken(ctx, gen.CreateProvisioningTokenRequestObject{Body: body})
		p := expectProblem(t, err, tc.code)
		switch tc.code {
		case problem.CodeRateLimited:
			if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 60 {
				t.Errorf("retry %v", p.RetryAfterSeconds)
			}
		case problem.CodeValidationFailed:
			if len(p.Errors) != 1 || (p.Errors[0].Field != "/allowedCidrs" && p.Errors[0].Field != "/code") {
				t.Errorf("errors %+v", p.Errors)
			}
		}
	}
	_, err := provServer(&fakeProvisioning{err: internal}).CreateProvisioningToken(ctx, gen.CreateProvisioningTokenRequestObject{Body: body})
	if !errors.Is(err, internal) {
		t.Errorf("internal error %v", err)
	}
}

func TestRevokeProvisioningToken(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	svc := &fakeProvisioning{}
	resp, err := provServer(svc).RevokeProvisioningToken(ctx, gen.RevokeProvisioningTokenRequestObject{TokenId: provToken.ID})
	if err != nil || svc.tokID != provToken.ID || svc.ip != clientIP {
		t.Fatalf("revoke %v %+v", err, svc)
	}
	if rec := visit(t, resp); rec.Code != http.StatusNoContent {
		t.Errorf("status %d", rec.Code)
	}
	_, err = provServer(&fakeProvisioning{err: provisioning.ErrNotFound}).RevokeProvisioningToken(ctx,
		gen.RevokeProvisioningTokenRequestObject{TokenId: "prv_x"})
	expectProblem(t, err, problem.CodeNotFound)
}

func TestProvisionedTenantsWithoutToken(t *testing.T) {
	t.Parallel()
	svc := &fakeProvisioning{}
	ctx := ctxWith(store.SessionAuthenticated, superRoot) // an admin session is no provisioning token
	_, err := provServer(svc).ListProvisionedTenants(ctx, gen.ListProvisionedTenantsRequestObject{})
	expectProblem(t, err, problem.CodeProvisioningTokenInvalid)
	_, err = provServer(svc).ProvisionTenant(ctx, gen.ProvisionTenantRequestObject{})
	expectProblem(t, err, problem.CodeProvisioningTokenInvalid)
	_, err = provServer(svc).GetProvisionedTenant(ctx, gen.GetProvisionedTenantRequestObject{TenantId: string(provTenant.ID)})
	expectProblem(t, err, problem.CodeProvisioningTokenInvalid)
	if len(svc.calls) != 0 {
		t.Errorf("service called %v", svc.calls)
	}
}

func TestListAndGetProvisionedTenants(t *testing.T) {
	t.Parallel()
	svc := &fakeProvisioning{}
	resp, err := provServer(svc).ListProvisionedTenants(provCtx(), gen.ListProvisionedTenantsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	list := resp.(gen.ListProvisionedTenants200JSONResponse)
	if len(list.Items) != 1 || svc.principal.TokenID != provToken.ID {
		t.Fatalf("list %+v", list)
	}
	want := gen.ProvisionedTenant{
		Id: string(provTenant.ID), Name: "Entity C", Fqdn: "entity-c.transfer.example.com", SetupState: gen.TenantSetupStateSetup,
		CreatedAt: now, DelegatedAdminActivated: true,
	}
	if list.Items[0] != want {
		t.Errorf("item %+v", list.Items[0])
	}
	got, err := provServer(svc).GetProvisionedTenant(provCtx(), gen.GetProvisionedTenantRequestObject{TenantId: string(provTenant.ID)})
	if err != nil || gen.ProvisionedTenant(got.(gen.GetProvisionedTenant200JSONResponse)) != want || svc.tid != provTenant.ID {
		t.Errorf("get %+v %v", got, err)
	}
	// An empty list is an empty array, never null.
	resp, _ = provServer(&fakeProvisioning{noTenants: true}).ListProvisionedTenants(provCtx(), gen.ListProvisionedTenantsRequestObject{})
	if b, _ := json.Marshal(resp); string(b) != `{"items":[]}` {
		t.Errorf("empty list %s", b)
	}
	for _, tc := range []struct {
		err  error
		code problem.Code
	}{
		{provisioning.ErrNotFound, problem.CodeNotFound},
		{&provisioning.AuthError{Reason: provisioning.ReasonRevoked}, problem.CodeProvisioningTokenInvalid},
	} {
		_, err = provServer(&fakeProvisioning{err: tc.err}).GetProvisionedTenant(provCtx(), gen.GetProvisionedTenantRequestObject{TenantId: "ten_x"})
		expectProblem(t, err, tc.code)
		_, err = provServer(&fakeProvisioning{err: tc.err}).ListProvisionedTenants(provCtx(), gen.ListProvisionedTenantsRequestObject{})
		expectProblem(t, err, tc.code)
	}
}

const provisionTenantJSON = `{"name":"Entity C","fqdn":"entity-c.transfer.example.com","defaultLanguage":"fr",` +
	`"storageQuotaBytes":549755813888,"backgroundPreset":"forest",` +
	`"delegatedAdmin":{"username":"admin.entity-c","email":"it@entity-c.example.com","language":"fr"}}`

func TestProvisionTenant(t *testing.T) {
	t.Parallel()
	svc := &fakeProvisioning{}
	body := decodeBody[gen.ProvisionTenantRequest](t, provisionTenantJSON)
	resp, err := provServer(svc).ProvisionTenant(withRaw(provCtx(), provisionTenantJSON), gen.ProvisionTenantRequestObject{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "act_") || strings.Contains(rec.Body.String(), "activation") {
		t.Errorf("answer %d %s", rec.Code, rec.Body.String())
	}
	in := svc.request
	if in.Name != "Entity C" || in.FQDN != "entity-c.transfer.example.com" || in.DefaultLanguage != "fr" ||
		in.StorageQuotaBytes != 549755813888 || in.MaxTransferBytes != nil || in.BackgroundPreset == nil || *in.BackgroundPreset != "forest" ||
		in.DelegatedAdmin != (adminauth.DelegatedAdmin{Username: "admin.entity-c", Email: "it@entity-c.example.com", Language: "fr"}) ||
		svc.principal.TokenID != provToken.ID || svc.ip != clientIP {
		t.Errorf("service input %+v principal %+v ip %v", in, svc.principal, svc.ip)
	}
	raw := `{"name":"x","fqdn":"x","defaultLanguage":"en","storageQuotaBytes":1,"maxTransferBytes":7,` +
		`"delegatedAdmin":{"username":"u","email":"u@example.com","language":"en","delivery":"mail"}}`
	if _, err := provServer(svc).ProvisionTenant(withRaw(provCtx(), raw),
		gen.ProvisionTenantRequestObject{Body: decodeBody[gen.ProvisionTenantRequest](t, raw)}); err != nil {
		t.Fatal(err)
	}
	if svc.request.MaxTransferBytes == nil || *svc.request.MaxTransferBytes != 7 || svc.request.DelegatedAdmin.Delivery != store.DeliveryMail {
		t.Errorf("service input %+v", svc.request)
	}
	// No body, no raw copy.
	_, err = provServer(svc).ProvisionTenant(provCtx(), gen.ProvisionTenantRequestObject{})
	expectField(t, expectProblem(t, err, problem.CodeValidationFailed), " required")
	_, err = provServer(svc).ProvisionTenant(provCtx(), gen.ProvisionTenantRequestObject{Body: body})
	if !errors.Is(err, errNoProvisioningBody) {
		t.Errorf("without raw body: %v", err)
	}
}

// The body is decoded strictly: no setup state, role or assignment can be
// slipped in (T-271), at the top or in the delegated admin.
func TestProvisionTenantStrictBody(t *testing.T) {
	t.Parallel()
	admin := `"delegatedAdmin":{"username":"u","email":"u@example.com","language":"en"}`
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"setup state", `{"name":"x","setupState":"active",` + admin + `}`, "/setupState invalid-format"},
		{"ceiling", `{"maxTransferCeiling":1,` + admin + `}`, "/maxTransferCeiling invalid-format"},
		{"role", `{"name":"x","delegatedAdmin":{"username":"u","role":"super_admin"}}`, "/delegatedAdmin/role invalid-format"},
		{"tenants", `{"delegatedAdmin":{"tenantIds":["ten_a"],"requireTotp":false}}`, "/delegatedAdmin/requireTotp invalid-format"},
		{"long member", `{"delegatedAdmin":{"` + strings.Repeat("x", maxEchoedMemberLen+1) + `":1}}`, "/delegatedAdmin invalid-format"},
		{"null transfer", `{"maxTransferBytes":null,` + admin + `}`, "/maxTransferBytes invalid-format"},
		{"null preset", `{"backgroundPreset":null,` + admin + `}`, "/backgroundPreset invalid-format"},
		{"null delivery", `{"delegatedAdmin":{"delivery":null}}`, "/delegatedAdmin/delivery invalid-format"},
		{"no admin", `{"name":"x"}`, "/delegatedAdmin required"},
		{"null admin", `{"name":"x","delegatedAdmin":null}`, "/delegatedAdmin required"},
		{"admin not an object", `{"delegatedAdmin":"u"}`, "/delegatedAdmin invalid-format"},
		{"not an object", `"x"`, " invalid-format"},
	} {
		svc := &fakeProvisioning{}
		_, err := provServer(svc).ProvisionTenant(withRaw(provCtx(), tc.raw), gen.ProvisionTenantRequestObject{Body: &gen.ProvisionTenantRequest{}})
		expectField(t, expectProblem(t, err, problem.CodeValidationFailed), tc.want)
		if len(svc.calls) != 0 {
			t.Errorf("%s: service called %v", tc.name, svc.calls)
		}
	}
}

func TestProvisionTenantErrors(t *testing.T) {
	t.Parallel()
	ctx := withRaw(provCtx(), provisionTenantJSON)
	body := decodeBody[gen.ProvisionTenantRequest](t, provisionTenantJSON)
	for _, tc := range []struct {
		name  string
		err   error
		code  problem.Code
		field string
	}{
		{"fqdn out of scope", &provisioning.ScopeError{Field: provisioning.FieldFQDN}, problem.CodeProvisioningScopeExceeded, "/fqdn not-allowed"},
		{"quota out of scope", &provisioning.ScopeError{Field: provisioning.FieldStorageQuotaBytes}, problem.CodeProvisioningScopeExceeded, "/storageQuotaBytes not-allowed"},
		{"max tenants", &provisioning.ScopeError{Field: provisioning.FieldMaxTenants}, problem.CodeProvisioningScopeExceeded, " not-allowed"},
		{"malformed fqdn", &provisioning.InvalidError{Field: provisioning.FieldFQDN, Reason: "x"}, problem.CodeValidationFailed, "/fqdn invalid-format"},
		{"rate", &provisioning.RateLimitError{RetryAfter: 90 * time.Second}, problem.CodeRateLimited, ""},
		{"token revoked meanwhile", &provisioning.AuthError{Reason: provisioning.ReasonRevoked}, problem.CodeProvisioningTokenInvalid, ""},
		{"tenant field", &tenantadmin.InvalidError{Field: tenantadmin.FieldName, Reason: "x"}, problem.CodeValidationFailed, "/name invalid-format"},
		{"admin email", &adminauth.InvalidError{Field: adminauth.FieldEmail}, problem.CodeValidationFailed, "/delegatedAdmin/email invalid-email"},
		{"admin username", &adminauth.InvalidError{Field: "/username"}, problem.CodeValidationFailed, "/delegatedAdmin/username invalid-format"},
		{"admin delivery", &adminauth.NotAllowedError{Field: adminauth.FieldDelivery}, problem.CodeValidationFailed, "/delegatedAdmin/delivery not-allowed"},
		{"taken", tenantadmin.ErrAlreadyExists, problem.CodeAlreadyExists, ""},
		{"preset", tenantadmin.ErrUnknownBackgroundPreset, problem.CodeUnknownBackgroundPreset, ""},
		{"no system smtp", adminauth.ErrSystemSMTPUnavailable, problem.CodeSystemSMTPUnavailable, ""},
	} {
		_, err := provServer(&fakeProvisioning{err: tc.err}).ProvisionTenant(ctx, gen.ProvisionTenantRequestObject{Body: body})
		p := expectProblem(t, err, tc.code)
		if tc.field != "" {
			expectField(t, p, tc.field)
		}
		if tc.code == problem.CodeRateLimited && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 90) {
			t.Errorf("%s: retry %v", tc.name, p.RetryAfterSeconds)
		}
		if tc.code == problem.CodeProvisioningScopeExceeded && p.Status != http.StatusForbidden {
			t.Errorf("%s: status %d", tc.name, p.Status)
		}
	}
	internal := errors.New("database is locked")
	_, err := provServer(&fakeProvisioning{err: internal}).ProvisionTenant(ctx, gen.ProvisionTenantRequestObject{Body: body})
	if !errors.Is(err, internal) {
		t.Errorf("internal error %v", err)
	}
}

// TestCaptureRawBodyProvisioning checks that the raw body of the two
// provisioning creations is kept, and of nothing else.
func TestCaptureRawBodyProvisioning(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/api/v1/admin/provisioning-tokens", true},
		{http.MethodPost, "/api/v1/provisioning/tenants", true},
		{http.MethodGet, "/api/v1/provisioning/tenants", false},
		{http.MethodDelete, "/api/v1/admin/provisioning-tokens/{tokenId}", false},
		{http.MethodPost, "/api/v1/admin/tenants", false},
		// Exact full paths only, never a suffix.
		{http.MethodPost, "/api/v2/provisioning/tenants", false},
		{http.MethodPost, "/api/v1/x/admin/provisioning-tokens", false},
	} {
		var got []byte
		var ok bool
		r := httptest.NewRequest(tc.method, "/", strings.NewReader(`{"a":1}`))
		r.Pattern = tc.method + " " + tc.path
		CaptureRawBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got, ok = r.Context().Value(rawBodyKey{}).([]byte)
		})).ServeHTTP(httptest.NewRecorder(), r)
		if ok != tc.want || (ok && string(got) != `{"a":1}`) {
			t.Errorf("%s %s: captured %q %v", tc.method, tc.path, got, ok)
		}
	}
}

func FuzzProvisioningBodies(f *testing.F) {
	for _, seed := range []string{tokenCreateJSON, provisionTenantJSON, `{}`, `null`, `{"delegatedAdmin":{"a":null}}`, `{"code":null}`, `[`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, err := range []error{checkTokenCreateMembers([]byte(raw)), checkProvisionTenantMembers([]byte(raw))} {
			if err == nil {
				continue
			}
			var p *problem.Problem
			if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) != 1 {
				t.Fatalf("%q: %v", raw, err)
			}
		}
	})
}
