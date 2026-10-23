package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/apitoken"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// sampleToken is a token as the store returns it.
var sampleToken = store.APIToken{
	ID: "tok_01", Name: "Nightly ERP export", Prefix: "tt_9fK2", TokenHash: []byte("hash-never-rendered"),
	AllowedCIDRs:   []netip.Prefix{netip.MustParsePrefix("10.10.20.15/32"), netip.MustParsePrefix("2001:db8::/32")},
	AllowedSenders: []string{"erp.entity-a.example.com"},
	CreatedBy:      "admin.entity-a", CreatedAt: now.Add(-time.Hour),
}

// fakeTokens is a fake APITokenService.
type fakeTokens struct {
	recorder
	list   []store.APIToken
	token  store.APIToken
	secret string
}

func (f *fakeTokens) List(_ context.Context, p adminauth.Principal, tid tenant.ID) ([]store.APIToken, error) {
	return f.list, f.record("List", p.SessionID, tid)
}

func (f *fakeTokens) Create(_ context.Context, p adminauth.Principal, tid tenant.ID, in apitoken.CreateInput, ip netip.Addr) (apitoken.Created, error) {
	return apitoken.Created{Token: f.token, Secret: f.secret}, f.record("Create", p.SessionID, tid, in, ip)
}

func (f *fakeTokens) Update(_ context.Context, p adminauth.Principal, tid tenant.ID, tokID string, in apitoken.UpdateInput, ip netip.Addr) (store.APIToken, error) {
	return f.token, f.record("Update", p.SessionID, tid, tokID, in, ip)
}

func (f *fakeTokens) Revoke(_ context.Context, p adminauth.Principal, tid tenant.ID, tokID string, ip netip.Addr) error {
	return f.record("Revoke", p.SessionID, tid, tokID, ip)
}

// tokenServer returns a server over svc.
func tokenServer(svc APITokenService) *Server {
	s := NewServer(WithAPITokenService(svc))
	s.now = func() time.Time { return now }
	return s
}

// tokenPatch returns a raw token merge patch.
func tokenPatch(s string) *gen.ApiTokenUpdate {
	b := gen.ApiTokenUpdate(s)
	return &b
}

// tokenCalls calls every token operation of s with a minimal valid request
// and returns the errors, by service method.
func tokenCalls(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	var err error
	_, err = s.ListApiTokens(ctx, gen.ListApiTokensRequestObject{TenantId: "ten_a"})
	out["List"] = err
	_, err = s.CreateApiToken(ctx, gen.CreateApiTokenRequestObject{TenantId: "ten_a", Body: &gen.ApiTokenCreate{Name: "n", AllowedCidrs: []string{"0.0.0.0/0"}}})
	out["Create"] = err
	_, err = s.UpdateApiToken(ctx, gen.UpdateApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01", Body: tokenPatch(`{"name":"n"}`)})
	out["Update"] = err
	_, err = s.RevokeApiToken(ctx, gen.RevokeApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01"})
	out["Revoke"] = err
	return out
}

func TestAPITokenWiring(t *testing.T) {
	t.Parallel()
	// Without service: 500 (wiring error), whatever the session.
	calls := tokenCalls(ctxWith(store.SessionAuthenticated, superRoot), NewServer())
	if len(calls) != 4 {
		t.Fatalf("%d operations, want 4", len(calls))
	}
	for name, err := range calls {
		if !errors.Is(err, errNoAPITokenService) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	// Without session in the context: 401 before the service.
	f := &fakeTokens{token: sampleToken}
	for name, err := range tokenCalls(ctxWith("", superRoot), tokenServer(f)) {
		if p := expectProblem(t, err, problem.CodeUnauthenticated); p.Code == "" {
			t.Error(name)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("service called without session: %v", f.calls)
	}
	// Every operation reaches the service with the session, the tenant and
	// the client IP; a service error is mapped.
	f = &fakeTokens{token: sampleToken, recorder: recorder{err: apitoken.ErrNotFound}}
	for name, err := range tokenCalls(ctxWith(store.SessionAuthenticated, delegated), tokenServer(f)) {
		expectProblem(t, err, problem.CodeNotFound)
		args := f.args[name]
		if len(args) < 2 || args[0] != "as_01" || args[1] != tenant.ID("ten_a") {
			t.Errorf("%s: service args %v", name, args)
		}
		if name != "List" && args[len(args)-1] != clientIP {
			t.Errorf("%s: client IP %v", name, args[len(args)-1])
		}
	}
}

func TestTokenErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		err   error
		code  problem.Code
		field string
	}{
		{&apitoken.InvalidError{Field: apitoken.FieldName, Reason: "too long"}, problem.CodeValidationFailed, "/name"},
		{fmt.Errorf("wrap: %w", &apitoken.InvalidError{Field: apitoken.FieldAllowedCIDRs + "/1"}), problem.CodeValidationFailed, "/allowedCidrs/1"},
		{apitoken.ErrInvalidInput, problem.CodeValidationFailed, ""},
		{apitoken.ErrStateConflict, problem.CodeStateConflict, ""},
		{apitoken.ErrUnauthenticated, problem.CodeUnauthenticated, ""},
		{apitoken.ErrForbidden, problem.CodeForbidden, ""},
		{apitoken.ErrNotFound, problem.CodeNotFound, ""},
	}
	for _, tt := range tests {
		p := expectProblem(t, tokenError(tt.err), tt.code)
		switch {
		case tt.field != "":
			if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: tt.field, Code: fieldInvalidFormat}}) {
				t.Errorf("%v: field errors %+v", tt.err, p.Errors)
			}
		case len(p.Errors) != 0:
			t.Errorf("%v: unexpected field errors %+v", tt.err, p.Errors)
		}
	}
	if err := tokenError(boom); !errors.Is(err, boom) {
		t.Errorf("internal error: %v", err)
	}
	if p := problem.From(tokenError(apitoken.ErrStateConflict)); p.Status != http.StatusConflict {
		t.Errorf("state-conflict status %d", p.Status)
	}
}

func TestListAPITokens(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	used, revoked := sampleToken, sampleToken
	used.ID, used.LastUsedAt, used.ExpiresAt = "tok_02", now.Add(-time.Minute), now.Add(24*time.Hour)
	used.AllowedSenders = nil
	revoked.ID, revoked.RevokedAt = "tok_03", now
	f := &fakeTokens{list: []store.APIToken{sampleToken, used, revoked}}
	resp, err := tokenServer(f).ListApiTokens(ctx, gen.ListApiTokensRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "hash") || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	items := resp.(gen.ListApiTokens200JSONResponse)
	if len(items) != 3 {
		t.Fatalf("%d items", len(items))
	}
	first := items[0]
	if first.Id != "tok_01" || first.Name != "Nightly ERP export" || first.Prefix != "tt_9fK2" || first.CreatedBy != "admin.entity-a" ||
		!first.CreatedAt.Equal(sampleToken.CreatedAt) || !reflect.DeepEqual(first.AllowedCidrs, []string{"10.10.20.15/32", "2001:db8::/32"}) ||
		first.LastUsedAt != nil || first.ExpiresAt != nil || first.RevokedAt != nil ||
		!reflect.DeepEqual(first.AllowedSenders, []string{"erp.entity-a.example.com"}) {
		t.Errorf("first = %+v", first)
	}
	// A token without senders renders an empty array, never null.
	if it := items[1]; it.AllowedSenders == nil || len(it.AllowedSenders) != 0 {
		t.Errorf("used.AllowedSenders = %#v", it.AllowedSenders)
	}
	if !strings.Contains(rec.Body.String(), `"allowedSenders":[]`) {
		t.Errorf("list body = %s", rec.Body)
	}
	if it := items[1]; it.LastUsedAt == nil || !it.LastUsedAt.Equal(used.LastUsedAt) || it.ExpiresAt == nil || !it.ExpiresAt.Equal(used.ExpiresAt) {
		t.Errorf("used = %+v", it)
	}
	if it := items[2]; it.RevokedAt == nil || !it.RevokedAt.Equal(now) {
		t.Errorf("revoked = %+v", it)
	}

	// No token: an empty array, never null.
	f.list = nil
	resp, err = tokenServer(f).ListApiTokens(ctx, gen.ListApiTokensRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, resp); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("empty list = %s", rec.Body)
	}
}

func TestCreateAPIToken(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	secret := "tt_" + strings.Repeat("x", 43) // not a real token
	tok := sampleToken
	tok.ExpiresAt = now.Add(30 * 24 * time.Hour)
	f := &fakeTokens{token: tok, secret: secret}
	s := tokenServer(f)
	expires := tok.ExpiresAt
	senders := gen.AllowedSenders{"reporting@entity-a.example.com"}
	resp, err := s.CreateApiToken(ctx, gen.CreateApiTokenRequestObject{TenantId: "ten_a", Body: &gen.ApiTokenCreate{
		Name: "Nightly ERP export", AllowedCidrs: []string{"10.10.20.15/32", "2001:db8::/32"}, ExpiresAt: &expires,
		AllowedSenders: &senders,
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := apitoken.CreateInput{
		Name: "Nightly ERP export", AllowedCIDRs: []string{"10.10.20.15/32", "2001:db8::/32"}, ExpiresAt: expires,
		AllowedSenders: []string{"reporting@entity-a.example.com"},
	}
	if got := f.args["Create"]; !reflect.DeepEqual(got[2], want) || got[3] != clientIP {
		t.Errorf("create args %v", got)
	}
	code, body := decode(t, resp)
	if code != http.StatusCreated || body["token"] != secret || body["id"] != "tok_01" || body["prefix"] != "tt_9fK2" ||
		body["createdBy"] != "admin.entity-a" || body["expiresAt"] != tok.ExpiresAt.Format(time.RFC3339) {
		t.Errorf("create = %d %v", code, body)
	}
	if cidrs, ok := body["allowedCidrs"].([]any); !ok || len(cidrs) != 2 || cidrs[1] != "2001:db8::/32" {
		t.Errorf("allowedCidrs = %v", body["allowedCidrs"])
	}
	if got, ok := body["allowedSenders"].([]any); !ok || len(got) != 1 || got[0] != "erp.entity-a.example.com" {
		t.Errorf("allowedSenders = %v", body["allowedSenders"])
	}
	for _, absent := range []string{"lastUsedAt", "revokedAt", "tokenHash"} {
		if _, ok := body[absent]; ok {
			t.Errorf("%s present: %v", absent, body)
		}
	}

	// A missing body reaches the service, which checks the access first,
	// with an empty input.
	f.err = &apitoken.InvalidError{Field: apitoken.FieldName}
	_, err = s.CreateApiToken(ctx, gen.CreateApiTokenRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/name", Code: fieldInvalidFormat}}) {
		t.Errorf("errors %+v", p.Errors)
	}
	if got := f.args["Create"]; !reflect.DeepEqual(got[2], apitoken.CreateInput{}) {
		t.Errorf("create args without body %v", got)
	}
	f.err = apitoken.ErrNotFound
	_, err = s.CreateApiToken(ctx, gen.CreateApiTokenRequestObject{TenantId: "ten_b"})
	expectProblem(t, err, problem.CodeNotFound)
}

func TestUpdateAPIToken(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeTokens{token: sampleToken}
	s := tokenServer(f)
	cases := []struct {
		body string
		want apitoken.UpdateInput
	}{
		{`{"name":"Renamed"}`, apitoken.UpdateInput{Name: ptr("Renamed")}},
		{`{"allowedCidrs":["10.0.0.0/8"]}`, apitoken.UpdateInput{AllowedCIDRs: []string{"10.0.0.0/8"}}},
		{`{"allowedCidrs":[]}`, apitoken.UpdateInput{AllowedCIDRs: []string{}}},
		{`{"allowedSenders":["ops@entity-a.example.com"]}`, apitoken.UpdateInput{AllowedSenders: []string{"ops@entity-a.example.com"}}},
		{`{"allowedSenders":[]}`, apitoken.UpdateInput{AllowedSenders: []string{}}},
		{`{"name":"x","allowedCidrs":["::/0"]}`, apitoken.UpdateInput{Name: ptr("x"), AllowedCIDRs: []string{"::/0"}}},
		{`{}`, apitoken.UpdateInput{}},
	}
	for _, c := range cases {
		resp, err := s.UpdateApiToken(ctx, gen.UpdateApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01", Body: tokenPatch(c.body)})
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		got := f.args["Update"]
		if got[2] != "tok_01" || got[4] != clientIP || !reflect.DeepEqual(got[3], c.want) {
			t.Errorf("%s: update args %v", c.body, got)
		}
		if in := got[3].(apitoken.UpdateInput); (in.AllowedCIDRs == nil) != (c.want.AllowedCIDRs == nil) ||
			(in.AllowedSenders == nil) != (c.want.AllowedSenders == nil) {
			t.Errorf("%s: list nil-ness %#v %#v", c.body, in.AllowedCIDRs, in.AllowedSenders)
		}
		code, body := decode(t, resp)
		if code != http.StatusOK || body["id"] != "tok_01" {
			t.Errorf("%s: update = %d %v", c.body, code, body)
		}
		if _, ok := body["token"]; ok {
			t.Errorf("%s: secret rendered", c.body)
		}
	}

	// A revoked token: 409.
	f.err = apitoken.ErrStateConflict
	_, err := s.UpdateApiToken(ctx, gen.UpdateApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01", Body: tokenPatch(`{"name":"x"}`)})
	expectProblem(t, err, problem.CodeStateConflict)
}

func TestUpdateAPITokenPatchErrors(t *testing.T) {
	t.Parallel()
	f := &fakeTokens{token: sampleToken}
	s := tokenServer(f)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	cases := []struct {
		name string
		body *gen.ApiTokenUpdate
		want []problem.FieldError
	}{
		{"no body", nil, []problem.FieldError{{Field: "", Code: fieldRequired}}},
		{"not an object", tokenPatch(`[1]`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"null body", tokenPatch(`null`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"malformed", tokenPatch(`{`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"null name", tokenPatch(`{"name": null }`), []problem.FieldError{{Field: "/name", Code: fieldNotNullable}}},
		{
			"null both", tokenPatch(`{"allowedCidrs":null,"name":null}`),
			[]problem.FieldError{{Field: "/name", Code: fieldNotNullable}, {Field: "/allowedCidrs", Code: fieldNotNullable}},
		},
		{"wrong type name", tokenPatch(`{"name":5}`), []problem.FieldError{{Field: "/name", Code: fieldInvalidFormat}}},
		{"wrong type ranges", tokenPatch(`{"allowedCidrs":"10.0.0.0/8"}`), []problem.FieldError{{Field: "/allowedCidrs", Code: fieldInvalidFormat}}},
		{"null senders", tokenPatch(`{"allowedSenders":null}`), []problem.FieldError{{Field: "/allowedSenders", Code: fieldNotNullable}}},
		{"wrong type sender", tokenPatch(`{"allowedSenders":["a",1]}`), []problem.FieldError{{Field: "/allowedSenders/1", Code: fieldInvalidFormat}}},
		{
			"unknown member", tokenPatch(`{"name":"x","zeta":1,"unknown":null}`),
			[]problem.FieldError{{Field: "/unknown", Code: fieldInvalidFormat}},
		},
		{"escaped member", tokenPatch(`{"a/b~c":1}`), []problem.FieldError{{Field: "/a~1b~0c", Code: fieldInvalidFormat}}},
		{
			"long member", tokenPatch(`{"` + strings.Repeat("m", maxEchoedMemberLen+1) + `":1}`),
			[]problem.FieldError{{Field: "", Code: fieldInvalidFormat}},
		},
	}
	for _, c := range cases {
		_, err := s.UpdateApiToken(ctx, gen.UpdateApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01", Body: c.body})
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if !reflect.DeepEqual(p.Errors, c.want) {
			t.Errorf("%s: errors %+v, want %+v", c.name, p.Errors, c.want)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("service called on a malformed patch: %v", f.calls)
	}
}

func TestRevokeAPIToken(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeTokens{}
	s := tokenServer(f)
	resp, err := s.RevokeApiToken(ctx, gen.RevokeApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, resp); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("revoke = %d %q", rec.Code, rec.Body)
	}
	if got := f.args["Revoke"]; got[2] != "tok_01" || got[3] != clientIP {
		t.Errorf("revoke args %v", got)
	}
	f.err = apitoken.ErrForbidden
	_, err = s.RevokeApiToken(ctx, gen.RevokeApiTokenRequestObject{TenantId: "ten_a", TokenId: "tok_01"})
	expectProblem(t, err, problem.CodeForbidden)
}
