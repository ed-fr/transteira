package admin

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhook"
	"github.com/ed-fr/transteira/internal/webhookadmin"
)

// sampleWebhook is a webhook as the service returns it.
var sampleWebhook = store.Webhook{
	ID: "whk_01", Name: "Security team channel", Kind: store.WebhookTeams, URLKeyID: "wk_never_rendered",
	URLHint: "https://entity-a.webhook.example.com", Events: []events.Type{events.VirusDetected, events.AbuseReported},
	Enabled: true, CreatedBy: "admin.entity-a", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute),
}

// fakeWebhooks is a fake WebhookService.
type fakeWebhooks struct {
	recorder
	list   []store.Webhook
	hook   store.Webhook
	secret string
	result webhook.Result
}

func (f *fakeWebhooks) ListTenant(_ context.Context, p adminauth.Principal, tid tenant.ID) ([]store.Webhook, error) {
	return f.list, f.record("ListTenant", p.SessionID, tid)
}

func (f *fakeWebhooks) GetTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, whkID string) (store.Webhook, error) {
	return f.hook, f.record("GetTenant", p.SessionID, tid, whkID)
}

func (f *fakeWebhooks) CreateTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, in webhookadmin.CreateInput, ip netip.Addr) (webhookadmin.Result, error) {
	return webhookadmin.Result{Webhook: f.hook, Secret: f.secret}, f.record("CreateTenant", p.SessionID, tid, in, ip)
}

func (f *fakeWebhooks) UpdateTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, whkID string, in webhookadmin.UpdateInput, ip netip.Addr) (webhookadmin.Result, error) {
	return webhookadmin.Result{Webhook: f.hook, Secret: f.secret}, f.record("UpdateTenant", p.SessionID, tid, whkID, in, ip)
}

func (f *fakeWebhooks) DeleteTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, whkID string, ip netip.Addr) error {
	return f.record("DeleteTenant", p.SessionID, tid, whkID, ip)
}

func (f *fakeWebhooks) TestTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, whkID string, ip netip.Addr) (webhook.Result, error) {
	return f.result, f.record("TestTenant", p.SessionID, tid, whkID, ip)
}

func (f *fakeWebhooks) ListSystem(_ context.Context, p adminauth.Principal) ([]store.Webhook, error) {
	return f.list, f.record("ListSystem", p.SessionID)
}

func (f *fakeWebhooks) GetSystem(_ context.Context, p adminauth.Principal, whkID string) (store.Webhook, error) {
	return f.hook, f.record("GetSystem", p.SessionID, whkID)
}

func (f *fakeWebhooks) CreateSystem(_ context.Context, p adminauth.Principal, in webhookadmin.CreateInput, ip netip.Addr) (webhookadmin.Result, error) {
	return webhookadmin.Result{Webhook: f.hook, Secret: f.secret}, f.record("CreateSystem", p.SessionID, in, ip)
}

func (f *fakeWebhooks) UpdateSystem(_ context.Context, p adminauth.Principal, whkID string, in webhookadmin.UpdateInput, ip netip.Addr) (webhookadmin.Result, error) {
	return webhookadmin.Result{Webhook: f.hook, Secret: f.secret}, f.record("UpdateSystem", p.SessionID, whkID, in, ip)
}

func (f *fakeWebhooks) DeleteSystem(_ context.Context, p adminauth.Principal, whkID string, ip netip.Addr) error {
	return f.record("DeleteSystem", p.SessionID, whkID, ip)
}

func (f *fakeWebhooks) TestSystem(_ context.Context, p adminauth.Principal, whkID string, ip netip.Addr) (webhook.Result, error) {
	return f.result, f.record("TestSystem", p.SessionID, whkID, ip)
}

// webhookServer returns a server over svc.
func webhookServer(svc WebhookService) *Server {
	s := NewServer(WithWebhookService(svc))
	s.now = func() time.Time { return now }
	return s
}

// webhookPatchBody returns a raw webhook merge patch.
func webhookPatchBody(s string) *gen.WebhookUpdate {
	b := gen.WebhookUpdate(s)
	return &b
}

// webhookCalls calls every webhook operation of s with a minimal valid
// request and returns the errors, by service method.
func webhookCalls(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	body := &gen.WebhookCreate{Name: "n", Kind: gen.WebhookKind("teams"), Url: "https://h.example.com", Events: []gen.WebhookEventType{"virus.detected"}}
	var err error
	_, err = s.ListTenantWebhooks(ctx, gen.ListTenantWebhooksRequestObject{TenantId: "ten_a"})
	out["ListTenant"] = err
	_, err = s.GetTenantWebhook(ctx, gen.GetTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	out["GetTenant"] = err
	_, err = s.CreateTenantWebhook(ctx, gen.CreateTenantWebhookRequestObject{TenantId: "ten_a", Body: body})
	out["CreateTenant"] = err
	_, err = s.UpdateTenantWebhook(ctx, gen.UpdateTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01", Body: webhookPatchBody(`{}`)})
	out["UpdateTenant"] = err
	_, err = s.DeleteTenantWebhook(ctx, gen.DeleteTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	out["DeleteTenant"] = err
	_, err = s.TestTenantWebhook(ctx, gen.TestTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	out["TestTenant"] = err
	_, err = s.ListSystemWebhooks(ctx, gen.ListSystemWebhooksRequestObject{})
	out["ListSystem"] = err
	_, err = s.GetSystemWebhook(ctx, gen.GetSystemWebhookRequestObject{WebhookId: "whk_01"})
	out["GetSystem"] = err
	_, err = s.CreateSystemWebhook(ctx, gen.CreateSystemWebhookRequestObject{Body: body})
	out["CreateSystem"] = err
	_, err = s.UpdateSystemWebhook(ctx, gen.UpdateSystemWebhookRequestObject{WebhookId: "whk_01", Body: webhookPatchBody(`{}`)})
	out["UpdateSystem"] = err
	_, err = s.DeleteSystemWebhook(ctx, gen.DeleteSystemWebhookRequestObject{WebhookId: "whk_01"})
	out["DeleteSystem"] = err
	_, err = s.TestSystemWebhook(ctx, gen.TestSystemWebhookRequestObject{WebhookId: "whk_01"})
	out["TestSystem"] = err
	return out
}

func TestWebhookWiring(t *testing.T) {
	t.Parallel()
	calls := webhookCalls(ctxWith(store.SessionAuthenticated, superRoot), NewServer())
	if len(calls) != 12 {
		t.Fatalf("%d operations, want 12", len(calls))
	}
	for name, err := range calls {
		if !errors.Is(err, errNoWebhookService) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	// Without session: 401 before the service.
	f := &fakeWebhooks{hook: sampleWebhook}
	for name, err := range webhookCalls(ctxWith("", superRoot), webhookServer(f)) {
		if p := expectProblem(t, err, problem.CodeUnauthenticated); p.Code == "" {
			t.Error(name)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("service called without session: %v", f.calls)
	}
	// Every operation reaches the service with the session, the tenant
	// and the client IP; a service error is mapped.
	f = &fakeWebhooks{hook: sampleWebhook, recorder: recorder{err: webhookadmin.ErrNotFound}}
	for name, err := range webhookCalls(ctxWith(store.SessionAuthenticated, superRoot), webhookServer(f)) {
		expectProblem(t, err, problem.CodeNotFound)
		args := f.args[name]
		if len(args) < 1 || args[0] != "as_01" {
			t.Errorf("%s: service args %v", name, args)
		}
		if strings.HasSuffix(name, "Tenant") && args[1] != tenant.ID("ten_a") {
			t.Errorf("%s: tenant %v", name, args[1])
		}
		if !strings.HasPrefix(name, "List") && !strings.HasPrefix(name, "Get") && args[len(args)-1] != clientIP {
			t.Errorf("%s: client IP %v", name, args[len(args)-1])
		}
	}
	if len(f.calls) != 12 {
		t.Errorf("service calls %v", f.calls)
	}
}

func TestWebhookErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		err   error
		code  problem.Code
		field problem.FieldError
	}{
		{&webhookadmin.InvalidError{Field: "/url", Code: "url-not-allowed"}, problem.CodeValidationFailed, problem.FieldError{Field: "/url", Code: "url-not-allowed"}},
		{&webhookadmin.InvalidError{Field: "/events/1", Code: "invalid-format"}, problem.CodeValidationFailed, problem.FieldError{Field: "/events/1", Code: "invalid-format"}},
		{webhookadmin.ErrLimitReached, problem.CodeStateConflict, problem.FieldError{}},
		{webhookadmin.ErrConflict, problem.CodeStateConflict, problem.FieldError{}},
		{webhookadmin.ErrUnauthenticated, problem.CodeUnauthenticated, problem.FieldError{}},
		{webhookadmin.ErrForbidden, problem.CodeForbidden, problem.FieldError{}},
		{webhookadmin.ErrNotFound, problem.CodeNotFound, problem.FieldError{}},
	}
	for _, tt := range tests {
		p := expectProblem(t, webhookError(tt.err), tt.code)
		switch {
		case tt.field.Field != "":
			if !reflect.DeepEqual(p.Errors, []problem.FieldError{tt.field}) {
				t.Errorf("%v: field errors %+v", tt.err, p.Errors)
			}
		case len(p.Errors) != 0:
			t.Errorf("%v: unexpected field errors %+v", tt.err, p.Errors)
		}
	}
	p := expectProblem(t, webhookError(&webhookadmin.RateLimitError{RetryAfter: 90 * time.Second}), problem.CodeRateLimited)
	if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 90 {
		t.Errorf("Retry-After %v", p.RetryAfterSeconds)
	}
	if err := webhookError(boom); !errors.Is(err, boom) {
		t.Errorf("internal error: %v", err)
	}
	if webhookError(nil) != nil {
		t.Error("webhookError(nil) != nil")
	}
}

func TestListWebhooks(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	failed := sampleWebhook
	failed.ID, failed.Kind, failed.SecretKeyID = "whk_02", store.WebhookGeneric, "wk_secret"
	failed.LastDelivery = store.WebhookDelivery{At: now.Add(-time.Minute), HTTPStatus: 502, Duration: 10003 * time.Millisecond, ErrorCategory: "http_status"}
	failed.CircuitOpenUntil = now.Add(time.Minute)
	ok := sampleWebhook
	ok.ID, ok.Events = "whk_03", []events.Type{}
	ok.LastDelivery = store.WebhookDelivery{At: now.Add(-time.Hour), Success: true, HTTPStatus: 200, Duration: 182 * time.Millisecond}
	ok.CircuitOpenUntil = now // passed: deliveries are allowed again
	f := &fakeWebhooks{list: []store.Webhook{sampleWebhook, failed, ok}}
	resp, err := webhookServer(f).ListTenantWebhooks(ctx, gen.ListTenantWebhooksRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, resp)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "wk_") || strings.Contains(body, `"secret"`) || strings.Contains(body, `"url"`) {
		t.Fatalf("list = %d %s", rec.Code, body)
	}
	items := resp.(gen.ListTenantWebhooks200JSONResponse)
	first := items[0]
	if first.Id != "whk_01" || first.Name != sampleWebhook.Name || first.Kind != "teams" || first.UrlHint != sampleWebhook.URLHint ||
		!reflect.DeepEqual(first.Events, []gen.WebhookEventType{"virus.detected", "abuse.reported"}) || !first.Enabled ||
		first.HasSecret || first.CreatedBy != "admin.entity-a" || !first.CreatedAt.Equal(sampleWebhook.CreatedAt) ||
		!first.UpdatedAt.Equal(sampleWebhook.UpdatedAt) || first.LastDelivery != nil || first.CircuitOpenUntil != nil {
		t.Errorf("first = %+v", first)
	}
	if !strings.Contains(body, `"lastDelivery":null`) || !strings.Contains(body, `"circuitOpenUntil":null`) {
		t.Errorf("null members missing: %s", body)
	}
	second := items[1]
	if d := second.LastDelivery; !second.HasSecret || d == nil || d.Success || d.DurationMs != 10003 || d.HttpStatus == nil ||
		*d.HttpStatus != 502 || d.ErrorCategory == nil || *d.ErrorCategory != "http_status" ||
		second.CircuitOpenUntil == nil || !second.CircuitOpenUntil.Equal(failed.CircuitOpenUntil) {
		t.Errorf("second = %+v", second)
	}
	third := items[2]
	if d := third.LastDelivery; d == nil || !d.Success || d.ErrorCategory != nil || third.CircuitOpenUntil != nil ||
		third.Events == nil {
		t.Errorf("third = %+v", third)
	}
	// No webhook: an empty array.
	f.list = nil
	sresp, _ := webhookServer(f).ListSystemWebhooks(ctxWith(store.SessionAuthenticated, superRoot), gen.ListSystemWebhooksRequestObject{})
	if rec := visit(t, sresp); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("empty list = %s", rec.Body)
	}
}

func TestCreateWebhook(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	gen1 := sampleWebhook
	gen1.Kind, gen1.SecretKeyID = store.WebhookGeneric, "wk_secret"
	secret := strings.Repeat("ab", 32)
	f := &fakeWebhooks{hook: gen1, secret: secret}
	s := webhookServer(f)
	enabled := false
	resp, err := s.CreateTenantWebhook(ctx, gen.CreateTenantWebhookRequestObject{TenantId: "ten_a", Body: &gen.WebhookCreate{
		Name: "SIEM", Kind: "generic", Url: "https://siem.example.com/hooks", Events: []gen.WebhookEventType{"virus.detected", "quota.reached"},
		Enabled: &enabled,
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := webhookadmin.CreateInput{
		Name: "SIEM", Kind: store.WebhookGeneric, URL: "https://siem.example.com/hooks",
		Events: []events.Type{events.VirusDetected, events.QuotaReached}, Enabled: &enabled,
	}
	if got := f.args["CreateTenant"]; !reflect.DeepEqual(got[2], want) || got[3] != clientIP {
		t.Errorf("create args %v", got)
	}
	code, body := decode(t, resp)
	if code != http.StatusCreated || body["secret"] != secret || body["hasSecret"] != true || body["id"] != "whk_01" {
		t.Errorf("create = %d %v", code, body)
	}
	// A teams webhook has no secret member; a missing body reaches the
	// service, which checks the access first, with an empty input.
	f.secret = ""
	sresp, err := s.CreateSystemWebhook(ctxWith(store.SessionAuthenticated, superRoot), gen.CreateSystemWebhookRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.args["CreateSystem"]; !reflect.DeepEqual(got[1], webhookadmin.CreateInput{}) {
		t.Errorf("create args without body %v", got)
	}
	if _, body := decode(t, sresp); body["secret"] != nil {
		t.Errorf("secret rendered: %v", body)
	}
	f.err = &webhookadmin.InvalidError{Field: "/url", Code: "url-not-allowed"}
	_, err = s.CreateTenantWebhook(ctx, gen.CreateTenantWebhookRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/url", Code: "url-not-allowed"}}) {
		t.Errorf("errors %+v", p.Errors)
	}
	f.err = webhookadmin.ErrLimitReached
	_, err = s.CreateSystemWebhook(ctxWith(store.SessionAuthenticated, superRoot), gen.CreateSystemWebhookRequestObject{})
	expectProblem(t, err, problem.CodeStateConflict)
}

func TestGetWebhook(t *testing.T) {
	t.Parallel()
	f := &fakeWebhooks{hook: sampleWebhook}
	s := webhookServer(f)
	resp, err := s.GetTenantWebhook(ctxWith(store.SessionAuthenticated, delegated), gen.GetTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := decode(t, resp); code != http.StatusOK || body["id"] != "whk_01" {
		t.Errorf("get = %d %v", code, body)
	}
	sresp, err := s.GetSystemWebhook(ctxWith(store.SessionAuthenticated, superRoot), gen.GetSystemWebhookRequestObject{WebhookId: "whk_01"})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := decode(t, sresp); code != http.StatusOK || body["urlHint"] != sampleWebhook.URLHint {
		t.Errorf("get system = %d %v", code, body)
	}
	if got := f.args["GetSystem"]; got[1] != "whk_01" {
		t.Errorf("get system args %v", got)
	}
}

func TestUpdateWebhook(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeWebhooks{hook: sampleWebhook}
	s := webhookServer(f)
	cases := []struct {
		body string
		want webhookadmin.UpdateInput
	}{
		{`{"name":"Renamed"}`, webhookadmin.UpdateInput{Name: ptr("Renamed")}},
		{`{"url":"https://new.example.com/x"}`, webhookadmin.UpdateInput{URL: ptr("https://new.example.com/x")}},
		{`{"events":["quota.warning"]}`, webhookadmin.UpdateInput{Events: []events.Type{events.QuotaWarning}}},
		{`{"events":[]}`, webhookadmin.UpdateInput{Events: []events.Type{}}},
		{`{"enabled":false,"rotateSecret":true}`, webhookadmin.UpdateInput{Enabled: ptr(false), RotateSecret: true}},
		{`{"rotateSecret":false}`, webhookadmin.UpdateInput{}},
		{`{}`, webhookadmin.UpdateInput{}},
	}
	for _, c := range cases {
		resp, err := s.UpdateTenantWebhook(ctx, gen.UpdateTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01", Body: webhookPatchBody(c.body)})
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		got := f.args["UpdateTenant"]
		if got[2] != "whk_01" || got[4] != clientIP || !reflect.DeepEqual(got[3], c.want) {
			t.Errorf("%s: update args %v", c.body, got)
		}
		if in := got[3].(webhookadmin.UpdateInput); (in.Events == nil) != (c.want.Events == nil) {
			t.Errorf("%s: events nil-ness %#v", c.body, in.Events)
		}
		if code, body := decode(t, resp); code != http.StatusOK || body["id"] != "whk_01" || body["secret"] != nil {
			t.Errorf("%s: update = %d %v", c.body, code, body)
		}
	}
	// A rotation returns the new secret.
	f.secret = strings.Repeat("cd", 32)
	resp, err := s.UpdateSystemWebhook(ctxWith(store.SessionAuthenticated, superRoot), gen.UpdateSystemWebhookRequestObject{WebhookId: "whk_01", Body: webhookPatchBody(`{"rotateSecret":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, body := decode(t, resp); body["secret"] != f.secret {
		t.Errorf("rotation = %v", body)
	}
	if got := f.args["UpdateSystem"]; got[1] != "whk_01" || !reflect.DeepEqual(got[2], webhookadmin.UpdateInput{RotateSecret: true}) {
		t.Errorf("update system args %v", got)
	}
}

func TestUpdateWebhookPatchErrors(t *testing.T) {
	t.Parallel()
	f := &fakeWebhooks{hook: sampleWebhook}
	s := webhookServer(f)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	cases := []struct {
		name string
		body *gen.WebhookUpdate
		want []problem.FieldError
	}{
		{"no body", nil, []problem.FieldError{{Field: "", Code: fieldRequired}}},
		{"not an object", webhookPatchBody(`[1]`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"null body", webhookPatchBody(`null`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{
			"null members", webhookPatchBody(`{"rotateSecret":null,"url":null,"name":null,"events":null,"enabled":null}`),
			[]problem.FieldError{
				{Field: "/name", Code: fieldNotNullable},
				{Field: "/url", Code: fieldNotNullable},
				{Field: "/events", Code: fieldNotNullable},
				{Field: "/enabled", Code: fieldNotNullable},
				{Field: "/rotateSecret", Code: fieldNotNullable},
			},
		},
		{"wrong type enabled", webhookPatchBody(`{"enabled":"yes"}`), []problem.FieldError{{Field: "/enabled", Code: fieldInvalidFormat}}},
		{"wrong type event", webhookPatchBody(`{"events":["virus.detected",2]}`), []problem.FieldError{{Field: "/events/1", Code: fieldInvalidFormat}}},
		{"unknown member", webhookPatchBody(`{"kind":"slack"}`), []problem.FieldError{{Field: "/kind", Code: fieldInvalidFormat}}},
		{"unknown secret", webhookPatchBody(`{"secret":"x"}`), []problem.FieldError{{Field: "/secret", Code: fieldInvalidFormat}}},
	}
	for _, c := range cases {
		_, err := s.UpdateTenantWebhook(ctx, gen.UpdateTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01", Body: c.body})
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if !reflect.DeepEqual(p.Errors, c.want) {
			t.Errorf("%s: errors %+v, want %+v", c.name, p.Errors, c.want)
		}
	}
	// The access is checked before the patch: a tenant out of reach is
	// not found and the instance-wide webhooks forbidden, whatever the
	// body; an intermediate login state is unauthenticated.
	_, err := s.UpdateTenantWebhook(ctx, gen.UpdateTenantWebhookRequestObject{TenantId: "ten_b", WebhookId: "whk_01", Body: webhookPatchBody(`[`)})
	expectProblem(t, err, problem.CodeNotFound)
	_, err = s.UpdateSystemWebhook(ctx, gen.UpdateSystemWebhookRequestObject{WebhookId: "whk_01", Body: webhookPatchBody(`[`)})
	expectProblem(t, err, problem.CodeForbidden)
	pending := ctxWith(store.SessionTOTPRequired, superRoot)
	_, err = s.UpdateSystemWebhook(pending, gen.UpdateSystemWebhookRequestObject{WebhookId: "whk_01", Body: webhookPatchBody(`[`)})
	expectProblem(t, err, problem.CodeUnauthenticated)
	_, err = s.UpdateSystemWebhook(ctxWith(store.SessionAuthenticated, superRoot), gen.UpdateSystemWebhookRequestObject{WebhookId: "whk_01", Body: webhookPatchBody(`{"x":1}`)})
	expectProblem(t, err, problem.CodeValidationFailed)
	if len(f.calls) != 0 {
		t.Errorf("service called on a refused patch: %v", f.calls)
	}
}

func TestDeleteAndTestWebhook(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeWebhooks{result: webhook.Result{Duration: 10002 * time.Millisecond, Category: webhook.CategoryTimeout}}
	s := webhookServer(f)
	resp, err := s.DeleteTenantWebhook(ctx, gen.DeleteTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, resp); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("delete = %d %q", rec.Code, rec.Body)
	}
	root := ctxWith(store.SessionAuthenticated, superRoot)
	sresp, err := s.DeleteSystemWebhook(root, gen.DeleteSystemWebhookRequestObject{WebhookId: "whk_01"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, sresp); rec.Code != http.StatusNoContent {
		t.Errorf("delete system = %d", rec.Code)
	}
	tr, err := s.TestTenantWebhook(ctx, gen.TestTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	if err != nil {
		t.Fatal(err)
	}
	code, body := decode(t, tr)
	if code != http.StatusOK || body["success"] != false || body["durationMs"] != float64(10002) || body["errorCategory"] != "timeout" {
		t.Errorf("test = %d %v", code, body)
	}
	if _, ok := body["httpStatus"]; ok {
		t.Errorf("httpStatus rendered: %v", body)
	}
	f.result = webhook.Result{Success: true, HTTPStatus: 200, Duration: 182 * time.Millisecond}
	tresp, err := s.TestSystemWebhook(root, gen.TestSystemWebhookRequestObject{WebhookId: "whk_01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, body := decode(t, tresp); body["success"] != true || body["httpStatus"] != float64(200) || body["errorCategory"] != nil {
		t.Errorf("test system = %v", body)
	}
	f.err = &webhookadmin.RateLimitError{RetryAfter: time.Minute}
	_, err = s.TestTenantWebhook(ctx, gen.TestTenantWebhookRequestObject{TenantId: "ten_a", WebhookId: "whk_01"})
	expectProblem(t, err, problem.CodeRateLimited)
}
