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
	"github.com/ed-fr/transteira/internal/droplink"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// sampleDropLink is a link as the store returns it.
var sampleDropLink = store.DropLink{
	ID: "drl_01", TokenHash: []byte("hash-never-rendered"), Label: "Supplier invoices",
	Recipients: []string{"accounting@entity-a.example.com"}, ValidityDays: 7, ConfidentialityLevel: "internal",
	Enabled: true, CreatedBy: "adm_01", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	MaxDepositsPerHour: 20,
}

// fakeDropLinks is a fake DropLinkService.
type fakeDropLinks struct {
	recorder
	list  []store.DropLink
	link  store.DropLink
	token string
	url   string
}

func (f *fakeDropLinks) List(_ context.Context, p adminauth.Principal, tid tenant.ID) ([]store.DropLink, error) {
	return f.list, f.record("List", p.SessionID, tid)
}

func (f *fakeDropLinks) Get(_ context.Context, p adminauth.Principal, tid tenant.ID, linkID string) (store.DropLink, error) {
	return f.link, f.record("Get", p.SessionID, tid, linkID)
}

func (f *fakeDropLinks) Create(_ context.Context, p adminauth.Principal, tid tenant.ID, in droplink.CreateInput, ip netip.Addr) (droplink.Created, error) {
	return droplink.Created{Link: f.link, Token: f.token, URL: f.url}, f.record("Create", p.SessionID, tid, in, ip)
}

func (f *fakeDropLinks) Update(_ context.Context, p adminauth.Principal, tid tenant.ID, linkID string, in droplink.UpdateInput, ip netip.Addr) (store.DropLink, error) {
	return f.link, f.record("Update", p.SessionID, tid, linkID, in, ip)
}

func (f *fakeDropLinks) Rotate(_ context.Context, p adminauth.Principal, tid tenant.ID, linkID string, ip netip.Addr) (droplink.Created, error) {
	return droplink.Created{Link: f.link, Token: f.token, URL: f.url}, f.record("Rotate", p.SessionID, tid, linkID, ip)
}

func (f *fakeDropLinks) Revoke(_ context.Context, p adminauth.Principal, tid tenant.ID, linkID string, ip netip.Addr) error {
	return f.record("Revoke", p.SessionID, tid, linkID, ip)
}

func dropLinkServer(svc DropLinkService) *Server {
	s := NewServer(WithDropLinkService(svc))
	s.now = func() time.Time { return now }
	return s
}

func linkPatch(s string) *gen.DropLinkUpdate {
	b := gen.DropLinkUpdate(s)
	return &b
}

// dropLinkCalls calls every drop link operation of s with a minimal valid
// request and returns the errors, by service method.
func dropLinkCalls(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	var err error
	_, err = s.ListDropLinks(ctx, gen.ListDropLinksRequestObject{TenantId: "ten_a"})
	out["List"] = err
	_, err = s.GetDropLink(ctx, gen.GetDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	out["Get"] = err
	_, err = s.CreateDropLink(ctx, gen.CreateDropLinkRequestObject{TenantId: "ten_a", Body: &gen.DropLinkCreate{Label: "l", ValidityDays: 7}})
	out["Create"] = err
	_, err = s.UpdateDropLink(ctx, gen.UpdateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01", Body: linkPatch(`{"label":"n"}`)})
	out["Update"] = err
	_, err = s.RotateDropLink(ctx, gen.RotateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	out["Rotate"] = err
	_, err = s.DeleteDropLink(ctx, gen.DeleteDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	out["Revoke"] = err
	return out
}

func TestDropLinkWiring(t *testing.T) {
	t.Parallel()
	calls := dropLinkCalls(ctxWith(store.SessionAuthenticated, superRoot), NewServer())
	if len(calls) != 6 {
		t.Fatalf("%d operations, want 6", len(calls))
	}
	for name, err := range calls {
		if !errors.Is(err, errNoDropLinkService) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	f := &fakeDropLinks{link: sampleDropLink}
	for name, err := range dropLinkCalls(ctxWith("", superRoot), dropLinkServer(f)) {
		expectProblem(t, err, problem.CodeUnauthenticated)
		_ = name
	}
	if len(f.calls) != 0 {
		t.Errorf("service called without session: %v", f.calls)
	}
	f = &fakeDropLinks{link: sampleDropLink, recorder: recorder{err: droplink.ErrNotFound}}
	for name, err := range dropLinkCalls(ctxWith(store.SessionAuthenticated, delegated), dropLinkServer(f)) {
		expectProblem(t, err, problem.CodeNotFound)
		args := f.args[name]
		if len(args) < 2 || args[0] != "as_01" || args[1] != tenant.ID("ten_a") {
			t.Errorf("%s: service args %v", name, args)
		}
		if name != "List" && name != "Get" && args[len(args)-1] != clientIP {
			t.Errorf("%s: client IP %v", name, args[len(args)-1])
		}
	}
}

func TestDropLinkErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		err    error
		code   problem.Code
		field  string
		status int
	}{
		{&droplink.InvalidError{Field: droplink.FieldLabel, Reason: "x"}, problem.CodeValidationFailed, "/label", 400},
		{fmt.Errorf("wrap: %w", &droplink.InvalidError{Field: droplink.FieldRecipients + "/1"}), problem.CodeValidationFailed, "/recipients/1", 400},
		{droplink.ErrInvalidInput, problem.CodeValidationFailed, "", 400},
		{droplink.ErrStateConflict, problem.CodeStateConflict, "", 409},
		{droplink.ErrLimitReached, problem.CodeDropLinkLimitReached, "", 409},
		{droplink.ErrUnauthenticated, problem.CodeUnauthenticated, "", 401},
		{droplink.ErrForbidden, problem.CodeForbidden, "", 403},
		{adminauth.ErrReadOnlyRole, problem.CodeReadOnlyRole, "", 403},
		{droplink.ErrNotFound, problem.CodeNotFound, "", 404},
	}
	for _, tt := range tests {
		p := expectProblem(t, dropLinkError(tt.err), tt.code)
		if p.Status != tt.status {
			t.Errorf("%v: status %d", tt.err, p.Status)
		}
		switch {
		case tt.field != "":
			if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: tt.field, Code: fieldInvalidFormat}}) {
				t.Errorf("%v: field errors %+v", tt.err, p.Errors)
			}
		case len(p.Errors) != 0:
			t.Errorf("%v: unexpected field errors %+v", tt.err, p.Errors)
		}
	}
	if err := dropLinkError(boom); !errors.Is(err, boom) {
		t.Errorf("internal error: %v", err)
	}
}

func TestListGetDropLinks(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	used, revoked := sampleDropLink, sampleDropLink
	used.ID, used.LastUsedAt, used.ConfidentialityLevel, used.Recipients = "drl_02", now.Add(-time.Minute), "", nil
	revoked.ID, revoked.RevokedAt, revoked.Enabled = "drl_03", now, false
	forgotten := sampleDropLink
	forgotten.ID, forgotten.CreatedAt, forgotten.ExpiresAt, forgotten.MaxDepositsPerHour = "drl_04", now.AddDate(-1, 0, -1), now.Add(time.Hour), 5
	revoked.CreatedAt = forgotten.CreatedAt
	f := &fakeDropLinks{list: []store.DropLink{sampleDropLink, used, revoked, forgotten}, link: used}
	s := dropLinkServer(f)
	resp, err := s.ListDropLinks(ctx, gen.ListDropLinksRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, resp)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "hash") || strings.Contains(body, `"token"`) || strings.Contains(body, `"url"`) {
		t.Fatalf("list = %d %s", rec.Code, body)
	}
	items := resp.(gen.ListDropLinks200JSONResponse).Items
	if len(items) != 4 {
		t.Fatalf("%d items", len(items))
	}
	first := items[0]
	if first.Id != "drl_01" || first.Label != "Supplier invoices" || first.ValidityDays != 7 || first.CreatedBy != "adm_01" ||
		first.ConfidentialityLevel == nil || *first.ConfidentialityLevel != "internal" || !first.Enabled ||
		first.LastUsedAt != nil || first.RevokedAt != nil ||
		!reflect.DeepEqual(first.Recipients, []string{"accounting@entity-a.example.com"}) {
		t.Errorf("first = %+v", first)
	}
	if it := items[1]; it.ConfidentialityLevel != nil || it.LastUsedAt == nil || it.Recipients == nil || len(it.Recipients) != 0 {
		t.Errorf("used = %+v", it)
	}
	if !strings.Contains(body, `"recipients":[]`) {
		t.Errorf("recipients null: %s", body)
	}
	if it := items[2]; it.RevokedAt == nil || it.Enabled || it.Unused == nil || *it.Unused {
		t.Errorf("revoked = %+v", it)
	}
	if it := items[3]; it.Unused == nil || !*it.Unused || it.ExpiresAt == nil || !it.ExpiresAt.Equal(now.Add(time.Hour)) ||
		it.MaxDepositsPerHour != 5 {
		t.Errorf("forgotten = %+v", it)
	}
	if it := items[0]; it.Unused == nil || *it.Unused || it.ExpiresAt != nil || it.MaxDepositsPerHour != 20 {
		t.Errorf("first limits = %+v", it)
	}
	if !strings.Contains(body, `"unused":false`) || !strings.Contains(body, `"maxDepositsPerHour":20`) {
		t.Errorf("limits not rendered: %s", body)
	}

	f.list = nil
	resp, _ = s.ListDropLinks(ctx, gen.ListDropLinksRequestObject{TenantId: "ten_a"})
	if rec := visit(t, resp); !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("empty list = %s", rec.Body)
	}

	g, err := s.GetDropLink(ctx, gen.GetDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_02"})
	if err != nil {
		t.Fatal(err)
	}
	if got := g.(gen.GetDropLink200JSONResponse); got.Id != "drl_02" {
		t.Errorf("get = %+v", got)
	}
	if args := f.args["Get"]; args[2] != "drl_02" {
		t.Errorf("get args %v", args)
	}
}

func TestCreateRotateDropLink(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	token := "ttd_" + strings.Repeat("x", 22)
	url := "https://transfer.entity-a.example.com/drop/" + token
	f := &fakeDropLinks{link: sampleDropLink, token: token, url: url}
	s := dropLinkServer(f)
	level, off, end, perHour := "internal", false, now.Add(24*time.Hour), 9
	resp, err := s.CreateDropLink(ctx, gen.CreateDropLinkRequestObject{TenantId: "ten_a", Body: &gen.DropLinkCreate{
		Label: "Supplier invoices", Recipients: []string{"accounting@entity-a.example.com"}, ValidityDays: 7,
		ConfidentialityLevel: &level, Enabled: &off, ExpiresAt: &end, MaxDepositsPerHour: &perHour,
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := droplink.CreateInput{
		Label: "Supplier invoices", Recipients: []string{"accounting@entity-a.example.com"}, ValidityDays: 7,
		ConfidentialityLevel: "internal", Enabled: &off, ExpiresAt: &end, MaxDepositsPerHour: &perHour,
	}
	if got := f.args["Create"]; !reflect.DeepEqual(got[2], want) || got[3] != clientIP {
		t.Errorf("create args %v", got)
	}
	code, body := decode(t, resp)
	if code != http.StatusCreated || body["token"] != token || body["url"] != url || body["id"] != "drl_01" ||
		body["createdBy"] != "adm_01" || body["label"] != "Supplier invoices" || body["unused"] != false ||
		body["maxDepositsPerHour"] != float64(20) {
		t.Errorf("create = %d %v", code, body)
	}
	if _, ok := body["tokenHash"]; ok {
		t.Errorf("hash rendered: %v", body)
	}

	// A missing body reaches the service (access check first) with an empty input.
	f.err = &droplink.InvalidError{Field: droplink.FieldLabel}
	_, err = s.CreateDropLink(ctx, gen.CreateDropLinkRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/label", Code: fieldInvalidFormat}}) {
		t.Errorf("errors %+v", p.Errors)
	}
	if got := f.args["Create"]; !reflect.DeepEqual(got[2], droplink.CreateInput{}) {
		t.Errorf("create args without body %v", got)
	}
	f.err = droplink.ErrLimitReached
	_, err = s.CreateDropLink(ctx, gen.CreateDropLinkRequestObject{TenantId: "ten_a"})
	expectProblem(t, err, problem.CodeDropLinkLimitReached)

	f.err = nil
	rot, err := s.RotateDropLink(ctx, gen.RotateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	if err != nil {
		t.Fatal(err)
	}
	code, body = decode(t, rot)
	if code != http.StatusOK || body["token"] != token || body["url"] != url {
		t.Errorf("rotate = %d %v", code, body)
	}
	if got := f.args["Rotate"]; got[2] != "drl_01" || got[3] != clientIP {
		t.Errorf("rotate args %v", got)
	}
	f.err = droplink.ErrStateConflict
	_, err = s.RotateDropLink(ctx, gen.RotateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	expectProblem(t, err, problem.CodeStateConflict)
}

func TestUpdateDropLink(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeDropLinks{link: sampleDropLink}
	s := dropLinkServer(f)
	update := func(body string) droplink.UpdateInput {
		t.Helper()
		resp, err := s.UpdateDropLink(ctx, gen.UpdateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01", Body: linkPatch(body)})
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := resp.(gen.UpdateDropLink200JSONResponse); got.Id != "drl_01" {
			t.Errorf("update = %+v", got)
		}
		return f.args["Update"][3].(droplink.UpdateInput)
	}
	label, days, on := "New", 30, true
	got := update(`{"label":"New","recipients":["a@entity-a.example.com"],"validityDays":30,"enabled":true,"confidentialityLevel":"internal"}`)
	want := droplink.UpdateInput{
		Label: &label, Recipients: []string{"a@entity-a.example.com"}, ValidityDays: &days, Enabled: &on,
		LevelSet: true, ConfidentialityLevel: "internal",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("full patch = %+v", got)
	}
	if got := update(`{}`); !reflect.DeepEqual(got, droplink.UpdateInput{}) {
		t.Errorf("empty patch = %+v", got)
	}
	if got := update(`{"confidentialityLevel":null}`); !got.LevelSet || got.ConfidentialityLevel != "" {
		t.Errorf("null level = %+v", got)
	}
	perHour := 50
	end := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := update(`{"expiresAt":"2027-01-02T03:04:05Z","maxDepositsPerHour":50}`); !reflect.DeepEqual(got,
		droplink.UpdateInput{ExpiresSet: true, ExpiresAt: end, MaxDepositsPerHour: &perHour}) {
		t.Errorf("limits patch = %+v", got)
	}
	if got := update(`{"expiresAt":null}`); !reflect.DeepEqual(got, droplink.UpdateInput{ExpiresSet: true}) {
		t.Errorf("null expiry = %+v", got)
	}
	if got := update(`{"recipients":[]}`); got.Recipients == nil || len(got.Recipients) != 0 {
		t.Errorf("empty recipients = %#v", got.Recipients)
	}
	if got := f.args["Update"]; got[2] != "drl_01" || got[4] != clientIP {
		t.Errorf("update args %v", got)
	}
	f.err = droplink.ErrStateConflict
	_, err := s.UpdateDropLink(ctx, gen.UpdateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01", Body: linkPatch(`{}`)})
	expectProblem(t, err, problem.CodeStateConflict)
}

func TestUpdateDropLinkPatchErrors(t *testing.T) {
	t.Parallel()
	f := &fakeDropLinks{link: sampleDropLink}
	s := dropLinkServer(f)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	cases := []struct {
		name string
		body *gen.DropLinkUpdate
		want []problem.FieldError
	}{
		{"no body", nil, []problem.FieldError{{Field: "", Code: fieldRequired}}},
		{"not an object", linkPatch(`[1]`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"null body", linkPatch(`null`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"malformed", linkPatch(`{`), []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"null label", linkPatch(`{"label":null}`), []problem.FieldError{{Field: "/label", Code: fieldNotNullable}}},
		{
			"nulls", linkPatch(`{"enabled":null,"recipients":null,"validityDays":null,"confidentialityLevel":null}`),
			[]problem.FieldError{
				{Field: "/recipients", Code: fieldNotNullable},
				{Field: "/validityDays", Code: fieldNotNullable},
				{Field: "/enabled", Code: fieldNotNullable},
			},
		},
		{"wrong type label", linkPatch(`{"label":5}`), []problem.FieldError{{Field: "/label", Code: fieldInvalidFormat}}},
		{"wrong type item", linkPatch(`{"recipients":["a",1]}`), []problem.FieldError{{Field: "/recipients/1", Code: fieldInvalidFormat}}},
		{"wrong type level", linkPatch(`{"confidentialityLevel":5}`), []problem.FieldError{{Field: "/confidentialityLevel", Code: fieldInvalidFormat}}},
		{"malformed expiry", linkPatch(`{"expiresAt":"tomorrow"}`), []problem.FieldError{{Field: "/expiresAt", Code: fieldInvalidFormat}}},
		{"zero expiry", linkPatch(`{"expiresAt":"0001-01-01T00:00:00Z"}`), []problem.FieldError{{Field: "/expiresAt", Code: fieldInvalidFormat}}},
		{"wrong type cap", linkPatch(`{"maxDepositsPerHour":"x"}`), []problem.FieldError{{Field: "/maxDepositsPerHour", Code: fieldInvalidFormat}}},
		{"null cap", linkPatch(`{"maxDepositsPerHour":null}`), []problem.FieldError{{Field: "/maxDepositsPerHour", Code: fieldNotNullable}}},
		{"unknown member", linkPatch(`{"label":"x","zeta":1}`), []problem.FieldError{{Field: "/zeta", Code: fieldInvalidFormat}}},
		{"token is read only", linkPatch(`{"token":"x"}`), []problem.FieldError{{Field: "/token", Code: fieldInvalidFormat}}},
		{
			"long member", linkPatch(`{"` + strings.Repeat("m", maxEchoedMemberLen+1) + `":1}`),
			[]problem.FieldError{{Field: "", Code: fieldInvalidFormat}},
		},
	}
	for _, c := range cases {
		_, err := s.UpdateDropLink(ctx, gen.UpdateDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01", Body: c.body})
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if !reflect.DeepEqual(p.Errors, c.want) {
			t.Errorf("%s: errors %+v, want %+v", c.name, p.Errors, c.want)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("service called on a malformed patch: %v", f.calls)
	}
}

func TestDeleteDropLink(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeDropLinks{}
	s := dropLinkServer(f)
	resp, err := s.DeleteDropLink(ctx, gen.DeleteDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, resp); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("delete = %d %q", rec.Code, rec.Body)
	}
	if got := f.args["Revoke"]; got[2] != "drl_01" || got[3] != clientIP {
		t.Errorf("revoke args %v", got)
	}
	f.err = adminauth.ErrReadOnlyRole
	_, err = s.DeleteDropLink(ctx, gen.DeleteDropLinkRequestObject{TenantId: "ten_a", DropLinkId: "drl_01"})
	expectProblem(t, err, problem.CodeReadOnlyRole)
}
