package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// fakeSearch is an operations service that also serves the transfer
// search.
type fakeSearch struct {
	*fakeOps
	result tenantops.SearchResult
}

func (f *fakeSearch) SearchTransfers(_ context.Context, p adminauth.Principal, q string, limit int) (tenantops.SearchResult, error) {
	return f.result, f.record("SearchTransfers", p.SessionID, q, limit)
}

// searchCtx returns the context of an authenticated session of a holding
// raw as the body kept by CaptureRawBody.
func searchCtx(a adminauth.Account, raw string) context.Context {
	return context.WithValue(ctxWith(store.SessionAuthenticated, a), rawBodyKey{}, []byte(raw))
}

// searchReq returns the request of a search body.
func searchReq(q string, limit *int) gen.SearchTransfersRequestObject {
	return gen.SearchTransfersRequestObject{Body: &gen.TransferSearch{Q: q, Limit: limit}}
}

// TestSearchTransfersHandler maps the request to the service, a missing
// limit to the default, and the result to the OpenAPI TransferSearchResult,
// each transfer as in the transfer list.
func TestSearchTransfersHandler(t *testing.T) {
	t.Parallel()
	f := &fakeSearch{fakeOps: newFakeOps(), result: tenantops.SearchResult{
		Kind:  tenantops.SearchByEmail,
		Items: []tenantops.SearchHit{{TenantID: "ten_b", TenantName: "Entity B", Transfer: sampleTransfer}},
		Tenants: []tenantops.SearchTenant{
			{TenantID: "ten_a", TenantName: "Entity A", More: true}, {TenantID: "ten_b", TenantName: "Entity B"},
		},
		Truncated: true,
	}}
	s := opsServer(f, &fakeSubjects{}, &fakeStats{})
	resp, err := s.SearchTransfers(searchCtx(delegated, `{"q":"carol@customer.example.net"}`), searchReq("carol@customer.example.net", nil))
	if err != nil {
		t.Fatal(err)
	}
	got := gen.TransferSearchResult(resp.(gen.SearchTransfers200JSONResponse))
	want := gen.TransferSearchResult{
		Kind: gen.TransferSearchResultKindEmail, Truncated: true,
		Items: []gen.TransferSearchHit{{TenantId: "ten_b", TenantName: "Entity B", Transfer: adminTransferBody(sampleTransfer)}},
		Tenants: []gen.TransferSearchTenant{
			{TenantId: "ten_a", TenantName: "Entity A", More: true}, {TenantId: "ten_b", TenantName: "Entity B"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("result %+v, want %+v", got, want)
	}
	if args := f.args["SearchTransfers"]; !reflect.DeepEqual(args[1:], []any{"carol@customer.example.net", tenantops.DefaultSearchLimit}) {
		t.Errorf("service args %v", args)
	}
	// An explicit limit, even out of range, is the service's to check.
	for _, limit := range []int{0, 7} {
		if _, err := s.SearchTransfers(searchCtx(delegated, `{"q":"x","limit":1}`), searchReq("x", &limit)); err != nil {
			t.Fatal(err)
		}
		if got := f.args["SearchTransfers"][2]; got != limit {
			t.Errorf("limit %v, want %d", got, limit)
		}
	}

	// No match: empty lists, never null.
	f.result = tenantops.SearchResult{Kind: tenantops.SearchByTransferID}
	resp, err = s.SearchTransfers(searchCtx(superRoot, `{"q":"trf_x"}`), searchReq("trf_x", nil))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(resp)
	if err != nil || string(body) != `{"items":[],"kind":"transfer_id","tenants":[],"truncated":false}` {
		t.Errorf("empty result %s, %v", body, err)
	}
}

// TestSearchTransfersHandlerRefusals checks the wiring errors, the session,
// the structural checks of the body, before the service, and the mapping
// of the service errors.
func TestSearchTransfersHandlerRefusals(t *testing.T) {
	t.Parallel()
	f := &fakeSearch{fakeOps: newFakeOps()}
	s := opsServer(f, &fakeSubjects{}, &fakeStats{})
	req := searchReq("carol@customer.example.net", nil)

	if _, err := NewServer().SearchTransfers(searchCtx(delegated, `{}`), req); !errors.Is(err, errNoOperationsService) {
		t.Errorf("no operations service: %v", err)
	}
	plain := opsServer(newFakeOps(), &fakeSubjects{}, &fakeStats{})
	if _, err := plain.SearchTransfers(searchCtx(delegated, `{}`), req); !errors.Is(err, errNoTransferSearch) {
		t.Errorf("operations service without search: %v", err)
	}
	_, err := s.SearchTransfers(context.Background(), req)
	expectProblem(t, err, problem.CodeUnauthenticated)
	pending := context.WithValue(ctxWith(store.SessionTOTPRequired, delegated), rawBodyKey{}, []byte(`{"zz":1}`))
	_, err = s.SearchTransfers(pending, req)
	expectProblem(t, err, problem.CodeUnauthenticated)
	if _, err := s.SearchTransfers(ctxWith(store.SessionAuthenticated, delegated), req); !errors.Is(err, errNoSearchBody) {
		t.Errorf("no raw body: %v", err)
	}
	for raw, field := range map[string]string{
		`[1]`:                    "",
		`null`:                   "",
		`{"q":"x","zz":1}`:       "/zz",
		`{"q":"x","a/b~c":1}`:    "/a~1b~0c",
		`{"q":"x","limit":null}`: "/limit",
		`{"q":null}`:             "/q",
	} {
		_, err := s.SearchTransfers(searchCtx(delegated, raw), req)
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Field != field || p.Errors[0].Code != fieldInvalidFormat {
			t.Errorf("%s: %+v, want invalid-format on %q", raw, p.Errors, field)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("the service was called: %v", f.calls)
	}

	boom := errors.New("boom")
	for _, tc := range []struct {
		err   error
		code  problem.Code
		field string
		fcode string
		retry int
	}{
		{&tenantops.InvalidError{Field: tenantops.FieldSearchQuery, Reason: "x", NotAnAddress: true}, problem.CodeValidationFailed, "/q", fieldInvalidEmail, 0},
		{&tenantops.InvalidError{Field: tenantops.FieldSearchQuery, Reason: "x"}, problem.CodeValidationFailed, "/q", fieldInvalidFormat, 0},
		{&tenantops.InvalidError{Field: tenantops.FieldSearchLimit, Reason: "x"}, problem.CodeValidationFailed, "/limit", fieldInvalidFormat, 0},
		{adminauth.ErrReadOnlyRole, problem.CodeReadOnlyRole, "", "", 0},
		{&tenantops.RateLimitError{RetryAfter: 20 * time.Second}, problem.CodeRateLimited, "", "", 20},
	} {
		f.err = tc.err
		_, err := s.SearchTransfers(searchCtx(delegated, `{"q":"carol@customer.example.net","limit":5}`), req)
		p := expectProblem(t, err, tc.code)
		if tc.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != tc.fcode) {
			t.Errorf("%v: errors %+v", tc.err, p.Errors)
		}
		if tc.retry != 0 && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != tc.retry) {
			t.Errorf("%v: retry after %v", tc.err, p.RetryAfterSeconds)
		}
	}
	f.err = boom
	if _, err := s.SearchTransfers(searchCtx(delegated, `{"q":"x"}`), req); !errors.Is(err, boom) {
		t.Errorf("service failure: %v", err)
	}
}

// TestCaptureRawBodySearch keeps the raw body of the search for its
// handler, unchanged for the generated decoder.
func TestCaptureRawBodySearch(t *testing.T) {
	t.Parallel()
	const body = `{"q":"carol@customer.example.net","zz":1}`
	var kept, decoded []byte
	h := CaptureRawBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		kept, _ = r.Context().Value(rawBodyKey{}).([]byte)
		decoded = make([]byte, len(body))
		_, _ = r.Body.Read(decoded)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/transfers/search", strings.NewReader(body))
	r.Pattern = searchRoute
	h.ServeHTTP(httptest.NewRecorder(), r)
	if string(kept) != body || string(decoded) != body {
		t.Errorf("kept %q, decoded %q", kept, decoded)
	}
}
