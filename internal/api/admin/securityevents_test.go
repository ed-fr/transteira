package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/securityevents"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeSecurityEvents records the calls and answers page or err.
type fakeSecurityEvents struct {
	page   store.Page[store.SecurityEvent]
	err    error
	tid    tenant.ID
	filter securityevents.Filter
	global bool
}

func (f *fakeSecurityEvents) ListTenant(_ context.Context, _ adminauth.Principal, tid tenant.ID, flt securityevents.Filter) (store.Page[store.SecurityEvent], error) {
	f.tid, f.filter = tid, flt
	return f.page, f.err
}

func (f *fakeSecurityEvents) ListGlobal(_ context.Context, _ adminauth.Principal, tid tenant.ID, flt securityevents.Filter) (store.Page[store.SecurityEvent], error) {
	f.tid, f.filter, f.global = tid, flt, true
	return f.page, f.err
}

func TestSecurityEventsHandlers(t *testing.T) {
	t.Parallel()
	at := now.Add(-time.Hour)
	svc := &fakeSecurityEvents{page: store.Page[store.SecurityEvent]{
		Items: []store.SecurityEvent{
			{
				ID: "sev_1", At: at, LastSeenAt: at.Add(time.Minute), TenantID: "ten_a", Type: "admin_login_failed",
				Reason: "password", IP: netip.MustParseAddr("203.0.113.7"), Occurrences: 4,
			},
			{ID: "sev_2", At: at, LastSeenAt: at, Type: "unknown_fqdn", Details: json.RawMessage(`{"host":"x"}`), Occurrences: 1},
		},
		NextCursor: "1:sev_2",
	}}
	s := NewServer(WithSecurityEventsService(svc))
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	typ, limit, cursor := gen.SecurityEventType("rate_limited"), 10, "c"
	from, to := at, now
	resp, err := s.ListTenantSecurityEvents(ctx, gen.ListTenantSecurityEventsRequestObject{
		TenantId: "ten_a", Params: gen.ListTenantSecurityEventsParams{Type: &typ, From: &from, To: &to, Limit: &limit, Cursor: &cursor},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := securityevents.Filter{Type: "rate_limited", From: from, To: to, Cursor: "c", Limit: 10}
	if svc.tid != "ten_a" || svc.filter != want || svc.global {
		t.Fatalf("service got %q %+v", svc.tid, svc.filter)
	}
	list := gen.SecurityEventList(resp.(gen.ListTenantSecurityEvents200JSONResponse))
	if len(list.Items) != 2 || list.NextCursor == nil || *list.NextCursor != "1:sev_2" {
		t.Fatalf("list = %+v", list)
	}
	first, second := list.Items[0], list.Items[1]
	if first.Id != "sev_1" || first.Ip != "203.0.113.7" || first.Reason == nil || *first.Reason != "password" ||
		first.TenantId == nil || *first.TenantId != "ten_a" || first.Occurrences == nil || *first.Occurrences != 4 ||
		first.LastSeenAt == nil || !first.LastSeenAt.Equal(at.Add(time.Minute)) || !first.OccurredAt.Equal(at) ||
		first.Type != "admin_login_failed" {
		t.Errorf("first = %+v", first)
	}
	// Unknown IP "-", no reason, no tenant, lastSeenAt absent for a single
	// occurrence; the details are not part of the API.
	if second.Ip != "-" || second.Reason != nil || second.TenantId != nil || second.LastSeenAt != nil ||
		second.Occurrences == nil || *second.Occurrences != 1 {
		t.Errorf("second = %+v", second)
	}
	body, _ := json.Marshal(second)
	if string(body) != `{"id":"sev_2","ip":"-","occurredAt":"`+at.Format(time.RFC3339Nano)+`","occurrences":1,"type":"unknown_fqdn"}` {
		t.Errorf("second renders %s", body)
	}

	tid := "ten_b"
	gresp, err := s.ListGlobalSecurityEvents(ctx, gen.ListGlobalSecurityEventsRequestObject{
		Params: gen.ListGlobalSecurityEventsParams{TenantId: &tid, Type: &typ},
	})
	if err != nil || !svc.global || svc.tid != "ten_b" || svc.filter.Type != "rate_limited" {
		t.Fatalf("global: %v, service got %q %+v", err, svc.tid, svc.filter)
	}
	if _, ok := gresp.(gen.ListGlobalSecurityEvents200JSONResponse); !ok {
		t.Fatalf("global response %T", gresp)
	}
}

func TestSecurityEventsHandlerErrors(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	// Without the service: 500 (a wiring error); without a session: 401.
	s := NewServer()
	if _, err := s.ListTenantSecurityEvents(ctx, gen.ListTenantSecurityEventsRequestObject{TenantId: "ten_a"}); !errors.Is(err, errNoSecurityEventsService) {
		t.Errorf("no service: %v", err)
	}
	if _, err := s.ListGlobalSecurityEvents(ctx, gen.ListGlobalSecurityEventsRequestObject{}); !errors.Is(err, errNoSecurityEventsService) {
		t.Errorf("no service: %v", err)
	}
	s = NewServer(WithSecurityEventsService(&fakeSecurityEvents{}))
	_, err := s.ListTenantSecurityEvents(context.Background(), gen.ListTenantSecurityEventsRequestObject{TenantId: "ten_a"})
	expectProblem(t, err, problem.CodeUnauthenticated)

	internal := errors.New("db down")
	for name, tc := range map[string]struct {
		err  error
		code problem.Code
	}{
		"invalid":     {&securityevents.InvalidError{Field: securityevents.FieldType}, problem.CodeValidationFailed},
		"not found":   {securityevents.ErrNotFound, problem.CodeNotFound},
		"not mine":    {adminauth.ErrNotFound, problem.CodeNotFound},
		"forbidden":   {adminauth.ErrForbidden, problem.CodeForbidden},
		"unauth":      {adminauth.ErrUnauthenticated, problem.CodeUnauthenticated},
		"server side": {internal, ""},
	} {
		s := NewServer(WithSecurityEventsService(&fakeSecurityEvents{err: tc.err}))
		_, errT := s.ListTenantSecurityEvents(ctx, gen.ListTenantSecurityEventsRequestObject{TenantId: "ten_a"})
		_, errG := s.ListGlobalSecurityEvents(ctx, gen.ListGlobalSecurityEventsRequestObject{})
		for _, err := range []error{errT, errG} {
			if tc.code == "" {
				if !errors.Is(err, internal) {
					t.Errorf("%s: %v", name, err)
				}
				continue
			}
			p := expectProblem(t, err, tc.code)
			if tc.code == problem.CodeValidationFailed && (len(p.Errors) != 1 || p.Errors[0].Field != "type" || p.Errors[0].Code != fieldInvalidFormat) {
				t.Errorf("%s: errors %+v", name, p.Errors)
			}
		}
	}
}
