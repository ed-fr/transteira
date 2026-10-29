package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// validThresholdsJSON is a complete thresholds body.
const validThresholdsJSON = `{"maxDailyBytesPerSender":1073741824,"maxDailyTransfersPerSender":20,"maxRecipientsPerTransfer":50,` +
	`"blockOnExceed":true,"unusualVolumeFactor":3.5,"unusualMinHistoryDays":7,"largeExternalTransferBytes":null,` +
	`"officeHours":{"start":"08:00","end":"24:00","weekdays":[1,2,3,4,5]},"timeZone":"Europe/Paris",` +
	`"maxInvitationsPerInviter":10,"externalMaxDailyBytes":null,"externalMaxDailyDeposits":5}`

// thresholdsCtx returns ctx carrying raw as CaptureThresholdsBody does.
func thresholdsCtx(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, rawBodyKey{}, []byte(raw))
}

// decodeThresholds decodes a thresholds body like the generated handler.
func decodeThresholds(t *testing.T, raw string) *gen.AbuseThresholds {
	t.Helper()
	var b gen.AbuseThresholds
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestAbuseThresholdsHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)

	got, err := s.GetAbuseThresholds(ctx, gen.GetAbuseThresholdsRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	def := store.DefaultAbuseSettings()
	if g := gen.AbuseThresholds(got.(gen.GetAbuseThresholds200JSONResponse)); g.TimeZone != def.TimeZone ||
		g.MaxInvitationsPerInviter != def.MaxInvitationsPerInviter {
		t.Errorf("get %+v", g)
	}

	upd, err := s.UpdateAbuseThresholds(thresholdsCtx(ctx, validThresholdsJSON),
		gen.UpdateAbuseThresholdsRequestObject{TenantId: "ten_a", Body: decodeThresholds(t, validThresholdsJSON)})
	if err != nil {
		t.Fatal(err)
	}
	in := svc.args["UpdateAbuseThresholds"][2].(store.AbuseSettings)
	if *in.MaxDailyBytesPerSender != 1<<30 || *in.MaxDailyTransfersPerSender != 20 || *in.MaxRecipientsPerTransfer != 50 ||
		!in.BlockOnExceed || *in.UnusualVolumePct != 350 || in.UnusualMinHistoryDays != 7 || in.LargeExternalTransferBytes != nil ||
		*in.OfficeStartMinute != 480 || *in.OfficeEndMinute != 1440 || in.OfficeWeekdays != 0b0011111 || in.TimeZone != "Europe/Paris" ||
		in.MaxInvitationsPerInviter != 10 || in.ExternalMaxDailyBytes != nil || *in.ExternalMaxDailyDeposits != 5 ||
		svc.args["UpdateAbuseThresholds"][3] != clientIP {
		t.Errorf("service input %+v", svc.args["UpdateAbuseThresholds"])
	}
	// The answer round-trips.
	out := gen.AbuseThresholds(upd.(gen.UpdateAbuseThresholds200JSONResponse))
	if *out.UnusualVolumeFactor != 3.5 || out.OfficeHours == nil || out.OfficeHours.Start != "08:00" || out.OfficeHours.End != "24:00" ||
		!reflect.DeepEqual(out.OfficeHours.Weekdays, []int{1, 2, 3, 4, 5}) || out.LargeExternalTransferBytes != nil {
		t.Errorf("answer %+v", out)
	}
	// No office hours, no factor: null.
	body := decodeThresholds(t, validThresholdsJSON)
	body.OfficeHours, body.UnusualVolumeFactor = nil, nil
	raw := strings.Replace(validThresholdsJSON, `"unusualVolumeFactor":3.5`, `"unusualVolumeFactor":null`, 1)
	upd, err = s.UpdateAbuseThresholds(thresholdsCtx(ctx, raw), gen.UpdateAbuseThresholdsRequestObject{TenantId: "ten_a", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if out := gen.AbuseThresholds(upd.(gen.UpdateAbuseThresholds200JSONResponse)); out.OfficeHours != nil || out.UnusualVolumeFactor != nil {
		t.Errorf("disabled rules: %+v", out)
	}
}

func TestAbuseThresholdsUpdateErrors(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	update := func(ctx context.Context, raw string) error {
		var b gen.AbuseThresholds
		_ = json.Unmarshal([]byte(raw), &b)
		_, err := s.UpdateAbuseThresholds(ctx, gen.UpdateAbuseThresholdsRequestObject{TenantId: "ten_a", Body: &b})
		return err
	}
	without := func(member string) string {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(validThresholdsJSON), &m)
		delete(m, member)
		b, _ := json.Marshal(m)
		return string(b)
	}
	// An absent member is refused, nullable or not; null only where allowed.
	for _, m := range []string{"largeExternalTransferBytes", "officeHours", "blockOnExceed", "timeZone"} {
		p := expectProblem(t, update(thresholdsCtx(ctx, without(m)), without(m)), problem.CodeValidationFailed)
		if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/" + m, Code: fieldRequired}}) {
			t.Errorf("without %s: %+v", m, p.Errors)
		}
	}
	nulled := strings.Replace(validThresholdsJSON, `"blockOnExceed":true`, `"blockOnExceed":null`, 1)
	p := expectProblem(t, update(thresholdsCtx(ctx, nulled), nulled), problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/blockOnExceed", Code: fieldNotNullable}}) {
		t.Errorf("null: %+v", p.Errors)
	}
	for _, raw := range []string{`null`, `[]`, `"x"`} {
		p := expectProblem(t, update(thresholdsCtx(ctx, raw), validThresholdsJSON), problem.CodeValidationFailed)
		if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}) {
			t.Errorf("%s: %+v", raw, p.Errors)
		}
	}
	// A value that cannot be converted names its field.
	for _, c := range []struct{ field, raw string }{
		{"/officeHours/start", strings.Replace(validThresholdsJSON, `"start":"08:00"`, `"start":"8h"`, 1)},
		{"/officeHours/end", strings.Replace(validThresholdsJSON, `"end":"24:00"`, `"end":"25:00"`, 1)},
		{"/officeHours/weekdays", strings.Replace(validThresholdsJSON, `[1,2,3,4,5]`, `[0,8]`, 1)},
		{"/officeHours/weekdays", strings.Replace(validThresholdsJSON, `[1,2,3,4,5]`, `[]`, 1)},
		{"/officeHours/weekdays", strings.Replace(validThresholdsJSON, `[1,2,3,4,5]`, `[1,2,2]`, 1)},
	} {
		p := expectProblem(t, update(thresholdsCtx(ctx, c.raw), c.raw), problem.CodeValidationFailed)
		if p.Errors[0].Field != c.field || p.Errors[0].Code != fieldInvalidFormat {
			t.Errorf("%s (%s): %+v", c.field, c.raw, p.Errors)
		}
	}
	// A service refusal names its field.
	svc.err, svc.errAt = &tenantadmin.InvalidError{Field: tenantadmin.FieldTimeZone}, "UpdateAbuseThresholds"
	p = expectProblem(t, update(thresholdsCtx(ctx, validThresholdsJSON), validThresholdsJSON), problem.CodeValidationFailed)
	if p.Errors[0].Field != tenantadmin.FieldTimeZone {
		t.Errorf("service error: %+v", p.Errors)
	}
	svc.err, svc.errAt = nil, ""
	// No body, and a server without CaptureThresholdsBody.
	_, err := s.UpdateAbuseThresholds(ctx, gen.UpdateAbuseThresholdsRequestObject{TenantId: "ten_a"})
	expectProblem(t, err, problem.CodeValidationFailed)
	if err := update(ctx, validThresholdsJSON); !errors.Is(err, errNoThresholdsBody) {
		t.Errorf("without the capture middleware: %v", err)
	}
	// An invalid body for a tenant the administrator cannot reach: 404 first.
	svc.err, svc.errAt = tenantadmin.ErrNotFound, "AbuseThresholds"
	expectProblem(t, update(thresholdsCtx(ctx, `{}`), `{}`), problem.CodeNotFound)
}

func TestThresholdsConversions(t *testing.T) {
	t.Parallel()
	// The factor goes through a float32: 1.1 must give 110, not 109.
	for f, want := range map[float32]int{1.5: 150, 1.1: 110, 2.3: 230, 100: 10000, 3.4e38: maxVolumePercent} {
		got, err := thresholdsSettings(gen.AbuseThresholds{UnusualVolumeFactor: &f})
		if err != nil || *got.UnusualVolumePct != want {
			t.Errorf("factor %v = %v, %v; want %d", f, got.UnusualVolumePct, err, want)
		}
	}
	for s, want := range map[string]int{"00:00": 0, "08:30": 510, "23:59": 1439} {
		if got, ok := parseClock(s, false); !ok || got != want {
			t.Errorf("parseClock(%q) = %d, %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "8:00", "08:0", "24:00", "24:01", "12:60", "ab:cd", "0800"} {
		if _, ok := parseClock(s, false); ok {
			t.Errorf("parseClock(%q) accepted", s)
		}
	}
	if m, ok := parseClock("24:00", true); !ok || m != 1440 {
		t.Errorf("end of day: %d %v", m, ok)
	}
	if formatClock(1440) != "24:00" || formatClock(65) != "01:05" {
		t.Error("formatClock")
	}
	// Weekdays: the mask round-trips in ISO order, Sunday being bit 6.
	start, end := 60, 120
	back := thresholdsBody(store.AbuseSettings{OfficeStartMinute: &start, OfficeEndMinute: &end, OfficeWeekdays: 0b1000001})
	if !reflect.DeepEqual(back.OfficeHours.Weekdays, []int{1, 7}) {
		t.Errorf("weekdays %v", back.OfficeHours.Weekdays)
	}
}

func TestCaptureThresholdsBody(t *testing.T) {
	t.Parallel()
	var gotRaw []byte
	var haveRaw bool
	var gotBody string
	h := CaptureThresholdsBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRaw, haveRaw = r.Context().Value(rawBodyKey{}).([]byte)
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	run := func(method, path, body string) {
		gotRaw, haveRaw, gotBody = nil, false, ""
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, strings.NewReader(body)))
	}
	run(http.MethodPut, "/api/v1/admin/tenants/ten_a/abuse-thresholds", `{"a":1}`)
	if !haveRaw || string(gotRaw) != `{"a":1}` || gotBody != `{"a":1}` {
		t.Errorf("captured %q (%v), downstream body %q", gotRaw, haveRaw, gotBody)
	}
	// Only the thresholds update is captured.
	run(http.MethodGet, "/api/v1/admin/tenants/ten_a/abuse-thresholds", "")
	run(http.MethodPut, "/api/v1/admin/tenants/ten_a/recipient-rules", `{}`)
	if haveRaw || gotBody != `{}` {
		t.Errorf("another operation captured: %v %q", haveRaw, gotBody)
	}
	// A body that cannot be read fails the same way downstream.
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tenants/ten_a/abuse-thresholds", nil)
	r.Body = io.NopCloser(&failingReader{err: io.ErrUnexpectedEOF})
	var readErr error
	CaptureThresholdsBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})).ServeHTTP(httptest.NewRecorder(), r)
	if !errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Errorf("downstream read error = %v", readErr)
	}
	// No body at all.
	r = httptest.NewRequest(http.MethodPut, "/api/v1/admin/tenants/ten_a/abuse-thresholds", nil)
	r.Body = nil
	called := false
	CaptureThresholdsBody(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Error("request without body not passed on")
	}
}

func TestAbuseReportHandlers(t *testing.T) {
	t.Parallel()
	ops := newFakeOps()
	ops.next = "c2"
	s := opsServer(ops, &fakeSubjects{}, &fakeStats{})
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	status, limit, cursor := gen.AbuseReportStatus("open"), 5, "c1"
	resp, err := s.ListAbuseReports(ctx, gen.ListAbuseReportsRequestObject{
		TenantId: "ten_a", Params: gen.ListAbuseReportsParams{Status: &status, Limit: &limit, Cursor: &cursor},
	})
	if err != nil {
		t.Fatal(err)
	}
	list := resp.(gen.ListAbuseReports200JSONResponse)
	if len(list.Items) != 1 || *list.NextCursor != "c2" ||
		!reflect.DeepEqual(ops.args["ListAbuseReports"][1:], []any{tenant.ID("ten_a"), store.AbuseReportOpen, 5, "c1"}) {
		t.Errorf("list %+v, args %v", list, ops.args["ListAbuseReports"])
	}
	r := list.Items[0]
	// 0-based position becomes a 1-based index; empty reporter, note and closing are absent.
	if r.RecipientIndex == nil || *r.RecipientIndex != 1 || r.ReportedBy != nil || r.Note != nil || r.ClosedAt != nil ||
		r.ClosedBy != nil || r.Message == nil || *r.Message != "looks like phishing" || r.ReporterVerified || r.Status != gen.AbuseReportStatus("open") {
		t.Errorf("report %+v", r)
	}

	got, err := s.GetAbuseReport(ctx, gen.GetAbuseReportRequestObject{TenantId: "ten_a", ReportId: "abr_01"})
	if err != nil || got.(gen.GetAbuseReport200JSONResponse).Id != "abr_01" {
		t.Errorf("get %+v %v", got, err)
	}

	note := "handled"
	upd, err := s.UpdateAbuseReport(ctx, gen.UpdateAbuseReportRequestObject{
		TenantId: "ten_a", ReportId: "abr_01", Body: &gen.AbuseReportUpdate{Status: gen.Closed, Note: &note},
	})
	if err != nil || upd.(gen.UpdateAbuseReport200JSONResponse).Status != gen.AbuseReportStatus("closed") {
		t.Fatalf("update %+v %v", upd, err)
	}
	args := ops.args["UpdateAbuseReport"]
	if args[3] != store.AbuseReportClosed || *args[4].(*string) != "handled" || args[5] != clientIP {
		t.Errorf("update args %v", args)
	}
	_, err = s.UpdateAbuseReport(ctx, gen.UpdateAbuseReportRequestObject{TenantId: "ten_a", ReportId: "abr_01"})
	expectProblem(t, err, problem.CodeValidationFailed)

	// Service errors: conflict and invalid status.
	ops.err = tenantops.ErrStateConflict
	_, err = s.UpdateAbuseReport(ctx, gen.UpdateAbuseReportRequestObject{TenantId: "ten_a", ReportId: "abr_01", Body: &gen.AbuseReportUpdate{Status: gen.Closed}})
	expectProblem(t, err, problem.CodeStateConflict)
	ops.err = &tenantops.InvalidError{Field: tenantops.FieldNote}
	_, err = s.UpdateAbuseReport(ctx, gen.UpdateAbuseReportRequestObject{TenantId: "ten_a", ReportId: "abr_01", Body: &gen.AbuseReportUpdate{Status: gen.Closed}})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/note" {
		t.Errorf("errors %+v", p.Errors)
	}
	// A verified reporter, a closed report and a shared link.
	closed := now.Add(time.Hour)
	body := abuseReportBody(store.AbuseReport{
		ID: "abr_02", ReporterEmail: "carol@customer.example.net", ReporterVerified: true, Status: store.AbuseReportClosed,
		ClosedAt: closed, ClosedBy: "admin.entity-a", Note: "n",
	})
	if body.ReportedBy == nil || *body.ReportedBy != "carol@customer.example.net" || body.RecipientIndex != nil ||
		body.ClosedAt == nil || !body.ClosedAt.Equal(closed) || *body.ClosedBy != "admin.entity-a" || *body.Note != "n" {
		t.Errorf("body %+v", body)
	}
}

// TestAbuseThresholdsThroughTheChain runs the update through the generated
// strict handler with CaptureThresholdsBody installed, as the admin router
// does: an absent member is refused, a complete body passes.
func TestAbuseThresholdsThroughTheChain(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	mux := http.NewServeMux()
	base := ctxWith(store.SessionAuthenticated, delegated)
	gen.HandlerWithOptions(gen.NewStrictHandler(tenantServer(svc), nil), gen.StdHTTPServerOptions{
		BaseRouter: mux,
		// The last middleware is the outermost: the session, then the capture.
		Middlewares: []gen.MiddlewareFunc{
			CaptureThresholdsBody,
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r.WithContext(base)) })
			},
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
	})
	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPut, "/admin/tenants/ten_a/abuse-thresholds", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, r)
		return rec
	}
	if rec := put(validThresholdsJSON); rec.Code != http.StatusOK {
		t.Fatalf("complete body: %d %s", rec.Code, rec.Body)
	}
	if len(svc.calls) != 1 || svc.calls[0] != "UpdateAbuseThresholds" {
		t.Errorf("service calls %v", svc.calls)
	}
	svc.calls = nil
	incomplete := strings.Replace(validThresholdsJSON, `"largeExternalTransferBytes":null,`, "", 1)
	if rec := put(incomplete); rec.Code == http.StatusOK || slices.Contains(svc.calls, "UpdateAbuseThresholds") {
		t.Errorf("body without a member: %d %s (calls %v)", rec.Code, rec.Body, svc.calls)
	}
}
