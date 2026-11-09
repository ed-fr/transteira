package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Abuse detection operations (since 1.1, CLAUDE.md sections 15 and 10): the
// thresholds of a tenant and the abuse reports of its recipients.

// apiBase is the base path of the API (OpenAPI servers), under which the
// admin router mounts the generated routes.
const apiBase = "/api/v1"

// rawBodyRoutes are the route patterns (method and full path, as set in
// Request.Pattern by the generated router) of the operations whose handler
// reads the raw body (see CaptureRawBody): the abuse thresholds update, since
// API 2.1 the one-time secrets settings update (every required member) and,
// since API 1.2, the creation of a provisioning token and of a tenant by a
// provisioning token, and since API 2.0 the import of a tenant
// configuration (strict JSON: duplicate and unknown members refused).
var rawBodyRoutes = map[string]bool{
	http.MethodPut + " " + apiBase + "/admin/tenants/{tenantId}/abuse-thresholds": true,
	http.MethodPut + " " + apiBase + "/admin/tenants/{tenantId}/secret-settings":  true,
	http.MethodPost + " " + apiBase + "/admin/provisioning-tokens":                true,
	http.MethodPost + " " + apiBase + "/provisioning/tenants":                     true,
	importRoute: true,
}

// importRoute is the route pattern of importTenant.
const importRoute = http.MethodPost + " " + apiBase + "/admin/tenants/import"

// rawBodyChecks are the checks CaptureRawBody runs on the raw body of a
// route before the generated handler decodes it: a non-nil error is the
// *problem.Problem answered instead. The import is strictly checked there
// (CheckImportBody), so that the typed decode only ever sees a document
// whose arrays are bounded (T-306).
var rawBodyChecks = map[string]func([]byte) error{
	importRoute: CheckImportBody,
}

// rawBodyKey is the context key of the raw body of an operation that reads
// it (see CaptureRawBody).
type rawBodyKey struct{}

// rawBodyWanted reports whether the handler of r reads its raw body: its
// matched route pattern is exactly one of rawBodyRoutes.
func rawBodyWanted(r *http.Request) bool { return rawBodyRoutes[r.Pattern] }

// CaptureRawBody is a middleware keeping in the request context the raw
// body of the operations whose handler reads it, and only those (see
// rawBodyWanted): every member of the abuse thresholds body is required,
// and the provisioning bodies refuse unknown members, which the generated
// types cannot tell. The body is read after the body limit middleware, so
// it is bounded. When the route has a check in rawBodyChecks (the import
// of a tenant configuration), a body it refuses is answered with its
// Problem and never reaches the generated decoder; any other body is
// handed back unchanged to the generated decoder.
func CaptureRawBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || !rawBodyWanted(r) {
			next.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			// The generated decoder gets the same error from the body.
			r.Body = io.NopCloser(&failingReader{err: err})
			next.ServeHTTP(w, r)
			return
		}
		if check := rawBodyChecks[r.Pattern]; check != nil {
			if err := check(raw); err != nil {
				writeProblem(w, r, err)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rawBodyKey{}, raw)))
	})
}

// writeProblem answers err, a *problem.Problem (anything else is a 500
// internal-error), with the request identifier as instance.
func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	var p *problem.Problem
	if !errors.As(err, &p) {
		p = problem.New(problem.CodeInternalError)
	}
	cp := *p
	cp.Instance = middleware.RequestID(r.Context())
	problem.Write(w, &cp)
}

// failingReader returns err on every read.
type failingReader struct{ err error }

// Read implements io.Reader.
func (f *failingReader) Read([]byte) (int, error) { return 0, f.err }

// bodyMember is a member every body of an operation must carry; nullable
// tells whether it may be null.
type bodyMember struct {
	name     string
	nullable bool
}

// thresholdMembers lists the members of the thresholds body, every one
// required, in the order their errors are reported; nullable tells whether
// the member may be null.
var thresholdMembers = []bodyMember{
	{"maxDailyBytesPerSender", true},
	{"maxDailyTransfersPerSender", true},
	{"maxRecipientsPerTransfer", true},
	{"blockOnExceed", false},
	{"unusualVolumeFactor", true},
	{"unusualMinHistoryDays", false},
	{"largeExternalTransferBytes", true},
	{"officeHours", true},
	{"timeZone", false},
	{"maxInvitationsPerInviter", false},
	{"externalMaxDailyBytes", true},
	{"externalMaxDailyDeposits", true},
}

// checkThresholdMembers checks that every member of the raw body is
// present, and that the ones that cannot be null are not. A body that is
// not a JSON object is refused as a whole.
func checkThresholdMembers(raw []byte) error { return checkMembers(raw, thresholdMembers) }

// checkMembers checks that every member of required is present in the raw
// body, and that the ones that cannot be null are not.
func checkMembers(raw []byte, required []bodyMember) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return validationFailed("", fieldInvalidFormat)
	}
	var errs []problem.FieldError
	for _, m := range required {
		v, ok := members[m.name]
		switch {
		case !ok:
			errs = append(errs, problem.FieldError{Field: "/" + m.name, Code: fieldRequired})
		case !m.nullable && bytes.Equal(bytes.TrimSpace(v), []byte("null")):
			errs = append(errs, problem.FieldError{Field: "/" + m.name, Code: fieldNotNullable})
		}
	}
	if len(errs) > 0 {
		return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(errs...))
	}
	return nil
}

// errNoThresholdsBody reports a server built without CaptureRawBody:
// a wiring error, answered 500.
var errNoThresholdsBody = errors.New("admin: raw body of the abuse thresholds missing (CaptureRawBody not installed)")

// GetAbuseThresholds returns the abuse detection settings of a tenant.
func (s *Server) GetAbuseThresholds(ctx context.Context, req gen.GetAbuseThresholdsRequestObject) (gen.GetAbuseThresholdsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := svc.AbuseThresholds(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetAbuseThresholds200JSONResponse(thresholdsBody(cur)), nil
}

// UpdateAbuseThresholds replaces the abuse detection settings of a tenant
// and returns them. Every member is required (null disables a rule).
func (s *Server) UpdateAbuseThresholds(ctx context.Context, req gen.UpdateAbuseThresholdsRequestObject) (gen.UpdateAbuseThresholdsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	if !ok {
		return nil, errNoThresholdsBody
	}
	in, err := thresholdsInput(raw, *req.Body)
	if err != nil {
		// A tenant the administrator cannot reach answers 404 whatever the
		// body: the access is probed before the validation error is shown.
		if _, perr := svc.AbuseThresholds(ctx, p, tenant.ID(req.TenantId)); perr != nil {
			return nil, tenantError(perr)
		}
		return nil, err
	}
	out, err := svc.UpdateAbuseThresholds(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateAbuseThresholds200JSONResponse(thresholdsBody(out)), nil
}

// thresholdsInput checks the members of the raw body and converts the
// decoded one.
func thresholdsInput(raw []byte, b gen.AbuseThresholds) (store.AbuseSettings, error) {
	if err := checkThresholdMembers(raw); err != nil {
		return store.AbuseSettings{}, err
	}
	return thresholdsSettings(b)
}

// thresholdsSettings converts the OpenAPI body to the settings of the
// store with tenantadmin.AbuseFromAPI, the conversion shared with the
// import. A value that cannot be converted names its field; the service
// checks the bounds.
func thresholdsSettings(b gen.AbuseThresholds) (store.AbuseSettings, error) {
	in := tenantadmin.ExportedAbuseThresholds{
		MaxDailyBytesPerSender: b.MaxDailyBytesPerSender, MaxDailyTransfersPerSender: b.MaxDailyTransfersPerSender,
		MaxRecipientsPerTransfer: b.MaxRecipientsPerTransfer, BlockOnExceed: b.BlockOnExceed,
		UnusualMinHistoryDays: b.UnusualMinHistoryDays, LargeExternalTransferBytes: b.LargeExternalTransferBytes,
		TimeZone: b.TimeZone, MaxInvitationsPerInviter: b.MaxInvitationsPerInviter,
		ExternalMaxDailyBytes: b.ExternalMaxDailyBytes, ExternalMaxDailyDeposits: b.ExternalMaxDailyDeposits,
	}
	if f := b.UnusualVolumeFactor; f != nil {
		v := float64(*f)
		in.UnusualVolumeFactor = &v
	}
	if oh := b.OfficeHours; oh != nil {
		in.OfficeHours = &tenantadmin.ExportedOfficeHours{Start: oh.Start, End: oh.End, Weekdays: oh.Weekdays}
	}
	out, err := tenantadmin.AbuseFromAPI(in)
	var ie *tenantadmin.InvalidError
	if errors.As(err, &ie) {
		return store.AbuseSettings{}, validationFailed(ie.Field, fieldInvalidFormat)
	}
	return out, err
}

// thresholdsBody renders the settings as the OpenAPI AbuseThresholds with
// tenantadmin.AbuseToAPI, the conversion shared with the export.
func thresholdsBody(s store.AbuseSettings) gen.AbuseThresholds {
	a := tenantadmin.AbuseToAPI(s)
	out := gen.AbuseThresholds{
		MaxDailyBytesPerSender: a.MaxDailyBytesPerSender, MaxDailyTransfersPerSender: a.MaxDailyTransfersPerSender,
		MaxRecipientsPerTransfer: a.MaxRecipientsPerTransfer, BlockOnExceed: a.BlockOnExceed,
		UnusualMinHistoryDays: a.UnusualMinHistoryDays, LargeExternalTransferBytes: a.LargeExternalTransferBytes,
		TimeZone: a.TimeZone, MaxInvitationsPerInviter: a.MaxInvitationsPerInviter,
		ExternalMaxDailyBytes: a.ExternalMaxDailyBytes, ExternalMaxDailyDeposits: a.ExternalMaxDailyDeposits,
	}
	if f := a.UnusualVolumeFactor; f != nil {
		f32 := float32(*f)
		out.UnusualVolumeFactor = &f32
	}
	if oh := a.OfficeHours; oh != nil {
		out.OfficeHours = &gen.OfficeHours{Start: oh.Start, End: oh.End, Weekdays: oh.Weekdays}
	}
	return out
}

// ListAbuseReports lists the abuse reports of a tenant, newest first.
func (s *Server) ListAbuseReports(ctx context.Context, req gen.ListAbuseReportsRequestObject) (gen.ListAbuseReportsResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListAbuseReports(ctx, p, tenant.ID(req.TenantId), store.AbuseReportStatus(deref(req.Params.Status)),
		deref(req.Params.Limit), deref(req.Params.Cursor))
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.ListAbuseReports200JSONResponse{Items: make([]gen.AbuseReport, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, r := range page.Items {
		resp.Items[i] = abuseReportBody(r)
	}
	return resp, nil
}

// GetAbuseReport returns one abuse report of a tenant.
func (s *Server) GetAbuseReport(ctx context.Context, req gen.GetAbuseReportRequestObject) (gen.GetAbuseReportResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	r, err := svc.GetAbuseReport(ctx, p, tenant.ID(req.TenantId), req.ReportId)
	if err != nil {
		return nil, operationError(err)
	}
	return gen.GetAbuseReport200JSONResponse(abuseReportBody(r)), nil
}

// UpdateAbuseReport closes or reopens an abuse report, with an optional
// note (merge patch: the note is kept when absent).
func (s *Server) UpdateAbuseReport(ctx context.Context, req gen.UpdateAbuseReportRequestObject) (gen.UpdateAbuseReportResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	r, err := svc.UpdateAbuseReport(ctx, p, tenant.ID(req.TenantId), req.ReportId, store.AbuseReportStatus(req.Body.Status),
		req.Body.Note, middleware.ClientIP(ctx))
	if err != nil {
		return nil, operationError(err)
	}
	return gen.UpdateAbuseReport200JSONResponse(abuseReportBody(r)), nil
}

// abuseReportBody renders r as the OpenAPI AbuseReport: the reporter,
// the note and the closing are absent when empty, the recipient index is
// 1-based.
func abuseReportBody(r store.AbuseReport) gen.AbuseReport {
	msg := r.Message
	out := gen.AbuseReport{
		Id: r.ID, TransferId: r.TransferID, SenderEmail: r.SenderEmail, ReporterVerified: r.ReporterVerified,
		Category: gen.AbuseReportCategory(r.Category), Message: &msg, Status: gen.AbuseReportStatus(r.Status),
		ReportedAt: r.CreatedAt, ReportedBy: optional(r.ReporterEmail), Note: optional(r.Note),
		ClosedBy: optional(r.ClosedBy), ClosedAt: optionalTime(r.ClosedAt),
	}
	if r.RecipientPosition != nil {
		i := *r.RecipientPosition + 1
		out.RecipientIndex = &i
	}
	return out
}
