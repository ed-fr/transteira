package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Abuse detection operations (since 1.1, CLAUDE.md sections 15 and 10): the
// thresholds of a tenant and the abuse reports of its recipients.

// thresholdsPath is the end of the path of the abuse thresholds, whose
// update needs the raw body (see CaptureThresholdsBody).
const thresholdsPath = "/abuse-thresholds"

// rawBodyKey is the context key of the raw body of an abuse thresholds
// update.
type rawBodyKey struct{}

// CaptureThresholdsBody is a middleware keeping the raw body of the abuse
// thresholds update in the request context, and only that one: every
// member of the body is required, and the generated type cannot tell a
// member that is absent from one that is null. The body is read after the
// body limit middleware, so it is bounded; it is handed back unchanged to
// the generated decoder.
func CaptureThresholdsBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, thresholdsPath) || r.Body == nil {
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
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rawBodyKey{}, raw)))
	})
}

// failingReader returns err on every read.
type failingReader struct{ err error }

// Read implements io.Reader.
func (f *failingReader) Read([]byte) (int, error) { return 0, f.err }

// thresholdMembers lists the members of the thresholds body, every one
// required, in the order their errors are reported; nullable tells whether
// the member may be null.
var thresholdMembers = []struct {
	name     string
	nullable bool
}{
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
func checkThresholdMembers(raw []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return validationFailed("", fieldInvalidFormat)
	}
	var errs []problem.FieldError
	for _, m := range thresholdMembers {
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

// errNoThresholdsBody reports a server built without CaptureThresholdsBody:
// a wiring error, answered 500.
var errNoThresholdsBody = errors.New("admin: raw body of the abuse thresholds missing (CaptureThresholdsBody not installed)")

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

// Office hours and unusual volume conversions.
const (
	officeEndOfDay   = "24:00"
	minutesPerHour   = 60
	minutesPerDay    = 24 * minutesPerHour
	maxVolumePercent = math.MaxInt32
)

// thresholdsSettings converts the OpenAPI body to the settings of the
// store: the unusual volume factor becomes a percentage, the office hours
// minutes of the day and a weekday mask. A value that cannot be converted
// names its field; the service checks the bounds.
func thresholdsSettings(b gen.AbuseThresholds) (store.AbuseSettings, error) {
	out := store.AbuseSettings{
		MaxDailyBytesPerSender: b.MaxDailyBytesPerSender, MaxDailyTransfersPerSender: b.MaxDailyTransfersPerSender,
		MaxRecipientsPerTransfer: b.MaxRecipientsPerTransfer, BlockOnExceed: b.BlockOnExceed,
		UnusualMinHistoryDays: b.UnusualMinHistoryDays, LargeExternalTransferBytes: b.LargeExternalTransferBytes,
		TimeZone: b.TimeZone, MaxInvitationsPerInviter: b.MaxInvitationsPerInviter,
		ExternalMaxDailyBytes: b.ExternalMaxDailyBytes, ExternalMaxDailyDeposits: b.ExternalMaxDailyDeposits,
	}
	if f := b.UnusualVolumeFactor; f != nil {
		pct := maxVolumePercent
		if v := math.Round(float64(*f) * 100); v < maxVolumePercent {
			pct = int(v)
		}
		out.UnusualVolumePct = &pct
	}
	if oh := b.OfficeHours; oh != nil {
		start, ok := parseClock(oh.Start, false)
		if !ok {
			return store.AbuseSettings{}, validationFailed(tenantadmin.FieldOfficeHours+"/start", fieldInvalidFormat)
		}
		end, ok := parseClock(oh.End, true)
		if !ok {
			return store.AbuseSettings{}, validationFailed(tenantadmin.FieldOfficeHours+"/end", fieldInvalidFormat)
		}
		mask, ok := weekdayMask(oh.Weekdays)
		if !ok {
			return store.AbuseSettings{}, validationFailed(tenantadmin.FieldOfficeHoursWeekdays, fieldInvalidFormat)
		}
		out.OfficeStartMinute, out.OfficeEndMinute, out.OfficeWeekdays = &start, &end, mask
	}
	return out, nil
}

// weekdayMask converts ISO 8601 weekdays (1 = Monday ... 7 = Sunday) to
// the mask of the store (bit 0 = Monday). It reports false for an empty
// list, a day out of range or a duplicate day (OpenAPI minItems 1 and
// uniqueItems).
func weekdayMask(days []int) (int, bool) {
	mask := 0
	for _, d := range days {
		if d < 1 || d > 7 || mask&(1<<(d-1)) != 0 {
			return 0, false
		}
		mask |= 1 << (d - 1)
	}
	return mask, mask != 0
}

// parseClock parses "HH:MM" (00:00 to 23:59), and "24:00" when allowEnd,
// to minutes of the day.
func parseClock(s string, allowEnd bool) (int, bool) {
	if allowEnd && s == officeEndOfDay {
		return minutesPerDay, true
	}
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*minutesPerHour + mm, true
}

// formatClock renders minutes of the day as HH:MM ("24:00" for the end).
func formatClock(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/minutesPerHour, minutes%minutesPerHour)
}

// thresholdsBody renders the settings as the OpenAPI AbuseThresholds.
func thresholdsBody(s store.AbuseSettings) gen.AbuseThresholds {
	out := gen.AbuseThresholds{
		MaxDailyBytesPerSender: s.MaxDailyBytesPerSender, MaxDailyTransfersPerSender: s.MaxDailyTransfersPerSender,
		MaxRecipientsPerTransfer: s.MaxRecipientsPerTransfer, BlockOnExceed: s.BlockOnExceed,
		UnusualMinHistoryDays: s.UnusualMinHistoryDays, LargeExternalTransferBytes: s.LargeExternalTransferBytes,
		TimeZone: s.TimeZone, MaxInvitationsPerInviter: s.MaxInvitationsPerInviter,
		ExternalMaxDailyBytes: s.ExternalMaxDailyBytes, ExternalMaxDailyDeposits: s.ExternalMaxDailyDeposits,
	}
	if s.UnusualVolumePct != nil {
		f := float32(*s.UnusualVolumePct) / 100
		out.UnusualVolumeFactor = &f
	}
	if s.OfficeStartMinute != nil && s.OfficeEndMinute != nil {
		days := []int{}
		for d := 1; d <= 7; d++ {
			if s.OfficeWeekdays&(1<<(d-1)) != 0 {
				days = append(days, d)
			}
		}
		out.OfficeHours = &gen.OfficeHours{
			Start: formatClock(*s.OfficeStartMinute), End: formatClock(*s.OfficeEndMinute), Weekdays: days,
		}
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
