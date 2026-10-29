package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/datasubject"
	"github.com/ed-fr/transteira/internal/stats"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// recorder records the calls of a fake service and answers err (only for
// the method errAt when it is set).
type recorder struct {
	err   error
	errAt string
	calls []string
	args  map[string][]any
}

func (r *recorder) record(name string, args ...any) error {
	r.calls = append(r.calls, name)
	if r.args == nil {
		r.args = map[string][]any{}
	}
	r.args[name] = args
	if r.errAt != "" && r.errAt != name {
		return nil
	}
	return r.err
}

var (
	sampleTransfer = tenantops.Transfer{
		ID: "trf_01", Status: store.TransferAvailable, Origin: tenantops.OriginInternal,
		SenderEmail: "alice@entity-a.example.com", Recipients: []string{"carol@customer.example.net"},
		FileCount: 1, TotalBytes: 2048, PasswordProtected: true, CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(24 * time.Hour), DownloadCount: 3,
	}
	sampleDetail = tenantops.TransferDetail{
		Transfer: sampleTransfer, SenderIP: netip.MustParseAddr("10.10.4.21"),
		Files: []tenantops.File{
			{ID: "fil_01", Name: "plans.pdf", Size: 2048, MediaType: "application/pdf", SHA256: strings.Repeat("a", 64), ScanStatus: store.ScanClean},
			{ID: "fil_02", Name: "big.bin", Size: 1, ScanStatus: store.ScanPending},
		},
	}
	sampleInvitation = tenantops.Invitation{
		ID: "inv_01", Email: "bob@partner.example.org", InvitedBy: "erased-0123456789abcdef", Status: store.InvitationRevoked,
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	sampleEntry = store.BlocklistEntry{
		ID: "blk_01", Kind: store.BlockDomain, Value: "spam.example.net", Comment: "abuse", CreatedBy: "admin.entity-a", CreatedAt: now,
	}
	sampleEvents = []store.AuditEvent{
		{
			ID: "aud_01", At: now, TenantID: "ten_a", ActorKind: store.ActorDepositor, Actor: "alice@entity-a.example.com",
			IP: netip.MustParseAddr("10.10.4.21"), Action: "transfer.finalized", ObjectKind: "transfer", ObjectID: "trf_01",
			Details: json.RawMessage(`{"fileCount":2}`),
		},
		{ID: "aud_02", At: now, ActorKind: store.ActorAdmin, Actor: "root", Action: "maintenance.enabled", ObjectKind: "system", ObjectID: "maintenance"},
		{ID: "aud_03", At: now, ActorKind: store.ActorSystem, Actor: "quota", Action: "quota.warning", ObjectKind: "tenant", ObjectID: "ten_a", Details: json.RawMessage(`null`)},
	}
)

// fakeOps is a fake OperationsService.
type fakeOps struct {
	recorder
	transfer   tenantops.Transfer
	detail     tenantops.TransferDetail
	invitation tenantops.Invitation
	events     []store.AuditEvent
	next       string
}

func newFakeOps() *fakeOps {
	return &fakeOps{transfer: sampleTransfer, detail: sampleDetail, invitation: sampleInvitation, events: sampleEvents}
}

func (f *fakeOps) ListTransfers(_ context.Context, p adminauth.Principal, tid tenant.ID, fl tenantops.TransferFilter) (store.Page[tenantops.Transfer], error) {
	return store.Page[tenantops.Transfer]{Items: []tenantops.Transfer{f.transfer}, NextCursor: f.next}, f.record("ListTransfers", p.SessionID, tid, fl)
}

func (f *fakeOps) GetTransfer(_ context.Context, p adminauth.Principal, tid tenant.ID, trfID string) (tenantops.TransferDetail, error) {
	return f.detail, f.record("GetTransfer", p.SessionID, tid, trfID)
}

func (f *fakeOps) DeleteTransfer(_ context.Context, p adminauth.Principal, tid tenant.ID, trfID, reason string, ip netip.Addr) error {
	return f.record("DeleteTransfer", p.SessionID, tid, trfID, reason, ip)
}

func (f *fakeOps) ResendNotification(_ context.Context, p adminauth.Principal, tid tenant.ID, trfID string, recipients []string, ip netip.Addr) error {
	return f.record("ResendNotification", p.SessionID, tid, trfID, recipients, ip)
}

func (f *fakeOps) ListInvitations(_ context.Context, p adminauth.Principal, tid tenant.ID, fl tenantops.InvitationFilter) (store.Page[tenantops.Invitation], error) {
	return store.Page[tenantops.Invitation]{Items: []tenantops.Invitation{f.invitation}, NextCursor: f.next}, f.record("ListInvitations", p.SessionID, tid, fl)
}

func (f *fakeOps) RevokeInvitation(_ context.Context, p adminauth.Principal, tid tenant.ID, invID string, ip netip.Addr) error {
	return f.record("RevokeInvitation", p.SessionID, tid, invID, ip)
}

func (f *fakeOps) ListBlocklist(_ context.Context, p adminauth.Principal, tid tenant.ID, fl tenantops.BlocklistFilter) (store.Page[store.BlocklistEntry], error) {
	return store.Page[store.BlocklistEntry]{Items: []store.BlocklistEntry{sampleEntry}, NextCursor: f.next}, f.record("ListBlocklist", p.SessionID, tid, fl)
}

func (f *fakeOps) CreateBlocklistEntry(_ context.Context, p adminauth.Principal, tid tenant.ID, in tenantops.BlocklistInput, ip netip.Addr) (store.BlocklistEntry, error) {
	e := store.BlocklistEntry{ID: "blk_02", Kind: store.BlocklistKind(in.Kind), Value: in.Value, Comment: in.Comment, CreatedBy: "root", CreatedAt: now}
	return e, f.record("CreateBlocklistEntry", p.SessionID, tid, in, ip)
}

func (f *fakeOps) DeleteBlocklistEntry(_ context.Context, p adminauth.Principal, tid tenant.ID, entryID string, ip netip.Addr) error {
	return f.record("DeleteBlocklistEntry", p.SessionID, tid, entryID, ip)
}

func (f *fakeOps) ListAuditEvents(_ context.Context, p adminauth.Principal, tid tenant.ID, fl tenantops.AuditFilter) (store.Page[store.AuditEvent], error) {
	return store.Page[store.AuditEvent]{Items: f.events, NextCursor: f.next}, f.record("ListAuditEvents", p.SessionID, tid, fl)
}

func (f *fakeOps) ListGlobalAuditEvents(_ context.Context, p adminauth.Principal, fl tenantops.GlobalAuditFilter) (store.Page[store.AuditEvent], error) {
	return store.Page[store.AuditEvent]{Items: f.events, NextCursor: f.next}, f.record("ListGlobalAuditEvents", p.SessionID, fl)
}

// fakeSubjects is a fake DataSubjectService.
type fakeSubjects struct {
	recorder
	summary datasubject.Summary
}

func (f *fakeSubjects) Search(_ context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, email string) (datasubject.Summary, error) {
	return f.summary, f.record("Search", p.SessionID, ip, tid, email)
}

func (f *fakeSubjects) Erase(_ context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, email string) (datasubject.EraseReport, error) {
	return datasubject.EraseReport{
		TransfersDeleted: 1, RecipientEntriesRemoved: 2, VerifiedAddressDeleted: true, InvitationsDeleted: 3, LogEntriesPseudonymised: 4,
		AccessLinks: 5,
	}, f.record("Erase", p.SessionID, ip, tid, email)
}

// fakeStats is a fake StatsService.
type fakeStats struct {
	recorder
	global stats.GlobalStats
}

func (f *fakeStats) TenantStats(_ context.Context, p adminauth.Principal, tid tenant.ID, period stats.Period) (stats.TenantStats, error) {
	st := stats.TenantStats{
		Period: period,
		UsageCounts: store.UsageCounts{
			Transfers: 5, BytesUploaded: 500, Downloads: 6, BytesDownloaded: 600, VirusDetections: 1,
		},
		Storage: stats.Storage{UsedBytes: 250, QuotaBytes: 1000, UsedRatio: 0.25},
		Series: []stats.Point{
			{Date: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), Transfers: 2, BytesUploaded: 200},
			{Date: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), Transfers: 3, BytesUploaded: 300},
		},
	}
	return st, f.record("TenantStats", p.SessionID, tid, period)
}

func (f *fakeStats) GlobalStats(_ context.Context, p adminauth.Principal, period stats.Period) (stats.GlobalStats, error) {
	g := f.global
	g.Period = period
	return g, f.record("GlobalStats", p.SessionID, period)
}

// opsServer returns a server over the three fakes.
func opsServer(ops OperationsService, subjects DataSubjectService, st StatsService) *Server {
	s := NewServer(WithOperationsService(ops), WithDataSubjectService(subjects), WithStatsService(st))
	s.now = func() time.Time { return now }
	return s
}

// operationCalls calls every operation of s with a minimal valid request
// and returns the errors, by operation name.
func operationCalls(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	var err error
	_, err = s.ListTenantTransfers(ctx, gen.ListTenantTransfersRequestObject{TenantId: "ten_a"})
	out["ListTransfers"] = err
	_, err = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	out["GetTransfer"] = err
	_, err = s.DeleteTenantTransfer(ctx, gen.DeleteTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	out["DeleteTransfer"] = err
	_, err = s.ResendTransferNotification(ctx, gen.ResendTransferNotificationRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	out["ResendNotification"] = err
	_, err = s.ListTenantInvitations(ctx, gen.ListTenantInvitationsRequestObject{TenantId: "ten_a"})
	out["ListInvitations"] = err
	_, err = s.RevokeInvitation(ctx, gen.RevokeInvitationRequestObject{TenantId: "ten_a", InvitationId: "inv_01"})
	out["RevokeInvitation"] = err
	_, err = s.ListBlocklist(ctx, gen.ListBlocklistRequestObject{TenantId: "ten_a"})
	out["ListBlocklist"] = err
	_, err = s.CreateBlocklistEntry(ctx, gen.CreateBlocklistEntryRequestObject{TenantId: "ten_a", Body: &gen.BlocklistEntryCreate{}})
	out["CreateBlocklistEntry"] = err
	_, err = s.DeleteBlocklistEntry(ctx, gen.DeleteBlocklistEntryRequestObject{TenantId: "ten_a", EntryId: "blk_01"})
	out["DeleteBlocklistEntry"] = err
	_, err = s.ListTenantAuditEvents(ctx, gen.ListTenantAuditEventsRequestObject{TenantId: "ten_a"})
	out["ListAuditEvents"] = err
	_, err = s.ListGlobalAuditEvents(ctx, gen.ListGlobalAuditEventsRequestObject{})
	out["ListGlobalAuditEvents"] = err
	_, err = s.GetTenantStats(ctx, gen.GetTenantStatsRequestObject{TenantId: "ten_a"})
	out["TenantStats"] = err
	_, err = s.GetGlobalStats(ctx, gen.GetGlobalStatsRequestObject{})
	out["GlobalStats"] = err
	_, err = s.SearchDataSubject(ctx, gen.SearchDataSubjectRequestObject{TenantId: "ten_a", Body: &gen.DataSubjectRequest{Email: "carol@customer.example.net"}})
	out["Search"] = err
	_, err = s.EraseDataSubject(ctx, gen.EraseDataSubjectRequestObject{TenantId: "ten_a", Body: &gen.DataSubjectRequest{Email: "carol@customer.example.net"}})
	out["Erase"] = err
	return out
}

func TestOperationsWiring(t *testing.T) {
	t.Parallel()
	wiring := map[string]error{
		"ListTransfers": errNoOperationsService, "GetTransfer": errNoOperationsService, "DeleteTransfer": errNoOperationsService,
		"ResendNotification": errNoOperationsService, "ListInvitations": errNoOperationsService,
		"RevokeInvitation": errNoOperationsService, "ListBlocklist": errNoOperationsService,
		"CreateBlocklistEntry": errNoOperationsService, "DeleteBlocklistEntry": errNoOperationsService,
		"ListAuditEvents": errNoOperationsService, "ListGlobalAuditEvents": errNoOperationsService,
		"TenantStats": errNoStatsService, "GlobalStats": errNoStatsService,
		"Search": errNoDataSubjectService, "Erase": errNoDataSubjectService,
	}
	// Without services: 500 (wiring error), whatever the session.
	ops := operationCalls(ctxWith(store.SessionAuthenticated, superRoot), NewServer())
	if len(ops) != 15 {
		t.Fatalf("%d operations, want 15", len(ops))
	}
	for name, err := range ops {
		if !errors.Is(err, wiring[name]) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	// Without session in the context: 401 before the services.
	o, d, st := newFakeOps(), &fakeSubjects{}, &fakeStats{}
	for name, err := range operationCalls(ctxWith("", superRoot), opsServer(o, d, st)) {
		if p := expectProblem(t, err, problem.CodeUnauthenticated); p.Code == "" {
			t.Error(name)
		}
	}
	if len(o.calls)+len(d.calls)+len(st.calls) != 0 {
		t.Errorf("services called without session: %v %v %v", o.calls, d.calls, st.calls)
	}
	// Every operation reaches its service with the session; a service
	// error is mapped.
	o, d, st = newFakeOps(), &fakeSubjects{}, &fakeStats{}
	o.err, d.err, st.err = tenantops.ErrNotFound, datasubject.ErrNotFound, stats.ErrNotFound
	for name, err := range operationCalls(ctxWith(store.SessionAuthenticated, delegated), opsServer(o, d, st)) {
		expectProblem(t, err, problem.CodeNotFound)
		args := o.args[name]
		if args == nil {
			args = d.args[name]
		}
		if args == nil {
			args = st.args[name]
		}
		if len(args) == 0 || args[0] != "as_01" {
			t.Errorf("%s: service args %v", name, args)
		}
	}
}

func TestOperationErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		err   error
		code  problem.Code
		field string
		retry int
		// fieldCode is the code of the field error (invalid-format when empty).
		fieldCode string
	}{
		{&tenantops.InvalidError{Field: tenantops.FieldStatus}, problem.CodeValidationFailed, "status", -1, ""},
		{&tenantops.InvalidError{Field: tenantops.FieldReason}, problem.CodeValidationFailed, "/reason", -1, ""},
		{&tenantops.InvalidError{Field: "/recipients/1", NotAnAddress: true}, problem.CodeValidationFailed, "/recipients/1", -1, fieldInvalidEmail},
		{&tenantops.InvalidError{Field: "/recipients/0"}, problem.CodeValidationFailed, "/recipients/0", -1, ""},
		{&datasubject.InvalidError{Field: datasubject.FieldEmail}, problem.CodeValidationFailed, "/email", -1, fieldInvalidEmail},
		{&datasubject.InvalidError{Field: "/other"}, problem.CodeValidationFailed, "/other", -1, ""},
		{stats.ErrInvalidPeriod, problem.CodeValidationFailed, "period", -1, ""},
		{tenantops.ErrInvalid, problem.CodeValidationFailed, "", -1, ""},
		{datasubject.ErrInvalid, problem.CodeValidationFailed, "", -1, ""},
		{&tenantops.BusyError{RetryAfter: 5 * time.Second}, problem.CodeStateConflict, "", 5, ""},
		{fmt.Errorf("erase: %w", datasubject.ErrBusy), problem.CodeStateConflict, "", int(datasubject.RetryAfter / time.Second), ""},
		{tenantops.ErrNotAvailable, problem.CodeStateConflict, "", -1, ""},
		{tenantops.ErrBusy, problem.CodeStateConflict, "", -1, ""},
		{&tenantops.RateLimitError{RetryAfter: 90 * time.Second}, problem.CodeRateLimited, "", 90, ""},
		{tenantops.ErrRateLimited, problem.CodeRateLimited, "", -1, ""},
		{tenantops.ErrMailUnavailable, problem.CodeMailUnavailable, "", -1, ""},
		{tenantops.ErrUnauthenticated, problem.CodeUnauthenticated, "", -1, ""},
		{tenantops.ErrForbidden, problem.CodeForbidden, "", -1, ""},
		{stats.ErrForbidden, problem.CodeForbidden, "", -1, ""},
		{tenantops.ErrNotFound, problem.CodeNotFound, "", -1, ""},
		{tenantops.ErrAlreadyExists, problem.CodeAlreadyExists, "", -1, ""},
	}
	for _, tt := range tests {
		p := expectProblem(t, operationError(tt.err), tt.code)
		switch {
		case tt.field != "":
			want := tt.fieldCode
			if want == "" {
				want = fieldInvalidFormat
			}
			if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: tt.field, Code: want}}) {
				t.Errorf("%v: field errors %+v", tt.err, p.Errors)
			}
		case len(p.Errors) != 0:
			t.Errorf("%v: unexpected field errors %+v", tt.err, p.Errors)
		}
		switch {
		case tt.retry >= 0 && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != tt.retry):
			t.Errorf("%v: retry after %v, want %d", tt.err, p.RetryAfterSeconds, tt.retry)
		case tt.retry < 0 && p.RetryAfterSeconds != nil:
			t.Errorf("%v: unexpected retry after %d", tt.err, *p.RetryAfterSeconds)
		}
	}
	if err := operationError(boom); !errors.Is(err, boom) {
		t.Errorf("internal error: %v", err)
	}
	if p := problem.From(operationError(tenantops.ErrMailUnavailable)); p.Status != http.StatusServiceUnavailable {
		t.Errorf("mail-unavailable status %d", p.Status)
	}
}

// decode renders resp through its Visit method and decodes the JSON body
// into a generic map.
func decode(t *testing.T, resp any) (int, map[string]any) {
	t.Helper()
	rec := visit(t, resp)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

func TestTransferOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	o := newFakeOps()
	s := opsServer(o, nil, nil)
	after := now.Add(-48 * time.Hour)
	status, mailAddr := gen.TransferStatus("available"), gen.Email("alice@entity-a.example.com")

	resp, err := s.ListTenantTransfers(ctx, gen.ListTenantTransfersRequestObject{TenantId: "ten_a", Params: gen.ListTenantTransfersParams{
		Status: &status, Email: &mailAddr, CreatedAfter: &after, Limit: ptr(10), Cursor: ptr("c1"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := tenantops.TransferFilter{Status: "available", Email: "alice@entity-a.example.com", CreatedAfter: after, Cursor: "c1", Limit: 10}
	if got := o.args["ListTransfers"]; got[1] != tenant.ID("ten_a") || !reflect.DeepEqual(got[2], want) {
		t.Errorf("list args %v", got)
	}
	code, body := decode(t, resp)
	items := body["items"].([]any)
	item := items[0].(map[string]any)
	if code != http.StatusOK || len(items) != 1 || item["senderEmail"] != "alice@entity-a.example.com" ||
		item["origin"] != "internal" || item["downloadCount"] != float64(3) || item["passwordProtected"] != true {
		t.Errorf("list = %d %v", code, body)
	}
	if _, ok := body["nextCursor"]; ok {
		t.Error("nextCursor present on the last page")
	}
	for _, absent := range []string{"invitationId", "firstDownloadedAt", "apiTokenId"} {
		if _, ok := item[absent]; ok {
			t.Errorf("%s present: %v", absent, item)
		}
	}
	o.next = "c2"
	o.transfer.Recipients = nil
	resp, _ = s.ListTenantTransfers(ctx, gen.ListTenantTransfersRequestObject{TenantId: "ten_a"})
	if _, body = decode(t, resp); body["nextCursor"] != "c2" {
		t.Errorf("nextCursor = %v", body["nextCursor"])
	}
	if r, ok := body["items"].([]any)[0].(map[string]any)["recipients"].([]any); !ok || len(r) != 0 {
		t.Errorf("no recipient rendered as %v", body["items"])
	}

	got, err := s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	if err != nil {
		t.Fatal(err)
	}
	code, body = decode(t, got)
	files := body["files"].([]any)
	f0, f1 := files[0].(map[string]any), files[1].(map[string]any)
	if code != http.StatusOK || body["senderIp"] != "10.10.4.21" || len(files) != 2 || f0["sha256"] != strings.Repeat("a", 64) ||
		f0["mediaType"] != "application/pdf" || f0["scanStatus"] != "clean" || body["fileCount"] != float64(1) {
		t.Errorf("detail = %d %v", code, body)
	}
	if _, ok := f1["sha256"]; ok {
		t.Errorf("empty fingerprint rendered: %v", f1)
	}
	if _, ok := f1["mediaType"]; ok {
		t.Errorf("empty media type rendered: %v", f1)
	}
	o.detail.SenderIP = netip.Addr{}
	got, _ = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	if _, body = decode(t, got); body["senderIp"] != nil {
		t.Errorf("unknown sender IP rendered: %v", body["senderIp"])
	}

	// A transfer created with an API token names it.
	o.transfer.Origin, o.transfer.APITokenID = tenantops.OriginAPI, "tok_01"
	o.detail.Origin, o.detail.APITokenID = tenantops.OriginAPI, "tok_01"
	resp, _ = s.ListTenantTransfers(ctx, gen.ListTenantTransfersRequestObject{TenantId: "ten_a"})
	_, body = decode(t, resp)
	if item := body["items"].([]any)[0].(map[string]any); item["origin"] != "api" || item["apiTokenId"] != "tok_01" {
		t.Errorf("token transfer listed as %v", item)
	}
	got, _ = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	if _, body = decode(t, got); body["origin"] != "api" || body["apiTokenId"] != "tok_01" {
		t.Errorf("token transfer detail = %v", body)
	}

	// The confidentiality snapshot and the download limit (version 1.1).
	if body["recipientVerification"] != false || body["confidentialityLevel"] != nil || body["maxDownloads"] != nil {
		t.Errorf("transfer without level = %v", body)
	}
	maxDl, maxCap := 3, 5
	level := tenantops.Transfer{
		MaxDownloads: &maxDl, ConfidentialityLevel: "secret", ConfidentialityLabel: "Secret",
		Rules: &store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMask1Day | store.ExpiryMask7Days, MaxDownloadsCap: &maxCap, RequirePassword: true},
	}
	o.transfer.MaxDownloads, o.transfer.ConfidentialityLevel, o.transfer.ConfidentialityLabel, o.transfer.Rules =
		level.MaxDownloads, level.ConfidentialityLevel, level.ConfidentialityLabel, level.Rules
	o.detail.Transfer = o.transfer
	resp, _ = s.ListTenantTransfers(ctx, gen.ListTenantTransfersRequestObject{TenantId: "ten_a"})
	_, body = decode(t, resp)
	listed := body["items"].([]any)[0].(map[string]any)
	ref, _ := listed["confidentialityLevel"].(map[string]any)
	if listed["maxDownloads"] != float64(3) || listed["recipientVerification"] != false || ref["key"] != "secret" || ref["label"] != "Secret" {
		t.Errorf("listed level = %v", listed)
	}
	got, _ = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	_, body = decode(t, got)
	ref, _ = body["confidentialityLevel"].(map[string]any)
	rules, _ := ref["rules"].(map[string]any)
	if body["maxDownloads"] != float64(3) || rules["maxDownloads"] != float64(5) || rules["requirePassword"] != true ||
		len(rules["allowedExpiryDays"].([]any)) != 2 || rules["internalRecipientsOnly"] != false {
		t.Errorf("detail level = %v", body)
	}
	o.transfer.Rules = nil
	o.detail.Transfer = o.transfer
	got, _ = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	if _, body = decode(t, got); body["confidentialityLevel"].(map[string]any)["rules"] != nil {
		t.Errorf("level without rules = %v", body["confidentialityLevel"])
	}
	if _, ok := body["recipientTracking"]; ok {
		t.Errorf("tracking of a shared transfer: %v", body["recipientTracking"])
	}

	// A transfer with one link per recipient: its verification option and
	// the tracking of each recipient, never a link.
	o.transfer.RecipientVerification = true
	o.detail.Transfer = o.transfer
	o.detail.RecipientTracking = []store.RecipientTracking{{LinkID: "rcl_01", Email: "carol@customer.example.net"}}
	got, _ = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	_, body = decode(t, got)
	tracking, _ := body["recipientTracking"].([]any)
	if body["recipientVerification"] != true || len(tracking) != 1 ||
		tracking[0].(map[string]any)["email"] != "carol@customer.example.net" || strings.Contains(fmt.Sprint(body), "rcl_") {
		t.Errorf("per-recipient detail = %v", body)
	}
	// Before its links exist: an empty tracking, telling it from a shared
	// transfer.
	o.detail.RecipientTracking = []store.RecipientTracking{}
	got, _ = s.GetTenantTransfer(ctx, gen.GetTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01"})
	_, body = decode(t, got)
	if tracking, ok := body["recipientTracking"].([]any); !ok || len(tracking) != 0 {
		t.Errorf("per-recipient detail before the links = %v", body)
	}
	o.detail.RecipientTracking = nil

	del, err := s.DeleteTenantTransfer(ctx, gen.DeleteTenantTransferRequestObject{
		TenantId: "ten_a", TransferId: "trf_01", Body: &gen.AdminReason{Reason: ptr("wrong recipient")},
	})
	if err != nil || visit(t, del).Code != http.StatusNoContent {
		t.Fatalf("delete = %v, %v", del, err)
	}
	if args := o.args["DeleteTransfer"]; args[3] != "wrong recipient" || args[4] != clientIP {
		t.Errorf("delete args %v", args)
	}
	if _, err := s.DeleteTenantTransfer(ctx, gen.DeleteTenantTransferRequestObject{TenantId: "ten_a", TransferId: "trf_01", Body: &gen.AdminReason{}}); err != nil {
		t.Fatal(err)
	}
	if args := o.args["DeleteTransfer"]; args[3] != "" {
		t.Errorf("delete without reason args %v", args)
	}

	recipients := []gen.Email{"carol@customer.example.net"}
	res, err := s.ResendTransferNotification(ctx, gen.ResendTransferNotificationRequestObject{
		TenantId: "ten_a", TransferId: "trf_01", Body: &gen.ResendRequest{Recipients: &recipients},
	})
	if err != nil || visit(t, res).Code != http.StatusAccepted {
		t.Fatalf("resend = %v, %v", res, err)
	}
	if args := o.args["ResendNotification"]; !reflect.DeepEqual(args[3], []string{"carol@customer.example.net"}) || args[4] != clientIP {
		t.Errorf("resend args %v", args)
	}
	if _, err := s.ResendTransferNotification(ctx, gen.ResendTransferNotificationRequestObject{
		TenantId: "ten_a", TransferId: "trf_01", Body: &gen.ResendRequest{},
	}); err != nil {
		t.Fatal(err)
	}
	if args := o.args["ResendNotification"]; args[3] != nil && len(args[3].([]string)) != 0 {
		t.Errorf("resend to all args %v", args)
	}
}

func TestInvitationAndBlocklistOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	o := newFakeOps()
	s := opsServer(o, nil, nil)
	invStatus := gen.InvitationStatus("revoked")
	resp, err := s.ListTenantInvitations(ctx, gen.ListTenantInvitationsRequestObject{TenantId: "ten_a", Params: gen.ListTenantInvitationsParams{
		Status: &invStatus, Limit: ptr(5), Cursor: ptr("c"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if args := o.args["ListInvitations"]; !reflect.DeepEqual(args[2], tenantops.InvitationFilter{Status: "revoked", Cursor: "c", Limit: 5}) {
		t.Errorf("invitation args %v", args)
	}
	_, body := decode(t, resp)
	item := body["items"].([]any)[0].(map[string]any)
	if item["invitedBy"] != "erased-0123456789abcdef" || item["email"] != "bob@partner.example.org" || item["status"] != "revoked" {
		t.Errorf("invitation = %v", item)
	}
	if _, ok := item["lastUsedAt"]; ok {
		t.Errorf("lastUsedAt of an unused invitation: %v", item)
	}
	if _, ok := body["nextCursor"]; ok {
		t.Error("nextCursor on the last page")
	}
	rev, err := s.RevokeInvitation(ctx, gen.RevokeInvitationRequestObject{TenantId: "ten_a", InvitationId: "inv_01"})
	if err != nil || visit(t, rev).Code != http.StatusNoContent {
		t.Fatalf("revoke = %v, %v", rev, err)
	}
	if args := o.args["RevokeInvitation"]; args[2] != "inv_01" || args[3] != clientIP {
		t.Errorf("revoke args %v", args)
	}

	kind := gen.BlocklistKind("domain")
	list, err := s.ListBlocklist(ctx, gen.ListBlocklistRequestObject{TenantId: "ten_a", Params: gen.ListBlocklistParams{Kind: &kind, Limit: ptr(3), Cursor: ptr("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if args := o.args["ListBlocklist"]; !reflect.DeepEqual(args[2], tenantops.BlocklistFilter{Kind: "domain", Cursor: "x", Limit: 3}) {
		t.Errorf("blocklist args %v", args)
	}
	if _, body = decode(t, list); body["items"].([]any)[0].(map[string]any)["comment"] != "abuse" {
		t.Errorf("blocklist = %v", body)
	}
	created, err := s.CreateBlocklistEntry(ctx, gen.CreateBlocklistEntryRequestObject{TenantId: "ten_a", Body: &gen.BlocklistEntryCreate{
		Kind: "email", Value: "mallory@example.net",
	}})
	if err != nil {
		t.Fatal(err)
	}
	code, body := decode(t, created)
	if code != http.StatusCreated || body["value"] != "mallory@example.net" || body["kind"] != "email" || body["createdBy"] != "root" {
		t.Errorf("created = %d %v", code, body)
	}
	if _, ok := body["comment"]; ok {
		t.Errorf("empty comment rendered: %v", body)
	}
	if args := o.args["CreateBlocklistEntry"]; !reflect.DeepEqual(args[2], tenantops.BlocklistInput{Kind: "email", Value: "mallory@example.net"}) || args[3] != clientIP {
		t.Errorf("create args %v", args)
	}
	// A missing body reaches the service, which checks the access first:
	// its validation error is reported as a required kind, any other error
	// as is.
	o.err, o.errAt = &tenantops.InvalidError{Field: tenantops.FieldKind}, "CreateBlocklistEntry"
	_, err = s.CreateBlocklistEntry(ctx, gen.CreateBlocklistEntryRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/kind", Code: fieldRequired}}) {
		t.Errorf("missing body: %+v", p.Errors)
	}
	if args := o.args["CreateBlocklistEntry"]; !reflect.DeepEqual(args[2], tenantops.BlocklistInput{}) {
		t.Errorf("missing body args %v", args)
	}
	o.err = tenantops.ErrNotFound
	_, err = s.CreateBlocklistEntry(ctx, gen.CreateBlocklistEntryRequestObject{TenantId: "ten_b"})
	expectProblem(t, err, problem.CodeNotFound)
	o.err, o.errAt = nil, ""
	del, err := s.DeleteBlocklistEntry(ctx, gen.DeleteBlocklistEntryRequestObject{TenantId: "ten_a", EntryId: "blk_01"})
	if err != nil || visit(t, del).Code != http.StatusNoContent {
		t.Fatalf("delete entry = %v, %v", del, err)
	}
	if args := o.args["DeleteBlocklistEntry"]; args[2] != "blk_01" || args[3] != clientIP {
		t.Errorf("delete entry args %v", args)
	}
}

func TestAuditOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	o := newFakeOps()
	s := opsServer(o, nil, nil)
	action := gen.AuditAction("transfer.finalized")
	from, to := now.Add(-time.Hour), now
	resp, err := s.ListTenantAuditEvents(ctx, gen.ListTenantAuditEventsRequestObject{TenantId: "ten_a", Params: gen.ListTenantAuditEventsParams{
		Action: &action, Actor: ptr("alice@entity-a.example.com"), From: &from, To: &to, Limit: ptr(7), Cursor: ptr("k"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantFilter := tenantops.AuditFilter{Action: "transfer.finalized", Actor: "alice@entity-a.example.com", From: from, To: to, Cursor: "k", Limit: 7}
	if args := o.args["ListAuditEvents"]; args[1] != tenant.ID("ten_a") || !reflect.DeepEqual(args[2], wantFilter) {
		t.Errorf("audit args %v", args)
	}
	_, body := decode(t, resp)
	items := body["items"].([]any)
	e0, e1, e2 := items[0].(map[string]any), items[1].(map[string]any), items[2].(map[string]any)
	if e0["tenantId"] != "ten_a" || e0["ip"] != "10.10.4.21" || e0["actor"].(map[string]any)["kind"] != "depositor" ||
		e0["object"].(map[string]any)["id"] != "trf_01" || e0["details"].(map[string]any)["fileCount"] != float64(2) {
		t.Errorf("event 0 = %v", e0)
	}
	for _, absent := range []string{"tenantId", "ip", "details"} {
		if _, ok := e1[absent]; ok {
			t.Errorf("event 1 has %s: %v", absent, e1)
		}
	}
	if _, ok := e2["details"]; ok {
		t.Errorf("null details rendered: %v", e2)
	}

	tid := "ten_01JAB00000000000000ENT1TYA"
	o.next = "n"
	global, err := s.ListGlobalAuditEvents(ctx, gen.ListGlobalAuditEventsRequestObject{Params: gen.ListGlobalAuditEventsParams{
		TenantId: &tid, Action: &action, Limit: ptr(2), Cursor: ptr("g"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantGlobal := tenantops.GlobalAuditFilter{TenantID: tenant.ID(tid), Action: "transfer.finalized", Cursor: "g", Limit: 2}
	if args := o.args["ListGlobalAuditEvents"]; !reflect.DeepEqual(args[1], wantGlobal) {
		t.Errorf("global args %v", args)
	}
	if _, body = decode(t, global); body["nextCursor"] != "n" || len(body["items"].([]any)) != 3 {
		t.Errorf("global = %v", body)
	}

	// Malformed stored details: a server error, before anything is written.
	o.events = []store.AuditEvent{{ID: "aud_bad", At: now, ActorKind: store.ActorSystem, Details: json.RawMessage(`{`)}}
	if _, err := s.ListTenantAuditEvents(ctx, gen.ListTenantAuditEventsRequestObject{TenantId: "ten_a"}); err == nil || !strings.Contains(err.Error(), "aud_bad") {
		t.Errorf("tenant list with bad details: %v", err)
	}
	if _, err := s.ListGlobalAuditEvents(ctx, gen.ListGlobalAuditEventsRequestObject{}); err == nil {
		t.Error("global list with bad details succeeded")
	}
}

func TestStatsOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	st := &fakeStats{global: stats.GlobalStats{
		Disk: stats.Disk{
			TotalBytes: 1000, UsedBytes: 300, UsedRatio: 0.3, AlertThreshold: stats.DefaultDiskAlertThreshold,
			AlertActive: true, AlertMailConfigured: true,
		},
		Tenants: []stats.TenantRow{{
			TenantID: "ten_a", Name: "Entity A", Transfers: 4, BytesUploaded: 400,
			Storage: stats.Storage{UsedBytes: 250, QuotaBytes: 1000, UsedRatio: 0.25},
		}},
	}}
	s := opsServer(nil, nil, st)
	period := gen.GetTenantStatsParamsPeriod("7d")
	resp, err := s.GetTenantStats(ctx, gen.GetTenantStatsRequestObject{TenantId: "ten_a", Params: gen.GetTenantStatsParams{Period: &period}})
	if err != nil {
		t.Fatal(err)
	}
	if args := st.args["TenantStats"]; args[1] != tenant.ID("ten_a") || args[2] != stats.Period7Days {
		t.Errorf("tenant stats args %v", args)
	}
	code, body := decode(t, resp)
	series := body["series"].([]any)
	if code != http.StatusOK || body["period"] != "7d" || body["transferCount"] != float64(5) || body["downloadCount"] != float64(6) ||
		body["bytesDownloaded"] != float64(600) || body["virusDetections"] != float64(1) || body["storageUsedRatio"] != 0.25 ||
		len(series) != 2 || series[1].(map[string]any)["date"] != "2026-10-22" || series[1].(map[string]any)["transfers"] != float64(3) {
		t.Errorf("tenant stats = %d %v", code, body)
	}
	// The period is passed as given: the service checks it after the
	// access.
	if _, err := s.GetTenantStats(ctx, gen.GetTenantStatsRequestObject{TenantId: "ten_a"}); err != nil || st.args["TenantStats"][2] != stats.Period("") {
		t.Errorf("no period: %v, %v", err, st.args["TenantStats"])
	}
	bad := gen.GetTenantStatsParamsPeriod("1y")
	st.err, st.errAt = stats.ErrInvalidPeriod, "TenantStats"
	_, err = s.GetTenantStats(ctx, gen.GetTenantStatsRequestObject{TenantId: "ten_a", Params: gen.GetTenantStatsParams{Period: &bad}})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "period" || st.args["TenantStats"][2] != stats.Period("1y") {
		t.Errorf("bad period errors %+v", p.Errors)
	}
	st.err, st.errAt = nil, ""

	gperiod := gen.GetGlobalStatsParamsPeriod("12m")
	global, err := s.GetGlobalStats(ctx, gen.GetGlobalStatsRequestObject{Params: gen.GetGlobalStatsParams{Period: &gperiod}})
	if err != nil {
		t.Fatal(err)
	}
	code, body = decode(t, global)
	disk := body["disk"].(map[string]any)
	row := body["tenants"].([]any)[0].(map[string]any)
	if code != http.StatusOK || body["period"] != "12m" || disk["totalBytes"] != float64(1000) || disk["usedBytes"] != float64(300) ||
		disk["alertThreshold"] != 0.85 || disk["alertActive"] != true || disk["alertMailConfigured"] != true || row["tenantId"] != "ten_a" || row["transferCount"] != float64(4) || row["storageQuotaBytes"] != float64(1000) {
		t.Errorf("global stats = %d %v", code, body)
	}
	gbad := gen.GetGlobalStatsParamsPeriod("1y")
	st.err = stats.ErrInvalidPeriod
	_, err = s.GetGlobalStats(ctx, gen.GetGlobalStatsRequestObject{Params: gen.GetGlobalStatsParams{Period: &gbad}})
	expectProblem(t, err, problem.CodeValidationFailed)
	if st.args["GlobalStats"][1] != stats.Period("1y") {
		t.Errorf("global stats args %v", st.args["GlobalStats"])
	}
	st.err = nil
	st.global.Tenants = nil
	global, _ = s.GetGlobalStats(ctx, gen.GetGlobalStatsRequestObject{})
	if _, body = decode(t, global); body["tenants"] == nil || len(body["tenants"].([]any)) != 0 {
		t.Errorf("no tenant: tenants = %v", body["tenants"])
	}
	if byteSize(math.MaxUint64) != math.MaxInt64 || byteSize(42) != 42 {
		t.Error("byteSize")
	}
}

func TestDataSubjectOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	d := &fakeSubjects{summary: datasubject.Summary{
		Email: "carol@customer.example.net", TransfersAsRecipient: 3, AuditEvents: 7, Invitations: 1, VerifiedAddress: true,
	}}
	s := opsServer(nil, d, nil)
	body := &gen.DataSubjectRequest{Email: "Carol@Customer.example.net"}
	resp, err := s.SearchDataSubject(ctx, gen.SearchDataSubjectRequestObject{TenantId: "ten_a", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if args := d.args["Search"]; args[1] != clientIP || args[2] != tenant.ID("ten_a") || args[3] != "Carol@Customer.example.net" {
		t.Errorf("search args %v", args)
	}
	code, out := decode(t, resp)
	if code != http.StatusOK || out["email"] != "carol@customer.example.net" || out["transfersAsRecipient"] != float64(3) ||
		out["securityEvents"] != float64(0) || out["verifiedAddress"] != true || out["auditEvents"] != float64(7) {
		t.Errorf("summary = %d %v", code, out)
	}
	erase, err := s.EraseDataSubject(ctx, gen.EraseDataSubjectRequestObject{TenantId: "ten_a", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	code, out = decode(t, erase)
	if code != http.StatusOK || out["transfersDeleted"] != float64(1) || out["recipientEntriesRemoved"] != float64(2) ||
		out["verifiedAddressDeleted"] != true || out["invitationsDeleted"] != float64(3) || out["logEntriesPseudonymised"] != float64(4) ||
		out["accessLinks"] != float64(5) {
		t.Errorf("report = %d %v", code, out)
	}
	if args := d.args["Erase"]; args[1] != clientIP || args[2] != tenant.ID("ten_a") {
		t.Errorf("erase args %v", args)
	}
	// Without body, the service checks the access first: its validation
	// error is reported as a required address, any other error as is.
	required := []problem.FieldError{{Field: "/email", Code: fieldRequired}}
	malformed := []problem.FieldError{{Field: "/email", Code: fieldInvalidEmail}}
	d.err = &datasubject.InvalidError{Field: datasubject.FieldEmail}
	_, err = s.SearchDataSubject(ctx, gen.SearchDataSubjectRequestObject{TenantId: "ten_a"})
	if p := expectProblem(t, err, problem.CodeValidationFailed); !reflect.DeepEqual(p.Errors, required) || d.args["Search"][3] != "" {
		t.Errorf("search without body %+v", p.Errors)
	}
	_, err = s.EraseDataSubject(ctx, gen.EraseDataSubjectRequestObject{TenantId: "ten_a"})
	if p := expectProblem(t, err, problem.CodeValidationFailed); !reflect.DeepEqual(p.Errors, required) || d.args["Erase"][3] != "" {
		t.Errorf("erase without body %+v", p.Errors)
	}
	// A malformed address: invalid-email.
	bad := &gen.DataSubjectRequest{Email: "Carol <carol@customer.example.net>"}
	_, err = s.SearchDataSubject(ctx, gen.SearchDataSubjectRequestObject{TenantId: "ten_a", Body: bad})
	if p := expectProblem(t, err, problem.CodeValidationFailed); !reflect.DeepEqual(p.Errors, malformed) {
		t.Errorf("search malformed %+v", p.Errors)
	}
	d.err = datasubject.ErrNotFound
	_, err = s.EraseDataSubject(ctx, gen.EraseDataSubjectRequestObject{TenantId: "ten_b"})
	expectProblem(t, err, problem.CodeNotFound)
	// A busy erasure: 409 with Retry-After.
	d.err, d.errAt = datasubject.ErrBusy, "Erase"
	_, err = s.EraseDataSubject(ctx, gen.EraseDataSubjectRequestObject{TenantId: "ten_a", Body: body})
	if p := expectProblem(t, err, problem.CodeStateConflict); p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 5 {
		t.Errorf("busy erase %+v", p)
	}
}

// TestOperationServiceFailures checks that every operation maps the error
// of its service, internal errors kept for the log.
func TestOperationServiceFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	o, d, st := newFakeOps(), &fakeSubjects{}, &fakeStats{}
	o.err, d.err, st.err = boom, boom, boom
	for name, err := range operationCalls(ctxWith(store.SessionAuthenticated, superRoot), opsServer(o, d, st)) {
		if !errors.Is(err, boom) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
