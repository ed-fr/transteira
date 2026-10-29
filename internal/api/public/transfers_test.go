package public

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/upload"
)

var created = time.Date(2026, 10, 19, 16, 0, 0, 0, time.UTC)

// uploadingDetails is a new transfer with two files, one complete.
func uploadingDetails() transfer.Details {
	return transfer.Details{
		ID: "trf_01", Status: store.TransferUploading, SenderEmail: "alice@entity-a.example.com",
		Recipients: []string{"carol@customer.example.net"}, ExpiryDays: 7, PasswordProtected: true,
		TotalBytes: 15, CreatedAt: created, UploadExpiresAt: created.Add(24 * time.Hour),
		Files: []transfer.File{
			{
				ID: "fil_1", Name: "plans.pdf", Size: 10, MediaType: "application/pdf", ScanStatus: store.ScanPending,
				UploadID: "upl_1", UploadOffset: 4,
			},
			{
				ID: "fil_2", Name: "empty.txt", Size: 5, SHA256: "e3b0", ScanStatus: store.ScanPending,
				UploadID: "upl_2", UploadOffset: 5,
			},
		},
	}
}

// fakeTransfers records its calls.
type fakeTransfers struct {
	err     error
	details transfer.Details
	sender  transfer.Sender
	req     transfer.CreateRequest
	key     string
	trfID   string
}

func (f *fakeTransfers) Create(_ context.Context, _ *tenant.Tenant, s transfer.Sender, req transfer.CreateRequest, key string) (transfer.Details, error) {
	f.sender, f.req, f.key = s, req, key
	return f.details, f.err
}

func (f *fakeTransfers) Get(_ context.Context, _ *tenant.Tenant, s transfer.Sender, id string) (transfer.Details, error) {
	f.sender, f.trfID = s, id
	return f.details, f.err
}

func (f *fakeTransfers) Cancel(_ context.Context, _ *tenant.Tenant, s transfer.Sender, id string) error {
	f.sender, f.trfID = s, id
	return f.err
}

func (f *fakeTransfers) Finalize(_ context.Context, _ *tenant.Tenant, s transfer.Sender, id string) (transfer.Details, error) {
	f.sender, f.trfID = s, id
	return f.details, f.err
}

func TestTransferOperationsRequireTenantServiceAndSession(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	calls := map[string]func(*Server, context.Context) error{
		"create": func(s *Server, ctx context.Context) error {
			_, err := s.CreateTransfer(ctx, gen.CreateTransferRequestObject{Body: &gen.TransferCreate{}})
			return err
		},
		"get": func(s *Server, ctx context.Context) error {
			_, err := s.GetTransfer(ctx, gen.GetTransferRequestObject{})
			return err
		},
		"cancel": func(s *Server, ctx context.Context) error {
			_, err := s.CancelTransfer(ctx, gen.CancelTransferRequestObject{})
			return err
		},
		"finalize": func(s *Server, ctx context.Context) error {
			_, err := s.FinalizeTransfer(ctx, gen.FinalizeTransferRequestObject{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := NewServer(WithTransfers(&fakeTransfers{}))
			wantProblem(t, call(srv, context.Background()), problem.CodeUnknownTenant)
			if err := call(NewServer(), depositCtx(t, &info)); !errors.Is(err, errNoTransferService) {
				t.Errorf("without transfer service: %v", err)
			}
			wantProblem(t, call(srv, depositCtx(t, nil)), problem.CodeUnauthenticated)
		})
	}
}

func TestCreateTransfer(t *testing.T) {
	t.Parallel()
	info := externalInfo()
	f := &fakeTransfers{details: uploadingDetails()}
	msg, pw, lang, del, mt, sum := "Hello", "secret", gen.Language("en"), true, "application/pdf", "ab"
	sender := gen.Email("bot@entity-a.example.com")
	recipients := []gen.Email{"carol@customer.example.net", "dave@customer.example.net"}
	key := "key-1"
	resp, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{
		Params: gen.CreateTransferParams{IdempotencyKey: &key},
		Body: &gen.TransferCreate{
			SenderEmail: &sender, Recipients: &recipients, Message: &msg, ExpiryDays: 7, Password: &pw,
			DeleteAfterFirstDownload: &del, Language: &lang,
			Files: []gen.FileDeclaration{{Name: "plans.pdf", Size: 10, MediaType: &mt, ExpectedSha256: &sum}, {Name: "b", Size: 0}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.CreateTransfer201JSONResponse)
	if !ok {
		t.Fatalf("response %T", resp)
	}
	if got.Headers.Location == nil || *got.Headers.Location != "/api/v1/transfers/trf_01" {
		t.Errorf("Location = %v", got.Headers.Location)
	}
	if got.Body.Id != "trf_01" || got.Body.Status != "uploading" || len(got.Body.Files) != 2 {
		t.Errorf("body = %+v", got.Body)
	}
	wantSender := transfer.Sender{
		Depositor: store.Depositor{Email: "bob@partner.example.org", Kind: deposit.KindExternal, InvitationID: "inv_secret_record"},
		ClientIP:  netip.MustParseAddr("192.0.2.7"),
	}
	if f.sender != wantSender || f.key != key {
		t.Errorf("sender %+v key %q, want %+v", f.sender, f.key, wantSender)
	}
	r := f.req
	if r.SenderEmail != string(sender) || !slices.Equal(r.Recipients, []string{"carol@customer.example.net", "dave@customer.example.net"}) ||
		r.Message != msg || r.ExpiryDays != 7 || r.Password == nil || *r.Password != pw || !r.DeleteAfterFirstDownload ||
		r.Language != "en" || len(r.Files) != 2 ||
		r.Files[0] != (transfer.FileDeclaration{Name: "plans.pdf", Size: 10, MediaType: mt, ExpectedSHA256: sum}) ||
		r.Files[1] != (transfer.FileDeclaration{Name: "b"}) {
		t.Errorf("request = %+v", r)
	}

	// Minimal body: optional members absent.
	internal := internalInfo()
	f = &fakeTransfers{details: uploadingDetails()}
	if _, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &internal), gen.CreateTransferRequestObject{
		Body: &gen.TransferCreate{ExpiryDays: 1, Files: []gen.FileDeclaration{{Name: "a", Size: 1}}},
	}); err != nil {
		t.Fatal(err)
	}
	if f.req.Recipients != nil || f.req.Password != nil || f.key != "" || f.sender.InvitationID != "" || f.sender.Kind != deposit.KindInternal {
		t.Errorf("minimal request = %+v, sender %+v", f.req, f.sender)
	}
	if f.req.MaxDownloads != nil || f.req.ConfidentialityLevel != "" || f.req.RecipientVerification {
		t.Errorf("minimal options = %+v", f.req)
	}

	// The options of version 1.1.
	maxDl, level, verif := 3, gen.ConfidentialityLevelKey("confidential"), true
	f = &fakeTransfers{details: uploadingDetails()}
	if _, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &internal), gen.CreateTransferRequestObject{
		Body: &gen.TransferCreate{
			ExpiryDays: 1, Files: []gen.FileDeclaration{{Name: "a", Size: 1}},
			MaxDownloads: &maxDl, ConfidentialityLevel: &level, RecipientVerification: &verif,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if f.req.MaxDownloads == nil || *f.req.MaxDownloads != 3 || f.req.ConfidentialityLevel != "confidential" || !f.req.RecipientVerification {
		t.Errorf("options = %+v", f.req)
	}

	// No body.
	_, err = NewServer(WithTransfers(&fakeTransfers{})).CreateTransfer(depositCtx(t, &internal), gen.CreateTransferRequestObject{})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/files" {
		t.Errorf("errors = %+v", p.Errors)
	}
	// Service error.
	_, err = NewServer(WithTransfers(&fakeTransfers{err: transfer.ErrQuotaExceeded})).CreateTransfer(depositCtx(t, &internal),
		gen.CreateTransferRequestObject{Body: &gen.TransferCreate{}})
	wantProblem(t, err, problem.CodeQuotaExceeded)
}

func TestTransferBody(t *testing.T) {
	t.Parallel()
	b := transferBody(uploadingDetails())
	if b.Message != nil || b.ExpiresAt != nil || b.FinalizedAt != nil || b.UploadExpiresAt == nil || b.DownloadUrl != nil {
		t.Errorf("optional members = %+v", b)
	}
	f0, f1 := b.Files[0], b.Files[1]
	if f0.MediaType == nil || *f0.MediaType != "application/pdf" || f0.Sha256 != nil || f0.UploadUrl == nil ||
		*f0.UploadUrl != "/api/v1/uploads/upl_1" || f0.UploadOffset == nil || *f0.UploadOffset != 4 || f0.ScanStatus != "pending" {
		t.Errorf("file 0 = %+v", f0)
	}
	if f1.MediaType != nil || f1.Sha256 == nil || *f1.Sha256 != "e3b0" || *f1.UploadOffset != 5 {
		t.Errorf("file 1 = %+v", f1)
	}

	// A finalized transfer: no upload URL, expiry and finalization set.
	d := uploadingDetails()
	d.Status, d.Message, d.ExpiresAt, d.FinalizedAt, d.UploadExpiresAt = store.TransferAvailable, "Hi", created.AddDate(0, 0, 7), created, time.Time{}
	d.DownloadURL = "https://transfer.entity-a.example.com/d/dl_x"
	d.Files[0].ScanStatus, d.Files[0].ScanSignature = store.ScanInfected, "Eicar-Test-Signature"
	for i := range d.Files {
		d.Files[i].UploadID, d.Files[i].UploadOffset = "", 0
	}
	b = transferBody(d)
	if b.Message == nil || *b.Message != "Hi" || b.ExpiresAt == nil || b.FinalizedAt == nil || b.UploadExpiresAt != nil ||
		b.Files[0].UploadUrl != nil || b.Files[0].UploadOffset != nil || b.Recipients[0] != "carol@customer.example.net" ||
		b.DownloadUrl == nil || *b.DownloadUrl != d.DownloadURL || b.Files[0].ScanSignature == nil ||
		*b.Files[0].ScanSignature != "Eicar-Test-Signature" || b.Files[0].ScanStatus != "infected" || b.Files[1].ScanSignature != nil {
		t.Errorf("finalized body = %+v", b)
	}
}

func TestTransferBodyLevel(t *testing.T) {
	t.Parallel()
	b := transferBody(uploadingDetails())
	if b.ConfidentialityLevel != nil || b.MaxDownloads != nil || b.RecipientVerification == nil || *b.RecipientVerification {
		t.Errorf("without level = %+v", b)
	}
	d := uploadingDetails()
	maxDl, maxCap := 2, 5
	d.MaxDownloads, d.ConfidentialityLevel, d.ConfidentialityLabel = &maxDl, "secret", "Secret"
	b = transferBody(d)
	if b.ConfidentialityLevel == nil || b.ConfidentialityLevel.Key != "secret" || b.ConfidentialityLevel.Label != "Secret" ||
		b.ConfidentialityLevel.Rules != nil || b.MaxDownloads == nil || *b.MaxDownloads != 2 {
		t.Errorf("level without rules = %+v", b.ConfidentialityLevel)
	}
	d.Rules = &store.ConfidentialityRules{
		ExpiryDaysMask: store.ExpiryMask1Day | store.ExpiryMask30Days, MaxDownloadsCap: &maxCap, RequirePassword: true,
		RequireRecipientVerification: true, InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
	}
	r := transferBody(d).ConfidentialityLevel.Rules
	if r == nil || !slices.Equal(r.AllowedExpiryDays, []gen.ExpiryDays{1, 30}) || r.MaxDownloads == nil || *r.MaxDownloads != 5 ||
		!r.RequirePassword || !r.RequireRecipientVerification || !r.InternalRecipientsOnly || !r.ForceDeleteAfterFirstDownload {
		t.Errorf("rules = %+v", r)
	}
}

func TestTransferBodyPerRecipient(t *testing.T) {
	t.Parallel()
	b := transferBody(uploadingDetails())
	if b.RecipientTracking != nil {
		t.Errorf("tracking without per-recipient links = %+v", b.RecipientTracking)
	}
	d := uploadingDetails()
	d.Status, d.RecipientVerification = store.TransferAvailable, true
	d.RecipientTracking = []store.RecipientTracking{{LinkID: "rcl_1", Email: "carol@customer.example.net", VerifiedAt: created}}
	b = transferBody(d)
	if b.RecipientVerification == nil || !*b.RecipientVerification || b.DownloadUrl != nil || b.RecipientTracking == nil ||
		len(*b.RecipientTracking) != 1 || (*b.RecipientTracking)[0].Email != "carol@customer.example.net" ||
		(*b.RecipientTracking)[0].VerifiedAt == nil {
		t.Errorf("per-recipient body = %+v", b)
	}
}

func TestGetCancelFinalizeTransfer(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	f := &fakeTransfers{details: uploadingDetails()}
	srv := NewServer(WithTransfers(f))
	ctx := depositCtx(t, &info)

	resp, err := srv.GetTransfer(ctx, gen.GetTransferRequestObject{TransferId: "trf_01"})
	if _, ok := resp.(gen.GetTransfer200JSONResponse); err != nil || !ok || f.trfID != "trf_01" {
		t.Errorf("get: %T %v %q", resp, err, f.trfID)
	}
	cresp, err := srv.CancelTransfer(ctx, gen.CancelTransferRequestObject{TransferId: "trf_02"})
	if _, ok := cresp.(gen.CancelTransfer204Response); err != nil || !ok || f.trfID != "trf_02" {
		t.Errorf("cancel: %T %v %q", cresp, err, f.trfID)
	}
	fresp, err := srv.FinalizeTransfer(ctx, gen.FinalizeTransferRequestObject{TransferId: "trf_03"})
	if _, ok := fresp.(gen.FinalizeTransfer202JSONResponse); err != nil || !ok || f.trfID != "trf_03" {
		t.Errorf("finalize: %T %v %q", fresp, err, f.trfID)
	}

	f.err = transfer.ErrNotFound
	_, err = srv.GetTransfer(ctx, gen.GetTransferRequestObject{})
	wantProblem(t, err, problem.CodeNotFound)
	_, err = srv.CancelTransfer(ctx, gen.CancelTransferRequestObject{})
	wantProblem(t, err, problem.CodeNotFound)
	_, err = srv.FinalizeTransfer(ctx, gen.FinalizeTransferRequestObject{})
	wantProblem(t, err, problem.CodeNotFound)
}

func TestTransferError(t *testing.T) {
	t.Parallel()
	internal := errors.New("disk full")
	tests := []struct {
		err   error
		code  problem.Code
		check func(t *testing.T, p *problem.Problem)
	}{
		{
			err:  &transfer.ValidationError{Fields: []transfer.FieldError{{Pointer: "/recipients/0", Code: "invalid-email"}, {Pointer: "Idempotency-Key", Code: "invalid-format"}}},
			code: problem.CodeValidationFailed, check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if len(p.Errors) != 2 || p.Errors[0].Field != "/recipients/0" || p.Errors[1].Field != "Idempotency-Key" || p.Errors[1].Code != "invalid-format" {
					t.Errorf("errors = %+v", p.Errors)
				}
			},
		},
		{
			err: fmt.Errorf("w: %w", &transfer.TooLargeError{MaxTransferBytes: 99}), code: problem.CodeTransferTooLarge,
			check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if p.MaxTransferBytes == nil || *p.MaxTransferBytes != 99 {
					t.Errorf("maxTransferBytes = %v", p.MaxTransferBytes)
				}
			},
		},
		{
			err: &transfer.FilesError{Kind: transfer.ErrIncomplete, FileIDs: []string{"fil_1"}}, code: problem.CodeUploadIncomplete,
			check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if !slices.Equal(p.Files, []string{"fil_1"}) {
					t.Errorf("files = %v", p.Files)
				}
			},
		},
		{err: &transfer.FilesError{Kind: transfer.ErrChecksumMismatch, FileIDs: []string{"fil_2"}}, code: problem.CodeChecksumMismatch},
		{
			err: &transfer.RuleError{Kind: transfer.ErrConfidentialityRule, Fields: []transfer.FieldError{
				{Pointer: "/password", Code: "required"}, {Pointer: "/expiryDays", Code: "not-allowed", Allowed: []int{1, 7}},
			}},
			code: problem.CodeConfidentialityRuleViolated, check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if len(p.Errors) != 2 || p.Errors[0].Field != "/password" || p.Errors[0].Allowed != nil ||
					!slices.Equal(p.Errors[1].Allowed, []any{1, 7}) {
					t.Errorf("errors = %+v", p.Errors)
				}
			},
		},
		{
			err: fmt.Errorf("w: %w", &transfer.RuleError{Kind: transfer.ErrRecipientDomainRefused, Fields: []transfer.FieldError{
				{Pointer: "/recipients/1", Code: "domain-denied"},
			}}),
			code: problem.CodeRecipientDomainRefused, check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if len(p.Errors) != 1 || p.Errors[0].Field != "/recipients/1" || p.Errors[0].Code != "domain-denied" {
					t.Errorf("errors = %+v", p.Errors)
				}
			},
		},
		{err: transfer.ErrIncomplete, code: problem.CodeUploadIncomplete},
		{err: transfer.ErrChecksumMismatch, code: problem.CodeChecksumMismatch},
		{err: transfer.ErrBlockedFile, code: problem.CodeBlockedFile},
		{err: &transfer.AbuseBlockedError{Rule: store.AbuseRuleDailyBytes}, code: problem.CodeAbuseThresholdBlocked},
		{err: fmt.Errorf("w: %w", transfer.ErrAbuseBlocked), code: problem.CodeAbuseThresholdBlocked},
		{err: transfer.ErrForbidden, code: problem.CodeDepositNotAllowed},
		{err: transfer.ErrNotFound, code: problem.CodeNotFound},
		{err: transfer.ErrConflict, code: problem.CodeStateConflict},
		{err: transfer.ErrBusy, code: problem.CodeStateConflict},
		{err: transfer.ErrQuotaExceeded, code: problem.CodeQuotaExceeded},
		{err: transfer.ErrIdempotencyMismatch, code: problem.CodeStateConflict},
		{
			err: &transfer.RateLimitError{RetryAfter: 90 * time.Second}, code: problem.CodeRateLimited,
			check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 90 {
					t.Errorf("retryAfterSeconds = %v", p.RetryAfterSeconds)
				}
			},
		},
		{err: internal, code: problem.CodeInternalError},
	}
	for _, tt := range tests {
		p := problem.From(transferError(tt.err))
		if p.Code != tt.code {
			t.Errorf("%v: code %s, want %s", tt.err, p.Code, tt.code)
			continue
		}
		if tt.check != nil {
			tt.check(t, p)
		}
	}
	if !errors.Is(transferError(internal), internal) {
		t.Error("unknown error not passed through")
	}
}

// fakeUploads records its calls.
type fakeUploads struct {
	err    error
	status upload.Status
	p      upload.Principal
	id     string
	offset int64
	body   []byte
}

func (f *fakeUploads) Status(_ context.Context, _ tenant.ID, p upload.Principal, id string) (upload.Status, error) {
	f.p, f.id = p, id
	return f.status, f.err
}

func (f *fakeUploads) Append(_ context.Context, _ tenant.ID, p upload.Principal, id string, offset int64, body io.Reader) (upload.Status, error) {
	f.p, f.id, f.offset = p, id, offset
	f.body, _ = io.ReadAll(body)
	return f.status, f.err
}

func (f *fakeUploads) Terminate(_ context.Context, _ tenant.ID, p upload.Principal, id string) error {
	f.p, f.id = p, id
	return f.err
}

func TestGetTusCapabilities(t *testing.T) {
	t.Parallel()
	_, err := NewServer().GetTusCapabilities(context.Background(), gen.GetTusCapabilitiesRequestObject{})
	wantProblem(t, err, problem.CodeUnknownTenant)
	ctx := tenant.WithTenant(context.Background(), &tenant.Tenant{ID: "ten_x", MaxTransferBytes: 21474836480})
	resp, err := NewServer().GetTusCapabilities(ctx, gen.GetTusCapabilitiesRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitGetTusCapabilitiesResponse(rec); err != nil {
		t.Fatal(err)
	}
	h := rec.Header()
	if rec.Code != http.StatusNoContent || h.Get("Tus-Resumable") != "1.0.0" || h.Get("Tus-Version") != "1.0.0" ||
		h.Get("Tus-Extension") != "expiration,termination" || h.Get("Tus-Max-Size") != "21474836480" {
		t.Errorf("capabilities: %d %v", rec.Code, h)
	}
}

func TestUploadOperationsRequireTenantServiceAndSession(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	calls := map[string]func(*Server, context.Context) error{
		"head": func(s *Server, ctx context.Context) error {
			_, err := s.GetUploadOffset(ctx, gen.GetUploadOffsetRequestObject{})
			return err
		},
		"patch": func(s *Server, ctx context.Context) error {
			_, err := s.AppendUploadChunk(ctx, gen.AppendUploadChunkRequestObject{})
			return err
		},
		"delete": func(s *Server, ctx context.Context) error {
			_, err := s.TerminateUpload(ctx, gen.TerminateUploadRequestObject{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := NewServer(WithUploads(&fakeUploads{}))
			wantProblem(t, call(srv, context.Background()), problem.CodeUnknownTenant)
			if err := call(NewServer(), depositCtx(t, &info)); !errors.Is(err, errNoUploadService) {
				t.Errorf("without upload service: %v", err)
			}
			wantProblem(t, call(srv, depositCtx(t, nil)), problem.CodeUnauthenticated)
		})
	}
}

func TestGetUploadOffset(t *testing.T) {
	t.Parallel()
	info := externalInfo()
	expires := time.Date(2026, 10, 21, 16, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	f := &fakeUploads{status: upload.Status{Offset: 3, Length: 10, ExpiresAt: expires}}
	resp, err := NewServer(WithUploads(f)).GetUploadOffset(depositCtx(t, &info), gen.GetUploadOffsetRequestObject{UploadId: "upl_1"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.GetUploadOffset200Response)
	if !ok {
		t.Fatalf("response %T", resp)
	}
	h := got.Headers
	if *h.UploadOffset != 3 || *h.UploadLength != 10 || *h.UploadExpires != "Wed, 21 Oct 2026 14:00:00 GMT" || *h.TusResumable != "1.0.0" {
		t.Errorf("headers = %+v", h)
	}
	if f.id != "upl_1" || f.p != (upload.Principal{Email: "bob@partner.example.org", Kind: deposit.KindExternal, InvitationID: "inv_secret_record"}) {
		t.Errorf("principal %+v id %q", f.p, f.id)
	}

	// A completed upload has no expiry.
	f.status = upload.Status{Offset: 10, Length: 10, Completed: true, ExpiresAt: expires}
	resp, _ = NewServer(WithUploads(f)).GetUploadOffset(depositCtx(t, &info), gen.GetUploadOffsetRequestObject{})
	if resp.(gen.GetUploadOffset200Response).Headers.UploadExpires != nil {
		t.Error("completed upload with Upload-Expires")
	}

	for err, want := range map[error]any{
		upload.ErrNotFound:  gen.GetUploadOffset404Response{},
		upload.ErrExpired:   gen.GetUploadOffset410Response{},
		upload.ErrFinalized: gen.GetUploadOffset410Response{},
	} {
		resp, gotErr := NewServer(WithUploads(&fakeUploads{err: err})).GetUploadOffset(depositCtx(t, &info), gen.GetUploadOffsetRequestObject{})
		if gotErr != nil || resp != want {
			t.Errorf("%v: %T %v", err, resp, gotErr)
		}
	}
	boom := errors.New("io")
	if _, gotErr := NewServer(WithUploads(&fakeUploads{err: boom})).GetUploadOffset(depositCtx(t, &info), gen.GetUploadOffsetRequestObject{}); !errors.Is(gotErr, boom) {
		t.Errorf("unknown error: %v", gotErr)
	}
}

func TestAppendUploadChunk(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	f := &fakeUploads{status: upload.Status{Offset: 6, Length: 10, ExpiresAt: created}}
	resp, err := NewServer(WithUploads(f)).AppendUploadChunk(depositCtx(t, &info), gen.AppendUploadChunkRequestObject{
		UploadId: "upl_1", Params: gen.AppendUploadChunkParams{UploadOffset: 3}, Body: stringsReader("abc"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.AppendUploadChunk204Response)
	if !ok || *got.Headers.UploadOffset != 6 || got.Headers.UploadExpires == nil {
		t.Fatalf("response %#v", resp)
	}
	if f.offset != 3 || string(f.body) != "abc" || f.id != "upl_1" {
		t.Errorf("append got offset %d body %q id %q", f.offset, f.body, f.id)
	}
	resp, _ = NewServer(WithUploads(f)).AppendUploadChunk(depositCtx(t, &info), gen.AppendUploadChunkRequestObject{})
	if resp != (gen.AppendUploadChunk400Response{}) {
		t.Errorf("nil body: %T", resp)
	}
	for err, want := range map[error]any{
		upload.ErrNotFound:       gen.AppendUploadChunk404Response{},
		upload.ErrBusy:           gen.AppendUploadChunk409Response{},
		upload.ErrOffsetMismatch: gen.AppendUploadChunk409Response{},
		upload.ErrFinalized:      gen.AppendUploadChunk409Response{},
		upload.ErrExpired:        gen.AppendUploadChunk410Response{},
		upload.ErrTooLarge:       gen.AppendUploadChunk413Response{},
		upload.ErrInvalid:        gen.AppendUploadChunk400Response{},
		upload.ErrInterrupted:    gen.AppendUploadChunk400Response{},
	} {
		resp, gotErr := NewServer(WithUploads(&fakeUploads{err: err})).AppendUploadChunk(depositCtx(t, &info),
			gen.AppendUploadChunkRequestObject{Body: stringsReader("x")})
		if gotErr != nil || resp != want {
			t.Errorf("%v: %T %v", err, resp, gotErr)
		}
	}
	boom := errors.New("io")
	if _, gotErr := NewServer(WithUploads(&fakeUploads{err: boom})).AppendUploadChunk(depositCtx(t, &info),
		gen.AppendUploadChunkRequestObject{Body: stringsReader("x")}); !errors.Is(gotErr, boom) {
		t.Errorf("unknown error: %v", gotErr)
	}
}

func TestTerminateUpload(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	f := &fakeUploads{}
	resp, err := NewServer(WithUploads(f)).TerminateUpload(depositCtx(t, &info), gen.TerminateUploadRequestObject{UploadId: "upl_9"})
	if got, ok := resp.(gen.TerminateUpload204Response); err != nil || !ok || *got.Headers.TusResumable != "1.0.0" || f.id != "upl_9" {
		t.Fatalf("terminate: %#v %v", resp, err)
	}
	for err, want := range map[error]any{
		upload.ErrNotFound:  gen.TerminateUpload404Response{},
		upload.ErrBusy:      gen.TerminateUpload409Response{},
		upload.ErrFinalized: gen.TerminateUpload409Response{},
	} {
		resp, gotErr := NewServer(WithUploads(&fakeUploads{err: err})).TerminateUpload(depositCtx(t, &info), gen.TerminateUploadRequestObject{})
		if gotErr != nil || resp != want {
			t.Errorf("%v: %T %v", err, resp, gotErr)
		}
	}
	boom := errors.New("io")
	if _, gotErr := NewServer(WithUploads(&fakeUploads{err: boom})).TerminateUpload(depositCtx(t, &info), gen.TerminateUploadRequestObject{}); !errors.Is(gotErr, boom) {
		t.Errorf("unknown error: %v", gotErr)
	}
}

// stringsReader returns a reader over s.
func stringsReader(s string) io.Reader { return strings.NewReader(s) }

func TestCreateTransferRemoteSender(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	info.Kind = deposit.KindInternalRemote
	f := &fakeTransfers{details: uploadingDetails()}
	if _, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{
		Body: &gen.TransferCreate{ExpiryDays: 1, Files: []gen.FileDeclaration{{Name: "a", Size: 1}}},
	}); err != nil {
		t.Fatal(err)
	}
	if f.sender.Kind != deposit.KindInternalRemote || f.sender.Email != info.Email {
		t.Errorf("sender = %+v", f.sender)
	}
}
