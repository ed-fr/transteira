package public

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// meInfo is the "my transfers" session of the tests.
func meInfo() mytransfers.SessionInfo {
	return mytransfers.SessionInfo{ID: "mts_secret_record", Email: "alice@entity-a.example.com", ExpiresAt: expires, CSRFToken: "csrf_me"}
}

// fakeMe records its calls and answers with the configured values.
type fakeMe struct {
	err    error
	page   store.Page[mytransfers.Transfer]
	detail mytransfers.TransferDetail

	gotIP       netip.Addr
	gotAccept   string
	gotEmail    string
	gotLanguage string
	gotToken    string
	gotSession  mytransfers.SessionInfo
	gotCursor   string
	gotLimit    int
	gotTransfer string
	gotDays     int
}

func (f *fakeMe) RequestLink(_ context.Context, _ *tenant.Tenant, ip netip.Addr, accept, email, language string) error {
	f.gotIP, f.gotAccept, f.gotEmail, f.gotLanguage = ip, accept, email, language
	return f.err
}

func (f *fakeMe) StartSession(_ context.Context, _ *tenant.Tenant, ip netip.Addr, token string) (mytransfers.Session, error) {
	f.gotIP, f.gotToken = ip, token
	if f.err != nil {
		return mytransfers.Session{}, f.err
	}
	return mytransfers.Session{Token: "ms_new", SessionInfo: meInfo()}, nil
}

func (f *fakeMe) End(_ context.Context, _ *tenant.Tenant, raw string) error {
	f.gotToken = raw
	return f.err
}

func (f *fakeMe) List(_ context.Context, _ *tenant.Tenant, sess mytransfers.SessionInfo, cursor string, limit int) (store.Page[mytransfers.Transfer], error) {
	f.gotSession, f.gotCursor, f.gotLimit = sess, cursor, limit
	return f.page, f.err
}

func (f *fakeMe) Get(_ context.Context, _ *tenant.Tenant, sess mytransfers.SessionInfo, trfID string) (mytransfers.TransferDetail, error) {
	f.gotSession, f.gotTransfer = sess, trfID
	return f.detail, f.err
}

func (f *fakeMe) Delete(_ context.Context, _ *tenant.Tenant, sess mytransfers.SessionInfo, ip netip.Addr, trfID string) error {
	f.gotSession, f.gotIP, f.gotTransfer = sess, ip, trfID
	return f.err
}

func (f *fakeMe) Extend(_ context.Context, _ *tenant.Tenant, sess mytransfers.SessionInfo, ip netip.Addr, trfID string, days int) (mytransfers.TransferDetail, error) {
	f.gotSession, f.gotIP, f.gotTransfer, f.gotDays = sess, ip, trfID, days
	return f.detail, f.err
}

// staticMe resolves every token to meInfo.
type staticMe struct{}

func (staticMe) ResolveSession(context.Context, string) (any, bool, error) {
	return meInfo(), true, nil
}
func (staticMe) CheckCSRF(string, string) bool { return true }

// meCtx returns a context with tenant A, a client IP and, with session, a
// "my transfers" session set by the middleware.
func meCtx(t *testing.T, session bool) context.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(tenantCtx())
	r.RemoteAddr = "192.0.2.7:1234"
	var captured context.Context
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { captured = r.Context() })
	chain := middleware.RealIP(nil)(h)
	if session {
		r.AddCookie(&http.Cookie{Name: middleware.MyTransfersCookie, Value: "ms_raw"})
		chain = middleware.RealIP(nil)(middleware.MyTransfersSession(staticMe{}, func(*http.Request) bool { return true }, nil)(h))
	}
	chain.ServeHTTP(httptest.NewRecorder(), r)
	if captured == nil {
		t.Fatal("middleware chain did not reach the handler")
	}
	return captured
}

func newMeServer(f *fakeMe) *Server {
	s := NewServer(WithMyTransfers(f))
	s.now = func() time.Time { return expires.Add(-time.Hour) }
	return s
}

// sampleTransfer is a leveled per-recipient transfer.
func sampleTransfer() store.Transfer {
	mask, _ := store.ExpiryDaysMaskOf([]int{1, 7})
	maxDl := 3
	return store.Transfer{
		ID: "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS", Status: store.TransferAvailable, SenderEmail: "alice@entity-a.example.com",
		Message: "Plans", Language: "en", ExpiryDays: 7, PasswordHash: "$argon2id$x", TotalBytes: 2048,
		CreatedAt: expires.Add(-48 * time.Hour), ExpiresAt: expires.Add(5 * 24 * time.Hour), DownloadCount: 2,
		MaxDownloads: &maxDl, ConfidentialityLevel: "confidential", ConfidentialityLabel: map[string]string{"en": "Confidential"},
		Rules: &store.ConfidentialityRules{ExpiryDaysMask: mask}, RecipientVerification: true, ExtensionCount: 1,
		DownloadTokenHash: []byte("secret-hash"), DownloadTokenKeyID: "wk_secret",
	}
}

func TestMyTransfersRequireTenantAndService(t *testing.T) {
	t.Parallel()
	bare := NewServer()
	srv := newMeServer(&fakeMe{})
	calls := map[string]func(*Server, context.Context) error{
		"request": func(s *Server, ctx context.Context) error {
			_, err := s.RequestMyTransfersLink(ctx, gen.RequestMyTransfersLinkRequestObject{Body: &gen.MyTransfersLinkRequest{Email: "a@b.example"}})
			return err
		},
		"start": func(s *Server, ctx context.Context) error {
			_, err := s.StartMyTransfersSession(ctx, gen.StartMyTransfersSessionRequestObject{Body: &gen.MyTransfersSessionStart{Token: "mta_x"}})
			return err
		},
		"current": func(s *Server, ctx context.Context) error {
			_, err := s.GetCurrentMyTransfersSession(ctx, gen.GetCurrentMyTransfersSessionRequestObject{})
			return err
		},
		"end": func(s *Server, ctx context.Context) error {
			_, err := s.EndMyTransfersSession(ctx, gen.EndMyTransfersSessionRequestObject{})
			return err
		},
		"list": func(s *Server, ctx context.Context) error {
			_, err := s.ListMyTransfers(ctx, gen.ListMyTransfersRequestObject{})
			return err
		},
		"get": func(s *Server, ctx context.Context) error {
			_, err := s.GetMyTransfer(ctx, gen.GetMyTransferRequestObject{TransferId: "trf_x"})
			return err
		},
		"delete": func(s *Server, ctx context.Context) error {
			_, err := s.DeleteMyTransfer(ctx, gen.DeleteMyTransferRequestObject{TransferId: "trf_x"})
			return err
		},
		"extend": func(s *Server, ctx context.Context) error {
			_, err := s.ExtendMyTransfer(ctx, gen.ExtendMyTransferRequestObject{TransferId: "trf_x", Body: &gen.TransferExtension{ExpiryDays: 7}})
			return err
		},
	}
	for name, call := range calls {
		wantProblem(t, call(srv, context.Background()), problem.CodeUnknownTenant)
		if err := call(bare, meCtx(t, true)); !errors.Is(err, errNoMyTransfersService) {
			t.Errorf("%s without service: %v", name, err)
		}
		if name != "request" && name != "start" {
			wantProblem(t, call(srv, meCtx(t, false)), problem.CodeUnauthenticated)
		}
	}
}

func TestRequestMyTransfersLink(t *testing.T) {
	t.Parallel()
	f := &fakeMe{}
	srv := newMeServer(f)
	lang, accept := gen.Language("fr"), "en"
	resp, err := srv.RequestMyTransfersLink(meCtx(t, false), gen.RequestMyTransfersLinkRequestObject{
		Params: gen.RequestMyTransfersLinkParams{AcceptLanguage: &accept},
		Body:   &gen.MyTransfersLinkRequest{Email: "alice@entity-a.example.com", Language: &lang},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitRequestMyTransfersLinkResponse(rec); err != nil || rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("response %d %q, %v", rec.Code, rec.Body, err)
	}
	if f.gotEmail != "alice@entity-a.example.com" || f.gotLanguage != "fr" || f.gotAccept != "en" || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service got %+v", f)
	}
	if _, err := srv.RequestMyTransfersLink(meCtx(t, false), gen.RequestMyTransfersLinkRequestObject{
		Body: &gen.MyTransfersLinkRequest{Email: "alice@entity-a.example.com"},
	}); err != nil || f.gotLanguage != "" || f.gotAccept != "" {
		t.Errorf("without language: %v, %+v", err, f)
	}
	p := problemOf(t, func() error {
		_, err := srv.RequestMyTransfersLink(meCtx(t, false), gen.RequestMyTransfersLinkRequestObject{})
		return err
	}(), problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "/email" || p.Errors[0].Code != "required" {
		t.Errorf("errors = %+v", p.Errors)
	}
}

func TestStartMyTransfersSession(t *testing.T) {
	t.Parallel()
	f := &fakeMe{}
	srv := newMeServer(f)
	resp, err := srv.StartMyTransfersSession(meCtx(t, false), gen.StartMyTransfersSessionRequestObject{
		Body: &gen.MyTransfersSessionStart{Token: "mta_abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitStartMyTransfersSessionResponse(rec); err != nil || rec.Code != http.StatusCreated {
		t.Fatalf("response %d, %v", rec.Code, err)
	}
	if got := rec.Header().Get("Set-Cookie"); got != "__Host-tt_me=ms_new; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict" {
		t.Errorf("Set-Cookie = %q", got)
	}
	var body gen.MyTransfersSession
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Email != "alice@entity-a.example.com" || body.CsrfToken != "csrf_me" || !body.ExpiresAt.Equal(expires) ||
		strings.Contains(rec.Body.String(), "mts_secret") || strings.Contains(rec.Body.String(), "ms_new") {
		t.Errorf("body = %s", rec.Body)
	}
	if f.gotToken != "mta_abc" || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service got %+v", f)
	}
	for _, body := range []*gen.MyTransfersSessionStart{nil, {}} {
		_, err := srv.StartMyTransfersSession(meCtx(t, false), gen.StartMyTransfersSessionRequestObject{Body: body})
		if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/token" {
			t.Errorf("errors = %+v", p.Errors)
		}
	}
	f.err = mytransfers.ErrAccessLinkInvalid
	_, err = srv.StartMyTransfersSession(meCtx(t, false), gen.StartMyTransfersSessionRequestObject{Body: &gen.MyTransfersSessionStart{Token: "mta_x"}})
	wantProblem(t, err, problem.CodeAccessLinkInvalid)
}

func TestCurrentAndEndMyTransfersSession(t *testing.T) {
	t.Parallel()
	f := &fakeMe{}
	srv := newMeServer(f)
	resp, err := srv.GetCurrentMyTransfersSession(meCtx(t, true), gen.GetCurrentMyTransfersSessionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	body := resp.(gen.GetCurrentMyTransfersSession200JSONResponse)
	if body.Email != "alice@entity-a.example.com" || body.CsrfToken != "csrf_me" {
		t.Errorf("current = %+v", body)
	}
	end, err := srv.EndMyTransfersSession(meCtx(t, true), gen.EndMyTransfersSessionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := end.VisitEndMyTransfersSessionResponse(rec); err != nil || rec.Code != http.StatusNoContent ||
		rec.Header().Get("Set-Cookie") != "__Host-tt_me=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict" {
		t.Errorf("end = %d %q, %v", rec.Code, rec.Header().Get("Set-Cookie"), err)
	}
	if f.gotToken != "ms_raw" {
		t.Errorf("ended %q", f.gotToken)
	}
	f.err = mytransfers.ErrUnauthenticated
	_, err = srv.EndMyTransfersSession(meCtx(t, true), gen.EndMyTransfersSessionRequestObject{})
	wantProblem(t, err, problem.CodeUnauthenticated)
}

func TestListMyTransfers(t *testing.T) {
	t.Parallel()
	scanning := sampleTransfer()
	scanning.Status, scanning.ConfidentialityLevel = store.TransferScanning, ""
	f := &fakeMe{page: store.Page[mytransfers.Transfer]{NextCursor: "next", Items: []mytransfers.Transfer{
		{SenderTransfer: store.SenderTransfer{Transfer: sampleTransfer(), Recipients: []string{"carol@customer.example.net"}, FileCount: 2, DownloadedBy: 1}, LevelLabel: "Confidential"},
		{SenderTransfer: store.SenderTransfer{Transfer: scanning, Recipients: []string{}, FileCount: 1}},
	}}}
	srv := newMeServer(f)
	cursor, limit := gen.Cursor("abc"), gen.Limit(10)
	resp, err := srv.ListMyTransfers(meCtx(t, true), gen.ListMyTransfersRequestObject{Params: gen.ListMyTransfersParams{Cursor: &cursor, Limit: &limit}})
	if err != nil {
		t.Fatal(err)
	}
	list := resp.(gen.ListMyTransfers200JSONResponse)
	if f.gotCursor != "abc" || f.gotLimit != 10 || f.gotSession != meInfo() {
		t.Errorf("service got %+v", f)
	}
	if list.NextCursor == nil || *list.NextCursor != "next" || len(list.Items) != 2 {
		t.Fatalf("list = %+v", list)
	}
	a, b := list.Items[0], list.Items[1]
	if a.Id != sampleTransfer().ID || a.FileCount != 2 || a.DownloadedBy != 1 || !a.PasswordProtected || !a.RecipientVerification ||
		a.ExpiresAt == nil || a.ConfidentialityLevel == nil || a.ConfidentialityLevel.Label != "Confidential" ||
		a.ConfidentialityLevel.Rules == nil || len(a.ConfidentialityLevel.Rules.AllowedExpiryDays) != 2 || a.Recipients[0] != "carol@customer.example.net" {
		t.Errorf("item = %+v", a)
	}
	if b.ExpiresAt != nil || b.ConfidentialityLevel != nil || b.Recipients == nil {
		t.Errorf("scanning item = %+v", b)
	}
	raw, _ := json.Marshal(list)
	for _, secret := range []string{"secret-hash", "wk_secret", "argon2id"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("list leaks %q: %s", secret, raw)
		}
	}
	// Last page, no cursor.
	f.page.NextCursor = ""
	resp, err = srv.ListMyTransfers(meCtx(t, true), gen.ListMyTransfersRequestObject{})
	if err != nil || resp.(gen.ListMyTransfers200JSONResponse).NextCursor != nil || f.gotCursor != "" || f.gotLimit != 0 {
		t.Errorf("last page = %+v, %v", resp, err)
	}
	f.err = &mytransfers.InvalidError{Field: mytransfers.FieldCursor}
	_, err = srv.ListMyTransfers(meCtx(t, true), gen.ListMyTransfersRequestObject{})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "cursor" || p.Errors[0].Code != "invalid-format" {
		t.Errorf("errors = %+v", p.Errors)
	}
}

func TestGetAndExtendMyTransfer(t *testing.T) {
	t.Parallel()
	extendable := expires.Add(7 * 24 * time.Hour)
	f := &fakeMe{detail: mytransfers.TransferDetail{
		SenderTransferDetail: store.SenderTransferDetail{
			TransferDetails: store.TransferDetails{
				Transfer:   sampleTransfer(),
				Recipients: []string{"carol@customer.example.net"},
				Files: []store.TransferFile{
					{ID: "fil_1", Name: "plans.pdf", Size: 1024, SHA256: strings.Repeat("a", 64), ScanStatus: store.ScanClean, DEKKeyID: "wk_dek", StorageName: "abcdef"},
					{ID: "fil_2", Name: "big.iso", Size: 1024, ScanStatus: store.ScanNotScannedTooLarge},
				},
			},
			DownloadedBy: 1,
			Tracking: []store.RecipientTracking{{
				LinkID: "rcl_secret", Email: "carol@customer.example.net", FirstDownloadedAt: expires, LastDownloadedAt: expires,
				Downloads: []store.RecipientDownload{{FileID: "fil_1", FirstAt: expires, LastAt: expires, Count: 2}},
			}},
		},
		LevelLabel: "Confidential", ExtendableTo: extendable,
	}}
	srv := newMeServer(f)
	resp, err := srv.GetMyTransfer(meCtx(t, true), gen.GetMyTransferRequestObject{TransferId: "trf_x"})
	if err != nil {
		t.Fatal(err)
	}
	d := gen.MyTransferDetail(resp.(gen.GetMyTransfer200JSONResponse))
	if f.gotTransfer != "trf_x" || d.FileCount != 2 || len(d.Files) != 2 || d.Files[0].Sha256 == nil || d.Files[1].Sha256 != nil ||
		d.Files[1].ScanStatus != "not_scanned_too_large" || d.ExtendableTo == nil || !d.ExtendableTo.Equal(extendable) ||
		d.ExtensionCount == nil || *d.ExtensionCount != 1 || d.DownloadCount != 2 || d.MaxDownloads == nil || *d.MaxDownloads != 3 ||
		d.Message == nil || *d.Message != "Plans" || len(d.RecipientTracking) != 1 || d.RecipientTracking[0].Downloads[0].Count != 2 {
		t.Errorf("detail = %+v", d)
	}
	raw, _ := json.Marshal(d)
	for _, secret := range []string{"secret-hash", "wk_secret", "wk_dek", "rcl_secret", "abcdef", "argon2id"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("detail leaks %q: %s", secret, raw)
		}
	}

	ext, err := srv.ExtendMyTransfer(meCtx(t, true), gen.ExtendMyTransferRequestObject{TransferId: "trf_y", Body: &gen.TransferExtension{ExpiryDays: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ext.(gen.ExtendMyTransfer200JSONResponse); !ok || f.gotTransfer != "trf_y" || f.gotDays != 7 || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("extend = %T, service got %+v", ext, f)
	}
	_, err = srv.ExtendMyTransfer(meCtx(t, true), gen.ExtendMyTransferRequestObject{TransferId: "trf_y"})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/expiryDays" || p.Errors[0].Code != "required" {
		t.Errorf("errors = %+v", p.Errors)
	}

	f.err = mytransfers.ErrNotFound
	_, err = srv.GetMyTransfer(meCtx(t, true), gen.GetMyTransferRequestObject{TransferId: "trf_x"})
	wantProblem(t, err, problem.CodeNotFound)
	_, err = srv.ExtendMyTransfer(meCtx(t, true), gen.ExtendMyTransferRequestObject{TransferId: "trf_y", Body: &gen.TransferExtension{ExpiryDays: 7}})
	wantProblem(t, err, problem.CodeNotFound)
}

func TestDeleteMyTransfer(t *testing.T) {
	t.Parallel()
	f := &fakeMe{}
	srv := newMeServer(f)
	resp, err := srv.DeleteMyTransfer(meCtx(t, true), gen.DeleteMyTransferRequestObject{TransferId: "trf_x"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitDeleteMyTransferResponse(rec); err != nil || rec.Code != http.StatusNoContent || f.gotTransfer != "trf_x" {
		t.Errorf("delete = %d, %v", rec.Code, err)
	}
	f.err = &mytransfers.BusyError{RetryAfter: 5 * time.Second}
	_, err = srv.DeleteMyTransfer(meCtx(t, true), gen.DeleteMyTransferRequestObject{TransferId: "trf_x"})
	if p := problemOf(t, err, problem.CodeStateConflict); p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 5 {
		t.Errorf("busy = %+v", p)
	}
}

func TestMyTransfersError(t *testing.T) {
	t.Parallel()
	other := errors.New("boom")
	for _, c := range []struct {
		err   error
		code  problem.Code
		field string
		fcode string
	}{
		{&mytransfers.InvalidError{Field: mytransfers.FieldEmail}, problem.CodeValidationFailed, "/email", "invalid-email"},
		{&mytransfers.InvalidError{Field: mytransfers.FieldLanguage}, problem.CodeValidationFailed, "/language", "invalid-format"},
		{&mytransfers.NotAllowedError{Allowed: []int{1, 7}}, problem.CodeValidationFailed, "/expiryDays", "not-allowed"},
		{&mytransfers.RateLimitError{RetryAfter: time.Hour}, problem.CodeRateLimited, "", ""},
		{&mytransfers.BusyError{RetryAfter: time.Second}, problem.CodeStateConflict, "", ""},
		{mytransfers.ErrMailUnavailable, problem.CodeMailUnavailable, "", ""},
		{mytransfers.ErrAccessLinkInvalid, problem.CodeAccessLinkInvalid, "", ""},
		{mytransfers.ErrUnauthenticated, problem.CodeUnauthenticated, "", ""},
		{mytransfers.ErrNotFound, problem.CodeNotFound, "", ""},
		{mytransfers.ErrNotExtendable, problem.CodeStateConflict, "", ""},
		{mytransfers.ErrExtensionLimit, problem.CodeExtensionLimitReached, "", ""},
	} {
		p := problemOf(t, myTransfersError(c.err), c.code)
		if c.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != c.field || p.Errors[0].Code != c.fcode) {
			t.Errorf("%v: errors = %+v", c.err, p.Errors)
		}
	}
	p := problemOf(t, myTransfersError(&mytransfers.NotAllowedError{Allowed: []int{1, 7}}), problem.CodeValidationFailed)
	if len(p.Errors[0].Allowed) != 2 || p.Errors[0].Allowed[1] != 7 {
		t.Errorf("allowed = %v", p.Errors[0].Allowed)
	}
	if p := problemOf(t, myTransfersError(&mytransfers.RateLimitError{RetryAfter: time.Hour}), problem.CodeRateLimited); p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
		t.Errorf("retry after = %v", p.RetryAfterSeconds)
	}
	if err := myTransfersError(other); !errors.Is(err, other) {
		t.Errorf("unknown error mapped to %v", err)
	}
}

func TestRequestMyTransfersLinkErrors(t *testing.T) {
	t.Parallel()
	f := &fakeMe{err: mytransfers.ErrMailUnavailable}
	srv := newMeServer(f)
	_, err := srv.RequestMyTransfersLink(meCtx(t, false), gen.RequestMyTransfersLinkRequestObject{
		Body: &gen.MyTransfersLinkRequest{Email: "alice@entity-a.example.com"},
	})
	wantProblem(t, err, problem.CodeMailUnavailable)
}
