package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

func (f *fakeDownloads) ReplyAccess(_ context.Context, _ *tenant.Tenant, token, cookie string, ip netip.Addr) (download.ReplyTarget, error) {
	f.gotToken, f.gotVerification, f.gotIP = token, cookie, ip
	return f.target, f.err
}

func (f *fakeDeposit) OpenReply(_ context.Context, _ *tenant.Tenant, ip netip.Addr, target deposit.ReplyTarget) (deposit.Session, error) {
	f.gotIP, f.gotTarget = ip, target
	return f.replySession, f.err
}

var replyExpires = time.Date(2026, 11, 2, 16, 20, 0, 0, time.UTC)

// replyTarget is the answer of the download service for a replier.
func replyTarget() download.ReplyTarget {
	return download.ReplyTarget{
		TransferID: "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS", LinkID: "rcl_01JABCD8E3W5Q2Z7K9M4N6P0RS",
		Email: "carol@customer.example.net", Recipient: "alice@entity-a.example.com", TransferExpiresAt: replyExpires,
	}
}

// replySessionInfo is the session opened for replyTarget.
func replySessionInfo() deposit.SessionInfo {
	info := internalInfo()
	info.Email, info.Kind, info.CanInvite = "carol@customer.example.net", deposit.KindReply, false
	info.ReplyToTransferID = "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS"
	info.Reply = &deposit.ReplyInfo{Recipient: "alice@entity-a.example.com", TransferExpiresAt: replyExpires}
	return info
}

func TestStartTransferReply(t *testing.T) {
	t.Parallel()
	d := &fakeDownloads{target: replyTarget()}
	dep := &fakeDeposit{replySession: deposit.Session{Token: "ds_reply", SessionInfo: replySessionInfo()}}
	s := NewServer(WithDownloads(d), WithDeposit(dep))
	s.now = func() time.Time { return expires.Add(-4 * time.Hour) }
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: download.VerificationCookieName, Value: "rv_cookie"})
	resp, err := s.StartTransferReply(downloadCtx(t, r), gen.StartTransferReplyRequestObject{
		LinkToken: linkToken, Body: &gen.TransferReplyStart{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.gotToken != linkToken || d.gotVerification != "rv_cookie" || d.gotIP != netip.MustParseAddr("192.0.2.7") ||
		dep.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("services called with %+v / %+v", d, dep)
	}
	if want := (deposit.ReplyTarget{
		TransferID: "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS", LinkID: "rcl_01JABCD8E3W5Q2Z7K9M4N6P0RS",
		Email: "carol@customer.example.net", Recipient: "alice@entity-a.example.com", TransferExpiresAt: replyExpires,
	}); dep.gotTarget != want {
		t.Errorf("target = %+v", dep.gotTarget)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitStartTransferReplyResponse(rec); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], middleware.DepositCookie+"=ds_reply;") || !strings.Contains(cookies[0], "HttpOnly") {
		t.Errorf("cookies = %q", cookies)
	}
	body := decodeSession(t, rec)
	if body.Kind != gen.DepositorKind("reply") || body.CanInvite || body.Email != "carol@customer.example.net" ||
		body.Reply == nil || body.Reply.Recipient != "alice@entity-a.example.com" || !body.Reply.TransferExpiresAt.Equal(replyExpires) {
		t.Errorf("body = %+v", body)
	}
	if strings.Contains(rec.Body.String(), "trf_") || strings.Contains(rec.Body.String(), "rcl_") {
		t.Errorf("internal identifiers leaked: %s", rec.Body)
	}
	// A body is optional; a supported language is accepted.
	fr := gen.Language("fr")
	for _, b := range []*gen.TransferReplyStart{nil, {Language: &fr}} {
		if _, err := s.StartTransferReply(downloadCtx(t, nil), gen.StartTransferReplyRequestObject{LinkToken: linkToken, Body: b}); err != nil {
			t.Errorf("body %+v: %v", b, err)
		}
	}
	// An unsupported language is refused before any service is called.
	d.gotToken = ""
	de := gen.Language("de")
	_, err = s.StartTransferReply(downloadCtx(t, nil), gen.StartTransferReplyRequestObject{LinkToken: linkToken, Body: &gen.TransferReplyStart{Language: &de}})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/language" || d.gotToken != "" {
		t.Errorf("errors = %+v, service token %q", p.Errors, d.gotToken)
	}
}

func TestStartTransferReplyErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		download error
		deposit  error
		code     problem.Code
	}{
		{"reply not allowed", download.ErrReplyNotAllowed, nil, problem.CodeReplyNotAllowed},
		{"verification required", download.ErrRecipientVerificationRequired, nil, problem.CodeRecipientVerificationRequired},
		{"gone", download.ErrGone, nil, problem.CodeTransferGone},
		{"unknown link", download.ErrNotFound, nil, problem.CodeNotFound},
		{"replier blocklisted", nil, deposit.ErrForbidden, problem.CodeDepositNotAllowed},
		{"original gone", nil, deposit.ErrReplyGone, problem.CodeTransferGone},
		{"too many reply sessions", nil, &deposit.RateLimitError{RetryAfter: 4 * time.Hour}, problem.CodeRateLimited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := NewServer(WithDownloads(&fakeDownloads{err: tc.download, target: replyTarget()}), WithDeposit(&fakeDeposit{err: tc.deposit}))
			_, err := s.StartTransferReply(downloadCtx(t, nil), gen.StartTransferReplyRequestObject{LinkToken: linkToken})
			wantProblem(t, err, tc.code)
		})
	}
	// Wiring errors and a missing tenant.
	_, err := NewServer(WithDownloads(&fakeDownloads{})).StartTransferReply(downloadCtx(t, nil), gen.StartTransferReplyRequestObject{})
	if err == nil || !strings.Contains(err.Error(), "no deposit service") {
		t.Errorf("without deposit service: %v", err)
	}
	_, err = NewServer(WithDeposit(&fakeDeposit{})).StartTransferReply(downloadCtx(t, nil), gen.StartTransferReplyRequestObject{})
	if err == nil || !strings.Contains(err.Error(), "no download service") {
		t.Errorf("without download service: %v", err)
	}
	_, err = NewServer(WithDownloads(&fakeDownloads{}), WithDeposit(&fakeDeposit{})).StartTransferReply(context.Background(), gen.StartTransferReplyRequestObject{})
	wantProblem(t, err, problem.CodeUnknownTenant)
}

func TestStartRecipientVerificationReplyNotAllowed(t *testing.T) {
	t.Parallel()
	_, err := NewServer(WithDownloads(&fakeDownloads{err: download.ErrReplyNotAllowed})).StartRecipientVerification(
		downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{})
	wantProblem(t, err, problem.CodeReplyNotAllowed)
}

func TestGetDownloadReplyFlags(t *testing.T) {
	t.Parallel()
	get := func(v download.View) gen.PublicTransfer {
		t.Helper()
		resp, err := NewServer(WithDownloads(&fakeDownloads{view: v})).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{LinkToken: linkToken})
		if err != nil {
			t.Fatal(err)
		}
		return gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse))
	}
	got := get(download.View{SenderEmail: "alice@entity-a.example.com", ReplyAllowed: true})
	if got.ReplyAllowed == nil || !*got.ReplyAllowed || got.Reply != nil {
		t.Errorf("replyable: %+v", got)
	}
	got = get(download.View{SenderEmail: "alice@entity-a.example.com"})
	if got.ReplyAllowed == nil || *got.ReplyAllowed || got.Reply != nil {
		t.Errorf("not replyable: %+v", got)
	}
	got = get(download.View{SenderEmail: "carol@customer.example.net", Reply: true})
	if got.ReplyAllowed == nil || *got.ReplyAllowed || got.Reply == nil || !*got.Reply {
		t.Errorf("reply transfer: %+v", got)
	}
	// Locked: neither flag.
	got = get(download.View{SenderEmail: "alice@entity-a.example.com", Locked: true, ReplyAllowed: true, Reply: true})
	if got.ReplyAllowed != nil || got.Reply != nil {
		t.Errorf("locked: %+v", got)
	}
}

func TestSenderOfReply(t *testing.T) {
	t.Parallel()
	sender := senderOf(depositCtx(t, nil), replySessionInfo())
	want := store.Depositor{Email: "carol@customer.example.net", Kind: store.DepositorReply, ReplyToTransferID: "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS"}
	if sender.Depositor != want || sender.InvitationID != "" || sender.ReplyToTransferID != want.ReplyToTransferID {
		t.Errorf("sender = %+v", sender)
	}
	// An ordinary session has no source transfer.
	if got := senderOf(depositCtx(t, nil), internalInfo()); got.ReplyToTransferID != "" {
		t.Errorf("internal sender = %+v", got)
	}
}

func TestTransferBodyReplyTo(t *testing.T) {
	t.Parallel()
	if b := transferBody(transfer.Details{ReplyToTransferID: "trf_orig"}); b.ReplyToTransferId == nil || *b.ReplyToTransferId != "trf_orig" {
		t.Errorf("reply body = %+v", b.ReplyToTransferId)
	}
	if b := transferBody(transfer.Details{}); b.ReplyToTransferId != nil {
		t.Errorf("plain body = %+v", b.ReplyToTransferId)
	}
}

func TestGetPublicTenantReplyFeature(t *testing.T) {
	t.Parallel()
	for _, allowed := range []bool{true, false} {
		ctx := tenant.WithTenant(context.Background(), &tenant.Tenant{
			ID: "ten_x", Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "fr",
			MaxTransferBytes: 5 << 30, PrimaryColor: "#0B5FFF", AccentColor: "#00875A", AllowTransferReply: allowed,
		})
		resp, err := NewServer(WithTenantService(&fakeTenantConfig{})).GetPublicTenant(ctx, gen.GetPublicTenantRequestObject{})
		if err != nil {
			t.Fatal(err)
		}
		if b := resp.(gen.GetPublicTenant200JSONResponse).Body; b.Features == nil || b.Features.TransferReply != allowed {
			t.Errorf("allowed=%v: features %+v", allowed, b.Features)
		}
	}
}
