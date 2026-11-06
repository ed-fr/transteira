package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/store"
)

const testDropToken = "ttd_00000000000000000000000000000001"

// withRequest puts a request carrying the Accept-Language header lang in
// ctx, as RequestMiddleware does.
func withRequest(ctx context.Context, lang string) context.Context {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", lang)
	return context.WithValue(ctx, requestKey{}, r)
}

func TestGetPublicDropLink(t *testing.T) {
	t.Parallel()
	t.Run("with level", func(t *testing.T) {
		t.Parallel()
		f := &fakeDeposit{dropLink: deposit.PublicDropLink{Label: "Supplier invoices", ValidityDays: 7, Level: &deposit.DropLinkLevel{
			Key: "internal", Label: "Interne", Rules: store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMaskAll, RequirePassword: true},
		}}}
		resp, err := newDepositServer(f).GetPublicDropLink(withRequest(depositCtx(t, nil), "fr"), gen.GetPublicDropLinkRequestObject{DropToken: testDropToken})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := resp.(gen.GetPublicDropLink200JSONResponse)
		if !ok {
			t.Fatalf("response %T", resp)
		}
		if got.Label != "Supplier invoices" || got.ValidityDays != 7 || got.Level == nil || got.Level.Key != "internal" ||
			got.Level.Label != "Interne" || got.Level.Rules == nil || !got.Level.Rules.RequirePassword ||
			len(got.Level.Rules.AllowedExpiryDays) != 3 {
			t.Errorf("body = %+v", got)
		}
		if f.gotDropToken != testDropToken || f.gotLang != "fr" || f.gotIP != netip.MustParseAddr("192.0.2.7") {
			t.Errorf("service called with token %q lang %q ip %v", f.gotDropToken, f.gotLang, f.gotIP)
		}
	})
	t.Run("without level nor request", func(t *testing.T) {
		t.Parallel()
		f := &fakeDeposit{dropLink: deposit.PublicDropLink{Label: "Scans", ValidityDays: 1}}
		resp, err := newDepositServer(f).GetPublicDropLink(depositCtx(t, nil), gen.GetPublicDropLinkRequestObject{DropToken: testDropToken})
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.(gen.GetPublicDropLink200JSONResponse); got.Level != nil || got.Label != "Scans" || f.gotLang != "" {
			t.Errorf("body = %+v, lang %q", got, f.gotLang)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{err: deposit.ErrDropLinkInvalid}).GetPublicDropLink(depositCtx(t, nil),
			gen.GetPublicDropLinkRequestObject{DropToken: "nope"})
		wantProblem(t, err, problem.CodeDropLinkInvalid)
	})
	if !requestOperations["GetPublicDropLink"] {
		t.Error("GetPublicDropLink does not get the request")
	}
}

func TestStartDepositSessionDropLink(t *testing.T) {
	t.Parallel()
	lang := "en"
	drop, inv := testDropToken, "inv_00000000000000000000000000000001"
	t.Run("challenge", func(t *testing.T) {
		t.Parallel()
		recog := "mac"
		f := &fakeDeposit{dropChallenge: deposit.Challenge{ID: "vch_d", Email: "sup@partner.example.org", ExpiresAt: expires, AttemptsRemaining: 2}}
		resp, err := newDepositServer(f).StartDepositSession(depositCtx(t, nil), gen.StartDepositSessionRequestObject{
			Params: gen.StartDepositSessionParams{AcceptLanguage: &lang, UnderscoreUnderscoreHostTtKnown: &recog},
			Body:   &gen.DepositSessionStart{Email: "sup@partner.example.org", DropLinkToken: &drop},
		})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := resp.(gen.StartDepositSession202JSONResponse)
		if !ok || got.ChallengeId != "vch_d" || got.AttemptsRemaining != 2 || !got.ExpiresAt.Equal(expires) {
			t.Fatalf("response %T %+v", resp, resp)
		}
		if f.gotDropToken != drop || f.gotEmail != "sup@partner.example.org" || f.gotLang != lang || f.gotRecog != "" {
			t.Errorf("service called with token %q email %q lang %q recognition %q", f.gotDropToken, f.gotEmail, f.gotLang, f.gotRecog)
		}
	})
	t.Run("with invitation", func(t *testing.T) {
		t.Parallel()
		f := &fakeDeposit{}
		_, err := newDepositServer(f).StartDepositSession(depositCtx(t, nil), gen.StartDepositSessionRequestObject{
			Body: &gen.DepositSessionStart{Email: "sup@partner.example.org", DropLinkToken: &drop, InvitationToken: &inv},
		})
		p := problemOf(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Field != "/dropLinkToken" || p.Errors[0].Code != "not-allowed" {
			t.Errorf("errors = %+v", p.Errors)
		}
		if f.gotDropToken != "" || f.gotEmail != "" {
			t.Error("service called")
		}
	})
	t.Run("invalid link", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{err: deposit.ErrDropLinkInvalid}).StartDepositSession(depositCtx(t, nil),
			gen.StartDepositSessionRequestObject{Body: &gen.DepositSessionStart{Email: "sup@partner.example.org", DropLinkToken: &drop}})
		wantProblem(t, err, problem.CodeDropLinkInvalid)
	})
}

func TestSessionBodyDropLink(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	info.Kind, info.CanInvite = deposit.KindDropLink, false
	info.Limits.ExpiryDays = []int{7}
	info.DropLink = &deposit.DropLinkInfo{ID: "drl_secret_record", Label: "Supplier invoices", ValidityDays: 7}
	body := sessionBody(info)
	if body.Kind != "drop_link" || body.CanInvite || body.DropLink == nil || body.DropLink.Label != "Supplier invoices" ||
		body.DropLink.ValidityDays != 7 || len(body.Limits.ExpiryDays) != 1 || body.Invitation != nil || body.Reply != nil {
		t.Errorf("body = %+v", body)
	}
	if sessionBody(internalInfo()).DropLink != nil {
		t.Error("internal session has a drop link")
	}
}
