package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
)

// withFlowCookie returns ctx carrying the flow cookie value, as
// middleware.FlowCookie puts it.
func withFlowCookie(t *testing.T, ctx context.Context, value string) context.Context {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/cb", nil)
	req.AddCookie(&http.Cookie{Name: oidc.FlowCookieName, Value: value})
	var got context.Context
	middleware.FlowCookie(oidc.FlowCookieName, "x", func(*http.Request) bool { return true })(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() })).ServeHTTP(nopWriter{}, req)
	return got
}

// nopWriter discards a response.
type nopWriter struct{}

func (nopWriter) Header() http.Header         { return http.Header{} }
func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriter) WriteHeader(int)             {}

func TestAuthMethodsAndStart(t *testing.T) {
	t.Parallel()
	anon := ctxWith("", adminauth.Account{})
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	resp, err := s.GetAdminAuthMethods(anon, gen.GetAdminAuthMethodsRequestObject{})
	if err != nil || resp.(gen.GetAdminAuthMethods200JSONResponse) != (gen.GetAdminAuthMethods200JSONResponse{Password: true, Sso: true}) {
		t.Errorf("GetAdminAuthMethods = %+v, %v", resp, err)
	}
	start, err := s.StartAdminOidcLogin(anon, gen.StartAdminOidcLoginRequestObject{Body: &gen.OidcStart{Email: "a@entity-a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, start)
	cookie := rec.Header().Get("Set-Cookie")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"redirectUrl":"https://login.example.com/authorize?state=s"`) ||
		!strings.HasPrefix(cookie, oidc.FlowCookieName+"=of_flow.mac") || !strings.Contains(cookie, "SameSite=Lax") ||
		!strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") {
		t.Errorf("start = %d %s %s", rec.Code, rec.Header(), rec.Body)
	}
	if args := svc.args["StartSSO"]; args[0] != "a@entity-a.example.com" || args[1] != clientIP {
		t.Errorf("StartSSO args = %v", args)
	}
	_, err = s.StartAdminOidcLogin(anon, gen.StartAdminOidcLoginRequestObject{})
	expectProblem(t, err, problem.CodeValidationFailed)
	for err, code := range map[error]problem.Code{
		adminauth.ErrSSONotAvailable:                         problem.CodeSSONotAvailable,
		&adminauth.RateLimitError{RetryAfter: time.Second}:   problem.CodeRateLimited,
		&adminauth.InvalidError{Field: adminauth.FieldEmail}: problem.CodeValidationFailed,
	} {
		_, got := newServer(&fakeService{err: err}, &fakeTenants{}).StartAdminOidcLogin(anon,
			gen.StartAdminOidcLoginRequestObject{Body: &gen.OidcStart{Email: "a@entity-a.example.com"}})
		expectProblem(t, got, code)
	}
	_, err = newServer(&fakeService{err: errors.New("boom")}, &fakeTenants{}).GetAdminAuthMethods(anon, gen.GetAdminAuthMethodsRequestObject{})
	if err == nil {
		t.Error("methods failure hidden")
	}
	noSvc := NewServer()
	if _, err := noSvc.GetAdminAuthMethods(anon, gen.GetAdminAuthMethodsRequestObject{}); !errors.Is(err, errNoService) {
		t.Error(err)
	}
	if _, err := noSvc.StartAdminOidcLogin(anon, gen.StartAdminOidcLoginRequestObject{}); !errors.Is(err, errNoService) {
		t.Error(err)
	}
	if _, err := noSvc.CompleteAdminOidcLogin(anon, gen.CompleteAdminOidcLoginRequestObject{}); !errors.Is(err, errNoService) {
		t.Error(err)
	}
}

func TestCompleteAdminOidcLogin(t *testing.T) {
	t.Parallel()
	ctx := withFlowCookie(t, ctxWith("", adminauth.Account{}), "of_flow.mac")
	str := func(s string) *string { return &s }
	params := gen.CompleteAdminOidcLoginParams{Code: str("c"), State: str("s"), Iss: str("https://idp"), Error: str("")}

	svc := &fakeService{}
	resp, err := newServer(svc, &fakeTenants{}).CompleteAdminOidcLogin(ctx, gen.CompleteAdminOidcLoginRequestObject{Params: params})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != SSOSuccessLocation ||
		!strings.HasPrefix(rec.Header().Get("Set-Cookie"), middleware.AdminCookie+"=as_tok") {
		t.Errorf("success = %d %v", rec.Code, rec.Header())
	}
	want := adminauth.SSOCallback{Cookie: "of_flow.mac", Code: "c", State: "s", Iss: "https://idp"}
	if got := svc.args["CompleteSSO"]; got[0] != want || got[1] != clientIP {
		t.Errorf("CompleteSSO args = %v", got)
	}

	for err, code := range map[error]string{
		&adminauth.SSOError{Reason: securitylog.ReasonMFAMissing}:       "sso-mfa-required",
		&adminauth.SSOError{Reason: securitylog.ReasonIdentityMismatch}: "invalid-credentials",
		&adminauth.SSOError{Reason: securitylog.ReasonStateInvalid}:     "invalid-credentials",
		&adminauth.RateLimitError{RetryAfter: time.Second}:              "rate-limited",
		adminauth.ErrSSONotAvailable:                                    "sso-not-available",
	} {
		resp, got := newServer(&fakeService{err: err}, &fakeTenants{}).CompleteAdminOidcLogin(ctx,
			gen.CompleteAdminOidcLoginRequestObject{})
		if got != nil {
			t.Fatalf("%v: %v", err, got)
		}
		rec := visit(t, resp)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login?error="+code ||
			rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("%v: %d %v", err, rec.Code, rec.Header())
		}
	}
	boom := errors.New("database down")
	if _, err := newServer(&fakeService{err: boom}, &fakeTenants{}).CompleteAdminOidcLogin(ctx,
		gen.CompleteAdminOidcLoginRequestObject{}); !errors.Is(err, boom) {
		t.Errorf("internal failure = %v", err)
	}
}

func TestDeleteAdminIdentityAndViews(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	resp, err := s.DeleteAdminIdentity(super, gen.DeleteAdminIdentityRequestObject{AdminId: "adm_x", IdentityId: "aid_y"})
	if _, ok := resp.(gen.DeleteAdminIdentity204Response); err != nil || !ok {
		t.Errorf("DeleteAdminIdentity = %v, %v", resp, err)
	}
	if args := svc.args["DeleteIdentity"]; args[1] != "adm_x" || args[2] != "aid_y" {
		t.Errorf("args = %v", args)
	}
	_, err = newServer(&fakeService{err: adminauth.ErrNotFound}, &fakeTenants{}).DeleteAdminIdentity(super,
		gen.DeleteAdminIdentityRequestObject{AdminId: "adm_x", IdentityId: "aid_y"})
	expectProblem(t, err, problem.CodeNotFound)
	_, err = s.DeleteAdminIdentity(ctxWith("", adminauth.Account{}), gen.DeleteAdminIdentityRequestObject{})
	expectProblem(t, err, problem.CodeUnauthenticated)

	// Views: ssoOnly always, identities when read, without tenant.
	linked := now.Add(-time.Hour)
	a := delegated
	a.SSOOnly = true
	a.Identities = []adminauth.Identity{{ID: "aid_1", Issuer: "https://idp.example.com", ClientID: "app", LinkedAt: linked}}
	b := adminBody(a)
	if b.SsoOnly == nil || !*b.SsoOnly || b.Identities == nil || len(*b.Identities) != 1 ||
		(*b.Identities)[0] != (gen.AdminIdentity{Id: "aid_1", Issuer: "https://idp.example.com", ClientId: "app", LinkedAt: linked}) {
		t.Errorf("adminBody = %+v", b)
	}
	if b := adminBody(delegated); b.SsoOnly == nil || *b.SsoOnly || b.Identities != nil {
		t.Errorf("adminBody(no identities) = %+v", b)
	}
	c := createdBody(a, adminauth.Activation{Delivery: adminauth.DeliveryNone, ExpiresAt: a.CreatedAt})
	if c.InvitationDelivery != gen.InvitationDeliveryNone || c.ActivationUrl != nil || !c.ActivationExpiresAt.Equal(a.CreatedAt) ||
		c.SsoOnly == nil || !*c.SsoOnly || c.Identities == nil {
		t.Errorf("createdBody(none) = %+v", c)
	}

	// The delivery none reaches the service.
	none := gen.InvitationDeliveryNone
	tids := []string{"ten_a"}
	svc = &fakeService{}
	if _, err := newServer(svc, &fakeTenants{}).CreateAdmin(super, gen.CreateAdminRequestObject{Body: &gen.AdminCreate{
		Username: "sso.a", Email: "sso@entity-a.example.com", Role: gen.DelegatedAdmin, TenantIds: &tids,
		Invitation: &gen.AdminInvitation{Delivery: &none},
	}}); err != nil {
		t.Fatal(err)
	}
	if req := svc.args["Create"][1].(adminauth.AdminCreate); req.Invitation.Delivery != adminauth.DeliveryNone {
		t.Errorf("Create got %+v", req)
	}
}

func TestSSOServiceErrors(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]problem.Code{
		adminauth.ErrSSORequired:      problem.CodeSSORequired,
		adminauth.ErrSSONotAvailable:  problem.CodeSSONotAvailable,
		adminauth.ErrSSONotConfigured: problem.CodeSSONotConfigured,
		adminauth.ErrSSOOnlyEnforced:  problem.CodeStateConflict,
	} {
		expectProblem(t, serviceError(err), code)
	}
}
