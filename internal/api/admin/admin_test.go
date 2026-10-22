package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

var (
	now       = time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("192.0.2.10")
	superRoot = adminauth.Account{
		ID: "adm_root", Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin, TOTPEnabled: true,
		Activated: true, RequireTOTP: true, Language: "fr", CreatedAt: now.Add(-time.Hour), LastLoginAt: now.Add(-time.Minute),
	}
	delegated = adminauth.Account{
		ID: "adm_deleg", Username: "admin.entity-a", Email: "admin@entity-a.example.com", Role: store.RoleDelegatedAdmin,
		TenantIDs: []tenant.ID{"ten_a", "ten_gone"}, CreatedAt: now.Add(-time.Hour),
	}
)

// fakeService records the calls and answers err, or canned values.
type fakeService struct {
	err   error
	calls []string
	// args are the last arguments received, per method.
	args map[string][]any
	// page is the answer of List.
	page store.Page[adminauth.Account]
	// confirmed is the answer of ConfirmEnrollment.
	confirmed adminauth.Confirmed
}

func (f *fakeService) record(name string, args ...any) error {
	f.calls = append(f.calls, name)
	if f.args == nil {
		f.args = map[string][]any{}
	}
	f.args[name] = args
	return f.err
}

// link is the activation link answered by Create and ResetCredentials.
var link = adminauth.Activation{
	URL: "https://admin.transfer.example.com/admin/activate#act_x", ExpiresAt: now.Add(72 * time.Hour),
}

// session returns a session in state; an intermediate state ends 5 minutes
// from now.
func session(state store.AdminSessionState) adminauth.Session {
	s := adminauth.Session{Token: "as_tok", CSRFToken: "csrf_tok", State: state, ExpiresAt: now.Add(12 * time.Hour)}
	if state != store.SessionAuthenticated {
		s.StateExpiresAt = now.Add(5 * time.Minute)
	}
	return s
}

func (f *fakeService) SetupRequired(context.Context) (bool, error) {
	return true, f.record("SetupRequired")
}

func (f *fakeService) CreateSuperAdmin(_ context.Context, req adminauth.SetupRequest, ip netip.Addr) (adminauth.SetupResult, error) {
	return adminauth.SetupResult{
		Session:    session(store.SessionTOTPEnrollmentRequired),
		Enrollment: adminauth.Enrollment{Secret: "JBSWY3DP", URI: "otpauth://totp/x", QRPNG: []byte{0x89, 'P', 'N', 'G'}},
	}, f.record("CreateSuperAdmin", req, ip)
}

func (f *fakeService) Login(_ context.Context, username, password string, ip netip.Addr) (adminauth.Session, error) {
	return session(store.SessionTOTPRequired), f.record("Login", username, password, ip)
}

func (f *fakeService) VerifyTOTP(_ context.Context, p adminauth.Principal, code, recovery string, ip netip.Addr) (adminauth.Session, error) {
	return session(store.SessionAuthenticated), f.record("VerifyTOTP", p.SessionID, code, recovery, ip)
}

func (f *fakeService) Logout(_ context.Context, p adminauth.Principal, ip netip.Addr) error {
	return f.record("Logout", p.SessionID, ip)
}

func (f *fakeService) ChangePassword(_ context.Context, p adminauth.Principal, cur, next string, ip netip.Addr) error {
	return f.record("ChangePassword", p.SessionID, cur, next, ip)
}

func (f *fakeService) StartEnrollment(_ context.Context, p adminauth.Principal, cur string, ip netip.Addr) (adminauth.Enrollment, error) {
	return adminauth.Enrollment{Secret: "JBSWY3DP", URI: "otpauth://totp/x", QRPNG: []byte("png")}, f.record("StartEnrollment", p.SessionID, cur, ip)
}

func (f *fakeService) ConfirmEnrollment(_ context.Context, p adminauth.Principal, code string, ip netip.Addr) (adminauth.Confirmed, error) {
	return f.confirmed, f.record("ConfirmEnrollment", p.SessionID, code, ip)
}

func (f *fakeService) DisableTOTP(_ context.Context, p adminauth.Principal, cur string, ip netip.Addr) error {
	return f.record("DisableTOTP", p.SessionID, cur, ip)
}

func (f *fakeService) List(_ context.Context, p adminauth.Principal, cursor string, limit int) (store.Page[adminauth.Account], error) {
	return f.page, f.record("List", p.SessionID, cursor, limit)
}

func (f *fakeService) Get(_ context.Context, p adminauth.Principal, id string) (adminauth.Account, error) {
	return delegated, f.record("Get", p.SessionID, id)
}

func (f *fakeService) Create(_ context.Context, p adminauth.Principal, req adminauth.AdminCreate, ip netip.Addr) (adminauth.Account, adminauth.Activation, error) {
	return delegated, link, f.record("Create", p.SessionID, req, ip)
}

func (f *fakeService) Update(_ context.Context, p adminauth.Principal, id string, u adminauth.AdminUpdate, ip netip.Addr) (adminauth.Account, error) {
	return delegated, f.record("Update", p.SessionID, id, u, ip)
}

func (f *fakeService) Delete(_ context.Context, p adminauth.Principal, id string, ip netip.Addr) error {
	return f.record("Delete", p.SessionID, id, ip)
}

func (f *fakeService) ResetCredentials(_ context.Context, p adminauth.Principal, id string, ip netip.Addr) (adminauth.Account, adminauth.Activation, error) {
	return delegated, link, f.record("ResetCredentials", p.SessionID, id, ip)
}

func (f *fakeService) Activate(_ context.Context, token, password string, ip netip.Addr) (adminauth.Session, error) {
	return session(store.SessionTOTPEnrollmentRequired), f.record("Activate", token, password, ip)
}

// fakeTenants holds ten_a and ten_b; ten_gone is unknown; ten_boom fails.
type fakeTenants struct {
	listErr error
	// lists counts the List calls (two pages).
	lists int
}

func (f *fakeTenants) Get(_ context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	switch tid {
	case "ten_a":
		return &tenant.Tenant{ID: tid, Name: "Entity A", FQDN: "transfer.entity-a.example.com"}, nil
	case "ten_boom":
		return nil, errors.New("database down")
	}
	return nil, fmt.Errorf("get tenant: %w", store.ErrNotFound)
}

func (f *fakeTenants) List(_ context.Context, opts store.TenantListOptions) (store.Page[*tenant.Tenant], error) {
	f.lists++
	if f.listErr != nil {
		return store.Page[*tenant.Tenant]{}, f.listErr
	}
	if opts.Limit != store.MaxPageSize {
		return store.Page[*tenant.Tenant]{}, errors.New("unexpected page size")
	}
	if opts.Cursor == "" {
		return store.Page[*tenant.Tenant]{
			Items:      []*tenant.Tenant{{ID: "ten_a", Name: "Entity A", FQDN: "transfer.entity-a.example.com"}},
			NextCursor: "next",
		}, nil
	}
	return store.Page[*tenant.Tenant]{Items: []*tenant.Tenant{{ID: "ten_b", Name: "Entity B", FQDN: "transfer.entity-b.example.com"}}}, nil
}

// newServer returns a server over svc and tenants with a fixed clock.
func newServer(svc Service, tenants Tenants) *Server {
	s := NewServer(WithService(svc), WithTenants(tenants))
	s.now = func() time.Time { return now }
	return s
}

// ctxWith returns a context carrying the client IP and, unless state is
// empty, a session of a in state, as the middlewares put them.
func ctxWith(state store.AdminSessionState, a adminauth.Account) context.Context {
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = clientIP.String() + ":1234"
	var got context.Context
	h := middleware.RealIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() }))
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
	if state == "" {
		return got
	}
	p := adminauth.Principal{SessionID: "as_01", State: state, CSRFToken: "csrf_01", ExpiresAt: now.Add(time.Hour), Admin: a}
	resolver := principalResolver{p: p}
	req = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(got)
	req.AddCookie(&http.Cookie{Name: middleware.AdminCookie, Value: "as_raw"})
	middleware.AdminSession(resolver, func(*http.Request) bool { return true }, nil)(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() })).ServeHTTP(httptest.NewRecorder(), req)
	return got
}

// principalResolver resolves any token to p.
type principalResolver struct{ p adminauth.Principal }

func (r principalResolver) ResolveSession(context.Context, string) (any, bool, error) {
	return r.p, true, nil
}
func (principalResolver) CheckCSRF(string, string) bool { return true }

// expectProblem asserts that err renders as a Problem with code.
func expectProblem(t *testing.T, err error, code problem.Code) problem.Problem {
	t.Helper()
	var p *problem.Problem
	if !errors.As(err, &p) || p.Code != code {
		t.Fatalf("error %v, want a %s Problem", err, code)
	}
	return *p
}

// visit renders a strict response to a recorder through its Visit method.
func visit(t *testing.T, resp any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	m := reflect.ValueOf(resp).MethodByName(visitName(resp))
	if !m.IsValid() {
		t.Fatalf("%T has no Visit method", resp)
	}
	if out := m.Call([]reflect.Value{reflect.ValueOf(rec)}); !out[0].IsNil() {
		t.Fatalf("visit: %v", out[0].Interface())
	}
	return rec
}

// visitName returns the name of the Visit...Response method of resp.
func visitName(resp any) string {
	typ := reflect.TypeOf(resp)
	for i := range typ.NumMethod() {
		if n := typ.Method(i).Name; strings.HasPrefix(n, "Visit") {
			return n
		}
	}
	return ""
}

func TestServiceErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		err  error
		code problem.Code
	}{
		{&adminauth.InvalidError{Field: adminauth.FieldUsername}, problem.CodeValidationFailed},
		{adminauth.ErrInvalid, problem.CodeValidationFailed},
		{&adminauth.RateLimitError{RetryAfter: 30 * time.Second}, problem.CodeRateLimited},
		{adminauth.ErrRateLimited, problem.CodeRateLimited},
		{adminauth.ErrInvalidCredentials, problem.CodeInvalidCredentials},
		{adminauth.ErrUnauthenticated, problem.CodeUnauthenticated},
		{adminauth.ErrForbidden, problem.CodeForbidden},
		{adminauth.ErrSetupTokenInvalid, problem.CodeSetupTokenInvalid},
		{adminauth.ErrSetupDone, problem.CodeSetupAlreadyDone},
		{adminauth.ErrNotFound, problem.CodeNotFound},
		{adminauth.ErrAlreadyExists, problem.CodeAlreadyExists},
		{adminauth.ErrStateConflict, problem.CodeStateConflict},
		{adminauth.ErrLastSuperAdmin, problem.CodeStateConflict},
		{adminauth.ErrSelfAction, problem.CodeStateConflict},
		{adminauth.ErrNoPendingEnrollment, problem.CodeStateConflict},
		{adminauth.ErrNotPromotable, problem.CodeStateConflict},
		{adminauth.ErrAccountDisabled, problem.CodeStateConflict},
		{fmt.Errorf("wrapped: %w", adminauth.ErrNotFound), problem.CodeNotFound},
	}
	for _, tt := range tests {
		got := serviceError(tt.err)
		p := expectProblem(t, got, tt.code)
		switch tt.code {
		case problem.CodeValidationFailed:
			if errors.As(tt.err, new(*adminauth.InvalidError)) && (len(p.Errors) != 1 || p.Errors[0].Field != "/username" || p.Errors[0].Code != fieldInvalidFormat) {
				t.Errorf("%v: field errors %+v", tt.err, p.Errors)
			}
		case problem.CodeRateLimited:
			if errors.As(tt.err, new(*adminauth.RateLimitError)) && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 30) {
				t.Errorf("%v: retry after %v", tt.err, p.RetryAfterSeconds)
			}
		}
	}
	if got := serviceError(boom); got != boom { //nolint:errorlint // identity is the point
		t.Errorf("serviceError(other) = %v, want it unchanged", got)
	}
	if got := serviceError(adminauth.ErrNoClientIP); !errors.Is(got, adminauth.ErrNoClientIP) {
		t.Errorf("ErrNoClientIP = %v, want a 500 keeping the cause", got)
	}
}

func TestSessionCookie(t *testing.T) {
	t.Parallel()
	s := newServer(&fakeService{}, &fakeTenants{})
	for _, tt := range []struct {
		sess adminauth.Session
		want string
	}{
		{session(store.SessionAuthenticated), "Max-Age=43200"},
		{session(store.SessionTOTPRequired), "Max-Age=300"},
		// The state expiry drives the cookie, whatever its length.
		{adminauth.Session{Token: "as_tok", State: store.SessionTOTPRequired, ExpiresAt: now.Add(time.Hour), StateExpiresAt: now.Add(10 * time.Minute)}, "Max-Age=600"},
		{adminauth.Session{Token: "as_tok", State: store.SessionTOTPRequired, ExpiresAt: now.Add(time.Minute), StateExpiresAt: now.Add(10 * time.Minute)}, "Max-Age=60"},
		{adminauth.Session{Token: "as_tok", State: store.SessionAuthenticated, ExpiresAt: now.Add(-time.Minute)}, "Max-Age=1"},
	} {
		c := *s.sessionCookie(tt.sess)
		if !strings.HasPrefix(c, "__Host-tt_admin=as_tok; Path=/; "+tt.want+"; HttpOnly; Secure; SameSite=Strict") {
			t.Errorf("cookie %q, want %s", c, tt.want)
		}
	}
}

func TestGetVersion(t *testing.T) {
	t.Parallel()
	s := NewServer()
	for _, tt := range []struct {
		commit string
		want   *string
	}{
		{"3f9c2ab", ptr("3f9c2ab")}, {unknownCommit, nil}, {"", nil},
	} {
		s.version = func() version.Info { return version.Info{Version: "1.2.3", Commit: tt.commit} }
		resp, err := s.GetVersion(context.Background(), gen.GetVersionRequestObject{})
		v, ok := resp.(gen.GetVersion200JSONResponse)
		if err != nil || !ok || v.Version != "1.2.3" || v.ApiVersion != gen.V1 || !reflect.DeepEqual(v.Commit, tt.want) {
			t.Errorf("commit %q: %+v %v", tt.commit, resp, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestNoService(t *testing.T) {
	t.Parallel()
	s := NewServer()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	calls := []func() error{
		func() error { _, err := s.GetSetupStatus(ctx, gen.GetSetupStatusRequestObject{}); return err },
		func() error { _, err := s.CreateSuperAdmin(ctx, gen.CreateSuperAdminRequestObject{}); return err },
		func() error { _, err := s.AdminLogin(ctx, gen.AdminLoginRequestObject{}); return err },
		func() error { _, err := s.AdminVerifyTotp(ctx, gen.AdminVerifyTotpRequestObject{}); return err },
		func() error { _, err := s.ChangeAdminPassword(ctx, gen.ChangeAdminPasswordRequestObject{}); return err },
		func() error { _, err := s.ActivateAdmin(ctx, gen.ActivateAdminRequestObject{}); return err },
		func() error { _, err := s.GetAdminMe(ctx, gen.GetAdminMeRequestObject{}); return err },
	}
	for i, call := range calls {
		err := call()
		if !errors.Is(err, errNoService) && !errors.Is(err, errNoTenants) {
			t.Errorf("call %d: %v, want a wiring error", i, err)
		}
	}
}

func TestNoSession(t *testing.T) {
	t.Parallel()
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith("", adminauth.Account{})
	pending := ctxWith(store.SessionTOTPRequired, superRoot)
	type call func(context.Context) error
	sessionOps := map[string]call{
		"AdminVerifyTotp": func(ctx context.Context) error {
			_, err := s.AdminVerifyTotp(ctx, gen.AdminVerifyTotpRequestObject{})
			return err
		},
		"AdminLogout": func(ctx context.Context) error {
			_, err := s.AdminLogout(ctx, gen.AdminLogoutRequestObject{})
			return err
		},
		"StartTotpEnrollment": func(ctx context.Context) error {
			_, err := s.StartTotpEnrollment(ctx, gen.StartTotpEnrollmentRequestObject{})
			return err
		},
		"ConfirmTotpEnrollment": func(ctx context.Context) error {
			_, err := s.ConfirmTotpEnrollment(ctx, gen.ConfirmTotpEnrollmentRequestObject{})
			return err
		},
	}
	authOps := map[string]call{
		"GetAdminMe": func(ctx context.Context) error {
			_, err := s.GetAdminMe(ctx, gen.GetAdminMeRequestObject{})
			return err
		},
		"ChangeAdminPassword": func(ctx context.Context) error {
			_, err := s.ChangeAdminPassword(ctx, gen.ChangeAdminPasswordRequestObject{})
			return err
		},
		"DisableTotp": func(ctx context.Context) error {
			_, err := s.DisableTotp(ctx, gen.DisableTotpRequestObject{})
			return err
		},
		"ListAdmins": func(ctx context.Context) error {
			_, err := s.ListAdmins(ctx, gen.ListAdminsRequestObject{})
			return err
		},
		"CreateAdmin": func(ctx context.Context) error {
			_, err := s.CreateAdmin(ctx, gen.CreateAdminRequestObject{})
			return err
		},
		"GetAdmin": func(ctx context.Context) error { _, err := s.GetAdmin(ctx, gen.GetAdminRequestObject{}); return err },
		"UpdateAdmin": func(ctx context.Context) error {
			_, err := s.UpdateAdmin(ctx, gen.UpdateAdminRequestObject{})
			return err
		},
		"DeleteAdmin": func(ctx context.Context) error {
			_, err := s.DeleteAdmin(ctx, gen.DeleteAdminRequestObject{})
			return err
		},
		"ResetAdminCredentials": func(ctx context.Context) error {
			_, err := s.ResetAdminCredentials(ctx, gen.ResetAdminCredentialsRequestObject{})
			return err
		},
	}
	for _, c := range sessionOps {
		expectProblem(t, c(ctx), problem.CodeUnauthenticated)
	}
	for name, c := range authOps {
		expectProblem(t, c(ctx), problem.CodeUnauthenticated)
		// An intermediate state does not open them: refused before the
		// service.
		if err := c(pending); err == nil {
			t.Errorf("%s accepted a session in state totp_required", name)
		} else {
			expectProblem(t, err, problem.CodeUnauthenticated)
		}
	}
	if len(svc.calls) != 0 {
		t.Errorf("the service was called: %v", svc.calls)
	}
	// Without service either, the session operations answer 500.
	noSvc := NewServer()
	if _, err := noSvc.AdminLogout(pending, gen.AdminLogoutRequestObject{}); !errors.Is(err, errNoService) {
		t.Errorf("logout without service: %v", err)
	}
	if _, err := noSvc.ListAdmins(pending, gen.ListAdminsRequestObject{}); !errors.Is(err, errNoService) {
		t.Errorf("list without service: %v", err)
	}
}

func TestMissingBodies(t *testing.T) {
	t.Parallel()
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	errs := []error{}
	add := func(_ any, err error) { errs = append(errs, err) }
	add(s.CreateSuperAdmin(ctx, gen.CreateSuperAdminRequestObject{}))
	add(s.AdminLogin(ctx, gen.AdminLoginRequestObject{}))
	add(s.AdminVerifyTotp(ctx, gen.AdminVerifyTotpRequestObject{}))
	add(s.ChangeAdminPassword(ctx, gen.ChangeAdminPasswordRequestObject{}))
	add(s.DisableTotp(ctx, gen.DisableTotpRequestObject{}))
	add(s.ConfirmTotpEnrollment(ctx, gen.ConfirmTotpEnrollmentRequestObject{}))
	add(s.CreateAdmin(ctx, gen.CreateAdminRequestObject{}))
	add(s.UpdateAdmin(ctx, gen.UpdateAdminRequestObject{AdminId: "adm_x"}))
	add(s.ActivateAdmin(ctx, gen.ActivateAdminRequestObject{}))
	for i, err := range errs {
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Code != fieldRequired {
			t.Errorf("call %d: field errors %+v", i, p.Errors)
		}
	}
	if len(svc.calls) != 0 {
		t.Errorf("the service was called: %v", svc.calls)
	}
}

func TestServiceFailures(t *testing.T) {
	t.Parallel()
	svc := &fakeService{err: adminauth.ErrForbidden}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	str := "x"
	email := gen.Email("a@example.com")
	errs := []error{}
	add := func(_ any, err error) { errs = append(errs, err) }
	add(s.GetSetupStatus(ctx, gen.GetSetupStatusRequestObject{}))
	add(s.CreateSuperAdmin(ctx, gen.CreateSuperAdminRequestObject{Body: &gen.SetupRequest{}}))
	add(s.AdminLogin(ctx, gen.AdminLoginRequestObject{Body: &gen.LoginRequest{}}))
	add(s.AdminVerifyTotp(ctx, gen.AdminVerifyTotpRequestObject{Body: &gen.TotpCode{Code: &str}}))
	add(s.AdminLogout(ctx, gen.AdminLogoutRequestObject{}))
	add(s.ChangeAdminPassword(ctx, gen.ChangeAdminPasswordRequestObject{Body: &gen.PasswordChange{}}))
	add(s.StartTotpEnrollment(ctx, gen.StartTotpEnrollmentRequestObject{}))
	add(s.DisableTotp(ctx, gen.DisableTotpRequestObject{Body: &gen.PasswordConfirmation{}}))
	add(s.ConfirmTotpEnrollment(ctx, gen.ConfirmTotpEnrollmentRequestObject{Body: &gen.TotpCode{Code: &str}}))
	add(s.ListAdmins(ctx, gen.ListAdminsRequestObject{}))
	add(s.CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: &gen.AdminCreate{Email: email}}))
	add(s.GetAdmin(ctx, gen.GetAdminRequestObject{AdminId: "adm_x"}))
	add(s.UpdateAdmin(ctx, gen.UpdateAdminRequestObject{AdminId: "adm_x", Body: &gen.AdminUpdate{}}))
	add(s.DeleteAdmin(ctx, gen.DeleteAdminRequestObject{AdminId: "adm_x"}))
	add(s.ResetAdminCredentials(ctx, gen.ResetAdminCredentialsRequestObject{AdminId: "adm_x"}))
	add(s.ActivateAdmin(ctx, gen.ActivateAdminRequestObject{Body: &gen.ActivationRequest{}}))
	for _, err := range errs {
		expectProblem(t, err, problem.CodeForbidden)
	}
	if len(svc.calls) != len(errs) {
		t.Errorf("calls %v", svc.calls)
	}
}

func TestSetupAndLogin(t *testing.T) {
	t.Parallel()
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith("", adminauth.Account{})

	status, err := s.GetSetupStatus(ctx, gen.GetSetupStatusRequestObject{})
	if err != nil || status != (gen.GetSetupStatus200JSONResponse{SetupRequired: true}) {
		t.Fatalf("setup status %+v %v", status, err)
	}

	token := "stp_token"
	resp, err := s.CreateSuperAdmin(ctx, gen.CreateSuperAdminRequestObject{Body: &gen.SetupRequest{
		Username: "root", Email: "root@example.com", Password: "a-long-passphrase", SetupToken: &token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := (adminauth.SetupRequest{Username: "root", Email: "root@example.com", Password: "a-long-passphrase", SetupToken: token}); !reflect.DeepEqual(svc.args["CreateSuperAdmin"], []any{want, clientIP}) {
		t.Errorf("setup args %v", svc.args["CreateSuperAdmin"])
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"qrCodePng":"iVBORw=="`) ||
		!strings.Contains(rec.Body.String(), `"csrfToken":"csrf_tok"`) || !strings.Contains(rec.Body.String(), `"secret":"JBSWY3DP"`) ||
		!strings.Contains(rec.Header().Get("Set-Cookie"), "__Host-tt_admin=as_tok; Path=/; Max-Age=300") {
		t.Errorf("setup answer %d %v %s", rec.Code, rec.Header(), rec.Body)
	}

	login, err := s.AdminLogin(ctx, gen.AdminLoginRequestObject{Body: &gen.LoginRequest{Username: "root", Password: "pw"}})
	if err != nil || !reflect.DeepEqual(svc.args["Login"], []any{"root", "pw", clientIP}) {
		t.Fatalf("login %v %v", err, svc.args["Login"])
	}
	rec = visit(t, login)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"csrfToken":"csrf_tok","status":"totp_required"}`+"\n" ||
		!strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=300") {
		t.Errorf("login answer %d %v %s", rec.Code, rec.Header(), rec.Body)
	}

	act, err := s.ActivateAdmin(ctx, gen.ActivateAdminRequestObject{Body: &gen.ActivationRequest{ActivationToken: "act_x", Password: "pw"}})
	if err != nil || !reflect.DeepEqual(svc.args["Activate"], []any{"act_x", "pw", clientIP}) {
		t.Fatalf("activate %v %v", err, svc.args["Activate"])
	}
	if rec = visit(t, act); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"totp_enrollment_required"`) {
		t.Errorf("activate answer %d %s", rec.Code, rec.Body)
	}
}

func TestSecondFactorAndLogout(t *testing.T) {
	t.Parallel()
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith(store.SessionTOTPRequired, superRoot)

	recovery := "rc-7KQ2-9XLM-4PZD"
	resp, err := s.AdminVerifyTotp(ctx, gen.AdminVerifyTotpRequestObject{Body: &gen.TotpCode{RecoveryCode: &recovery}})
	if err != nil || !reflect.DeepEqual(svc.args["VerifyTOTP"], []any{"as_01", "", recovery, clientIP}) {
		t.Fatalf("verify %v %v", err, svc.args["VerifyTOTP"])
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"authenticated"`) ||
		!strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=43200") {
		t.Errorf("verify answer %d %v %s", rec.Code, rec.Header(), rec.Body)
	}

	out, err := s.AdminLogout(ctx, gen.AdminLogoutRequestObject{})
	if err != nil || !reflect.DeepEqual(svc.args["Logout"], []any{"as_01", clientIP}) {
		t.Fatalf("logout %v %v", err, svc.args["Logout"])
	}
	if rec = visit(t, out); rec.Code != http.StatusNoContent || rec.Header().Get("Set-Cookie") != middleware.ExpiredCookie(middleware.AdminCookie) {
		t.Errorf("logout answer %d %v", rec.Code, rec.Header())
	}
}

func TestOwnAccount(t *testing.T) {
	t.Parallel()
	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith(store.SessionAuthenticated, delegated)

	if _, err := s.ChangeAdminPassword(ctx, gen.ChangeAdminPasswordRequestObject{Body: &gen.PasswordChange{CurrentPassword: "old", NewPassword: "new"}}); err != nil ||
		!reflect.DeepEqual(svc.args["ChangePassword"], []any{"as_01", "old", "new", clientIP}) {
		t.Errorf("change password %v %v", err, svc.args["ChangePassword"])
	}
	if _, err := s.DisableTotp(ctx, gen.DisableTotpRequestObject{Body: &gen.PasswordConfirmation{CurrentPassword: "old"}}); err != nil ||
		!reflect.DeepEqual(svc.args["DisableTOTP"], []any{"as_01", "old", clientIP}) {
		t.Errorf("disable totp %v %v", err, svc.args["DisableTOTP"])
	}

	enr, err := s.StartTotpEnrollment(ctx, gen.StartTotpEnrollmentRequestObject{})
	if err != nil || !reflect.DeepEqual(svc.args["StartEnrollment"], []any{"as_01", "", clientIP}) {
		t.Fatalf("enrollment %v %v", err, svc.args["StartEnrollment"])
	}
	if rec := visit(t, enr); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"qrCodePng":"cG5n"`) || strings.Contains(rec.Body.String(), "csrfToken") {
		t.Errorf("enrollment answer %d %s", rec.Code, rec.Body)
	}
	// A re-enrollment carries the current password; an empty body none.
	current := "old"
	if _, err := s.StartTotpEnrollment(ctx, gen.StartTotpEnrollmentRequestObject{Body: &gen.TotpReenrollment{CurrentPassword: &current}}); err != nil ||
		!reflect.DeepEqual(svc.args["StartEnrollment"], []any{"as_01", "old", clientIP}) {
		t.Errorf("re-enrollment %v %v", err, svc.args["StartEnrollment"])
	}
	if _, err := s.StartTotpEnrollment(ctx, gen.StartTotpEnrollmentRequestObject{Body: &gen.TotpReenrollment{}}); err != nil ||
		!reflect.DeepEqual(svc.args["StartEnrollment"], []any{"as_01", "", clientIP}) {
		t.Errorf("enrollment with an empty body %v %v", err, svc.args["StartEnrollment"])
	}

	code := "204816"
	codes := []string{"rc-1", "rc-2", "rc-3", "rc-4", "rc-5", "rc-6", "rc-7", "rc-8"}
	// From an authenticated session: no rotation, no cookie.
	svc.confirmed = adminauth.Confirmed{RecoveryCodes: codes}
	conf, err := s.ConfirmTotpEnrollment(ctx, gen.ConfirmTotpEnrollmentRequestObject{Body: &gen.TotpCode{Code: &code}})
	if err != nil || !reflect.DeepEqual(svc.args["ConfirmEnrollment"], []any{"as_01", code, clientIP}) {
		t.Fatalf("confirm %v %v", err, svc.args["ConfirmEnrollment"])
	}
	if rec := visit(t, conf); rec.Code != http.StatusOK || rec.Header().Get("Set-Cookie") != "" || strings.Contains(rec.Body.String(), "csrfToken") ||
		!strings.Contains(rec.Body.String(), `"rc-8"`) {
		t.Errorf("confirm answer %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	// Completing a login: the rotated session.
	rotated := session(store.SessionAuthenticated)
	svc.confirmed = adminauth.Confirmed{RecoveryCodes: codes, Session: &rotated}
	conf, err = s.ConfirmTotpEnrollment(ctxWith(store.SessionTOTPEnrollmentRequired, superRoot),
		gen.ConfirmTotpEnrollmentRequestObject{Body: &gen.TotpCode{Code: &code}})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, conf); !strings.Contains(rec.Header().Get("Set-Cookie"), "__Host-tt_admin=as_tok") ||
		!strings.Contains(rec.Body.String(), `"csrfToken":"csrf_tok"`) {
		t.Errorf("confirm (login) answer %v %s", rec.Header(), rec.Body)
	}
}

func TestGetAdminMe(t *testing.T) {
	t.Parallel()
	tenants := &fakeTenants{}
	s := newServer(&fakeService{}, tenants)

	// A super admin manages every tenant (two pages).
	resp, err := s.GetAdminMe(ctxWith(store.SessionAuthenticated, superRoot), gen.GetAdminMeRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	me := resp.(gen.GetAdminMe200JSONResponse)
	if me.Id != "adm_root" || me.Username != "root" || me.Role != gen.SuperAdmin || !me.TotpEnabled || me.CsrfToken != "csrf_01" ||
		me.Language == nil || *me.Language != "fr" || len(me.Tenants) != 2 || me.Tenants[1] != (gen.TenantRef{Id: "ten_b", Name: "Entity B", Fqdn: "transfer.entity-b.example.com"}) {
		t.Errorf("super admin me %+v", me)
	}
	if tenants.lists != 2 {
		t.Errorf("tenant pages read %d", tenants.lists)
	}

	// A delegated admin: its tenants, a deleted one skipped, no language.
	resp, err = s.GetAdminMe(ctxWith(store.SessionAuthenticated, delegated), gen.GetAdminMeRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	me = resp.(gen.GetAdminMe200JSONResponse)
	if me.Role != gen.DelegatedAdmin || me.Language != nil || len(me.Tenants) != 1 || me.Tenants[0].Id != "ten_a" {
		t.Errorf("delegated me %+v", me)
	}
	rec := visit(t, resp)
	if !strings.Contains(rec.Body.String(), `"tenants":[{"fqdn":"transfer.entity-a.example.com","id":"ten_a","name":"Entity A"}]`) {
		t.Errorf("delegated me body %s", rec.Body)
	}

	// A delegated admin with no tenant left gets an empty list, not null.
	lone := delegated
	lone.TenantIDs = []tenant.ID{"ten_gone"}
	resp, _ = s.GetAdminMe(ctxWith(store.SessionAuthenticated, lone), gen.GetAdminMeRequestObject{})
	if rec := visit(t, resp); !strings.Contains(rec.Body.String(), `"tenants":[]`) {
		t.Errorf("lone me body %s", rec.Body)
	}

	// Registry failures are 500s.
	broken := delegated
	broken.TenantIDs = []tenant.ID{"ten_boom"}
	if _, err := s.GetAdminMe(ctxWith(store.SessionAuthenticated, broken), gen.GetAdminMeRequestObject{}); err == nil {
		t.Error("tenant read failure ignored")
	}
	tenants.listErr = errors.New("database down")
	if _, err := s.GetAdminMe(ctxWith(store.SessionAuthenticated, superRoot), gen.GetAdminMeRequestObject{}); err == nil {
		t.Error("tenant list failure ignored")
	}
}

func TestAccounts(t *testing.T) {
	t.Parallel()
	svc := &fakeService{page: store.Page[adminauth.Account]{Items: []adminauth.Account{superRoot, delegated}, NextCursor: "cur_2"}}
	s := newServer(svc, &fakeTenants{})
	ctx := ctxWith(store.SessionAuthenticated, superRoot)

	limit, cursor := 10, "cur_1"
	list, err := s.ListAdmins(ctx, gen.ListAdminsRequestObject{Params: gen.ListAdminsParams{Limit: &limit, Cursor: &cursor}})
	if err != nil || !reflect.DeepEqual(svc.args["List"], []any{"as_01", "cur_1", 10}) {
		t.Fatalf("list %v %v", err, svc.args["List"])
	}
	l := list.(gen.ListAdmins200JSONResponse)
	if len(l.Items) != 2 || l.NextCursor == nil || *l.NextCursor != "cur_2" {
		t.Errorf("list %+v", l)
	}
	root := l.Items[0]
	if root.LastLoginAt == nil || !root.LastLoginAt.Equal(superRoot.LastLoginAt) || root.RequireTotp == nil || !*root.RequireTotp ||
		len(root.TenantIds) != 0 || root.TenantIds == nil || !root.Activated {
		t.Errorf("super admin item %+v", root)
	}
	deleg := l.Items[1]
	if deleg.LastLoginAt != nil || *deleg.RequireTotp || !reflect.DeepEqual(deleg.TenantIds, []string{"ten_a", "ten_gone"}) || deleg.Disabled {
		t.Errorf("delegated item %+v", deleg)
	}
	// Last page: no cursor.
	svc.page = store.Page[adminauth.Account]{Items: []adminauth.Account{}}
	list, _ = s.ListAdmins(ctx, gen.ListAdminsRequestObject{})
	if l := list.(gen.ListAdmins200JSONResponse); l.NextCursor != nil || l.Items == nil {
		t.Errorf("last page %+v", l)
	}
	if !reflect.DeepEqual(svc.args["List"], []any{"as_01", "", 0}) {
		t.Errorf("default list args %v", svc.args["List"])
	}

	require := false
	tids := []string{"ten_a"}
	created, err := s.CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: &gen.AdminCreate{
		Username: "admin.entity-a", Email: "admin@entity-a.example.com", Role: gen.DelegatedAdmin, TenantIds: &tids, RequireTotp: &require,
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantCreate := adminauth.AdminCreate{
		Username: "admin.entity-a", Email: "admin@entity-a.example.com", Role: store.RoleDelegatedAdmin,
		TenantIDs: []tenant.ID{"ten_a"}, RequireTOTP: &require,
	}
	if !reflect.DeepEqual(svc.args["Create"], []any{"as_01", wantCreate, clientIP}) {
		t.Errorf("create args %v", svc.args["Create"])
	}
	if rec := visit(t, created); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"id":"adm_deleg"`) ||
		!strings.Contains(rec.Body.String(), `"activationUrl":"https://admin.transfer.example.com/admin/activate#act_x"`) ||
		!strings.Contains(rec.Body.String(), `"activationExpiresAt":"2026-10-25T08:00:00Z"`) ||
		!strings.Contains(rec.Body.String(), `"activated":false`) {
		t.Errorf("create answer %d %s", rec.Code, rec.Body)
	}
	// Without tenant IDs: an empty list, which the service refuses.
	if _, err := s.CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: &gen.AdminCreate{Username: "x", Role: gen.DelegatedAdmin}}); err != nil {
		t.Fatal(err)
	}
	if got := svc.args["Create"][1].(adminauth.AdminCreate); got.TenantIDs == nil || len(got.TenantIDs) != 0 || got.RequireTOTP != nil {
		t.Errorf("create without tenants %+v", got)
	}

	got, err := s.GetAdmin(ctx, gen.GetAdminRequestObject{AdminId: "adm_deleg"})
	if err != nil || got.(gen.GetAdmin200JSONResponse).Id != "adm_deleg" || !reflect.DeepEqual(svc.args["Get"], []any{"as_01", "adm_deleg"}) {
		t.Errorf("get %+v %v", got, err)
	}

	email := gen.Email("new@entity-a.example.com")
	role := gen.SuperAdmin
	disabled := true
	updated, err := s.UpdateAdmin(ctx, gen.UpdateAdminRequestObject{AdminId: "adm_deleg", Body: &gen.AdminUpdate{
		Email: &email, Role: &role, TenantIds: &tids, RequireTotp: &require, Disabled: &disabled,
	}})
	if err != nil || updated.(gen.UpdateAdmin200JSONResponse).Id != "adm_deleg" {
		t.Fatalf("update %+v %v", updated, err)
	}
	u := svc.args["Update"][2].(adminauth.AdminUpdate)
	if svc.args["Update"][1] != "adm_deleg" || *u.Email != "new@entity-a.example.com" || *u.Role != store.RoleSuperAdmin ||
		!reflect.DeepEqual(*u.TenantIDs, []tenant.ID{"ten_a"}) || *u.RequireTOTP || !*u.Disabled {
		t.Errorf("update args %+v", u)
	}
	// An empty patch changes nothing.
	if _, err := s.UpdateAdmin(ctx, gen.UpdateAdminRequestObject{AdminId: "adm_deleg", Body: &gen.AdminUpdate{}}); err != nil {
		t.Fatal(err)
	}
	if u := svc.args["Update"][2].(adminauth.AdminUpdate); u != (adminauth.AdminUpdate{}) {
		t.Errorf("empty patch %+v", u)
	}

	del, err := s.DeleteAdmin(ctx, gen.DeleteAdminRequestObject{AdminId: "adm_deleg"})
	if err != nil || !reflect.DeepEqual(svc.args["Delete"], []any{"as_01", "adm_deleg", clientIP}) {
		t.Fatalf("delete %v %v", err, svc.args["Delete"])
	}
	if rec := visit(t, del); rec.Code != http.StatusNoContent {
		t.Errorf("delete answer %d", rec.Code)
	}
	reset, err := s.ResetAdminCredentials(ctx, gen.ResetAdminCredentialsRequestObject{AdminId: "adm_deleg"})
	if err != nil || !reflect.DeepEqual(svc.args["ResetCredentials"], []any{"as_01", "adm_deleg", clientIP}) {
		t.Fatalf("reset %v %v", err, svc.args["ResetCredentials"])
	}
	if rec := visit(t, reset); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"adm_deleg"`) ||
		!strings.Contains(rec.Body.String(), `"activationUrl":"https://admin.transfer.example.com/admin/activate#act_x"`) {
		t.Errorf("reset answer %d %s", rec.Code, rec.Body)
	}
}
