package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// fakeExpress records the calls of the express administration.
type fakeExpress struct {
	err     error
	secret  store.Secret
	deleted int
	calls   []string
	tenant  *tenant.Tenant
	actor   secret.AdminActor
	link    string
}

func (f *fakeExpress) Lookup(_ context.Context, t *tenant.Tenant, actor secret.AdminActor, link string) (store.Secret, error) {
	f.calls = append(f.calls, "Lookup")
	f.tenant, f.actor, f.link = t, actor, link
	return f.secret, f.err
}

func (f *fakeExpress) PurgeExpress(_ context.Context, t *tenant.Tenant, actor secret.AdminActor) (int, error) {
	f.calls = append(f.calls, "PurgeExpress")
	f.tenant, f.actor = t, actor
	return f.deleted, f.err
}

// expressTenants holds the active ten_a, ten_deleting being deleted;
// ten_boom fails; any other tenant is unknown.
type expressTenants struct{ *fakeTenants }

func (expressTenants) Get(_ context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	switch tid {
	case "ten_a":
		return &tenant.Tenant{ID: tid, FQDN: "transfer.entity-a.example.com", Status: tenant.StatusActive}, nil
	case "ten_deleting":
		return &tenant.Tenant{ID: tid, Status: tenant.StatusDeleting}, nil
	case "ten_boom":
		return nil, errors.New("database down")
	case "bad id":
		return nil, fmt.Errorf("get tenant: %w", store.ErrInvalid)
	}
	return nil, fmt.Errorf("get tenant: %w", store.ErrNotFound)
}

// expressServer returns a server over f and expressTenants.
func expressServer(f ExpressSecretService) *Server {
	return NewServer(WithExpressSecretService(f), WithTenants(expressTenants{&fakeTenants{}}))
}

// lookupLink is a pasted link with its key.
const lookupLink = "https://transfer.entity-a.example.com/s/tts_Xp4kQ7mZr2Lw9TfB3nHc8VyJd5Gs1KqA6eWu0RtNb7M#k=key"

func TestLookupTenantSecret(t *testing.T) {
	t.Parallel()
	f := &fakeExpress{secret: store.Secret{
		ID: "sec_1", State: store.SecretActive, CreatorKind: store.SecretCreatorAnonymous, Express: true,
		Delivery: store.SecretDeliveryLink, CreatedAt: now, ExpiresAt: now.Add(1000),
	}}
	s := expressServer(f)
	req := gen.LookupTenantSecretRequestObject{TenantId: "ten_a", Body: &gen.SecretLookup{Link: lookupLink}}
	auditor := adminauth.Account{ID: "adm_audit", Username: "audrey", Role: store.RoleAuditor, TenantIDs: []tenant.ID{"ten_a"}}
	for _, a := range []adminauth.Account{delegated, superRoot, auditor} {
		resp, err := s.LookupTenantSecret(ctxWith(store.SessionAuthenticated, a), req)
		if err != nil {
			t.Fatalf("%s: %v", a.Username, err)
		}
		code, out := decode(t, resp)
		if code != http.StatusOK || out["id"] != "sec_1" || out["creatorKind"] != "anonymous" || out["express"] != true ||
			out["senderEmail"] != nil || out["delivery"] != "link" {
			t.Errorf("%s: %d %v", a.Username, code, out)
		}
		if f.tenant.ID != "ten_a" || f.link != lookupLink || f.actor.Username != a.Username || f.actor.IP != clientIP {
			t.Errorf("%s: call %+v %q %+v", a.Username, f.tenant, f.link, f.actor)
		}
	}
	// Without body, the service refuses the empty link.
	f.err = &secret.ValidationError{Fields: []secret.FieldError{{Pointer: secret.FieldLink, Code: secret.CodeRequired}}}
	_, err := s.LookupTenantSecret(ctxWith(store.SessionAuthenticated, delegated), gen.LookupTenantSecretRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if f.link != "" || len(p.Errors) != 1 || p.Errors[0].Field != "/link" || p.Errors[0].Code != "required" {
		t.Errorf("no body: %q %+v", f.link, p.Errors)
	}
	f.err = secret.ErrNotFound
	_, err = s.LookupTenantSecret(ctxWith(store.SessionAuthenticated, delegated), req)
	expectProblem(t, err, problem.CodeNotFound)
	boom := errors.New("database down")
	f.err = boom
	if _, err = s.LookupTenantSecret(ctxWith(store.SessionAuthenticated, delegated), req); !errors.Is(err, boom) {
		t.Errorf("store failure: %v", err)
	}
}

func TestPurgeExpressSecrets(t *testing.T) {
	t.Parallel()
	f := &fakeExpress{deleted: 412}
	s := expressServer(f)
	req := gen.PurgeExpressSecretsRequestObject{TenantId: "ten_a"}
	for _, a := range []adminauth.Account{delegated, superRoot} {
		resp, err := s.PurgeExpressSecrets(ctxWith(store.SessionAuthenticated, a), req)
		if err != nil {
			t.Fatal(err)
		}
		if code, out := decode(t, resp); code != http.StatusOK || out["deleted"] != float64(412) {
			t.Errorf("%s: %d %v", a.Username, code, out)
		}
		if f.tenant.ID != "ten_a" || f.actor.Username != a.Username || f.actor.IP != clientIP {
			t.Errorf("%s: call %+v %+v", a.Username, f.tenant, f.actor)
		}
	}
	boom := errors.New("database down")
	f.err = boom
	if _, err := s.PurgeExpressSecrets(ctxWith(store.SessionAuthenticated, delegated), req); !errors.Is(err, boom) {
		t.Errorf("store failure: %v", err)
	}
}

// The access checks of both operations come before the service.
func TestExpressAdminAccess(t *testing.T) {
	t.Parallel()
	auditorA := adminauth.Account{ID: "adm_audit", Username: "audrey", Role: store.RoleAuditor, TenantIDs: []tenant.ID{"ten_a"}}
	calls := map[string]func(*Server, context.Context, gen.TenantId) error{
		"lookup": func(s *Server, ctx context.Context, tid gen.TenantId) error {
			_, err := s.LookupTenantSecret(ctx, gen.LookupTenantSecretRequestObject{TenantId: tid, Body: &gen.SecretLookup{Link: lookupLink}})
			return err
		},
		"purge": func(s *Server, ctx context.Context, tid gen.TenantId) error {
			_, err := s.PurgeExpressSecrets(ctx, gen.PurgeExpressSecretsRequestObject{TenantId: tid})
			return err
		},
	}
	for name, call := range calls {
		f := &fakeExpress{}
		s := expressServer(f)
		authed := ctxWith(store.SessionAuthenticated, delegated)
		// Wiring errors.
		if err := call(NewServer(WithTenants(expressTenants{&fakeTenants{}})), authed, "ten_a"); !errors.Is(err, errNoExpressSecretService) {
			t.Errorf("%s without service: %v", name, err)
		}
		if err := call(NewServer(WithExpressSecretService(f)), authed, "ten_a"); !errors.Is(err, errNoTenants) {
			t.Errorf("%s without registry: %v", name, err)
		}
		// Sessions.
		expectProblem(t, call(s, ctxWith("", delegated), "ten_a"), problem.CodeUnauthenticated)
		expectProblem(t, call(s, ctxWith(store.SessionTOTPRequired, delegated), "ten_a"), problem.CodeUnauthenticated)
		// Tenants: another one, a missing one, one being deleted, a
		// malformed identifier: all 404; a failing registry: 500.
		for _, tid := range []gen.TenantId{"ten_b", "ten_gone", "ten_deleting", "bad id"} {
			ctx := authed
			if tid != "ten_b" {
				ctx = ctxWith(store.SessionAuthenticated, superRoot)
			}
			expectProblem(t, call(s, ctx, tid), problem.CodeNotFound)
		}
		if err := call(s, ctxWith(store.SessionAuthenticated, superRoot), "ten_boom"); err == nil || errors.As(err, new(*problem.Problem)) {
			t.Errorf("%s with a failing registry: %v", name, err)
		}
		// The auditor of the tenant may look up, never purge; outside its
		// tenants, nothing exists.
		err := call(s, ctxWith(store.SessionAuthenticated, auditorA), "ten_a")
		if name == "purge" {
			expectProblem(t, err, problem.CodeReadOnlyRole)
		} else if err != nil {
			t.Errorf("auditor lookup: %v", err)
		}
		expectProblem(t, call(s, ctxWith(store.SessionAuthenticated, auditorA), "ten_b"), problem.CodeNotFound)
		if name == "purge" && slices.Contains(f.calls, "PurgeExpress") {
			t.Errorf("refused purges reached the service: %v", f.calls)
		}
	}
}

func TestSecretSettingsExpressMembers(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	on, ip, tok, pending := true, 5, 100, 1000
	svc := &fakeTenantService{secretSettings: &tenantadmin.SecretSettingsInput{
		Enabled: true, Durations: []string{"1h"}, FileMaxBytes: tenant.DefaultSecretFileBytes,
		ExpressEnabled: &on, ExpressPerHourPerIP: &ip, ExpressPerHourPerToken: &tok, ExpressMaxPending: &pending,
	}}
	s := tenantServer(svc)
	resp, err := s.GetSecretSettings(ctx, gen.GetSecretSettingsRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	if code, out := decode(t, resp); code != http.StatusOK || out["expressEnabled"] != true || out["expressPerHourPerIp"] != float64(5) ||
		out["expressPerHourPerToken"] != float64(100) || out["expressMaxPending"] != float64(1000) {
		t.Errorf("get = %d %v", code, out)
	}

	// The members given reach the service, the absent ones stay nil.
	raw := `{"enabled":true,"durations":["1h"],"fileAllowed":true,"fileMaxBytes":2097152,"emailAllowed":true,` +
		`"expressEnabled":false,"expressPerHourPerIp":7}`
	off, seven := false, 7
	body := &gen.SecretSettings{
		Enabled: true, Durations: []gen.SecretDuration{"1h"}, FileAllowed: true, FileMaxBytes: 2097152, EmailAllowed: true,
		ExpressEnabled: &off, ExpressPerHourPerIp: &seven,
	}
	if _, err := s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, []byte(raw)),
		gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body}); err != nil {
		t.Fatal(err)
	}
	in := svc.args["UpdateSecretSettings"][2].(tenantadmin.SecretSettingsInput)
	if in.ExpressEnabled == nil || *in.ExpressEnabled || in.ExpressPerHourPerIP == nil || *in.ExpressPerHourPerIP != 7 ||
		in.ExpressPerHourPerToken != nil || in.ExpressMaxPending != nil {
		t.Errorf("input = %+v", in)
	}

	// A null express member is refused, each one named, after the
	// required members.
	nulls := `{"enabled":true,"durations":["1h"],"fileAllowed":true,"fileMaxBytes":1,"emailAllowed":true,` +
		`"expressEnabled":null,"expressMaxPending": null }`
	_, err = s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, []byte(nulls)),
		gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: &gen.SecretSettings{}})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 2 || p.Errors[0].Field != "/expressEnabled" || p.Errors[1].Field != "/expressMaxPending" ||
		p.Errors[0].Code != fieldNotNullable {
		t.Errorf("null members: %+v", p.Errors)
	}
	// Out of range, from the service.
	svc.err = &tenantadmin.InvalidError{Field: tenantadmin.FieldExpressMaxPending, Code: tenantadmin.CodeOutOfRange}
	_, err = s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, []byte(raw)),
		gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body})
	p = expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "/expressMaxPending" || p.Errors[0].Code != "out-of-range" {
		t.Errorf("out of range: %+v", p.Errors)
	}
}

// adminSecretBody marks the express secrets, without creator address.
func TestAdminSecretBodyExpress(t *testing.T) {
	t.Parallel()
	b := adminSecretBody(store.Secret{ID: "sec_1", CreatorKind: store.SecretCreatorAPIToken, Express: true, Delivery: store.SecretDeliveryLink})
	if b.Express == nil || !*b.Express || b.SenderEmail != nil || b.CreatorKind != "api_token" {
		t.Errorf("express = %+v", b)
	}
	b = adminSecretBody(store.Secret{ID: "sec_2", CreatorKind: store.SecretCreatorInternal, SenderEmail: "alice@entity-a.example.com"})
	if b.Express == nil || *b.Express || b.SenderEmail == nil {
		t.Errorf("2.1 secret = %+v", b)
	}
}

// TestSecretSettingsInstanceDisabled: the answers of getSecretSettings and
// updateSecretSettings always say whether the instance kill switch is on
// (expressInstanceDisabled, read only, since 2.3), from the server option
// and never from the body; a limit raised by a delegated admin (service
// ErrForbidden, T-418) is 403 forbidden.
func TestSecretSettingsInstanceDisabled(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	raw := `{"enabled":true,"durations":["1h"],"fileAllowed":true,"fileMaxBytes":2097152,"emailAllowed":true,` +
		`"expressInstanceDisabled":%s}`
	for _, on := range []bool{false, true} {
		svc := &fakeTenantService{}
		s := tenantServer(svc)
		if on {
			WithExpressKillSwitch(true)(s)
		}
		resp, err := s.GetSecretSettings(ctx, gen.GetSecretSettingsRequestObject{TenantId: "ten_a"})
		if err != nil {
			t.Fatal(err)
		}
		if code, out := decode(t, resp); code != http.StatusOK || out["expressInstanceDisabled"] != on {
			t.Errorf("switch %v: get = %d %v", on, code, out)
		}
		// The member sent is ignored: the answer tells the server switch.
		sent := !on
		body := &gen.SecretSettings{
			Enabled: true, Durations: []gen.SecretDuration{"1h"}, FileAllowed: true, FileMaxBytes: 2097152, EmailAllowed: true,
			ExpressInstanceDisabled: &sent,
		}
		upd, err := s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, fmt.Appendf(nil, raw, strconv.FormatBool(sent))),
			gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body})
		if err != nil {
			t.Fatal(err)
		}
		if code, out := decode(t, upd); code != http.StatusOK || out["expressInstanceDisabled"] != on {
			t.Errorf("switch %v: update = %d %v", on, code, out)
		}
	}

	svc := &fakeTenantService{err: tenantadmin.ErrForbidden, errAt: "UpdateSecretSettings"}
	pending := tenant.DefaultExpressMaxPending + 1
	body := &gen.SecretSettings{
		Enabled: true, Durations: []gen.SecretDuration{"1h"}, FileAllowed: true, FileMaxBytes: 2097152, EmailAllowed: true,
		ExpressMaxPending: &pending,
	}
	_, err := tenantServer(svc).UpdateSecretSettings(
		context.WithValue(ctx, rawBodyKey{}, []byte(`{"enabled":true,"durations":["1h"],"fileAllowed":true,"fileMaxBytes":2097152,`+
			`"emailAllowed":true,"expressMaxPending":1001}`)),
		gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body})
	expectProblem(t, err, problem.CodeForbidden)
}
