package admin

import (
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// wantNotSupported checks err is a 400 validation-failed whose only entry is
// the not-supported code of field.
func wantNotSupported(t *testing.T, name string, err error, field string) {
	t.Helper()
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != field || p.Errors[0].Code != "not-supported" {
		t.Errorf("%s: errors %+v, want %s not-supported", name, p.Errors, field)
	}
}

// The members of API 2.0 that are not implemented yet are refused with a
// 400 not-supported, for the admins who may use the operation only: another
// admin keeps the answer of the service (403 or 404). The service is never
// reached by a refused request.
func TestInterimNotSupportedV20(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	deleg := ctxWith(store.SessionAuthenticated, delegated)
	tids := []string{"ten_a"}
	none, mail := gen.InvitationDeliveryNone, gen.InvitationDeliveryMail

	// The mail delivery of a delegated admin is implemented.
	svc := &fakeService{mailed: true}
	if _, err := newServer(svc, &fakeTenants{}).CreateAdmin(super, gen.CreateAdminRequestObject{Body: &gen.AdminCreate{
		Username: "a", Email: "a@entity-a.example.com", Role: gen.DelegatedAdmin, TenantIds: &tids,
		Invitation: &gen.AdminInvitation{Delivery: &mail},
	}}); err != nil {
		t.Errorf("mail delivery: %v", err)
	}

	// Invitation and update of an account.
	svc = &fakeService{}
	_, err := newServer(svc, &fakeTenants{}).InviteAdmin(super, gen.InviteAdminRequestObject{AdminId: "adm_x", Body: &gen.AdminInvitation{Delivery: &none}})
	wantNotSupported(t, "invite none", err, "/delivery")
	if len(svc.calls) != 0 {
		t.Errorf("the service was called: %v", svc.calls)
	}
	// The auditor role is implemented (since step 2 of V2): creation and
	// update reach the service with the role.
	svc = &fakeService{}
	if _, err := newServer(svc, &fakeTenants{}).CreateAdmin(super, gen.CreateAdminRequestObject{Body: &gen.AdminCreate{
		Username: "audit.a", Email: "audit@entity-a.example.com", Role: gen.Auditor, TenantIds: &tids,
	}}); err != nil {
		t.Errorf("create auditor: %v", err)
	} else if req := svc.args["Create"][1].(adminauth.AdminCreate); req.Role != store.RoleAuditor {
		t.Errorf("create auditor: service got role %q", req.Role)
	}
	role := gen.Auditor
	if _, err := newServer(svc, &fakeTenants{}).UpdateAdmin(super, gen.UpdateAdminRequestObject{AdminId: "adm_x", Body: &gen.AdminUpdate{Role: &role}}); err != nil {
		t.Errorf("update auditor: %v", err)
	} else if u := svc.args["Update"][2].(adminauth.AdminUpdate); u.Role == nil || *u.Role != store.RoleAuditor {
		t.Errorf("update auditor: service got %+v", u)
	}

	// Tenant creation with a first delegated admin without activation link:
	// a new tenant has no single sign-on yet (interim not-supported).
	tsvc := &fakeTenantService{}
	_, err = tenantServer(tsvc).CreateTenant(super, gen.CreateTenantRequestObject{Body: &gen.TenantCreate{
		Name: "Entity B", Fqdn: "transfer.entity-b.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1 << 40,
		DelegatedAdmin: &gen.NewDelegatedAdmin{Username: "admin.b", Email: "admin@entity-b.example.com", Language: "fr", Delivery: &none},
	}})
	wantNotSupported(t, "create tenant delivery none", err, "/delegatedAdmin/delivery")
	if len(tsvc.args["CreateTenant"]) != 0 {
		t.Errorf("create tenant delivery none: the service was called")
	}

	// Tenant import (since step 5 of V2): the same refusal of a first
	// delegated admin without activation link, before the service.
	tsvc = &fakeTenantService{}
	_, err = tenantServer(tsvc).ImportTenant(importCtx(super, strings.Replace(validImport, `"config"`,
		`"delegatedAdmin":{"username":"admin.c","email":"admin@entity-c.example.com","language":"fr","delivery":"none"},"config"`, 1)), importReq())
	wantNotSupported(t, "import tenant delivery none", err, "/delegatedAdmin/delivery")
	if len(tsvc.args["ImportTenant"]) != 0 {
		t.Errorf("import tenant delivery none: the service was called")
	}
	// The link-only and end-to-end policies of an import are not stored
	// before steps 6 and 7: the service refuses any value but the default,
	// answered 422 import-invalid at its pointer (not a silent loss).
	for _, ptr := range []string{
		"/config/settings/linkOnlyAllowed", "/config/settings/e2ePolicy",
		"/config/confidentialityLevels/items/0/rules/e2ePolicy",
	} {
		tsvc = &fakeTenantService{err: &tenantadmin.ImportError{Pointer: ptr, Reason: "not supported yet"}}
		_, err = tenantServer(tsvc).ImportTenant(importCtx(super, validImport), importReq())
		p := expectProblem(t, err, problem.CodeImportInvalid)
		if len(p.Errors) != 1 || p.Errors[0].Field != ptr {
			t.Errorf("import %s: errors %+v", ptr, p.Errors)
		}
	}

	// Tenant merge patch: the policies are super admin only, like
	// antivirusEnabled. The super admin gets not-supported, a delegated
	// admin of the tenant 403 forbidden; the service is never reached.
	for _, body := range []string{`{"linkOnlyAllowed":true}`, `{"e2ePolicy":"allowed"}`, `{"name":"x","linkOnlyAllowed":false}`} {
		tsvc = &fakeTenantService{}
		_, err = tenantServer(tsvc).UpdateTenant(super, gen.UpdateTenantRequestObject{TenantId: "ten_a", Body: patchBody(body)})
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Code != "not-supported" {
			t.Errorf("%s: errors %+v", body, p.Errors)
		}
		_, err = tenantServer(tsvc).UpdateTenant(deleg, gen.UpdateTenantRequestObject{TenantId: "ten_a", Body: patchBody(body)})
		expectProblem(t, err, problem.CodeForbidden)
		if len(tsvc.args["UpdateTenant"]) != 0 {
			t.Errorf("%s: the service was called", body)
		}
	}
	// A tenant outside the scope of the admin stays a 404 from the service.
	tsvc = &fakeTenantService{err: tenantadmin.ErrNotFound}
	_, err = tenantServer(tsvc).UpdateTenant(deleg, gen.UpdateTenantRequestObject{TenantId: "ten_b", Body: patchBody(`{"linkOnlyAllowed":true}`)})
	expectProblem(t, err, problem.CodeNotFound)

	// Confidentiality levels: the policies of a rule.
	yes, allowed := true, gen.E2ePolicy("allowed")
	rules := gen.ConfidentialityRules{AllowedExpiryDays: []gen.ExpiryDays{gen.N1}}
	for name, tc := range map[string]struct {
		set   func(*gen.ConfidentialityRules)
		field string
	}{
		"link only": {func(r *gen.ConfidentialityRules) { r.LinkOnlyAllowed = &yes }, "/items/1/rules/linkOnlyAllowed"},
		"e2e":       {func(r *gen.ConfidentialityRules) { r.E2ePolicy = &allowed }, "/items/1/rules/e2ePolicy"},
	} {
		r := rules
		tc.set(&r)
		levels := &gen.ConfidentialityLevelList{Items: []gen.ConfidentialityLevel{
			{Key: "a", IsDefault: true, Rules: rules}, {Key: "b", Rules: r},
		}}
		tsvc = &fakeTenantService{}
		_, err = tenantServer(tsvc).UpdateConfidentialityLevels(deleg, gen.UpdateConfidentialityLevelsRequestObject{TenantId: "ten_a", Body: levels})
		wantNotSupported(t, name, err, tc.field)
		if len(tsvc.args["UpdateConfidentialityLevels"]) != 0 {
			t.Errorf("%s: the service was called", name)
		}
		// Outside the scope of the admin: the service answers (404).
		tsvc = &fakeTenantService{err: tenantadmin.ErrNotFound}
		_, err = tenantServer(tsvc).UpdateConfidentialityLevels(deleg, gen.UpdateConfidentialityLevelsRequestObject{TenantId: "ten_b", Body: levels})
		expectProblem(t, err, problem.CodeNotFound)
	}
}
