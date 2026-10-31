package admin

import (
	"reflect"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// The members of API 1.2 not implemented yet are refused with a 400 naming
// them, before the service is called, rather than ignored (fail closed).
func TestCreateTenantRefusesUnimplementedMembers(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	setup := gen.TenantSetupStateSetup
	active := gen.TenantSetupStateActive
	base := func() *gen.TenantCreate {
		return &gen.TenantCreate{Name: "Entity B", Fqdn: "transfer.entity-b.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1 << 40}
	}
	tests := []struct {
		name  string
		set   func(b *gen.TenantCreate)
		field string
	}{
		{"setup state setup", func(b *gen.TenantCreate) { b.SetupState = &setup }, "/setupState"},
		{"setup state active", func(b *gen.TenantCreate) { b.SetupState = &active }, "/setupState"},
		{"delegated admin", func(b *gen.TenantCreate) {
			b.DelegatedAdmin = &gen.NewDelegatedAdmin{Username: "admin.b", Email: "admin@entity-b.example.com", Language: "en"}
		}, "/delegatedAdmin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeTenantService{}
			b := base()
			tt.set(b)
			_, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: b})
			p := expectProblem(t, err, problem.CodeValidationFailed)
			if want := []problem.FieldError{{Field: tt.field, Code: fieldNotSupported}}; !reflect.DeepEqual(p.Errors, want) {
				t.Errorf("errors %+v, want %+v", p.Errors, want)
			}
			if len(svc.calls) != 0 {
				t.Errorf("the service was called: %v", svc.calls)
			}
		})
	}
	// A delegated admin keeps the 403 of the service, whatever the body.
	svc := &fakeTenantService{err: tenantadmin.ErrForbidden}
	b := base()
	b.SetupState = &setup
	_, err := tenantServer(svc).CreateTenant(ctxWith(store.SessionAuthenticated, delegated), gen.CreateTenantRequestObject{Body: b})
	expectProblem(t, err, problem.CodeForbidden)
}

// The background preset of API 1.2 is implemented: passed to the service,
// whose refusal of an unknown preset is a 422.
func TestCreateTenantBackgroundPreset(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	preset := gen.BackgroundPresetId("ocean")
	body := &gen.TenantCreate{
		Name: "Entity B", Fqdn: "transfer.entity-b.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1 << 40,
		BackgroundPreset: &preset,
	}
	svc := &fakeTenantService{}
	if _, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body}); err != nil {
		t.Fatal(err)
	}
	if in := svc.args["CreateTenant"][1].(tenantadmin.TenantCreate); in.BackgroundPreset == nil || *in.BackgroundPreset != "ocean" {
		t.Errorf("create input %+v", in)
	}
	svc = &fakeTenantService{err: tenantadmin.ErrUnknownBackgroundPreset}
	_, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body})
	expectProblem(t, err, problem.CodeUnknownBackgroundPreset)
}

func TestCreateAdminRefusesMailDelivery(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	tids := []string{"ten_a"}
	body := func(inv *gen.AdminInvitation) *gen.AdminCreate {
		return &gen.AdminCreate{
			Username: "admin.entity-a", Email: "admin@entity-a.example.com", Role: gen.DelegatedAdmin,
			TenantIds: &tids, Invitation: inv,
		}
	}
	mail, cp := gen.Mail, gen.Copy

	svc := &fakeService{}
	s := newServer(svc, &fakeTenants{})
	_, err := s.CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: body(&gen.AdminInvitation{Delivery: &mail})})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if want := []problem.FieldError{{Field: "/invitation/delivery", Code: fieldNotSupported}}; !reflect.DeepEqual(p.Errors, want) {
		t.Errorf("errors %+v", p.Errors)
	}
	if len(svc.calls) != 0 {
		t.Errorf("the service was called: %v", svc.calls)
	}

	// Copy, explicit or by default, keeps the 1.1 behavior: the link is
	// returned once.
	for _, inv := range []*gen.AdminInvitation{nil, {}, {Delivery: &cp}} {
		resp, err := s.CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: body(inv)})
		if err != nil {
			t.Fatalf("invitation %+v: %v", inv, err)
		}
		got := resp.(gen.CreateAdmin201JSONResponse)
		if got.InvitationDelivery != gen.Copy || got.ActivationUrl == nil || *got.ActivationUrl == "" {
			t.Errorf("invitation %+v: answer %+v", inv, got)
		}
	}
}
