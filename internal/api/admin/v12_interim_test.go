package admin

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// The members of API 1.2 not implemented yet (the setup state) are refused
// with a 400 naming them, before the service is called, rather than ignored
// (fail closed).
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

// The mail delivery of API 1.2 is implemented: the invitation is passed to
// the service and a mailed link is never returned (T-255).
func TestCreateAdminInvitation(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	tids := []string{"ten_a"}
	body := func(inv *gen.AdminInvitation) *gen.AdminCreate {
		return &gen.AdminCreate{
			Username: "admin.entity-a", Email: "admin@entity-a.example.com", Role: gen.DelegatedAdmin,
			TenantIds: &tids, Invitation: inv,
		}
	}
	mail, cp, fr := gen.Mail, gen.Copy, gen.Language("fr")

	// Copy, explicit or by default: the link is returned once.
	for _, inv := range []*gen.AdminInvitation{nil, {}, {Delivery: &cp}} {
		svc := &fakeService{}
		resp, err := newServer(svc, &fakeTenants{}).CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: body(inv)})
		if err != nil {
			t.Fatalf("invitation %+v: %v", inv, err)
		}
		got := resp.(gen.CreateAdmin201JSONResponse)
		if got.InvitationDelivery != gen.Copy || got.ActivationUrl == nil || *got.ActivationUrl == "" {
			t.Errorf("invitation %+v: answer %+v", inv, got)
		}
		if in := svc.args["Create"][1].(adminauth.AdminCreate); in.Invitation.Delivery != "" && in.Invitation.Delivery != store.DeliveryCopy {
			t.Errorf("invitation %+v: passed %+v", inv, in.Invitation)
		}
	}

	// Mail: passed on, and the answer carries no URL.
	svc := &fakeService{mailed: true}
	resp, err := newServer(svc, &fakeTenants{}).CreateAdmin(ctx, gen.CreateAdminRequestObject{Body: body(&gen.AdminInvitation{Delivery: &mail, Language: &fr})})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.CreateAdmin201JSONResponse)
	if got.InvitationDelivery != gen.Mail || got.ActivationUrl != nil || got.ActivationExpiresAt.IsZero() {
		t.Errorf("mail answer %+v", got)
	}
	if in := svc.args["Create"][1].(adminauth.AdminCreate); in.Invitation != (adminauth.Invitation{Delivery: store.DeliveryMail, Language: "fr"}) {
		t.Errorf("passed %+v", in.Invitation)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "activationUrl") || strings.Contains(string(raw), "act_") {
		t.Errorf("the answer leaks the link: %s", raw)
	}
}

func TestInviteAdmin(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	mail, fr := gen.Mail, gen.Language("fr")

	// No body: the defaults (copy).
	svc := &fakeService{}
	resp, err := newServer(svc, &fakeTenants{}).InviteAdmin(ctx, gen.InviteAdminRequestObject{AdminId: "adm_deleg"})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.InviteAdmin200JSONResponse)
	if got.InvitationDelivery != gen.Copy || got.ActivationUrl == nil || *got.ActivationUrl == "" {
		t.Errorf("copy answer %+v", got)
	}
	if !reflect.DeepEqual(svc.args["Invite"], []any{"as_01", "adm_deleg", adminauth.Invitation{}, clientIP}) {
		t.Errorf("args %v", svc.args["Invite"])
	}

	// Mail.
	svc = &fakeService{mailed: true}
	resp, err = newServer(svc, &fakeTenants{}).InviteAdmin(ctx, gen.InviteAdminRequestObject{
		AdminId: "adm_deleg", Body: &gen.AdminInvitation{Delivery: &mail, Language: &fr},
	})
	if err != nil {
		t.Fatal(err)
	}
	got = resp.(gen.InviteAdmin200JSONResponse)
	if got.InvitationDelivery != gen.Mail || got.ActivationUrl != nil {
		t.Errorf("mail answer %+v", got)
	}
	if !reflect.DeepEqual(svc.args["Invite"], []any{"as_01", "adm_deleg", adminauth.Invitation{Delivery: store.DeliveryMail, Language: "fr"}, clientIP}) {
		t.Errorf("args %v", svc.args["Invite"])
	}

	// The service errors.
	for name, tc := range map[string]struct {
		err   error
		code  problem.Code
		field string
		fcode string
	}{
		"not found":      {adminauth.ErrNotFound, problem.CodeNotFound, "", ""},
		"disabled":       {adminauth.ErrAccountDisabled, problem.CodeStateConflict, "", ""},
		"already active": {adminauth.ErrAdminAlreadyActive, problem.CodeAdminAlreadyActive, "", ""},
		"no smtp":        {adminauth.ErrSystemSMTPUnavailable, problem.CodeSystemSMTPUnavailable, "", ""},
		"forbidden":      {adminauth.ErrForbidden, problem.CodeForbidden, "", ""},
		"rate limited":   {&adminauth.RateLimitError{RetryAfter: time.Minute}, problem.CodeRateLimited, "", ""},
		"not allowed": {
			&adminauth.NotAllowedError{Field: "/delivery"}, problem.CodeValidationFailed, "/delivery", "not-allowed",
		},
		"invalid": {
			&adminauth.InvalidError{Field: "/language"}, problem.CodeValidationFailed, "/language", "invalid-format",
		},
	} {
		svc := &fakeService{err: tc.err}
		_, err := newServer(svc, &fakeTenants{}).InviteAdmin(ctx, gen.InviteAdminRequestObject{AdminId: "adm_deleg"})
		p := expectProblem(t, err, tc.code)
		if tc.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != tc.fcode) {
			t.Errorf("%s: errors %+v", name, p.Errors)
		}
	}
}

func TestCreateTenantDelegatedAdmin(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	mail := gen.Mail
	body := func(delivery *gen.InvitationDelivery) *gen.TenantCreate {
		return &gen.TenantCreate{
			Name: "Entity B", Fqdn: "transfer.entity-b.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1 << 40,
			DelegatedAdmin: &gen.NewDelegatedAdmin{
				Username: "admin.b", Email: "admin@entity-b.example.com", Language: "fr", Delivery: delivery,
			},
		}
	}
	expires := now.Add(72 * time.Hour)

	// Copy (the default): the URL is returned.
	svc := &fakeTenantService{invited: &tenantadmin.InvitedAdmin{
		Account:    adminauth.Account{ID: "adm_new"},
		Activation: adminauth.Activation{URL: "https://admin.example.com/admin/activate#act_x", Delivery: store.DeliveryCopy, ExpiresAt: expires},
	}}
	resp, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body(nil)})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.CreateTenant201JSONResponse)
	if d := got.DelegatedAdmin; d == nil || d.Id != "adm_new" || d.InvitationDelivery != gen.Copy ||
		d.ActivationUrl == nil || *d.ActivationUrl == "" || !d.ActivationExpiresAt.Equal(expires) {
		t.Errorf("copy answer %+v", got.DelegatedAdmin)
	}
	in := svc.args["CreateTenant"][1].(tenantadmin.TenantCreate)
	if want := (&adminauth.DelegatedAdmin{Username: "admin.b", Email: "admin@entity-b.example.com", Language: "fr"}); !reflect.DeepEqual(in.DelegatedAdmin, want) {
		t.Errorf("passed %+v", in.DelegatedAdmin)
	}

	// Mail: no URL.
	svc = &fakeTenantService{invited: &tenantadmin.InvitedAdmin{
		Account:    adminauth.Account{ID: "adm_new"},
		Activation: adminauth.Activation{Delivery: store.DeliveryMail, ExpiresAt: expires},
	}}
	resp, err = tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body(&mail)})
	if err != nil {
		t.Fatal(err)
	}
	got = resp.(gen.CreateTenant201JSONResponse)
	if d := got.DelegatedAdmin; d == nil || d.InvitationDelivery != gen.Mail || d.ActivationUrl != nil {
		t.Errorf("mail answer %+v", got.DelegatedAdmin)
	}
	if in := svc.args["CreateTenant"][1].(tenantadmin.TenantCreate); in.DelegatedAdmin.Delivery != store.DeliveryMail {
		t.Errorf("passed %+v", in.DelegatedAdmin)
	}

	// No delegated admin: none in the answer.
	svc = &fakeTenantService{}
	b := body(nil)
	b.DelegatedAdmin = nil
	resp, err = tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: b})
	if err != nil || resp.(gen.CreateTenant201JSONResponse).DelegatedAdmin != nil {
		t.Errorf("answer %+v, %v", resp, err)
	}

	// Errors: the fields of the admin are prefixed, the others mapped.
	for name, tc := range map[string]struct {
		err   error
		code  problem.Code
		field string
		fcode string
	}{
		"invalid username": {&adminauth.InvalidError{Field: adminauth.FieldUsername}, problem.CodeValidationFailed, "/delegatedAdmin/username", "invalid-format"},
		"invalid email":    {&adminauth.InvalidError{Field: adminauth.FieldEmail}, problem.CodeValidationFailed, "/delegatedAdmin/email", "invalid-email"},
		"invalid language": {&adminauth.InvalidError{Field: adminauth.FieldLanguage}, problem.CodeValidationFailed, "/delegatedAdmin/language", "invalid-format"},
		"no smtp":          {adminauth.ErrSystemSMTPUnavailable, problem.CodeSystemSMTPUnavailable, "", ""},
		"forbidden":        {adminauth.ErrForbidden, problem.CodeForbidden, "", ""},
		"unauthenticated":  {adminauth.ErrUnauthenticated, problem.CodeUnauthenticated, "", ""},
		"conflict":         {tenantadmin.ErrAlreadyExists, problem.CodeAlreadyExists, "", ""},
		"tenant invalid": {
			&tenantadmin.InvalidError{Field: tenantadmin.FieldMaxTransferBytes, Reason: "x"}, problem.CodeValidationFailed, "/maxTransferBytes", "",
		},
	} {
		svc := &fakeTenantService{err: tc.err}
		_, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body(nil)})
		p := expectProblem(t, err, tc.code)
		if tc.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != tc.field || (tc.fcode != "" && p.Errors[0].Code != tc.fcode)) {
			t.Errorf("%s: errors %+v", name, p.Errors)
		}
	}
}

// A copied link without URL is still a copy (pointer to an empty URL); only
// the mail delivery hides the URL.
func TestDeliveryOf(t *testing.T) {
	t.Parallel()
	if d, url := deliveryOf(adminauth.Activation{Delivery: store.DeliveryMail, URL: "x"}); d != gen.Mail || url != nil {
		t.Errorf("mail: %v %v", d, url)
	}
	if d, url := deliveryOf(adminauth.Activation{Delivery: store.DeliveryCopy}); d != gen.Copy || url == nil || *url != "" {
		t.Errorf("copy without URL: %v %v", d, url)
	}
	if d, url := deliveryOf(adminauth.Activation{URL: "u"}); d != gen.Copy || url == nil || *url != "u" {
		t.Errorf("copy: %v %v", d, url)
	}
}
