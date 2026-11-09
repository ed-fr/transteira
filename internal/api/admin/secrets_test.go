package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
	"github.com/ed-fr/transteira/internal/tenantops"
)

func TestListTenantSecrets(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	o := newFakeOps()
	o.next = "cursor2"
	o.secrets = []store.Secret{
		{
			ID: "sec_01", State: store.SecretActive, CreatorKind: store.SecretCreatorInternal, SenderEmail: "alice@entity-a.example.com",
			Delivery: store.SecretDeliveryEmail, RecipientEmail: "carol@customer.example.net", ReadReceipt: true,
			CreatedAt: now, ExpiresAt: now.Add(1000),
		},
		{
			ID: "sec_02", State: store.SecretDeleted, CreatorKind: store.SecretCreatorAPIToken, SenderEmail: "bot@entity-a.example.com",
			Delivery: store.SecretDeliveryLink, FileSize: 2048, CreatedAt: now, EndedAt: now, EndReason: store.SecretEndDeletedByAdmin,
		},
		{
			ID: "sec_03", State: store.SecretLocked, CreatorKind: store.SecretCreatorExternal, SenderEmail: "x@customer.example.net",
			Delivery: store.SecretDeliveryEmail, CreatedAt: now, EndedAt: now, EndReason: store.SecretEndLocked,
		},
		{
			ID: "sec_04", State: store.SecretDeleted, CreatorKind: store.SecretCreatorInternalRemote, SenderEmail: "y@entity-a.example.com",
			Delivery: store.SecretDeliveryLink, CreatedAt: now, EndedAt: now, EndReason: store.SecretEndDeletedByCreator, ReadAt: now,
		},
	}
	s := opsServer(o, nil, nil)
	state, sender, limit, cursor := gen.SecretState("active"), gen.Email("alice@entity-a.example.com"), 5, "c1"
	resp, err := s.ListTenantSecrets(ctx, gen.ListTenantSecretsRequestObject{
		TenantId: "ten_a", Params: gen.ListTenantSecretsParams{State: &state, Sender: &sender, Limit: &limit, Cursor: &cursor},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f := o.args["ListSecrets"][2].(tenantops.SecretFilter); f.State != "active" || f.Sender != string(sender) || f.Limit != 5 || f.Cursor != "c1" {
		t.Errorf("filter = %+v", f)
	}
	code, out := decode(t, resp)
	items, _ := out["items"].([]any)
	if code != http.StatusOK || len(items) != 4 || out["nextCursor"] != "cursor2" {
		t.Fatalf("list = %d %v", code, out)
	}
	first := items[0].(map[string]any)
	if first["id"] != "sec_01" || first["recipient"] != "carol@customer.example.net" || first["hasFile"] != false ||
		first["readReceipt"] != true || first["creatorKind"] != "internal" || first["expiresAt"] == nil {
		t.Errorf("first = %v", first)
	}
	second := items[1].(map[string]any)
	if second["endReason"] != "deleted" || second["hasFile"] != true || second["fileSize"] != float64(2048) || second["recipient"] != nil {
		t.Errorf("second = %v", second)
	}
	if items[2].(map[string]any)["endReason"] != "locked" || items[3].(map[string]any)["endReason"] != "deleted" {
		t.Errorf("end reasons = %v %v", items[2], items[3])
	}
	for _, it := range items {
		for _, k := range []string{"text", "token", "verifier", "key", "encryptedText"} {
			if _, ok := it.(map[string]any)[k]; ok {
				t.Errorf("the listing exposes %q", k)
			}
		}
	}

	o.err = &tenantops.InvalidError{Field: tenantops.FieldSender, NotAnAddress: true}
	_, err = s.ListTenantSecrets(ctx, gen.ListTenantSecretsRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "sender" || p.Errors[0].Code != fieldInvalidEmail {
		t.Errorf("errors = %+v", p.Errors)
	}
}

func TestDeleteTenantSecret(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	o := newFakeOps()
	s := opsServer(o, nil, nil)
	resp, err := s.DeleteTenantSecret(ctx, gen.DeleteTenantSecretRequestObject{TenantId: "ten_a", SecretId: "sec_01"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := visit(t, resp); rec.Code != http.StatusNoContent {
		t.Errorf("status = %d", rec.Code)
	}
	if args := o.args["DeleteSecret"]; args[1] != tenant.ID("ten_a") || args[2] != "sec_01" || args[3] != clientIP {
		t.Errorf("args = %v", args)
	}
	o.err = tenantops.ErrNotFound
	_, err = s.DeleteTenantSecret(ctx, gen.DeleteTenantSecretRequestObject{TenantId: "ten_a", SecretId: "sec_01"})
	expectProblem(t, err, problem.CodeNotFound)
}

// validSecretSettingsJSON is a body carrying every required member.
const validSecretSettingsJSON = `{"enabled":true,"durations":["1h","1d"],"fileAllowed":false,"fileMaxBytes":2097152,"emailAllowed":true}`

func TestSecretSettingsHandlers(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	resp, err := s.GetSecretSettings(ctx, gen.GetSecretSettingsRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	code, out := decode(t, resp)
	if code != http.StatusOK || out["enabled"] != true || out["fileMaxBytes"] != float64(tenant.DefaultSecretFileBytes) ||
		out["emailRequiresPassphrase"] != false || out["defaultDuration"] != nil || len(out["durations"].([]any)) != 3 {
		t.Errorf("get = %d %v", code, out)
	}

	def, yes := gen.SecretDuration("1d"), true
	body := &gen.SecretSettings{
		Enabled: true, Durations: []gen.SecretDuration{"1h", "1d"}, DefaultDuration: &def, FileAllowed: false,
		FileMaxBytes: tenant.MinSecretFileBytes, EmailAllowed: true, EmailRequiresPassphrase: &yes,
	}
	rawCtx := context.WithValue(ctx, rawBodyKey{}, []byte(validSecretSettingsJSON))
	upd, err := s.UpdateSecretSettings(rawCtx, gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	in := svc.args["UpdateSecretSettings"][2].(tenantadmin.SecretSettingsInput)
	if !in.Enabled || len(in.Durations) != 2 || in.Durations[1] != "1d" || in.DefaultDuration != "1d" || in.FileAllowed ||
		in.FileMaxBytes != tenant.MinSecretFileBytes || !in.EmailAllowed || !in.EmailRequiresPassphrase || svc.args["UpdateSecretSettings"][3] != clientIP {
		t.Errorf("input = %+v", in)
	}
	code, out = decode(t, upd)
	if code != http.StatusOK || out["defaultDuration"] != "1d" || out["emailRequiresPassphrase"] != true || out["fileAllowed"] != false {
		t.Errorf("update = %d %v", code, out)
	}

	_, err = s.UpdateSecretSettings(ctx, gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a"})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "/durations" {
		t.Errorf("no body: %+v", p.Errors)
	}
	svc.err = &tenantadmin.InvalidError{Field: tenantadmin.FieldFileMaxBytes, Reason: "range"}
	_, err = s.UpdateSecretSettings(rawCtx, gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body})
	p = expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "/fileMaxBytes" {
		t.Errorf("invalid: %+v", p.Errors)
	}
	svc.err = nil
	// A server without CaptureRawBody.
	_, err = s.UpdateSecretSettings(ctx, gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: body})
	if !errors.Is(err, errNoSecretSettingsBody) {
		t.Errorf("without the capture middleware: %v", err)
	}
	// A body missing required members, or with a null one, names each.
	for raw, want := range map[string][]string{
		`{}`: {"/enabled", "/durations", "/fileAllowed", "/fileMaxBytes", "/emailAllowed"},
		`{"enabled":true,"durations":["1d"],"fileMaxBytes":1}`:                                     {"/fileAllowed", "/emailAllowed"},
		`{"enabled":null,"durations":["1d"],"fileAllowed":true,"fileMaxBytes":1,"emailAllowed":1}`: {"/enabled"},
	} {
		_, err = s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, []byte(raw)),
			gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: &gen.SecretSettings{}})
		p = expectProblem(t, err, problem.CodeValidationFailed)
		var got []string
		for _, fe := range p.Errors {
			got = append(got, fe.Field)
		}
		if !slices.Equal(got, want) {
			t.Errorf("body %s: fields %v, want %v", raw, got, want)
		}
	}
	_, err = s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, []byte(`[]`)), gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: &gen.SecretSettings{}})
	expectProblem(t, err, problem.CodeValidationFailed)
	// An invalid body for a tenant the administrator cannot reach: 404 first.
	svc.err = tenantadmin.ErrNotFound
	_, err = s.UpdateSecretSettings(context.WithValue(ctx, rawBodyKey{}, []byte(`{}`)), gen.UpdateSecretSettingsRequestObject{TenantId: "ten_a", Body: &gen.SecretSettings{}})
	expectProblem(t, err, problem.CodeNotFound)
	svc.err = nil
	svc.err = tenantadmin.ErrNotFound
	_, err = s.GetSecretSettings(ctx, gen.GetSecretSettingsRequestObject{TenantId: "ten_a"})
	expectProblem(t, err, problem.CodeNotFound)
}

// TestImportSecretSettings checks that the settings of an imported
// configuration reach the service (including emailRequiresPassphrase), and
// that an unknown member is still refused.
func TestImportSecretSettings(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	settings := `"secretSettings":{"enabled":true,"durations":["1h","1d"],"defaultDuration":"1d","fileAllowed":true,` +
		`"fileMaxBytes":10485760,"emailAllowed":true,"emailRequiresPassphrase":true},`
	raw := strings.Replace(validImport, `"network"`, settings+`"network"`, 1)
	svc := &fakeTenantService{}
	if _, err := tenantServer(svc).ImportTenant(importCtx(super, raw), importReq()); err != nil {
		t.Fatal(err)
	}
	ss := svc.args["ImportTenant"][1].(tenantadmin.ImportInput).Config.SecretSettings
	if ss == nil || !ss.Enabled || len(ss.Durations) != 2 || ss.DefaultDuration == nil || *ss.DefaultDuration != "1d" ||
		ss.FileMaxBytes != 10485760 || !ss.EmailRequiresPassphrase {
		t.Errorf("settings = %+v", ss)
	}
	// Still strict: an incomplete block and an unknown member are refused.
	for name, bad := range map[string]string{
		"incomplete": `"secretSettings":{"enabled":true},`, "unknown": `"secretSettings":{"enabled":true,"durations":["1h"],"fileAllowed":true,"fileMaxBytes":1,"emailAllowed":true,"x":1},`,
	} {
		raw := strings.Replace(validImport, `"network"`, bad+`"network"`, 1)
		_, err := tenantServer(&fakeTenantService{}).ImportTenant(importCtx(super, raw), importReq())
		var p *problem.Problem
		if !errors.As(err, &p) || p.Code != problem.CodeImportInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}
