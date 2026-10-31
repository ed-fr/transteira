package admin

import (
	"reflect"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

func TestGetTenantSetup(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	svc := &fakeTenantService{}
	resp, err := tenantServer(svc).GetTenantSetup(ctx, gen.GetTenantSetupRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	want := gen.GetTenantSetup200JSONResponse{SetupState: gen.TenantSetupStateSetup, Items: []gen.TenantSetupItem{
		{Key: "branding_logo", Done: true}, {Key: "smtp", Required: true},
	}}
	if !reflect.DeepEqual(resp, want) {
		t.Errorf("answer %+v, want %+v", resp, want)
	}
	if !reflect.DeepEqual(svc.args["GetSetup"], []any{"as_01", tenant.ID("ten_a")}) {
		t.Errorf("args %v", svc.args["GetSetup"])
	}
	_, err = tenantServer(&fakeTenantService{err: tenantadmin.ErrNotFound}).GetTenantSetup(ctx, gen.GetTenantSetupRequestObject{TenantId: "ten_b"})
	expectProblem(t, err, problem.CodeNotFound)
}

func TestCompleteTenantSetup(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	yes := true
	svc := &fakeTenantService{}
	resp, err := tenantServer(svc).CompleteTenantSetup(ctx, gen.CompleteTenantSetupRequestObject{
		TenantId: "ten_a", Body: &gen.TenantSetupCompletion{Force: &yes, MailTemplatesReviewed: &yes},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.CompleteTenantSetup200JSONResponse)
	if got.SetupState != gen.TenantSetupStateActive || !got.CanComplete || len(got.Items) != 2 {
		t.Errorf("answer %+v", got)
	}
	if !reflect.DeepEqual(svc.args["CompleteSetup"], []any{"as_01", tenant.ID("ten_a"), true, true, clientIP}) {
		t.Errorf("args %v", svc.args["CompleteSetup"])
	}
	// An empty object: no force, no review.
	svc = &fakeTenantService{}
	if _, err := tenantServer(svc).CompleteTenantSetup(ctx, gen.CompleteTenantSetupRequestObject{
		TenantId: "ten_a", Body: &gen.TenantSetupCompletion{},
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(svc.args["CompleteSetup"], []any{"as_01", tenant.ID("ten_a"), false, false, clientIP}) {
		t.Errorf("args %v", svc.args["CompleteSetup"])
	}
	// No body.
	svc = &fakeTenantService{}
	_, err = tenantServer(svc).CompleteTenantSetup(ctx, gen.CompleteTenantSetupRequestObject{TenantId: "ten_a"})
	expectProblem(t, err, problem.CodeValidationFailed)
	if len(svc.calls) != 0 {
		t.Errorf("the service was called: %v", svc.calls)
	}

	// The errors.
	for name, tc := range map[string]struct {
		err    error
		code   problem.Code
		fields []problem.FieldError
	}{
		"incomplete": {
			&tenantadmin.IncompleteError{Missing: []string{"smtp", "privacy_policy"}}, problem.CodeSetupIncomplete,
			[]problem.FieldError{{Field: "smtp", Code: "not-done"}, {Field: "privacy_policy", Code: "not-done"}},
		},
		"incomplete, bare":  {tenantadmin.ErrSetupIncomplete, problem.CodeSetupIncomplete, nil},
		"already complete":  {tenantadmin.ErrSetupComplete, problem.CodeSetupAlreadyComplete, nil},
		"forced, delegated": {tenantadmin.ErrForbidden, problem.CodeForbidden, nil},
		"not found":         {tenantadmin.ErrNotFound, problem.CodeNotFound, nil},
		"unauthenticated":   {tenantadmin.ErrUnauthenticated, problem.CodeUnauthenticated, nil},
	} {
		svc := &fakeTenantService{err: tc.err}
		_, err := tenantServer(svc).CompleteTenantSetup(ctx, gen.CompleteTenantSetupRequestObject{
			TenantId: "ten_a", Body: &gen.TenantSetupCompletion{},
		})
		p := expectProblem(t, err, tc.code)
		if !reflect.DeepEqual(p.Errors, tc.fields) {
			t.Errorf("%s: errors %+v, want %+v", name, p.Errors, tc.fields)
		}
	}
}

func TestGetTextProposal(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	svc := &fakeTenantService{}
	resp, err := tenantServer(svc).GetTextProposal(ctx, gen.GetTextProposalRequestObject{
		TenantId: "ten_a", Document: gen.LegalDocumentPathPrivacyPolicy, Language: "fr",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := gen.GetTextProposal200JSONResponse{
		Document: gen.TextProposalDocumentPrivacyPolicy, Language: "fr", Markdown: "# Notice", Notice: "setup.textProposal.reviewNotice",
	}
	if !reflect.DeepEqual(resp, want) {
		t.Errorf("answer %+v, want %+v", resp, want)
	}
	if !reflect.DeepEqual(svc.args["TextProposal"], []any{"as_01", tenant.ID("ten_a"), "privacy-policy", "fr"}) {
		t.Errorf("args %v", svc.args["TextProposal"])
	}
	_, err = tenantServer(&fakeTenantService{err: tenantadmin.ErrNotFound}).GetTextProposal(ctx, gen.GetTextProposalRequestObject{
		TenantId: "ten_a", Document: "terms", Language: "de",
	})
	expectProblem(t, err, problem.CodeNotFound)
}

// The tenant views carry their setup state (since 1.2), none when unknown.
func TestTenantBodySetupState(t *testing.T) {
	t.Parallel()
	v := viewA
	if b := tenantBody(v); b.SetupState != nil {
		t.Errorf("unknown state rendered: %v", *b.SetupState)
	}
	v.SetupState = tenant.SetupStateSetup
	if b := tenantBody(v); b.SetupState == nil || *b.SetupState != gen.TenantSetupStateSetup {
		t.Errorf("state %v", b.SetupState)
	}
	if b := tenantCreatedBody(tenantadmin.TenantCreated{TenantView: v}); b.SetupState == nil || *b.SetupState != gen.TenantSetupStateSetup {
		t.Errorf("created state %v", b.SetupState)
	}
}
