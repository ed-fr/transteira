package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/keyrotation"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/systemsettings"
)

// fakeMaintenance is a fake MaintenanceService.
type fakeMaintenance struct {
	recorder
	state maintenance.State
}

func (f *fakeMaintenance) Get(_ context.Context, p adminauth.Principal) (maintenance.State, error) {
	return f.state, f.record("Get", p.SessionID)
}

func (f *fakeMaintenance) Set(_ context.Context, p adminauth.Principal, enabled bool, messages map[string]string, ip netip.Addr) (maintenance.State, error) {
	return f.state, f.record("Set", p.SessionID, enabled, messages, ip)
}

// fakeSettings is a fake SystemSettingsService.
type fakeSettings struct {
	recorder
	settings systemsettings.Settings
}

func (f *fakeSettings) Get(_ context.Context, p adminauth.Principal) (systemsettings.Settings, error) {
	return f.settings, f.record("Get", p.SessionID)
}

func (f *fakeSettings) Update(_ context.Context, p adminauth.Principal, patch systemsettings.Patch, ip netip.Addr) (systemsettings.Settings, error) {
	return f.settings, f.record("Update", p.SessionID, patch, ip)
}

// fakeRotations is a fake KeyRotationService.
type fakeRotations struct {
	recorder
	rotation keyrotation.Rotation
	status   keyrotation.MasterKeyStatus
}

func (f *fakeRotations) Start(_ context.Context, p adminauth.Principal, code, recovery string, ip netip.Addr) (keyrotation.Rotation, error) {
	return f.rotation, f.record("Start", p.SessionID, code, recovery, ip)
}

func (f *fakeRotations) Get(_ context.Context, p adminauth.Principal, rotID string) (keyrotation.Rotation, error) {
	return f.rotation, f.record("Get", p.SessionID, rotID)
}

func (f *fakeRotations) Status(_ context.Context, p adminauth.Principal) (keyrotation.MasterKeyStatus, error) {
	return f.status, f.record("Status", p.SessionID)
}

// sampleRotation is a completed rotation.
var sampleRotation = keyrotation.Rotation{
	ID: "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7", Status: store.RotationCompleted, FromKeyID: "mk_old", ToKeyID: "mk_new",
	TotalKeys: 10, RewrappedKeys: 10, StartedAt: now.Add(-time.Minute), CompletedAt: now,
}

// systemServer returns a server over the three system services.
func systemServer(m MaintenanceService, st SystemSettingsService, r KeyRotationService) *Server {
	return NewServer(WithMaintenance(m), WithSystemSettings(st), WithKeyRotation(r))
}

// settingsPatch returns a raw system settings merge patch.
func settingsPatch(s string) *gen.SystemSettingsUpdate {
	b := gen.SystemSettingsUpdate(s)
	return &b
}

// maintenanceUpdate returns a raw MaintenanceUpdate.
func maintenanceUpdate(s string) *gen.MaintenanceUpdate {
	b := gen.MaintenanceUpdate(s)
	return &b
}

// totpBody returns a raw master key rotation start body.
func totpBody(s string) *gen.StartMasterKeyRotationJSONRequestBody {
	b := gen.StartMasterKeyRotationJSONRequestBody(s)
	return &b
}

// systemCalls calls every system operation of s with a minimal valid
// request and returns the errors, by operation.
func systemCalls(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	var err error
	_, err = s.GetMaintenance(ctx, gen.GetMaintenanceRequestObject{})
	out["GetMaintenance"] = err
	_, err = s.SetMaintenance(ctx, gen.SetMaintenanceRequestObject{Body: maintenanceUpdate(`{"enabled":true}`)})
	out["SetMaintenance"] = err
	_, err = s.GetSystemSettings(ctx, gen.GetSystemSettingsRequestObject{})
	out["GetSystemSettings"] = err
	_, err = s.UpdateSystemSettings(ctx, gen.UpdateSystemSettingsRequestObject{Body: settingsPatch(`{"diskAlertThreshold":0.9}`)})
	out["UpdateSystemSettings"] = err
	_, err = s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: totpBody(`{"code":"204816"}`)})
	out["StartMasterKeyRotation"] = err
	_, err = s.GetMasterKeyRotation(ctx, gen.GetMasterKeyRotationRequestObject{RotationId: sampleRotation.ID})
	out["GetMasterKeyRotation"] = err
	_, err = s.GetMasterKeyStatus(ctx, gen.GetMasterKeyStatusRequestObject{})
	out["GetMasterKeyStatus"] = err
	return out
}

func TestSystemWiring(t *testing.T) {
	t.Parallel()
	want := map[string]error{
		"GetMaintenance": errNoMaintenance, "SetMaintenance": errNoMaintenance,
		"GetSystemSettings": errNoSystemSettings, "UpdateSystemSettings": errNoSystemSettings,
		"StartMasterKeyRotation": errNoKeyRotation, "GetMasterKeyRotation": errNoKeyRotation, "GetMasterKeyStatus": errNoKeyRotation,
	}
	calls := systemCalls(ctxWith(store.SessionAuthenticated, superRoot), NewServer())
	if len(calls) != len(want) {
		t.Fatalf("%d operations, want %d", len(calls), len(want))
	}
	for name, err := range calls {
		if !errors.Is(err, want[name]) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	// Without session in the context: 401 before the services.
	m, st, r := &fakeMaintenance{}, &fakeSettings{}, &fakeRotations{}
	for name, err := range systemCalls(ctxWith("", superRoot), systemServer(m, st, r)) {
		if p := expectProblem(t, err, problem.CodeUnauthenticated); p.Code == "" {
			t.Error(name)
		}
	}
	if len(m.calls)+len(st.calls)+len(r.calls) != 0 {
		t.Errorf("services called without session: %v %v %v", m.calls, st.calls, r.calls)
	}
	// Every operation reaches its service with the session, but the two
	// changes the handler refuses to a delegated admin itself (403 before
	// the body); a service error (here the role check) is mapped.
	m = &fakeMaintenance{recorder: recorder{err: adminauth.ErrForbidden}}
	st = &fakeSettings{recorder: recorder{err: adminauth.ErrForbidden}}
	r = &fakeRotations{recorder: recorder{err: adminauth.ErrForbidden}}
	for name, err := range systemCalls(ctxWith(store.SessionAuthenticated, delegated), systemServer(m, st, r)) {
		if p := expectProblem(t, err, problem.CodeForbidden); p.Code == "" {
			t.Error(name)
		}
	}
	for _, rec := range []recorder{m.recorder, st.recorder, r.recorder} {
		for name, args := range rec.args {
			if args[0] != "as_01" {
				t.Errorf("%s: session %v", name, args[0])
			}
			if (name == "Set" || name == "Update" || name == "Start") && args[len(args)-1] != clientIP {
				t.Errorf("%s: client IP %v", name, args[len(args)-1])
			}
		}
	}
	if len(m.calls) != 1 || len(st.calls) != 1 || len(r.calls) != 3 {
		t.Errorf("calls %v %v %v", m.calls, st.calls, r.calls)
	}
}

// TestSystemChangesRoleBeforeBody: a delegated admin sending a missing or
// malformed body to SetMaintenance or UpdateSystemSettings gets 403, never
// the 400 of the body (security review L5, as startMasterKeyRotation).
func TestSystemChangesRoleBeforeBody(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	m, st := &fakeMaintenance{}, &fakeSettings{}
	s := systemServer(m, st, nil)
	for _, body := range []string{"", `[]`, `{}`, `{"enabled":null}`, `{"unknown":1}`, `{"diskAlertThreshold":null}`, `not json`} {
		mreq := gen.SetMaintenanceRequestObject{}
		sreq := gen.UpdateSystemSettingsRequestObject{}
		if body != "" {
			mreq.Body, sreq.Body = maintenanceUpdate(body), settingsPatch(body)
		}
		_, err := s.SetMaintenance(ctx, mreq)
		expectProblem(t, err, problem.CodeForbidden)
		_, err = s.UpdateSystemSettings(ctx, sreq)
		expectProblem(t, err, problem.CodeForbidden)
	}
	if len(m.calls)+len(st.calls) != 0 {
		t.Errorf("services called: %v %v", m.calls, st.calls)
	}
}

func TestSystemErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err   error
		code  problem.Code
		field string
		fcode string
	}{
		{&maintenance.InvalidError{Field: "/message/fr"}, problem.CodeValidationFailed, "/message/fr", fieldInvalidFormat},
		{maintenance.ErrInvalid, problem.CodeValidationFailed, "", ""},
		{maintenance.ErrForcedByEnvironment, problem.CodeStateConflict, "", ""},
		{&systemsettings.InvalidError{Field: systemsettings.FieldAlertEmail}, problem.CodeValidationFailed, "/alertEmail", fieldInvalidEmail},
		{&systemsettings.InvalidError{Field: systemsettings.FieldDiskAlertThreshold}, problem.CodeValidationFailed, "/diskAlertThreshold", fieldInvalidFormat},
		{systemsettings.ErrInvalidInput, problem.CodeValidationFailed, "", ""},
		{keyrotation.ErrNoNewKey, problem.CodeNewMasterKeyMissing, "", ""},
		{keyrotation.ErrConflict, problem.CodeStateConflict, "", ""},
		{keyrotation.ErrNotFound, problem.CodeNotFound, "", ""},
		{adminauth.ErrInvalidCredentials, problem.CodeInvalidCredentials, "", ""},
		{&adminauth.RateLimitError{RetryAfter: time.Minute}, problem.CodeRateLimited, "", ""},
		{&adminauth.InvalidError{Field: adminauth.FieldCode}, problem.CodeValidationFailed, "/code", fieldInvalidFormat},
		{adminauth.ErrUnauthenticated, problem.CodeUnauthenticated, "", ""},
		{adminauth.ErrForbidden, problem.CodeForbidden, "", ""},
	}
	for _, c := range cases {
		p := expectProblem(t, systemError(c.err), c.code)
		if c.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != c.field || p.Errors[0].Code != c.fcode) {
			t.Errorf("%v: errors %+v", c.err, p.Errors)
		}
	}
	// Each rotation conflict names its case, as in the OpenAPI examples.
	details := map[error]string{
		keyrotation.ErrConflict:         "",
		keyrotation.ErrRunning:          "A master key rotation is already running.",
		keyrotation.ErrRotationMismatch: "A rotation between other keys is unfinished; finish or abandon it with the command line.",
		keyrotation.ErrRestartRequired:  "The last rotation is complete; restart with the new key as TT_MASTER_KEY_FILE before starting another.",
	}
	for err, detail := range details {
		if p := expectProblem(t, systemError(fmt.Errorf("wrapped: %w", err)), problem.CodeStateConflict); p.Detail != detail {
			t.Errorf("%v: detail %q, want %q", err, p.Detail, detail)
		}
	}
	// Server errors, the shutdown included, keep their cause (500).
	for _, err := range []error{keyrotation.ErrClosed, adminauth.ErrNoClientIP, errors.New("boom")} {
		if got := systemError(err); got != err { //nolint:errorlint // identity expected
			t.Errorf("systemError(%v) = %v", err, got)
		}
	}
}

func TestMaintenanceOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	m := &fakeMaintenance{state: maintenance.State{Source: maintenance.SourceNone, Message: map[string]string{}}}
	s := systemServer(m, nil, nil)
	resp, err := s.GetMaintenance(ctx, gen.GetMaintenanceRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	code, body := decode(t, resp)
	if code != http.StatusOK || !reflect.DeepEqual(body, map[string]any{"enabled": false, "source": "none", "adminEnabled": false}) {
		t.Errorf("get = %d %v", code, body)
	}

	since := now.Add(-time.Hour)
	m.state = maintenance.State{
		Enabled: true, Source: maintenance.SourceAdmin, AdminEnabled: true, Since: since,
		Message: map[string]string{"fr": "Mise a jour", "en": "Upgrade"},
	}
	msgs := map[string]string{"fr": "Mise a jour", "en": "Upgrade"}
	set, err := s.SetMaintenance(ctx, gen.SetMaintenanceRequestObject{
		Body: maintenanceUpdate(`{"enabled":true,"message":{"fr":"Mise a jour","en":"Upgrade"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if args := m.args["Set"]; args[1] != true || !reflect.DeepEqual(args[2], msgs) {
		t.Errorf("set args %v", args)
	}
	code, body = decode(t, set)
	if code != http.StatusOK || body["enabled"] != true || body["source"] != "admin" || body["adminEnabled"] != true ||
		body["since"] != since.Format(time.RFC3339) || !reflect.DeepEqual(body["message"], map[string]any{"fr": "Mise a jour", "en": "Upgrade"}) {
		t.Errorf("set = %d %v", code, body)
	}
	// The message is a copy: changing the answer leaves the state alone.
	b := maintenanceBody(m.state)
	(*b.Message)["fr"] = "x"
	if m.state.Message["fr"] != "Mise a jour" {
		t.Error("maintenance message aliased")
	}

	// No message: nil messages; disabling forced maintenance: 409.
	m.err = maintenance.ErrForcedByEnvironment
	_, err = s.SetMaintenance(ctx, gen.SetMaintenanceRequestObject{Body: maintenanceUpdate(`{"enabled":false,"message":null}`)})
	expectProblem(t, err, problem.CodeStateConflict)
	if args := m.args["Set"]; args[1] != false || args[2].(map[string]string) != nil {
		t.Errorf("disable args %v", args)
	}
	m.err = errors.New("boom")
	if _, err := s.GetMaintenance(ctx, gen.GetMaintenanceRequestObject{}); err == nil || err.Error() != "boom" {
		t.Errorf("get failure: %v", err)
	}
	// A missing body is refused before the service.
	m.recorder = recorder{}
	_, err = s.SetMaintenance(ctx, gen.SetMaintenanceRequestObject{})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "" || p.Errors[0].Code != fieldRequired || len(m.calls) != 0 {
		t.Errorf("missing body: %+v, calls %v", p.Errors, m.calls)
	}
	// So is a malformed one: {} must not disable the mode.
	_, err = s.SetMaintenance(ctx, gen.SetMaintenanceRequestObject{Body: maintenanceUpdate(`{}`)})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/enabled" || p.Errors[0].Code != fieldRequired || len(m.calls) != 0 {
		t.Errorf("empty body: %+v, calls %v", p.Errors, m.calls)
	}
}

func TestDecodeMaintenanceUpdate(t *testing.T) {
	t.Parallel()
	ok := []struct {
		raw      string
		enabled  bool
		messages map[string]string
	}{
		{`{"enabled":true}`, true, nil},
		{`{"enabled":false,"message":null}`, false, nil},
		{`{"message":{"en":"Back soon"},"enabled":true}`, true, map[string]string{"en": "Back soon"}},
		{`{"enabled":true,"message":{}}`, true, map[string]string{}},
	}
	for _, c := range ok {
		enabled, messages, err := decodeMaintenanceUpdate([]byte(c.raw))
		if err != nil || enabled != c.enabled || !reflect.DeepEqual(messages, c.messages) {
			t.Errorf("%s: %v %v, %v", c.raw, enabled, messages, err)
		}
	}
	bad := []struct {
		raw, field, code string
	}{
		{`null`, "", fieldInvalidFormat},
		{`[]`, "", fieldInvalidFormat},
		{`true`, "", fieldInvalidFormat},
		{`{`, "", fieldInvalidFormat},
		{`{}`, "/enabled", fieldRequired},
		{`{"message":{"en":"x"}}`, "/enabled", fieldRequired},
		{`{"enabled": null }`, "/enabled", fieldNotNullable},
		{`{"enabled":"true"}`, "/enabled", fieldInvalidFormat},
		{`{"enabled":1}`, "/enabled", fieldInvalidFormat},
		{`{"enabled":true,"mesage":{"en":"x"}}`, "/mesage", fieldInvalidFormat},
		{`{"mesage":{"en":"x"}}`, "/mesage", fieldInvalidFormat},
		{`{"enabled":true,"message":"x"}`, "/message", fieldInvalidFormat},
		{`{"enabled":true,"message":{"en":1}}`, "/message", fieldInvalidFormat},
		{`{"enabled":true,"message":[]}`, "/message", fieldInvalidFormat},
	}
	for _, c := range bad {
		_, _, err := decodeMaintenanceUpdate([]byte(c.raw))
		var p *problem.Problem
		if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) != 1 ||
			p.Errors[0].Field != c.field || p.Errors[0].Code != c.code {
			t.Errorf("%s: %v", c.raw, err)
		}
	}
}

func TestDecodeTotpCode(t *testing.T) {
	t.Parallel()
	ok := []struct {
		raw, code, recovery string
	}{
		{`{}`, "", ""},
		{`{"code":"204816"}`, "204816", ""},
		{`{"recoveryCode":"rc-1"}`, "", "rc-1"},
		{`{"code":"1","recoveryCode":"rc-1"}`, "1", "rc-1"},
	}
	for _, c := range ok {
		code, recovery, err := decodeTotpCode([]byte(c.raw))
		if err != nil || code != c.code || recovery != c.recovery {
			t.Errorf("%s: %q %q, %v", c.raw, code, recovery, err)
		}
	}
	bad := []struct {
		raw, field string
	}{
		{`null`, ""},
		{`[]`, ""},
		{`"204816"`, ""},
		{`{`, ""},
		{`{"code":"204816","cdoe":"1"}`, "/cdoe"},
		{`{"code":204816}`, "/code"},
		{`{"code":null}`, "/code"},
		{`{"recoveryCode":["rc-1"]}`, "/recoveryCode"},
	}
	for _, c := range bad {
		_, _, err := decodeTotpCode([]byte(c.raw))
		var p *problem.Problem
		if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) != 1 ||
			p.Errors[0].Field != c.field || p.Errors[0].Code != fieldInvalidFormat {
			t.Errorf("%s: %v", c.raw, err)
		}
	}
}

func TestSystemSettingsOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	st := &fakeSettings{settings: systemsettings.Settings{DiskAlertThreshold: 0.85}}
	s := systemServer(nil, st, nil)
	resp, err := s.GetSystemSettings(ctx, gen.GetSystemSettingsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"alertEmail":null,"diskAlertThreshold":0.85}` {
		t.Errorf("get = %d %s", rec.Code, rec.Body)
	}

	st.settings = systemsettings.Settings{DiskAlertThreshold: 0.9, AlertEmail: "it-admin@example.com", AlertEmailLanguage: "fr"}
	upd, err := s.UpdateSystemSettings(ctx, gen.UpdateSystemSettingsRequestObject{Body: settingsPatch(`{"diskAlertThreshold":0.9,"alertEmail":"it-admin@example.com"}`)})
	if err != nil {
		t.Fatal(err)
	}
	rec = visit(t, upd)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"alertEmail":"it-admin@example.com","diskAlertThreshold":0.9}` {
		t.Errorf("update = %d %s", rec.Code, rec.Body)
	}
	patch := st.args["Update"][1].(systemsettings.Patch)
	if patch.Threshold == nil || *patch.Threshold != 0.9 || !patch.Email.Set || patch.Email.Value == nil || *patch.Email.Value != "it-admin@example.com" {
		t.Errorf("patch %+v", patch)
	}
	st.err = &systemsettings.InvalidError{Field: systemsettings.FieldAlertEmail}
	_, err = s.UpdateSystemSettings(ctx, gen.UpdateSystemSettingsRequestObject{Body: settingsPatch(`{"alertEmail":"Bob <b@example.com>"}`)})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Code != fieldInvalidEmail {
		t.Errorf("bad address %+v", p.Errors)
	}
	st.err = errors.New("boom")
	if _, err := s.GetSystemSettings(ctx, gen.GetSystemSettingsRequestObject{}); err == nil || err.Error() != "boom" {
		t.Errorf("get failure: %v", err)
	}
	// Body errors are answered before the service.
	st.recorder = recorder{}
	_, err = s.UpdateSystemSettings(ctx, gen.UpdateSystemSettingsRequestObject{})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Code != fieldRequired {
		t.Errorf("missing body %+v", p.Errors)
	}
	_, err = s.UpdateSystemSettings(ctx, gen.UpdateSystemSettingsRequestObject{Body: settingsPatch(`{"diskAlertThreshold":null}`)})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/diskAlertThreshold" || p.Errors[0].Code != fieldNotNullable {
		t.Errorf("null threshold %+v", p.Errors)
	}
	if len(st.calls) != 0 {
		t.Errorf("service called: %v", st.calls)
	}
}

func TestDecodeSystemSettingsUpdate(t *testing.T) {
	t.Parallel()
	addr := "it@example.com"
	threshold := 0.5
	ok := []struct {
		raw  string
		want systemsettings.Patch
	}{
		{`{}`, systemsettings.Patch{}},
		{`{"alertEmail":null}`, systemsettings.Patch{Email: systemsettings.Field[string]{Set: true}}},
		{`{"alertEmail":"it@example.com"}`, systemsettings.Patch{Email: systemsettings.Field[string]{Set: true, Value: &addr}}},
		{`{"diskAlertThreshold":0.5}`, systemsettings.Patch{Threshold: &threshold}},
	}
	for _, c := range ok {
		got, err := decodeSystemSettingsUpdate([]byte(c.raw))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, %v", c.raw, got, err)
		}
	}
	long := strings.Repeat("x", maxEchoedMemberLen+1)
	bad := []struct {
		raw, field, code string
	}{
		{`[]`, "", fieldInvalidFormat},
		{`null`, "", fieldInvalidFormat},
		{`{`, "", fieldInvalidFormat},
		{`{"zeta":1,"alpha/b":2}`, "/alpha~1b", fieldInvalidFormat},
		{`{"` + long + `":1}`, "", fieldInvalidFormat},
		{`{"diskAlertThreshold": null ,"alertEmail":null}`, "/diskAlertThreshold", fieldNotNullable},
		{`{"diskAlertThreshold":"0.9"}`, "/diskAlertThreshold", fieldInvalidFormat},
		{`{"alertEmail":42}`, "/alertEmail", fieldInvalidFormat},
		{`{"diskAlertThreshold":1e999}`, "/diskAlertThreshold", fieldInvalidFormat},
	}
	for _, c := range bad {
		_, err := decodeSystemSettingsUpdate([]byte(c.raw))
		var p *problem.Problem
		if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) != 1 ||
			p.Errors[0].Field != c.field || p.Errors[0].Code != c.code {
			t.Errorf("%s: %v", c.raw, err)
		}
	}
}

func TestMasterKeyOperations(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	running := keyrotation.Rotation{
		ID: sampleRotation.ID, Status: store.RotationRunning, FromKeyID: "mk_old", ToKeyID: "mk_new", TotalKeys: 10, StartedAt: now,
	}
	r := &fakeRotations{rotation: running, status: keyrotation.MasterKeyStatus{ActiveKeyID: "mk_old"}}
	s := systemServer(nil, nil, r)

	st, err := s.GetMasterKeyStatus(ctx, gen.GetMasterKeyStatusRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	code, body := decode(t, st)
	if code != http.StatusOK || !reflect.DeepEqual(body, map[string]any{"activeKeyId": "mk_old", "restartRequired": false}) {
		t.Errorf("status = %d %v", code, body)
	}
	failed := keyrotation.Rotation{ID: "rot_x", Status: store.RotationFailed, StartedAt: now, CompletedAt: now, Error: "key row 3"}
	r.status = keyrotation.MasterKeyStatus{ActiveKeyID: "mk_old", NewKeyID: "mk_new", RestartRequired: true, LatestRotation: &failed}
	st, _ = s.GetMasterKeyStatus(ctx, gen.GetMasterKeyStatusRequestObject{})
	code, body = decode(t, st)
	latest, _ := body["latestRotation"].(map[string]any)
	if code != http.StatusOK || body["newKeyId"] != "mk_new" || body["restartRequired"] != true ||
		latest["status"] != "failed" || latest["error"] != "key row 3" || latest["completedAt"] == nil {
		t.Errorf("status = %d %v", code, body)
	}

	started, err := s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: totpBody(`{"code":"204816"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if args := r.args["Start"]; args[1] != "204816" || args[2] != "" {
		t.Errorf("start args %v", args)
	}
	code, body = decode(t, started)
	if code != http.StatusAccepted || body["id"] != running.ID || body["status"] != "running" || body["totalKeys"] != float64(10) ||
		body["rewrappedKeys"] != float64(0) || body["completedAt"] != nil || body["error"] != nil {
		t.Errorf("start = %d %v", code, body)
	}
	// A recovery code is passed as such; a missing body as no code, so
	// that the service checks the role and the new key first.
	if _, err := s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: totpBody(`{"recoveryCode":"rc-1"}`)}); err != nil {
		t.Fatal(err)
	}
	if args := r.args["Start"]; args[1] != "" || args[2] != "rc-1" {
		t.Errorf("recovery args %v", args)
	}
	r.err = keyrotation.ErrNoNewKey
	_, err = s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{})
	expectProblem(t, err, problem.CodeNewMasterKeyMissing)
	if args := r.args["Start"]; args[1] != "" || args[2] != "" {
		t.Errorf("no body args %v", args)
	}
	r.err = adminauth.ErrInvalidCredentials
	_, err = s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: totpBody(`{"code":"000000"}`)})
	expectProblem(t, err, problem.CodeInvalidCredentials)

	// An invalid body answers 400 only after the role and the new key are
	// checked (through the status), and never reaches Start.
	invalid := totpBody(`{"code":"204816","cdoe":"1"}`)
	r.recorder = recorder{err: adminauth.ErrForbidden}
	_, err = s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: invalid})
	expectProblem(t, err, problem.CodeForbidden)
	r.recorder = recorder{}
	r.status = keyrotation.MasterKeyStatus{ActiveKeyID: "mk_old"}
	_, err = s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: invalid})
	expectProblem(t, err, problem.CodeNewMasterKeyMissing)
	r.status.NewKeyID = "mk_new"
	_, err = s.StartMasterKeyRotation(ctx, gen.StartMasterKeyRotationRequestObject{Body: invalid})
	if p := expectProblem(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/cdoe" || p.Errors[0].Code != fieldInvalidFormat {
		t.Errorf("unknown member %+v", p.Errors)
	}
	if !reflect.DeepEqual(r.calls, []string{"Status", "Status"}) {
		t.Errorf("invalid body calls %v", r.calls)
	}

	r.err = nil
	r.rotation = sampleRotation
	got, err := s.GetMasterKeyRotation(ctx, gen.GetMasterKeyRotationRequestObject{RotationId: sampleRotation.ID})
	if err != nil {
		t.Fatal(err)
	}
	code, body = decode(t, got)
	if code != http.StatusOK || body["status"] != "completed" || body["completedAt"] != now.Format(time.RFC3339) || r.args["Get"][1] != sampleRotation.ID {
		t.Errorf("get = %d %v", code, body)
	}
	r.err = keyrotation.ErrNotFound
	_, err = s.GetMasterKeyRotation(ctx, gen.GetMasterKeyRotationRequestObject{RotationId: "rot_unknown"})
	expectProblem(t, err, problem.CodeNotFound)
	r.err = errors.New("boom")
	if _, err := s.GetMasterKeyStatus(ctx, gen.GetMasterKeyStatusRequestObject{}); err == nil || err.Error() != "boom" {
		t.Errorf("status failure: %v", err)
	}
}

// TestRotationConflictDetails pins the exact texts of the 409 state-conflict
// details of startMasterKeyRotation. The administration matches them (keep in
// sync with conflictKind in web/src/admin/screens/system/masterKey.ts, which
// looks for "already running", "other keys" and "restart"); changing one is a
// breaking change for that screen and for the OpenAPI examples.
func TestRotationConflictDetails(t *testing.T) {
	cases := map[string]string{
		detailRotationRunning:  "A master key rotation is already running.",
		detailRotationMismatch: "A rotation between other keys is unfinished; finish or abandon it with the command line.",
		detailRestartRequired:  "The last rotation is complete; restart with the new key as TT_MASTER_KEY_FILE before starting another.",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("detail = %q, want %q", got, want)
		}
	}
	for detail, marker := range map[string]string{
		detailRotationRunning:  "already running",
		detailRotationMismatch: "other keys",
		detailRestartRequired:  "restart",
	} {
		if !strings.Contains(strings.ToLower(detail), marker) {
			t.Errorf("detail %q does not contain %q", detail, marker)
		}
	}
}
