package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/strictjson"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// exportA is the configuration answered by the fake ExportConfig.
var exportA = tenantadmin.ConfigExport{
	SchemaVersion: 1, ExportedAt: now, SourceVersion: "2.0.0",
	Network: &tenantadmin.ExportedNetwork{InternalCIDRs: []string{"10.10.0.0/16"}, InternalDomains: []string{"entity-a.example.com"}},
}

func (f *fakeTenantService) ExportConfig(_ context.Context, p adminauth.Principal, tid tenant.ID, includeBranding bool, ip netip.Addr) (tenantadmin.ConfigExport, error) {
	return exportA, f.record("ExportConfig", p.SessionID, tid, includeBranding, ip)
}

func (f *fakeTenantService) ImportTenant(_ context.Context, p adminauth.Principal, in tenantadmin.ImportInput, ip netip.Addr) (tenantadmin.TenantCreated, error) {
	v := viewA
	v.SetupState = tenant.SetupStateSetup
	return tenantadmin.TenantCreated{TenantView: v, DelegatedAdmin: f.invited}, f.record("ImportTenant", p.SessionID, in, ip)
}

// auditorA is an auditor of tenant A.
var auditorA = adminauth.Account{ID: "adm_audit", Username: "audrey", Role: store.RoleAuditor, TenantIDs: []tenant.ID{"ten_a"}}

// validImport is a minimal valid import body.
const validImport = `{"name":"Entity C","fqdn":"transfer.entity-c.example.com","storageQuotaBytes":1099511627776,` +
	`"config":{"schemaVersion":1,"exportedAt":"2026-11-04T10:00:00Z","sourceVersion":"2.0.0",` +
	`"network":{"internalCidrs":["10.30.0.0/16","10.31.0.0/16"],"internalDomains":["entity-c.example.com"]}}}`

// importCtx returns ctx with raw kept as by CaptureRawBody.
func importCtx(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, rawBodyKey{}, []byte(raw))
}

// importReq is the request object the generated handler would build.
func importReq() gen.ImportTenantRequestObject {
	return gen.ImportTenantRequestObject{Body: &gen.TenantImport{}}
}

func TestExportTenantConfig(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	svc := &fakeTenantService{}
	yes := true
	resp, err := tenantServer(svc).ExportTenantConfig(super, gen.ExportTenantConfigRequestObject{
		TenantId: "ten_a", Params: gen.ExportTenantConfigParams{IncludeBranding: &yes},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.args["ExportConfig"]; got[1] != tenant.ID("ten_a") || got[2] != true || got[3] != clientIP {
		t.Errorf("service args = %v", got)
	}
	rec := visit(t, resp)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	h := rec.Header()
	if got := h.Get("Content-Disposition"); got != `attachment; filename="tenant-transfer.entity-a.example.com-config.json"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if h.Get("Cache-Control") != "no-store" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", h)
	}
	var back tenantadmin.ConfigExport
	if err := json.Unmarshal(rec.Body.Bytes(), &back); err != nil || !reflect.DeepEqual(back, exportA) {
		t.Errorf("body = %s (%v)", rec.Body, err)
	}

	// Without the parameter, no branding.
	svc = &fakeTenantService{}
	if _, err := tenantServer(svc).ExportTenantConfig(super, gen.ExportTenantConfigRequestObject{TenantId: "ten_a"}); err != nil {
		t.Fatal(err)
	}
	if svc.args["ExportConfig"][2] != false {
		t.Errorf("includeBranding default = %v", svc.args["ExportConfig"][2])
	}

	// The errors of the service: auditor, out of scope, failing name lookup.
	for name, tc := range map[string]struct {
		ctx   context.Context
		err   error
		errAt string
		code  problem.Code
	}{
		"auditor":         {ctxWith(store.SessionAuthenticated, auditorA), adminauth.ErrReadOnlyRole, "", problem.CodeReadOnlyRole},
		"out of scope":    {ctxWith(store.SessionAuthenticated, delegated), tenantadmin.ErrNotFound, "", problem.CodeNotFound},
		"unauthenticated": {ctxWith(store.SessionTOTPRequired, superRoot), tenantadmin.ErrUnauthenticated, "", problem.CodeUnauthenticated},
		"name lookup":     {super, tenantadmin.ErrNotFound, "GetTenant", problem.CodeNotFound},
	} {
		svc := &fakeTenantService{err: tc.err, errAt: tc.errAt}
		_, err := tenantServer(svc).ExportTenantConfig(tc.ctx, gen.ExportTenantConfigRequestObject{TenantId: "ten_b"})
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		expectProblem(t, err, tc.code)
	}
	// Without service or session.
	if _, err := NewServer().ExportTenantConfig(super, gen.ExportTenantConfigRequestObject{TenantId: "ten_a"}); !errors.Is(err, errNoTenantService) {
		t.Errorf("without service: %v", err)
	}
	_, err = tenantServer(&fakeTenantService{}).ExportTenantConfig(context.Background(), gen.ExportTenantConfigRequestObject{TenantId: "ten_a"})
	expectProblem(t, err, problem.CodeUnauthenticated)
}

func TestExportFileName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"transfer.entity-a.example.com": "tenant-transfer.entity-a.example.com-config.json",
		`a"b\c d/é`:                     "tenant-a_b_c_d__-config.json",
	} {
		if got := exportFileName(in); got != want {
			t.Errorf("exportFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigExportResponseEncodeError(t *testing.T) {
	t.Parallel()
	bad := configExportResponse{body: tenantadmin.ConfigExport{AbuseThresholds: &tenantadmin.ExportedAbuseThresholds{
		UnusualVolumeFactor: ptr(math.NaN()),
	}}}
	if err := bad.VisitExportTenantConfigResponse(httptest.NewRecorder()); err == nil {
		t.Error("a NaN was encoded")
	}
}

func TestImportTenant(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	svc := &fakeTenantService{}
	resp, err := tenantServer(svc).ImportTenant(importCtx(super, validImport), importReq())
	if err != nil {
		t.Fatal(err)
	}
	body, ok := resp.(gen.ImportTenant201JSONResponse)
	if !ok || body.SetupState == nil || *body.SetupState != gen.TenantSetupState(tenant.SetupStateSetup) {
		t.Fatalf("response %#v", resp)
	}
	in := svc.args["ImportTenant"][1].(tenantadmin.ImportInput)
	if in.Name != "Entity C" || in.FQDN != "transfer.entity-c.example.com" || in.StorageQuotaBytes != 1<<40 ||
		in.Config.SchemaVersion != 1 || in.Config.SourceVersion != "2.0.0" || in.DelegatedAdmin != nil ||
		in.Config.Network == nil || len(in.Config.Network.InternalCIDRs) != 2 {
		t.Errorf("service input = %+v", in)
	}
	if svc.args["ImportTenant"][2] != clientIP {
		t.Errorf("ip = %v", svc.args["ImportTenant"][2])
	}

	// With a first delegated admin, mail delivery.
	svc = &fakeTenantService{}
	withAdmin := strings.Replace(validImport, `"config"`,
		`"delegatedAdmin":{"username":"admin.c","email":"admin@entity-c.example.com","language":"fr","delivery":"mail"},"config"`, 1)
	if _, err := tenantServer(svc).ImportTenant(importCtx(super, withAdmin), importReq()); err != nil {
		t.Fatal(err)
	}
	d := svc.args["ImportTenant"][1].(tenantadmin.ImportInput).DelegatedAdmin
	if d == nil || d.Username != "admin.c" || d.Email != "admin@entity-c.example.com" || d.Language != "fr" || d.Delivery != store.ActivationDelivery("mail") {
		t.Errorf("delegated admin = %+v", d)
	}
	// Without delivery: the default of the service.
	svc = &fakeTenantService{}
	noDelivery := strings.Replace(withAdmin, `,"delivery":"mail"`, "", 1)
	if _, err := tenantServer(svc).ImportTenant(importCtx(super, noDelivery), importReq()); err != nil {
		t.Fatal(err)
	}
	if d := svc.args["ImportTenant"][1].(tenantadmin.ImportInput).DelegatedAdmin; d == nil || d.Delivery != "" {
		t.Errorf("delegated admin without delivery = %+v", d)
	}
}

// TestImportTenantAccess checks the role is checked before the body: a
// refused admin learns nothing of the document, and the service is never
// reached.
func TestImportTenantAccess(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		ctx  context.Context
		code problem.Code
	}{
		"delegated admin": {ctxWith(store.SessionAuthenticated, delegated), problem.CodeForbidden},
		"auditor":         {ctxWith(store.SessionAuthenticated, auditorA), problem.CodeForbidden},
		"pending totp":    {ctxWith(store.SessionTOTPRequired, superRoot), problem.CodeUnauthenticated},
		"no session":      {context.Background(), problem.CodeUnauthenticated},
	} {
		for _, raw := range []string{validImport, `{"config":{"schemaVersion":2}}`, `{"x":1}`} {
			svc := &fakeTenantService{}
			_, err := tenantServer(svc).ImportTenant(importCtx(tc.ctx, raw), importReq())
			if err == nil {
				t.Fatalf("%s: no error", name)
			}
			expectProblem(t, err, tc.code)
			if len(svc.calls) != 0 {
				t.Errorf("%s: the service was called: %v", name, svc.calls)
			}
		}
	}
	super := ctxWith(store.SessionAuthenticated, superRoot)
	if _, err := NewServer().ImportTenant(importCtx(super, validImport), importReq()); !errors.Is(err, errNoTenantService) {
		t.Errorf("without service: %v", err)
	}
	if _, err := tenantServer(&fakeTenantService{}).ImportTenant(super, importReq()); !errors.Is(err, errNoImportBody) {
		t.Errorf("without raw body: %v", err)
	}
}

// TestImportTenantStrict checks the refusals of the document before the
// service: 422 import-invalid at the pointer of the first problem, never
// the value, or 422 import-schema-unsupported.
func TestImportTenantStrict(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	deep := `{"unknown":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `,"name":"x","config":{"schemaVersion":1}}`
	withConfig := func(section string) string {
		return strings.Replace(validImport, `"network"`, section+`,"network"`, 1)
	}
	abuse := `"abuseThresholds":{"maxDailyBytesPerSender":null,"maxDailyTransfersPerSender":null,` +
		`"maxRecipientsPerTransfer":null,"blockOnExceed":false,"unusualVolumeFactor":null,"unusualMinHistoryDays":7,` +
		`"largeExternalTransferBytes":null,"timeZone":"UTC","officeHours":null,"maxInvitationsPerInviter":20,` +
		`"externalMaxDailyBytes":null}`
	blocklist := `"blocklist":[` + strings.TrimSuffix(strings.Repeat(`{"kind":"email","value":"a@example.com"},`, tenantadmin.MaxImportBlocklistEntries+1), ",") + `]`
	longName := strings.Repeat("member", 20)
	for name, tc := range map[string]struct {
		raw          string
		code         problem.Code
		field, fcode string
	}{
		"duplicate key": {
			strings.Replace(validImport, `"name":"Entity C"`, `"name":"Entity C","name":"Other"`, 1),
			problem.CodeImportInvalid, "/name", "duplicate",
		},
		"duplicate nested": {
			strings.Replace(validImport, `"sourceVersion":"2.0.0"`, `"sourceVersion":"2.0.0","sourceVersion":"x"`, 1),
			problem.CodeImportInvalid, "/config/sourceVersion", "duplicate",
		},
		"unknown member": {
			strings.Replace(validImport, `"internalDomains"`, `"secret":"s3cr3t","internalDomains"`, 1),
			problem.CodeImportInvalid, "/config/network/secret", "unknown-member",
		},
		"unknown smtp password": {
			strings.Replace(validImport, `"network"`, `"smtp":{"host":"h","port":25,"security":"none","fromAddress":"a@b.example","password":"p"},"network"`, 1),
			problem.CodeImportInvalid, "/config/smtp/password", "unknown-member",
		},
		"case variant": {
			strings.Replace(validImport, `"name"`, `"Name"`, 1),
			problem.CodeImportInvalid, "/Name", "unknown-member",
		},
		"object for array": {
			strings.Replace(validImport, `"internalCidrs":["10.30.0.0/16","10.31.0.0/16"]`, `"internalCidrs":{}`, 1),
			problem.CodeImportInvalid, "/config/network/internalCidrs", "type",
		},
		"null section": {
			strings.Replace(validImport, `"network":{`, `"settings":null,"network":{`, 1),
			problem.CodeImportInvalid, "/config/settings", "type",
		},
		"deep nesting":     {deep, problem.CodeImportInvalid, "/unknown", "unknown-member"},
		"string number":    {strings.Replace(validImport, `1099511627776`, `"1"`, 1), problem.CodeImportInvalid, "/storageQuotaBytes", "type"},
		"nested type":      {strings.Replace(validImport, `"sourceVersion":"2.0.0"`, `"sourceVersion":2`, 1), problem.CodeImportInvalid, "/config/sourceVersion", "type"},
		"trailing data":    {validImport + `{}`, problem.CodeImportInvalid, "", "syntax"},
		"no config":        {`{"name":"x"}`, problem.CodeImportInvalid, "/config", "required"},
		"no version":       {`{"config":{"exportedAt":"2026-11-04T10:00:00Z"}}`, problem.CodeImportInvalid, "/config/schemaVersion", "required"},
		"null version":     {`{"config":{"schemaVersion":null}}`, problem.CodeImportInvalid, "/config/schemaVersion", "required"},
		"schema 2":         {strings.Replace(validImport, `"schemaVersion":1`, `"schemaVersion":2`, 1), problem.CodeImportSchemaUnsupported, "", ""},
		"schema 2 unknown": {`{"config":{"schemaVersion":2,"newSection":{"a":[1]}},"newTop":true}`, problem.CodeImportSchemaUnsupported, "", ""},
		"schema 0":         {`{"config":{"schemaVersion":0}}`, problem.CodeImportSchemaUnsupported, "", ""},
		"schema string":    {`{"config":{"schemaVersion":"one"}}`, problem.CodeImportInvalid, "/config/schemaVersion", "type"},
		"schema quoted 1":  {`{"config":{"schemaVersion":"1"}}`, problem.CodeImportInvalid, "/config/schemaVersion", "type"},
		"schema boolean":   {`{"config":{"schemaVersion":true}}`, problem.CodeImportInvalid, "/config/schemaVersion", "type"},
		"schema fraction":  {`{"config":{"schemaVersion":1.0}}`, problem.CodeImportInvalid, "/config/schemaVersion", "type"},
		"schema exponent":  {`{"config":{"schemaVersion":1e0}}`, problem.CodeImportInvalid, "/config/schemaVersion", "type"},
		"schema object":    {`{"config":{"schemaVersion":{}}}`, problem.CodeImportInvalid, "/config/schemaVersion", "type"},
		"schema minus":     {`{"config":{"schemaVersion":-1}}`, problem.CodeImportSchemaUnsupported, "", ""},
		"schema huge":      {`{"config":{"schemaVersion":123456789012345678901234567890}}`, problem.CodeImportSchemaUnsupported, "", ""},
		"abuse member missing": {
			withConfig(abuse), problem.CodeImportInvalid, "/config/abuseThresholds/externalMaxDailyDeposits", "required",
		},
		"office hours member missing": {
			withConfig(strings.Replace(abuse, `"officeHours":null`, `"officeHours":{"start":"08:00","end":"18:00"}`, 1)),
			problem.CodeImportInvalid, "/config/abuseThresholds/officeHours/weekdays", "required",
		},
		"too many blocklist entries": {withConfig(blocklist), problem.CodeImportInvalid, "/config/blocklist", "too-many"},
		"too many weekdays": {
			withConfig(strings.Replace(abuse, `"officeHours":null`, `"officeHours":{"start":"08:00","end":"18:00","weekdays":[1,2,3,4,5,6,7,1]}`, 1)),
			problem.CodeImportInvalid, "/config/abuseThresholds/officeHours/weekdays", "too-many",
		},
		"long member name": {
			withConfig(`"` + longName + `":1`), problem.CodeImportInvalid,
			"/config/" + longName[:strictjson.MaxPointerSegment] + "…", "unknown-member",
		},
		"delivery none": {
			strings.Replace(validImport, `"config"`,
				`"delegatedAdmin":{"username":"a","email":"a@entity-c.example.com","language":"fr","delivery":"none"},"config"`, 1),
			problem.CodeValidationFailed, "/delegatedAdmin/delivery", "not-supported",
		},
	} {
		svc := &fakeTenantService{}
		_, err := tenantServer(svc).ImportTenant(importCtx(super, tc.raw), importReq())
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		p := expectProblem(t, err, tc.code)
		if tc.field != "" || tc.fcode != "" {
			if len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != tc.fcode {
				t.Errorf("%s: errors %+v, want %s %s", name, p.Errors, tc.field, tc.fcode)
			}
		}
		if out, _ := json.Marshal(p); strings.Contains(string(out), "s3cr3t") || strings.Contains(string(out), "Other") {
			t.Errorf("%s: the problem quotes a value: %s", name, out)
		}
		if len(svc.calls) != 0 {
			t.Errorf("%s: the service was called: %v", name, svc.calls)
		}
	}
	// Valid JSON that is not an object: refused by the strict check.
	for _, raw := range []string{`[]`, `"x"`, `null`, `{`} {
		_, err := tenantServer(&fakeTenantService{}).ImportTenant(importCtx(super, raw), importReq())
		p := expectProblem(t, err, problem.CodeImportInvalid)
		if len(p.Errors) != 1 || p.Errors[0].Field != "" {
			t.Errorf("%s: errors %+v", raw, p.Errors)
		}
	}
}

// TestImportTenantErrors checks the mapping of the errors of the service
// to the answers importTenant declares.
func TestImportTenantErrors(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	server := errors.New("database down")
	for name, tc := range map[string]struct {
		err          error
		code         problem.Code
		field, fcode string
	}{
		"bad cidr": {
			&tenantadmin.ImportError{Pointer: "/config/network/internalCidrs/1", Reason: `netip.ParsePrefix("x")`},
			problem.CodeImportInvalid, "/config/network/internalCidrs/1", "invalid-value",
		},
		"coded": {
			&tenantadmin.ImportError{Pointer: "/config/smtp/fromAddress", Reason: "r", Code: "some-code"},
			problem.CodeImportInvalid, "/config/smtp/fromAddress", "some-code",
		},
		"admin host": {
			&tenantadmin.ImportError{Pointer: "/fqdn", Reason: "r", Code: tenantadmin.CodeAdminHost},
			problem.CodeValidationFailed, "/fqdn", "reserved-host",
		},
		"bare invalid":     {tenantadmin.ErrImportInvalid, problem.CodeImportInvalid, "", "invalid-value"},
		"schema":           {tenantadmin.ErrImportSchemaUnsupported, problem.CodeImportSchemaUnsupported, "", ""},
		"fqdn used":        {tenantadmin.ErrAlreadyExists, problem.CodeAlreadyExists, "", ""},
		"username used":    {fmt.Errorf("x: %w", adminauth.ErrAlreadyExists), problem.CodeAlreadyExists, "", ""},
		"admin email":      {&adminauth.InvalidError{Field: adminauth.FieldEmail}, problem.CodeValidationFailed, "/delegatedAdmin" + adminauth.FieldEmail, "invalid-email"},
		"no system smtp":   {adminauth.ErrSystemSMTPUnavailable, problem.CodeSystemSMTPUnavailable, "", ""},
		"tenant invalid":   {&tenantadmin.InvalidError{Field: "/name", Reason: "r"}, problem.CodeValidationFailed, "/name", "invalid-format"},
		"auth invalid":     {adminauth.ErrInvalid, problem.CodeValidationFailed, "", ""},
		"invalid":          {tenantadmin.ErrInvalid, problem.CodeValidationFailed, "", ""},
		"unauthenticated":  {tenantadmin.ErrUnauthenticated, problem.CodeUnauthenticated, "", ""},
		"auth unauthent.":  {adminauth.ErrUnauthenticated, problem.CodeUnauthenticated, "", ""},
		"forbidden":        {adminauth.ErrForbidden, problem.CodeForbidden, "", ""},
		"tenant forbidden": {tenantadmin.ErrForbidden, problem.CodeForbidden, "", ""},
	} {
		svc := &fakeTenantService{err: tc.err}
		_, err := tenantServer(svc).ImportTenant(importCtx(super, validImport), importReq())
		p := expectProblem(t, err, tc.code)
		if tc.field != "" || tc.fcode != "" {
			if len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != tc.fcode {
				t.Errorf("%s: errors %+v, want %s %s", name, p.Errors, tc.field, tc.fcode)
			}
		}
		if p.Detail != "" || strings.Contains(fmt.Sprint(p), "ParsePrefix") {
			t.Errorf("%s: the problem carries the reason: %+v", name, p)
		}
	}
	svc := &fakeTenantService{err: server}
	if _, err := tenantServer(svc).ImportTenant(importCtx(super, validImport), importReq()); !errors.Is(err, server) {
		t.Errorf("server error: %v", err)
	}
}

func TestDecodePointer(t *testing.T) {
	t.Parallel()
	if got := decodePointer(errors.New("x")); got != "" {
		t.Errorf("non type error: %q", got)
	}
	if got := decodePointer(&json.UnmarshalTypeError{Field: "config.network"}); got != "/config/network" {
		t.Errorf("type error: %q", got)
	}
}

// --- The whitelist tree against the specification ------------------------------

// specDoc is api/openapi.yaml as generic YAML.
func loadSpec(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// specNode is a schema of the specification reduced to what the
// whitelist tree describes.
type specNode struct {
	kind     strictjson.Kind
	nullable bool
	members  map[string]map[string]any // object: member schemas
	required []string                  // object: required members, sorted
	item     map[string]any            // array: item schema
	maxItems int                       // array: maxItems, -1 when none
}

// resolve follows a local $ref.
func resolve(t *testing.T, doc, s map[string]any) map[string]any {
	t.Helper()
	for {
		ref, ok := s["$ref"].(string)
		if !ok {
			return s
		}
		node := any(doc)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			node = node.(map[string]any)[part]
		}
		s = node.(map[string]any)
	}
}

// reduce reduces the schema s (after $ref, oneOf with null and type lists).
func reduce(t *testing.T, doc, s map[string]any) specNode {
	t.Helper()
	s = resolve(t, doc, s)
	var n specNode
	if alts, ok := s["oneOf"].([]any); ok {
		var rest []map[string]any
		for _, a := range alts {
			a := resolve(t, doc, a.(map[string]any))
			if a["type"] == "null" {
				n.nullable = true
				continue
			}
			rest = append(rest, a)
		}
		if len(rest) != 1 {
			t.Fatalf("oneOf with %d non-null alternatives", len(rest))
		}
		inner := reduce(t, doc, rest[0])
		inner.nullable = inner.nullable || n.nullable
		return inner
	}
	typ := ""
	switch v := s["type"].(type) {
	case string:
		typ = v
	case []any:
		for _, x := range v {
			if x == "null" {
				n.nullable = true
			} else {
				typ = x.(string)
			}
		}
	}
	if typ == "" && s["properties"] != nil {
		typ = "object"
	}
	switch typ {
	case "object":
		n.kind = strictjson.KindObject
		n.members = map[string]map[string]any{}
		n.required = []string{}
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				n.required = append(n.required, r.(string))
			}
			sort.Strings(n.required)
		}
		if props, ok := s["properties"].(map[string]any); ok {
			for name, child := range props {
				n.members[name] = child.(map[string]any)
			}
		} else if add, ok := s["additionalProperties"].(map[string]any); ok {
			// A map: its keys are the enum of propertyNames.
			names := resolve(t, doc, s["propertyNames"].(map[string]any))
			for _, k := range names["enum"].([]any) {
				n.members[k.(string)] = add
			}
		}
	case "array":
		n.kind = strictjson.KindArray
		n.item = s["items"].(map[string]any)
		n.maxItems = -1
		if m, ok := s["maxItems"]; ok {
			n.maxItems = toInt(t, m)
		}
	default:
		n.kind = strictjson.KindScalar
	}
	return n
}

// compareTree checks that got describes the schema s at path.
func compareTree(t *testing.T, doc map[string]any, path string, s map[string]any, got *strictjson.Schema) {
	t.Helper()
	want := reduce(t, doc, s)
	if got.Kind() != want.kind {
		t.Errorf("%s: kind %v, spec %v", path, got.Kind(), want.kind)
		return
	}
	if want.kind != strictjson.KindScalar && got.Nullable() != want.nullable {
		t.Errorf("%s: nullable %v, spec %v", path, got.Nullable(), want.nullable)
	}
	switch want.kind {
	case strictjson.KindObject:
		names := make([]string, 0, len(want.members))
		for name := range want.members {
			names = append(names, name)
		}
		sort.Strings(names)
		if !reflect.DeepEqual(got.MemberNames(), names) {
			t.Errorf("%s: members %v, spec %v", path, got.MemberNames(), names)
			return
		}
		if !reflect.DeepEqual(got.Required(), want.required) {
			t.Errorf("%s: required %v, spec %v", path, got.Required(), want.required)
		}
		for _, name := range names {
			child, _ := got.Member(name)
			compareTree(t, doc, path+"/"+name, want.members[name], child)
		}
	case strictjson.KindArray:
		// Every array of an import is bounded, by the same limit as the
		// spec, so that no typed decode allocates an unbounded array.
		n, ok := got.MaxItems()
		switch {
		case !ok || want.maxItems < 0:
			t.Errorf("%s: unbounded array (tree limit %v, spec maxItems %d)", path, ok, want.maxItems)
		case n != want.maxItems:
			t.Errorf("%s: maxItems %d, spec %d", path, n, want.maxItems)
		}
		compareTree(t, doc, path+"/0", want.item, got.Item())
	}
}

// toInt converts a YAML number to an int.
func toInt(t *testing.T, v any) int {
	t.Helper()
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	}
	t.Fatalf("maxItems %v (%T) is not a number", v, v)
	return 0
}

// TestImportSchemaMatchesSpec checks that the whitelist tree of an import
// is exactly the OpenAPI TenantImport, recursively: the same members, the
// same required members, the same objects and arrays, the same nullable
// ones, the same array limits (every array having one).
func TestImportSchemaMatchesSpec(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	compareTree(t, doc, "", map[string]any{"$ref": "#/components/schemas/TenantImport"}, importSchema)
	// The language maps follow the languages of the interface.
	lang := resolve(t, doc, map[string]any{"$ref": "#/components/schemas/Language"})
	var langs []string
	for _, l := range lang["enum"].([]any) {
		langs = append(langs, l.(string))
	}
	sort.Strings(langs)
	if !reflect.DeepEqual(langs, tenant.Languages()) {
		t.Errorf("spec languages %v, interface %v", langs, tenant.Languages())
	}
}

// TestImportSchemaDecodes checks that every member of the whitelist tree
// is decoded by importBody: a member the tree allows but the decoder would
// refuse (DisallowUnknownFields) or ignore would be a drift.
func TestImportSchemaDecodes(t *testing.T) {
	t.Parallel()
	var walk func(path []string, s *strictjson.Schema, typ reflect.Type)
	walk = func(path []string, s *strictjson.Schema, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		switch s.Kind() {
		case strictjson.KindObject:
			if typ.Kind() == reflect.Map {
				for _, name := range s.MemberNames() {
					child, _ := s.Member(name)
					walk(append(path, name), child, typ.Elem())
				}
				return
			}
			if typ.Kind() != reflect.Struct {
				t.Errorf("%v: object decoded into %v", path, typ)
				return
			}
			fields := map[string]reflect.Type{}
			for i := range typ.NumField() {
				f := typ.Field(i)
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				fields[name] = f.Type
			}
			for _, name := range s.MemberNames() {
				ft, ok := fields[name]
				if !ok {
					t.Errorf("%v: member %q not decoded", path, name)
					continue
				}
				child, _ := s.Member(name)
				walk(append(path, name), child, ft)
			}
			if len(fields) != len(s.MemberNames()) {
				t.Errorf("%v: %d fields, %d members", path, len(fields), len(s.MemberNames()))
			}
		case strictjson.KindArray:
			if typ.Kind() != reflect.Slice {
				t.Errorf("%v: array decoded into %v", path, typ)
				return
			}
			walk(append(path, "0"), s.Item(), typ.Elem())
		default:
			if k := typ.Kind(); k == reflect.Struct && typ != reflect.TypeOf(time.Time{}) || k == reflect.Slice || k == reflect.Map {
				t.Errorf("%v: scalar decoded into %v", path, typ)
			}
		}
	}
	walk(nil, importSchema, reflect.TypeOf(importBody{}))
}

func TestIsJSONInteger(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{"1": true, "-12": true, "0": true, "": false, "-": false, "1.0": false, "1e0": false, `"1"`: false, "true": false} {
		if got := isJSONInteger([]byte(v)); got != want {
			t.Errorf("isJSONInteger(%q) = %v", v, got)
		}
	}
}
