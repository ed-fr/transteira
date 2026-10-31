package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

// setupDecision is what a tenant still being configured gets for an
// operation of the OpenAPI document.
type setupDecision int

const (
	// setupOutsideTenant: served outside any tenant (before the tenant
	// resolution), whatever its state.
	setupOutsideTenant setupDecision = iota + 1
	// setupAdminHost: served on the admin hosts only (administration,
	// provisioning), which no tenant state affects (T-263); 404 on a
	// tenant host.
	setupAdminHost
	// setupServed: in the closed allowlist, served as usual.
	setupServed
	// setupRefused: refused with 503 tenant-in-setup.
	setupRefused
	// setupRefusedTus: refused with a bodyless 503 (tus operations).
	setupRefusedTus
)

// setupDecisions classifies every operation of the specification that is
// not an administration or provisioning operation (those are setupAdminHost
// by their path). A new public operation must be added here, or the test
// fails: the middleware refuses it by default, and the classification makes
// the choice explicit (T-260).
var setupDecisions = map[string]setupDecision{
	"getHealth":      setupOutsideTenant,
	"getMetrics":     setupOutsideTenant,
	"getStatus":      setupOutsideTenant,
	"askTls":         setupOutsideTenant,
	"getOpenApiSpec": setupOutsideTenant,

	"getVersion":             setupServed,
	"getPublicTenant":        setupServed,
	"getTenantAsset":         setupServed,
	"getTenantLegalDocument": setupServed,

	"startDepositSession":          setupRefused,
	"confirmVerificationChallenge": setupRefused,
	"getCurrentDepositSession":     setupRefused,
	"endDepositSession":            setupRefused,
	"createTransfer":               setupRefused,
	"getTransfer":                  setupRefused,
	"cancelTransfer":               setupRefused,
	"finalizeTransfer":             setupRefused,
	"createInvitation":             setupRefused,
	"getInvitation":                setupRefused,
	"getDownload":                  setupRefused,
	"unlockDownload":               setupRefused,
	"downloadFile":                 setupRefused,
	"downloadArchive":              setupRefused,
	"startRecipientVerification":   setupRefused,
	"confirmRecipientVerification": setupRefused,
	"reportAbuse":                  setupRefused,
	"startTransferReply":           setupRefused,
	"requestMyTransfersLink":       setupRefused,
	"startMyTransfersSession":      setupRefused,
	"getCurrentMyTransfersSession": setupRefused,
	"endMyTransfersSession":        setupRefused,
	"listMyTransfers":              setupRefused,
	"getMyTransfer":                setupRefused,
	"deleteMyTransfer":             setupRefused,
	"extendMyTransfer":             setupRefused,

	"getTusCapabilities": setupRefusedTus,
	"getUploadOffset":    setupRefusedTus,
	"appendUploadChunk":  setupRefusedTus,
	"terminateUpload":    setupRefusedTus,
}

// setupOperation is an operation of the specification.
type setupOperation struct {
	id, method, path string
}

// specOperations parses api/openapi.yaml into its operations, with their
// full path (server URL of the document, of the path or of the operation).
func setupSpecOperations(t *testing.T) []setupOperation {
	t.Helper()
	type server struct {
		URL string `yaml:"url"`
	}
	type op struct {
		OperationID string   `yaml:"operationId"`
		Servers     []server `yaml:"servers"`
	}
	var doc struct {
		Servers []server                  `yaml:"servers"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPISpec, &doc); err != nil {
		t.Fatal(err)
	}
	var out []setupOperation
	for path, item := range doc.Paths {
		base := doc.Servers[0].URL
		raw, _ := yaml.Marshal(item)
		var pathServers struct {
			Servers []server `yaml:"servers"`
		}
		if err := yaml.Unmarshal(raw, &pathServers); err != nil {
			t.Fatal(err)
		}
		if len(pathServers.Servers) > 0 {
			base = pathServers.Servers[0].URL
		}
		for _, m := range []string{"get", "put", "post", "delete", "options", "head", "patch"} {
			v, ok := item[m]
			if !ok {
				continue
			}
			raw, _ := yaml.Marshal(v)
			var o op
			if err := yaml.Unmarshal(raw, &o); err != nil {
				t.Fatal(err)
			}
			b := base
			if len(o.Servers) > 0 {
				b = o.Servers[0].URL
			}
			out = append(out, setupOperation{id: o.OperationID, method: strings.ToUpper(m), path: strings.TrimSuffix(b, "/") + path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	if len(out) == 0 {
		t.Fatal("no operation in api/openapi.yaml")
	}
	return out
}

// stateResolver serves hostA with the setup state state.
type stateResolver struct{ state tenant.SetupState }

func (s stateResolver) Resolve(_ context.Context, host string) (*tenant.Tenant, error) {
	if host == hostA {
		return &tenant.Tenant{ID: "ten_a", FQDN: hostA, DefaultLanguage: "en", SetupState: s.state}, nil
	}
	return nil, tenant.ErrUnknownTenant
}

// pathParam matches a path template parameter.
var pathParam = regexp.MustCompile(`\{[A-Za-z]+\}`)

// sendOperation sends op to hostA with the headers every operation may
// require (tus version and offset) and a malformed JSON body: a refusal
// must come before the body is read.
func sendOperation(t *testing.T, e *env, op setupOperation) (int, http.Header, string) {
	t.Helper()
	ct := "application/json"
	if op.id == "appendUploadChunk" {
		ct = tusContentType
	}
	var body *strings.Reader
	if op.method != http.MethodGet && op.method != http.MethodHead && op.method != http.MethodOptions {
		body = strings.NewReader("{")
	} else {
		body = strings.NewReader("")
	}
	rec := e.do(t, op.method, pathParam.ReplaceAllString(op.path, "x"), hostA, body,
		"Content-Type", ct, "Tus-Resumable", "1.0.0", "Upload-Offset", "0")
	return rec.Code, rec.Header(), rec.Body.String()
}

// Every operation of the specification is classified, and a tenant in
// setup gets exactly that decision (T-260).
func TestSetupEveryOperationClassified(t *testing.T) {
	t.Parallel()
	ops := setupSpecOperations(t)
	known := map[string]bool{}
	for _, op := range ops {
		known[op.id] = true
	}
	for id := range setupDecisions {
		if !known[id] {
			t.Errorf("setupDecisions has a stale entry %q", id)
		}
	}
	e := newEnv(t, envConfig{
		resolver: stateResolver{state: tenant.SetupStateSetup},
		opts:     []Option{WithGlobalLimiter(&budgetLimiter{n: 1 << 30})},
	})
	for _, op := range ops {
		decision, ok := setupDecisions[op.id]
		if strings.HasPrefix(op.path, APIBaseURL+"/admin/") || strings.HasPrefix(op.path, APIBaseURL+"/provisioning/") {
			if ok {
				t.Errorf("%s: an admin host operation is classified", op.id)
			}
			decision = setupAdminHost
		} else if !ok {
			t.Errorf("operation %s (%s %s) is not classified for a tenant in setup: add it to setupDecisions", op.id, op.method, op.path)
			continue
		}
		status, h, body := sendOperation(t, e, op)
		inSetup := status == http.StatusServiceUnavailable
		switch decision {
		case setupRefused:
			if !inSetup || !strings.Contains(body, `"code":"tenant-in-setup"`) || h.Get("Retry-After") != "" {
				t.Errorf("%s: %d %v %s, want 503 tenant-in-setup without Retry-After", op.id, status, h, body)
			}
		case setupRefusedTus:
			if !inSetup || body != "" || h.Get("Tus-Resumable") != tusVersion || h.Get("Retry-After") != "" {
				t.Errorf("%s: %d %v %q, want a bodyless tus 503", op.id, status, h, body)
			}
		case setupServed, setupOutsideTenant:
			if inSetup || strings.Contains(body, "tenant-in-setup") {
				t.Errorf("%s: %d %s, want it served", op.id, status, body)
			}
		case setupAdminHost:
			if status != http.StatusNotFound || strings.Contains(body, "tenant-in-setup") {
				t.Errorf("%s on a tenant host: %d %s, want 404", op.id, status, body)
			}
		}
	}
}

// Every pattern of the allowlist is a route of the API router, served to an
// active tenant as to a tenant in setup.
func TestSetupAllowlistRoutes(t *testing.T) {
	t.Parallel()
	ops := setupSpecOperations(t)
	byPattern := map[string]string{}
	for _, op := range ops {
		byPattern[op.method+" "+op.path] = op.id
	}
	for pattern := range setupAllowed {
		id, ok := byPattern[pattern]
		if !ok || setupDecisions[id] != setupServed {
			t.Errorf("allowlist pattern %q is not a served operation (%q)", pattern, id)
		}
	}
	if n := len(setupAllowed); n != 4 {
		t.Errorf("%d allowed patterns: the allowlist is closed, review any change (T-260)", n)
	}
}

// An active tenant reaches the operations; a tenant without a known state
// is refused (fail closed).
func TestSetupStates(t *testing.T) {
	t.Parallel()
	active := newEnv(t, envConfig{resolver: stateResolver{state: tenant.SetupStateActive}})
	rec := active.do(t, http.MethodPost, "/api/v1/transfers", hostA, strings.NewReader(`{}`), "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)

	for _, state := range []tenant.SetupState{"", "suspended"} {
		e := newEnv(t, envConfig{resolver: stateResolver{state: state}})
		rec := e.do(t, http.MethodPost, "/api/v1/transfers", hostA, strings.NewReader(`{}`), "Content-Type", "application/json")
		decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeTenantInSetup)
	}
}

// Maintenance is checked first; the setup refusal comes before the API
// token is verified (no invalid token event) and before the body is read.
func TestSetupOrder(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{resolver: stateResolver{state: tenant.SetupStateSetup}})
	e.maintenance.Store(true)
	rec := e.do(t, http.MethodPost, "/api/v1/transfers", hostA, strings.NewReader(`{}`), "Content-Type", "application/json")
	p := decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
	if p.RetryAfterSeconds == nil {
		t.Error("maintenance without Retry-After")
	}
	rec = e.do(t, http.MethodPatch, "/api/v1/uploads/upl_x", hostA, strings.NewReader("bytes"),
		"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", tusContentType)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("tus PATCH in maintenance: %d %v", rec.Code, rec.Header())
	}
	e.maintenance.Store(false)

	big := strings.Repeat(" ", 1<<21)
	rec = e.do(t, http.MethodPost, "/api/v1/transfers", hostA, strings.NewReader(big),
		"Content-Type", "text/plain", "Authorization", "Bearer tt_invalid")
	decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeTenantInSetup)
	if strings.Contains(e.secLog.String(), "api_token_invalid") {
		t.Errorf("the token was verified: %s", e.secLog.String())
	}
	// Control: an active tenant verifies (and refuses) the token.
	active := newEnv(t, envConfig{resolver: stateResolver{state: tenant.SetupStateActive}})
	active.do(t, http.MethodPost, "/api/v1/transfers", hostA, strings.NewReader(`{}`),
		"Content-Type", "application/json", "Authorization", "Bearer tt_invalid")
	if !strings.Contains(active.secLog.String(), "api_token_invalid") {
		t.Errorf("control: no token event: %s", active.secLog.String())
	}
	// The instance routes answer on the host of a tenant in setup.
	if rec := e.do(t, http.MethodGet, "/healthz", hostA, nil); rec.Code != http.StatusOK {
		t.Errorf("healthz: %d", rec.Code)
	}
}

// A request reaching the API router without tenant (a wiring error) is
// refused like a tenant in setup (fail closed); the allowlist is served.
func TestSetupWithoutTenant(t *testing.T) {
	t.Parallel()
	served := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := setupMiddleware(served)
	for _, tc := range []struct {
		pattern string
		status  int
		body    bool
	}{
		{http.MethodPost + " " + APIBaseURL + "/transfers", http.StatusServiceUnavailable, true},
		{tusOptionsPattern, http.StatusServiceUnavailable, false},
		{tusUploadPattern, http.StatusServiceUnavailable, false},
		{http.MethodGet + " " + APIBaseURL + "/tenant", http.StatusNoContent, false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Pattern = tc.pattern
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.status || (rec.Body.Len() > 0) != tc.body {
			t.Errorf("%s: %d %q", tc.pattern, rec.Code, rec.Body.String())
		}
		if tc.body && !strings.Contains(rec.Body.String(), "tenant-in-setup") {
			t.Errorf("%s: %s", tc.pattern, rec.Body.String())
		}
	}
}
