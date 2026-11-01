package httpserver

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/ratelimit"
)

// provisioningOperation is an operation of the spec protected by the
// provisioningToken security scheme, with a concrete path.
type provisioningOperation struct {
	method, path, id string
}

// provisioningOperations lists the operations of api/openapi.yaml whose
// security is provisioningToken, their path parameters filled in.
func provisioningOperations(t *testing.T) []provisioningOperation {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPISpec, &doc); err != nil {
		t.Fatal(err)
	}
	var ops []provisioningOperation
	for path, item := range doc.Paths {
		for verb, node := range item {
			method := strings.ToUpper(verb)
			if !slices.Contains([]string{"GET", "PUT", "POST", "DELETE", "PATCH"}, method) {
				continue
			}
			var op specOperation
			if err := node.Decode(&op); err != nil {
				t.Fatal(err)
			}
			if op.Security == nil || !slices.ContainsFunc(*op.Security, func(alt map[string][]string) bool {
				_, ok := alt["provisioningToken"]
				return ok
			}) {
				continue
			}
			concrete := strings.ReplaceAll(path, "{tenantId}", "ten_01JAB00000000000000ENT1TYC")
			if strings.Contains(concrete, "{") {
				t.Fatalf("%s: unknown path parameter", path)
			}
			ops = append(ops, provisioningOperation{method, APIBaseURL + concrete, op.OperationID})
		}
	}
	if len(ops) == 0 {
		t.Fatal("no operation with the provisioningToken security in the spec")
	}
	return ops
}

// TestProvisioningFailsClosed walks every provisioning operation of the
// spec: without a provisioning service, nothing opens them, neither the
// absence of credential, nor a tenant API token, nor an admin session.
func TestProvisioningFailsClosed(t *testing.T) {
	t.Parallel()
	// Far more refusals than the lockout allows come from the same client.
	e, _ := newAdminEnv(t, WithProvisioningFailures(ratelimit.NewWindow(ratelimit.MaxWindowLimit, time.Hour)))
	credentials := []struct {
		name string
		hdr  []string
		code problem.Code
	}{
		{"no credential", nil, problem.CodeUnauthenticated},
		{"tenant api token", []string{"Authorization", "Bearer tt_EXAMPLE4fK2xQ8mL1zV4bN7cR0tY3wE6uI9oP2aS5dF"}, problem.CodeProvisioningTokenInvalid},
		{"provisioning-like token", []string{"Authorization", "Bearer ttp_EXAMPLE4fK2xQ8mL1zV4bN7cR0tY3wE6uI9oP2aS5"}, problem.CodeProvisioningTokenInvalid},
		{"admin session", adminAuth(), problem.CodeUnauthenticated},
		{"empty bearer", []string{"Authorization", "Bearer "}, problem.CodeProvisioningTokenInvalid},
		{"other scheme", []string{"Authorization", "Basic dXNlcjpwYXNz"}, problem.CodeProvisioningTokenInvalid},
	}
	for _, op := range provisioningOperations(t) {
		for _, c := range credentials {
			t.Run(op.id+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				hdr := append([]string{"Content-Type", "application/json"}, c.hdr...)
				var body io.Reader
				if op.method == http.MethodPost {
					body = strings.NewReader("{}")
				}
				rec := e.do(t, op.method, op.path, hostAdmin, body, hdr...)
				decodeProblem(t, rec, http.StatusUnauthorized, c.code)
				if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
					t.Errorf("WWW-Authenticate %q", rec.Header().Get("WWW-Authenticate"))
				}
			})
		}
		// Never served on a tenant host, whatever the credential.
		rec := e.do(t, op.method, op.path, hostA, nil, "Authorization", "Bearer ttp_x")
		decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	}
}
