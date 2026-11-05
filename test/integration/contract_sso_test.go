package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/ed-fr/transteira/internal/oidc/oidctest"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Contract tests of the single sign-on operations (CLAUDE.md section 24.2):
// the answers of the running server, status, headers and body, are
// validated against api/openapi.yaml.

var (
	specOnce    sync.Once
	specDoc     *openapi3.T
	errSpecLoad error
)

// openAPIDoc loads api/openapi.yaml once. doc.Validate is not called:
// kin-openapi rejects the flow mapping of ExportedAsset.dataBase64 (a comma
// in a plain scalar), which Spectral does not report.
func openAPIDoc(t *testing.T) *openapi3.T {
	t.Helper()
	specOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		specDoc, errSpecLoad = openapi3.NewLoader().LoadFromFile(filepath.Join(filepath.Dir(file), "..", "..", "api", "openapi.yaml"))
	})
	if errSpecLoad != nil {
		t.Fatalf("api/openapi.yaml: %v", errSpecLoad)
	}
	return specDoc
}

// findRoute matches the URL path (below /api/v1) and the method with an
// operation of the specification.
func findRoute(t *testing.T, method, path string) (*routers.Route, map[string]string) {
	t.Helper()
	doc := openAPIDoc(t)
	rel := strings.TrimPrefix(strings.SplitN(path, "?", 2)[0], "/api/v1")
	for tmpl, item := range doc.Paths.Map() {
		re := regexp.MustCompile("^" + regexp.MustCompile(`\\\{[^}]+\\\}`).ReplaceAllString(regexp.QuoteMeta(tmpl), "([^/]+)") + "$")
		m := re.FindStringSubmatch(rel)
		if m == nil || item.GetOperation(method) == nil {
			continue
		}
		names := regexp.MustCompile(`\{([^}]+)\}`).FindAllStringSubmatch(tmpl, -1)
		params := map[string]string{}
		for i, n := range names {
			params[n[1]] = m[i+1]
		}
		return &routers.Route{Spec: doc, Path: tmpl, PathItem: item, Method: method, Operation: item.GetOperation(method)}, params
	}
	t.Fatalf("%s %s: no operation in the specification", method, path)
	return nil, nil
}

// contractError validates resp, the answer to method path, against the
// operation operationID of the specification: the status must be declared,
// the content type and the body must match its schema.
func contractError(t *testing.T, operationID, method, path string, resp response) error {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, "http://"+adminHost+path, nil)
	route, params := findRoute(t, method, path)
	if route.Operation.OperationID != operationID {
		t.Fatalf("%s %s is %s in the specification, want %s", method, path, route.Operation.OperationID, operationID)
	}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
		Status:                 resp.status,
		Header:                 resp.header,
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	in.SetBodyBytes(resp.body)
	return openapi3filter.ValidateResponse(context.Background(), in)
}

// expectContract fails when resp does not match the contract of operationID.
func expectContract(t *testing.T, operationID, method, path string, resp response) {
	t.Helper()
	if err := contractError(t, operationID, method, path, resp); err != nil {
		t.Errorf("%s %s -> %d does not match the contract: %v\nbody: %s", operationID, path, resp.status, err, resp.body)
	}
	// A 303 is declared with its Location header.
	if resp.status == http.StatusSeeOther && resp.header.Get("Location") == "" {
		t.Errorf("%s: 303 without Location", operationID)
	}
}

// TestContractHarnessDetectsViolations checks that the validator is not
// vacuous: a wrong type, a missing member, an undeclared status and a
// wrong content type are all reported.
func TestContractHarnessDetectsViolations(t *testing.T) {
	t.Parallel()
	json := http.Header{"Content-Type": {contentJSON}}
	path := tenantPath("ten_01JAB00000000000000ENT1TYA", "/sso")
	for name, resp := range map[string]response{
		"wrong type":          {status: 200, header: json, body: []byte(`{"enabled":"yes"}`)},
		"missing members":     {status: 200, header: json, body: []byte(`{"enabled":true}`)},
		"undeclared status":   {status: 418, header: json, body: []byte(`{}`)},
		"wrong content type":  {status: 200, header: http.Header{"Content-Type": {"text/plain"}}, body: []byte(`ok`)},
		"extra secret member": {status: 200, header: json, body: []byte(`{"enabled":true,"issuer":"https://login.example.com/x","clientId":"a","hasClientSecret":"secret","emailDomains":["a.example.com"],"enforced":false,"requireMfa":true,"createdAt":"2026-11-04T09:00:00Z","updatedAt":"2026-11-04T09:00:00Z"}`)},
	} {
		if contractError(t, "getTenantSso", http.MethodGet, path, resp) == nil {
			t.Errorf("%s: the violation was not detected", name)
		}
	}
	good := response{status: 200, header: json, body: []byte(`{"enabled":true,"issuer":"https://login.example.com/x","clientId":"a","hasClientSecret":true,"emailDomains":["a.example.com"],"enforced":false,"requireMfa":true,"createdAt":"2026-11-04T09:00:00Z","updatedAt":"2026-11-04T09:00:00Z"}`)}
	if err := contractError(t, "getTenantSso", http.MethodGet, path, good); err != nil {
		t.Errorf("a valid answer is refused: %v", err)
	}
}

// TestContractSSO validates every answer of the single sign-on operations:
// success and error statuses alike.
func TestContractSSO(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startSSO(t, e, serverOptions{})
		tidA, tidB := string(s.tenantA.ID), string(s.tenantB.ID)
		ssoPath := tenantPath(tidA, "/sso")
		anon := s.client(nil, adminIP(80))

		// Login methods and routing, before any configuration.
		expectContract(t, "getAdminAuthMethods", http.MethodGet, pathSSOMethods, anon.send(t, http.MethodGet, pathSSOMethods, nil, nil))
		expectContract(t, "startAdminOidcLogin", http.MethodPost, pathSSOStart,
			anon.send(t, http.MethodPost, pathSSOStart, map[string]string{"email": "who@" + domainA}, nil))
		expectContract(t, "startAdminOidcLogin", http.MethodPost, pathSSOStart,
			anon.send(t, http.MethodPost, pathSSOStart, map[string]string{"email": "not an address"}, nil))
		expectContract(t, "getTenantSso", http.MethodGet, ssoPath, s.sa.call(t, http.MethodGet, ssoPath, nil))
		expectContract(t, "testTenantSso", http.MethodPost, ssoPath+"/test", s.sa.call(t, http.MethodPost, ssoPath+"/test", nil))
		expectContract(t, "deleteTenantSso", http.MethodDelete, ssoPath, s.sa.call(t, http.MethodDelete, ssoPath, nil))

		// Configuration: refused first, then saved.
		bad := s.ssoBody([]string{domainA}, map[string]any{"issuer": "https://login.example.com/common/v2.0"})
		expectContract(t, "putTenantSso", http.MethodPut, ssoPath, s.putSSO(t, tidA, bad))
		noSecret := s.ssoBody([]string{domainA}, nil)
		delete(noSecret, "clientSecret")
		expectContract(t, "putTenantSso", http.MethodPut, ssoPath, s.putSSO(t, tidA, noSecret))
		expectContract(t, "putTenantSso", http.MethodPut, ssoPath, s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)))
		expectContract(t, "getTenantSso", http.MethodGet, ssoPath, s.sa.call(t, http.MethodGet, ssoPath, nil))
		expectContract(t, "getAdminAuthMethods", http.MethodGet, pathSSOMethods, anon.send(t, http.MethodGet, pathSSOMethods, nil, nil))
		expectContract(t, "testTenantSso", http.MethodPost, ssoPath+"/test", s.sa.call(t, http.MethodPost, ssoPath+"/test", nil))
		// A provider that refuses the connection is a result, not an error.
		dead := s.ssoBody([]string{domainA}, map[string]any{"issuer": "https://127.0.0.1:1/idp", "clientSecret": "dead-provider-secret"})
		mustStatus(t, "dead provider", s.putSSO(t, tidA, dead), http.StatusOK)
		failed := s.sa.call(t, http.MethodPost, ssoPath+"/test", nil)
		expectContract(t, "testTenantSso", http.MethodPost, ssoPath+"/test", failed)
		if !strings.Contains(string(failed.body), `"success":false`) {
			t.Errorf("test of a dead provider = %s", failed.body)
		}
		mustStatus(t, "restore", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)), http.StatusOK)

		// Unknown tenant, and the role refusals.
		unknown := tenantPath("ten_01JAB00000000000000ENT1TYA", "/sso")
		expectContract(t, "getTenantSso", http.MethodGet, unknown, s.sa.call(t, http.MethodGet, unknown, nil))
		del := s.createDelegatedOf2(t, "contract.user", tidA)
		expectContract(t, "putTenantSso", http.MethodPut, ssoPath, del.call(t, http.MethodPut, ssoPath, s.ssoBody([]string{domainA}, nil)))
		expectContract(t, "deleteTenantSso", http.MethodDelete, ssoPath, del.call(t, http.MethodDelete, ssoPath, nil))
		expectContract(t, "testTenantSso", http.MethodPost, ssoPath+"/test", del.call(t, http.MethodPost, ssoPath+"/test", nil))
		expectContract(t, "getTenantSso", http.MethodGet, ssoPath, del.call(t, http.MethodGet, ssoPath, nil))
		expectContract(t, "getTenantSso", http.MethodGet, tenantPath(tidB, "/sso"), del.call(t, http.MethodGet, tenantPath(tidB, "/sso"), nil))
		expectContract(t, "getTenantSso", http.MethodGet, ssoPath, anon.send(t, http.MethodGet, ssoPath, nil, nil))

		// Accounts: creation without link, a refusal, identities.
		resp := s.sa.call(t, http.MethodPost, pathAdmins, map[string]any{
			"username": "contract.sso", "email": uniqueEmail(t, "contract-sso", domainA), "role": "delegated_admin",
			"tenantIds": []string{tidA}, "invitation": map[string]any{"delivery": "none"},
		})
		expectContract(t, "createAdmin", http.MethodPost, pathAdmins, resp)
		var created adminJSON
		mustJSON(t, resp.body, &created)
		expectContract(t, "createAdmin", http.MethodPost, pathAdmins, s.sa.call(t, http.MethodPost, pathAdmins, map[string]any{
			"username": "contract.nosso", "email": uniqueEmail(t, "contract-nosso", domainB), "role": "delegated_admin",
			"tenantIds": []string{tidB}, "invitation": map[string]any{"delivery": "none"},
		}))
		email := created.Email
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-contract", Email: email, EmailVerified: verified()})
		c, cb := s.ssoLogin(t, email, adminIP(81))
		c.adoptSSO(t, cb)
		// The callback is a 303 whatever the outcome; one failure and one success.
		expectContract(t, "completeAdminOidcLogin", http.MethodGet, ssoCallbackPath, cb)
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-stranger", Email: email, EmailVerified: verified()})
		_, cb = s.ssoLogin(t, email, adminIP(82))
		expectContract(t, "completeAdminOidcLogin", http.MethodGet, ssoCallbackPath, cb)
		expectContract(t, "completeAdminOidcLogin", http.MethodGet, ssoCallbackPath+"?error=access_denied",
			anon.send(t, http.MethodGet, ssoCallbackPath+"?error=access_denied", nil, nil))

		adminPath := pathAdmins + "/" + created.ID
		got := s.sa.call(t, http.MethodGet, adminPath, nil)
		expectContract(t, "getAdmin", http.MethodGet, adminPath, got)
		ids := s.identitiesOf(t, created.ID)
		if len(ids) != 1 {
			t.Fatalf("identities = %+v", ids)
		}
		idPath := adminPath + "/identities/" + ids[0].ID
		expectContract(t, "deleteAdminIdentity", http.MethodDelete, idPath, del.call(t, http.MethodDelete, idPath, nil))
		expectContract(t, "deleteAdminIdentity", http.MethodDelete, idPath, s.sa.call(t, http.MethodDelete, idPath, nil))
		expectContract(t, "deleteAdminIdentity", http.MethodDelete, idPath, s.sa.call(t, http.MethodDelete, idPath, nil))
		expectContract(t, "deleteTenantSso", http.MethodDelete, ssoPath, s.sa.call(t, http.MethodDelete, ssoPath, nil))
	})
}

// createDelegatedOf2 creates a delegated admin of tenant tid (address in
// domain A) and returns it signed in.
func (s *ssoEnv) createDelegatedOf2(t *testing.T, username, tid string) *adminClient {
	t.Helper()
	return s.sa.createDelegatedOf(t, username, tid, domainA, adminIP(90))
}
