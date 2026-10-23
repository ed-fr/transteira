package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

// frenchResolver resolves hostA to a tenant whose default language is
// French.
type frenchResolver struct{}

func (frenchResolver) Resolve(_ context.Context, host string) (*tenant.Tenant, error) {
	if host == hostA {
		return &tenant.Tenant{ID: "ten_a", FQDN: hostA, DefaultLanguage: "fr"}, nil
	}
	return nil, tenant.ErrUnknownTenant
}

// TestMaintenanceMessage checks the detail of the maintenance Problem: the
// message of the language negotiated from Accept-Language, else of the
// tenant default, absent when none is set, and no Content-Language.
func TestMaintenanceMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{resolver: frenchResolver{}})
	e.maintenance.Store(true)
	e.maintenance.setMessages(map[string]string{"fr": "Retour vers 20 h.", "en": "Back around 8 pm.\nSorry."})
	deposit := func(headers ...string) (*httptest.ResponseRecorder, problem.Problem) {
		t.Helper()
		rec := e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader(`{}`),
			append([]string{"Content-Type", "application/json"}, headers...)...)
		return rec, decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
	}

	rec, p := deposit("Accept-Language", "en-GB,en;q=0.9")
	if p.Detail != "Back around 8 pm.\nSorry." || e.maintenance.lastAsked() != [2]string{"en", "fr"} {
		t.Errorf("English detail %q, asked %v", p.Detail, e.maintenance.lastAsked())
	}
	if rec.Header().Get("Content-Language") != "" {
		t.Errorf("Content-Language %q", rec.Header().Get("Content-Language"))
	}
	if rec.Header().Get("Retry-After") != "300" {
		t.Errorf("Retry-After %q", rec.Header().Get("Retry-After"))
	}

	// No usable Accept-Language: the tenant default.
	if _, p = deposit("Accept-Language", "de"); p.Detail != "Retour vers 20 h." || e.maintenance.lastAsked() != [2]string{"fr", "fr"} {
		t.Errorf("tenant default detail %q, asked %v", p.Detail, e.maintenance.lastAsked())
	}

	// No message: no detail.
	e.maintenance.setMessages(nil)
	if rec, p = deposit(); p.Detail != "" || strings.Contains(rec.Body.String(), `"detail"`) {
		t.Errorf("detail without message: %s", rec.Body.String())
	}
}

// TestMaintenanceMiddlewareWithoutTenant drives the middleware directly on
// a request without tenant (not reachable through the router, which
// resolves the tenant first): the default language of the instance is
// negotiated and no tenant default is passed.
func TestMaintenanceMiddlewareWithoutTenant(t *testing.T) {
	t.Parallel()
	mode := &fakeMaintenance{messages: map[string]string{"en": "Back soon."}}
	mode.Store(true)
	h := maintenanceMiddleware(mode)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("blocked operation reached")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/transfers", nil)
	req.Pattern = http.MethodPost + " " + APIBaseURL + "/transfers"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var p problem.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != http.StatusServiceUnavailable || p.Code != problem.CodeMaintenance {
		t.Fatalf("answer %d %s: %v", rec.Code, rec.Body.String(), err)
	}
	if p.Detail != "Back soon." || mode.lastAsked() != [2]string{"en", ""} {
		t.Errorf("detail %q, asked %v", p.Detail, mode.lastAsked())
	}
}

// TestNoMaintenance checks the mode of a server built without one.
func TestNoMaintenance(t *testing.T) {
	t.Parallel()
	var m MaintenanceMode = noMaintenance{}
	if m.Active() || m.Message("en", "fr") != "" {
		t.Error("noMaintenance is active or has a message")
	}
}
