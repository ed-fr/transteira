package httpserver

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MaintenanceMode reports the maintenance mode (*maintenance.Mode).
type MaintenanceMode interface {
	// Active reports whether the maintenance mode is in effect; it is
	// called on every deposit request and must be cheap.
	Active() bool
	// Message returns the maintenance message for the negotiated language
	// lang on a tenant whose default language is tenantDefault, with the
	// language it is written in; two empty strings for none.
	Message(lang, tenantDefault string) (msg, msgLang string)
}

// noMaintenance is the maintenance mode of a server built without one:
// never active.
type noMaintenance struct{}

func (noMaintenance) Active() bool                              { return false }
func (noMaintenance) Message(_, _ string) (msg, msgLang string) { return "", "" }

// MaintenanceRetryAfter is the delay suggested to clients refused during
// maintenance (Retry-After header).
const MaintenanceRetryAfter = 5 * time.Minute

// tusVersion is the tus protocol version sent in the Tus-Resumable header,
// which the tus protocol requires on every response but OPTIONS.
const tusVersion = "1.0.0"

// tusUploadPattern is the route pattern of the tus PATCH operation
// (appendUploadChunk), whose responses carry no body.
const tusUploadPattern = http.MethodPatch + " " + APIBaseURL + "/uploads/{uploadId}"

// maintenanceBlocked lists the route patterns (as set in Request.Pattern by
// the API router) of the operations refused in maintenance mode: those that
// start or feed a deposit. Health check, downloads and administration stay
// available.
var maintenanceBlocked = map[string]struct{}{
	http.MethodPost + " " + APIBaseURL + "/deposit-sessions":                {},
	http.MethodPost + " " + APIBaseURL + "/transfers":                       {},
	http.MethodPost + " " + APIBaseURL + "/transfers/{transferId}/finalize": {},
	tusUploadPattern: {},
	http.MethodPost + " " + APIBaseURL + "/invitations": {},
	// A reply to a transfer (since 1.1) starts a deposit.
	http.MethodPost + " " + APIBaseURL + "/downloads/{linkToken}/reply": {},
}

// maintenanceMiddleware refuses the deposit operations with 503 and a
// Retry-After header while mode is active. The tus PATCH operation gets a
// bodyless 503 with the Tus-Resumable header, as declared by the OpenAPI
// document; the other operations get a 503 maintenance Problem whose
// detail is the maintenance message in the language negotiated from
// Accept-Language and the tenant default (plain text, absent when none is
// set). The Problem carries no Content-Language: its title stays English
// whatever the language of the message, and the language of the detail
// (which may be a fallback) is not reported; a client that shows the
// message marked up with its language reads PublicTenant.maintenanceMessage
// and maintenanceMessageLanguage instead. It runs as a per-operation
// middleware of the API router, before the body limit and before the
// request body is read or decoded.
func maintenanceMiddleware(mode MaintenanceMode) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, blocked := maintenanceBlocked[r.Pattern]; !blocked || !mode.Active() {
				next.ServeHTTP(w, r)
				return
			}
			if r.Pattern == tusUploadPattern {
				h := w.Header()
				h.Set("Tus-Resumable", tusVersion)
				h.Set("Retry-After", strconv.Itoa(int(MaintenanceRetryAfter/time.Second)))
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			opts := []problem.Option{problem.WithRetryAfter(MaintenanceRetryAfter)}
			var tenantDefault string
			if t, ok := tenant.FromContext(r.Context()); ok {
				tenantDefault = t.DefaultLanguage
			}
			lang := i18n.Negotiate(r.Header.Get("Accept-Language"), tenantDefault)
			if msg, _ := mode.Message(lang, tenantDefault); msg != "" {
				opts = append(opts, problem.WithDetail(msg))
			}
			writeProblem(w, r, problem.New(problem.CodeMaintenance, opts...))
		})
	}
}
