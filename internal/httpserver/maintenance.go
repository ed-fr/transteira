package httpserver

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
)

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
}

// maintenanceMiddleware refuses the deposit operations with 503 and a
// Retry-After header while flag is set. The tus PATCH operation gets a
// bodyless 503 with the Tus-Resumable header, as declared by the OpenAPI
// document; the other operations get a 503 maintenance Problem. It runs as
// a per-operation middleware of the API router, before the body limit and
// before the request body is read or decoded.
func maintenanceMiddleware(flag *atomic.Bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, blocked := maintenanceBlocked[r.Pattern]; !blocked || !flag.Load() {
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
			writeProblem(w, r, problem.New(problem.CodeMaintenance, problem.WithRetryAfter(MaintenanceRetryAfter)))
		})
	}
}
