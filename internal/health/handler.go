package health

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/version"
)

// Overall statuses of the Health schema.
const (
	overallOK       = "ok"
	overallDegraded = "degraded"
)

// versionString returns the application version, replaceable in tests.
var versionString = func() string { return version.Get().Version }

// response is the OpenAPI Health schema.
type response struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Maintenance bool   `json:"maintenance"`
	Checks      checks `json:"checks"`
}

type checks struct {
	Database  Status `json:"database"`
	Antivirus Status `json:"antivirus"`
	Storage   Status `json:"storage"`
}

// Handler serves the health report of svc as the OpenAPI Health schema:
// 200 when every component is available, 503 otherwise. maintenance reports
// whether maintenance mode is active; nil means never. Only GET and HEAD are
// accepted. Responses are never cached and never contain error details.
func Handler(svc *Service, maintenance func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			var opts []problem.Option
			if id := h.Get(middleware.HeaderRequestID); id != "" {
				opts = append(opts, problem.WithInstance(id))
			}
			problem.Write(w, problem.New(problem.CodeMethodNotAllowed, opts...))
			return
		}

		report := svc.Run(r.Context())
		resp := response{
			Status:      overallOK,
			Version:     versionString(),
			Maintenance: maintenance != nil && maintenance(),
			Checks:      checks(report),
		}
		code := http.StatusOK
		if !report.Healthy() {
			resp.Status = overallDegraded
			code = http.StatusServiceUnavailable
		}
		// Marshaling strings and booleans cannot fail.
		body, _ := json.Marshal(resp)

		h.Set("Content-Type", "application/json")
		h.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(code)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}
