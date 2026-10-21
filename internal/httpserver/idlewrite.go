package httpserver

import (
	"log/slog"
	"net/http"
	"time"
)

// DefaultDownloadIdleTimeout is the idle write timeout of a download
// response when Deps.DownloadIdleTimeout is not set
// (TT_DOWNLOAD_IDLE_TIMEOUT).
const DefaultDownloadIdleTimeout = 60 * time.Second

// idleWriteMiddleware gives the responses of the routes whose policy sets
// idleWrite an idle write timeout instead of a global deadline (security
// finding M1): the write deadline of the connection is set to timeout at
// once and moved timeout ahead before every write, so that a large
// download may last hours while a client that stops reading is cut after
// timeout, releasing its stream. A writer without deadline support
// (tests) is accepted.
func idleWriteMiddleware(timeout time.Duration, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !policyOf(r).idleWrite {
				next.ServeHTTP(w, r)
				return
			}
			iw := &idleWriter{ResponseWriter: w, rc: http.NewResponseController(w), timeout: timeout, now: time.Now}
			logDeadlineError(r, logger, iw.extend())
			next.ServeHTTP(iw, r)
		})
	}
}

// idleWriter extends the write deadline before every write. It unwraps for
// http.ResponseController (flush, deadlines).
type idleWriter struct {
	http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
	now     func() time.Time
}

// extend moves the write deadline timeout ahead.
func (w *idleWriter) extend() error {
	return w.rc.SetWriteDeadline(w.now().Add(w.timeout))
}

// Write implements http.ResponseWriter. A deadline that cannot be set (a
// writer without deadline support) leaves the response without idle
// timeout.
func (w *idleWriter) Write(b []byte) (int, error) {
	_ = w.extend()
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the wrapped writer (http.ResponseController).
func (w *idleWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
