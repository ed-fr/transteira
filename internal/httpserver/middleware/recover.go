package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// preservedOnPanic lists the response headers kept when a panic is turned
// into a 500 response. Every other header set by the failed handler (for
// example Content-Disposition, ETag or tus headers) is removed so that it
// does not describe the error body.
var preservedOnPanic = []string{
	HeaderRequestID,
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"X-Frame-Options",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
}

// Recover turns a panic in the next handler into a 500 internal-error
// Problem carrying the request identifier, and logs the panic value and
// stack trace on logger (a nil logger discards). Only the method and the
// matched route pattern are logged, never the path, which may contain a
// download token, nor the query string.
//
// If the handler had already started the response, a clean error can no
// longer be sent: Recover then panics with [http.ErrAbortHandler] so that
// net/http aborts the connection and the client sees a truncated response
// rather than a seemingly complete one. A panic with http.ErrAbortHandler is
// propagated untouched and not logged, as net/http expects.
//
// Recover must be the outermost middleware so that it also covers the
// others. It finds the request identifier in the X-Request-Id response
// header set by [AssignRequestID], and the security headers set by
// [SecurityHeaders] are kept on the error response.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	logger = orDiscard(logger)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tw := &trackingWriter{ResponseWriter: w}
			defer func() {
				if v := recover(); v != nil {
					handlePanic(logger, tw, r, v)
				}
			}()
			next.ServeHTTP(tw, r)
		})
	}
}

// handlePanic logs the recovered value v and answers 500, or aborts the
// connection when the response has already started.
func handlePanic(logger *slog.Logger, tw *trackingWriter, r *http.Request, v any) {
	if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(v)
	}
	w := tw.ResponseWriter
	logger.ErrorContext(r.Context(), "panic serving request",
		slog.String("request_id", requestIDOf(w, r)),
		slog.String("method", r.Method),
		slog.String("route", r.Pattern),
		slog.Bool("response_started", tw.started),
		slog.String("panic", fmt.Sprint(v)),
		slog.String("stack", string(debug.Stack())),
	)
	if tw.started {
		panic(http.ErrAbortHandler)
	}
	resetHeaders(w.Header())
	writeProblem(w, r, problem.CodeInternalError)
}

// resetHeaders removes every header of h except preservedOnPanic.
func resetHeaders(h http.Header) {
	keep := make(map[string][]string, len(preservedOnPanic))
	for _, k := range preservedOnPanic {
		if v, ok := h[k]; ok {
			keep[k] = v
		}
	}
	clear(h)
	for k, v := range keep {
		h[k] = v
	}
}

// ResponseStarted reports whether the final response status (or any body
// byte, or a flush) has already been sent on w. It follows the chain of
// writers exposing Unwrap() http.ResponseWriter until it finds the
// tracking writer installed by [Recover]; it returns false when there is
// none, so callers must not rely on it outside a Recover chain.
//
// Handlers use it to decide how to report an error: before the response
// has started, a Problem can still be written; afterwards, the only honest
// option is to abort the connection with panic(http.ErrAbortHandler), so
// that the client sees a truncated response instead of a seemingly
// complete one. Like the response writer itself, it must only be called
// from the goroutine serving the request.
func ResponseStarted(w http.ResponseWriter) bool {
	for w != nil {
		if tw, ok := w.(*trackingWriter); ok {
			return tw.started
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = u.Unwrap()
	}
	return false
}

// trackingWriter records whether the final response header was sent. It
// supports http.Flusher directly and every other optional interface
// (Hijacker, deadlines, full duplex) through [http.ResponseController] via
// Unwrap.
type trackingWriter struct {
	http.ResponseWriter
	started bool
}

// WriteHeader implements http.ResponseWriter. Informational 1xx statuses
// other than 101 Switching Protocols do not start the final response.
func (w *trackingWriter) WriteHeader(code int) {
	if code >= http.StatusOK || code == http.StatusSwitchingProtocols {
		w.started = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter.
func (w *trackingWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher; it is a no-op when the underlying writer
// cannot flush.
func (w *trackingWriter) Flush() {
	w.started = true
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap returns the underlying writer, for http.ResponseController.
func (w *trackingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
