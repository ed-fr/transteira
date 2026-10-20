package httpserver

import (
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// DefaultUploadIdleTimeout is the idle read timeout of a tus PATCH body when
// Deps.UploadIdleTimeout is not set (TT_UPLOAD_IDLE_TIMEOUT).
const DefaultUploadIdleTimeout = 60 * time.Second

// tus header names.
const (
	headerTusResumable = "Tus-Resumable"
	headerTusVersion   = "Tus-Version"
)

// tusContentType is the only media type of a tus PATCH body.
const tusContentType = "application/offset+octet-stream"

// Route patterns of the tus operations on an upload resource. OPTIONS
// /uploads is not one: it needs no Tus-Resumable header.
const (
	tusHeadPattern   = http.MethodHead + " " + APIBaseURL + "/uploads/{uploadId}"
	tusDeletePattern = http.MethodDelete + " " + APIBaseURL + "/uploads/{uploadId}"
)

// isTusPattern reports whether pattern is a tus operation on an upload
// resource (HEAD, PATCH or DELETE).
func isTusPattern(pattern string) bool {
	return policyOfPattern(pattern).tus
}

// tusMiddleware applies the tus protocol rules to the routes whose policy
// sets tus, before authentication:
//
//   - every response carries Tus-Resumable, and its error responses (4xx and
//     503) have no body, whoever writes them (session, CSRF and maintenance
//     middlewares included); a 500 keeps its Problem body;
//   - a request whose Tus-Resumable header is not exactly TusVersion gets
//     412 with Tus-Version (a missing header is caught earlier, by the
//     parameter binding: see tusParamError);
//   - a PATCH whose media type is not application/offset+octet-stream gets
//     415.
func tusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !policyOf(r).tus {
			next.ServeHTTP(w, r)
			return
		}
		tw := newTusWriter(w, r)
		switch {
		case r.Header.Get(headerTusResumable) != public.TusVersion:
			tusVersionUnsupported(tw)
		case r.Method == http.MethodPatch && !isTusContentType(r.Header.Get("Content-Type")):
			tw.WriteHeader(http.StatusUnsupportedMediaType)
		default:
			next.ServeHTTP(tw, r)
		}
	})
}

// tusVersionUnsupported answers 412 with the supported versions.
func tusVersionUnsupported(w http.ResponseWriter) {
	w.Header().Set(headerTusVersion, public.TusVersion)
	w.WriteHeader(http.StatusPreconditionFailed)
}

// isTusContentType reports whether ct names the tus PATCH media type.
func isTusContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mt, tusContentType)
}

// tusParamError answers a parameter binding failure of a tus operation:
// 412 for the Tus-Resumable header (missing or repeated), 400 otherwise
// (Upload-Offset missing or malformed), without body, as tus requires.
func tusParamError(w http.ResponseWriter, r *http.Request, err error) {
	tw := newTusWriter(w, r)
	if fe, ok := fieldErrorOf(err); ok && fe.Field == headerTusResumable {
		tusVersionUnsupported(tw)
		return
	}
	tw.WriteHeader(http.StatusBadRequest)
}

// tusWriter adds Tus-Resumable to the response and drops the body of the
// error responses but 500 (see tusMiddleware). An error response also
// carries Connection: close: the request body may be unread, and the
// connection is not worth keeping for it (net/http then drains at most a
// bounded part of it, under the read deadline set by idleBodyHandler). It
// unwraps for http.ResponseController, so that deadlines still reach the
// connection.
type tusWriter struct {
	http.ResponseWriter
	wroteHeader bool
	discard     bool
}

// newTusWriter wraps w for a tus request.
func newTusWriter(w http.ResponseWriter, _ *http.Request) *tusWriter {
	return &tusWriter{ResponseWriter: w}
}

// WriteHeader implements http.ResponseWriter.
func (w *tusWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return // superfluous call, ignored as net/http does
	}
	w.wroteHeader = true
	h := w.Header()
	h.Set(headerTusResumable, public.TusVersion)
	if code >= http.StatusBadRequest {
		h.Set("Connection", "close")
		if code != http.StatusInternalServerError {
			w.discard = true
			h.Del("Content-Type")
			h.Del("Content-Length")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter.
func (w *tusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.discard {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the wrapped writer (http.ResponseController).
func (w *tusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// idleBodyHandler sets the read deadline of every API request as soon as
// its route is known. A route whose policy sets idleBody gets an idle read
// timeout instead of a global deadline (threat T-123): the read deadline
// of the connection is set to timeout at once, and every Read moves it
// timeout ahead, so that a large upload may last hours while a stalled or
// trickling one is cut after timeout. Any other route with a deadline in
// its policy (RequestDeadline by default, including unknown routes) gets
// that read deadline at once, or the idle timeout when shorter for a tus
// operation (HEAD, DELETE); deadlineMiddleware sets the policy deadline
// again, with the write deadline, when the operation runs. Streaming routes without
// deadline get none here: a read deadline would make net/http cancel a
// long download when its background read times out.
//
// It wraps the API router itself, not a per-operation middleware, because
// the generated code binds the parameters before the middlewares run: the
// deadline must already hold when an early rejection (parameter error, tus
// protocol, maintenance, session, CSRF) leaves the body unread and net/http
// drains it after the handler. A writer without deadline support (tests)
// is accepted.
//
// mux only selects the route; next serves the request.
func idleBodyHandler(mux *http.ServeMux, next http.Handler, timeout time.Duration, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		p := policyOfPattern(pattern)
		rc := http.NewResponseController(w)
		switch {
		case p.idleBody:
			logDeadlineError(r, logger, rc.SetReadDeadline(time.Now().Add(timeout)))
			r.Body = &idleBody{ReadCloser: r.Body, rc: rc, timeout: timeout, now: time.Now}
		case p.deadline > 0:
			d := p.deadline
			if p.tus {
				// The other tus operations follow the upload idle
				// timeout too, when it is shorter.
				d = min(d, timeout)
			}
			logDeadlineError(r, logger, rc.SetReadDeadline(time.Now().Add(d)))
		}
		next.ServeHTTP(w, r)
	})
}

// idleBody extends the read deadline before every Read.
type idleBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	timeout time.Duration
	now     func() time.Time
}

// Read implements io.Reader. A deadline that cannot be set (a writer
// without deadline support) leaves the body without idle timeout.
func (b *idleBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(b.now().Add(b.timeout))
	return b.ReadCloser.Read(p)
}

// logDeadlineError logs a deadline failure other than http.ErrNotSupported
// at debug level.
func logDeadlineError(r *http.Request, logger *slog.Logger, err error) {
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		logger.DebugContext(r.Context(), "cannot set request deadline",
			slog.String("request_id", middleware.RequestID(r.Context())),
			slog.String("route", r.Pattern),
			slog.String("error", err.Error()))
	}
}
