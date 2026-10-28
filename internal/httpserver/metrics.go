package httpserver

import (
	"net/http"
)

// RequestCounter counts the responses of the server by status code
// (*metrics.Counters implements it through HTTPRequest).
type RequestCounter interface {
	HTTPRequest(status int)
}

// StreamCounter tracks the download streams in progress
// (*metrics.Counters implements it). Every StreamOpened is followed by
// exactly one StreamClosed.
type StreamCounter interface {
	StreamOpened()
	StreamClosed()
}

// statusWriter records the status code of a response. It unwraps for
// http.ResponseController (deadlines, flush, full duplex) and implements
// http.Flusher, like the other writers of the package, so that the
// streaming of uploads and downloads is unaffected. It does not implement
// http.Hijacker: no route hijacks its connection, and one that would must
// not sit behind it.
type statusWriter struct {
	http.ResponseWriter
	status int
	// onStart, when set, is called once with the final status, when the
	// header is first sent.
	onStart func(status int)
}

// start records the final status the first time it is known.
func (w *statusWriter) start(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	if w.onStart != nil {
		w.onStart(code)
	}
}

// WriteHeader implements http.ResponseWriter. Informational 1xx statuses
// other than 101 are not final and are not recorded.
func (w *statusWriter) WriteHeader(code int) {
	if code >= http.StatusOK || code == http.StatusSwitchingProtocols {
		w.start(code)
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter; a body without WriteHeader is a 200.
func (w *statusWriter) Write(b []byte) (int, error) {
	w.start(http.StatusOK)
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher; it is a no-op when the underlying writer
// cannot flush.
func (w *statusWriter) Flush() {
	w.start(http.StatusOK)
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap returns the wrapped writer (http.ResponseController).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// requestCountMiddleware counts every response by status code. A handler
// that returns without writing answers 200, one that panics (before the
// recovery layer answers) counts as 500. A nil counter disables it.
func requestCountMiddleware(c RequestCounter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if c == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w}
			done := false
			defer func() {
				switch {
				case !done:
					c.HTTPRequest(http.StatusInternalServerError)
				case sw.status == 0:
					c.HTTPRequest(http.StatusOK)
				default:
					c.HTTPRequest(sw.status)
				}
			}()
			next.ServeHTTP(sw, r)
			done = true
		})
	}
}

// streamGaugeMiddleware tracks the download streams in progress: the routes
// whose policy sets idleWrite (file and archive downloads) count as a
// stream from the moment a GET answers 200 or 206 until the handler
// returns, whatever the way it ends (deferred). Refused requests, HEAD
// requests and other answers are not streams. A nil counter disables it.
func streamGaugeMiddleware(c StreamCounter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if c == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !policyOf(r).idleWrite || r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			opened := false
			defer func() {
				if opened {
					c.StreamClosed()
				}
			}()
			sw := &statusWriter{ResponseWriter: w, onStart: func(status int) {
				if status == http.StatusOK || status == http.StatusPartialContent {
					opened = true
					c.StreamOpened()
				}
			}}
			next.ServeHTTP(sw, r)
		})
	}
}
