package middleware

import (
	"context"
	"net/http"
)

// flowCookieKey is the context key of the flow cookie value.
type flowCookieKey struct{}

// FlowCookie returns the middleware of the redirect target of a login
// flow (the single sign-on callback, since API 2.0): for the requests
// applies selects, it puts the value of the cookie name in the context
// ([FlowCookieFrom]) and adds the Set-Cookie header clearCookie, which expires
// that cookie, to the response whatever its outcome, next to any cookie
// the handler sets (it is added when the status is written, after the
// handler set its headers). Other requests pass through untouched.
//
// Only a top-level navigation may present the flow: when the fetch
// metadata of the request says otherwise (a Sec-Fetch-Mode other than
// navigate, or a Sec-Fetch-Dest other than document: an image, a script or
// a fetch of a cross-site page), the context holds no cookie value, so the
// handler answers as for a callback without flow. Browsers without fetch
// metadata send neither header and are not affected.
func FlowCookie(name, clearCookie string, applies func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !applies(r) {
				next.ServeHTTP(w, r)
				return
			}
			value := ""
			if c, err := r.Cookie(name); err == nil && navigation(r) {
				value = c.Value
			}
			cw := &clearingWriter{ResponseWriter: w, clear: clearCookie}
			next.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), flowCookieKey{}, value)))
			cw.add()
		})
	}
}

// navigation reports whether the fetch metadata of r, when present, says
// it is a top-level navigation.
func navigation(r *http.Request) bool {
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" && m != "navigate" {
		return false
	}
	if d := r.Header.Get("Sec-Fetch-Dest"); d != "" && d != "document" {
		return false
	}
	return true
}

// FlowCookieFrom returns the flow cookie value put in ctx by [FlowCookie],
// "" when there is none.
func FlowCookieFrom(ctx context.Context) string {
	v, _ := ctx.Value(flowCookieKey{}).(string)
	return v
}

// clearingWriter adds a Set-Cookie header once, before the status is
// written.
type clearingWriter struct {
	http.ResponseWriter
	clear string
	done  bool
}

// add adds the clearing cookie unless already done.
func (w *clearingWriter) add() {
	if !w.done {
		w.done = true
		w.Header().Add("Set-Cookie", w.clear)
	}
}

// WriteHeader implements http.ResponseWriter.
func (w *clearingWriter) WriteHeader(code int) {
	w.add()
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter.
func (w *clearingWriter) Write(b []byte) (int, error) {
	w.add()
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the wrapped writer (http.ResponseController).
func (w *clearingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
