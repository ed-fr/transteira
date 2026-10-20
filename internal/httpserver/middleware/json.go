package middleware

import (
	"mime"
	"net/http"
	"strings"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// RequireJSON refuses POST, PUT and PATCH requests that carry a body
// (Content-Length > 0, or an unknown length such as a chunked body) unless
// their Content-Type media type is application/json or
// application/merge-patch+json, compared case-insensitively. Parameters
// such as charset=utf-8 are allowed. Other requests get a 415
// unsupported-media-type Problem. Requests without a body, other methods,
// and requests for which exempt (may be nil) returns true, such as tus
// uploads (application/offset+octet-stream) and image uploads, pass.
//
// Besides keeping handlers on a single input format, this adds defense in
// depth against CSRF: an HTML form or a "simple" cross-site fetch can only
// send application/x-www-form-urlencoded, multipart/form-data or
// text/plain, and sending application/json cross-site requires a CORS
// preflight, which the API never approves. It is not a CSRF control on its
// own: a body-less cross-site POST (Content-Length 0) passes, as do exempt
// routes. The mandatory controls for cookie-authenticated routes remain
// the CSRF token (X-CSRF-Token header), SameSite=Strict cookies and the
// Origin check.
func RequireJSON(exempt func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if needsJSON(r) && (exempt == nil || !exempt(r)) && !isJSONType(r.Header.Get("Content-Type")) {
				writeProblem(w, r, problem.CodeUnsupportedMediaType)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// needsJSON reports whether r is a body-carrying write request.
func needsJSON(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return r.ContentLength != 0
	default:
		return false
	}
}

// isJSONType reports whether the Content-Type value ct names an accepted
// JSON media type.
func isJSONType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	mt = strings.ToLower(mt)
	return mt == "application/json" || mt == "application/merge-patch+json"
}
