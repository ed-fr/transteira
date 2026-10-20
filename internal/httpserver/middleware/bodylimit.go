package middleware

import (
	"errors"
	"net/http"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// DefaultJSONBodyLimit is the body limit of JSON API requests (1 MiB).
const DefaultJSONBodyLimit int64 = 1 << 20

// NoBodyLimit is the limit to return from the function given to
// [BodyLimitFunc] to leave a request body unlimited. Only operations that enforce their own limit,
// such as tus PATCH uploads (bounded by the declared Upload-Length and the
// tenant's per-transfer limit), may use it.
const NoBodyLimit int64 = -1

// ImageBodyLimit is the body limit of branding image uploads (10 MiB, the
// largest asset the API accepts: a background image). The handler enforces
// the smaller per-asset limits, such as 5 MiB for a logo.
const ImageBodyLimit int64 = 10 << 20

// BodyLimit limits request bodies to n bytes, except for requests for which
// exempt (may be nil) returns true, which are left unlimited (see
// [NoBodyLimit]). It is [BodyLimitFunc] with a fixed limit.
//
// n must not be negative; 0 allows only empty bodies.
func BodyLimit(n int64, exempt func(*http.Request) bool) func(http.Handler) http.Handler {
	if n < 0 {
		panic("middleware: BodyLimit requires a non-negative limit")
	}
	return BodyLimitFunc(func(r *http.Request) int64 {
		if exempt != nil && exempt(r) {
			return NoBodyLimit
		}
		return n
	})
}

// BodyLimitFunc limits each request body to limit(r) bytes, so that
// operations can have different limits (for example
// [DefaultJSONBodyLimit] for JSON requests and [ImageBodyLimit] for image
// uploads). A negative limit (use [NoBodyLimit]) leaves the body
// unlimited; 0 allows only empty bodies.
//
// A request announcing a Content-Length above the limit is refused upfront
// with a 413 payload-too-large Problem, without calling the next handler.
// Other bodies (chunked, or lying about their length) are wrapped with
// [http.MaxBytesReader]: reading past the limit returns an
// *[http.MaxBytesError]. Handlers that read the body must map that error
// to 413 payload-too-large; [IsBodyTooLarge] detects it.
//
// A nil limit panics, being a wiring error.
func BodyLimitFunc(limit func(*http.Request) int64) func(http.Handler) http.Handler {
	if limit == nil {
		panic("middleware: BodyLimitFunc requires a limit function")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := limit(r)
			if n < 0 {
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength > n {
				writeProblem(w, r, problem.CodePayloadTooLarge)
				return
			}
			r = r.WithContext(r.Context()) // shallow copy: never mutate the caller's request
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// IsBodyTooLarge reports whether err is or wraps the error returned when a
// body limited by [BodyLimit] exceeds its limit.
func IsBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}
