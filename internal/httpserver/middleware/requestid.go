package middleware

import (
	"context"
	"net/http"

	"github.com/ed-fr/transteira/internal/id"
)

// HeaderRequestID is the response header carrying the request identifier.
const HeaderRequestID = "X-Request-Id"

// ctxKey is the unexported type of this package's context keys.
type ctxKey int

const (
	requestIDKey ctxKey = iota
	clientIPKey
)

// AssignRequestID gives every request a fresh identifier (prefix "req_"),
// stores it in the request context (see [RequestID]) and returns it in the
// X-Request-Id response header. The header is set before the next handler
// runs, so it is present on every response, including errors and panics.
//
// An incoming X-Request-Id header is never trusted nor propagated: it is
// attacker-controlled and would let a client inject arbitrary text into the
// logs or collide with another request's identifier.
func AssignRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := id.New(id.Request)
		w.Header().Set(HeaderRequestID, rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, rid)))
	})
}

// RequestID returns the request identifier stored by [AssignRequestID], or
// "" when there is none.
func RequestID(ctx context.Context) string {
	rid, _ := ctx.Value(requestIDKey).(string)
	return rid
}
