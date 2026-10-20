// Package middleware provides the HTTP middlewares shared by every TransTeira
// request: panic recovery, request identifiers, real client IP, security
// headers, rate limiting, tenant resolution, deposit session authentication,
// CSRF protection and request body limits.
//
// Each middleware has the signature func(http.Handler) http.Handler and can
// be composed with [Chain]. The recommended order, from outermost to
// innermost, is:
//
//  1. [Recover]
//  2. [AssignRequestID]
//  3. [RealIP]
//  4. [SecurityHeaders]
//  5. [RateLimit] (global, per client IP)
//  6. routes that do not belong to a tenant (health check, OpenAPI document)
//  7. [Tenant]
//  8. [DepositSession] and [CSRF], per operation
//  9. [BodyLimit] and [RequireJSON]
//
// The package depends only on the small interfaces [TenantResolver],
// [SecurityEvents], [Limiter] and [SessionResolver], never on their
// implementations, so that it can be tested in isolation. Errors are
// rendered as RFC 9457 Problem Details through internal/api/problem, with
// the request identifier as the "instance" member.
package middleware
