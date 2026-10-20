// Package tenant models a TransTeira entity (tenant) and resolves the tenant
// of an incoming request from its HTTP Host header.
//
// Every request is bound to exactly one tenant: the HTTP middleware
// normalises the Host header with [NormalizeHost], resolves it with a
// [Resolver] and stores the result in the request context with [WithTenant].
// Downstream code reads it back with [FromContext] or [IDFromContext]. There is
// no default tenant: an unknown host yields [ErrUnknownTenant] and must be
// rejected.
package tenant
