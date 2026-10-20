package tenant

import "context"

// ctxKey is the unexported type of the context key holding the tenant, so
// that no other package can read or overwrite it by accident.
type ctxKey struct{}

// WithTenant returns a copy of ctx carrying t. A nil t leaves ctx unchanged.
func WithTenant(ctx context.Context, t *Tenant) context.Context {
	if t == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, t)
}

// FromContext returns the tenant stored in ctx by [WithTenant], and whether
// one was present.
func FromContext(ctx context.Context) (*Tenant, bool) {
	t, ok := ctx.Value(ctxKey{}).(*Tenant)
	return t, ok
}

// IDFromContext returns the identifier of the tenant stored in ctx. It
// reports false when ctx carries no tenant or a tenant with an empty ID.
func IDFromContext(ctx context.Context) (ID, bool) {
	t, ok := FromContext(ctx)
	if !ok || t.ID.IsZero() {
		return "", false
	}
	return t.ID, true
}
