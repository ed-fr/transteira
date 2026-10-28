package webhookadmin

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhook"
)

// ListTenant returns the webhooks of tenant tid, oldest first.
func (s *Service) ListTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]store.Webhook, error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return nil, err
	}
	return s.list(ctx, s.tenantOwner(tid))
}

// GetTenant returns the webhook whkID of tenant tid.
func (s *Service) GetTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string) (store.Webhook, error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.Webhook{}, err
	}
	return s.get(ctx, s.tenantOwner(tid), whkID)
}

// CreateTenant creates a webhook of tenant tid, receiving tenant events
// only, and returns it with its signing secret for the generic kind. Its
// URL counts against URLChangeLimit per URLChangeWindow per administrator
// and tenant (*RateLimitError).
func (s *Service) CreateTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, in CreateInput, ip netip.Addr) (Result, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return Result{}, err
	}
	return s.create(ctx, p, s.tenantOwner(tid), in, ip, urlKey(p, tid))
}

// UpdateTenant applies the merge patch in to the webhook whkID of tenant
// tid. Enabling a webhook closes its circuit breaker; a new URL or secret
// destroys the previous one. A new URL counts against URLChangeLimit per
// URLChangeWindow per administrator and tenant (*RateLimitError).
func (s *Service) UpdateTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string, in UpdateInput, ip netip.Addr) (Result, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return Result{}, err
	}
	return s.update(ctx, p, s.tenantOwner(tid), whkID, in, ip, urlKey(p, tid))
}

// DeleteTenant deletes the webhook whkID of tenant tid, destroying its
// sealed URL and secret first.
func (s *Service) DeleteTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string, ip netip.Addr) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	return s.remove(ctx, p, s.tenantOwner(tid), whkID, ip)
}

// TestTenant sends a webhook.test event to the webhook whkID of tenant tid,
// even while its circuit breaker is open, and returns the outcome. It is
// limited to TestLimit per TestWindow per administrator and tenant
// (*RateLimitError). The test changes no delivery state.
func (s *Service) TestTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string, ip netip.Addr) (webhook.Result, error) {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return webhook.Result{}, err
	}
	return s.test(ctx, p, s.tenantOwner(tid), whkID, ip, urlKey(p, tid), t)
}

// ListSystem returns the instance-wide webhooks, oldest first (super
// admin).
func (s *Service) ListSystem(ctx context.Context, p adminauth.Principal) ([]store.Webhook, error) {
	if err := superAdmin(p); err != nil {
		return nil, err
	}
	return s.list(ctx, s.systemOwner)
}

// GetSystem returns the instance-wide webhook whkID (super admin).
func (s *Service) GetSystem(ctx context.Context, p adminauth.Principal, whkID string) (store.Webhook, error) {
	if err := superAdmin(p); err != nil {
		return store.Webhook{}, err
	}
	return s.get(ctx, s.systemOwner, whkID)
}

// CreateSystem creates an instance-wide webhook, receiving system events
// only (super admin). Its URL counts against URLChangeLimit per
// URLChangeWindow per administrator (*RateLimitError).
func (s *Service) CreateSystem(ctx context.Context, p adminauth.Principal, in CreateInput, ip netip.Addr) (Result, error) {
	if err := superAdmin(p); err != nil {
		return Result{}, err
	}
	return s.create(ctx, p, s.systemOwner, in, ip, urlKey(p, ""))
}

// UpdateSystem applies the merge patch in to the instance-wide webhook
// whkID (super admin), like [Service.UpdateTenant].
func (s *Service) UpdateSystem(ctx context.Context, p adminauth.Principal, whkID string, in UpdateInput, ip netip.Addr) (Result, error) {
	if err := superAdmin(p); err != nil {
		return Result{}, err
	}
	return s.update(ctx, p, s.systemOwner, whkID, in, ip, urlKey(p, ""))
}

// DeleteSystem deletes the instance-wide webhook whkID (super admin).
func (s *Service) DeleteSystem(ctx context.Context, p adminauth.Principal, whkID string, ip netip.Addr) error {
	if err := superAdmin(p); err != nil {
		return err
	}
	return s.remove(ctx, p, s.systemOwner, whkID, ip)
}

// TestSystem sends a webhook.test event to the instance-wide webhook whkID
// (super admin), limited to TestLimit per TestWindow per administrator.
func (s *Service) TestSystem(ctx context.Context, p adminauth.Principal, whkID string, ip netip.Addr) (webhook.Result, error) {
	if err := superAdmin(p); err != nil {
		return webhook.Result{}, err
	}
	return s.test(ctx, p, s.systemOwner, whkID, ip, urlKey(p, ""), nil)
}

// list returns the webhooks of o.
func (s *Service) list(ctx context.Context, o owner) ([]store.Webhook, error) {
	list, err := o.list(ctx)
	if err != nil {
		return nil, storeError("list webhooks", err)
	}
	return list, nil
}

// get returns the webhook whkID of o.
func (s *Service) get(ctx context.Context, o owner, whkID string) (store.Webhook, error) {
	w, err := o.get(ctx, whkID)
	if err != nil {
		return store.Webhook{}, storeError("get webhook", err)
	}
	return w, nil
}

// urlKey returns the rate limit key of administrator p on tenant tid (""
// for the instance-wide webhooks).
func urlKey(p adminauth.Principal, tid tenant.ID) string { return p.Admin.ID + "|" + string(tid) }

// create validates in and creates the webhook for o; key is the URL rate
// limit key.
func (s *Service) create(ctx context.Context, p adminauth.Principal, o owner, in CreateInput, ip netip.Addr, key string) (Result, error) {
	switch {
	case !validName(in.Name):
		return Result{}, invalid(FieldName, CodeInvalidFormat)
	case in.Kind != store.WebhookTeams && in.Kind != store.WebhookSlack && in.Kind != store.WebhookGeneric:
		return Result{}, invalid(FieldKind, CodeInvalidFormat)
	}
	if err := checkEvents(in.Events, o.allowed); err != nil {
		return Result{}, err
	}
	hint, err := s.checkURL(ctx, in.URL, key)
	if err != nil {
		return Result{}, err
	}
	w := store.Webhook{
		ID: id.New(id.Webhook), Name: in.Name, Kind: in.Kind, URLHint: hint, Events: in.Events,
		Enabled: in.Enabled == nil || *in.Enabled, CreatedBy: p.Admin.Username, CreatedAt: s.now(),
	}
	var secret []byte
	if w.Kind == store.WebhookGeneric {
		secret = newSecret()
	}
	created, err := o.create(ctx, w, []byte(in.URL), secret)
	if err != nil {
		return Result{}, storeError("create webhook", err)
	}
	s.record(ctx, p, ip, o, audit.ActionWebhookCreated, created.ID, map[string]any{
		"kind": string(created.Kind), "events": eventNames(created.Events), "host": hostOf(created.URLHint),
	})
	return Result{Webhook: created, Secret: string(secret)}, nil
}

// update validates in and applies it to the webhook whkID of o; key is
// the URL rate limit key.
func (s *Service) update(ctx context.Context, p adminauth.Principal, o owner, whkID string, in UpdateInput, ip netip.Addr, key string) (Result, error) {
	c := change{enabled: in.Enabled, at: s.now()}
	if in.Name != nil {
		if !validName(*in.Name) {
			return Result{}, invalid(FieldName, CodeInvalidFormat)
		}
		c.name = *in.Name
	}
	if in.Events != nil {
		if err := checkEvents(in.Events, o.allowed); err != nil {
			return Result{}, err
		}
		c.events = in.Events
	}
	if in.URL != nil {
		hint, err := s.checkURL(ctx, *in.URL, key)
		if err != nil {
			return Result{}, err
		}
		c.url, c.hint = []byte(*in.URL), hint
	}
	if in.RotateSecret {
		c.secret = newSecret()
	}
	before, after, err := o.update(ctx, whkID, c)
	if err != nil {
		return Result{}, storeError("update webhook", err)
	}
	if in.URL != nil || in.RotateSecret {
		s.scrub(ctx)
	}
	s.record(ctx, p, ip, o, audit.ActionWebhookUpdated, whkID, map[string]any{
		"kind": string(after.Kind), "fields": changedFields(before, after, in),
	})
	return Result{Webhook: after, Secret: string(c.secret)}, nil
}

// changedFields returns the API names of the fields that in changed from
// before to after: a new URL or secret always counts as a change.
func changedFields(before, after store.Webhook, in UpdateInput) []string {
	out := []string{}
	for _, f := range []struct {
		changed bool
		name    string
	}{
		{before.Name != after.Name, "name"},
		{in.URL != nil, "url"},
		{!slices.Equal(before.Events, after.Events), "events"},
		{before.Enabled != after.Enabled, "enabled"},
		{in.RotateSecret, "rotateSecret"},
	} {
		if f.changed {
			out = append(out, f.name)
		}
	}
	return out
}

// remove deletes the webhook whkID of o.
func (s *Service) remove(ctx context.Context, p adminauth.Principal, o owner, whkID string, ip netip.Addr) error {
	removed, err := o.remove(ctx, whkID)
	if err != nil {
		return storeError("delete webhook", err)
	}
	s.scrub(ctx)
	s.record(ctx, p, ip, o, audit.ActionWebhookDeleted, whkID, map[string]any{
		"kind": string(removed.Kind), "host": hostOf(removed.URLHint),
	})
	return nil
}

// test sends the test event to the webhook whkID of o, of tenant t (nil
// for the instance), limited per key.
func (s *Service) test(ctx context.Context, p adminauth.Principal, o owner, whkID string, ip netip.Addr, key string,
	t *tenant.Tenant,
) (webhook.Result, error) {
	if ok, retry := s.tests.Allow(key); !ok {
		return webhook.Result{}, &RateLimitError{RetryAfter: max(retry, time.Second)}
	}
	w, err := s.get(ctx, o, whkID)
	if err != nil {
		return webhook.Result{}, err
	}
	target, err := s.target(ctx, o, w, t)
	if err != nil {
		return webhook.Result{}, storeError("unseal webhook", err)
	}
	res := s.tester.SendTest(ctx, target, s.now())
	s.record(ctx, p, ip, o, audit.ActionWebhookTested, whkID, map[string]any{
		"success": res.Success, "category": string(res.Category),
	})
	return res, nil
}

// target unseals the URL and secret of w, a webhook of o and of tenant t
// (nil for the instance). The result must never be logged.
func (s *Service) target(ctx context.Context, o owner, w store.Webhook, t *tenant.Tenant) (webhook.Target, error) {
	url, err := o.open(ctx, w.URLKeyID)
	if err != nil {
		return webhook.Target{}, err
	}
	target := webhook.Target{
		ID: w.ID, Kind: webhook.Kind(w.Kind), URL: string(url), Events: w.Events, Version: w.UpdatedAt,
		ConsecutiveFailures: w.ConsecutiveFailures, CircuitOpenUntil: w.CircuitOpenUntil,
	}
	if t != nil {
		target.TenantID, target.TenantName, target.IncludeAddresses = string(t.ID), t.Name, t.WebhookIncludeAddresses
	}
	if w.SecretKeyID != "" {
		if target.Secret, err = o.open(ctx, w.SecretKeyID); err != nil {
			return webhook.Target{}, err
		}
	}
	return target, nil
}
