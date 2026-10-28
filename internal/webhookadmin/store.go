package webhookadmin

import (
	"context"
	"errors"
	"fmt"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhook"
)

// Subscribers returns the references of the enabled webhooks of tenantID
// subscribed to t, or of the instance-wide ones when tenantID is "". It
// unseals nothing: the URL and the secret are unsealed by [Service.Target]
// right before each attempt. The webhooks of a tenant are read under that
// tenant's scope only, so that an event of a tenant never reaches the
// webhook of another one (T-179), and the instance-wide webhooks only hold
// system events (P30). A missing tenant, a malformed tenant ID, or a
// tenant being deleted, has no subscribers.
func (s *Service) Subscribers(ctx context.Context, tenantID string, t events.Type) ([]webhook.Ref, error) {
	o, _, ok, err := s.deliveryOwner(ctx, tenantID)
	if !ok || err != nil {
		return nil, err
	}
	list, err := o.subscribed(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("webhookadmin: list subscribers: %w", err)
	}
	out := make([]webhook.Ref, 0, len(list))
	for _, w := range list {
		out = append(out, webhook.Ref{ID: w.ID, TenantID: string(o.tenant()), CircuitOpenUntil: w.CircuitOpenUntil})
	}
	return out, nil
}

// deliveryOwner returns the owner of the webhooks of tenantID ("" for the
// instance) and the tenant (nil for the instance). ok is false when the
// tenant is missing, malformed or being deleted: it has no webhook to
// call.
func (s *Service) deliveryOwner(ctx context.Context, tenantID string) (o owner, tn *tenant.Tenant, ok bool, err error) {
	if tenantID == "" {
		return s.systemOwner, nil, true, nil
	}
	tn, err = s.getTenant(ctx, tenant.ID(tenantID))
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return nil, nil, false, nil
	case err != nil:
		return nil, nil, false, fmt.Errorf("webhookadmin: get tenant: %w", err)
	case tn.Status != tenant.StatusActive:
		return nil, nil, false, nil
	}
	return s.tenantOwner(tn.ID), tn, true, nil
}

// Target re-reads the webhook whkID of tenantID ("" for an instance-wide
// webhook), in that tenant's scope only (T-179), and returns it unsealed
// with its current settings, before an attempt of the dispatcher. ok is
// false when the webhook is gone (or malformed), disabled, or its tenant
// is missing or being deleted. The result must never be logged.
//
// The webhook and its keys are read one after the other: a concurrent
// change of its URL or rotation of its secret can destroy a key between
// the two reads. A key not found is therefore read again once, with the
// webhook; a key still missing then means the webhook is being changed or
// deleted, and ok is false without an error.
func (s *Service) Target(ctx context.Context, tenantID, whkID string) (webhook.Target, bool, error) {
	o, tn, ok, err := s.deliveryOwner(ctx, tenantID)
	if !ok || err != nil {
		return webhook.Target{}, false, err
	}
	for retried := false; ; retried = true {
		w, err := o.get(ctx, whkID)
		switch {
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
			return webhook.Target{}, false, nil
		case err != nil:
			return webhook.Target{}, false, fmt.Errorf("webhookadmin: get webhook: %w", err)
		case !w.Enabled:
			return webhook.Target{}, false, nil
		}
		target, err := s.target(ctx, o, w, tn)
		switch {
		case err == nil:
			return target, true, nil
		case !errors.Is(err, store.ErrNotFound):
			return webhook.Target{}, false, fmt.Errorf("webhookadmin: unseal webhook %s: %w", w.ID, err)
		case retried:
			return webhook.Target{}, false, nil
		}
	}
}

// RecordDelivery records the state of a delivery to the webhook whkID of
// tenantID ("" for an instance-wide webhook), in that tenant's scope,
// while the webhook keeps the version d.Version. A webhook deleted or
// changed in the meantime is not an error: nothing is recorded.
func (s *Service) RecordDelivery(ctx context.Context, tenantID, whkID string, d webhook.Delivery) error {
	o := s.systemOwner
	if tenantID != "" {
		o = s.tenantOwner(tenant.ID(tenantID))
	}
	err := o.record(ctx, whkID, store.WebhookDeliveryState{
		Version: d.Version,
		Last: store.WebhookDelivery{
			At: d.At, Success: d.Result.Success, HTTPStatus: d.Result.HTTPStatus, Duration: d.Result.Duration,
			ErrorCategory: string(d.Result.Category),
		},
		ConsecutiveFailures: d.ConsecutiveFailures, CircuitOpenUntil: d.CircuitOpenUntil,
	})
	if err != nil {
		return fmt.Errorf("webhookadmin: record delivery: %w", err)
	}
	return nil
}
