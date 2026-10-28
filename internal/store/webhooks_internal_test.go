package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// webhookFixture is a fault-injecting database holding one generic webhook
// of a tenant and one of the instance.
type webhookFixture struct {
	db        *DB
	plan      *faultPlan
	tid       tenant.ID
	tenantWhk Webhook
	systemWhk Webhook
}

// newWebhookFixture builds a webhookFixture.
func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	ctx := context.Background()
	db, plan := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	f := &webhookFixture{db: db, plan: plan, tid: tn.ID}
	f.tenantWhk, err = f.createTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.systemWhk, err = f.createSystem(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// tenantKey stores a wrapped secret of the tenant.
func (f *webhookFixture) tenantKey(ctx context.Context) string {
	k := WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeSecret, KeyID: "mk_0123456789abcdef", Blob: []byte("x")}
	_ = f.db.WrappedKeys().Create(ctx, f.tid, k)
	return k.ID
}

// systemKey stores a webhook system secret.
func (f *webhookFixture) systemKey(ctx context.Context) string {
	s := SystemSecret{ID: id.New(id.SystemSecret), Purpose: SecretPurposeWebhook, KeyID: "mk_0123456789abcdef", Blob: []byte("x")}
	_ = f.db.SystemSecrets().Create(ctx, s)
	return s.ID
}

// createTenant creates a generic tenant webhook.
func (f *webhookFixture) createTenant(ctx context.Context) (Webhook, error) {
	w := Webhook{
		ID: id.New(id.Webhook), Name: "n", Kind: WebhookGeneric, URLKeyID: f.tenantKey(ctx), URLHint: "https://h.example.com",
		SecretKeyID: f.tenantKey(ctx), Events: []events.Type{events.VirusDetected}, Enabled: true, CreatedBy: "admin",
	}
	var got Webhook
	err := f.tenantTx(ctx, func(tx *ScopedTx) error {
		var err error
		got, err = f.db.Webhooks().CreateTx(ctx, tx, w)
		return err
	})
	return got, err
}

// createSystem creates a generic instance-wide webhook.
func (f *webhookFixture) createSystem(ctx context.Context) (Webhook, error) {
	w := Webhook{
		ID: id.New(id.Webhook), Name: "n", Kind: WebhookGeneric, URLKeyID: f.systemKey(ctx), URLHint: "https://h.example.com",
		SecretKeyID: f.systemKey(ctx), Events: []events.Type{events.DiskAlertRaised}, Enabled: true, CreatedBy: "admin",
	}
	var got Webhook
	err := f.db.systemScope(reasonSystemWebhooks).Tx(ctx, func(tx *SystemTx) error {
		var err error
		got, err = f.db.SystemWebhooks().CreateTx(ctx, tx, w)
		return err
	})
	return got, err
}

// tenantTx runs fn in a write transaction of the tenant.
func (f *webhookFixture) tenantTx(ctx context.Context, fn func(tx *ScopedTx) error) error {
	sc, _ := f.db.Scoped(f.tid)
	return sc.Tx(ctx, fn)
}

// updateTenant enables the tenant webhook.
func (f *webhookFixture) updateTenant() error {
	ctx := context.Background()
	return f.tenantTx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.Webhooks().UpdateTx(ctx, tx, f.tenantWhk.ID, WebhookChange{Enabled: new(true)})
		return err
	})
}

// updateSystem enables the instance-wide webhook.
func (f *webhookFixture) updateSystem() error {
	ctx := context.Background()
	return f.db.systemScope(reasonSystemWebhooks).Tx(ctx, func(tx *SystemTx) error {
		_, err := f.db.SystemWebhooks().UpdateTx(ctx, tx, f.systemWhk.ID, WebhookChange{Enabled: new(true)})
		return err
	})
}

// TestWebhookDriverFaults reaches the error paths of the webhook
// repositories that a healthy database never takes.
func TestWebhookDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newWebhookFixture(t)
	tenantDelete := func() error {
		return f.tenantTx(ctx, func(tx *ScopedTx) error { return f.db.Webhooks().DeleteTx(ctx, tx, f.tenantWhk.ID) })
	}
	systemDelete := func() error {
		return f.db.systemScope(reasonSystemWebhooks).Tx(ctx, func(tx *SystemTx) error {
			return f.db.SystemWebhooks().DeleteTx(ctx, tx, f.systemWhk.ID)
		})
	}
	state := WebhookDeliveryState{Last: WebhookDelivery{At: time.Now(), Success: true}, Version: time.Now()}
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"count", faultQuery, "SELECT count(*) FROM webhooks WHERE tenant_id = ?", func() error { _, err := f.createTenant(ctx); return err }},
		{"list query", faultQuery, "FROM webhooks WHERE tenant_id = ? ORDER BY", func() error { _, err := f.db.Webhooks().List(ctx, f.tid); return err }},
		{"subscribers", faultQuery, "FROM webhooks WHERE tenant_id = ? ORDER BY", func() error {
			_, err := f.db.Webhooks().ListSubscribed(ctx, f.tid, events.VirusDetected)
			return err
		}},
		{"update exec", faultExec, "UPDATE webhooks SET name", f.updateTenant},
		{"close breaker", faultExec, "UPDATE webhooks SET consecutive_failures = 0", f.updateTenant},
		{"delete exec", faultExec, "DELETE FROM webhooks", tenantDelete},
		{"delete rows", faultRows, "DELETE FROM webhooks", tenantDelete},
		{"delete probe", faultQuery, "SELECT count(*) FROM webhooks WHERE tenant_id = ? AND id = ?", tenantDelete},
		{"record", faultExec, "UPDATE webhooks SET last_delivery_at", func() error {
			return f.db.Webhooks().RecordDelivery(ctx, f.tid, f.tenantWhk.ID, state)
		}},
		{"system count", faultQuery, "SELECT count(*) FROM system_webhooks", func() error { _, err := f.createSystem(ctx); return err }},
		{"system list", faultQuery, "FROM system_webhooks ORDER BY", func() error { _, err := f.db.SystemWebhooks().List(ctx); return err }},
		{"system subscribers", faultQuery, "FROM system_webhooks ORDER BY", func() error {
			_, err := f.db.SystemWebhooks().ListSubscribed(ctx, events.DiskAlertRaised)
			return err
		}},
		{"system update exec", faultExec, "UPDATE system_webhooks SET name", f.updateSystem},
		{"system close breaker", faultExec, "UPDATE system_webhooks SET consecutive_failures = 0", f.updateSystem},
		{"system delete exec", faultExec, "DELETE FROM system_webhooks", systemDelete},
		{"system delete rows", faultRows, "DELETE FROM system_webhooks", systemDelete},
		{"system delete probe", faultQuery, "SELECT count(*) FROM system_webhooks WHERE id = ?", systemDelete},
		{"system record", faultExec, "UPDATE system_webhooks SET last_delivery_at", func() error {
			return f.db.SystemWebhooks().RecordDelivery(ctx, f.systemWhk.ID, state)
		}},
		{"system secret delete", faultExec, "DELETE FROM system_secrets", func() error {
			return f.db.systemScope(reasonSystemWebhooks).Tx(ctx, func(tx *SystemTx) error {
				return f.db.SystemSecrets().DeleteTx(ctx, tx, f.systemWhk.URLKeyID)
			})
		}},
	} {
		f.plan.reset()
		f.plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || !errors.Is(err, errInjected) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	f.plan.reset()

	// A corrupted events column is reported, never half-decoded.
	if _, err := rawSystemExec(ctx, f.db, `UPDATE webhooks SET events = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Webhooks().Get(ctx, f.tid, f.tenantWhk.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get with corrupted events = %v, want a decoding error", err)
	}
}

// TestWebhookLockFailure checks that a failing lock (PostgreSQL only)
// aborts a creation.
func TestWebhookLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newWebhookFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	if _, err := f.createTenant(ctx); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("tenant Create with a failing lock = %v", err)
	}
	if _, err := f.createSystem(ctx); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("system Create with a failing lock = %v", err)
	}
}
