package isolation_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// webhookKey stores a wrapped secret of tid (a sealed URL or signing
// secret, opaque here) and returns its ID.
func webhookKey(t *testing.T, db *store.DB, tid tenant.ID) string {
	t.Helper()
	k := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeSecret, KeyID: "mk_0000000000000001", Blob: []byte("sealed")}
	if err := db.WrappedKeys().Create(t.Context(), tid, k); err != nil {
		t.Fatalf("WrappedKeys.Create: %v", err)
	}
	return k.ID
}

// createWebhook stores a generic webhook of tid subscribed to
// virus.detected.
func createWebhook(t *testing.T, db *store.DB, tid tenant.ID) store.Webhook {
	t.Helper()
	w := store.Webhook{
		ID: id.New(id.Webhook), Name: "SIEM", Kind: store.WebhookGeneric, URLKeyID: webhookKey(t, db, tid),
		URLHint: "https://siem.example.com", SecretKeyID: webhookKey(t, db, tid),
		Events: []events.Type{events.VirusDetected}, Enabled: true, CreatedBy: "admin",
	}
	var got store.Webhook
	err := scopedTx(t, db, tid, func(tx *store.ScopedTx) error {
		var err error
		got, err = db.Webhooks().CreateTx(t.Context(), tx, w)
		return err
	})
	if err != nil {
		t.Fatalf("Webhooks.CreateTx: %v", err)
	}
	return got
}

// scopedTx runs fn in a write transaction of tid.
func scopedTx(t *testing.T, db *store.DB, tid tenant.ID, fn func(tx *store.ScopedTx) error) error {
	t.Helper()
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	return s.Tx(t.Context(), fn)
}

// TestWebhooksIsolation attacks A's webhook from tenant B through every
// repository method (T-179, T-186): B never reads, changes, deletes or
// records a delivery on it, cannot reuse A's sealed keys, an event of B
// never selects it, and the instance-wide webhooks are disjoint from the
// tenant ones.
func TestWebhooksIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		whkA := createWebhook(t, db, a.ID)
		whkB := createWebhook(t, db, b.ID)
		hooks := db.Webhooks()

		if _, err := hooks.Get(ctx, b.ID, whkA.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(A's webhook) from B = %v", err)
		}
		if list, err := hooks.List(ctx, b.ID); err != nil || len(list) != 1 || list[0].ID != whkB.ID {
			t.Errorf("List(B) = %+v, %v", list, err)
		}
		if subs, err := hooks.ListSubscribed(ctx, b.ID, events.VirusDetected); err != nil || len(subs) != 1 || subs[0].ID != whkB.ID {
			t.Errorf("ListSubscribed(B) = %+v, %v", subs, err)
		}
		err := scopedTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			_, err := hooks.UpdateTx(ctx, tx, whkA.ID, store.WebhookChange{Name: "Stolen", Enabled: new(false)})
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateTx(A's webhook) from B = %v", err)
		}
		err = scopedTx(t, db, b.ID, func(tx *store.ScopedTx) error { return hooks.DeleteTx(ctx, tx, whkA.ID) })
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteTx(A's webhook) from B = %v", err)
		}
		// The state carries the current version of A's webhook: only the
		// scope stops it.
		state := store.WebhookDeliveryState{
			Last: store.WebhookDelivery{At: time.Now()}, ConsecutiveFailures: 5, CircuitOpenUntil: time.Now().Add(time.Hour),
			Version: whkA.UpdatedAt,
		}
		if err := hooks.RecordDelivery(ctx, b.ID, whkA.ID, state); err != nil {
			t.Errorf("RecordDelivery(A's webhook) from B = %v", err)
		}
		// B cannot point its webhook at A's sealed URL or secret.
		err = scopedTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			_, err := hooks.UpdateTx(ctx, tx, whkB.ID, store.WebhookChange{URLKeyID: whkA.URLKeyID, URLHint: "https://x.example.com"})
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateTx(B) with A's url key = %v", err)
		}
		err = scopedTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			_, err := hooks.CreateTx(ctx, tx, store.Webhook{
				ID: id.New(id.Webhook), Name: "x", Kind: store.WebhookTeams, URLKeyID: whkA.URLKeyID, URLHint: "https://x.example.com",
				Events: []events.Type{events.VirusDetected}, CreatedBy: "x",
			})
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CreateTx in B with A's url key = %v", err)
		}
		got, err := hooks.Get(ctx, a.ID, whkA.ID)
		if err != nil || got.Name != whkA.Name || !got.Enabled || got.ConsecutiveFailures != 0 || got.URLKeyID != whkA.URLKeyID {
			t.Errorf("A's webhook after B's attempts = %+v, %v", got, err)
		}

		// The instance-wide webhooks never list a tenant webhook, and the
		// reverse.
		if _, err := db.SystemWebhooks().Get(ctx, whkA.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SystemWebhooks.Get(A's webhook) = %v", err)
		}
		if list, err := db.SystemWebhooks().List(ctx); err != nil || len(list) != 0 {
			t.Errorf("SystemWebhooks.List = %+v, %v", list, err)
		}
		if err := db.SystemWebhooks().RecordDelivery(ctx, whkA.ID, state); err != nil {
			t.Errorf("SystemWebhooks.RecordDelivery(A's webhook) = %v", err)
		}
		if got, _ := hooks.Get(ctx, a.ID, whkA.ID); got.ConsecutiveFailures != 0 {
			t.Errorf("a system record changed A's webhook: %+v", got)
		}

		// Deleting a tenant (keys destroyed first) removes its webhooks only.
		c := newTenant(t, db, "transfer.entity-c.example.com")
		createWebhook(t, db, c.ID)
		keys, err := db.WrappedKeys().ListIDs(ctx, c.ID, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if err := db.WrappedKeys().Delete(ctx, c.ID, k); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Tenants().Delete(ctx, c.ID); err != nil {
			t.Fatalf("Delete(C): %v", err)
		}
		if n := rawCount(t, e, "webhooks", "tenant_id", c.ID); n != 0 {
			t.Errorf("webhooks holds %d rows of deleted C", n)
		}
		if n := rawCount(t, e, "webhooks", "tenant_id", a.ID); n != 1 {
			t.Errorf("webhooks holds %d rows of A, want 1", n)
		}
	})
}

// TestRLSWebhooksCrossTenantRawSQL bypasses the application layer: a raw
// transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT statements
// at B's webhook and at the instance-wide webhooks. Row-level security
// alone must stop them.
func TestRLSWebhooksCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	createWebhook(t, f.db, f.a.ID)
	whkB := createWebhook(t, f.db, f.b.ID)
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM webhooks WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM webhooks`, nil, 1},
			{`SELECT count(*) FROM webhooks WHERE id = $1`, []any{whkB.ID}, 0},
			{`SELECT count(*) FROM webhooks WHERE true OR tenant_id = $1`, []any{b}, 1},
			{`SELECT count(*) FROM system_webhooks`, nil, 0},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE webhooks SET enabled = false WHERE tenant_id = $1`, []any{b}},
			{`UPDATE webhooks SET url_key_id = NULL WHERE id = $1`, []any{whkB.ID}},
			{`DELETE FROM webhooks WHERE tenant_id = $1`, []any{b}},
			{`UPDATE system_webhooks SET enabled = false`, nil},
			{`DELETE FROM system_webhooks`, nil},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows", s.stmt, n)
			}
		}
		return nil
	})

	for _, v := range []struct {
		name string
		stmt string
		args []any
	}{
		{
			"insert a webhook for B", `INSERT INTO webhooks (id, tenant_id, name, kind, url_hint, events, created_at,
			created_by, updated_at) VALUES ($1, $2, 'x', 'teams', 'https://x.example.com', '["virus.detected"]', 0, 'x', 0)`,
			[]any{id.New(id.Webhook), b},
		},
		{"move A's webhook to B", `UPDATE webhooks SET tenant_id = $1`, []any{b}},
		{
			"insert an instance-wide webhook", `INSERT INTO system_webhooks (id, name, kind, url_hint, events, created_at,
			created_by, updated_at) VALUES ($1, 'x', 'teams', 'https://x.example.com', '["disk.alert_raised"]', 0, 'x', 0)`,
			[]any{id.New(id.Webhook)},
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}
	got, err := f.db.Webhooks().Get(ctx, f.b.ID, whkB.ID)
	if err != nil || !got.Enabled || got.URLKeyID != whkB.URLKeyID {
		t.Errorf("B's webhook after the attacks = %+v, %v", got, err)
	}
}
