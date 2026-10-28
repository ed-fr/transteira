package store_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// secretKey stores a new wrapped secret for tid and returns its ID.
func secretKey(t *testing.T, db *store.DB, tid tenant.ID) string {
	t.Helper()
	k := newWrappedKey(mk1, "sealed")
	k.Purpose = store.KeyPurposeSecret
	return mustCreateKey(t, db, tid, k).ID
}

// systemWebhookSecret stores a new system secret of purpose purpose and
// returns its ID.
func systemWebhookSecret(t *testing.T, db *store.DB, purpose string) string {
	t.Helper()
	s := store.SystemSecret{ID: id.New(id.SystemSecret), Purpose: purpose, KeyID: mk1, Blob: []byte("sealed")}
	if err := db.SystemSecrets().Create(context.Background(), s); err != nil {
		t.Fatalf("Create system secret: %v", err)
	}
	return s.ID
}

// newWebhook returns a valid new webhook of kind with the given keys.
func newWebhook(kind store.WebhookKind, urlKey, secretKey string, evs ...events.Type) store.Webhook {
	return store.Webhook{
		ID: id.New(id.Webhook), Name: "Security channel", Kind: kind, URLKeyID: urlKey,
		URLHint: "https://hooks.example.com", SecretKeyID: secretKey, Events: evs, Enabled: true,
		CreatedBy: "admin.a",
	}
}

// scopedTx runs fn in a write transaction of tid.
func scopedTx(ctx context.Context, t *testing.T, db *store.DB, tid tenant.ID, fn func(tx *store.ScopedTx) error) error {
	t.Helper()
	sc, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	return sc.Tx(ctx, fn)
}

// systemTx runs fn in a system write transaction.
func systemTx(ctx context.Context, t *testing.T, db *store.DB, fn func(tx *store.SystemTx) error) error {
	t.Helper()
	sys, err := db.System("test")
	if err != nil {
		t.Fatal(err)
	}
	return sys.Tx(ctx, fn)
}

// createWebhook stores w for tid and returns it.
func createWebhook(t *testing.T, db *store.DB, tid tenant.ID, w store.Webhook) (store.Webhook, error) {
	t.Helper()
	ctx := context.Background()
	var got store.Webhook
	err := scopedTx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		var err error
		got, err = db.Webhooks().CreateTx(ctx, tx, w)
		return err
	})
	return got, err
}

// updateWebhook applies c to the webhook whkID of tid.
func updateWebhook(t *testing.T, db *store.DB, tid tenant.ID, whkID string, c store.WebhookChange) (store.Webhook, error) {
	t.Helper()
	ctx := context.Background()
	var got store.Webhook
	err := scopedTx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		var err error
		got, err = db.Webhooks().UpdateTx(ctx, tx, whkID, c)
		return err
	})
	return got, err
}

// createSystemWebhook stores the instance-wide webhook w.
func createSystemWebhook(t *testing.T, db *store.DB, w store.Webhook) (store.Webhook, error) {
	t.Helper()
	ctx := context.Background()
	var got store.Webhook
	err := systemTx(ctx, t, db, func(tx *store.SystemTx) error {
		var err error
		got, err = db.SystemWebhooks().CreateTx(ctx, tx, w)
		return err
	})
	return got, err
}

// updateSystemWebhook applies c to the instance-wide webhook whkID.
func updateSystemWebhook(t *testing.T, db *store.DB, whkID string, c store.WebhookChange) (store.Webhook, error) {
	t.Helper()
	ctx := context.Background()
	var got store.Webhook
	err := systemTx(ctx, t, db, func(tx *store.SystemTx) error {
		var err error
		got, err = db.SystemWebhooks().UpdateTx(ctx, tx, whkID, c)
		return err
	})
	return got, err
}

// webhookIDs returns the identifiers of list.
func webhookIDs(list []store.Webhook) []string {
	out := make([]string, len(list))
	for i, w := range list {
		out[i] = w.ID
	}
	return out
}

func TestWebhooksCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Webhooks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		gen := newWebhook(store.WebhookGeneric, secretKey(t, db, a.ID), secretKey(t, db, a.ID),
			events.VirusDetected, events.QuotaReached)
		created, err := createWebhook(t, db, a.ID, gen)
		if err != nil {
			t.Fatalf("Create generic = %v", err)
		}
		at := fixedNow.Truncate(time.Millisecond)
		if !created.CreatedAt.Equal(at) || !created.UpdatedAt.Equal(at) || !created.HasSecret() {
			t.Errorf("Create = %+v", created)
		}
		got, err := repo.Get(ctx, a.ID, gen.ID)
		if err != nil || !reflect.DeepEqual(got, created) {
			t.Errorf("Get = %+v, %v; want %+v", got, err, created)
		}
		teams := newWebhook(store.WebhookTeams, secretKey(t, db, a.ID), "", events.AbuseReported)
		teams.CreatedAt = fixedNow.Add(time.Hour)
		teams.Enabled = false
		if _, err := createWebhook(t, db, a.ID, teams); err != nil {
			t.Fatalf("Create teams = %v", err)
		}

		// Tenant B sees none of them.
		if _, err := repo.Get(ctx, b.ID, gen.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get from B = %v", err)
		}
		if list, err := repo.List(ctx, b.ID); err != nil || len(list) != 0 {
			t.Errorf("List B = %v, %v", list, err)
		}
		list, err := repo.List(ctx, a.ID)
		if err != nil || !reflect.DeepEqual(webhookIDs(list), []string{gen.ID, teams.ID}) {
			t.Errorf("List A = %v, %v", webhookIDs(list), err)
		}

		// Subscribers: enabled and subscribed only.
		if subs, err := repo.ListSubscribed(ctx, a.ID, events.VirusDetected); err != nil ||
			!reflect.DeepEqual(webhookIDs(subs), []string{gen.ID}) {
			t.Errorf("ListSubscribed virus = %v, %v", webhookIDs(subs), err)
		}
		if subs, err := repo.ListSubscribed(ctx, a.ID, events.AbuseReported); err != nil || len(subs) != 0 {
			t.Errorf("ListSubscribed disabled = %v, %v", webhookIDs(subs), err)
		}
		if subs, err := repo.ListSubscribed(ctx, b.ID, events.VirusDetected); err != nil || len(subs) != 0 {
			t.Errorf("ListSubscribed B = %v, %v", webhookIDs(subs), err)
		}
		if _, err := repo.ListSubscribed(ctx, "", events.VirusDetected); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("ListSubscribed without tenant = %v", err)
		}

		// Delivery state, then re-enabling closes the breaker.
		open := fixedNow.Add(15 * time.Minute).Truncate(time.Millisecond)
		state := store.WebhookDeliveryState{
			Last: store.WebhookDelivery{
				At: fixedNow, HTTPStatus: 502, Duration: 1500 * time.Millisecond, ErrorCategory: "http_status",
			},
			ConsecutiveFailures: 5, CircuitOpenUntil: open, Version: created.UpdatedAt,
		}
		if err := repo.RecordDelivery(ctx, a.ID, gen.ID, state); err != nil {
			t.Fatal(err)
		}
		got, _ = repo.Get(ctx, a.ID, gen.ID)
		want := store.WebhookDelivery{At: at, HTTPStatus: 502, Duration: 1500 * time.Millisecond, ErrorCategory: "http_status"}
		if got.LastDelivery != want || got.ConsecutiveFailures != 5 || !got.CircuitOpenUntil.Equal(open) ||
			!got.UpdatedAt.Equal(created.UpdatedAt) {
			t.Errorf("after a failure = %+v", got)
		}
		// A delivery computed from another version records nothing.
		stale := state
		stale.Version, stale.ConsecutiveFailures = created.UpdatedAt.Add(-time.Millisecond), 1
		if err := repo.RecordDelivery(ctx, a.ID, gen.ID, stale); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Get(ctx, a.ID, gen.ID); got.ConsecutiveFailures != 5 {
			t.Errorf("stale delivery recorded: %+v", got)
		}
		ok := store.WebhookDeliveryState{
			Last: store.WebhookDelivery{At: fixedNow, Success: true, HTTPStatus: 200}, Version: fixedNow.Add(time.Hour),
		}
		if err := repo.RecordDelivery(ctx, a.ID, teams.ID, ok); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Get(ctx, a.ID, teams.ID); !got.LastDelivery.Success || got.LastDelivery.ErrorCategory != "" {
			t.Errorf("after a success = %+v", got.LastDelivery)
		}
		// A missing webhook, or one of another tenant, is not an error.
		okGen := ok
		okGen.Version = created.UpdatedAt
		if err := repo.RecordDelivery(ctx, b.ID, gen.ID, okGen); err != nil {
			t.Errorf("RecordDelivery from B = %v", err)
		}
		if got, _ := repo.Get(ctx, a.ID, gen.ID); got.LastDelivery.Success {
			t.Error("tenant B changed the delivery state of tenant A")
		}
		if err := repo.RecordDelivery(ctx, "", gen.ID, ok); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RecordDelivery without tenant = %v", err)
		}

		newURL, newSecret := secretKey(t, db, a.ID), secretKey(t, db, a.ID)
		later := fixedNow.Add(2 * time.Hour)
		upd, err := updateWebhook(t, db, a.ID, gen.ID, store.WebhookChange{
			Name: "Renamed", URLKeyID: newURL, URLHint: "https://other.example.com", SecretKeyID: newSecret,
			Events: []events.Type{events.AbuseReported}, Enabled: ptr(true), UpdatedAt: later,
		})
		if err != nil || upd.Name != "Renamed" || upd.URLKeyID != newURL || upd.URLHint != "https://other.example.com" ||
			upd.SecretKeyID != newSecret || !reflect.DeepEqual(upd.Events, []events.Type{events.AbuseReported}) ||
			upd.ConsecutiveFailures != 0 || !upd.CircuitOpenUntil.IsZero() || !upd.UpdatedAt.Equal(later.Truncate(time.Millisecond)) {
			t.Fatalf("Update = %+v, %v", upd, err)
		}
		if got, _ := repo.Get(ctx, a.ID, gen.ID); !reflect.DeepEqual(got, upd) {
			t.Errorf("Get after update = %+v, want %+v", got, upd)
		}
		// An empty change keeps everything (but the update time); disabling
		// keeps the breaker.
		state.Version = upd.UpdatedAt
		if err := repo.RecordDelivery(ctx, a.ID, gen.ID, state); err != nil {
			t.Fatal(err)
		}
		upd, err = updateWebhook(t, db, a.ID, gen.ID, store.WebhookChange{Enabled: ptr(false)})
		if err != nil || upd.Enabled || upd.Name != "Renamed" || upd.ConsecutiveFailures != 5 {
			t.Errorf("disable = %+v, %v", upd, err)
		}
		// Every change moves the version forward, even when the clock says
		// otherwise: a delivery in flight based on the previous version is
		// not recorded, so that re-enabling wins.
		prev := upd.UpdatedAt
		upd, err = updateWebhook(t, db, a.ID, gen.ID, store.WebhookChange{Enabled: ptr(true), UpdatedAt: prev.Add(-time.Hour)})
		if err != nil || !upd.UpdatedAt.Equal(prev.Add(time.Millisecond)) || upd.ConsecutiveFailures != 0 {
			t.Fatalf("re-enable = %+v, %v", upd, err)
		}
		state.Version = prev
		if err := repo.RecordDelivery(ctx, a.ID, gen.ID, state); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Get(ctx, a.ID, gen.ID); got.ConsecutiveFailures != 0 || !got.CircuitOpenUntil.IsZero() {
			t.Errorf("an in-flight delivery undid the re-enabling: %+v", got)
		}
		// A change computed from a stale version is refused, and changes
		// nothing; computed from the current version, it applies.
		if _, err := updateWebhook(t, db, a.ID, gen.ID, store.WebhookChange{Name: "Stale", Version: prev}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Update from a stale version = %v", err)
		}
		if got, _ := repo.Get(ctx, a.ID, gen.ID); got.Name != "Renamed" || !got.UpdatedAt.Equal(upd.UpdatedAt) {
			t.Errorf("a stale update changed the webhook: %+v", got)
		}
		if got, err := updateWebhook(t, db, a.ID, gen.ID, store.WebhookChange{Name: "Current", Version: upd.UpdatedAt}); err != nil || got.Name != "Current" {
			t.Errorf("Update from the current version = %+v, %v", got, err)
		}

		// Deleting needs the keys destroyed first (D23).
		del := func(tid tenant.ID, whkID string) error {
			return scopedTx(ctx, t, db, tid, func(tx *store.ScopedTx) error { return repo.DeleteTx(ctx, tx, whkID) })
		}
		if err := del(a.ID, gen.ID); !errors.Is(err, store.ErrKeysRemain) {
			t.Errorf("Delete with keys = %v", err)
		}
		if err := del(b.ID, gen.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete from B = %v", err)
		}
		err = scopedTx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			w, err := repo.GetTx(ctx, tx, gen.ID)
			if err != nil {
				return err
			}
			if err := db.WrappedKeys().DeleteTx(ctx, tx, w.URLKeyID); err != nil {
				return err
			}
			if err := db.WrappedKeys().DeleteTx(ctx, tx, w.SecretKeyID); err != nil {
				return err
			}
			return repo.DeleteTx(ctx, tx, gen.ID)
		})
		if err != nil {
			t.Fatalf("Delete = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, gen.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get after delete = %v", err)
		}
		err = scopedTx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := repo.GetTx(ctx, tx, gen.ID)
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetTx after delete = %v", err)
		}
		// A webhook whose URL key was destroyed (tenant deletion) reads
		// without it.
		w, _ := repo.Get(ctx, a.ID, teams.ID)
		if err := db.WrappedKeys().Delete(ctx, a.ID, w.URLKeyID); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID, teams.ID); err != nil || got.URLKeyID != "" {
			t.Errorf("Get without url key = %+v, %v", got, err)
		}
	})
}

func TestWebhooksValidation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		urlKey, secret := secretKey(t, db, a.ID), secretKey(t, db, a.ID)
		valid := func() store.Webhook { return newWebhook(store.WebhookGeneric, urlKey, secret, events.VirusDetected) }

		for name, mutate := range map[string]func(*store.Webhook){
			"id":               func(w *store.Webhook) { w.ID = id.New(id.APIToken) },
			"name":             func(w *store.Webhook) { w.Name = "" },
			"name line":        func(w *store.Webhook) { w.Name = "a\nb" },
			"kind":             func(w *store.Webhook) { w.Kind = "email" },
			"url key":          func(w *store.Webhook) { w.URLKeyID = "" },
			"hint":             func(w *store.Webhook) { w.URLHint = strings.Repeat("h", store.MaxWebhookURLHintLen+1) },
			"generic secret":   func(w *store.Webhook) { w.SecretKeyID = "" },
			"teams secret":     func(w *store.Webhook) { w.Kind = store.WebhookSlack },
			"secret id":        func(w *store.Webhook) { w.SecretKeyID = "wk_bad" },
			"creator":          func(w *store.Webhook) { w.CreatedBy = "" },
			"delivered":        func(w *store.Webhook) { w.ConsecutiveFailures = 1 },
			"no event":         func(w *store.Webhook) { w.Events = nil },
			"system event":     func(w *store.Webhook) { w.Events = []events.Type{events.DiskAlertRaised} },
			"test event":       func(w *store.Webhook) { w.Events = []events.Type{events.WebhookTest} },
			"duplicate events": func(w *store.Webhook) { w.Events = []events.Type{events.QuotaReached, events.QuotaReached} },
		} {
			w := valid()
			mutate(&w)
			if _, err := createWebhook(t, db, a.ID, w); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create with a bad %s = %v", name, err)
			}
		}
		// Keys of another tenant, or of another purpose.
		w := valid()
		w.URLKeyID = secretKey(t, db, b.ID)
		if _, err := createWebhook(t, db, a.ID, w); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create with a key of B = %v", err)
		}
		w = valid()
		w.SecretKeyID = mustCreateKey(t, db, a.ID, newWrappedKey(mk1, "dek")).ID
		if _, err := createWebhook(t, db, a.ID, w); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Create with a data key = %v", err)
		}
		created, err := createWebhook(t, db, a.ID, valid())
		if err != nil {
			t.Fatal(err)
		}
		dup := valid()
		dup.ID = created.ID
		dup.URLKeyID, dup.SecretKeyID = secretKey(t, db, a.ID), secretKey(t, db, a.ID)
		if _, err := createWebhook(t, db, a.ID, dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create with a used id = %v", err)
		}
		if _, err := createWebhook(t, db, a.ID, newWebhook(store.WebhookTeams, urlKey, "", events.QuotaWarning)); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create with a used url key = %v", err)
		}

		// Changes.
		teams, err := createWebhook(t, db, a.ID, newWebhook(store.WebhookTeams, secretKey(t, db, a.ID), "", events.QuotaWarning))
		if err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]store.WebhookChange{
			"name":         {Name: "a\tb\nc"},
			"url key":      {URLKeyID: "wk_bad", URLHint: "https://x.example.com"},
			"hint":         {URLKeyID: secretKey(t, db, a.ID)},
			"secret id":    {SecretKeyID: "ss_bad"},
			"system event": {Events: []events.Type{events.MaintenanceEnabled}},
			"no event":     {Events: []events.Type{}},
		} {
			if _, err := updateWebhook(t, db, a.ID, created.ID, c); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Update with a bad %s = %v", name, err)
			}
		}
		if _, err := updateWebhook(t, db, a.ID, teams.ID, store.WebhookChange{SecretKeyID: secretKey(t, db, a.ID)}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update teams with a secret = %v", err)
		}
		if _, err := updateWebhook(t, db, a.ID, created.ID, store.WebhookChange{SecretKeyID: secretKey(t, db, b.ID)}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update with a secret of B = %v", err)
		}
		if _, err := updateWebhook(t, db, a.ID, created.ID, store.WebhookChange{
			URLKeyID: secretKey(t, db, b.ID), URLHint: "https://x.example.com",
		}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update with a url of B = %v", err)
		}
		if _, err := updateWebhook(t, db, b.ID, created.ID, store.WebhookChange{Name: "x"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update from B = %v", err)
		}
		if _, err := updateWebhook(t, db, a.ID, created.ID, store.WebhookChange{URLKeyID: teams.URLKeyID, URLHint: "https://x.example.com"}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Update with a used url key = %v", err)
		}

		// Delivery states.
		ctx := context.Background()
		v := fixedNow
		for name, s := range map[string]store.WebhookDeliveryState{
			"version":  {Last: store.WebhookDelivery{At: fixedNow}},
			"time":     {Version: v},
			"status":   {Version: v, Last: store.WebhookDelivery{At: fixedNow, HTTPStatus: 99}},
			"status 2": {Version: v, Last: store.WebhookDelivery{At: fixedNow, HTTPStatus: 600}},
			"duration": {Version: v, Last: store.WebhookDelivery{At: fixedNow, Duration: -1}},
			"failures": {Version: v, Last: store.WebhookDelivery{At: fixedNow}, ConsecutiveFailures: -1},
			"category": {Version: v, Last: store.WebhookDelivery{At: fixedNow, ErrorCategory: "a\nb"}},
		} {
			if err := db.Webhooks().RecordDelivery(ctx, a.ID, created.ID, s); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("RecordDelivery with a bad %s = %v", name, err)
			}
			if err := db.SystemWebhooks().RecordDelivery(ctx, created.ID, s); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("system RecordDelivery with a bad %s = %v", name, err)
			}
		}
	})
}

func TestWebhooksLimit(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		for range store.MaxWebhooks {
			if _, err := createWebhook(t, db, a.ID, newWebhook(store.WebhookSlack, secretKey(t, db, a.ID), "", events.QuotaReached)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := createWebhook(t, db, a.ID, newWebhook(store.WebhookSlack, secretKey(t, db, a.ID), "", events.QuotaReached)); !errors.Is(err, store.ErrLimitReached) {
			t.Errorf("Create above the limit = %v", err)
		}
		// The limit is per tenant.
		if _, err := createWebhook(t, db, b.ID, newWebhook(store.WebhookSlack, secretKey(t, db, b.ID), "", events.QuotaReached)); err != nil {
			t.Errorf("Create for B = %v", err)
		}
		for range store.MaxWebhooks {
			w := newWebhook(store.WebhookTeams, systemWebhookSecret(t, db, store.SecretPurposeWebhook), "", events.DiskAlertRaised)
			if _, err := createSystemWebhook(t, db, w); err != nil {
				t.Fatal(err)
			}
		}
		w := newWebhook(store.WebhookTeams, systemWebhookSecret(t, db, store.SecretPurposeWebhook), "", events.DiskAlertRaised)
		if _, err := createSystemWebhook(t, db, w); !errors.Is(err, store.ErrLimitReached) {
			t.Errorf("system Create above the limit = %v", err)
		}
	})
}

// TestWebhooksConcurrentUpdate runs a change that keeps the URL against a
// change of the URL that destroys the previous key: on PostgreSQL, the
// first one reads the webhook without a lock before the second commits,
// and must not write the destroyed key back (foreign key failure) nor
// overwrite the second one; it is refused with ErrConflict, or applies on
// top of it when it read the webhook after the commit.
func TestWebhooksConcurrentUpdate(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Webhooks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		w, err := createWebhook(t, db, a.ID, newWebhook(store.WebhookTeams, secretKey(t, db, a.ID), "", events.VirusDetected))
		if err != nil {
			t.Fatal(err)
		}
		newURL := secretKey(t, db, a.ID)
		updated, release := make(chan struct{}), make(chan struct{})
		readdressed := make(chan error, 1)
		go func() {
			readdressed <- scopedTx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				_, err := repo.UpdateTx(ctx, tx, w.ID, store.WebhookChange{URLKeyID: newURL, URLHint: "https://moved.example.com"})
				if err == nil {
					err = db.WrappedKeys().DeleteTx(ctx, tx, w.URLKeyID)
				}
				close(updated)
				<-release
				return err
			})
		}()
		<-updated
		renamed := make(chan error, 1)
		go func() {
			_, err := updateWebhook(t, db, a.ID, w.ID, store.WebhookChange{Name: "Renamed"})
			renamed <- err
		}()
		// Give the rename the time to read the webhook and wait on its row
		// (PostgreSQL); SQLite serializes it after the commit.
		time.Sleep(200 * time.Millisecond)
		close(release)
		if err := <-readdressed; err != nil {
			t.Fatalf("re-address = %v", err)
		}
		err = <-renamed
		if err != nil && !errors.Is(err, store.ErrConflict) {
			t.Errorf("concurrent rename = %v, want nil or ErrConflict", err)
		}
		got, gerr := repo.Get(ctx, a.ID, w.ID)
		if gerr != nil || got.URLKeyID != newURL || (err == nil) != (got.Name == "Renamed") {
			t.Errorf("after the concurrent updates = %+v, %v (rename: %v)", got, gerr, err)
		}
	})
}

func TestSystemWebhooksCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SystemWebhooks()
		secret := func() string { return systemWebhookSecret(t, db, store.SecretPurposeWebhook) }

		gen := newWebhook(store.WebhookGeneric, secret(), secret(), events.DiskAlertRaised, events.MaintenanceEnabled)
		created, err := createSystemWebhook(t, db, gen)
		if err != nil {
			t.Fatalf("Create = %v", err)
		}
		if got, err := repo.Get(ctx, gen.ID); err != nil || !reflect.DeepEqual(got, created) {
			t.Errorf("Get = %+v, %v; want %+v", got, err, created)
		}
		slack := newWebhook(store.WebhookSlack, secret(), "", events.AntivirusAlertRaised)
		slack.CreatedAt = fixedNow.Add(time.Minute)
		if _, err := createSystemWebhook(t, db, slack); err != nil {
			t.Fatal(err)
		}
		if list, err := repo.List(ctx); err != nil || !reflect.DeepEqual(webhookIDs(list), []string{gen.ID, slack.ID}) {
			t.Errorf("List = %v, %v", webhookIDs(list), err)
		}
		if subs, err := repo.ListSubscribed(ctx, events.MaintenanceEnabled); err != nil ||
			!reflect.DeepEqual(webhookIDs(subs), []string{gen.ID}) {
			t.Errorf("ListSubscribed = %v, %v", webhookIDs(subs), err)
		}
		if _, err := repo.Get(ctx, id.New(id.Webhook)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get unknown = %v", err)
		}

		// Validation: tenant events, keys of the wrong kind or purpose.
		bad := newWebhook(store.WebhookTeams, secret(), "", events.VirusDetected)
		if _, err := createSystemWebhook(t, db, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Create with a tenant event = %v", err)
		}
		bad = newWebhook(store.WebhookTeams, id.New(id.WrappedKey), "", events.DiskAlertCleared)
		if _, err := createSystemWebhook(t, db, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Create with a wrapped key id = %v", err)
		}
		bad = newWebhook(store.WebhookTeams, systemWebhookSecret(t, db, store.SecretPurposeAdminTOTP), "", events.DiskAlertCleared)
		if _, err := createSystemWebhook(t, db, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Create with a totp secret = %v", err)
		}
		bad = newWebhook(store.WebhookTeams, id.New(id.SystemSecret), "", events.DiskAlertCleared)
		if _, err := createSystemWebhook(t, db, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create with an unknown secret = %v", err)
		}
		if _, err := updateSystemWebhook(t, db, gen.ID, store.WebhookChange{Events: []events.Type{events.QuotaWarning}}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update with a tenant event = %v", err)
		}
		if _, err := updateSystemWebhook(t, db, gen.ID, store.WebhookChange{SecretKeyID: id.New(id.SystemSecret)}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update with an unknown secret = %v", err)
		}
		if _, err := updateSystemWebhook(t, db, id.New(id.Webhook), store.WebhookChange{Name: "x"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update unknown = %v", err)
		}

		// Delivery and breaker.
		state := store.WebhookDeliveryState{
			Last:                store.WebhookDelivery{At: fixedNow, ErrorCategory: "timeout", Duration: time.Second},
			ConsecutiveFailures: 5, CircuitOpenUntil: fixedNow.Add(time.Minute), Version: created.UpdatedAt,
		}
		if err := repo.RecordDelivery(ctx, gen.ID, state); err != nil {
			t.Fatal(err)
		}
		if err := repo.RecordDelivery(ctx, id.New(id.Webhook), state); err != nil {
			t.Errorf("RecordDelivery unknown = %v", err)
		}
		got, _ := repo.Get(ctx, gen.ID)
		if got.ConsecutiveFailures != 5 || got.LastDelivery.ErrorCategory != "timeout" || got.LastDelivery.HTTPStatus != 0 {
			t.Errorf("after a failure = %+v", got)
		}
		newURL, newSecret := secret(), secret()
		upd, err := updateSystemWebhook(t, db, gen.ID, store.WebhookChange{
			Name: "Ops", URLKeyID: newURL, URLHint: "https://ops.example.com", SecretKeyID: newSecret, Enabled: ptr(true),
		})
		if err != nil || upd.Name != "Ops" || upd.URLKeyID != newURL || upd.SecretKeyID != newSecret ||
			upd.ConsecutiveFailures != 0 || !upd.CircuitOpenUntil.IsZero() {
			t.Fatalf("Update = %+v, %v", upd, err)
		}
		if got, _ := repo.Get(ctx, gen.ID); !reflect.DeepEqual(got, upd) {
			t.Errorf("Get after update = %+v, want %+v", got, upd)
		}
		// The delivery based on the version before the update records
		// nothing.
		if err := repo.RecordDelivery(ctx, gen.ID, state); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Get(ctx, gen.ID); got.ConsecutiveFailures != 0 || !upd.UpdatedAt.After(created.UpdatedAt) {
			t.Errorf("stale delivery recorded: %+v", got)
		}
		// A change computed from a stale version is refused.
		if _, err := updateSystemWebhook(t, db, gen.ID, store.WebhookChange{Name: "Stale", Version: created.UpdatedAt}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Update from a stale version = %v", err)
		}
		if got, _ := repo.Get(ctx, gen.ID); got.Name != "Ops" {
			t.Errorf("a stale update changed the webhook: %+v", got)
		}
		if _, err := updateSystemWebhook(t, db, gen.ID, store.WebhookChange{Enabled: ptr(false), Version: upd.UpdatedAt}); err != nil {
			t.Errorf("disable = %v", err)
		}

		// Delete: keys first (D23).
		del := func(whkID string, keys ...string) error {
			return systemTx(ctx, t, db, func(tx *store.SystemTx) error {
				for _, k := range keys {
					if err := db.SystemSecrets().DeleteTx(ctx, tx, k); err != nil {
						return err
					}
				}
				return repo.DeleteTx(ctx, tx, whkID)
			})
		}
		if err := del(gen.ID); !errors.Is(err, store.ErrKeysRemain) {
			t.Errorf("Delete with keys = %v", err)
		}
		if err := del(gen.ID, newURL); !errors.Is(err, store.ErrKeysRemain) {
			t.Errorf("Delete with the secret = %v", err)
		}
		if err := del(gen.ID, newURL, newSecret); err != nil {
			t.Fatalf("Delete = %v", err)
		}
		if err := del(gen.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete twice = %v", err)
		}
		if err := del(gen.ID, newURL); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteTx of a destroyed secret = %v", err)
		}
		err = systemTx(ctx, t, db, func(tx *store.SystemTx) error {
			_, err := repo.GetTx(ctx, tx, slack.ID)
			if err != nil {
				return err
			}
			_, err = repo.GetTx(ctx, tx, gen.ID)
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetTx after delete = %v", err)
		}
	})
}
