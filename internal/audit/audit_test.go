package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

var testNow = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

// openDB returns a migrated database on engine e.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func event(action audit.Action) audit.Event {
	return audit.Event{
		ActorKind: store.ActorAdmin, Actor: "root", IP: netip.MustParseAddr("192.0.2.10"),
		Action: action, ObjectKind: audit.ObjectAdmin, ObjectID: "adm_01JABCG1H2J3K415M6N7P8Q9R0",
		Details: map[string]any{"method": "totp"},
	}
}

func TestWriter(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		w := audit.New(db)

		if err := w.Record(ctx, event(audit.ActionAdminLogin)); err != nil {
			t.Fatalf("Record = %v", err)
		}
		noDetails := event(audit.ActionSetupCompleted)
		noDetails.Details = nil
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, noDetails) })
		if err != nil {
			t.Fatalf("RecordTx = %v", err)
		}

		page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("List = %d items, %v", len(page.Items), err)
		}
		byAction := map[string]store.AuditEvent{}
		for _, ev := range page.Items {
			byAction[ev.Action] = ev
		}
		login := byAction["admin.login"]
		var details map[string]string
		if err := json.Unmarshal(login.Details, &details); err != nil || details["method"] != "totp" ||
			login.Actor != "root" || login.ActorKind != store.ActorAdmin || login.ObjectKind != "admin" ||
			login.IP.String() != "192.0.2.10" || login.TenantID != "" {
			t.Errorf("login event = %+v (%v)", login, err)
		}
		if setup := byAction["setup.completed"]; setup.Details != nil {
			t.Errorf("setup event details = %s, want none", setup.Details)
		}

		// A malformed event is refused by the store, in both paths.
		bad := event("Not An Action")
		if err := w.Record(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Record(bad action) = %v, want ErrInvalid", err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, bad) })
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RecordTx(bad action) = %v, want ErrInvalid", err)
		}
	})
}

func TestWriterRefusesSecrets(t *testing.T) {
	db := openDB(t, storetest.SQLite(t))
	w := audit.New(db)
	ctx := context.Background()
	for _, key := range []string{"password", "newPassword", "Secret", "session_token", "totp_code", "recovery_code", "passphrase"} {
		ev := event(audit.ActionAdminLogin)
		ev.Details = map[string]any{key: "x"}
		if err := w.Record(ctx, ev); !errors.Is(err, audit.ErrSecretDetail) {
			t.Errorf("Record(%s) = %v, want ErrSecretDetail", key, err)
		}
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, ev) })
		if !errors.Is(err, audit.ErrSecretDetail) {
			t.Errorf("RecordTx(%s) = %v, want ErrSecretDetail", key, err)
		}
	}
	// A value JSON cannot encode is an error too.
	ev := event(audit.ActionAdminLogin)
	ev.Details = map[string]any{"fields": func() {}}
	if err := w.Record(ctx, ev); err == nil {
		t.Error("Record(unencodable details) = nil, want an error")
	}
	page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Errorf("List = %d items, %v, want none", len(page.Items), err)
	}
}
