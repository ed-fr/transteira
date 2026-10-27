package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestWriterPublishes checks that every committed audit event is published
// as a log.audit event, and that nothing is published for a refused event
// or a rolled back transaction.
func TestWriterPublishes(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		rec := &events.Recorder{}
		w := audit.New(db, audit.WithPublisher(rec))
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		errRollback := errors.New("rollback")

		// Record: published with the stored fields.
		if err := w.Record(ctx, event(audit.ActionAdminLogin)); err != nil {
			t.Fatal(err)
		}
		got := rec.Events()
		if len(got) != 1 {
			t.Fatalf("published %d events, want 1", len(got))
		}
		ev := got[0]
		lr := ev.Log
		if ev.Type != events.LogAudit || ev.Severity != events.SeverityInfo || ev.TenantID != "" ||
			!ev.OccurredAt.Equal(testNow) || lr == nil || lr.Stream != events.StreamAudit || !lr.Time.Equal(testNow) ||
			lr.Action != "admin.login" || lr.ActorKind != "admin" || lr.Actor != "root" ||
			lr.IP.String() != "192.0.2.10" || lr.ObjectKind != audit.ObjectAdmin ||
			lr.ObjectID != "adm_01JABCG1H2J3K415M6N7P8Q9R0" || lr.AuditID == "" || lr.Tenant != "" {
			t.Fatalf("published event = %+v, log = %+v", ev, lr)
		}
		var details map[string]string
		if err := json.Unmarshal(lr.Details, &details); err != nil || details["method"] != "totp" {
			t.Fatalf("published details = %s (%v)", lr.Details, err)
		}

		// RecordTx: published after the commit only.
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			if err := w.RecordTx(ctx, tx, event(audit.ActionAdminLogout)); err != nil {
				return err
			}
			if len(rec.Events()) != 1 {
				t.Error("RecordTx published before the commit")
			}
			return nil
		})
		if err != nil || len(rec.OfType(events.LogAudit)) != 2 {
			t.Fatalf("RecordTx: err=%v published=%d", err, len(rec.Events()))
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			if err := w.RecordTx(ctx, tx, event(audit.ActionAdminLogout)); err != nil {
				return err
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) || len(rec.Events()) != 2 {
			t.Fatalf("RecordTx rolled back: err=%v published=%d", err, len(rec.Events()))
		}

		// RecordScoped and RecordScopedTx: published with the tenant.
		scopedEv := audit.Event{
			ActorKind: store.ActorSystem, Actor: "quota", Action: audit.ActionQuotaWarning,
			ObjectKind: audit.ObjectTenant, ObjectID: string(ta.ID),
		}
		if err := w.RecordScoped(ctx, ta.ID, scopedEv); err != nil {
			t.Fatal(err)
		}
		got = rec.Events()
		if len(got) != 3 || got[2].TenantID != string(ta.ID) || got[2].Log.Tenant != string(ta.ID) ||
			got[2].Log.Details != nil || got[2].Log.Action != "quota.warning" {
			t.Fatalf("RecordScoped published %+v", got)
		}
		sa, err := db.Scoped(ta.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error {
			if err := w.RecordScopedTx(ctx, tx, scopedEv); err != nil {
				return err
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) || len(rec.Events()) != 3 {
			t.Fatalf("RecordScopedTx rolled back: err=%v published=%d", err, len(rec.Events()))
		}

		// Refused by the guards or by the store: nothing published.
		secret := event(audit.ActionAdminLogin)
		secret.Details = map[string]any{"password": "x"}
		personal := event(audit.ActionAdminLogin)
		personal.Details = map[string]any{"to": "a@example.com"}
		for _, bad := range []audit.Event{secret, personal, event("Not An Action")} {
			_ = w.Record(ctx, bad)
			_ = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, bad) })
			_ = w.RecordScoped(ctx, ta.ID, bad)
		}
		if n := len(rec.Events()); n != 3 {
			t.Fatalf("refused events published: %d events, want 3", n)
		}
	})
}

// TestWriterPublisherDefaults checks that a writer without publisher, or
// with a nil one, publishes nothing, and OrNew.
func TestWriterPublisherDefaults(t *testing.T) {
	db := openDB(t, storetest.SQLite(t))
	ctx := context.Background()
	for _, w := range []*audit.Writer{audit.New(db), audit.New(db, audit.WithPublisher(nil))} {
		if err := w.Record(ctx, event(audit.ActionAdminLogin)); err != nil {
			t.Fatal(err)
		}
	}
	shared := audit.New(db)
	if audit.OrNew(shared, db) != shared {
		t.Error("OrNew(w) is not w")
	}
	if w := audit.OrNew(nil, db); w == nil || w == shared {
		t.Error("OrNew(nil) did not build a writer")
	}
}
