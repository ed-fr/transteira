package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// auditEvent returns a valid event of tenant tid at at.
func auditEvent(tid tenant.ID, action, actor string, at time.Time) store.AuditEvent {
	return store.AuditEvent{
		At: at, TenantID: tid, ActorKind: store.ActorAdmin, Actor: actor, Action: action,
		ObjectKind: "admin", ObjectID: "adm_x",
	}
}

func TestAuditEvents(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AuditEvents()
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		tb := newTenant(t, db, "transfer.entity-b.example.com")

		g := auditEvent("", "setup.completed", "root", msNow)
		g.IP = netip.MustParseAddr("::ffff:192.0.2.1")
		g.Details = json.RawMessage(`{"via":"setup"}`)
		got, err := repo.Append(ctx, g)
		if err != nil || !id.Valid(id.Audit, got.ID) || got.IP != netip.MustParseAddr("192.0.2.1") || !got.At.Equal(msNow) {
			t.Fatalf("Append(global) = %+v, %v", got, err)
		}
		zero := auditEvent(ta.ID, "admin.login", "root", time.Time{}) // store clock
		if got, err := repo.Append(ctx, zero); err != nil || !got.At.Equal(msNow) {
			t.Errorf("Append(zero time) = %+v, %v", got, err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			_, err := repo.AppendTx(ctx, tx, auditEvent(tb.ID, "admin.updated", "root", msNow.Add(time.Second)))
			return err
		})
		if err != nil {
			t.Fatalf("AppendTx = %v", err)
		}
		err = inTx(t, db, ta.ID, func(tx *store.ScopedTx) error {
			ev, err := repo.AppendScopedTx(ctx, tx, auditEvent("", "transfer.deleted", "alice@entity-a.example.com", msNow.Add(2*time.Second)))
			if err == nil && ev.TenantID != ta.ID {
				t.Errorf("AppendScopedTx tenant = %q", ev.TenantID)
			}
			if err != nil {
				return err
			}
			_, err = repo.AppendScopedTx(ctx, tx, auditEvent(ta.ID, "transfer.deleted", "bob@entity-a.example.com", msNow.Add(3*time.Second)))
			return err
		})
		if err != nil {
			t.Fatalf("AppendScopedTx = %v", err)
		}
		err = inTx(t, db, ta.ID, func(tx *store.ScopedTx) error {
			_, err := repo.AppendScopedTx(ctx, tx, auditEvent(tb.ID, "transfer.deleted", "x", msNow))
			return err
		})
		wantErr(t, "AppendScopedTx(other tenant)", err, store.ErrInvalid)
		err = inTx(t, db, ta.ID, func(tx *store.ScopedTx) error {
			_, err := repo.AppendScopedTx(ctx, tx, auditEvent("", "bad", "x", msNow))
			return err
		})
		wantErr(t, "AppendScopedTx(bad action)", err, store.ErrInvalid)
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			_, err := repo.AppendTx(ctx, tx, auditEvent("", "bad", "x", msNow))
			return err
		})
		wantErr(t, "AppendTx(bad action)", err, store.ErrInvalid)

		// The whole log, newest first.
		all, err := repo.List(ctx, store.AuditFilter{})
		if err != nil || len(all.Items) != 5 || all.NextCursor != "" {
			t.Fatalf("List(all) = %+v, %v", all, err)
		}
		wantOrder := []string{"bob@entity-a.example.com", "alice@entity-a.example.com", "root", "root", "root"}
		for i, ev := range all.Items {
			if ev.Actor != wantOrder[i] {
				t.Errorf("List(all)[%d] = %+v", i, ev)
			}
		}
		last := all.Items[4]
		if last.ID != got.ID && all.Items[3].ID != got.ID {
			t.Errorf("global event not listed: %+v", all.Items)
		}
		for _, ev := range all.Items {
			if ev.ID == got.ID && (ev.TenantID != "" || string(ev.Details) != `{"via":"setup"}` || ev.IP != got.IP) {
				t.Errorf("listed global event = %+v", ev)
			}
		}

		// Tenant scope: only that tenant's events.
		pa, err := repo.List(ctx, store.AuditFilter{TenantID: ta.ID})
		if err != nil || len(pa.Items) != 3 {
			t.Fatalf("List(tenant a) = %+v, %v", pa, err)
		}
		for _, ev := range pa.Items {
			if ev.TenantID != ta.ID || ev.Details != nil || ev.IP.IsValid() {
				t.Errorf("tenant a listed %+v", ev)
			}
		}
		if pb, err := repo.List(ctx, store.AuditFilter{TenantID: tb.ID}); err != nil || len(pb.Items) != 1 || pb.Items[0].Action != "admin.updated" {
			t.Errorf("List(tenant b) = %+v, %v", pb, err)
		}

		// Filters and paging.
		filters := map[string]struct {
			f    store.AuditFilter
			want int
		}{
			"action":        {store.AuditFilter{Action: "transfer.deleted"}, 2},
			"actor":         {store.AuditFilter{Actor: "root"}, 3},
			"tenant actor":  {store.AuditFilter{TenantID: ta.ID, Actor: "root"}, 1},
			"tenant action": {store.AuditFilter{TenantID: ta.ID, Action: "admin.login"}, 1},
			"since":         {store.AuditFilter{Since: msNow.Add(2 * time.Second)}, 2},
			"until":         {store.AuditFilter{Until: msNow.Add(time.Second)}, 3},
			"period":        {store.AuditFilter{Since: msNow.Add(time.Second), Until: msNow.Add(2 * time.Second)}, 2},
		}
		for name, tt := range filters {
			if p, err := repo.List(ctx, tt.f); err != nil || len(p.Items) != tt.want {
				t.Errorf("List(%s) = %d items, %v; want %d", name, len(p.Items), err, tt.want)
			}
		}
		for _, tid := range []tenant.ID{"", ta.ID} {
			var seen []string
			cursor := ""
			for {
				p, err := repo.List(ctx, store.AuditFilter{TenantID: tid, Cursor: cursor, Limit: 1})
				if err != nil {
					t.Fatalf("List(page): %v", err)
				}
				for _, ev := range p.Items {
					seen = append(seen, ev.ID)
				}
				if cursor = p.NextCursor; cursor == "" {
					break
				}
			}
			want := 5
			if tid != "" {
				want = 3
			}
			if len(seen) != want {
				t.Errorf("paging over %q saw %d events, want %d", tid, len(seen), want)
			}
		}
		badFilters := map[string]store.AuditFilter{
			"cursor":        {Cursor: "nope"},
			"cursor id":     {Cursor: "12:bogus"},
			"cursor ms":     {Cursor: "012:" + got.ID},
			"cursor no sep": {Cursor: got.ID},
			"period":        {Since: msNow, Until: msNow.Add(-time.Second)},
			"tenant":        {TenantID: "bogus"},
		}
		for name, f := range badFilters {
			if _, err := repo.List(ctx, f); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("List(%s) err = %v, want ErrInvalid", name, err)
			}
		}

		// Validation.
		bad := map[string]func(*store.AuditEvent){
			"tenant":        func(ev *store.AuditEvent) { ev.TenantID = "bogus" },
			"actor kind":    func(ev *store.AuditEvent) { ev.ActorKind = "email" },
			"actor empty":   func(ev *store.AuditEvent) { ev.Actor = "" },
			"actor newline": func(ev *store.AuditEvent) { ev.Actor = "a\nb" },
			"actor long":    func(ev *store.AuditEvent) { ev.Actor = strings.Repeat("a", store.MaxAuditActorLen+1) },
			"action":        func(ev *store.AuditEvent) { ev.Action = "Admin.Login" },
			"action long":   func(ev *store.AuditEvent) { ev.Action = "a." + strings.Repeat("b", 63) },
			"object kind":   func(ev *store.AuditEvent) { ev.ObjectKind = "" },
			"object id":     func(ev *store.AuditEvent) { ev.ObjectID = "" },
			"details size": func(ev *store.AuditEvent) {
				ev.Details = json.RawMessage(`{"a":"` + strings.Repeat("b", store.MaxAuditDetailsBytes) + `"}`)
			},
			"details json":   func(ev *store.AuditEvent) { ev.Details = json.RawMessage(`{`) },
			"details object": func(ev *store.AuditEvent) { ev.Details = json.RawMessage(`[1]`) },
		}
		for name, mutate := range bad {
			ev := auditEvent("", "admin.login", "root", msNow)
			mutate(&ev)
			if _, err := repo.Append(ctx, ev); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Append(%s) err = %v, want ErrInvalid", name, err)
			}
		}
		for _, k := range []store.AuditActorKind{store.ActorDepositor, store.ActorRecipient, store.ActorAPIToken, store.ActorSystem} {
			ev := auditEvent("", "admin.login", "x", msNow)
			ev.ActorKind = k
			if _, err := repo.Append(ctx, ev); err != nil {
				t.Errorf("Append(actor kind %s) = %v", k, err)
			}
		}

		// The events of a deleted tenant stay, for the super admin only.
		if err := db.Tenants().Delete(ctx, tb.ID); err != nil {
			t.Fatal(err)
		}
		if p, err := repo.List(ctx, store.AuditFilter{Action: "admin.updated"}); err != nil || len(p.Items) != 1 || p.Items[0].TenantID != tb.ID {
			t.Errorf("events of a deleted tenant = %+v, %v", p, err)
		}

		// Purge.
		if n, err := repo.Purge(ctx, msNow.Add(time.Second)); err != nil || n != 6 {
			t.Errorf("Purge = %d, %v; want 6", n, err)
		}
		if p, _ := repo.List(ctx, store.AuditFilter{}); len(p.Items) != 3 {
			t.Errorf("events after Purge = %d, want 3", len(p.Items))
		}
	})
}

// TestAuditSameMillisecondOrder checks that events recorded in the same
// millisecond list in reverse recording order (monotonic identifiers),
// through every append path.
func TestAuditSameMillisecondOrder(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AuditEvents()
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		const n = 30
		for i := range n {
			ev := auditEvent(ta.ID, "admin.login", "root", msNow)
			ev.ObjectID = "obj" + strings.Repeat("x", i)
			var err error
			switch i % 2 {
			case 0:
				_, err = repo.Append(ctx, ev)
			default:
				_, err = repo.AppendScoped(ctx, ta.ID, ev)
			}
			if err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
		}
		page, err := repo.List(ctx, store.AuditFilter{TenantID: ta.ID, Limit: n})
		if err != nil || len(page.Items) != n {
			t.Fatalf("List = %d items, %v", len(page.Items), err)
		}
		for i, ev := range page.Items {
			if want := "obj" + strings.Repeat("x", n-1-i); ev.ObjectID != want {
				t.Fatalf("item %d = %q, want %q", i, ev.ObjectID, want)
			}
		}
	})
}
