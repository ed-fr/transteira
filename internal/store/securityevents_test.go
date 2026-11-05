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

func TestSecurityEvents(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SecurityEvents()
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		tb := newTenant(t, db, "transfer.entity-b.example.com")

		if got, err := repo.Save(ctx, nil); err != nil || len(got) != 0 {
			t.Fatalf("Save(nil) = %v, %v", got, err)
		}
		saved, err := repo.Save(ctx, []store.SecurityEvent{
			{
				At: msNow, Type: "unknown_fqdn", IP: netip.MustParseAddr("::ffff:198.51.100.23"),
				Details: json.RawMessage(`{"host":"evil.example.net"}`),
			},
			{
				At: msNow.Add(time.Second), TenantID: ta.ID, Type: "admin_login_failed", Reason: "password",
				IP: netip.MustParseAddr("203.0.113.7"), Occurrences: 3, LastSeenAt: msNow.Add(5 * time.Second),
			},
			{At: msNow.Add(2 * time.Second), TenantID: ta.ID, Type: "rate_limited", Details: json.RawMessage(`{"scope":"code"}`)},
			{TenantID: tb.ID, Type: "deposit_refused", Reason: "ip"}, // store clock
		})
		if err != nil || len(saved) != 4 {
			t.Fatalf("Save = %+v, %v", saved, err)
		}
		for _, ev := range saved {
			if !id.Valid(id.SecurityEvent, ev.ID) || ev.Occurrences < 1 || ev.LastSeenAt.Before(ev.At) {
				t.Errorf("saved %+v", ev)
			}
		}
		if saved[0].IP != netip.MustParseAddr("198.51.100.23") || saved[0].Occurrences != 1 || !saved[0].LastSeenAt.Equal(msNow) {
			t.Errorf("saved[0] = %+v", saved[0])
		}
		if !saved[3].At.Equal(msNow) {
			t.Errorf("zero time not set from the store clock: %+v", saved[3])
		}

		// Update of the coalesced occurrences of an existing row, and of a
		// row purged meanwhile (no-op).
		upd := saved[2]
		upd.Occurrences, upd.LastSeenAt = 7, msNow.Add(40*time.Second)
		gone := saved[2]
		gone.ID = id.New(id.SecurityEvent)
		if _, err := repo.Save(ctx, []store.SecurityEvent{upd, gone}); err != nil {
			t.Fatalf("Save(update) = %v", err)
		}

		// The whole log, newest first.
		all, err := repo.List(ctx, store.SecurityEventFilter{})
		if err != nil || len(all.Items) != 4 || all.NextCursor != "" {
			t.Fatalf("List(all) = %+v, %v", all, err)
		}
		wantTypes := []string{"rate_limited", "admin_login_failed", "deposit_refused", "unknown_fqdn"}
		for i, ev := range all.Items {
			if ev.Type != wantTypes[i] {
				t.Errorf("List(all)[%d] = %+v", i, ev)
			}
		}
		for _, ev := range all.Items {
			switch ev.ID {
			case saved[0].ID:
				if ev.TenantID != "" || string(ev.Details) != `{"host":"evil.example.net"}` || ev.IP != saved[0].IP || ev.Reason != "" {
					t.Errorf("listed tenant-less event = %+v", ev)
				}
			case saved[1].ID:
				if ev.TenantID != ta.ID || ev.Reason != "password" || ev.Occurrences != 3 || !ev.LastSeenAt.Equal(msNow.Add(5*time.Second)) {
					t.Errorf("listed coalesced event = %+v", ev)
				}
			case saved[2].ID:
				if ev.Occurrences != 7 || !ev.LastSeenAt.Equal(msNow.Add(40*time.Second)) || ev.IP.IsValid() {
					t.Errorf("listed updated event = %+v", ev)
				}
			}
		}

		// Tenant scope: only that tenant's events, never one without
		// tenant (T-283).
		pa, err := repo.List(ctx, store.SecurityEventFilter{TenantID: ta.ID})
		if err != nil || len(pa.Items) != 2 {
			t.Fatalf("List(tenant a) = %+v, %v", pa, err)
		}
		for _, ev := range pa.Items {
			if ev.TenantID != ta.ID || (ev.ID != saved[1].ID && ev.ID != saved[2].ID) {
				t.Errorf("tenant a listed %+v", ev)
			}
		}
		if pb, err := repo.List(ctx, store.SecurityEventFilter{TenantID: tb.ID}); err != nil || len(pb.Items) != 1 || pb.Items[0].ID != saved[3].ID {
			t.Errorf("List(tenant b) = %+v, %v", pb, err)
		}

		// Filters and paging.
		filters := map[string]struct {
			f    store.SecurityEventFilter
			want int
		}{
			"type":         {store.SecurityEventFilter{Type: "rate_limited"}, 1},
			"unknown type": {store.SecurityEventFilter{Type: "no_such_type"}, 0},
			"tenant type":  {store.SecurityEventFilter{TenantID: ta.ID, Type: "admin_login_failed"}, 1},
			"tenant other": {store.SecurityEventFilter{TenantID: tb.ID, Type: "unknown_fqdn"}, 0},
			"since":        {store.SecurityEventFilter{Since: msNow.Add(time.Second)}, 2},
			// from/to compare the first occurrence (decision 9).
			"until":  {store.SecurityEventFilter{Until: msNow.Add(time.Second)}, 3},
			"period": {store.SecurityEventFilter{Since: msNow.Add(time.Second), Until: msNow.Add(time.Second)}, 1},
		}
		for name, tt := range filters {
			if p, err := repo.List(ctx, tt.f); err != nil || len(p.Items) != tt.want {
				t.Errorf("List(%s) = %d items, %v; want %d", name, len(p.Items), err, tt.want)
			}
		}
		for _, tid := range []tenant.ID{"", ta.ID} {
			seen := map[string]bool{}
			cursor := ""
			for {
				p, err := repo.List(ctx, store.SecurityEventFilter{TenantID: tid, Cursor: cursor, Limit: 1})
				if err != nil {
					t.Fatalf("List(page): %v", err)
				}
				for _, ev := range p.Items {
					seen[ev.ID] = true
				}
				if cursor = p.NextCursor; cursor == "" {
					break
				}
			}
			want := 4
			if tid != "" {
				want = 2
			}
			if len(seen) != want {
				t.Errorf("paging over %q saw %d events, want %d", tid, len(seen), want)
			}
		}
		badFilters := map[string]store.SecurityEventFilter{
			"cursor":    {Cursor: "nope"},
			"cursor id": {Cursor: "12:aud_01JABCN9R0S1T2V3V4W5X6Y7Z8"},
			"period":    {Since: msNow, Until: msNow.Add(-time.Second)},
			"tenant":    {TenantID: "bogus"},
			"type":      {Type: "Bad-Type"},
			"type long": {Type: strings.Repeat("a", store.MaxSecurityEventTypeLen+1)},
		}
		for name, f := range badFilters {
			if _, err := repo.List(ctx, f); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("List(%s) err = %v, want ErrInvalid", name, err)
			}
		}

		// Validation: nothing of a malformed batch is written.
		bad := map[string]func(*store.SecurityEvent){
			"tenant":       func(ev *store.SecurityEvent) { ev.TenantID = "bogus" },
			"type":         func(ev *store.SecurityEvent) { ev.Type = "" },
			"type syntax":  func(ev *store.SecurityEvent) { ev.Type = "a b" },
			"reason":       func(ev *store.SecurityEvent) { ev.Reason = "alice@example.com" },
			"reason long":  func(ev *store.SecurityEvent) { ev.Reason = strings.Repeat("a", store.MaxSecurityEventReasonLen+1) },
			"details json": func(ev *store.SecurityEvent) { ev.Details = json.RawMessage(`{`) },
			"details list": func(ev *store.SecurityEvent) { ev.Details = json.RawMessage(`[1]`) },
			"details size": func(ev *store.SecurityEvent) {
				ev.Details = json.RawMessage(`{"a":"` + strings.Repeat("b", store.MaxSecurityEventDetailsBytes) + `"}`)
			},
			"details address": func(ev *store.SecurityEvent) { ev.Details = json.RawMessage(`{"host":"alice@example.com"}`) },
			"details escaped": func(ev *store.SecurityEvent) { ev.Details = json.RawMessage(`{"host":"alice@example.com"}`) },
			"occurrences":     func(ev *store.SecurityEvent) { ev.Occurrences = -1 },
			"last seen":       func(ev *store.SecurityEvent) { ev.LastSeenAt = ev.At.Add(-time.Second) },
			"id":              func(ev *store.SecurityEvent) { ev.ID = "aud_01JABCN9R0S1T2V3V4W5X6Y7Z8" },
		}
		for name, mutate := range bad {
			ev := store.SecurityEvent{At: msNow, Type: "rate_limited"}
			mutate(&ev)
			if _, err := repo.Save(ctx, []store.SecurityEvent{{At: msNow, Type: "rate_limited"}, ev}); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Save(%s) err = %v, want ErrInvalid", name, err)
			}
		}
		if _, err := repo.Save(ctx, make([]store.SecurityEvent, store.MaxSecurityEventBatch+1)); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Save(too many) err = %v, want ErrInvalid", err)
		}
		if p, _ := repo.List(ctx, store.SecurityEventFilter{}); len(p.Items) != 4 {
			t.Errorf("a refused batch wrote %d rows", len(p.Items)-4)
		}
		if !store.ValidSecurityEventType("verification_code_invalid") || store.ValidSecurityEventType("9x") {
			t.Error("ValidSecurityEventType")
		}

		// Purge: strictly before the cutoff, on the first occurrence.
		if n, err := repo.Purge(ctx, msNow.Add(time.Second)); err != nil || n != 2 {
			t.Errorf("Purge = %d, %v; want 2", n, err)
		}
		if p, err := repo.List(ctx, store.SecurityEventFilter{}); err != nil || len(p.Items) != 2 {
			t.Errorf("after the purge: %+v, %v", p, err)
		}
	})
}
