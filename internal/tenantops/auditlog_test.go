package tenantops

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// auditFixture writes, one second apart: a depositor event of A, an admin
// event of A, an event of B and a global event; it returns their IDs in
// that order.
func (ev *env) auditFixture() []string {
	ev.t.Helper()
	ctx := context.Background()
	events := []store.AuditEvent{
		{
			TenantID: ev.a.ID, ActorKind: store.ActorDepositor, Actor: alice, IP: clientIP,
			Action: string(audit.ActionTransferCreated), ObjectKind: audit.ObjectTransfer, ObjectID: missingTrf,
		},
		{
			TenantID: ev.a.ID, ActorKind: store.ActorAdmin, Actor: "alice.admin", IP: clientIP,
			Action: string(audit.ActionBlocklistUpdated), ObjectKind: audit.ObjectBlocklistEntry, ObjectID: missingBlk,
		},
		{
			TenantID: ev.b.ID, ActorKind: store.ActorAdmin, Actor: "bob.admin",
			Action: string(audit.ActionBlocklistUpdated), ObjectKind: audit.ObjectBlocklistEntry, ObjectID: missingBlk,
		},
		{ActorKind: store.ActorAdmin, Actor: "root", Action: string(audit.ActionAdminLogin), ObjectKind: audit.ObjectAdmin, ObjectID: "adm_x"},
	}
	ids := make([]string, len(events))
	for i, e := range events {
		ev.clock.Advance(time.Second)
		got, err := ev.db.AuditEvents().Append(ctx, e)
		mustNoErr(ev.t, "append", err)
		ids[i] = got.ID
	}
	return ids
}

// eventIDs returns the IDs of a page of events.
func eventIDs(page store.Page[store.AuditEvent]) []string {
	out := make([]string, len(page.Items))
	for i, e := range page.Items {
		out[i] = e.ID
	}
	return out
}

// TestListAuditEvents returns the events of one tenant only, with filters.
func TestListAuditEvents(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ids := ev.auditFixture()

		page, err := ev.svc.ListAuditEvents(ctx, ev.adminA, ev.a.ID, AuditFilter{})
		mustNoErr(t, "list", err)
		if got := eventIDs(page); !slices.Equal(got, []string{ids[1], ids[0]}) {
			t.Fatalf("listed %v, want A's events %v", got, ids[:2])
		}
		for _, c := range []struct {
			name string
			f    AuditFilter
			want []string
		}{
			{"action", AuditFilter{Action: "transfer.created"}, []string{ids[0]}},
			{"unknown action", AuditFilter{Action: "transfer.vanished"}, []string{}},
			{"actor address", AuditFilter{Actor: "Alice@Entity-A.example.com"}, []string{ids[0]}},
			{"actor username", AuditFilter{Actor: "alice.admin"}, []string{ids[1]}},
			{"from", AuditFilter{From: testStart.Add(2 * time.Second)}, []string{ids[1]}},
			{"to", AuditFilter{To: testStart.Add(time.Second)}, []string{ids[0]}},
			{"period", AuditFilter{From: testStart, To: testStart.Add(time.Hour)}, []string{ids[1], ids[0]}},
			{"page", AuditFilter{Limit: 1}, []string{ids[1]}},
		} {
			page, err := ev.svc.ListAuditEvents(ctx, ev.super, ev.a.ID, c.f)
			if got := eventIDs(page); err != nil || !slices.Equal(got, c.want) {
				t.Errorf("%s: %v, %v; want %v", c.name, got, err, c.want)
			}
		}
		page, err = ev.svc.ListAuditEvents(ctx, ev.adminA, ev.a.ID, AuditFilter{Limit: 1})
		mustNoErr(t, "page", err)
		page, err = ev.svc.ListAuditEvents(ctx, ev.adminA, ev.a.ID, AuditFilter{Limit: 1, Cursor: page.NextCursor})
		if got := eventIDs(page); err != nil || !slices.Equal(got, []string{ids[0]}) {
			t.Errorf("second page = %v, %v", got, err)
		}

		for _, c := range []struct {
			f     AuditFilter
			field string
		}{
			{AuditFilter{Action: "transfer"}, FieldAction},
			{AuditFilter{Action: "Transfer.Created"}, FieldAction},
			{AuditFilter{Action: strings.Repeat("a", 60) + ".abcd"}, FieldAction},
			{AuditFilter{Actor: strings.Repeat("é", MaxActorFilterLen+1)}, FieldActor},
			{AuditFilter{Actor: "\xff"}, FieldActor},
			{AuditFilter{From: testStart, To: testStart.Add(-time.Second)}, FieldTo},
			{AuditFilter{Limit: store.MaxPageSize + 1}, FieldLimit},
			{AuditFilter{Cursor: "garbage"}, FieldCursor},
		} {
			_, err := ev.svc.ListAuditEvents(ctx, ev.adminA, ev.a.ID, c.f)
			wantInvalid(t, "filter "+c.field, err, c.field)
		}
		ev.faults("listAudit")
		_, err = ev.svc.ListAuditEvents(ctx, ev.adminA, ev.a.ID, AuditFilter{})
		wantErr(t, "list failure", err, errBoom)
	})
}

// TestListGlobalAuditEvents returns the whole log, or one tenant's events,
// to the super admin only.
func TestListGlobalAuditEvents(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ids := ev.auditFixture()

		page, err := ev.svc.ListGlobalAuditEvents(ctx, ev.super, GlobalAuditFilter{})
		mustNoErr(t, "list", err)
		if got := eventIDs(page); !slices.Equal(got, []string{ids[3], ids[2], ids[1], ids[0]}) {
			t.Fatalf("listed %v", got)
		}
		if page.Items[0].TenantID != "" || page.Items[1].TenantID != ev.b.ID {
			t.Errorf("tenants = %q, %q", page.Items[0].TenantID, page.Items[1].TenantID)
		}
		for _, c := range []struct {
			name string
			f    GlobalAuditFilter
			want []string
		}{
			{"tenant", GlobalAuditFilter{TenantID: ev.b.ID}, []string{ids[2]}},
			{"unknown tenant", GlobalAuditFilter{TenantID: missingTen}, []string{}},
			{"action", GlobalAuditFilter{Action: "admin.login"}, []string{ids[3]}},
			{"tenant and action", GlobalAuditFilter{TenantID: ev.a.ID, Action: "blocklist.updated"}, []string{ids[1]}},
			{"page", GlobalAuditFilter{Limit: 2}, []string{ids[3], ids[2]}},
		} {
			page, err := ev.svc.ListGlobalAuditEvents(ctx, ev.super, c.f)
			if got := eventIDs(page); err != nil || !slices.Equal(got, c.want) {
				t.Errorf("%s: %v, %v; want %v", c.name, got, err, c.want)
			}
		}

		_, err = ev.svc.ListGlobalAuditEvents(ctx, ev.adminA, GlobalAuditFilter{})
		wantErr(t, "delegated admin", err, ErrForbidden)
		_, err = ev.svc.ListGlobalAuditEvents(ctx, ev.adminA, GlobalAuditFilter{TenantID: ev.a.ID})
		wantErr(t, "delegated admin on its tenant", err, ErrForbidden)
		_, err = ev.svc.ListGlobalAuditEvents(ctx, unauthenticated(ev.super), GlobalAuditFilter{})
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
		for _, c := range []struct {
			f     GlobalAuditFilter
			field string
		}{
			{GlobalAuditFilter{TenantID: tenant.ID("ten_bad")}, FieldTenantID},
			{GlobalAuditFilter{Action: "bad"}, FieldAction},
			{GlobalAuditFilter{Limit: -1}, FieldLimit},
			{GlobalAuditFilter{Cursor: "garbage"}, FieldCursor},
		} {
			_, err := ev.svc.ListGlobalAuditEvents(ctx, ev.super, c.f)
			wantInvalid(t, "filter "+c.field, err, c.field)
		}
		ev.faults("listAudit")
		_, err = ev.svc.ListGlobalAuditEvents(ctx, ev.super, GlobalAuditFilter{})
		wantErr(t, "list failure", err, errBoom)
	})
}
