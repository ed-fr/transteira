package isolation_test

import (
	"crypto/sha256"
	"database/sql"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Addresses shared by both tenants in the operation scenarios.
const (
	sharedSender    = "alice@entity-a.example.com"
	sharedRecipient = "bob@partner.example.net"
	opsPseudonym    = "erased-0123456789abcdef"
)

// opsIP is the client IP of the operation scenarios.
var opsIP = netip.MustParseAddr("192.0.2.1")

// tokenHashOf returns the SHA-256 of a fictitious link token.
func tokenHashOf(token string) []byte {
	h := sha256.Sum256([]byte("operations " + token))
	return h[:]
}

// opsDay is the day of the usage counters of the operation scenarios.
var opsDay = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

// seedOperations gives A and B the same addresses everywhere (transfer
// sender and recipient, invitation, audit actor, deposit tables) and their
// own usage counters (A: 1 transfer, B: 2) and quota levels (A: 80, B:
// 100). It returns the transfer of each tenant.
func seedOperations(t *testing.T, f *fixture) map[tenant.ID]store.TransferDetails {
	t.Helper()
	ctx := t.Context()
	out := map[tenant.ID]store.TransferDetails{}
	for i, tid := range []tenant.ID{f.a.ID, f.b.ID} {
		out[tid] = createTransfer(t, f.db, tid)
		inv := store.Invitation{ID: id.New(id.Invitation), TokenHash: tokenHashOf(string(tid)), Email: sharedRecipient, InvitedBy: sharedSender}
		if err := f.db.Invitations().Create(ctx, tid, inv); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.AuditEvents().AppendScoped(ctx, tid, store.AuditEvent{
			ActorKind: store.ActorDepositor, Actor: sharedSender,
			Action: "transfer.created", ObjectKind: "transfer", ObjectID: out[tid].ID,
		}); err != nil {
			t.Fatal(err)
		}
		s, err := f.db.Scoped(tid)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			_, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, store.VerifiedAddress{Email: sharedSender, FirstVerifiedIP: opsIP})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.TenantUsage().Add(ctx, tid, opsDay, store.UsageCounts{Transfers: int64(i + 1)}); err != nil {
			t.Fatal(err)
		}
		level := []int{store.QuotaLevelWarning, store.QuotaLevelReached}[i]
		if ok, err := f.db.QuotaAlerts().CompareAndSet(ctx, tid, store.QuotaLevelNone, level, time.Time{}); err != nil || !ok {
			t.Fatalf("CompareAndSet: %v, %v", ok, err)
		}
	}
	return out
}

// TestOperationsIsolation checks, through the repositories, that the
// administrator view, the GDPR erasure, the usage counters and the quota
// alerts of a tenant never reach another tenant holding the same
// addresses.
func TestOperationsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		trf := seedOperations(t, f)
		ta, tb := trf[f.a.ID], trf[f.b.ID]

		// The address filter of the administrator list stays in A.
		for _, email := range []string{sharedSender, sharedRecipient} {
			p, err := f.db.Transfers().AdminList(ctx, f.a.ID, store.AdminTransferFilter{Email: email})
			if err != nil || len(p.Items) != 1 || p.Items[0].ID != ta.ID {
				t.Errorf("AdminList(A, %s) = %+v, %v", email, p.Items, err)
			}
		}
		if ids, err := f.db.Transfers().IDsBySender(ctx, f.a.ID, sharedSender); err != nil || !slices.Equal(ids, []string{ta.ID}) {
			t.Errorf("IDsBySender(A) = %v, %v", ids, err)
		}
		if ids, err := f.db.Transfers().IDsByRecipient(ctx, f.a.ID, sharedRecipient); err != nil || !slices.Equal(ids, []string{ta.ID}) {
			t.Errorf("IDsByRecipient(A) = %v, %v", ids, err)
		}
		s, err := f.db.Scoped(f.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Tx(ctx, func(tx *store.ScopedTx) error {
			err := f.db.Transfers().IncrementDownloadsTx(ctx, tx, tb.ID)
			assertNotFound(t, "IncrementDownloadsTx(B's transfer) from A", err)
			return err
		})
		_ = s.Tx(ctx, func(tx *store.ScopedTx) error {
			assertNotFound(t, "RemoveRecipientTx(B's transfer) from A", f.db.Transfers().RemoveRecipientTx(ctx, tx, tb.ID, sharedRecipient))
			if n, err := f.db.Transfers().CountRecipientsTx(ctx, tx, tb.ID); err != nil || n != 0 {
				t.Errorf("CountRecipientsTx(B's transfer) from A = %d, %v", n, err)
			}
			return nil
		})

		// The GDPR erasure of the address in A leaves B intact.
		n, err := f.db.AuditEvents().PseudonymiseActor(ctx, f.a.ID, sharedSender, opsPseudonym)
		if err != nil || n != 1 {
			t.Errorf("PseudonymiseActor(A) = %d, %v", n, err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			if n, err := f.db.Invitations().PseudonymiseInviterTx(ctx, tx, sharedSender, opsPseudonym, time.Time{}); err != nil || n != 1 {
				t.Errorf("PseudonymiseInviterTx(A) = %d, %v", n, err)
			}
			if n, err := f.db.Invitations().DeleteByEmailTx(ctx, tx, sharedRecipient); err != nil || n != 1 {
				t.Errorf("DeleteByEmailTx(A) = %d, %v", n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := f.db.VerifiedAddresses().Delete(ctx, f.a.ID, sharedSender); err != nil || !ok {
			t.Errorf("VerifiedAddresses.Delete(A) = %v, %v", ok, err)
		}
		if n, err := f.db.AuditEvents().CountActor(ctx, f.b.ID, sharedSender); err != nil || n != 1 {
			t.Errorf("CountActor(B) after A's erasure = %d, %v", n, err)
		}
		if invitee, inviter, err := f.db.Invitations().CountByEmail(ctx, f.b.ID, sharedRecipient); err != nil || invitee != 1 || inviter != 0 {
			t.Errorf("B's invitations after A's erasure: invitee %d, inviter %d, %v", invitee, inviter, err)
		}
		pb, err := f.db.Invitations().List(ctx, f.b.ID, store.InvitationFilter{})
		if err != nil || len(pb.Items) != 1 || pb.Items[0].InvitedBy != sharedSender || !pb.Items[0].RevokedAt.IsZero() {
			t.Errorf("B's invitation after A's erasure = %+v, %v", pb.Items, err)
		}
		if _, err := f.db.VerifiedAddresses().Get(ctx, f.b.ID, sharedSender); err != nil {
			t.Errorf("B's verified address after A's erasure: %v", err)
		}
		if got, err := f.db.Transfers().Get(ctx, f.b.ID, tb.ID); err != nil || got.DownloadCount != 0 ||
			!slices.Equal(got.Recipients, []string{sharedRecipient}) {
			t.Errorf("B's transfer = %+v, %v", got, err)
		}

		// Usage counters and quota levels are per tenant.
		if got, err := f.db.TenantUsage().Range(ctx, f.a.ID, opsDay); err != nil || len(got) != 1 || got[0].Transfers != 1 {
			t.Errorf("Range(A) = %+v, %v", got, err)
		}
		all, err := f.db.TenantUsage().RangeAll(ctx, opsDay)
		if err != nil || all[f.a.ID].Transfers != 1 || all[f.b.ID].Transfers != 2 {
			t.Errorf("RangeAll = %+v, %v", all, err)
		}
		if q, err := f.db.QuotaAlerts().Get(ctx, f.a.ID); err != nil || q.Level != store.QuotaLevelWarning {
			t.Errorf("quota level of A = %+v, %v", q, err)
		}
		// A's swap from B's level finds A's row only.
		if ok, err := f.db.QuotaAlerts().CompareAndSet(ctx, f.a.ID, store.QuotaLevelReached, store.QuotaLevelNone, time.Time{}); err != nil || ok {
			t.Errorf("CompareAndSet(A from B's level) = %v, %v", ok, err)
		}
		if q, err := f.db.QuotaAlerts().Get(ctx, f.b.ID); err != nil || q.Level != store.QuotaLevelReached {
			t.Errorf("quota level of B = %+v, %v", q, err)
		}
	})
}

// TestOperationsTenantDeletion deletes tenant B and checks that only B's
// usage counters and quota level disappear, at the raw database level.
func TestOperationsTenantDeletion(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		for _, tid := range []tenant.ID{f.a.ID, f.b.ID} {
			if err := f.db.TenantUsage().Add(ctx, tid, opsDay, store.UsageCounts{Transfers: 1}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.QuotaAlerts().CompareAndSet(ctx, tid, store.QuotaLevelNone, store.QuotaLevelWarning, time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.db.Tenants().Delete(ctx, f.b.ID); err != nil {
			t.Fatalf("Delete(B): %v", err)
		}
		for _, table := range []string{"tenant_daily_stats", "tenant_quota_alerts"} {
			if n := rawCount(t, e, table, "tenant_id", f.b.ID); n != 0 {
				t.Errorf("%s holds %d rows of deleted B", table, n)
			}
			if n := rawCount(t, e, table, "tenant_id", f.a.ID); n != 1 {
				t.Errorf("%s holds %d rows of A, want 1", table, n)
			}
		}
	})
}

// TestRLSOperationsCrossTenantRawSQL bypasses the application layer: a raw
// transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT statements
// at B's usage counters and quota level, and tries to pseudonymise its own
// audit events. Row-level security alone must stop them.
func TestRLSOperationsCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	seedOperations(t, f)
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM tenant_daily_stats WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM tenant_daily_stats`, nil, 1},
			{`SELECT count(*) FROM tenant_daily_stats WHERE transfers = 2`, nil, 0},
			{`SELECT count(*) FROM tenant_daily_stats WHERE true OR tenant_id = $1`, []any{b}, 1},
			{`SELECT count(*) FROM tenant_quota_alerts WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM tenant_quota_alerts`, nil, 1},
			{`SELECT count(*) FROM tenant_quota_alerts WHERE level = 100`, nil, 0},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE tenant_daily_stats SET transfers = 999 WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM tenant_daily_stats WHERE tenant_id = $1`, []any{b}},
			{`UPDATE tenant_quota_alerts SET level = 0 WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM tenant_quota_alerts WHERE tenant_id = $1`, []any{b}},
			// The tenant scope stays append-only on the audit log: the
			// pseudonymisation is a system query.
			{`UPDATE audit_events SET actor = '` + opsPseudonym + `' WHERE tenant_id = $1`, []any{a}},
			{`UPDATE audit_events SET actor = '` + opsPseudonym + `' WHERE tenant_id = $1`, []any{b}},
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
		{"insert counters for B", `INSERT INTO tenant_daily_stats (tenant_id, day) VALUES ($1, 86400000)`, []any{b}},
		{"insert a quota level for B", `INSERT INTO tenant_quota_alerts (tenant_id, level, changed_at) VALUES ($1, 0, 0)`, []any{b}},
		{"move A's counters to B", `UPDATE tenant_daily_stats SET tenant_id = $1`, []any{b}},
		{"move A's quota level to B", `UPDATE tenant_quota_alerts SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}
	for tid, want := range map[tenant.ID]int64{f.a.ID: 1, f.b.ID: 2} {
		if got, err := f.db.TenantUsage().Range(ctx, tid, opsDay); err != nil || len(got) != 1 || got[0].Transfers != want {
			t.Errorf("usage of %s after the attacks = %+v, %v", tid, got, err)
		}
	}
	if q, err := f.db.QuotaAlerts().Get(ctx, f.b.ID); err != nil || q.Level != store.QuotaLevelReached {
		t.Errorf("quota level of B after the attacks = %+v, %v", q, err)
	}
	for _, tid := range []tenant.ID{f.a.ID, f.b.ID} {
		if n, err := f.db.AuditEvents().CountActor(ctx, tid, sharedSender); err != nil || n != 1 {
			t.Errorf("audit events of %s after the attacks = %d, %v", tid, n, err)
		}
	}
}
