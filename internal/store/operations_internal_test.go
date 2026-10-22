package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestMigration0010Upgrade applies 0010_operations on a database at 0009
// holding transfers: the finalized ones feed the upload counters of their
// finalization day, per tenant; the others are ignored; the new columns
// read as unknown sender IP and no download.
func TestMigration0010Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 9)
		if n, err := db.Migrate(ctx); err != nil || n != 9 {
			t.Fatalf("Migrate to 0009 = %d, %v", n, err)
		}
		a := createLegacyTenant(ctx, t, db, "a.example.com", 5)
		b := createLegacyTenant(ctx, t, db, "b.example.com", 5)
		day1 := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
		day2 := day1.AddDate(0, 0, 1)
		insert := func(tid tenant.ID, status string, size int64, finalized time.Time) string {
			t.Helper()
			trfID := id.New(id.Transfer)
			fin, exp := "NULL", "NULL"
			if !finalized.IsZero() {
				fin = fmt.Sprint(toMillis(finalized))
				exp = fmt.Sprint(toMillis(finalized.AddDate(0, 0, 7)))
			}
			q := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
				delete_after_first_download, total_bytes, created_at, finalized_at, expires_at)
				VALUES ('` + trfID + `', '` + string(tid) + `', '` + status + `', 'alice@a.example.com', 'internal', 7,
				false, ` + fmt.Sprint(size) + `, 1, ` + fin + `, ` + exp + `)`
			if _, err := rawSystemExec(ctx, db, q); err != nil {
				t.Fatalf("insert legacy transfer: %v", err)
			}
			return trfID
		}
		first := insert(a, "scanning", 5, day1.Add(10*time.Hour))
		insert(a, "scanning", 7, day1.Add(23*time.Hour+59*time.Minute))
		insert(a, "scanning", 11, day2)
		insert(b, "scanning", 13, day1.Add(time.Hour))
		insert(a, "uploading", 17, time.Time{})

		db.migrationsFS = migrationFiles
		if n, err := db.Migrate(ctx); err != nil || n != len(mustMigrations(t, db))-9 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		got, err := db.TenantUsage().Range(ctx, a, time.Time{})
		want := []DailyUsage{
			{Day: day1, UsageCounts: UsageCounts{Transfers: 2, BytesUploaded: 12}},
			{Day: day2, UsageCounts: UsageCounts{Transfers: 1, BytesUploaded: 11}},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("usage of A after 0010 = %+v, %v", got, err)
		}
		if got, err := db.TenantUsage().Range(ctx, b, time.Time{}); err != nil ||
			!reflect.DeepEqual(got, []DailyUsage{{Day: day1, UsageCounts: UsageCounts{Transfers: 1, BytesUploaded: 13}}}) {
			t.Errorf("usage of B after 0010 = %+v, %v", got, err)
		}
		d, err := db.Transfers().Get(ctx, a, first)
		if err != nil || d.SenderIP.IsValid() || d.DownloadCount != 0 {
			t.Errorf("legacy transfer after 0010 = %+v, %v", d.Transfer, err)
		}
	})
}

// TestOperationsSchemaConstraints checks the check constraints of the
// tables of 0010, on both engines.
func TestOperationsSchemaConstraints(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 10, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		tid := "'" + string(tn.ID) + "'"
		stats := `INSERT INTO tenant_daily_stats (tenant_id, day, transfers, bytes_uploaded, downloads, bytes_downloaded, virus_detections) VALUES (` + tid + `, `
		alert := `INSERT INTO tenant_quota_alerts (tenant_id, level, changed_at) VALUES (`
		for name, q := range map[string]string{
			"day not at midnight":   stats + `1, 0, 0, 0, 0, 0)`,
			"negative transfers":    stats + `0, -1, 0, 0, 0, 0)`,
			"negative uploads":      stats + `0, 0, -1, 0, 0, 0)`,
			"negative downloads":    stats + `0, 0, 0, -1, 0, 0)`,
			"negative served bytes": stats + `0, 0, 0, 0, -1, 0)`,
			"negative detections":   stats + `0, 0, 0, 0, 0, -1)`,
			"stats of no tenant":    `INSERT INTO tenant_daily_stats (tenant_id, day) VALUES ('ten_01JZZZZZZZZZZZZZZZZZZZZZZZ', 0)`,
			"unknown level":         alert + tid + `, 50, 0)`,
			"alert of no tenant":    alert + `'ten_01JZZZZZZZZZZZZZZZZZZZZZZZ', 80, 0)`,
		} {
			if _, err := rawSystemExec(ctx, db, q); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		for _, q := range []string{stats + `86400000, 1, 2, 3, 4, 5)`, alert + tid + `, 100, 0)`} {
			if _, err := rawSystemExec(ctx, db, q); err != nil {
				t.Errorf("%.80s: %v", q, err)
			}
		}
		if _, err := rawSystemExec(ctx, db, alert+tid+`, 80, 0)`); err == nil {
			t.Error("second quota alert row accepted")
		}
	})
}

// TestOperationsDriverFaults injects a driver failure into each step of
// the operations of 0010 and checks that it surfaces as an error, never as
// a success.
func TestOperationsDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := &transferFixture{db: db, plan: plan}
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.tid = tn.ID
	f.trf = Transfer{ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 1}
	f.file = f.newFile(ctx, t)
	if err := f.create(ctx, f.trf, f.file); err != nil {
		t.Fatal(err)
	}
	inv := Invitation{ID: id.New(id.Invitation), TokenHash: make([]byte, TokenHashSize), Email: "bob@b.example.org", InvitedBy: fixtureEmail}
	if err := db.Invitations().Create(ctx, f.tid, inv); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AuditEvents().AppendScoped(ctx, f.tid, AuditEvent{
		ActorKind: ActorDepositor, Actor: fixtureEmail,
		Action: "transfer.created", ObjectKind: "transfer", ObjectID: f.trf.ID,
	}); err != nil {
		t.Fatal(err)
	}
	day := DayOf(time.Now())
	if err := db.TenantUsage().Add(ctx, f.tid, day, UsageCounts{Transfers: 1}); err != nil {
		t.Fatal(err)
	}
	_, err = db.Admins().Create(ctx, Admin{
		Username: "delegate", Email: "delegate@example.com", Role: RoleDelegatedAdmin,
		TenantIDs: []tenant.ID{f.tid}, PasswordHash: testPHCInternal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Admins().Create(ctx, Admin{Username: "root", Email: "root@example.com", Role: RoleSuperAdmin, PasswordHash: testPHCInternal}); err != nil {
		t.Fatal(err)
	}
	scoped := func(fn func(tx *ScopedTx) error) error { return f.tx(ctx, fn) }
	ops := map[string]func() error{
		"adminlist": func() error {
			_, err := db.Transfers().AdminList(ctx, f.tid, AdminTransferFilter{Email: "bob@b.example.org"})
			return err
		},
		"increment": func() error {
			return scoped(func(tx *ScopedTx) error {
				if err := db.Transfers().IncrementDownloadsTx(ctx, tx, f.trf.ID); err != nil {
					return err
				}
				return errRollback
			})
		},
		"bysender":     func() error { _, err := db.Transfers().IDsBySender(ctx, f.tid, fixtureEmail); return err },
		"byrecipient":  func() error { _, err := db.Transfers().IDsByRecipient(ctx, f.tid, "bob@b.example.org"); return err },
		"byinvitation": func() error { _, err := db.Transfers().IDsByInvitation(ctx, f.tid, inv.ID); return err },
		"recipients": func() error {
			return scoped(func(tx *ScopedTx) error {
				if _, err := db.Transfers().CountRecipientsTx(ctx, tx, f.trf.ID); err != nil {
					return err
				}
				if err := db.Transfers().RemoveRecipientTx(ctx, tx, f.trf.ID, "bob@b.example.org"); err != nil {
					return err
				}
				return errRollback
			})
		},
		"usedall": func() error { _, err := db.Transfers().UsedBytesAll(ctx); return err },
		"invlist": func() error {
			_, err := db.Invitations().List(ctx, f.tid, InvitationFilter{Status: InvitationPending})
			return err
		},
		"invcount": func() error { _, _, err := db.Invitations().CountByEmail(ctx, f.tid, fixtureEmail); return err },
		"invids":   func() error { _, err := db.Invitations().IDsByEmail(ctx, f.tid, fixtureEmail); return err },
		"invdelete": func() error {
			return scoped(func(tx *ScopedTx) error {
				return rollbackAfter(db.Invitations().DeleteByEmailTx(ctx, tx, "bob@b.example.org"))
			})
		},
		"invpseudo": func() error {
			return scoped(func(tx *ScopedTx) error {
				return rollbackAfter(db.Invitations().PseudonymiseInviterTx(ctx, tx, fixtureEmail, "erased-0123456789abcdef", time.Time{}))
			})
		},
		"verified": func() error { _, err := db.VerifiedAddresses().Delete(ctx, f.tid, fixtureEmail); return err },
		"challenges": func() error {
			return scoped(func(tx *ScopedTx) error { return rollbackAfter(db.Challenges().DeleteByEmailTx(ctx, tx, fixtureEmail)) })
		},
		"sessions": func() error {
			return scoped(func(tx *ScopedTx) error {
				return rollbackAfter(db.DepositSessions().DeleteByEmailTx(ctx, tx, fixtureEmail))
			})
		},
		"audappend": func() error {
			_, err := db.AuditEvents().AppendScoped(ctx, f.tid, AuditEvent{
				ActorKind: ActorSystem, Actor: "system",
				Action: "quota.warning", ObjectKind: "tenant", ObjectID: string(f.tid),
			})
			return err
		},
		"audcount": func() error { _, err := db.AuditEvents().CountActor(ctx, f.tid, fixtureEmail); return err },
		"audpseudo": func() error {
			_, err := db.AuditEvents().PseudonymiseActor(ctx, f.tid, "nobody@example.com", "erased-0123456789abcdef")
			return err
		},
		"usageadd":   func() error { return db.TenantUsage().Add(ctx, f.tid, day, UsageCounts{Downloads: 1}) },
		"usagenew":   func() error { return db.TenantUsage().Add(ctx, f.tid, day.AddDate(0, 0, 1), UsageCounts{Downloads: 1}) },
		"usagerange": func() error { _, err := db.TenantUsage().Range(ctx, f.tid, day); return err },
		"usageall":   func() error { _, err := db.TenantUsage().RangeAll(ctx, day); return err },
		"usagepurge": func() error { _, err := db.TenantUsage().Purge(ctx, day.AddDate(-2, 0, 0)); return err },
		"quotaget":   func() error { _, err := db.QuotaAlerts().Get(ctx, f.tid); return err },
		"quotaset": func() error {
			_, err := db.QuotaAlerts().CompareAndSet(ctx, f.tid, QuotaLevelNone, QuotaLevelNone, time.Time{})
			return err
		},
		"quotaswap": func() error {
			_, err := db.QuotaAlerts().CompareAndSet(ctx, f.tid, QuotaLevelWarning, QuotaLevelWarning, time.Time{})
			return err
		},
		"contacts":      func() error { _, err := db.Admins().TenantContacts(ctx, f.tid); return err },
		"supercontacts": func() error { _, err := db.Admins().SuperAdminContacts(ctx); return err },
	}
	faults := []struct{ op, match string }{
		{faultBegin, ""},
		{faultCommit, ""},
		{faultExec, ""},
		{faultQuery, ""},
		{faultNext, ""},
		{faultScanNil, ""},
		{faultRows, ""},
	}
	for name, op := range ops {
		for _, fl := range faults {
			for after := 0; after < 4; after++ {
				plan.reset()
				plan.add(fl.op, fl.match, after)
				_ = op() // must not panic; errors are checked below
			}
		}
		plan.reset()
		if err := op(); err != nil && !errors.Is(err, errRollback) {
			t.Errorf("%s fails without faults: %v", name, err)
		}
	}
	// A begin fault is never reported as success.
	for name, op := range ops {
		plan.reset()
		plan.add(faultBegin, "", 0)
		if err := op(); !errors.Is(err, errInjected) {
			t.Errorf("%s ignores a begin fault: %v", name, err)
		}
	}
	// Each statement's own failure surfaces.
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"adminlist query", faultQuery, "FROM transfers t", ops["adminlist"]},
		{"adminlist scan", faultScanNil, "FROM transfers t", ops["adminlist"]},
		{"adminlist recipients", faultQuery, "SELECT email FROM transfer_recipients", ops["adminlist"]},
		{"adminlist file count", faultQuery, "SELECT count(*) FROM transfer_files", ops["adminlist"]},
		{"increment rows", faultRows, "download_count + 1", ops["increment"]},
		{"usedall scan", faultScanNil, "GROUP BY tenant_id ORDER BY", ops["usedall"]},
		{"invlist scan", faultScanNil, "FROM invitations", ops["invlist"]},
		{"invcount second", faultQuery, "invited_by = ?", ops["invcount"]},
		{"invdelete exec", faultExec, "DELETE FROM invitations", ops["invdelete"]},
		{"invdelete rows", faultRows, "DELETE FROM invitations", ops["invdelete"]},
		{"invpseudo exec", faultExec, "SET invited_by", ops["invpseudo"]},
		{"challenges exec", faultExec, "DELETE FROM verification_challenges", ops["challenges"]},
		{"verified exec", faultExec, "DELETE FROM verified_addresses", ops["verified"]},
		{"audcount query", faultQuery, "FROM audit_events", ops["audcount"]},
		{"audpseudo exec", faultExec, "UPDATE audit_events", ops["audpseudo"]},
		{"audpseudo rows", faultRows, "UPDATE audit_events", ops["audpseudo"]},
		{"usagerange scan", faultScanNil, "FROM tenant_daily_stats", ops["usagerange"]},
		{"usageall query", faultQuery, "FROM tenant_daily_stats", ops["usageall"]},
		{"usageall scan", faultScanNil, "FROM tenant_daily_stats", ops["usageall"]},
		{"usagepurge exec", faultExec, "DELETE FROM tenant_daily_stats", ops["usagepurge"]},
		{"usagepurge rows", faultRows, "DELETE FROM tenant_daily_stats", ops["usagepurge"]},
		{"quotaget scan", faultQuery, "FROM tenant_quota_alerts", ops["quotaget"]},
		{"quotaset swap", faultExec, "UPDATE tenant_quota_alerts", ops["quotaset"]},
		{"quotaset rows", faultRows, "UPDATE tenant_quota_alerts", ops["quotaset"]},
		{"contacts scan", faultScanNil, "FROM admins", ops["contacts"]},
	} {
		plan.reset()
		plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || errors.Is(err, errRollback) {
			t.Errorf("%s: no error (%v)", c.name, err)
		}
	}
	// The insert of a first quota level fails on a fresh tenant.
	plan.reset()
	b, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "B", FQDN: "b.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	plan.add(faultExec, "INSERT INTO tenant_quota_alerts", 0)
	if _, err := db.QuotaAlerts().CompareAndSet(ctx, b.ID, QuotaLevelNone, QuotaLevelWarning, time.Time{}); !errors.Is(err, errInjected) {
		t.Errorf("quota insert fault: %v", err)
	}
	plan.reset()

	// A failing tenant lock (PostgreSQL only) aborts the counters and the
	// quota swap.
	d := *db.dialect
	d.lockTenant = "SELECT bogus("
	db.dialect = &d
	if _, err := db.QuotaAlerts().CompareAndSet(ctx, f.tid, QuotaLevelNone, QuotaLevelWarning, time.Time{}); err == nil ||
		!strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("CompareAndSet with a failing lock = %v", err)
	}
	if err := db.TenantUsage().Add(ctx, f.tid, day, UsageCounts{Transfers: 1}); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Add with a failing lock = %v", err)
	}
}

// rollbackAfter turns the result of a write run for its error paths only
// into errRollback, so that the fault test leaves the data in place.
func rollbackAfter(_ int64, err error) error {
	if err != nil {
		return err
	}
	return errRollback
}

// testPHCInternal is a syntactically valid password hash.
const testPHCInternal = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
