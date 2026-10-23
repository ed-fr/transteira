package isolation_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// adminTables are the system tables of the administration (0008_admin)
// and the instance settings (0012_system): a tenant-scoped transaction
// must neither read nor write them.
var adminTables = []string{
	"admins", "admin_tenants", "admin_sessions", "admin_recovery_codes", "admin_activations",
	"admin_login_failures", "system_secrets", "system_settings",
}

// adminFixture adds to f a super admin with a pending TOTP secret and
// recovery codes, a delegated admin of A with an activation link, a
// session, a login failure counter, and audit events: one global, one of
// A, one of B. It returns the super admin.
func adminFixture(t *testing.T, f *fixture) store.Admin {
	t.Helper()
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	sum := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	sa, err := f.db.Admins().Create(ctx, store.Admin{
		Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",
	})
	must(err)
	must(f.db.Admins().SetPendingTOTP(ctx, sa.ID, store.SystemSecret{
		ID:      id.New(id.SystemSecret),
		Purpose: store.SecretPurposeAdminTOTP, KeyID: "mk_0123456789abcdef", Blob: []byte("sealed"),
	}))
	must(f.db.AdminRecoveryCodes().Replace(ctx, sa.ID, [][]byte{sum("rc")}))
	del, err := f.db.Admins().Create(ctx, store.Admin{
		Username: "admin.a", Email: "a@entity-a.example.com",
		Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{f.a.ID},
	})
	must(err)
	must(f.db.AdminActivations().Create(ctx, store.AdminActivation{
		ID: id.New(id.AdminActivation), AdminID: del.ID,
		TokenHash: sum("act"), CreatedAt: epoch, ExpiresAt: epoch.Add(time.Hour),
	}))
	must(f.db.AdminSessions().Create(ctx, store.AdminSession{
		ID: id.New(id.AdminSession), TokenHash: sum("sess"),
		AdminID: sa.ID, State: store.SessionAuthenticated, CreatedAt: epoch, ExpiresAt: epoch.Add(time.Hour),
	}))
	_, err = f.db.AdminLoginFailures().RecordFailure(ctx, []store.AdminLoginRule{{
		Key: store.AdminLoginIPKey(netip.MustParseAddr("192.0.2.1")), MaxFailures: 5, Window: time.Hour, LockDuration: time.Hour,
	}}, epoch)
	must(err)
	for _, tid := range []tenant.ID{"", f.a.ID, f.b.ID} {
		_, err := f.db.AuditEvents().Append(ctx, store.AuditEvent{
			TenantID: tid, ActorKind: store.ActorAdmin, Actor: "root",
			Action: "admin.login", ObjectKind: "admin", ObjectID: sa.ID,
		})
		must(err)
	}
	return sa
}

// TestRLSAdminTablesSystemOnly bypasses the store: raw transactions scoped
// to a tenant, or without any scope, see no administration row and cannot
// write any; only the system scope reaches them.
func TestRLSAdminTablesSystemOnly(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	sa := adminFixture(t, f)
	a := string(f.a.ID)

	for _, scope := range []*string{&a, nil} {
		_ = inTenantTx(ctx, t, raw, scope, func(tx *sql.Tx) error {
			for _, table := range adminTables {
				if n := countRows(ctx, t, tx, `SELECT count(*) FROM `+table); n != 0 {
					t.Errorf("a tenant-scoped transaction sees %d rows of %s", n, table)
				}
			}
			for _, stmt := range []string{
				`UPDATE admins SET disabled = true`,
				`DELETE FROM admin_sessions`,
				`DELETE FROM system_secrets`,
				`UPDATE admin_recovery_codes SET used_at = NULL`,
				`DELETE FROM admin_login_failures`,
				`DELETE FROM admin_tenants`,
				`UPDATE system_settings SET maintenance_enabled = true, alert_email = 'evil@example.com'`,
				`DELETE FROM system_settings`,
			} {
				if n := affected(ctx, t, tx, stmt); n != 0 {
					t.Errorf("%s affected %d rows from a tenant scope", stmt, n)
				}
			}
			return nil
		})
		inserts := []string{
			`INSERT INTO admins (id, username, email, role, require_totp, created_at, updated_at)
				VALUES ('adm_evil', 'evil', 'e@example.com', 'super_admin', true, 0, 0)`,
			`INSERT INTO admin_tenants (admin_id, tenant_id) VALUES ('` + sa.ID + `', '` + a + `')`,
			`INSERT INTO admin_sessions (id, token_hash, admin_id, state, created_at, last_seen_at, expires_at)
				VALUES ('as_evil', '\x01'::bytea, '` + sa.ID + `', 'authenticated', 0, 0, 9999999999999)`,
			`INSERT INTO admin_login_failures (scope, key, failures) VALUES ('ip', '192.0.2.9', '')`,
			`INSERT INTO system_secrets (id, purpose, key_id, blob, created_at)
				VALUES ('ss_evil', 'admin-totp', 'mk_0123456789abcdef', '\x01'::bytea, 0)`,
			`INSERT INTO system_settings (id, updated_at) VALUES (1, 0)`,
		}
		for _, stmt := range inserts {
			err := inTenantTx(ctx, t, raw, scope, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, stmt)
				return err
			})
			assertRLSViolation(t, stmt, err)
		}
	}

	// The system scope sees them.
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	for _, table := range adminTables {
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM `+table); n == 0 {
			t.Errorf("the system scope sees no row of %s", table)
		}
	}
}

// TestRLSAdminTablesForced checks that every administration table has
// row-level security enabled, forced, and a policy (the generic check of
// rls_test.go only covers the tables with a tenant_id column).
func TestRLSAdminTablesForced(t *testing.T) {
	t.Parallel()
	_, raw := pgFixture(t)
	ctx := t.Context()
	for _, table := range append(adminTables, "audit_events") {
		var enabled, forced bool
		var policies int
		err := raw.QueryRowContext(ctx, `SELECT c.relrowsecurity, c.relforcerowsecurity,
				(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = current_schema() AND c.relname = $1`, table).Scan(&enabled, &forced, &policies)
		if err != nil || !enabled || !forced || policies == 0 {
			t.Errorf("table %s: RLS enabled=%v forced=%v policies=%d (%v)", table, enabled, forced, policies, err)
		}
	}
}

// TestRLSAuditEventsTenantIsolation bypasses the store: a raw transaction
// scoped to A sees and writes A's audit events only, never B's nor the
// global ones.
func TestRLSAuditEventsTenantIsolation(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	adminFixture(t, f)
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		checks := []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM audit_events`, nil, 1},
			{`SELECT count(*) FROM audit_events WHERE tenant_id = $1`, []any{a}, 1},
			{`SELECT count(*) FROM audit_events WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM audit_events WHERE tenant_id IS NULL`, nil, 0},
			{`SELECT count(*) FROM audit_events WHERE true OR tenant_id IS NULL`, nil, 1},
		}
		for _, c := range checks {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, stmt := range []string{
			`UPDATE audit_events SET actor = 'forged' WHERE tenant_id <> '` + a + `' OR tenant_id IS NULL`,
			`DELETE FROM audit_events WHERE tenant_id IS NULL`,
			`DELETE FROM audit_events WHERE tenant_id = '` + b + `'`,
		} {
			if n := affected(ctx, t, tx, stmt); n != 0 {
				t.Errorf("%s affected %d rows", stmt, n)
			}
		}
		return nil
	})
	insert := `INSERT INTO audit_events (id, at, tenant_id, actor_kind, actor, action, object_kind, object_id) VALUES `
	for name, stmt := range map[string]string{
		"other tenant": insert + `('aud_x1', 0, '` + b + `', 'admin', 'x', 'a.b', 'o', 'i')`,
		"global":       insert + `('aud_x2', 0, NULL, 'admin', 'x', 'a.b', 'o', 'i')`,
	} {
		err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, stmt)
			return err
		})
		assertRLSViolation(t, "insert "+name+" audit event", err)
	}
	err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, insert+`('aud_x3', 0, '`+a+`', 'admin', 'x', 'a.b', 'o', 'i')`)
		return err
	})
	if err != nil {
		t.Errorf("a tenant scope cannot append its own audit event: %v", err)
	}
	// Without any scope, nothing is visible.
	_ = inTenantTx(ctx, t, raw, nil, func(tx *sql.Tx) error {
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM audit_events`); n != 0 {
			t.Errorf("an unscoped transaction sees %d audit events", n)
		}
		return nil
	})
}

// TestAuditListTenantIsolation checks, on every engine, that the listing
// of a tenant's audit log returns its own events only, whatever the
// filters and cursors, while the instance-wide listing returns every event.
func TestAuditListTenantIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		f := newFixture(t, e)
		adminFixture(t, f)
		ctx := context.Background()
		repo := f.db.AuditEvents()
		all, err := repo.List(ctx, store.AuditFilter{})
		if err != nil || len(all.Items) != 3 {
			t.Fatalf("List(all) = %+v, %v", all, err)
		}
		for _, tid := range []tenant.ID{f.a.ID, f.b.ID} {
			// Cursors taken from the global listing (other tenants' and global
			// events) only move the page; they never reveal other rows.
			cursors := []string{""}
			for i := range all.Items {
				p, err := repo.List(ctx, store.AuditFilter{Limit: i + 1})
				if err != nil {
					t.Fatal(err)
				}
				cursors = append(cursors, p.NextCursor)
			}
			for _, c := range cursors {
				p, err := repo.List(ctx, store.AuditFilter{TenantID: tid, Cursor: c, Actor: "root", Action: "admin.login"})
				if err != nil {
					t.Fatalf("List(%s, cursor %q): %v", tid, c, err)
				}
				for _, ev := range p.Items {
					if ev.TenantID != tid {
						t.Errorf("tenant %s listed an event of %q", tid, ev.TenantID)
					}
				}
			}
			p, err := repo.List(ctx, store.AuditFilter{TenantID: tid})
			if err != nil || len(p.Items) != 1 {
				t.Errorf("List(%s) = %+v, %v; want its single event", tid, p, err)
			}
		}
	})
}
