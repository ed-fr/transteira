package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// withTenantFixture is a migrated database with one existing tenant.
type withTenantFixture struct {
	db    *DB
	e     storetest.Engine
	other *tenant.Tenant
}

// newWithTenantFixture opens and migrates e and creates the tenant
// "other.example.com", with one network rule.
func newWithTenantFixture(t *testing.T, e storetest.Engine) *withTenantFixture {
	t.Helper()
	ctx := context.Background()
	db := openEngine(t, e)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	other, err := db.Tenants().Create(ctx, wtTenant("other.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.NetworkRules().Replace(ctx, other.ID, nil, []string{"other.example.com"}); err != nil {
		t.Fatal(err)
	}
	return &withTenantFixture{db: db, e: e, other: other}
}

// wtTenant returns a valid new tenant for fqdn.
func wtTenant(fqdn string) *tenant.Tenant {
	return &tenant.Tenant{
		SetupState: tenant.SetupStateActive, Name: fqdn, FQDN: fqdn, DefaultLanguage: "fr",
		MaxTransferBytes: 1 << 20, StorageQuotaBytes: 1 << 30,
	}
}

// wtUnknownTenant is a well-formed tenant ID that names no tenant.
const wtUnknownTenant = tenant.ID("ten_01J00000000000000000000000")

// writeWholeConfig writes every configuration part of the tenant of tx with
// the Tx variants, failing the test on any error.
func writeWholeConfig(t *testing.T, ctx context.Context, db *DB, tx *ScopedTx) {
	t.Helper()
	if _, err := db.NetworkRules().ReplaceTx(ctx, tx, []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}, []string{"New.Example.com"}); err != nil {
		t.Fatalf("network rules: %v", err)
	}
	if _, err := db.RecipientRules().ReplaceTx(ctx, tx, RecipientRuleSet{Allowed: []string{"partner.example"}, Denied: []string{"mail.example"}}, time.Time{}); err != nil {
		t.Fatalf("recipient rules: %v", err)
	}
	if _, err := db.ConfidentialityLevels().ReplaceTx(ctx, tx, testLevels(), "adm_test", time.Time{}); err != nil {
		t.Fatalf("levels: %v", err)
	}
	abuse := DefaultAbuseSettings()
	abuse.MaxInvitationsPerInviter = 7
	if _, err := db.AbuseSettings().PutTx(ctx, tx, abuse); err != nil {
		t.Fatalf("abuse: %v", err)
	}
	if _, err := db.TenantEmailTemplates().PutTx(ctx, tx, EmailTemplate{Key: EmailTemplateInvitation, Language: "fr", Subject: "Invitation"}); err != nil {
		t.Fatalf("template: %v", err)
	}
	if _, err := db.TenantLegalDocuments().PutTx(ctx, tx, LegalDocument{Document: LegalNotice, Language: "fr", Content: "Mentions"}); err != nil {
		t.Fatalf("legal: %v", err)
	}
	if _, err := db.Blocklist().CreateTx(ctx, tx, BlocklistEntry{Kind: BlockDomain, Value: "Bad.Example"}); err != nil {
		t.Fatalf("blocklist: %v", err)
	}
	if err := db.SMTPSettings().PutTx(ctx, tx, SMTPConfig{Host: "relay", Port: 25, Security: SMTPSecurityNone, FromAddress: "noreply@new.example.com"}); err != nil {
		t.Fatalf("smtp: %v", err)
	}
}

// TestWithTenantCreateWith writes the whole configuration of a new tenant
// in the transaction that creates it: everything commits together, the
// commit hooks run after the commit, and system queries work again in the
// same transaction afterwards.
func TestWithTenantCreateWith(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newWithTenantFixture(t, e)
		db := f.db
		var hookRan, hookSawTenant bool
		created, err := db.Tenants().CreateWith(ctx, wtTenant("new.example.com"), func(tx *SystemTx, c *tenant.Tenant) error {
			err := tx.WithTenant(ctx, c.ID, func(stx *ScopedTx) error {
				if stx.Tenant() != c.ID {
					t.Errorf("Tenant() = %s, want %s", stx.Tenant(), c.ID)
				}
				writeWholeConfig(t, ctx, db, stx)
				stx.AfterCommit(func() {
					hookRan = true
					_, err := db.Tenants().Get(ctx, c.ID)
					hookSawTenant = err == nil
				})
				return nil
			})
			if err != nil {
				return err
			}
			if hookRan {
				t.Error("a hook ran before the commit")
			}
			// The system scope is back: the tenant row is readable.
			_, err = scanTenant(tx.QueryRow(ctx, qTenantGet, string(c.ID)))
			return err
		})
		if err != nil {
			t.Fatalf("CreateWith: %v", err)
		}
		if !hookRan || !hookSawTenant {
			t.Fatalf("hook ran=%v saw tenant=%v", hookRan, hookSawTenant)
		}
		nr, err := db.NetworkRules().Get(ctx, created.ID)
		if err != nil || len(nr.CIDRs) != 1 || nr.CIDRs[0].String() != "10.0.0.0/8" || !slices.Equal(nr.Domains, []string{"new.example.com"}) {
			t.Fatalf("network rules: %+v, %v", nr, err)
		}
		rr, err := db.RecipientRules().Get(ctx, created.ID)
		if err != nil || !slices.Equal(rr.Allowed, []string{"partner.example"}) || !slices.Equal(rr.Denied, []string{"mail.example"}) {
			t.Fatalf("recipient rules: %+v, %v", rr, err)
		}
		levels, err := db.ConfidentialityLevels().List(ctx, created.ID)
		if err != nil || len(levels) != 1 || levels[0].Key != "only" {
			t.Fatalf("levels: %+v, %v", levels, err)
		}
		abuse, err := db.AbuseSettings().Get(ctx, created.ID)
		if err != nil || abuse.MaxInvitationsPerInviter != 7 {
			t.Fatalf("abuse: %+v, %v", abuse, err)
		}
		if tpl, err := db.TenantEmailTemplates().Get(ctx, created.ID, EmailTemplateInvitation, "fr"); err != nil || tpl.Subject != "Invitation" {
			t.Fatalf("template: %+v, %v", tpl, err)
		}
		if doc, err := db.TenantLegalDocuments().Get(ctx, created.ID, LegalNotice, "fr"); err != nil || doc.Content != "Mentions" {
			t.Fatalf("legal: %+v, %v", doc, err)
		}
		blocks, err := db.Blocklist().List(ctx, created.ID, BlocklistFilter{})
		if err != nil || len(blocks.Items) != 1 || blocks.Items[0].Value != "bad.example" {
			t.Fatalf("blocklist: %+v, %v", blocks, err)
		}
		if smtp, err := db.SMTPSettings().Get(ctx, created.ID); err != nil || smtp.Host != "relay" {
			t.Fatalf("smtp: %+v, %v", smtp, err)
		}
		// The other tenant is untouched.
		if nr, err := db.NetworkRules().Get(ctx, f.other.ID); err != nil || !slices.Equal(nr.Domains, []string{"other.example.com"}) {
			t.Fatalf("other tenant rules: %+v, %v", nr, err)
		}
	})
}

// TestWithTenantRollback checks that an error of fn rolls back the tenant
// row and every configuration row, and that no hook runs.
func TestWithTenantRollback(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newWithTenantFixture(t, e)
		db := f.db
		boom := errors.New("boom")
		var newID tenant.ID
		hookRan := false
		_, err := db.Tenants().CreateWith(ctx, wtTenant("new.example.com"), func(tx *SystemTx, c *tenant.Tenant) error {
			newID = c.ID
			return tx.WithTenant(ctx, c.ID, func(stx *ScopedTx) error {
				writeWholeConfig(t, ctx, db, stx)
				stx.AfterCommit(func() { hookRan = true })
				return boom
			})
		})
		if !errors.Is(err, boom) {
			t.Fatalf("CreateWith = %v, want boom", err)
		}
		if hookRan {
			t.Fatal("a hook ran after a rollback")
		}
		if _, err := db.Tenants().Get(ctx, newID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tenant after rollback: %v", err)
		}
		if _, err := db.Tenants().TenantByFQDN(ctx, "new.example.com"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tenant by FQDN after rollback: %v", err)
		}
		for _, table := range []string{
			"tenant_network_rules", "recipient_domain_rules", "confidentiality_levels", "tenant_abuse_settings",
			"tenant_email_templates", "tenant_legal_documents", "blocklist_entries", "tenant_smtp_settings",
		} {
			if n := wtCountRows(t, db, table, newID); n != 0 {
				t.Errorf("%s: %d rows left after rollback", table, n)
			}
		}
	})
}

// wtCountRows counts the rows of table for tenant tid, in the system scope
// (bypassing the repositories).
func wtCountRows(t *testing.T, db *DB, table string, tid tenant.ID) int {
	t.Helper()
	var n int
	err := db.systemScope("test count rows").ReadTx(context.Background(), func(tx *SystemTx) error {
		q := `SELECT count(*) FROM ` + table + ` WHERE tenant_id = ?`
		if db.dialect.numbered {
			q = rebindNumbered(q)
		}
		return tx.tx.QueryRowContext(context.Background(), q, string(tid)).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestWithTenantScopeRestored checks that the system scope is back after
// WithTenant, whether fn succeeded or failed with an error that leaves the
// transaction usable, and that an invalid tenant ID is refused without
// calling fn.
func TestWithTenantScopeRestored(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newWithTenantFixture(t, e)
		db := f.db
		boom := errors.New("boom")
		err := db.systemScope("test with tenant").Tx(ctx, func(tx *SystemTx) error {
			for _, tid := range []tenant.ID{"", "nope", "ten_not-a-ulid"} {
				called := false
				err := tx.WithTenant(ctx, tid, func(*ScopedTx) error { called = true; return nil })
				if !errors.Is(err, ErrInvalid) || called {
					t.Errorf("WithTenant(%q) = %v, called=%v; want ErrInvalid without call", tid, err, called)
				}
			}
			// A failing fn that leaves the transaction usable.
			if err := tx.WithTenant(ctx, f.other.ID, func(stx *ScopedTx) error {
				_, err := db.NetworkRules().ReplaceTx(ctx, stx, nil, []string{"not a domain"})
				if !errors.Is(err, ErrInvalid) {
					t.Errorf("ReplaceTx(invalid) = %v", err)
				}
				return boom
			}); !errors.Is(err, boom) {
				t.Errorf("WithTenant(boom) = %v", err)
			}
			if _, err := scanTenant(tx.QueryRow(ctx, qTenantGet, string(f.other.ID))); err != nil {
				t.Errorf("system query after a failed fn: %v", err)
			}
			if err := tx.WithTenant(ctx, f.other.ID, func(*ScopedTx) error { return nil }); err != nil {
				t.Errorf("WithTenant: %v", err)
			}
			if _, err := scanTenant(tx.QueryRow(ctx, qTenantGet, string(f.other.ID))); err != nil {
				t.Errorf("system query after WithTenant: %v", err)
			}
			if e.Driver == "postgres" {
				var scope, tid string
				if err := tx.tx.QueryRowContext(ctx, `SELECT current_setting('app.system_scope', true), current_setting('app.tenant_id', true)`).Scan(&scope, &tid); err != nil {
					return err
				}
				if scope != "on" || tid != "" {
					t.Errorf("scope after WithTenant: system_scope=%q tenant_id=%q", scope, tid)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// TestWithTenantIsolation checks that the ScopedTx of WithTenant only
// reaches the rows of its tenant: through the repositories, and on
// PostgreSQL even with raw statements naming another tenant (row-level
// security).
func TestWithTenantIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newWithTenantFixture(t, e)
		db := f.db
		_, err := db.Tenants().CreateWith(ctx, wtTenant("new.example.com"), func(tx *SystemTx, c *tenant.Tenant) error {
			return tx.WithTenant(ctx, c.ID, func(stx *ScopedTx) error {
				// The repositories see none of the other tenant's rules and
				// replace only the new tenant's.
				set, err := readNetworkRulesForTest(ctx, stx)
				if err != nil {
					return err
				}
				if len(set) != 0 {
					t.Errorf("new tenant sees %d rules of another tenant", len(set))
				}
				if _, err := db.NetworkRules().ReplaceTx(ctx, stx, nil, []string{"new.example.com"}); err != nil {
					return err
				}
				if e.Driver != "postgres" {
					return nil
				}
				// Row-level security: raw statements naming the other
				// tenant neither see nor write its rows.
				var n int
				if err := stx.tx.QueryRowContext(ctx, `SELECT count(*) FROM tenant_network_rules WHERE tenant_id = $1`, string(f.other.ID)).Scan(&n); err != nil {
					return err
				}
				if n != 0 {
					t.Errorf("RLS: tenant scope sees %d rows of another tenant", n)
				}
				res, err := stx.tx.ExecContext(ctx, `DELETE FROM tenant_network_rules WHERE tenant_id = $1`, string(f.other.ID))
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n != 0 {
					t.Errorf("RLS: tenant scope deleted %d rows of another tenant", n)
				}
				// A forbidden insert aborts the PostgreSQL transaction: run
				// it last, in a savepoint.
				if _, err := stx.tx.ExecContext(ctx, `SAVEPOINT wt`); err != nil {
					return err
				}
				if _, err := stx.tx.ExecContext(ctx, `INSERT INTO tenant_network_rules (tenant_id, kind, value) VALUES ($1, 'domain', 'evil.example')`, string(f.other.ID)); err == nil {
					t.Error("RLS: tenant scope inserted a row of another tenant")
				}
				_, err = stx.tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT wt`)
				return err
			})
		})
		if err != nil {
			t.Fatalf("CreateWith: %v", err)
		}
		if nr, err := db.NetworkRules().Get(ctx, f.other.ID); err != nil || !slices.Equal(nr.Domains, []string{"other.example.com"}) {
			t.Fatalf("other tenant rules: %+v, %v", nr, err)
		}
	})
}

// readNetworkRulesForTest lists the raw network rules visible to tx.
func readNetworkRulesForTest(ctx context.Context, tx *ScopedTx) ([]string, error) {
	rows, err := tx.Query(ctx, qRulesList)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (string, error) {
		var kind, value string
		err := r.Scan(&kind, &value)
		return value, err
	})
}

// TestWithTenantScopeErrors checks, on PostgreSQL, the failures of the
// scope statements: setting the tenant scope (fn is not called) and
// restoring the system scope after a successful fn.
func TestWithTenantScopeErrors(t *testing.T) {
	t.Parallel()
	pg, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL unavailable")
	}
	ctx := context.Background()
	f := newWithTenantFixture(t, pg)
	err := f.db.systemScope("test scope errors").Tx(ctx, func(tx *SystemTx) error {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		called := false
		if err := tx.WithTenant(canceled, f.other.ID, func(*ScopedTx) error { called = true; return nil }); err == nil || called {
			t.Errorf("WithTenant(canceled) = %v, called=%v", err, called)
		}
		live, cancelLive := context.WithCancel(ctx)
		defer cancelLive()
		err := tx.WithTenant(live, f.other.ID, func(*ScopedTx) error { cancelLive(); return nil })
		if err == nil || errors.Is(err, ErrInvalid) {
			t.Errorf("WithTenant(restore fails) = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestConfigTxVariants checks the validation and the errors of the Tx
// write variants used by a configuration import: invalid input is refused
// before any statement, and a write for a tenant that does not exist fails.
func TestConfigTxVariants(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newWithTenantFixture(t, e)
		db := f.db
		badAbuse := DefaultAbuseSettings()
		badAbuse.MaxInvitationsPerInviter = 0
		badLevels := testLevels()
		badLevels[0].IsDefault = false
		invalidCases := map[string]func(tx *ScopedTx) error{
			"network rules": func(tx *ScopedTx) error {
				_, err := db.NetworkRules().ReplaceTx(ctx, tx, nil, []string{"bad domain"})
				return err
			},
			"recipient rules allowed": func(tx *ScopedTx) error {
				_, err := db.RecipientRules().ReplaceTx(ctx, tx, RecipientRuleSet{Allowed: []string{"Bad Domain"}}, time.Time{})
				return err
			},
			"recipient rules denied": func(tx *ScopedTx) error {
				_, err := db.RecipientRules().ReplaceTx(ctx, tx, RecipientRuleSet{Denied: []string{"Bad Domain"}}, time.Time{})
				return err
			},
			"levels": func(tx *ScopedTx) error {
				_, err := db.ConfidentialityLevels().ReplaceTx(ctx, tx, badLevels, "adm_test", time.Time{})
				return err
			},
			"abuse": func(tx *ScopedTx) error {
				_, err := db.AbuseSettings().PutTx(ctx, tx, badAbuse)
				return err
			},
			"blocklist": func(tx *ScopedTx) error {
				_, err := db.Blocklist().CreateTx(ctx, tx, BlocklistEntry{Kind: BlockDomain, Value: "not a domain"})
				return err
			},
		}
		for name, fn := range invalidCases {
			err := db.systemScope("test tx variants").Tx(ctx, func(tx *SystemTx) error {
				return tx.WithTenant(ctx, f.other.ID, fn)
			})
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
		// A tenant that does not exist: the inserts violate the foreign key
		// (each case in its own transaction, as the error aborts it on
		// PostgreSQL).
		missingCases := map[string]func(tx *ScopedTx) error{
			"network rules": func(tx *ScopedTx) error {
				_, err := db.NetworkRules().ReplaceTx(ctx, tx, nil, []string{"x.example"})
				return err
			},
			"recipient rules": func(tx *ScopedTx) error {
				_, err := db.RecipientRules().ReplaceTx(ctx, tx, RecipientRuleSet{Allowed: []string{"x.example"}}, time.Time{})
				return err
			},
			"levels": func(tx *ScopedTx) error {
				_, err := db.ConfidentialityLevels().ReplaceTx(ctx, tx, testLevels(), "adm_test", time.Time{})
				return err
			},
			"abuse": func(tx *ScopedTx) error {
				_, err := db.AbuseSettings().PutTx(ctx, tx, DefaultAbuseSettings())
				return err
			},
			"blocklist": func(tx *ScopedTx) error {
				_, err := db.Blocklist().CreateTx(ctx, tx, BlocklistEntry{Kind: BlockDomain, Value: "x.example"})
				return err
			},
		}
		for name, fn := range missingCases {
			s, err := db.Scoped(wtUnknownTenant)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Tx(ctx, fn); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s for a missing tenant: %v, want ErrNotFound", name, err)
			}
		}
		// A duplicate blocklist value is a conflict.
		s, err := db.Scoped(f.other.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *ScopedTx) error {
			for range 2 {
				if _, err := db.Blocklist().CreateTx(ctx, tx, BlocklistEntry{Kind: BlockEmail, Value: "a@x.example"}); err != nil {
					return err
				}
			}
			return nil
		})
		if !errors.Is(err, ErrConflict) {
			t.Errorf("duplicate blocklist entry: %v, want ErrConflict", err)
		}
	})
}
