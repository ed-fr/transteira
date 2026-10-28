package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// testLevels is a valid list of one level.
func testLevels() []ConfidentialityLevel {
	return []ConfidentialityLevel{{
		Key: "only", Labels: map[string]string{"fr": "Seul", "en": "Only"}, IsDefault: true,
		Rules: ConfidentialityRules{ExpiryDaysMask: ExpiryMaskAll},
	}}
}

// TestConfidentialityDriverFaults makes each statement of the
// confidentiality level and recipient rule repositories fail.
func TestConfidentialityDriverFaults(t *testing.T) {
	t.Parallel()
	rules := RecipientRuleSet{Allowed: []string{"a.example"}, Denied: []string{"b.example"}}
	steps := []struct {
		name, op, match string
		run             func(context.Context, *DB, tenant.ID) error
	}{
		{"list levels", faultQuery, "FROM confidentiality_levels WHERE tenant_id = ? ORDER BY", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.ConfidentialityLevels().List(ctx, tid)
			return err
		}},
		{"scan levels", faultScanNil, "FROM confidentiality_levels WHERE tenant_id = ? ORDER BY", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.ConfidentialityLevels().List(ctx, tid)
			return err
		}},
		{"list levels tx", faultQuery, "FROM confidentiality_levels WHERE tenant_id = ? ORDER BY", func(ctx context.Context, db *DB, tid tenant.ID) error {
			s, _ := db.Scoped(tid)
			return s.ReadTx(ctx, func(tx *ScopedTx) error {
				_, err := db.ConfidentialityLevels().ListTx(ctx, tx)
				return err
			})
		}},
		{"delete levels", faultExec, "DELETE FROM confidentiality_levels", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.ConfidentialityLevels().Replace(ctx, tid, testLevels(), "", time.Time{})
			return err
		}},
		{"insert level", faultExec, "INSERT INTO confidentiality_levels", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.ConfidentialityLevels().Replace(ctx, tid, testLevels(), "", time.Time{})
			return err
		}},
		{"list rules", faultQuery, "FROM recipient_domain_rules", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.RecipientRules().Get(ctx, tid)
			return err
		}},
		{"scan rules", faultScanNil, "FROM recipient_domain_rules", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.RecipientRules().Get(ctx, tid)
			return err
		}},
		{"list rules tx", faultQuery, "FROM recipient_domain_rules", func(ctx context.Context, db *DB, tid tenant.ID) error {
			s, _ := db.Scoped(tid)
			return s.ReadTx(ctx, func(tx *ScopedTx) error {
				_, err := db.RecipientRules().GetTx(ctx, tx)
				return err
			})
		}},
		{"delete rules", faultExec, "DELETE FROM recipient_domain_rules", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.RecipientRules().Replace(ctx, tid, rules, time.Time{})
			return err
		}},
		{"insert rule", faultExec, "INSERT INTO recipient_domain_rules", func(ctx context.Context, db *DB, tid tenant.ID) error {
			_, err := db.RecipientRules().Replace(ctx, tid, rules, time.Time{})
			return err
		}},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db, plan := openFault(t)
			tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.RecipientRules().Replace(ctx, tn.ID, rules, time.Time{}); err != nil {
				t.Fatal(err)
			}
			plan.add(s.op, s.match, 0)
			if err := s.run(ctx, db, tn.ID); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestConfidentialityLockFailure checks that a failing tenant lock
// (PostgreSQL only) aborts both replaces.
func TestConfidentialityLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	d := *db.dialect
	d.lockTenant = "SELECT bogus("
	db.dialect = &d
	if _, err := db.ConfidentialityLevels().Replace(ctx, tn.ID, testLevels(), "", time.Time{}); err == nil {
		t.Error("levels Replace with a failing lock succeeded")
	}
	if _, err := db.RecipientRules().Replace(ctx, tn.ID, RecipientRuleSet{}, time.Time{}); err == nil {
		t.Error("rules Replace with a failing lock succeeded")
	}
}

// TestConfidentialityMalformedRows checks that a stored level or transfer
// label that is not valid JSON is reported, not silently read.
func TestConfidentialityMalformedRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	s, _ := f.db.Scoped(f.tid)
	err := s.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.tx.ExecContext(ctx, `UPDATE confidentiality_levels SET descriptions = 'nope' WHERE tenant_id = ? AND key = 'public'`, string(f.tid))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ConfidentialityLevels().Get(ctx, f.tid, "public"); !errors.Is(err, ErrInvalid) {
		t.Errorf("Get(malformed level) = %v", err)
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.tx.ExecContext(ctx, `UPDATE confidentiality_levels SET descriptions = 'null' WHERE tenant_id = ? AND key = 'internal'`, string(f.tid))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if l, err := f.db.ConfidentialityLevels().Get(ctx, f.tid, "internal"); err != nil || l.Descriptions == nil {
		t.Errorf("Get(null descriptions) = %#v, %v", l.Descriptions, err)
	}

	trf := f.trf
	trf.ID = id.New(id.Transfer)
	trf.ConfidentialityLevel, trf.ConfidentialityLabel = "public", map[string]string{"fr": "P", "en": "P"}
	trf.Rules = &ConfidentialityRules{ExpiryDaysMask: 1}
	if err := f.create(ctx, trf, f.newFile(ctx, t)); err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.tx.ExecContext(ctx, `UPDATE transfers SET confidentiality_label = '[' WHERE tenant_id = ? AND id = ?`, string(f.tid), trf.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Transfers().Get(ctx, f.tid, trf.ID); !errors.Is(err, ErrInvalid) {
		t.Errorf("Get(malformed label) = %v", err)
	}
}
