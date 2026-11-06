package store

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// newFaultDropLink stores an enabled drop link (level "internal") in the
// fixture's tenant, without injected faults, and returns it.
func newFaultDropLink(ctx context.Context, t *testing.T, f *transferFixture, recipients ...string) DropLink {
	t.Helper()
	if len(recipients) == 0 {
		recipients = []string{"svc@a.example.com"}
	}
	h := sha256.Sum256([]byte(id.New(id.DropLink)))
	l, err := f.db.DropLinks().Create(ctx, f.tid, DropLink{
		ID: id.New(id.DropLink), TokenHash: h[:], Label: "Docs", Recipients: recipients, ValidityDays: 7,
		ConfidentialityLevel: "internal", Enabled: true, CreatedBy: "adm_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestDropLinkDriverFaults injects a driver failure into each statement of
// the drop link repository and checks that it surfaces as an error.
func TestDropLinkDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	type step struct {
		name, op, match string
		run             func(t *testing.T, f *transferFixture) func() error
	}
	create := func(_ *testing.T, f *transferFixture) func() error {
		return func() error {
			h := sha256.Sum256([]byte(id.New(id.DropLink)))
			_, err := f.db.DropLinks().Create(ctx, f.tid, DropLink{
				ID: id.New(id.DropLink), TokenHash: h[:], Label: "Docs", Recipients: []string{"svc@a.example.com"},
				ValidityDays: 7, ConfidentialityLevel: "internal", Enabled: true, CreatedBy: "adm_1",
			})
			return err
		}
	}
	update := func(t *testing.T, f *transferFixture) func() error {
		l := newFaultDropLink(ctx, t, f)
		return func() error {
			_, _, err := f.db.DropLinks().Update(ctx, f.tid, l.ID, DropLinkUpdate{Label: "New"}, now)
			return err
		}
	}
	revoke := func(t *testing.T, f *transferFixture) func() error {
		l := newFaultDropLink(ctx, t, f)
		return func() error { _, _, err := f.db.DropLinks().Revoke(ctx, f.tid, l.ID, now); return err }
	}
	purge := func(t *testing.T, f *transferFixture) func() error {
		l := newFaultDropLink(ctx, t, f)
		if _, _, err := f.db.DropLinks().Revoke(ctx, f.tid, l.ID, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		return func() error { _, err := f.db.DropLinks().Purge(ctx, f.tid, now); return err }
	}
	list := func(t *testing.T, f *transferFixture) func() error {
		newFaultDropLink(ctx, t, f)
		return func() error { _, err := f.db.DropLinks().List(ctx, f.tid); return err }
	}
	count := func(t *testing.T, f *transferFixture) func() error {
		newFaultDropLink(ctx, t, f)
		return func() error { _, err := f.db.DropLinks().CountByRecipient(ctx, f.tid, "svc@a.example.com"); return err }
	}
	erase := func(t *testing.T, f *transferFixture) func() error {
		newFaultDropLink(ctx, t, f)
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.DropLinks().RemoveRecipientTx(ctx, tx, "svc@a.example.com", now)
				return err
			})
		}
	}
	replaceLevels := func(t *testing.T, f *transferFixture) func() error {
		levels, err := f.db.ConfidentialityLevels().List(ctx, f.tid)
		if err != nil {
			t.Fatal(err)
		}
		return func() error {
			_, err := f.db.ConfidentialityLevels().Replace(ctx, f.tid, levels, "admin", now)
			return err
		}
	}
	usage := func(t *testing.T, f *transferFixture) func() error {
		l := newFaultDropLink(ctx, t, f)
		return func() error { _, err := f.db.DropLinks().UsageSince(ctx, f.tid, l.ID, now); return err }
	}
	usageTx := func(t *testing.T, f *transferFixture) func() error {
		l := newFaultDropLink(ctx, t, f)
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.DropLinks().UsageSinceTx(ctx, tx, l.ID, now)
				return err
			})
		}
	}
	useSession := func(t *testing.T, f *transferFixture) func() error {
		l := newFaultDropLink(ctx, t, f)
		s := DepositSession{
			ID: id.New(id.DepositSession), TokenHash: hashOf("ds-fault"), Email: "x@partner.example.org",
			Kind: DepositorDropLink, DropLinkID: l.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := f.db.DepositSessions().Create(ctx, f.tid, s); err != nil {
			t.Fatal(err)
		}
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				return f.db.DropLinks().UseSessionTx(ctx, tx, s.ID, l.ID, now)
			})
		}
	}
	steps := []step{
		{"use session", faultExec, "SET used_at = ?", useSession},
		{"usage", faultQuery, "min(used_at)", usage},
		{"usage tx", faultQuery, "min(used_at)", usageTx},
		{"create count", faultQuery, "SELECT count(*) FROM drop_links WHERE tenant_id = ?", create},
		{"create level", faultQuery, "FROM confidentiality_levels WHERE tenant_id = ? AND key = ?", create},
		{"create insert", faultExec, "INSERT INTO drop_links", create},
		{"update read", faultQuery, "FROM drop_links WHERE tenant_id = ? AND id = ?", update},
		{"update write", faultExec, "UPDATE drop_links SET label", update},
		{"revoke write", faultExec, "UPDATE drop_links SET revoked_at", revoke},
		{"revoke rows", faultRows, "UPDATE drop_links SET revoked_at", revoke},
		{"list", faultQuery, "ORDER BY created_at DESC, id DESC", list},
		{"list scan", faultScanNil, "ORDER BY created_at DESC, id DESC", list},
		{"purge list", faultQuery, "expires_at < ?) AND id > ?", purge},
		{"purge refs", faultQuery, "drop_link_id = ?", purge},
		{"purge delete", faultExec, "DELETE FROM drop_links", purge},
		{"purge rows", faultRows, "DELETE FROM drop_links", purge},
		{"count recipients", faultQuery, "SELECT id, recipients FROM drop_links", count},
		{"count recipients scan", faultScanNil, "SELECT id, recipients FROM drop_links", count},
		{"erase recipients", faultQuery, "SELECT id, recipients FROM drop_links", erase},
		{"erase write", faultExec, "UPDATE drop_links SET recipients", erase},
		{"replace levels keys", faultQuery, "SELECT DISTINCT confidentiality_level FROM drop_links", replaceLevels},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newTransferFixture(t)
			run := s.run(t, f)
			f.plan.add(s.op, s.match, 0)
			if err := run(); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestDropLinkStoredValues checks that a malformed recipient list in the
// database is reported, never returned.
func TestDropLinkStoredValues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	l := newFaultDropLink(ctx, t, f)
	// The column check accepts any JSON array; strings are expected.
	if _, err := f.db.write.ExecContext(ctx, `UPDATE drop_links SET recipients = '[1]' WHERE id = ?`, l.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DropLinks().Get(ctx, f.tid, l.ID); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("Get(malformed recipients) = %v", err)
	}
	if _, err := f.db.DropLinks().CountByRecipient(ctx, f.tid, "svc@a.example.com"); err == nil {
		t.Error("CountByRecipient(malformed recipients) succeeded")
	}
}

// TestDropLinkLockFailure checks that a failing tenant lock (PostgreSQL
// only) fails every drop link write that takes it.
func TestDropLinkLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	l := newFaultDropLink(ctx, t, f)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	h := sha256.Sum256([]byte("x"))
	_, err := f.db.DropLinks().Create(ctx, f.tid, DropLink{
		ID: id.New(id.DropLink), TokenHash: h[:], Label: "Docs", Recipients: []string{"svc@a.example.com"},
		ValidityDays: 7, Enabled: true, CreatedBy: "adm_1",
	})
	if err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Create with a failing lock = %v", err)
	}
	if _, _, err := f.db.DropLinks().Update(ctx, f.tid, l.ID, DropLinkUpdate{Label: "X"}, time.Time{}); err == nil ||
		!strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Update with a failing lock = %v", err)
	}
	err = f.tx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.DropLinks().RemoveRecipientTx(ctx, tx, "svc@a.example.com", time.Time{})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("RemoveRecipientTx with a failing lock = %v", err)
	}
}
