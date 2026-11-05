package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestSecurityEventsSchemaHoldsNoAddress pins the columns of
// security_events (threat model T-285): closed tokens, a client IP, bounded
// details and counters, and no column that could hold an e-mail address or
// free text. A new column must be reviewed against T-285 before it is
// added to this list.
func TestSecurityEventsSchemaHoldsNoAddress(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		const known = `('id', 'at', 'tenant_id', 'event_type', 'reason', 'ip', 'details', 'occurrences', 'last_seen_at')`
		columns := `SELECT count(*) FROM pragma_table_info('security_events')`
		other := columns + ` WHERE name NOT IN ` + known
		if db.dialect.numbered {
			columns = `SELECT count(*) FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = 'security_events'`
			other = columns + ` AND column_name NOT IN ` + known
		}
		if n := rawInt(ctx, t, db, columns); n != 9 {
			t.Errorf("security_events has %d columns, want 9", n)
		}
		if n := rawInt(ctx, t, db, other); n != 0 {
			t.Errorf("security_events has %d unreviewed columns", n)
		}
		// The checks of the migration bound the token columns.
		for name, q := range map[string]string{
			"reason too long": `INSERT INTO security_events (id, at, event_type, reason, occurrences, last_seen_at)
				VALUES ('sev_x', 1, 'rate_limited', '` + strings.Repeat("a", MaxSecurityEventReasonLen+1) + `', 1, 1)`,
			"last seen before": `INSERT INTO security_events (id, at, event_type, occurrences, last_seen_at)
				VALUES ('sev_y', 2, 'rate_limited', 1, 1)`,
			"no occurrence": `INSERT INTO security_events (id, at, event_type, occurrences, last_seen_at)
				VALUES ('sev_z', 1, 'rate_limited', 0, 1)`,
		} {
			if err := rawExecArgs(ctx, t, db, q); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	})
}

// TestSecurityEventsDriverFaults reaches the error paths of the security
// events repository that a healthy database never takes, on the tenant
// and the system listings alike.
func TestSecurityEventsDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	tid := newTestTenant(ctx, t, db, "a.example.com")
	repo := db.SecurityEvents()
	saved, err := repo.Save(ctx, []SecurityEvent{{TenantID: tid, Type: "rate_limited"}})
	if err != nil {
		t.Fatal(err)
	}
	upd := saved[0]
	upd.Occurrences = 2
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"insert", faultExec, "INSERT INTO security_events", func() error {
			_, err := repo.Save(ctx, []SecurityEvent{{Type: "rate_limited"}})
			return err
		}},
		{"update", faultExec, "UPDATE security_events", func() error {
			_, err := repo.Save(ctx, []SecurityEvent{upd})
			return err
		}},
		{"tenant query", faultQuery, "SELECT id, at, event_type", func() error {
			_, err := repo.List(ctx, SecurityEventFilter{TenantID: tid})
			return err
		}},
		{"tenant scan", faultScanNil, "SELECT id, at, event_type", func() error {
			_, err := repo.List(ctx, SecurityEventFilter{TenantID: tid})
			return err
		}},
		{"system query", faultQuery, "SELECT tenant_id, id", func() error {
			_, err := repo.List(ctx, SecurityEventFilter{})
			return err
		}},
		{"system scan", faultScanNil, "SELECT tenant_id, id", func() error {
			_, err := repo.List(ctx, SecurityEventFilter{})
			return err
		}},
	} {
		plan.reset()
		plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	plan.reset()
	// The identifier generator fails: nothing is written.
	db.newAuditID = func(id.Prefix) (string, error) { return "", errInjected }
	if _, err := repo.Save(ctx, []SecurityEvent{{Type: "rate_limited"}}); !errors.Is(err, errInjected) {
		t.Errorf("Save with a failing generator = %v", err)
	}
}
