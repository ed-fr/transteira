package store

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestTxIsolationReadCommitted checks that every PostgreSQL transaction
// runs READ COMMITTED even when the server default is REPEATABLE READ, so
// that the tenant lock followed by a count stays exact (threat T-12).
func TestTxIsolationReadCommitted(t *testing.T) {
	t.Parallel()
	pg, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL not available")
	}
	u, err := url.Parse(pg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("default_transaction_isolation", "repeatable read")
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20") // pgx does not decode "+"
	ctx := context.Background()
	db, err := Open(ctx, &config.Config{DBDriver: pg.Driver, DBDSN: config.NewSecret(u.String()), DBMigrateDSN: config.NewSecret(pg.MigrateDSN)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var def string
	if err := db.write.QueryRowContext(ctx, `SHOW default_transaction_isolation`).Scan(&def); err != nil || def != "repeatable read" {
		t.Fatalf("server default = %q, %v: the test setup is not effective", def, err)
	}
	s, err := db.Scoped(tenant.ID(id.New(id.Tenant)))
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(context.Context, func(*ScopedTx) error) error{"Tx": s.Tx, "ReadTx": s.ReadTx} {
		var level string
		err := run(ctx, func(tx *ScopedTx) error {
			return tx.tx.QueryRowContext(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level)
		})
		if err != nil || level != "read committed" {
			t.Errorf("%s isolation = %q, %v; want read committed", name, level, err)
		}
	}
	err = db.systemScope("test isolation").Tx(ctx, func(tx *SystemTx) error {
		var level string
		if err := tx.tx.QueryRowContext(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level); err != nil {
			return err
		}
		if level != "read committed" {
			t.Errorf("system Tx isolation = %q", level)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
