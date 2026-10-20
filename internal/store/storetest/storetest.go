// Package storetest provides the database engines the store tests run on.
//
// [Engines] always returns a SQLite engine backed by a temporary file, and a
// PostgreSQL engine when TT_TEST_POSTGRES_DSN (runtime role) and
// TT_TEST_POSTGRES_MIGRATE_DSN (owner role) are set (make test starts the
// throwaway server of test/docker-compose.test.yml). Each PostgreSQL engine
// gets a fresh schema, created by the owner role, selected through the
// search_path connection parameter of both DSNs and dropped when the test
// ends, so tests are independent and may run in parallel. When TT_TEST_REQUIRE_POSTGRES=1 (make check), an
// unreachable PostgreSQL fails the test instead of being skipped.
//
// The package does not import the store, so that the store's own internal
// tests can use it.
package storetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	// Register the "pgx" database/sql driver.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ed-fr/transteira/internal/config"
)

// Environment variables read by Engines.
const (
	// EnvPostgresDSN is the DSN of the test PostgreSQL server, runtime role.
	EnvPostgresDSN = "TT_TEST_POSTGRES_DSN"
	// EnvPostgresMigrateDSN is the DSN of the test PostgreSQL server, owner
	// role (migrations and per-test schemas).
	EnvPostgresMigrateDSN = "TT_TEST_POSTGRES_MIGRATE_DSN"
	// EnvRequirePostgres, set to "1", makes a missing or unreachable
	// PostgreSQL a test failure.
	EnvRequirePostgres = "TT_TEST_REQUIRE_POSTGRES"
)

// connectTimeout bounds the PostgreSQL reachability check.
const connectTimeout = 5 * time.Second

// Engine is a database a test can open with store.Open.
type Engine struct {
	// Name is the engine name used for sub-test names ("sqlite",
	// "postgres").
	Name string
	// Driver is config.DriverSQLite or config.DriverPostgres.
	Driver string
	// DSN is the connection string of a database reserved for the test
	// (runtime role for PostgreSQL).
	DSN string
	// MigrateDSN is the owner-role connection string used by migrations
	// ("" for SQLite).
	MigrateDSN string
	// Schema is the PostgreSQL schema reserved for the test ("" for SQLite).
	Schema string
}

// Config returns an installation configuration selecting the engine.
func (e Engine) Config() *config.Config {
	return &config.Config{DBDriver: e.Driver, DBDSN: config.NewSecret(e.DSN), DBMigrateDSN: config.NewSecret(e.MigrateDSN)}
}

// SQLite returns a SQLite engine on a new file in a temporary directory
// removed at the end of the test.
func SQLite(t testing.TB) Engine {
	t.Helper()
	return Engine{
		Name:   config.DriverSQLite,
		Driver: config.DriverSQLite,
		DSN:    filepath.Join(t.TempDir(), "transteira.db"),
	}
}

// Postgres returns a PostgreSQL engine on a fresh schema, or ok=false when
// TT_TEST_POSTGRES_DSN or TT_TEST_POSTGRES_MIGRATE_DSN is unset or the
// server is unreachable. In both cases
// it fails the test instead when TT_TEST_REQUIRE_POSTGRES=1.
func Postgres(t testing.TB) (Engine, bool) {
	t.Helper()
	required := os.Getenv(EnvRequirePostgres) == "1"
	dsn, ownerDSN := os.Getenv(EnvPostgresDSN), os.Getenv(EnvPostgresMigrateDSN)
	if dsn == "" || ownerDSN == "" {
		if required {
			t.Fatalf("storetest: %s=1 but %s or %s is not set", EnvRequirePostgres, EnvPostgresDSN, EnvPostgresMigrateDSN)
		}
		return Engine{}, false
	}
	// The owner role creates and drops the per-test schema.
	admin, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		t.Fatalf("storetest: invalid %s: %v", EnvPostgresMigrateDSN, err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		if required {
			t.Fatalf("storetest: PostgreSQL unreachable (run make test-env-up): %v", err)
		}
		t.Logf("storetest: PostgreSQL unreachable, running on SQLite only: %v", err)
		return Engine{}, false
	}
	schema := "tt_" + randomHex(t, 8)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("storetest: creating schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("storetest: dropping schema %s: %v", schema, err)
		}
	})
	return Engine{
		Name:       config.DriverPostgres,
		Driver:     config.DriverPostgres,
		DSN:        withSearchPath(t, dsn, schema),
		MigrateDSN: withSearchPath(t, ownerDSN, schema),
		Schema:     schema,
	}, true
}

// Engines returns the engines every store test must run on: SQLite always,
// PostgreSQL when available (mandatory with TT_TEST_REQUIRE_POSTGRES=1).
func Engines(t testing.TB) []Engine {
	t.Helper()
	engines := []Engine{SQLite(t)}
	if pg, ok := Postgres(t); ok {
		engines = append(engines, pg)
	}
	return engines
}

// Run runs fn as a sub-test on every engine returned by Engines.
func Run(t *testing.T, fn func(t *testing.T, e Engine)) {
	t.Helper()
	for _, e := range Engines(t) {
		t.Run(e.Name, func(t *testing.T) { fn(t, e) })
	}
}

// withSearchPath adds the search_path run-time parameter to a PostgreSQL
// DSN, in URL or keyword/value form.
func withSearchPath(t testing.TB, dsn, schema string) string {
	t.Helper()
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return dsn + " search_path=" + schema
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("storetest: invalid PostgreSQL DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// randomHex returns n random bytes in hexadecimal.
func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("storetest: random: %v", err)
	}
	return hex.EncodeToString(b)
}
