package storetest

import (
	"strings"
	"testing"
)

func TestWithSearchPath(t *testing.T) {
	t.Parallel()
	got := withSearchPath(t, "postgres://u:p@h:5432/db?sslmode=disable", "tt_x")
	if !strings.Contains(got, "search_path=tt_x") || !strings.Contains(got, "sslmode=disable") {
		t.Errorf("URL form = %q", got)
	}
	if got := withSearchPath(t, "host=h dbname=db", "tt_x"); got != "host=h dbname=db search_path=tt_x" {
		t.Errorf("keyword form = %q", got)
	}
}

func TestSQLiteEngine(t *testing.T) {
	t.Parallel()
	e := SQLite(t)
	if e.Name != "sqlite" || e.Schema != "" || !strings.HasSuffix(e.DSN, "transteira.db") {
		t.Errorf("SQLite() = %+v", e)
	}
	if c := e.Config(); c.DBDriver != "sqlite" || c.DBDSN.Reveal() != e.DSN {
		t.Errorf("Config() = %+v", c)
	}
}

func TestPostgresUnavailable(t *testing.T) {
	// Clear the environment of make test (TT_TEST_REQUIRE_POSTGRES=1 and
	// both DSNs) so that the fallback is tested deterministically.
	t.Setenv(EnvRequirePostgres, "")
	t.Setenv(EnvPostgresDSN, "")
	t.Setenv(EnvPostgresMigrateDSN, "")
	if _, ok := Postgres(t); ok {
		t.Error("Postgres() without DSN reported ok")
	}
	t.Setenv(EnvPostgresDSN, "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	if _, ok := Postgres(t); ok {
		t.Error("Postgres() without migrate DSN reported ok")
	}
	t.Setenv(EnvPostgresMigrateDSN, "postgres://o:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	if _, ok := Postgres(t); ok {
		t.Error("Postgres() with an unreachable server reported ok")
	}
	if n := len(Engines(t)); n != 1 {
		t.Errorf("Engines() = %d engines, want SQLite only", n)
	}
}
