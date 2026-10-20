package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// envSuperuserDSN is the DSN of the test PostgreSQL bootstrap superuser,
// used only to create throwaway roles.
const envSuperuserDSN = "TT_TEST_POSTGRES_SUPERUSER_DSN"

// liveRoles returns a PostgreSQL engine and a superuser connection, or skips
// the test (fails it when TT_TEST_REQUIRE_POSTGRES=1).
func liveRoles(t *testing.T) (storetest.Engine, *sql.DB) {
	t.Helper()
	e, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL not available")
	}
	dsn := os.Getenv(envSuperuserDSN)
	if dsn == "" {
		if os.Getenv(storetest.EnvRequirePostgres) == "1" {
			t.Fatalf("%s is required with %s=1", envSuperuserDSN, storetest.EnvRequirePostgres)
		}
		t.Skipf("%s not set", envSuperuserDSN)
	}
	su, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = su.Close() })
	return e, su
}

// throwawayRole creates a login role allowed to connect and to use the
// engine's schema, runs the extra grants (with placeholders replaced by the quoted
// role, schema and database: "{role}", "{schema}", "{db}"), and returns a
// runtime DSN for it. The role is dropped at the end of the test.
func throwawayRole(t *testing.T, e storetest.Engine, su *sql.DB, suffix string, extra ...string) string {
	t.Helper()
	ctx := context.Background()
	role := e.Schema + "_" + suffix
	u, err := url.Parse(e.DSN)
	if err != nil {
		t.Fatal(err)
	}
	db := strings.TrimPrefix(u.Path, "/")
	repl := strings.NewReplacer(
		"{role}", pgx.Identifier{role}.Sanitize(),
		"{schema}", pgx.Identifier{e.Schema}.Sanitize(),
		"{db}", pgx.Identifier{db}.Sanitize())
	stmts := append([]string{
		`CREATE ROLE {role} LOGIN PASSWORD 'throwaway' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`,
		`GRANT CONNECT ON DATABASE {db} TO {role}`,
		`GRANT USAGE ON SCHEMA {schema} TO {role}`,
	}, extra...)
	t.Cleanup(func() {
		for _, s := range []string{`DROP OWNED BY {role}`, `DROP ROLE IF EXISTS {role}`} {
			if _, err := su.ExecContext(context.Background(), repl.Replace(s)); err != nil {
				t.Errorf("cleanup %s: %v", s, err)
			}
		}
	})
	for _, s := range stmts {
		if _, err := su.ExecContext(ctx, repl.Replace(s)); err != nil {
			t.Fatalf("%s: %v", repl.Replace(s), err)
		}
	}
	u.User = url.UserPassword(role, "throwaway")
	return u.String()
}

// TestVerifyLiveCreatePrivileges checks, on a real PostgreSQL server, that
// Open refuses a runtime role with CREATE on the database or, through a
// role it belongs to, on its schema, and accepts a plain role.
func TestVerifyLiveCreatePrivileges(t *testing.T) {
	t.Parallel()
	e, su := liveRoles(t)
	ctx := context.Background()
	open := func(dsn string) error {
		db, err := Open(ctx, &config.Config{DBDriver: config.DriverPostgres, DBDSN: config.NewSecret(dsn)})
		if err == nil {
			_ = db.Close()
		}
		return err
	}

	plain := throwawayRole(t, e, su, "plain")
	if err := open(plain); err != nil {
		t.Fatalf("a plain runtime role is refused: %v", err)
	}

	creator := e.Schema + "_creator"
	creatorID := pgx.Identifier{creator}.Sanitize()
	if _, err := su.ExecContext(ctx, `CREATE ROLE `+creatorID+` NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = su.ExecContext(context.Background(), `DROP OWNED BY `+creatorID)
		_, _ = su.ExecContext(context.Background(), `DROP ROLE IF EXISTS `+creatorID)
	})
	member := throwawayRole(t, e, su, "member",
		`GRANT CREATE ON SCHEMA {schema} TO `+creatorID,
		`GRANT `+creatorID+` TO {role}`)
	if err := open(member); !errors.Is(err, ErrUnsafeDatabase) || !strings.Contains(err.Error(), "CREATE") {
		t.Errorf("member of a role with CREATE on the schema: %v", err)
	}

	dbCreate := throwawayRole(t, e, su, "dbcreate", `GRANT CREATE ON DATABASE {db} TO {role}`)
	if err := open(dbCreate); !errors.Is(err, ErrUnsafeDatabase) || !strings.Contains(err.Error(), "CREATE") {
		t.Errorf("CREATE on the database: %v", err)
	}
	if err := open(dbCreate); err != nil && strings.Contains(err.Error(), "throwaway") {
		t.Errorf("error leaks the password: %v", err)
	}
}
