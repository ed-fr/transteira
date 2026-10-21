package integration_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// execSystem runs statements on the database of e, bypassing the store, in
// one transaction of the system scope (on PostgreSQL, app.system_scope =
// 'on').
func execSystem(t *testing.T, e storetest.Engine, stmts ...string) {
	t.Helper()
	driver := "sqlite"
	if e.Driver == config.DriverPostgres {
		driver = "pgx"
		stmts = append([]string{`SELECT set_config('app.system_scope', 'on', true)`}, stmts...)
	}
	dsn := e.DSN
	if driver == "sqlite" {
		// The running server writes concurrently: wait for its lock
		// instead of failing with SQLITE_BUSY.
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "_pragma=busy_timeout(10000)"
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	ctx := context.Background()
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestStragglerRecovery covers a key wrapped under the old master key after
// its rotation completed (a process that kept running with the old key, or
// a database restored from an older backup): the server refuses to start
// with the new key and points to "rotate-master-key -recover-from", the
// real command re-wraps the straggler under the active key, and the server
// then starts and opens every key.
func TestStragglerRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the transteira binary")
	}
	t.Parallel()
	bin := buildBinary(t, t.TempDir())
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		k1, k2 := newKeyFile(t, "K1"), newKeyFile(t, "K2")
		a, _ := createTenants(t, e)
		base := testEnv(t, e, serverOptions{clamd: fakeClamd(t)})
		mustStart(t, "first start with K1", withKeys(base, k1, nil)).stop(t)
		ks1 := openKeyStore(t, e, k1, nil)
		before := newEncryptedFile(t, ks1, a.ID, 1)

		// Rotation K1 -> K2 with the real command, then the switch.
		if code, out, errOut := runRotateCommand(t, bin, withKeys(base, k1, &k2)); code != 0 {
			t.Fatalf("rotate-master-key exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		envK2 := withKeys(base, k2, nil)
		mustStart(t, "start with K2", envK2).stop(t)

		// A straggler under the retired K1. The database refuses it, so K1
		// is unregistered for the insert, as a write racing the completion
		// or an old backup would leave it.
		records, err := ks1.db.MasterKeys().List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var rec store.MasterKeyRecord
		for _, r := range records {
			if r.ID == k1.id {
				rec = r
			}
		}
		if rec.Status != store.MasterKeyRetired {
			t.Fatalf("K1 is not retired: %+v", records)
		}
		execSystem(t, e, `DELETE FROM master_keys WHERE id = '`+k1.id+`'`)
		straggler := newEncryptedFile(t, ks1, a.ID, 2)
		execSystem(t, e, fmt.Sprintf(`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES ('%s', 'retired', %d, %d)`,
			k1.id, rec.CreatedAt.UnixMilli(), rec.RetiredAt.UnixMilli()))
		if got := keyIDOf(t, ks1, a.ID, straggler.wkID); got != k1.id {
			t.Fatalf("straggler under %s, want K1", got)
		}

		// The server refuses K2 alone, naming K1 and the recovery command.
		mustRefuse(t, "restart with K2 and a straggler", envK2, masterkey.ReasonMissingKey, k1.id, k1, k2)
		if _, _, err := startApp(t, envK2); err == nil || !strings.Contains(err.Error(), "-recover-from") {
			t.Fatalf("app.Run = %v, want a refusal pointing to -recover-from", err)
		}

		// Recovery with the real command, K1 given on the command line only.
		code, out, errOut := runRotateCommand(t, bin, envK2, "-recover-from", k1.path)
		if code != 0 || !strings.Contains(out, "1 key(s) re-wrapped from the retired key "+k1.id) {
			t.Fatalf("rotate-master-key -recover-from exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		assertNoKeyMaterial(t, "rotate-master-key -recover-from output", out+errOut, k1, k2)

		mustStart(t, "start with K2 after the recovery", envK2).stop(t)
		ks2 := openKeyStore(t, e, k2, nil)
		assertDecrypts(t, "after the recovery, with K2 only", ks2, []encryptedFile{before, straggler})
		if got, err := ks2.vault.Open(ctx, a.ID, crypto.PurposeDEK, straggler.wkID); err != nil || len(got) != crypto.DEKSize {
			t.Errorf("straggler after the recovery: %v", err)
		}
	})
}
