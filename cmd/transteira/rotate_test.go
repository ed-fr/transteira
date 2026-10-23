package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// writeKeyFile writes a new random master key to a new directory outside the
// data volumes and returns its path.
func writeKeyFile(t *testing.T) string {
	t.Helper()
	path, _ := masterkeytest.WriteKeyFile(t, t.TempDir())
	return path
}

// keyStore opens the SQLite database dsn, migrated, with the key of keyFile.
func keyStore(t *testing.T, dsn, keyFile string) (*store.DB, *masterkey.Vault) {
	t.Helper()
	cfg := &config.Config{DBDriver: config.DriverSQLite, DBDSN: config.NewSecret(dsn), MasterKeyFile: keyFile}
	db, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	kr, err := masterkey.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Close)
	return db, masterkey.NewVault(db, kr, nil)
}

// sealUnder stores a secret for a new tenant, wrapped with the key of
// keyFile, in the database of dsn, and returns the tenant and row IDs.
func sealUnder(t *testing.T, dsn, keyFile string) (tenant.ID, string) {
	t.Helper()
	ctx := context.Background()
	db, v := keyStore(t, dsn, keyFile)
	kr, err := masterkey.Load(&config.Config{MasterKeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Close()
	if _, err := masterkey.Check(ctx, db, kr, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	wkID, err := v.Seal(ctx, tn.ID, crypto.PurposeSecret, []byte("smtp password"))
	if err != nil {
		t.Fatal(err)
	}
	return tn.ID, wkID
}

// expectOpens checks that the secret wkID of tid opens with keyFile alone.
func expectOpens(t *testing.T, dsn, keyFile string, tid tenant.ID, wkID string) {
	t.Helper()
	_, v := keyStore(t, dsn, keyFile)
	if got, err := v.Open(context.Background(), tid, crypto.PurposeSecret, wkID); err != nil || string(got) != "smtp password" {
		t.Errorf("Open(%s) failed: %v", wkID, err)
	}
}

func TestRotateMasterKeyCommand(t *testing.T) {
	dsn := setMigrateEnv(t)
	oldKey, newKey := writeKeyFile(t), writeKeyFile(t)
	tid, wkID := sealUnder(t, dsn, oldKey)
	t.Setenv("TT_MASTER_KEY_FILE", oldKey)

	// Without the new key the command refuses to run.
	if code, _, errOut := runCmd("rotate-master-key"); code != exitError || !strings.Contains(errOut, masterkey.ErrNoNewKey.Error()) {
		t.Fatalf("rotate-master-key (no new key) = %d, %q", code, errOut)
	}

	t.Setenv("TT_MASTER_KEY_NEW_FILE", newKey)
	t.Setenv("TT_LOG_LEVEL", "error") // the progress is printed whatever the level
	code, out, errOut := runCmd("rotate-master-key", "-batch-size", "1")
	if code != exitOK || !strings.Contains(out, "1/1 key(s) re-wrapped") || !strings.Contains(out, "completed: 1 key(s) re-wrapped") ||
		!strings.Contains(out, masterkey.DocLink) || errOut != "" {
		t.Fatalf("rotate-master-key = %d, %q, %q", code, out, errOut)
	}

	// The startup check now asks to switch TT_MASTER_KEY_FILE.
	code, _, errOut = runCmd("rotate-master-key")
	if code != exitError || !strings.Contains(errOut, "is completed") {
		t.Fatalf("rotate-master-key (completed) = %d, %q", code, errOut)
	}
	expectOpens(t, dsn, newKey, tid, wkID)
	got := rotationAudit(t, dsn, newKey)
	if len(got) != 2 || !strings.HasPrefix(got[0], "master_key.rotation_started system/cli rot_") ||
		!strings.Contains(got[0], `"resumed":false`) || !strings.Contains(got[0], `"total":1`) ||
		!strings.HasPrefix(got[1], "master_key.rotation_completed system/cli rot_") || !strings.Contains(got[1], `"rewrapped":1`) {
		t.Errorf("audit = %q", got)
	}
}

// rotationAudit returns the master key rotation audit events of the
// database dsn, oldest first, as "action kind/actor object details".
func rotationAudit(t *testing.T, dsn, keyFile string) []string {
	t.Helper()
	db, _ := keyStore(t, dsn, keyFile)
	page, err := db.AuditEvents().List(context.Background(), store.AuditFilter{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(page.Items) - 1; i >= 0; i-- {
		e := page.Items[i]
		if strings.HasPrefix(e.Action, "master_key.") {
			out = append(out, fmt.Sprintf("%s %s/%s %s %s", e.Action, e.ActorKind, e.Actor, e.ObjectID, e.Details))
		}
	}
	return out
}

func TestRotateMasterKeyRecoverAndAbandon(t *testing.T) {
	dsn := setMigrateEnv(t)
	k1, k2, k3 := writeKeyFile(t), writeKeyFile(t), writeKeyFile(t)
	tid, wkID := sealUnder(t, dsn, k1)
	t.Setenv("TT_MASTER_KEY_FILE", k1)
	t.Setenv("TT_MASTER_KEY_NEW_FILE", k2)
	if code, _, errOut := runCmd("rotate-master-key"); code != exitOK {
		t.Fatalf("rotate-master-key = %d, %q", code, errOut)
	}
	t.Setenv("TT_MASTER_KEY_FILE", k2)
	t.Setenv("TT_MASTER_KEY_NEW_FILE", "")

	// A straggler under the retired k1 (unregistered for the insert).
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	k1ID := keyID(t, k1)
	exec := func(q string) {
		t.Helper()
		if _, err := raw.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`DELETE FROM master_keys WHERE id = '` + k1ID + `'`)
	_, v1 := keyStore(t, dsn, k1)
	late, err := v1.Seal(context.Background(), tid, crypto.PurposeSecret, []byte("smtp password"))
	if err != nil {
		t.Fatal(err)
	}
	exec(fmt.Sprintf(`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES ('%s', 'retired', 1, 2)`, k1ID))

	// The regular command refuses (no new key); the recovery refuses a key
	// inside a volume, a missing file, and the combination with -abandon.
	if code, _, errOut := runCmd("rotate-master-key"); code != exitError || !strings.Contains(errOut, "TT_MASTER_KEY_NEW_FILE") {
		t.Errorf("rotate-master-key (no new key) = %d, %q", code, errOut)
	}
	inside := filepath.Join(os.Getenv("TT_DATA_DIR"), "old.key")
	if code, _, errOut := runCmd("rotate-master-key", "-recover-from", inside); code != exitError || !strings.Contains(errOut, "must not be located inside") {
		t.Errorf("-recover-from inside a volume = %d, %q", code, errOut)
	}
	if code, _, errOut := runCmd("rotate-master-key", "-recover-from", filepath.Join(t.TempDir(), "missing.key")); code != exitError || !strings.Contains(errOut, "-recover-from") {
		t.Errorf("-recover-from missing file = %d, %q", code, errOut)
	}
	if code, _, _ := runCmd("rotate-master-key", "-recover-from", k1, "-abandon"); code != exitUsage {
		t.Errorf("-recover-from with -abandon = %d", code)
	}
	if code, _, errOut := runCmd("rotate-master-key", "-recover-from", k3); code != exitError || !strings.Contains(errOut, "not recorded as retired") {
		t.Errorf("-recover-from an unknown key = %d, %q", code, errOut)
	}

	code, out, errOut := runCmd("rotate-master-key", "-recover-from", k1)
	if code != exitOK || !strings.Contains(out, "Recovery") || !strings.Contains(out, "1 key(s) re-wrapped from the retired key "+k1ID) {
		t.Fatalf("rotate-master-key -recover-from = %d, %q, %q", code, out, errOut)
	}
	expectOpens(t, dsn, k2, tid, wkID)
	expectOpens(t, dsn, k2, tid, late)

	// -abandon: nothing running, then a rotation to k3 with nothing under it.
	if code, _, errOut := runCmd("rotate-master-key", "-abandon"); code != exitError || !strings.Contains(errOut, "no master key rotation is running") {
		t.Errorf("-abandon (nothing running) = %d, %q", code, errOut)
	}
	db, _ := keyStore(t, dsn, k2)
	kr, err := masterkey.Load(&config.Config{MasterKeyFile: k2, MasterKeyNewFile: k3})
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Close()
	rot, err := masterkey.StartRotation(context.Background(), db, kr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runCmd("rotate-master-key", "-abandon")
	if code != exitOK || !strings.Contains(out, "Rotation "+rot.ID) || !strings.Contains(out, "abandoned") {
		t.Errorf("-abandon = %d, %q, %q", code, out, errOut)
	}
	// Rotation, recovery, abandon: every step is audited by the command.
	got := rotationAudit(t, dsn, k2)
	want := []string{
		"master_key.rotation_started system/cli", "master_key.rotation_completed system/cli",
		"master_key.rotation_started system/cli", "master_key.rotation_completed system/cli",
		"master_key.rotation_failed system/cli " + rot.ID,
	}
	if len(got) != len(want) {
		t.Fatalf("audit = %q", got)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("audit[%d] = %q, want %q...", i, got[i], w)
		}
	}
	if !strings.Contains(got[4], `"reason":"abandoned"`) || !strings.Contains(got[2], `"from":"`+k1ID+`"`) {
		t.Errorf("audit details = %q", got)
	}
}

// keyID returns the ID of the key in path.
func keyID(t *testing.T, path string) string {
	t.Helper()
	k, err := crypto.LoadMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	return k.ID()
}

func TestRotateMasterKeyCommandErrors(t *testing.T) {
	dsn := setMigrateEnv(t)
	t.Setenv("TT_DB_DRIVER", "oracle")
	if code, _, errOut := runCmd("rotate-master-key"); code != exitError || !strings.Contains(errOut, "TT_DB_DRIVER") {
		t.Errorf("rotate-master-key (bad config) = %d, %q", code, errOut)
	}
	t.Setenv("TT_DB_DRIVER", "sqlite")

	// Unreadable key file: refused before the database is touched.
	t.Setenv("TT_MASTER_KEY_NEW_FILE", writeKeyFile(t))
	for _, args := range [][]string{{"rotate-master-key"}, {"rotate-master-key", "-recover-from", writeKeyFile(t)}} {
		if code, _, errOut := runCmd(args...); code != exitError || !strings.Contains(errOut, "TT_MASTER_KEY_FILE") {
			t.Errorf("%v (missing key file) = %d, %q", args, code, errOut)
		}
	}
	if _, err := os.Stat(dsn); !os.IsNotExist(err) {
		t.Errorf("the database was created: %v", err)
	}

	// Unreachable database.
	t.Setenv("TT_MASTER_KEY_FILE", writeKeyFile(t))
	t.Setenv("TT_DB_DSN", filepath.Join(t.TempDir(), "missing", "db.sqlite"))
	for _, args := range [][]string{{"rotate-master-key"}, {"rotate-master-key", "-abandon"}, {"rotate-master-key", "-recover-from", writeKeyFile(t)}} {
		if code, _, errOut := runCmd(args...); code != exitError || !strings.Contains(errOut, "opening sqlite database") {
			t.Errorf("%v (no database) = %d, %q", args, code, errOut)
		}
	}

	// Wrong current key: the startup check refuses.
	t.Setenv("TT_DB_DSN", dsn)
	sealUnder(t, dsn, writeKeyFile(t))
	if code, _, errOut := runCmd("rotate-master-key"); code != exitError || !strings.Contains(errOut, "which are not provided") {
		t.Errorf("rotate-master-key (wrong key) = %d, %q", code, errOut)
	}

	// Failed rotation: a corrupted row under the current key.
	second := filepath.Join(filepath.Dir(dsn), "second.db")
	t.Setenv("TT_DB_DSN", second)
	cur := writeKeyFile(t)
	t.Setenv("TT_MASTER_KEY_FILE", cur)
	tid, wkID := sealUnder(t, second, cur)
	db, _ := keyStore(t, second, cur)
	row, err := db.WrappedKeys().Get(context.Background(), tid, wkID)
	if err != nil {
		t.Fatal(err)
	}
	row.ID = "wk_01JAAAAAAAAAAAAAAAAAAAAAAA"
	if err := db.WrappedKeys().Create(context.Background(), tid, row); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCmd("rotate-master-key"); code != exitError || !strings.Contains(errOut, "cannot be unwrapped") {
		t.Errorf("rotate-master-key (corrupted row) = %d, %q", code, errOut)
	}
}

func TestInterrupted(t *testing.T) {
	t.Parallel()
	other := errors.New("other")
	if err := interrupted(store.Rotation{}, other); !errors.Is(err, other) {
		t.Errorf("interrupted(other) = %v", err)
	}
	if err := interrupted(store.Rotation{}, context.Canceled); err == nil || !strings.Contains(err.Error(), "before the rotation started") {
		t.Errorf("interrupted(before start) = %v", err)
	}
	err := interrupted(store.Rotation{ID: "rot_x", RewrappedKeys: 3}, fmt.Errorf("wrapped: %w", context.Canceled))
	if err == nil || !strings.Contains(err.Error(), "after 3 key(s)") || !strings.Contains(err.Error(), "rot_x") {
		t.Errorf("interrupted(after start) = %v", err)
	}
}

// TestRotateMasterKeyRecoverFirstBatchFails: a clean-up rotation whose
// first batch fails still records its start before its failure.
func TestRotateMasterKeyRecoverFirstBatchFails(t *testing.T) {
	dsn := setMigrateEnv(t)
	k1, k2 := writeKeyFile(t), writeKeyFile(t)
	tid, _ := sealUnder(t, dsn, k1)
	t.Setenv("TT_MASTER_KEY_FILE", k1)
	t.Setenv("TT_MASTER_KEY_NEW_FILE", k2)
	if code, _, errOut := runCmd("rotate-master-key"); code != exitOK {
		t.Fatalf("rotate-master-key = %d, %q", code, errOut)
	}
	t.Setenv("TT_MASTER_KEY_FILE", k2)
	t.Setenv("TT_MASTER_KEY_NEW_FILE", "")

	// A corrupted straggler under the retired k1 (unregistered for the
	// insert).
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	exec := func(q string) {
		t.Helper()
		if _, err := raw.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	k1ID := keyID(t, k1)
	exec(`DELETE FROM master_keys WHERE id = '` + k1ID + `'`)
	db, _ := keyStore(t, dsn, k2)
	bad := store.WrappedKey{
		ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: k1ID,
		Blob: []byte(strings.Repeat("x", 60)),
	}
	if err := db.WrappedKeys().Create(context.Background(), tid, bad); err != nil {
		t.Fatal(err)
	}
	exec(fmt.Sprintf(`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES ('%s', 'retired', 1, 2)`, k1ID))
	code, out, errOut := runCmd("rotate-master-key", "-recover-from", k1)
	if code != exitError || !strings.Contains(errOut, bad.ID) {
		t.Fatalf("rotate-master-key -recover-from (corrupted row) = %d, %q, %q", code, out, errOut)
	}
	got := rotationAudit(t, dsn, k2)
	want := []string{
		"master_key.rotation_started system/cli", "master_key.rotation_completed system/cli",
		"master_key.rotation_started system/cli", "master_key.rotation_failed system/cli",
	}
	if len(got) != len(want) {
		t.Fatalf("audit = %q", got)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("audit[%d] = %q, want %q...", i, got[i], w)
		}
	}
	if !strings.Contains(got[2], `"resumed":false`) || !strings.Contains(got[3], `"reason":"rewrap"`) {
		t.Errorf("audit details = %q", got)
	}
}
