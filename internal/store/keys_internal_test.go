package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Master key identifiers of the internal tests.
const (
	testMK1 = "mk_1111111111111111"
	testMK2 = "mk_2222222222222222"
	testMK3 = "mk_3333333333333333"
)

// keyFixture is a fault-injecting database holding a tenant, an active
// master key, two keys wrapped under it and a running rotation to testMK2.
type keyFixture struct {
	db   *DB
	plan *faultPlan
	tid  tenant.ID
	wk   string
	rot  string
}

// newKeyFixture builds a keyFixture; with empty set, the database only
// holds the tenant.
func newKeyFixture(t *testing.T, empty bool) *keyFixture {
	t.Helper()
	ctx := context.Background()
	db, plan := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	f := &keyFixture{db: db, plan: plan, tid: tn.ID}
	if empty {
		return f
	}
	if _, err := db.MasterKeys().EnsureActive(ctx, testMK1, time.Now()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		f.wk = id.New(id.WrappedKey)
		if err := db.WrappedKeys().Create(ctx, tn.ID, WrappedKey{ID: f.wk, Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("k")}); err != nil {
			t.Fatal(err)
		}
	}
	f.rot = id.New(id.Rotation)
	if err := db.KeyRotations().Start(ctx, Rotation{ID: f.rot, FromKeyID: testMK1, ToKeyID: testMK2, TotalKeys: 2}); err != nil {
		t.Fatal(err)
	}
	return f
}

// identityRewrap returns the key unchanged.
func identityRewrap(k WrappedKey, _ tenant.ID) ([]byte, error) { return k.Blob, nil }

// rewrapAll rewraps every key of the fixture's rotation.
func (f *keyFixture) rewrapAll(t *testing.T) {
	t.Helper()
	if _, err := f.db.KeyRotations().RewrapBatch(context.Background(), f.rot, testMK1, testMK2, 100, identityRewrap); err != nil {
		t.Fatal(err)
	}
}

// TestKeyDriverFaults injects a driver failure into each statement of the
// key repositories and checks that it surfaces as an error.
func TestKeyDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	type step struct {
		name, op, match string
		after           int // matching statements let through before the fault
		empty           bool
		prep            func(*testing.T, *keyFixture)
		run             func(*keyFixture) error
	}
	createKey := func(f *keyFixture) error {
		return f.db.WrappedKeys().Create(ctx, f.tid, WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("k")})
	}
	getKey := func(f *keyFixture) error { _, err := f.db.WrappedKeys().Get(ctx, f.tid, f.wk); return err }
	deleteKey := func(f *keyFixture) error { return f.db.WrappedKeys().Delete(ctx, f.tid, f.wk) }
	inUse := func(f *keyFixture) error { _, err := f.db.WrappedKeys().KeyIDsInUse(ctx); return err }
	count := func(f *keyFixture) error { _, err := f.db.WrappedKeys().CountByKey(ctx, testMK1); return err }
	list := func(f *keyFixture) error { _, err := f.db.MasterKeys().List(ctx); return err }
	ensure := func(f *keyFixture) error { _, err := f.db.MasterKeys().EnsureActive(ctx, testMK1, now); return err }
	start := func(f *keyFixture) error {
		return f.db.KeyRotations().Start(ctx, Rotation{ID: id.New(id.Rotation), FromKeyID: testMK1, ToKeyID: testMK2})
	}
	rewrap := func(f *keyFixture) error {
		_, err := f.db.KeyRotations().RewrapBatch(ctx, f.rot, testMK1, testMK2, 100, identityRewrap)
		return err
	}
	complete := func(f *keyFixture) error { return f.db.KeyRotations().Complete(ctx, f.rot, now) }
	fail := func(f *keyFixture) error { return f.db.KeyRotations().Fail(ctx, f.rot, "boom", now) }
	scrub := func(f *keyFixture) error { return f.db.ScrubDeleted(ctx) }
	abandon := func(f *keyFixture) error { return f.db.KeyRotations().Abandon(ctx, f.rot, "abandoned", now) }
	registered := func(t *testing.T, f *keyFixture) {
		if _, err := f.db.MasterKeys().EnsureActive(ctx, testMK1, now); err != nil {
			t.Fatal(err)
		}
	}
	allRewrapped := func(t *testing.T, f *keyFixture) { f.rewrapAll(t) }

	steps := []step{
		{name: "create", op: faultExec, match: "INSERT INTO wrapped_keys", run: createKey},
		{name: "get", op: faultQuery, match: "FROM wrapped_keys WHERE tenant_id", run: getKey},
		{name: "delete", op: faultExec, match: "DELETE FROM wrapped_keys", run: deleteKey},
		{name: "in use query", op: faultQuery, match: "DISTINCT", run: inUse},
		{name: "in use scan", op: faultScanNil, match: "DISTINCT", run: inUse},
		{name: "count", op: faultQuery, match: "SELECT count(*) FROM wrapped_keys", run: count},
		{name: "list query", op: faultQuery, match: "FROM master_keys ORDER BY", run: list},
		{name: "list scan", op: faultScanNil, match: "FROM master_keys ORDER BY", run: list},
		{name: "ensure count", op: faultQuery, match: "SELECT count(*) FROM master_keys", empty: true, run: ensure},
		{name: "ensure insert", op: faultExec, match: "INSERT INTO master_keys", empty: true, run: ensure},
		{name: "start running", op: faultQuery, match: "WHERE status = 'running'", empty: true, prep: registered, run: start},
		{name: "start target status", op: faultQuery, match: "SELECT status FROM master_keys", empty: true, prep: registered, run: start},
		{name: "start source status", op: faultQuery, match: "SELECT status FROM master_keys", after: 1, empty: true, prep: registered, run: start},
		{name: "ensure in use", op: faultQuery, match: "DISTINCT", empty: true, run: ensure},
		{name: "scrub", op: faultQuery, match: "wal_checkpoint", run: scrub},
		{name: "rewrap get", op: faultQuery, match: "FROM key_rotations WHERE id", run: rewrap},
		{name: "rewrap batch query", op: faultQuery, match: "ORDER BY id LIMIT", run: rewrap},
		{name: "rewrap batch scan", op: faultScanNil, match: "ORDER BY id LIMIT", run: rewrap},
		{name: "rewrap update", op: faultExec, match: "UPDATE wrapped_keys", run: rewrap},
		{name: "rewrap update rows", op: faultRows, match: "UPDATE wrapped_keys", run: rewrap},
		{name: "rewrap progress", op: faultExec, match: "SET rewrapped_keys", run: rewrap},
		{name: "rewrap progress rows", op: faultRows, match: "SET rewrapped_keys", run: rewrap},
		{name: "complete get", op: faultQuery, match: "FROM key_rotations WHERE id", prep: allRewrapped, run: complete},
		{name: "complete count", op: faultQuery, match: "SELECT count(*) FROM wrapped_keys", prep: allRewrapped, run: complete},
		{name: "complete retire", op: faultExec, match: "SET status = 'retired'", prep: allRewrapped, run: complete},
		{name: "complete status", op: faultQuery, match: "SELECT status FROM master_keys", prep: allRewrapped, run: complete},
		{name: "complete lock", op: faultExec, match: "lock wrapped_keys", prep: func(t *testing.T, f *keyFixture) { f.rewrapAll(t); withLock(f.db) }, run: complete},
		{name: "complete add", op: faultExec, match: "INSERT INTO master_keys", prep: allRewrapped, run: complete},
		{name: "complete finish", op: faultExec, match: "UPDATE key_rotations SET status", prep: allRewrapped, run: complete},
		{name: "fail finish", op: faultExec, match: "UPDATE key_rotations SET status", run: fail},
		{name: "abandon get", op: faultQuery, match: "FROM key_rotations WHERE id", run: abandon},
		{name: "abandon lock", op: faultExec, match: "lock wrapped_keys", prep: func(_ *testing.T, f *keyFixture) { withLock(f.db) }, run: abandon},
		{name: "abandon status", op: faultQuery, match: "SELECT status FROM master_keys", run: abandon},
		{name: "abandon count", op: faultQuery, match: "SELECT count(*) FROM wrapped_keys", run: abandon},
		{name: "abandon finish", op: faultExec, match: "UPDATE key_rotations SET status", run: abandon},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newKeyFixture(t, s.empty)
			if s.prep != nil {
				s.prep(t, f)
			}
			f.plan.add(s.op, s.match, s.after)
			if err := s.run(f); err == nil {
				t.Errorf("%s: fault %s on %q ignored", s.name, s.op, s.match)
			}
			f.plan.reset()
			if err := s.run(f); err != nil {
				t.Errorf("%s fails without faults: %v", s.name, err)
			}
		})
	}
}

// fakeResult is a sql.Result with a chosen row count or error.
type fakeResult struct {
	n   int64
	err error
}

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return r.n, r.err }

func TestAffected(t *testing.T) {
	t.Parallel()
	if err := affected(fakeResult{n: 1}); err != nil {
		t.Errorf("one row: %v", err)
	}
	if err := affected(fakeResult{}); !errors.Is(err, ErrRotationNotRunning) {
		t.Errorf("no row: %v", err)
	}
	if err := affected(fakeResult{err: errInjected}); !errors.Is(err, errInjected) {
		t.Errorf("driver error: %v", err)
	}
}

func TestValidMasterKeyID(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		testMK1: true, "mk_0123456789abcdef": true,
		"": false, "mk_": false, "mk_0123456789abcde": false, "mk_0123456789abcdef0": false,
		"mk_0123456789abcdeg": false, "mk_0123456789ABCDEF": false, "MK_0123456789abcdef": false, "xx_0123456789abcdef": false,
	} {
		if got := validMasterKeyID(s); got != want {
			t.Errorf("validMasterKeyID(%q) = %v, want %v", s, got, want)
		}
	}
}

// rawSystemExec runs a raw statement (without placeholders) in a system
// transaction on the write pool.
func rawSystemExec(ctx context.Context, db *DB, q string) (sql.Result, error) {
	var res sql.Result
	err := db.runTx(ctx, db.write, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		var err error
		res, err = tx.ExecContext(ctx, q)
		return err
	})
	return res, err
}

// TestKeySchemaConstraints checks the guarantees the schema enforces by
// itself, on both engines: a single active master key, a single running
// rotation, distinct rotation keys, and the conditional rewrap.
func TestKeySchemaConstraints(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		conflict := func(what, q string) {
			t.Helper()
			if _, err := rawSystemExec(ctx, db, q); !errors.Is(classify(err), ErrConflict) {
				t.Errorf("%s: err = %v, want a uniqueness violation", what, err)
			}
		}
		if _, err := rawSystemExec(ctx, db, `INSERT INTO master_keys (id, status, created_at) VALUES ('`+testMK1+`', 'active', 0)`); err != nil {
			t.Fatal(err)
		}
		conflict("second active master key", `INSERT INTO master_keys (id, status, created_at) VALUES ('`+testMK2+`', 'active', 0)`)
		if _, err := rawSystemExec(ctx, db, `INSERT INTO master_keys (id, status, created_at) VALUES ('`+testMK2+`', 'retired', 0)`); err != nil {
			t.Errorf("retired master key: %v", err)
		}
		insertRot := func(rotID, status string) string {
			return `INSERT INTO key_rotations (id, from_key_id, to_key_id, status, total_keys, rewrapped_keys, started_at)
				VALUES ('` + rotID + `', '` + testMK1 + `', '` + testMK2 + `', '` + status + `', 0, 0, 0)`
		}
		if _, err := rawSystemExec(ctx, db, insertRot("rot_a", "running")); err != nil {
			t.Fatal(err)
		}
		conflict("second running rotation", insertRot("rot_b", "running"))
		if _, err := rawSystemExec(ctx, db, insertRot("rot_c", "failed")); err != nil {
			t.Errorf("failed rotation: %v", err)
		}
		for what, q := range map[string]string{
			"same keys": `INSERT INTO key_rotations (id, from_key_id, to_key_id, status, total_keys, rewrapped_keys, started_at)
				VALUES ('rot_d', '` + testMK1 + `', '` + testMK1 + `', 'failed', 0, 0, 0)`,
			"bad status":  insertRot("rot_e", "paused"),
			"bad purpose": `INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES ('wk_x', 'ten_x', 'kek', 'k', 'x', 0)`,
		} {
			if _, err := rawSystemExec(ctx, db, q); err == nil {
				t.Errorf("%s accepted", what)
			}
		}

		// The rewrap update leaves a row already moved to another key alone.
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		wk := id.New(id.WrappedKey)
		if err := db.WrappedKeys().Create(ctx, tn.ID, WrappedKey{ID: wk, Purpose: KeyPurposeDEK, KeyID: testMK3, Blob: []byte("new")}); err != nil {
			t.Fatal(err)
		}
		var n int64
		err = db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
			res, err := tx.Exec(ctx, qWrappedKeyRewrap, []byte("stale"), testMK3, wk, testMK1)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil || n != 0 {
			t.Errorf("conditional rewrap updated %d rows, %v", n, err)
		}
		if k, _ := db.WrappedKeys().Get(ctx, tn.ID, wk); string(k.Blob) != "new" {
			t.Errorf("blob overwritten: %q", k.Blob)
		}
	})
}

// TestKeyTablesRLS checks on PostgreSQL that a tenant-scoped transaction
// can neither read nor write the system key tables, and sees only its own
// wrapped keys.
func TestKeyTablesRLS(t *testing.T) {
	t.Parallel()
	e, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL not available")
	}
	ctx := context.Background()
	db := openEngine(t, e)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if e.Driver != config.DriverPostgres {
		t.Fatalf("engine %s", e.Driver)
	}
	var tids []tenant.ID
	for _, host := range []string{"a.example.com", "b.example.com"} {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: host, FQDN: host, DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		tids = append(tids, tn.ID)
		if err := db.WrappedKeys().Create(ctx, tn.ID, WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("k")}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.MasterKeys().EnsureActive(ctx, testMK1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.KeyRotations().Start(ctx, Rotation{ID: id.New(id.Rotation), FromKeyID: testMK1, ToKeyID: testMK2}); err != nil {
		t.Fatal(err)
	}
	err := db.runTx(ctx, db.write, db.dialect.scopeTenant, []any{string(tids[0])}, func(tx *sql.Tx) error {
		for q, want := range map[string]int{
			`SELECT count(*) FROM master_keys`:                                              1, // read policy: ids are not secret
			`SELECT count(*) FROM key_rotations`:                                            0,
			`SELECT count(*) FROM wrapped_keys`:                                             1,
			`SELECT count(*) FROM wrapped_keys WHERE tenant_id = '` + string(tids[1]) + `'`: 0,
		} {
			var n int
			if err := tx.QueryRowContext(ctx, q).Scan(&n); err != nil || n != want {
				t.Errorf("%s = %d, %v; want %d", q, n, err, want)
			}
		}
		for _, q := range []string{
			`UPDATE master_keys SET status = 'retired'`,
			`DELETE FROM key_rotations`,
			`DELETE FROM wrapped_keys WHERE tenant_id = '` + string(tids[1]) + `'`,
		} {
			res, err := tx.ExecContext(ctx, q)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 0 {
				t.Errorf("%s affected %d rows", q, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO master_keys (id, status, created_at) VALUES ('` + testMK2 + `', 'retired', 0)`,
		`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES ('wk_x', '` + string(tids[1]) + `', 'dek', 'k', 'x', 0)`,
	} {
		err := db.runTx(ctx, db.write, db.dialect.scopeTenant, []any{string(tids[0])}, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, q)
			return err
		})
		if err == nil {
			t.Errorf("tenant scope could run %s", q)
		}
	}
	if keys, err := db.MasterKeys().List(ctx); err != nil || len(keys) != 1 || keys[0].Status != MasterKeyActive {
		t.Errorf("master keys after the attempts = %+v, %v", keys, err)
	}
}

// withLock gives db a dialect whose wrapped_keys lock is a harmless
// statement, so that the PostgreSQL-only lock path runs on SQLite.
func withLock(db *DB) {
	d := *db.dialect
	d.lockWrappedKeys = "SELECT 'lock wrapped_keys'"
	db.dialect = &d
}

func TestScrubDeletedBusy(t *testing.T) {
	t.Parallel()
	db, _ := openFault(t)
	d := *db.dialect
	d.scrubDeleted = "SELECT 1, 10, 5" // busy, as reported by a partial checkpoint
	db.dialect = &d
	if err := db.ScrubDeleted(context.Background()); !errors.Is(err, ErrScrubBusy) {
		t.Errorf("ScrubDeleted(busy) = %v, want ErrScrubBusy", err)
	}
}

// TestCleanupRotation covers keys wrapped under the old master key after a
// completed rotation (the PostgreSQL race the lock of Complete closes, or a
// database restored from an older backup): a clean-up rotation from the
// retired key to the active one rewraps them without changing the master
// keys.
func TestCleanupRotation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if e.Driver != config.DriverPostgres {
			withLock(db) // PostgreSQL runs the real LOCK TABLE
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		keys, rots, mks := db.WrappedKeys(), db.KeyRotations(), db.MasterKeys()
		if _, err := mks.EnsureActive(ctx, testMK1, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := keys.Create(ctx, tn.ID, WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("a")}); err != nil {
			t.Fatal(err)
		}
		rotate := func(from, to string) error {
			rot := Rotation{ID: id.New(id.Rotation), FromKeyID: from, ToKeyID: to}
			if err := rots.Start(ctx, rot); err != nil {
				return err
			}
			if _, err := rots.RewrapBatch(ctx, rot.ID, from, to, 100, identityRewrap); err != nil {
				return err
			}
			return rots.Complete(ctx, rot.ID, time.Now())
		}
		if err := rotate(testMK1, testMK2); err != nil {
			t.Fatalf("A to B: %v", err)
		}
		before, err := mks.List(ctx)
		if err != nil {
			t.Fatal(err)
		}

		// A straggler under the retired key: the trigger refuses it, so it
		// is planted by unregistering the key for the insert.
		straggler := WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("late")}
		if err := keys.Create(ctx, tn.ID, straggler); !errors.Is(err, ErrKeyRetired) {
			t.Fatalf("Create under the retired key = %v, want ErrKeyRetired", err)
		}
		retiredAt := before[0].RetiredAt.UnixMilli()
		if _, err := rawSystemExec(ctx, db, `DELETE FROM master_keys WHERE id = '`+testMK1+`'`); err != nil {
			t.Fatal(err)
		}
		if err := keys.Create(ctx, tn.ID, straggler); err != nil {
			t.Fatal(err)
		}
		if _, err := rawSystemExec(ctx, db, fmt.Sprintf(`INSERT INTO master_keys (id, status, created_at, retired_at)
			VALUES ('%s', 'retired', %d, %d)`, testMK1, before[0].CreatedAt.UnixMilli(), retiredAt)); err != nil {
			t.Fatal(err)
		}
		if ids, err := keys.KeyIDsInUse(ctx); err != nil || len(ids) != 2 {
			t.Fatalf("KeyIDsInUse = %v, %v", ids, err)
		}

		// Clean-up rotation A (retired) to B (active).
		if err := rotate(testMK1, testMK2); err != nil {
			t.Fatalf("clean-up rotation: %v", err)
		}
		after, err := mks.List(ctx)
		if err != nil || len(after) != 2 || after[0] != before[0] || after[1] != before[1] {
			t.Errorf("master keys changed by the clean-up rotation:\nbefore %+v\nafter  %+v, %v", before, after, err)
		}
		if active, err := mks.Active(ctx); err != nil || active != testMK2 {
			t.Errorf("Active = %q, %v", active, err)
		}
		if k, err := keys.Get(ctx, tn.ID, straggler.ID); err != nil || k.KeyID != testMK2 {
			t.Errorf("straggler = %+v, %v", k, err)
		}
		if ids, err := keys.KeyIDsInUse(ctx); err != nil || len(ids) != 1 || ids[0] != testMK2 {
			t.Errorf("KeyIDsInUse after clean-up = %v, %v", ids, err)
		}

		// The rewrap trigger refuses a retired target as well.
		err = db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
			_, err := tx.Exec(ctx, qWrappedKeyRewrap, []byte("x"), testMK1, straggler.ID, testMK2)
			return err
		})
		if !errors.Is(classify(err), ErrKeyRetired) {
			t.Errorf("rewrap to a retired key = %v, want the trigger to refuse it", err)
		}
	})
}

// TestCompleteRefusesRetiredTarget covers a target key retired between
// Start and Complete (only possible by tampering).
func TestCompleteRefusesRetiredTarget(t *testing.T) {
	t.Parallel()
	f := newKeyFixture(t, false)
	ctx := context.Background()
	f.rewrapAll(t)
	if _, err := rawSystemExec(ctx, f.db, `INSERT INTO master_keys (id, status, created_at) VALUES ('`+testMK2+`', 'retired', 0)`); err != nil {
		t.Fatal(err)
	}
	if err := f.db.KeyRotations().Complete(ctx, f.rot, time.Now()); !errors.Is(err, ErrKeyRetired) {
		t.Errorf("Complete(retired target) = %v, want ErrKeyRetired", err)
	}
}
