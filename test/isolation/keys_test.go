package isolation_test

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Adversarial isolation tests of the encryption at rest (CLAUDE.md sections
// 5 and 16.1; threat model T-30, T-31, T-74, T-75): a wrapped key of tenant
// A is never readable, destroyable nor listable through tenant B's scope, a
// wrapped blob moved to another row or tenant does not open, and a file
// encrypted for one tenant and file does not decrypt under another binding.

// sealedKey is a wrapped key stored through the Vault, with the plaintext it
// must open to.
type sealedKey struct {
	tid       tenant.ID
	wkID      string
	purpose   crypto.Purpose
	plaintext []byte
}

// keyFixture is a fixture whose tenants also own wrapped keys.
type keyFixture struct {
	*fixture
	vault *masterkey.Vault
	// keysA and keysB are the wrapped keys of each tenant, in creation order.
	keysA []sealedKey
	keysB []sealedKey
}

// newKeyFixture builds a fixture and seals, alternately for A and B, n data
// keys and one secret per tenant, under a single deterministic master key.
func newKeyFixture(t *testing.T, e storetest.Engine, n int) *keyFixture {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, "K1"), nil)
	if err != nil {
		t.Fatalf("masterkey.New: %v", err)
	}
	f := &keyFixture{fixture: newFixture(t, e)}
	f.vault = masterkey.NewVault(f.db, kr, nil)
	for range n {
		f.keysA = append(f.keysA, f.newDEK(t, f.a.ID))
		f.keysB = append(f.keysB, f.newDEK(t, f.b.ID))
	}
	f.keysA = append(f.keysA, f.seal(t, f.a.ID, crypto.PurposeSecret, "smtp password of entity A"))
	f.keysB = append(f.keysB, f.seal(t, f.b.ID, crypto.PurposeSecret, "smtp password of entity B"))
	return f
}

// newDEK creates a data key for tid through the Vault.
func (f *keyFixture) newDEK(t *testing.T, tid tenant.ID) sealedKey {
	t.Helper()
	wkID, dek, err := f.vault.NewDEK(t.Context(), tid)
	if err != nil {
		t.Fatalf("NewDEK(%s): %v", tid, err)
	}
	return sealedKey{tid: tid, wkID: wkID, purpose: crypto.PurposeDEK, plaintext: dek}
}

// seal stores secret for tid through the Vault.
func (f *keyFixture) seal(t *testing.T, tid tenant.ID, p crypto.Purpose, secret string) sealedKey {
	t.Helper()
	wkID, err := f.vault.Seal(t.Context(), tid, p, []byte(secret))
	if err != nil {
		t.Fatalf("Seal(%s): %v", tid, err)
	}
	return sealedKey{tid: tid, wkID: wkID, purpose: p, plaintext: []byte(secret)}
}

// assertKeysOpen checks that every key opens, through its own tenant's
// scope, to its original plaintext.
func (f *keyFixture) assertKeysOpen(t *testing.T, who string, keys []sealedKey) {
	t.Helper()
	for _, k := range keys {
		got, err := f.vault.Open(t.Context(), k.tid, k.purpose, k.wkID)
		if err != nil || !bytes.Equal(got, k.plaintext) {
			t.Errorf("%s: Open(%s) = %v; want the original %s key", who, k.wkID, err, k.purpose)
		}
	}
}

// wkIDs returns the row identifiers of keys.
func wkIDs(keys []sealedKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.wkID)
	}
	return out
}

// rawSystemExec runs stmt (with ? placeholders) on the engine's database,
// bypassing the store: an attacker with write access to the database. On
// PostgreSQL it runs with app.system_scope = 'on', the documented bypass of
// the policies, as the raw counts of helpers_test.go do.
func rawSystemExec(t *testing.T, e storetest.Engine, stmt string, args ...any) int64 {
	t.Helper()
	ctx := t.Context()
	raw := rawDB(t, e)
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if e.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', 'on', true)`); err != nil {
			t.Fatalf("set system scope: %v", err)
		}
		stmt = rebind(stmt)
	}
	res, err := tx.ExecContext(ctx, stmt, args...)
	if err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit %s: %v", stmt, err)
	}
	return n
}

// rebind turns ? placeholders into PostgreSQL's $1, $2...
func rebind(q string) string {
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TestWrappedKeyVaultIsolation attacks the wrapped keys of tenant A from
// tenant B's scope, through the Vault and through the store: every attempt
// is reported exactly like a missing key (no oracle), and A's keys still
// open afterwards.
func TestWrappedKeyVaultIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := t.Context()
		f := newKeyFixture(t, e, 3)
		repo := f.db.WrappedKeys()
		missing := id.New(id.WrappedKey)

		// normalized returns err's message with wkID replaced, so that the
		// error for A's key and for a key that never existed can be compared.
		normalized := func(err error, wkID string) string {
			if err == nil {
				return "<nil>"
			}
			return strings.ReplaceAll(err.Error(), wkID, "<id>")
		}

		for _, k := range f.keysA {
			attacks := []struct {
				name string
				run  func(wkID string) error
			}{
				{"Vault.Open as DEK", func(wkID string) error {
					_, err := f.vault.Open(ctx, f.b.ID, crypto.PurposeDEK, wkID)
					return err
				}},
				// The other purpose must not turn into ErrPurposeMismatch,
				// which would reveal that the row exists.
				{"Vault.Open as secret", func(wkID string) error {
					_, err := f.vault.Open(ctx, f.b.ID, crypto.PurposeSecret, wkID)
					return err
				}},
				{"Vault.Destroy", func(wkID string) error { return f.vault.Destroy(ctx, f.b.ID, wkID) }},
				{"WrappedKeys.Get", func(wkID string) error {
					_, err := repo.Get(ctx, f.b.ID, wkID)
					return err
				}},
				{"WrappedKeys.Delete", func(wkID string) error { return repo.Delete(ctx, f.b.ID, wkID) }},
			}
			for _, a := range attacks {
				err := a.run(k.wkID)
				assertNotFound(t, a.name+"(B, A's "+string(k.purpose)+")", err)
				for _, leak := range []string{string(f.a.ID), string(k.plaintext)} {
					if strings.Contains(fmtErr(err), leak) {
						t.Errorf("%s(B, A's key): error %q reveals %q", a.name, err, leak)
					}
				}
				if got, want := normalized(err, k.wkID), normalized(a.run(missing), missing); got != want {
					t.Errorf("%s: A's key gives %q but a missing key gives %q (existence oracle)", a.name, got, want)
				}
			}
		}

		// Spellings of A's identifiers do not reach A's rows either.
		for _, bad := range []string{
			strings.ToLower(f.keysA[0].wkID), f.keysA[0].wkID + " ", " " + f.keysA[0].wkID,
			f.keysA[0].wkID + "' OR '1'='1", "%", "wk_%",
		} {
			_, err := f.vault.Open(ctx, f.b.ID, crypto.PurposeDEK, bad)
			assertNotFound(t, "Open(B, "+bad+")", err)
			_, err = f.vault.Open(ctx, f.a.ID, crypto.PurposeDEK, bad)
			assertNotFound(t, "Open(A, "+bad+")", err)
			assertNotFound(t, "Destroy(B, "+bad+")", f.vault.Destroy(ctx, f.b.ID, bad))
		}

		// A well-formed but unknown tenant sees nothing.
		unknown := tenant.ID(id.New(id.Tenant))
		_, err := f.vault.Open(ctx, unknown, crypto.PurposeDEK, f.keysA[0].wkID)
		assertNotFound(t, "Open(unknown tenant)", err)
		assertNotFound(t, "Destroy(unknown tenant)", f.vault.Destroy(ctx, unknown, f.keysA[0].wkID))
		// A malformed tenant (never produced by tenant resolution) is refused
		// before any query, as by every scoped operation (executor_test.go).
		for _, tid := range []tenant.ID{"", tenant.ID(strings.ToLower(string(f.a.ID))), f.a.ID + " "} {
			got, err := f.vault.Open(ctx, tid, crypto.PurposeDEK, f.keysA[0].wkID)
			if !errors.Is(err, store.ErrInvalid) || got != nil {
				t.Errorf("Open(tenant %q) = %d bytes, %v; want store.ErrInvalid", tid, len(got), err)
			}
			if err := f.vault.Destroy(ctx, tid, f.keysA[0].wkID); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Destroy(tenant %q) = %v; want store.ErrInvalid", tid, err)
			}
		}

		// Nothing was destroyed: every key of both tenants still opens, and
		// the raw row counts are unchanged.
		f.assertKeysOpen(t, "A", f.keysA)
		f.assertKeysOpen(t, "B", f.keysB)
		if n := rawCount(t, e, "wrapped_keys", "tenant_id", f.a.ID); n != len(f.keysA) {
			t.Errorf("A has %d wrapped keys after the attacks, want %d", n, len(f.keysA))
		}
		if n := rawCount(t, e, "wrapped_keys", "tenant_id", f.b.ID); n != len(f.keysB) {
			t.Errorf("B has %d wrapped keys after the attacks, want %d", n, len(f.keysB))
		}

		// B destroying its own keys never touches A's.
		for _, k := range f.keysB {
			if err := f.vault.Destroy(ctx, f.b.ID, k.wkID); err != nil {
				t.Fatalf("Destroy(B's own %s): %v", k.wkID, err)
			}
		}
		f.assertKeysOpen(t, "A after B erased its keys", f.keysA)
	})
}

// fmtErr returns err's message, or "" for nil.
func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestWrappedKeysCannotBeListedByTenant checks, structurally, that the
// wrapped key repository offers no way to enumerate keys through a tenant
// scope: every method returning a wrapped key takes the tenant, and the
// methods spanning every tenant (the master key operations) only return
// master key identifiers or counts, never rows, tenant IDs nor blobs. A new
// listing method fails this test until it gets an isolation case.
func TestWrappedKeysCannotBeListedByTenant(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeFor[*store.WrappedKeys]()
	tid := reflect.TypeFor[tenant.ID]()
	// A scoped transaction is bound to one tenant (TestScopedTxKeyIsolation).
	scopedTx := reflect.TypeFor[*store.ScopedTx]()
	wk := reflect.TypeFor[store.WrappedKey]()
	systemWide := map[string]bool{"KeyIDsInUse": true, "CountByKey": true}

	returnsKeys := func(m reflect.Method) bool {
		for i := range m.Type.NumOut() {
			out := m.Type.Out(i)
			for out.Kind() == reflect.Slice || out.Kind() == reflect.Pointer || out.Kind() == reflect.Map {
				out = out.Elem()
			}
			if out == wk || (out.Kind() == reflect.Struct && strings.Contains(out.Name(), "Page")) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		seen[m.Name] = true
		takesTenant := false
		for j := 1; j < m.Type.NumIn(); j++ {
			if m.Type.In(j) == tid || m.Type.In(j) == scopedTx {
				takesTenant = true
			}
		}
		switch {
		case takesTenant:
		case systemWide[m.Name]:
			if returnsKeys(m) {
				t.Errorf("WrappedKeys.%s spans every tenant and returns wrapped keys", m.Name)
			}
		default:
			t.Errorf("WrappedKeys.%s takes no tenant.ID and is not a reviewed system-wide method: add an isolation case", m.Name)
		}
		if returnsKeys(m) && !takesTenant {
			t.Errorf("WrappedKeys.%s returns wrapped keys without a tenant scope", m.Name)
		}
	}
	for name := range systemWide {
		if !seen[name] {
			t.Errorf("reviewed system-wide method WrappedKeys.%s no longer exists: update this test", name)
		}
	}
}

// TestScopedTxKeyIsolation attacks A's wrapped keys from a transaction
// bound to B (WrappedKeys.CreateTx and DeleteTx, Vault.SealTx and
// DestroyTx): B cannot destroy A's keys, and a key sealed in B's
// transaction belongs to B.
func TestScopedTxKeyIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := t.Context()
		f := newKeyFixture(t, e, 1)
		scopedB, err := f.db.Scoped(f.b.ID)
		if err != nil {
			t.Fatal(err)
		}
		victim := f.keysA[0]
		var sealedInB string
		err = scopedB.Tx(ctx, func(tx *store.ScopedTx) error {
			if err := f.vault.DestroyTx(ctx, tx, victim.wkID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DestroyTx(A's key) in B's transaction = %v, want store.ErrNotFound", err)
			}
			if err := f.db.WrappedKeys().DeleteTx(ctx, tx, victim.wkID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DeleteTx(A's key) in B's transaction = %v, want store.ErrNotFound", err)
			}
			var err error
			sealedInB, err = f.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte("secret of B"))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		f.assertKeysOpen(t, "A after B's transaction", f.keysA)
		if _, err := f.vault.Open(ctx, f.a.ID, crypto.PurposeSecret, sealedInB); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A opens the key sealed in B's transaction: %v", err)
		}
		if got, err := f.vault.Open(ctx, f.b.ID, crypto.PurposeSecret, sealedInB); err != nil || string(got) != "secret of B" {
			t.Errorf("B's key sealed in its transaction: %v", err)
		}
	})
}

// TestCopiedWrappedBlobDoesNotOpen copies wrapped blobs between rows with
// raw SQL through the system path (an attacker with write access to the
// database, or a restored row in the wrong place): a blob only opens on the
// row, tenant and purpose it was wrapped for.
func TestCopiedWrappedBlobDoesNotOpen(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := t.Context()
		f := newKeyFixture(t, e, 4)
		a0, a1, a2, a3 := f.keysA[0], f.keysA[1], f.keysA[2], f.keysA[3]
		b0 := f.keysB[0]
		copyBlob := `UPDATE wrapped_keys SET blob = (SELECT blob FROM wrapped_keys WHERE id = ?) WHERE id = ?`
		fresh := id.New(id.WrappedKey)

		cases := []struct {
			name   string
			attack func()
			// victim is the row opened after the attack.
			tid     tenant.ID
			purpose crypto.Purpose
			wkID    string
		}{
			{
				name:   "A's blob onto another row of A",
				attack: func() { rawSystemExec(t, e, copyBlob, a0.wkID, a1.wkID) },
				tid:    f.a.ID, purpose: crypto.PurposeDEK, wkID: a1.wkID,
			},
			{
				name:   "A's blob onto a row of B",
				attack: func() { rawSystemExec(t, e, copyBlob, a0.wkID, b0.wkID) },
				tid:    f.b.ID, purpose: crypto.PurposeDEK, wkID: b0.wkID,
			},
			{
				name: "A's row moved to B with its ID",
				attack: func() {
					rawSystemExec(t, e, `UPDATE wrapped_keys SET tenant_id = ? WHERE id = ?`, string(f.b.ID), a2.wkID)
				},
				tid: f.b.ID, purpose: crypto.PurposeDEK, wkID: a2.wkID,
			},
			{
				name: "A's blob inserted as a new row of B",
				attack: func() {
					rawSystemExec(t, e, `INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at)
						SELECT ?, ?, purpose, key_id, blob, created_at FROM wrapped_keys WHERE id = ?`,
						fresh, string(f.b.ID), a0.wkID)
				},
				tid: f.b.ID, purpose: crypto.PurposeDEK, wkID: fresh,
			},
			{
				name: "A's data key relabelled as a secret",
				attack: func() {
					rawSystemExec(t, e, `UPDATE wrapped_keys SET purpose = 'secret' WHERE id = ?`, a3.wkID)
				},
				tid: f.a.ID, purpose: crypto.PurposeSecret, wkID: a3.wkID,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tc.attack()
				got, err := f.vault.Open(ctx, tc.tid, tc.purpose, tc.wkID)
				if !errors.Is(err, crypto.ErrUnwrap) {
					t.Fatalf("Open after the attack = %d bytes, %v; want crypto.ErrUnwrap", len(got), err)
				}
				if got != nil {
					t.Errorf("Open returned %d bytes along with the error", len(got))
				}
				for _, k := range append(slices.Clone(f.keysA), f.keysB...) {
					if strings.Contains(err.Error(), string(k.plaintext)) {
						t.Errorf("error %q reveals a key", err)
					}
				}
			})
		}

		// The moved row is gone from A's scope.
		_, err := f.vault.Open(ctx, f.a.ID, crypto.PurposeDEK, a2.wkID)
		assertNotFound(t, "Open(A, moved row)", err)
		// The source rows were not harmed by the copies.
		f.assertKeysOpen(t, "A's source row", []sealedKey{a0})
		f.assertKeysOpen(t, "untouched keys", append([]sealedKey{f.keysA[4]}, f.keysB[1:]...))
	})
}

// TestStreamBindingAcrossTenants encrypts a file for tenant A and file X
// with a data key from the Vault, and checks that it only decrypts with that
// exact key, tenant and file: the right key with B's or file Y's binding
// fails, as does B's key, and no plaintext byte is ever returned. The same
// holds for resuming an upload from a checkpoint.
func TestStreamBindingAcrossTenants(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := t.Context()
		f := newKeyFixture(t, e, 1)
		dekA, err := f.vault.Open(ctx, f.a.ID, crypto.PurposeDEK, f.keysA[0].wkID)
		if err != nil {
			t.Fatal(err)
		}
		dekB, err := f.vault.Open(ctx, f.b.ID, crypto.PurposeDEK, f.keysB[0].wkID)
		if err != nil {
			t.Fatal(err)
		}
		a, b := string(f.a.ID), string(f.b.ID)
		fileX, fileY := id.New(id.File), id.New(id.File)

		plaintext := bytes.Repeat([]byte("confidential report of entity A, "), 200) // several chunks
		var ct bytes.Buffer
		w, err := crypto.NewWriter(&ct, dekA, a, fileX, crypto.WithChunkSize(crypto.MinChunkSize))
		if err != nil {
			t.Fatal(err)
		}
		half := len(plaintext) / 2
		if _, err := w.Write(plaintext[:half]); err != nil {
			t.Fatal(err)
		}
		st, err := w.Checkpoint(nil)
		if err != nil {
			t.Fatal(err)
		}
		atCheckpoint := bytes.Clone(ct.Bytes())
		if _, err := w.Write(plaintext[half:]); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		// Positive control.
		if got := decrypt(t, ct.Bytes(), dekA, a, fileX); !bytes.Equal(got, plaintext) {
			t.Fatal("the right key and binding do not decrypt the file")
		}

		bindings := []struct {
			name         string
			dek          []byte
			tenant, file string
		}{
			{"A's key, B's tenant, file X", dekA, b, fileX},
			{"A's key, A's tenant, file Y", dekA, a, fileY},
			{"A's key, B's tenant, file Y", dekA, b, fileY},
			{"B's key, B's tenant, file X", dekB, b, fileX},
			{"B's key, A's tenant, file X", dekB, a, fileX},
		}
		for _, bd := range bindings {
			t.Run(bd.name, func(t *testing.T) {
				r, err := crypto.NewReader(bytes.NewReader(ct.Bytes()), bd.dek, bd.tenant, bd.file)
				if err != nil {
					t.Fatalf("NewReader: %v", err)
				}
				got, err := io.ReadAll(r)
				if !errors.Is(err, crypto.ErrAuth) {
					t.Errorf("decrypting under %s: err = %v, want crypto.ErrAuth", bd.name, err)
				}
				if len(got) != 0 {
					t.Errorf("decrypting under %s returned %d plaintext bytes", bd.name, len(got))
				}

				_, _, err = crypto.ResumeWriter(io.Discard, bd.dek, bd.tenant, bd.file, st, int64(len(atCheckpoint)))
				if !errors.Is(err, crypto.ErrAuth) {
					t.Errorf("resuming A/X's checkpoint under %s: err = %v, want crypto.ErrAuth", bd.name, err)
				}
			})
		}

		// The checkpoint still resumes under its own binding, to the same file.
		resumed := bytes.NewBuffer(bytes.Clone(atCheckpoint))
		w2, _, err := crypto.ResumeWriter(resumed, dekA, a, fileX, st, int64(len(atCheckpoint)))
		if err != nil {
			t.Fatalf("ResumeWriter(own binding): %v", err)
		}
		if _, err := w2.Write(plaintext[half:]); err != nil {
			t.Fatal(err)
		}
		if err := w2.Close(); err != nil {
			t.Fatal(err)
		}
		if got := decrypt(t, resumed.Bytes(), dekA, a, fileX); !bytes.Equal(got, plaintext) {
			t.Error("the resumed upload does not decrypt to the original")
		}
	})
}

// decrypt decrypts ct entirely, failing the test on any error.
func decrypt(t *testing.T, ct, dek []byte, tenantID, fileID string) []byte {
	t.Helper()
	r, err := crypto.NewReader(bytes.NewReader(ct), dek, tenantID, fileID)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return got
}

// TestRLSWrappedKeysCrossTenantRawSQL bypasses the store: a raw transaction
// of the runtime role scoped to A runs crafted queries aimed at B's wrapped
// keys. Row-level security alone must hide them, refuse writes and offer no
// existence oracle.
func TestRLSWrappedKeysCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	e, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL not available (set TT_TEST_POSTGRES_DSN and TT_TEST_POSTGRES_MIGRATE_DSN, see test/README.md)")
	}
	ctx := t.Context()
	f := newKeyFixture(t, e, 3)
	raw := rawDB(t, e)
	a, b := string(f.a.ID), string(f.b.ID)
	bKey := f.keysB[0].wkID
	aKey := f.keysA[0].wkID
	sortedA := slices.Sorted(slices.Values(wkIDs(f.keysA)))

	t.Run("select", func(t *testing.T) {
		_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			checks := []struct {
				query string
				args  []any
				want  int
			}{
				{`SELECT count(*) FROM wrapped_keys`, nil, len(f.keysA)},
				{`SELECT count(*) FROM wrapped_keys WHERE tenant_id = $1`, []any{b}, 0},
				{`SELECT count(*) FROM wrapped_keys WHERE id = $1`, []any{bKey}, 0},
				{`SELECT count(*) FROM wrapped_keys WHERE tenant_id <> $1`, []any{a}, 0},
				{`SELECT count(*) FROM wrapped_keys WHERE true OR tenant_id = $1`, []any{b}, len(f.keysA)},
				{`SELECT count(*) FROM wrapped_keys WHERE id LIKE '%' OR id = $1`, []any{bKey}, len(f.keysA)},
				{`SELECT count(*) FROM tenants t RIGHT JOIN wrapped_keys w ON w.tenant_id = t.id WHERE w.tenant_id = $1`, []any{b}, 0},
				{`WITH k AS (SELECT * FROM wrapped_keys) SELECT count(*) FROM k WHERE tenant_id = $1`, []any{b}, 0},
				{`SELECT count(*) FROM (SELECT (SELECT blob FROM wrapped_keys WHERE id = $1) AS blob) s WHERE s.blob IS NOT NULL`, []any{bKey}, 0},
				{`SELECT count(*) FROM (SELECT id FROM wrapped_keys UNION ALL SELECT id FROM wrapped_keys WHERE tenant_id = $1) u`, []any{b}, len(f.keysA)},
				{`SELECT count(*) FROM wrapped_keys WHERE EXISTS (SELECT 1 FROM wrapped_keys x WHERE x.tenant_id = $1)`, []any{b}, 0},
			}
			for _, c := range checks {
				if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
					t.Errorf("%s = %d, want %d", c.query, n, c.want)
				}
			}
			var ids string
			if err := tx.QueryRowContext(ctx, `SELECT string_agg(id, ',' ORDER BY id) FROM wrapped_keys`).Scan(&ids); err != nil {
				t.Fatal(err)
			}
			if ids != strings.Join(sortedA, ",") {
				t.Errorf("A's raw scope lists %q, want only A's keys %q", ids, strings.Join(sortedA, ","))
			}
			return nil
		})
	})

	t.Run("no existence oracle", func(t *testing.T) {
		// A query that fails when a row is invisible fails the same way for
		// B's real key and for a key that never existed.
		probe := func(wkID string) string {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				var n int
				return tx.QueryRowContext(ctx, `SELECT 1 / (SELECT count(*) FROM wrapped_keys WHERE id = $1)::int`, wkID).Scan(&n)
			})
			return pgCode(err)
		}
		if got, want := probe(bKey), probe(id.New(id.WrappedKey)); got != want || got != "22012" {
			t.Errorf("probe on B's key = SQLSTATE %q, on a missing key = %q; want both 22012 (division by zero)", got, want)
		}
		if got := probe(aKey); got != "" {
			t.Errorf("probe on A's own key = SQLSTATE %q, want success", got)
		}
	})

	t.Run("update and delete affect zero rows", func(t *testing.T) {
		_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			stmts := []struct {
				stmt string
				args []any
			}{
				{`UPDATE wrapped_keys SET blob = '\x00'::bytea WHERE id = $1`, []any{bKey}},
				{`UPDATE wrapped_keys SET key_id = 'mk_0000000000000000' WHERE tenant_id = $1`, []any{b}},
				{`DELETE FROM wrapped_keys WHERE id = $1`, []any{bKey}},
				{`DELETE FROM wrapped_keys WHERE tenant_id = $1`, []any{b}},
			}
			for _, s := range stmts {
				if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
					t.Errorf("%s affected %d rows of B", s.stmt, n)
				}
			}
			return nil
		})
	})

	// Each violating statement runs in its own transaction: the error
	// aborts the transaction.
	violations := []struct {
		name string
		stmt string
		args []any
		code string
	}{
		{
			"insert a wrapped key for B",
			`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES ($1, $2, 'dek', 'mk_0000000000000000', '\x01'::bytea, 0)`,
			[]any{id.New(id.WrappedKey), b},
			pgInsufficientPrivilege,
		},
		{
			"move A's keys to B",
			`UPDATE wrapped_keys SET tenant_id = $1`,
			[]any{b},
			pgInsufficientPrivilege,
		},
		{
			// The subquery sees no row of B: the copy degrades to NULL and
			// the NOT NULL constraint refuses it; B's blob never reaches A.
			"copy B's blob onto A's row",
			`UPDATE wrapped_keys SET blob = (SELECT blob FROM wrapped_keys WHERE id = $1) WHERE id = $2`,
			[]any{bKey, aKey},
			"23502",
		},
	}
	for _, v := range violations {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			if got := pgCode(err); got != v.code {
				t.Errorf("%s: err = %v, want SQLSTATE %s", v.name, err, v.code)
			}
		})
	}

	f.assertKeysOpen(t, "A", f.keysA)
	f.assertKeysOpen(t, "B", f.keysB)
}

// pgCode returns the SQLSTATE of a PostgreSQL error, or "" when err is nil
// or not a PostgreSQL error.
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
