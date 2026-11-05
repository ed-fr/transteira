package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// proofSecret returns a sealed proof signing private key under mk1.
func proofSecret() store.SystemSecret {
	return store.SystemSecret{ID: id.New(id.SystemSecret), Purpose: store.SecretPurposeProofSigning, KeyID: mk1, Blob: []byte("sealed ed25519")}
}

// newProofKey returns an active key with a distinct public key.
func newProofKey(b byte) store.ProofKey {
	return store.ProofKey{ID: id.New(id.ProofKey), PublicKey: bytes.Repeat([]byte{b}, store.ProofPublicKeySize)}
}

// createProofKey stores k with a new secret and returns k as stored.
func createProofKey(t *testing.T, db *store.DB, k store.ProofKey) store.ProofKey {
	t.Helper()
	s := proofSecret()
	if err := systemTx(context.Background(), t, db, func(tx *store.SystemTx) error { return db.ProofKeys().CreateTx(context.Background(), tx, k, s) }); err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	got, err := db.ProofKeys().Get(context.Background(), k.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return got
}

func TestProofKeys(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		keys := db.ProofKeys()

		if _, err := keys.Active(ctx); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Active(none) = %v", err)
		}
		if err := systemTx(context.Background(), t, db, func(tx *store.SystemTx) error { _, err := keys.RetireActiveTx(ctx, tx, fixedNow); return err }); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RetireActiveTx(none) = %v", err)
		}
		if l, err := keys.List(ctx); err != nil || len(l) != 0 {
			t.Errorf("List(empty) = %v, %v", l, err)
		}

		k1 := createProofKey(t, db, newProofKey(1))
		if !k1.Active() || k1.PrivateKeySecretID == "" || !k1.CreatedAt.Equal(msNow) || len(k1.PublicKey) != 32 {
			t.Errorf("created key = %+v", k1)
		}
		if s, err := db.SystemSecrets().Get(ctx, k1.PrivateKeySecretID); err != nil || s.Purpose != store.SecretPurposeProofSigning {
			t.Errorf("private key secret = %+v, %v", s, err)
		}
		if got, err := keys.Active(ctx); err != nil || got.ID != k1.ID {
			t.Errorf("Active = %+v, %v", got, err)
		}
		err := systemTx(context.Background(), t, db, func(tx *store.SystemTx) error {
			got, err := keys.ActiveTx(ctx, tx)
			if err == nil && got.ID != k1.ID {
				t.Errorf("ActiveTx = %+v", got)
			}
			return err
		})
		if err != nil {
			t.Errorf("ActiveTx = %v", err)
		}

		// At most one active key: nothing of the second one is stored.
		k2 := newProofKey(2)
		s2 := proofSecret()
		err = systemTx(context.Background(), t, db, func(tx *store.SystemTx) error { return keys.CreateTx(ctx, tx, k2, s2) })
		wantErr(t, "CreateTx(second active)", err, store.ErrConflict)
		if _, err := db.SystemSecrets().Get(ctx, s2.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("secret of the refused key = %v", err)
		}
		if _, err := keys.Get(ctx, k2.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(refused key) = %v", err)
		}

		// Validation.
		bad := map[string]func(*store.ProofKey, *store.SystemSecret){
			"id":         func(k *store.ProofKey, _ *store.SystemSecret) { k.ID = id.New(id.TransferProof) },
			"public key": func(k *store.ProofKey, _ *store.SystemSecret) { k.PublicKey = k.PublicKey[:31] },
			"secret ref": func(k *store.ProofKey, _ *store.SystemSecret) { k.PrivateKeySecretID = id.New(id.SystemSecret) },
			"retired":    func(k *store.ProofKey, _ *store.SystemSecret) { k.RetiredAt = fixedNow },
			"purpose":    func(_ *store.ProofKey, s *store.SystemSecret) { s.Purpose = store.SecretPurposeWebhook },
			"secret":     func(_ *store.ProofKey, s *store.SystemSecret) { s.Blob = nil },
		}
		for name, mutate := range bad {
			k, s := newProofKey(9), proofSecret()
			mutate(&k, &s)
			err := systemTx(context.Background(), t, db, func(tx *store.SystemTx) error { return keys.CreateTx(ctx, tx, k, s) })
			wantErr(t, "CreateTx("+name+")", err, store.ErrInvalid)
		}

		// Retirement erases the private key; the public key stays.
		later := msNow.Add(time.Hour)
		var retired store.ProofKey
		err = systemTx(context.Background(), t, db, func(tx *store.SystemTx) error {
			var err error
			retired, err = keys.RetireActiveTx(ctx, tx, later)
			return err
		})
		if err != nil || retired.ID != k1.ID || retired.PrivateKeySecretID != "" || !retired.RetiredAt.Equal(later) {
			t.Fatalf("RetireActiveTx = %+v, %v", retired, err)
		}
		if _, err := db.SystemSecrets().Get(ctx, k1.PrivateKeySecretID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("private key after retirement = %v", err)
		}
		got, err := keys.Get(ctx, k1.ID)
		if err != nil || got.Active() || got.PrivateKeySecretID != "" || !bytes.Equal(got.PublicKey, k1.PublicKey) || !got.RetiredAt.Equal(later) {
			t.Errorf("retired key = %+v, %v", got, err)
		}
		if _, err := keys.Active(ctx); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Active after retirement = %v", err)
		}
		// A retired key cannot be retired again.
		err = systemTx(context.Background(), t, db, func(tx *store.SystemTx) error { _, err := keys.RetireActiveTx(ctx, tx, later); return err })
		wantErr(t, "RetireActiveTx(retired)", err, store.ErrNotFound)

		// A new key; retiring it before its creation time clamps to it.
		k3 := newProofKey(3)
		k3.CreatedAt = later
		k3 = createProofKey(t, db, k3)
		err = systemTx(context.Background(), t, db, func(tx *store.SystemTx) error {
			var err error
			retired, err = keys.RetireActiveTx(ctx, tx, fixedNow)
			return err
		})
		if err != nil || !retired.RetiredAt.Equal(k3.CreatedAt) {
			t.Errorf("RetireActiveTx(early) = %+v, %v", retired, err)
		}
		k4 := createProofKey(t, db, store.ProofKey{ID: id.New(id.ProofKey), PublicKey: bytes.Repeat([]byte{4}, 32), CreatedAt: later.Add(time.Hour)})

		// Same public key twice.
		dup := newProofKey(4)
		err = systemTx(context.Background(), t, db, func(tx *store.SystemTx) error {
			if _, err := keys.RetireActiveTx(ctx, tx, later.Add(2*time.Hour)); err != nil {
				return err
			}
			return keys.CreateTx(ctx, tx, dup, proofSecret())
		})
		wantErr(t, "CreateTx(duplicate public key)", err, store.ErrConflict)

		list, err := keys.List(ctx)
		if err != nil || len(list) != 3 || list[0].ID != k4.ID || list[1].ID != k3.ID || list[2].ID != k1.ID {
			t.Errorf("List = %+v, %v", list, err)
		}
		if _, err := keys.Get(ctx, "psk_unknown"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(unknown) = %v", err)
		}
	})
}

// statement returns a JSON statement naming sender, recipients and
// downloaders, with extra fields.
func statement(t *testing.T, sender string, recipients, downloaders []string, files ...string) []byte {
	t.Helper()
	type dl struct {
		Email string `json:"email"`
		At    string `json:"firstDownloadedAt"`
	}
	type file struct {
		Name string `json:"name"`
	}
	v := map[string]any{"schemaVersion": 1, "senderEmail": sender, "recipients": recipients}
	if downloaders != nil {
		var d []dl
		for _, a := range downloaders {
			d = append(d, dl{Email: a, At: "2026-11-05T10:00:00Z"})
		}
		v["recipientDownloads"] = d
	}
	var fs []file
	for _, f := range files {
		fs = append(fs, file{Name: f})
	}
	v["files"] = fs
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// proofFixture holds a database with a proof key and two tenants.
type proofFixture struct {
	db   *store.DB
	key  store.ProofKey
	a, b tenant.ID
}

func newProofFixture(t *testing.T, e storetest.Engine) *proofFixture {
	t.Helper()
	db := openDB(t, e)
	return &proofFixture{
		db: db, key: createProofKey(t, db, newProofKey(1)),
		a: newTenant(t, db, "transfer.entity-a.example.com").ID, b: newTenant(t, db, "transfer.entity-b.example.com").ID,
	}
}

// proof returns a valid proof of trfID signed by the fixture key.
func (f *proofFixture) proof(trfID string, kind store.ProofKind, rcl string, st []byte) store.TransferProof {
	return store.TransferProof{
		TransferID: trfID, Kind: kind, RecipientLinkID: rcl, Statement: st,
		Signature: bytes.Repeat([]byte{7}, store.ProofSignatureSize), KeyID: f.key.ID,
		ExpiresAt: fixedNow.AddDate(1, 0, 0),
	}
}

// insert stores p in tenant tid.
func (f *proofFixture) insert(t *testing.T, tid tenant.ID, p store.TransferProof) error {
	t.Helper()
	s, err := f.db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	return s.Tx(context.Background(), func(tx *store.ScopedTx) error { return f.db.TransferProofs().InsertTx(context.Background(), tx, p) })
}

// mustInsert stores p in tenant tid or fails.
func (f *proofFixture) mustInsert(t *testing.T, tid tenant.ID, p store.TransferProof) {
	t.Helper()
	if err := f.insert(t, tid, p); err != nil {
		t.Fatalf("InsertTx: %v", err)
	}
}

// eraseAddress runs DeleteByAddressTx in tenant tid.
func (f *proofFixture) eraseAddress(t *testing.T, tid tenant.ID, email string) (int, error) {
	t.Helper()
	s, err := f.db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		var err error
		n, err = f.db.TransferProofs().DeleteByAddressTx(context.Background(), tx, email)
		return err
	})
	return n, err
}

func TestTransferProofs(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newProofFixture(t, e)
		proofs := f.db.TransferProofs()
		trf, rcl1, rcl2 := id.New(id.Transfer), id.New(id.RecipientLink), id.New(id.RecipientLink)
		st := statement(t, "s@entity-a.example.com", []string{"r@example.org"}, nil)

		dep := f.proof(trf, store.ProofDeposit, "", st)
		dep.ID = id.New(id.TransferProof)
		f.mustInsert(t, f.a, dep)
		got, err := proofs.Get(ctx, f.a, trf, store.ProofDeposit, "")
		if err != nil || got.ID != dep.ID || got.TransferID != trf || got.Kind != store.ProofDeposit || got.RecipientLinkID != "" ||
			!bytes.Equal(got.Statement, st) || !bytes.Equal(got.Signature, dep.Signature) || got.KeyID != f.key.ID ||
			!got.CreatedAt.Equal(msNow) || !got.ExpiresAt.Equal(dep.ExpiresAt.Truncate(time.Millisecond)) {
			t.Errorf("Get(deposit) = %+v, %v", got, err)
		}
		// One row per fact.
		wantErr(t, "InsertTx(second deposit)", f.insert(t, f.a, f.proof(trf, store.ProofDeposit, "", st)), store.ErrConflict)
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, "", st))
		wantErr(t, "InsertTx(second delivery)", f.insert(t, f.a, f.proof(trf, store.ProofDelivery, "", st)), store.ErrConflict)
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, rcl1, st))
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, rcl2, st))
		wantErr(t, "InsertTx(second recipient delivery)", f.insert(t, f.a, f.proof(trf, store.ProofDelivery, rcl1, st)), store.ErrConflict)
		dupID := f.proof(id.New(id.Transfer), store.ProofDeposit, "", st)
		dupID.ID = dep.ID
		wantErr(t, "InsertTx(duplicate id)", f.insert(t, f.a, dupID), store.ErrConflict)
		unknownKey := f.proof(id.New(id.Transfer), store.ProofDeposit, "", st)
		unknownKey.KeyID = id.New(id.ProofKey)
		wantErr(t, "InsertTx(unknown key)", f.insert(t, f.a, unknownKey), store.ErrNotFound)

		for _, rcl := range []string{"", rcl1, rcl2} {
			got, err := proofs.Get(ctx, f.a, trf, store.ProofDelivery, rcl)
			if err != nil || got.RecipientLinkID != rcl || got.Kind != store.ProofDelivery {
				t.Errorf("Get(delivery %q) = %+v, %v", rcl, got, err)
			}
		}
		if _, err := proofs.Get(ctx, f.a, trf, store.ProofDeposit, rcl1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deposit of a recipient) = %v", err)
		}
		if _, err := proofs.Get(ctx, f.a, id.New(id.Transfer), store.ProofDeposit, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(unknown transfer) = %v", err)
		}
		if _, err := proofs.Get(ctx, "bogus", trf, store.ProofDeposit, ""); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Get(bad tenant) = %v", err)
		}
		s, _ := f.db.Scoped(f.a)
		err = s.ReadTx(ctx, func(tx *store.ScopedTx) error {
			got, err := proofs.GetTx(ctx, tx, trf, store.ProofDelivery, rcl2)
			if err == nil && got.RecipientLinkID != rcl2 {
				t.Errorf("GetTx = %+v", got)
			}
			if _, err := proofs.GetTx(ctx, tx, trf, store.ProofDelivery, id.New(id.RecipientLink)); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetTx(unknown) = %v", err)
			}
			return err
		})
		if err != nil {
			t.Errorf("GetTx = %v", err)
		}

		// Validation.
		bad := map[string]func(*store.TransferProof){
			"id":                func(p *store.TransferProof) { p.ID = id.New(id.Transfer) },
			"transfer":          func(p *store.TransferProof) { p.TransferID = "trf_x" },
			"kind":              func(p *store.TransferProof) { p.Kind = "receipt" },
			"deposit recipient": func(p *store.TransferProof) { p.Kind, p.RecipientLinkID = store.ProofDeposit, rcl1 },
			"recipient":         func(p *store.TransferProof) { p.RecipientLinkID = id.New(id.Transfer) },
			"short statement":   func(p *store.TransferProof) { p.Statement = []byte("1") },
			"big statement": func(p *store.TransferProof) {
				p.Statement = []byte(`"` + string(bytes.Repeat([]byte("a"), store.MaxProofStatementBytes)) + `"`)
			},
			"not json":  func(p *store.TransferProof) { p.Statement = []byte("{x}") },
			"signature": func(p *store.TransferProof) { p.Signature = p.Signature[:63] },
			"key":       func(p *store.TransferProof) { p.KeyID = id.New(id.SystemSecret) },
			"expiry":    func(p *store.TransferProof) { p.CreatedAt, p.ExpiresAt = fixedNow, fixedNow },
		}
		for name, mutate := range bad {
			p := f.proof(id.New(id.Transfer), store.ProofDelivery, "", st)
			mutate(&p)
			wantErr(t, "InsertTx("+name+")", f.insert(t, f.a, p), store.ErrInvalid)
		}
		// Statements of exactly the bounds are accepted.
		f.mustInsert(t, f.a, f.proof(id.New(id.Transfer), store.ProofDeposit, "", []byte("{}")))
		max := []byte(`"` + string(bytes.Repeat([]byte("a"), store.MaxProofStatementBytes-2)) + `"`)
		f.mustInsert(t, f.a, f.proof(id.New(id.Transfer), store.ProofDeposit, "", max))
	})
}

func TestTransferProofsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newProofFixture(t, e)
		proofs := f.db.TransferProofs()
		trf, rcl := id.New(id.Transfer), id.New(id.RecipientLink)
		const addr = "victim@example.org"
		st := statement(t, "s@entity-a.example.com", []string{addr}, []string{addr})
		old := f.proof(trf, store.ProofDeposit, "", st)
		old.CreatedAt, old.ExpiresAt = fixedNow.AddDate(-1, 0, -1), fixedNow.Add(-time.Hour)
		f.mustInsert(t, f.a, old)
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, "", st))
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, rcl, st))

		// Tenant B sees, purges and erases nothing of tenant A.
		for _, c := range []struct {
			kind store.ProofKind
			rcl  string
		}{{store.ProofDeposit, ""}, {store.ProofDelivery, ""}, {store.ProofDelivery, rcl}} {
			if _, err := proofs.Get(ctx, f.b, trf, c.kind, c.rcl); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("tenant B Get(%s %q) = %v", c.kind, c.rcl, err)
			}
		}
		if n, err := proofs.Purge(ctx, f.b, fixedNow.AddDate(2, 0, 0)); err != nil || n != 0 {
			t.Errorf("tenant B Purge = %d, %v", n, err)
		}
		if n, err := proofs.CountByAddress(ctx, f.b, addr); err != nil || n != 0 {
			t.Errorf("tenant B CountByAddress = %d, %v", n, err)
		}
		if n, err := f.eraseAddress(t, f.b, addr); err != nil || n != 0 {
			t.Errorf("tenant B DeleteByAddressTx = %d, %v", n, err)
		}
		// Tenant B may record the same facts for its own transfer ID.
		f.mustInsert(t, f.b, f.proof(trf, store.ProofDeposit, "", st))
		for _, c := range []struct {
			kind store.ProofKind
			rcl  string
		}{{store.ProofDeposit, ""}, {store.ProofDelivery, ""}, {store.ProofDelivery, rcl}} {
			if _, err := proofs.Get(ctx, f.a, trf, c.kind, c.rcl); err != nil {
				t.Errorf("tenant A Get(%s %q) after tenant B = %v", c.kind, c.rcl, err)
			}
		}
		// Tenant A's purge leaves tenant B's rows.
		if n, err := proofs.Purge(ctx, f.a, fixedNow.AddDate(2, 0, 0)); err != nil || n != 3 {
			t.Errorf("tenant A Purge = %d, %v", n, err)
		}
		if _, err := proofs.Get(ctx, f.b, trf, store.ProofDeposit, ""); err != nil {
			t.Errorf("tenant B proof after tenant A's purge = %v", err)
		}
		if n, err := f.eraseAddress(t, f.a, addr); err != nil || n != 0 {
			t.Errorf("tenant A DeleteByAddressTx after purge = %d, %v", n, err)
		}
		if _, err := proofs.Get(ctx, f.b, trf, store.ProofDeposit, ""); err != nil {
			t.Errorf("tenant B proof after tenant A's erasure = %v", err)
		}
		if _, err := proofs.Purge(ctx, "bogus", fixedNow); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Purge(bad tenant) = %v", err)
		}
	})
}

func TestTransferProofsPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newProofFixture(t, e)
		proofs := f.db.TransferProofs()
		st := []byte("{}")
		var keep []string
		for i := range 5 {
			trf := id.New(id.Transfer)
			p := f.proof(trf, store.ProofDeposit, "", st)
			p.CreatedAt, p.ExpiresAt = fixedNow.Add(-48*time.Hour), fixedNow.Add(time.Duration(i-2)*time.Hour)
			f.mustInsert(t, f.a, p)
			if i > 2 {
				keep = append(keep, trf)
			}
		}
		// expires_at <= now is purged: i = 0, 1, 2.
		if n, err := proofs.Purge(ctx, f.a, fixedNow); err != nil || n != 3 {
			t.Errorf("Purge = %d, %v", n, err)
		}
		for _, trf := range keep {
			if _, err := proofs.Get(ctx, f.a, trf, store.ProofDeposit, ""); err != nil {
				t.Errorf("kept proof %s: %v", trf, err)
			}
		}
		if n, err := proofs.Purge(ctx, f.a, fixedNow); err != nil || n != 0 {
			t.Errorf("Purge(again) = %d, %v", n, err)
		}
	})
}

func TestTransferProofsDeleteByAddress(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newProofFixture(t, e)
		proofs := f.db.TransferProofs()
		const addr = "jo@example.org"
		cases := []struct {
			name   string
			st     []byte
			delete bool
		}{
			{"sender", statement(t, addr, []string{"x@example.net"}, nil), true},
			{"sender upper case", statement(t, "Jo@Example.ORG", []string{"x@example.net"}, nil), true},
			{"recipient", statement(t, "s@example.com", []string{"x@example.net", addr}, nil), true},
			{"downloader", statement(t, "s@example.com", []string{"x@example.net"}, []string{addr}), true},
			{"longer address", statement(t, "s@example.com", []string{"bjo@example.org", "jo@example.org.evil.example"}, nil), false},
			{"file name", statement(t, "s@example.com", []string{"x@example.net"}, nil, addr+".pdf", "mail "+addr), false},
			{"other field", []byte(`{"senderEmail":1,"recipients":"jo@example.org","note":"jo@example.org"}`), false},
			{"other address", statement(t, "s@example.com", []string{"x@example.net"}, nil), false},
		}
		ids := make([]string, len(cases))
		for i, c := range cases {
			ids[i] = id.New(id.Transfer)
			f.mustInsert(t, f.a, f.proof(ids[i], store.ProofDeposit, "", c.st))
		}
		// The same address in tenant B is not touched.
		other := id.New(id.Transfer)
		f.mustInsert(t, f.b, f.proof(other, store.ProofDeposit, "", statement(t, addr, nil, nil)))

		// The count matches what the erasure then deletes, in tenant A only.
		if n, err := proofs.CountByAddress(ctx, f.a, " JO@example.org "); err != nil || n != 4 {
			t.Errorf("CountByAddress = %d, %v, want 4", n, err)
		}
		if n, err := proofs.CountByAddress(ctx, f.b, addr); err != nil || n != 1 {
			t.Errorf("CountByAddress(tenant B) = %d, %v, want 1", n, err)
		}
		if _, err := proofs.CountByAddress(ctx, f.a, "not an address"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("CountByAddress(malformed) = %v", err)
		}
		if _, err := proofs.CountByAddress(ctx, "bogus", addr); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("CountByAddress(bad tenant) = %v", err)
		}

		// The address is normalized; the prefilter lower-cases the
		// statements and the confirmation normalizes their addresses.
		n, err := f.eraseAddress(t, f.a, " JO@example.org ")
		if err != nil || n != 4 {
			t.Errorf("DeleteByAddressTx = %d, %v, want 4", n, err)
		}
		for i, c := range cases {
			_, err := proofs.Get(ctx, f.a, ids[i], store.ProofDeposit, "")
			if gone := errors.Is(err, store.ErrNotFound); gone != c.delete {
				t.Errorf("%s: deleted = %v (%v), want %v", c.name, gone, err, c.delete)
			}
		}
		if _, err := proofs.Get(ctx, f.b, other, store.ProofDeposit, ""); err != nil {
			t.Errorf("tenant B proof = %v", err)
		}
		if _, err := f.eraseAddress(t, f.a, "not an address"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("DeleteByAddressTx(malformed) = %v", err)
		}

		// An address with characters a JSON encoder may escape is found
		// through its domain, then confirmed.
		odd := "a&b/c@example.org"
		escaped := []byte(`{"senderEmail":"a&b\/c@example.org","recipients":[]}`)
		near := []byte(`{"senderEmail":"ab/c@example.org","recipients":[]}`)
		oddID, nearID := id.New(id.Transfer), id.New(id.Transfer)
		f.mustInsert(t, f.a, f.proof(oddID, store.ProofDeposit, "", escaped))
		f.mustInsert(t, f.a, f.proof(nearID, store.ProofDeposit, "", near))
		if n, err := f.eraseAddress(t, f.a, odd); err != nil || n != 1 {
			t.Errorf("DeleteByAddressTx(escaped) = %d, %v", n, err)
		}
		if _, err := proofs.Get(ctx, f.a, nearID, store.ProofDeposit, ""); err != nil {
			t.Errorf("near proof = %v", err)
		}

		// More candidates than one batch.
		for range 120 {
			f.mustInsert(t, f.a, f.proof(id.New(id.Transfer), store.ProofDeposit, "", statement(t, "s@example.com", []string{"many@example.org"}, nil)))
			f.mustInsert(t, f.a, f.proof(id.New(id.Transfer), store.ProofDeposit, "", statement(t, "s@example.com", []string{"xmany@example.org"}, nil)))
		}
		if n, err := proofs.CountByAddress(ctx, f.a, "many@example.org"); err != nil || n != 120 {
			t.Errorf("CountByAddress(many) = %d, %v", n, err)
		}
		if n, err := f.eraseAddress(t, f.a, "many@example.org"); err != nil || n != 120 {
			t.Errorf("DeleteByAddressTx(many) = %d, %v", n, err)
		}
		if n, err := f.eraseAddress(t, f.a, "xmany@example.org"); err != nil || n != 120 {
			t.Errorf("DeleteByAddressTx(xmany) = %d, %v", n, err)
		}
	})
}

func TestTransferProofsGetRecipientDelivery(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newProofFixture(t, e)
		proofs := f.db.TransferProofs()
		trf, other := id.New(id.Transfer), id.New(id.Transfer)
		sender := "s@entity-a.example.com"
		addr := func(i int) string { return fmt.Sprintf("r%02d@example.org", i) }
		// The overall row names downloaders too: it is never the answer.
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, "",
			statement(t, sender, []string{"all@example.org"}, []string{"all@example.org", addr(0)})))
		// More rows than two batches, so that the lookup pages.
		var want string
		for i := range 23 {
			p := f.proof(trf, store.ProofDelivery, id.New(id.RecipientLink), statement(t, sender, []string{addr(i)}, []string{addr(i)}))
			p.ID = id.New(id.TransferProof)
			f.mustInsert(t, f.a, p)
			if i == 21 {
				want = p.ID
			}
		}
		// Statements without exactly one download are skipped.
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, id.New(id.RecipientLink),
			statement(t, sender, nil, []string{"two@example.org", "three@example.org"})))
		f.mustInsert(t, f.a, f.proof(trf, store.ProofDelivery, id.New(id.RecipientLink),
			statement(t, "none@example.org", nil, nil)))
		// Same address on another transfer, and in another tenant.
		f.mustInsert(t, f.a, f.proof(other, store.ProofDelivery, id.New(id.RecipientLink),
			statement(t, sender, nil, []string{"elsewhere@example.org"})))
		f.mustInsert(t, f.b, f.proof(trf, store.ProofDelivery, id.New(id.RecipientLink),
			statement(t, sender, nil, []string{"tenant-b@example.org"})))

		got, err := proofs.GetRecipientDelivery(ctx, f.a, trf, " R21@Example.ORG ")
		if err != nil || got.ID != want || got.RecipientLinkID == "" || got.Kind != store.ProofDelivery {
			t.Errorf("GetRecipientDelivery = %+v, %v", got, err)
		}
		for _, a := range []string{
			"all@example.org", "two@example.org", "none@example.org", "elsewhere@example.org",
			"tenant-b@example.org", "nobody@example.org",
		} {
			_, err := proofs.GetRecipientDelivery(ctx, f.a, trf, a)
			wantErr(t, "GetRecipientDelivery("+a+")", err, store.ErrNotFound)
		}
		if got, err := proofs.GetRecipientDelivery(ctx, f.b, trf, "tenant-b@example.org"); err != nil || got.TransferID != trf {
			t.Errorf("GetRecipientDelivery(tenant b) = %+v, %v", got, err)
		}
		_, err = proofs.GetRecipientDelivery(ctx, f.a, trf, "not an address")
		wantErr(t, "GetRecipientDelivery(bad address)", err, store.ErrInvalid)
		_, err = proofs.GetRecipientDelivery(ctx, "bogus", trf, addr(1))
		wantErr(t, "GetRecipientDelivery(bad tenant)", err, store.ErrInvalid)
	})
}
