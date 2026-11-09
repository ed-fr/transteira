package secret

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// TestWithStore runs a secret from creation to reveal and deletion on the
// real store, on every engine: the proofs are checked by the store, a
// wrong passphrase is counted, the reveal is single, and another tenant
// never sees the secret.
func TestWithStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Millisecond)
		db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		kr, err := masterkey.New(masterkeytest.Key(t, "secret"), nil)
		if err != nil {
			t.Fatal(err)
		}
		vault := masterkey.NewVault(db, kr, nil)
		newTenant := func(fqdn string) *tenant.Tenant {
			tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
				SetupState: tenant.SetupStateActive, Name: fqdn, FQDN: fqdn, DefaultLanguage: "en",
				MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
			})
			if err != nil {
				t.Fatal(err)
			}
			return tn
		}
		a, b := newTenant("transfer.entity-a.example.com"), newTenant("transfer.entity-b.example.com")
		seclog, rec := &fakeSeclog{}, &fakeAudit{}
		svc, err := New(Deps{
			Secrets: db.Secrets(vault), Creators: &fakeCreators{}, Scrubber: vault, Files: &fakeFiles{}, SecurityLog: seclog,
		}, Options{Audit: rec, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}

		s, d := seal(t, "the plans", "correct horse")
		req := s.request()
		req.Passphrase = &Passphrase{KDF: d.KDF, Iterations: d.Iterations, Salt: d.EncodedSalt()}
		created, err := svc.Create(ctx, a, internalSender(), req)
		if err != nil {
			t.Fatal(err)
		}
		if created.State != store.SecretActive || !created.ExpiresAt.Equal(now.Add(24*time.Hour)) {
			t.Fatalf("created = %+v", created)
		}
		st, err := svc.Status(ctx, a, internalIP, created.Token)
		if err != nil || st.Passphrase == nil || st.Passphrase.Salt != d.EncodedSalt() || st.FileSize != 0 {
			t.Fatalf("status = %+v, %v", st, err)
		}
		// Under B, the token of A is unknown.
		if _, err := svc.Status(ctx, b, internalIP, created.Token); !errors.Is(err, ErrNotFound) {
			t.Errorf("status under B: %v", err)
		}
		if _, err := svc.Reveal(ctx, b, internalIP, created.Token, s.keyProof, s.proof); !errors.Is(err, ErrNotFound) {
			t.Errorf("reveal under B: %v", err)
		}
		// A wrong key proof is not counted, a wrong passphrase is.
		var proof *ProofError
		if _, err := svc.Reveal(ctx, a, internalIP, created.Token, s.proof, s.proof); !errors.As(err, &proof) || proof.Counted {
			t.Fatalf("wrong key proof: %v", err)
		}
		if _, err := svc.Reveal(ctx, a, internalIP, created.Token, s.keyProof, s.keyProof); !errors.As(err, &proof) || !proof.Counted || proof.Remaining != 4 {
			t.Fatalf("wrong passphrase: %v", err)
		}
		out, err := svc.Reveal(ctx, a, internalIP, created.Token, s.keyProof, s.proof)
		if err != nil || out.EncryptedText != s.text {
			t.Fatalf("reveal = %+v, %v", out, err)
		}
		var gone *GoneError
		if _, err := svc.Reveal(ctx, a, internalIP, created.Token, s.keyProof, s.proof); !errors.As(err, &gone) || gone.Reason != ReasonRead {
			t.Errorf("second reveal: %v", err)
		}
		if _, err := svc.Status(ctx, a, internalIP, created.Token); !errors.As(err, &gone) || gone.Reason != ReasonRead {
			t.Errorf("status after the reveal: %v", err)
		}
		want := []string{"secret_invalid", "secret_invalid", "secret_proof_invalid reason=key", "secret_proof_invalid reason=passphrase"}
		if got := seclog.types(); !slices.Equal(got, want) {
			t.Errorf("security log = %v, want %v", got, want)
		}

		// My secrets: listed for the address in A only, deleted once.
		other, _ := seal(t, "second", "")
		second, err := svc.Create(ctx, a, internalSender(), other.request())
		if err != nil {
			t.Fatal(err)
		}
		page, err := svc.ListMine(ctx, a, alice, "", 0)
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("list = %+v, %v", page, err)
		}
		if page, err := svc.ListMine(ctx, b, alice, "", 0); err != nil || len(page.Items) != 0 {
			t.Errorf("list under B = %+v, %v", page, err)
		}
		if err := svc.DeleteMine(ctx, b, alice, internalIP, second.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("delete under B: %v", err)
		}
		if err := svc.DeleteMine(ctx, a, bob, internalIP, second.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("delete by another address: %v", err)
		}
		if err := svc.DeleteMine(ctx, a, alice, internalIP, second.ID); err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteMine(ctx, a, alice, internalIP, second.ID); err != nil {
			t.Errorf("second delete: %v", err)
		}
		if _, err := svc.Status(ctx, a, internalIP, second.Token); !errors.As(err, &gone) || gone.Reason != ReasonDeleted {
			t.Errorf("status after the deletion: %v", err)
		}
		wantAudit := []audit.Action{
			audit.ActionSecretCreated, audit.ActionSecretRevealed, audit.ActionSecretCreated, audit.ActionSecretDeleted,
		}
		if got := rec.actions(); !slices.Equal(got, wantAudit) {
			t.Errorf("audit = %v, want %v", got, wantAudit)
		}
		// The verifiers given at creation are the SHA-256 of the proofs.
		if !tte2.VerifierMatches(mustHex(t, s.verifier), mustHex(t, s.proof)) {
			t.Error("verifier mismatch in the fixture")
		}
	})
}

// mustHex decodes a proof.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := tte2.ParseProof(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
