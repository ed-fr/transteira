package secret

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/storage"
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
			Directory: StoreDirectory{DB: db}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
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

// TestFileWithStore runs a secret with a file on the real store and file
// storage, on every engine: the upload activates it, the reveal returns
// the one-time grant, the first complete download deletes the file and
// destroys its key, and another tenant never reaches it.
func TestFileWithStore(t *testing.T) {
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
		files, err := storage.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = files.Close() })
		rec := &fakeAudit{}
		svc, err := New(Deps{
			Secrets: db.Secrets(vault), Creators: &fakeCreators{}, Scrubber: vault, Files: files, SecurityLog: &fakeSeclog{},
			Directory: StoreDirectory{DB: db}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
		}, Options{Audit: rec, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}

		key, err := tte2.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, _ := tte2.NewWriter(&buf, key, 0)
		_, _ = w.Write(bytes.Repeat([]byte("f"), 70_000))
		_ = w.Close()
		stream := buf.Bytes()

		s, _ := seal(t, "", "")
		req := s.request()
		req.File = &File{Size: int64(len(stream)), EncryptedMetadata: "AQ" + strings.Repeat("A", 38)}
		created, err := svc.Create(ctx, a, internalSender(), req)
		if err != nil || created.State != store.SecretPending {
			t.Fatalf("create = %+v, %v", created, err)
		}
		if _, err := svc.UploadFile(ctx, b, internalSender(), created.ID, bytes.NewReader(stream)); !errors.Is(err, ErrNotFound) {
			t.Errorf("upload under B: %v", err)
		}
		var format *FormatError
		if _, err := svc.UploadFile(ctx, a, internalSender(), created.ID, bytes.NewReader(stream[:100])); !errors.As(err, &format) {
			t.Errorf("short body: %v", err)
		}
		sec, err := svc.UploadFile(ctx, a, internalSender(), created.ID, bytes.NewReader(stream))
		if err != nil || sec.State != store.SecretActive {
			t.Fatalf("upload = %+v, %v", sec, err)
		}
		if _, err := svc.UploadFile(ctx, a, internalSender(), created.ID, bytes.NewReader(stream)); !errors.Is(err, ErrConflict) {
			t.Errorf("second upload: %v", err)
		}
		st, err := svc.Status(ctx, a, internalIP, created.Token)
		if err != nil || st.FileSize != int64(len(stream)) {
			t.Fatalf("status = %+v, %v", st, err)
		}
		out, err := svc.Reveal(ctx, a, internalIP, created.Token, s.keyProof, s.proof)
		if err != nil || !id.SecretGrantValid(out.FileGrant) || out.EncryptedMetadata == "" {
			t.Fatalf("reveal = %+v, %v", out, err)
		}
		if _, err := svc.DownloadFile(ctx, b, internalIP, created.Token, out.FileGrant); !errors.Is(err, ErrNotFound) {
			t.Errorf("download under B: %v", err)
		}
		d, err := svc.DownloadFile(ctx, a, internalIP, created.Token, out.FileGrant)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(d)
		_ = d.Close()
		if err != nil || !bytes.Equal(got, stream) || d.Size() != int64(len(stream)) {
			t.Fatalf("download = %d bytes, %v", len(got), err)
		}
		d.Delivered(ctx)
		if _, err := svc.DownloadFile(ctx, a, internalIP, created.Token, out.FileGrant); !errors.Is(err, ErrNotFound) {
			t.Errorf("second download: %v", err)
		}
		if entries, err := files.ListSecretFiles(a.ID); err != nil || len(entries) != 0 {
			t.Errorf("files left: %v, %v", entries, err)
		}
		wantAudit := []audit.Action{audit.ActionSecretCreated, audit.ActionSecretRevealed, audit.ActionSecretFileDownloaded}
		if got := rec.actions(); !slices.Equal(got, wantAudit) {
			t.Errorf("audit = %v, want %v", got, wantAudit)
		}

		// The lock after five wrong passphrases removes the file at once,
		// without waiting for the orphan sweep (threat model T-355).
		ps, pd := seal(t, "", "correct horse")
		req = ps.request()
		req.Passphrase = &Passphrase{KDF: pd.KDF, Iterations: pd.Iterations, Salt: pd.EncodedSalt()}
		req.File = &File{Size: int64(len(stream)), EncryptedMetadata: "AQ" + strings.Repeat("A", 38)}
		locked, err := svc.Create(ctx, a, internalSender(), req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UploadFile(ctx, a, internalSender(), locked.ID, bytes.NewReader(stream)); err != nil {
			t.Fatal(err)
		}
		if entries, err := files.ListSecretFiles(a.ID); err != nil || len(entries) != 1 {
			t.Fatalf("files before the lock: %v, %v", entries, err)
		}
		var gone *GoneError
		for range store.SecretMaxFailedProofs {
			_, err = svc.Reveal(ctx, a, internalIP, locked.Token, ps.keyProof, ps.keyProof)
		}
		if !errors.As(err, &gone) || gone.Reason != ReasonLocked {
			t.Fatalf("fifth wrong passphrase: %v", err)
		}
		if entries, err := files.ListSecretFiles(a.ID); err != nil || len(entries) != 0 {
			t.Errorf("files left after the lock: %v, %v", entries, err)
		}
	})
}
