package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// faultFiles is the storage of the secret files with injectable faults.
type faultFiles struct {
	*storage.Store
	createErr, openErr, removeErr error
	// readOnly hands out a file opened for reading only: writes fail.
	readOnly bool
	removed  atomic.Int64
}

func (f *faultFiles) CreateSecretFile(tid tenant.ID, name string) (*os.File, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	w, err := f.Store.CreateSecretFile(tid, name)
	if err != nil || !f.readOnly {
		return w, err
	}
	_ = w.Close()
	r, _, err := f.Store.OpenSecretFile(tid, name)
	return r, err
}

func (f *faultFiles) OpenSecretFile(tid tenant.ID, name string) (*os.File, int64, error) {
	if f.openErr != nil {
		return nil, 0, f.openErr
	}
	return f.Store.OpenSecretFile(tid, name)
}

func (f *faultFiles) RemoveSecretFile(tid tenant.ID, name string) error {
	f.removed.Add(1)
	if f.removeErr != nil {
		return f.removeErr
	}
	return f.Store.RemoveSecretFile(tid, name)
}

// newFiles returns the storage of the secret files of a test.
func newFiles(t *testing.T) *faultFiles {
	t.Helper()
	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &faultFiles{Store: st}
}

// tte2Stream returns a valid TTE2 stream of plain bytes of plaintext.
func tte2Stream(t *testing.T, plain int) []byte {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := tte2.NewWriter(&buf, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("p"), plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withFile declares a file of size bytes on c.
func withFile(c CreateSecret, size int64) CreateSecret {
	c.FileSize, c.FileMetadata, c.FileStorageName = size, "bWV0YQ", storage.NewName()
	return c
}

// alice is the creator of the test secrets (f.input).
var alice = SecretActor{Email: "alice@a.example.com", Kind: SecretCreatorInternal}

// keyRows counts the wrapped keys left.
func (f *secretFixture) keyRows(t *testing.T) int64 {
	t.Helper()
	return rawInt(context.Background(), t, f.db, `SELECT count(*) FROM wrapped_keys`)
}

func (f *secretFixture) clock() time.Time { return f.now.Add(time.Minute) }

// TestSecretsFileUpload covers the upload of a file: refusals, malformed
// bodies, the link and the e-mail deliveries, on both engines.
func TestSecretsFileUpload(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		files := newFiles(t)
		stream := tte2Stream(t, 100_000)
		size := int64(len(stream))
		cs := f.create(ctx, t, f.a, withFile(f.input(newProofs()), size))
		sec := cs.Secret
		if sec.State != SecretPending {
			t.Fatalf("state %s", sec.State)
		}
		upload := func(id string, actor SecretActor, body []byte) (Secret, error) {
			return f.repo.UploadFile(ctx, f.a, id, actor, files, bytes.NewReader(body), f.clock)
		}
		// Another creator, another tenant, a malformed ID: not found.
		for _, actor := range []SecretActor{
			{Email: "bob@a.example.com", Kind: SecretCreatorInternal},
			{Email: "alice@a.example.com", Kind: SecretCreatorExternal},
			{APITokenID: "tok_x"},
		} {
			if _, err := upload(sec.ID, actor, stream); !errors.Is(err, ErrNotFound) {
				t.Errorf("actor %+v: %v", actor, err)
			}
		}
		if _, err := f.repo.UploadFile(ctx, f.b, sec.ID, alice, files, bytes.NewReader(stream), nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("other tenant: %v", err)
		}
		if _, err := upload("sec_bad", alice, stream); !errors.Is(err, ErrNotFound) {
			t.Errorf("malformed ID: %v", err)
		}
		// Malformed bodies: short, long, bad header. The secret stays
		// pending, without file key nor file; each attempt draws a fresh
		// storage name, recorded in the row.
		bad := bytes.Clone(stream)
		bad[0] ^= 0xff
		names := map[string]bool{sec.FileStorageName: true}
		for name, body := range map[string][]byte{
			"short": stream[:len(stream)-1], "long": append(bytes.Clone(stream), 0), "header": bad, "empty": nil,
		} {
			if _, err := upload(sec.ID, alice, body); !errors.Is(err, ErrSecretFileFormat) || !errors.Is(err, ErrSecretUploadAborted) {
				t.Errorf("%s body: %v", name, err)
			}
			if entries, err := files.ListSecretFiles(f.a); err != nil || len(entries) != 0 {
				t.Errorf("%s body: partial file left: %v, %v", name, entries, err)
			}
			got, _ := f.repo.Get(ctx, f.a, sec.ID)
			if !storage.ValidName(got.FileStorageName) || names[got.FileStorageName] {
				t.Errorf("%s body: storage name %q not fresh", name, got.FileStorageName)
			}
			names[got.FileStorageName] = true
		}
		got, _ := f.repo.Get(ctx, f.a, sec.ID)
		if got.State != SecretPending || !got.FileUploadedAt.IsZero() {
			t.Fatalf("after failures: %+v", got)
		}
		if f.keyRows(t) != 1 {
			t.Errorf("keys after failures = %d, want the text key only", f.keyRows(t))
		}
		f.assertNoOrphanKeys(t, "failed uploads")

		// The upload activates a link secret, its expiry from the clock.
		out, err := upload(sec.ID, alice, stream)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != SecretActive || !out.ActivatedAt.Equal(f.clock()) || !out.ExpiresAt.Equal(f.clock().Add(time.Hour)) ||
			!out.FileUploadedAt.Equal(f.clock()) || names[out.FileStorageName] {
			t.Fatalf("uploaded = %+v", out)
		}
		// Encrypted at rest: the stored bytes are not the stream.
		stored, n, err := files.Store.OpenSecretFile(f.a, out.FileStorageName)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(stored)
		_ = stored.Close()
		if n <= size || bytes.Contains(raw, stream[:64]) {
			t.Errorf("stored file not encrypted at rest (%d bytes)", n)
		}
		// Second upload, a secret without file: state conflict.
		if _, err := upload(sec.ID, alice, stream); !errors.Is(err, ErrSecretState) || !errors.Is(err, ErrConflict) ||
			errors.Is(err, ErrSecretUploadAborted) {
			t.Errorf("second upload: %v", err)
		}
		plain := f.create(ctx, t, f.a, f.input(newProofs()))
		if _, err := upload(plain.Secret.ID, alice, stream); !errors.Is(err, ErrSecretState) {
			t.Errorf("no file: %v", err)
		}

		// E-mail delivery: the upload keeps it pending, the send call
		// activates it.
		mail := withFile(f.input(newProofs()), size)
		mail.Delivery, mail.RecipientEmail = SecretDeliveryEmail, "carol@example.org"
		mc := f.create(ctx, t, f.a, mail)
		ms := mc.Secret
		if _, err := f.repo.ActivateForSend(ctx, f.a, ms.ID, alice, mc.Token, f.now); !errors.Is(err, ErrSecretState) {
			t.Errorf("send before the upload: %v", err)
		}
		up, err := upload(ms.ID, alice, stream)
		if err != nil || up.State != SecretPending || up.FileUploadedAt.IsZero() {
			t.Fatalf("e-mail upload = %+v, %v", up, err)
		}
		if _, err := f.repo.ActivateForSend(ctx, f.a, ms.ID, SecretActor{Email: "bob@a.example.com"}, mc.Token, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("send by another creator: %v", err)
		}
		if _, err := f.repo.ActivateForSend(ctx, f.a, "sec_bad", alice, mc.Token, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("send of a malformed ID: %v", err)
		}
		if _, err := f.repo.ActivateForSend(ctx, f.a, out.ID, alice, cs.Token, f.now); !errors.Is(err, ErrSecretState) {
			t.Errorf("send of a link secret: %v", err)
		}
		// A token that is not the secret's: not found, nothing activated.
		if _, err := f.repo.ActivateForSend(ctx, f.a, ms.ID, alice, cs.Token, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("send with another token: %v", err)
		}
		if _, err := f.repo.ActivateForSend(ctx, f.a, ms.ID, alice, "", f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("send without token: %v", err)
		}
		// Under another tenant, the secret is unknown.
		if _, err := f.repo.ActivateForSend(ctx, f.b, ms.ID, alice, mc.Token, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("send under another tenant: %v", err)
		}
		act, err := f.repo.ActivateForSend(ctx, f.a, ms.ID, alice, mc.Token, f.now)
		if err != nil || act.State != SecretActive || !act.ExpiresAt.Equal(f.now.Add(time.Hour)) {
			t.Fatalf("send = %+v, %v", act, err)
		}
		if _, err := f.repo.ActivateForSend(ctx, f.a, ms.ID, alice, mc.Token, f.now); !errors.Is(err, ErrSecretState) {
			t.Errorf("second send: %v", err)
		}
		// An e-mail secret without file is sent at once.
		textMail := f.input(newProofs())
		textMail.Delivery, textMail.RecipientEmail = SecretDeliveryEmail, "carol@example.org"
		tm := f.create(ctx, t, f.a, textMail)
		if act, err := f.repo.ActivateForSend(ctx, f.a, tm.Secret.ID, alice, tm.Token, time.Time{}); err != nil || act.State != SecretActive {
			t.Fatalf("send without file = %+v, %v", act, err)
		}
		f.assertNoOrphanKeys(t, "uploads")

		// A concurrent upload (file key attached) is refused.
		busy := f.create(ctx, t, f.a, withFile(f.input(newProofs()), size)).Secret
		err = writeScoped(ctx, f.db, f.a, "attach", func(tx *ScopedTx) error {
			wk, _, err := f.keys.NewDEKTx(ctx, tx)
			if err != nil {
				return err
			}
			return execOne(ctx, tx, qSecretFileBegin, wk, storage.NewName(), busy.ID)
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := upload(busy.ID, alice, stream); !errors.Is(err, ErrSecretState) {
			t.Errorf("concurrent upload: %v", err)
		}
		// The pending purge takes the attached key with the row.
		ended, _, err := f.repo.PurgePending(ctx, f.now.Add(2*time.Hour), 10)
		if err != nil || len(ended) == 0 {
			t.Fatalf("purge = %v, %v", ended, err)
		}
		f.assertNoOrphanKeys(t, "purge")
	})
}

// TestSecretsFileDownload covers the one-time grant: the reveal, the
// refusals, the single complete download, the sweep of an expired grant
// and the tombstone purge that waits for it.
func TestSecretsFileDownload(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		files := newFiles(t)
		stream := tte2Stream(t, 200_000)
		size := int64(len(stream))
		newFileSecret := func() (CreatedSecret, proofs) {
			p := newProofs()
			cs := f.create(ctx, t, f.a, withFile(f.input(p), size))
			if _, err := f.repo.UploadFile(ctx, f.a, cs.Secret.ID, alice, files, bytes.NewReader(stream), f.clock); err != nil {
				t.Fatal(err)
			}
			return cs, p
		}
		cs, p := newFileSecret()
		at := f.now.Add(2 * time.Minute)
		// The key proof comes first: a caller without the key learns
		// nothing of the file.
		wrong := p
		wrong.key[0] ^= 1
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, wrong.key, p.proof, at); !errors.Is(err, ErrSecretKeyProof) {
			t.Fatalf("wrong key proof: %v", err)
		}
		rv, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, at)
		if err != nil {
			t.Fatal(err)
		}
		if rv.FileMetadata != "bWV0YQ" || !strings.HasPrefix(rv.FileGrant, "ttg_") ||
			!rv.FileGrantExpiresAt.Equal(at.Add(SecretFileGrantLifetime)) || rv.Secret.FileStorageName == "" {
			t.Fatalf("revealed = %+v", rv)
		}
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM secrets WHERE file_metadata IS NOT NULL`); n != 0 {
			t.Error("file metadata kept after the reveal")
		}
		// Refusals: malformed, wrong, expired grant; unknown token; a
		// pending secret; another tenant.
		other, _ := newFileSecret()
		pend := f.create(ctx, t, f.a, withFile(f.input(newProofs()), size))
		cases := []struct {
			name, token, grant string
			now                time.Time
			want               error
		}{
			{"malformed grant", cs.Token, "ttg_x", at, ErrSecretGrant},
			{"wrong grant", cs.Token, "ttg_" + strings.Repeat("A", 43), at, ErrSecretGrant},
			{"expired grant", cs.Token, rv.FileGrant, rv.FileGrantExpiresAt, ErrSecretGrant},
			{"no grant", other.Token, rv.FileGrant, at, ErrSecretGrant},
			{"pending", pend.Token, rv.FileGrant, at, ErrSecretPending},
			{"malformed token", "tts_x", rv.FileGrant, at, ErrNotFound},
			{"unknown token", "tts_" + strings.Repeat("B", 43), rv.FileGrant, at, ErrNotFound},
		}
		for _, c := range cases {
			_, err := f.repo.OpenFile(ctx, f.a, c.token, c.grant, files, c.now)
			unknown := errors.Is(c.want, ErrNotFound) && !errors.Is(c.want, ErrSecretGrant) && !errors.Is(c.want, ErrSecretPending)
			if !errors.Is(err, c.want) || (unknown && errors.Is(err, ErrSecretGrant)) {
				t.Errorf("%s: %v", c.name, err)
			}
		}
		if _, err := f.repo.OpenFile(ctx, f.b, cs.Token, rv.FileGrant, files, at); !errors.Is(err, ErrNotFound) ||
			errors.Is(err, ErrSecretGrant) {
			t.Errorf("other tenant: %v", err)
		}
		// Two downloads at once: both stream, the first to complete ends
		// the grant.
		d1, err := f.repo.OpenFile(ctx, f.a, cs.Token, rv.FileGrant, files, at)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := f.repo.OpenFile(ctx, f.a, cs.Token, rv.FileGrant, files, at)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(d1)
		if err != nil || !bytes.Equal(got, stream) || d1.Size != size || d1.ID != cs.Secret.ID {
			t.Fatalf("download = %d bytes (%d), %v", len(got), d1.Size, err)
		}
		_ = d1.Close()
		_ = d2.Close()
		// cs: its file key; other: text and file keys; pend: its text key.
		if f.keyRows(t) != 4 {
			t.Errorf("keys before completion = %d", f.keyRows(t))
		}
		ended, ok, err := f.repo.CompleteFileDownload(ctx, f.a, cs.Secret.ID, rv.FileGrant, at)
		if err != nil || !ok || ended.RemovedFile != rv.Secret.FileStorageName || ended.Secret.FileDownloadedAt.IsZero() ||
			ended.Secret.FileStorageName != "" {
			t.Fatalf("complete = %+v, %v, %v", ended, ok, err)
		}
		if _, ok, err := f.repo.CompleteFileDownload(ctx, f.a, cs.Secret.ID, rv.FileGrant, at); ok || err != nil {
			t.Errorf("second completion = %v, %v", ok, err)
		}
		if _, ok, err := f.repo.CompleteFileDownload(ctx, f.a, "sec_unknown", rv.FileGrant, at); ok || err != nil {
			t.Errorf("unknown secret completion = %v, %v", ok, err)
		}
		if _, err := f.repo.OpenFile(ctx, f.a, cs.Token, rv.FileGrant, files, at); !errors.Is(err, ErrSecretGrant) {
			t.Errorf("used grant: %v", err)
		}
		f.assertNoOrphanKeys(t, "download")

		// An expired grant: the tombstone purge waits, the sweep cleans it.
		p2 := newProofs()
		cs2 := f.create(ctx, t, f.a, withFile(f.input(p2), size))
		if _, err := f.repo.UploadFile(ctx, f.a, cs2.Secret.ID, alice, files, bytes.NewReader(stream), f.clock); err != nil {
			t.Fatal(err)
		}
		rv2, err := f.repo.Reveal(ctx, f.a, cs2.Token, p2.key, p2.proof, at)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := f.repo.PurgeTombstones(ctx, f.a, at.Add(SecretTombstoneRetention+time.Hour)); err != nil {
			t.Fatal(err)
		} else if _, gerr := f.repo.Get(ctx, f.a, cs2.Secret.ID); gerr != nil {
			t.Fatalf("tombstone with a pending grant purged (%d): %v", n, gerr)
		}
		if out, _, err := f.repo.ExpireGrants(ctx, at.Add(time.Minute), 10); err != nil || len(out) != 0 {
			t.Fatalf("early sweep = %v, %v", out, err)
		}
		out, more, err := f.repo.ExpireGrants(ctx, rv2.FileGrantExpiresAt, 10)
		if err != nil || more || len(out) != 1 || out[0].RemovedFile != rv2.Secret.FileStorageName ||
			out[0].Secret.State != SecretRead || !out[0].Secret.FileDownloadedAt.IsZero() {
			t.Fatalf("grant sweep = %+v, %v, %v", out, more, err)
		}
		if _, ok, err := f.repo.CompleteFileDownload(ctx, f.a, cs2.Secret.ID, rv2.FileGrant, at); ok || err != nil {
			t.Errorf("completion after the sweep = %v, %v", ok, err)
		}
		f.assertNoOrphanKeys(t, "grant sweep")
		if _, err := f.repo.PurgeTombstones(ctx, f.a, at.Add(SecretTombstoneRetention+time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.Get(ctx, f.a, cs2.Secret.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("tombstone after the sweep: %v", err)
		}
	})
}

// TestSecretsFileQuota covers the storage quota: the secret files count,
// and a file that does not fit is refused.
func TestSecretsFileQuota(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		if err := rawExecArgs(ctx, t, f.db, `UPDATE tenants SET storage_quota_bytes = ? WHERE id = ?`, int64(3000), string(f.a)); err != nil {
			t.Fatal(err)
		}
		used := func() int64 {
			t.Helper()
			n, err := readScoped(ctx, f.db, f.a, "used", func(tx *ScopedTx) (int64, error) {
				return f.db.Transfers().UsedBytesTx(ctx, tx)
			})
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		if used() != 0 {
			t.Fatal("used before")
		}
		cs := f.create(ctx, t, f.a, withFile(f.input(newProofs()), 2000))
		f.create(ctx, t, f.b, withFile(f.input(newProofs()), 500))
		if used() != 2000 {
			t.Errorf("used = %d", used())
		}
		all, err := f.db.Transfers().UsedBytesAll(ctx)
		if err != nil || all[f.a] != 2000 || all[f.b] != 500 {
			t.Errorf("UsedBytesAll = %v, %v", all, err)
		}
		if _, err := f.repo.Create(ctx, f.a, withFile(f.input(newProofs()), 1001)); !errors.Is(err, ErrSecretQuotaExceeded) {
			t.Errorf("over quota: %v", err)
		}
		f.create(ctx, t, f.a, withFile(f.input(newProofs()), 1000)) // exactly at the quota
		// A secret without file never counts.
		f.create(ctx, t, f.a, f.input(newProofs()))
		if _, err := f.repo.DeleteByAdmin(ctx, f.a, cs.Secret.ID, f.now); err != nil {
			t.Fatal(err)
		}
		if used() != 1000 {
			t.Errorf("used after deletion = %d", used())
		}
		f.assertNoOrphanKeys(t, "quota")
	})
}

// TestSecretsMarkReceiptSent checks that one receipt is marked, once, even
// under concurrency, and only for an ended secret asked with a receipt.
func TestSecretsMarkReceiptSent(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		in := f.input(p)
		in.ReadReceipt = true
		cs := f.create(ctx, t, f.a, in)
		if ok, err := f.repo.MarkReceiptSent(ctx, f.a, cs.Secret.ID, f.now); ok || err != nil {
			t.Fatalf("active secret = %v, %v", ok, err)
		}
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); err != nil {
			t.Fatal(err)
		}
		if ok, err := f.repo.MarkReceiptSent(ctx, f.b, cs.Secret.ID, f.now); ok || err != nil {
			t.Fatalf("other tenant = %v, %v", ok, err)
		}
		var (
			wg      sync.WaitGroup
			winners atomic.Int64
		)
		for range 8 {
			wg.Go(func() {
				ok, err := f.repo.MarkReceiptSent(ctx, f.a, cs.Secret.ID, time.Time{})
				if err != nil {
					t.Error(err)
				}
				if ok {
					winners.Add(1)
				}
			})
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("%d winners", winners.Load())
		}
		if s, _ := f.repo.Get(ctx, f.a, cs.Secret.ID); s.ReceiptSentAt.IsZero() {
			t.Error("receipt not marked")
		}
		// Without receipt, or deleted: never marked.
		p2 := newProofs()
		plain := f.create(ctx, t, f.a, f.input(p2))
		if _, err := f.repo.Reveal(ctx, f.a, plain.Token, p2.key, p2.proof, f.now); err != nil {
			t.Fatal(err)
		}
		del := f.create(ctx, t, f.a, in)
		if _, err := f.repo.DeleteByAdmin(ctx, f.a, del.Secret.ID, f.now); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{plain.Secret.ID, del.Secret.ID} {
			if ok, err := f.repo.MarkReceiptSent(ctx, f.a, id, f.now); ok || err != nil {
				t.Errorf("%s = %v, %v", id, ok, err)
			}
		}
	})
}

// TestSecretFileRefs lists the stored names with their keys.
func TestSecretFileRefs(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		files := newFiles(t)
		stream := tte2Stream(t, 10)
		pend := f.create(ctx, t, f.a, withFile(f.input(newProofs()), int64(len(stream))))
		up := f.create(ctx, t, f.a, withFile(f.input(newProofs()), int64(len(stream))))
		uploaded, err := f.repo.UploadFile(ctx, f.a, up.Secret.ID, alice, files, bytes.NewReader(stream), nil)
		if err != nil {
			t.Fatal(err)
		}
		f.create(ctx, t, f.b, withFile(f.input(newProofs()), int64(len(stream))))
		refs, err := f.repo.SecretFileRefs(ctx, f.a)
		if err != nil || len(refs) != 2 || refs[pend.Secret.FileStorageName] || !refs[uploaded.FileStorageName] {
			t.Fatalf("refs = %v, %v", refs, err)
		}
		f.db.reconcileRows = 1
		if _, err := f.repo.SecretFileRefs(ctx, f.a); !errors.Is(err, ErrTooManyRows) {
			t.Errorf("too many rows: %v", err)
		}
	})
}

// deleteOnRead deletes the secret when the body is first read.
type deleteOnRead struct {
	r    io.Reader
	once sync.Once
	fn   func()
}

func (d *deleteOnRead) Read(p []byte) (int, error) {
	d.once.Do(d.fn)
	return d.r.Read(p)
}

// failingReader fails every read.
type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

// TestSecretsFileFaults covers the failures of the vault, the files and
// the database on the file paths (SQLite with injected faults).
func TestSecretsFileFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := newSecretFixtureDB(t, db)
	files := newFiles(t)
	// Larger than a chunk of the at-rest encryption: a write error shows
	// before the close.
	stream := tte2Stream(t, 100_000)
	size := int64(len(stream))
	errKey, errFile := errors.New("vault down"), errors.New("disk down")
	upload := func(secID string, body io.Reader) error {
		_, err := f.repo.UploadFile(ctx, f.a, secID, alice, files, body, f.clock)
		return err
	}
	pend := f.create(ctx, t, f.a, withFile(f.input(newProofs()), size))
	check := func(label string, err, want error) {
		t.Helper()
		if (want == nil && err == nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v", label, err)
		}
		if err != nil && strings.Contains(err.Error(), os.TempDir()) {
			t.Errorf("%s: the error leaks a path: %v", label, err)
		}
		if s, _ := f.repo.Get(ctx, f.a, pend.Secret.ID); s.State != SecretPending || !s.FileUploadedAt.IsZero() {
			t.Errorf("%s: secret %+v", label, s)
		}
		f.assertNoOrphanKeys(t, label) //nolint:contextcheck // a test assertion, on its own background context
	}

	// No vault.
	noKeys := db.Secrets(nil)
	if _, err := noKeys.UploadFile(ctx, f.a, pend.Secret.ID, alice, files, nil, nil); !errors.Is(err, errSecretNoKeys) {
		t.Errorf("upload without vault: %v", err)
	}
	if _, err := noKeys.OpenFile(ctx, f.a, pend.Token, "", files, f.now); !errors.Is(err, errSecretNoKeys) {
		t.Errorf("open without vault: %v", err)
	}
	if _, _, err := noKeys.CompleteFileDownload(ctx, f.a, pend.Secret.ID, "", f.now); !errors.Is(err, errSecretNoKeys) {
		t.Errorf("complete without vault: %v", err)
	}

	f.keys.newErr = errKey
	check("NewDEKTx", upload(pend.Secret.ID, bytes.NewReader(stream)), errKey)
	f.keys.newErr = nil
	files.createErr = errFile
	check("create file", upload(pend.Secret.ID, bytes.NewReader(stream)), errFile)
	files.createErr = nil
	files.readOnly = true
	check("write file", upload(pend.Secret.ID, bytes.NewReader(stream)), nil)
	files.readOnly = false
	check("read body", upload(pend.Secret.ID, failingReader{errFile}), errFile)
	f.keys.shortKey = true
	check("short key", upload(pend.Secret.ID, bytes.NewReader(stream)), crypto.ErrKeySize)
	f.keys.shortKey = false
	// The cleanup fails too: both errors are reported.
	files.removeErr = errFile
	f.keys.dstrErr = errKey
	err := upload(pend.Secret.ID, failingReader{io.ErrUnexpectedEOF})
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, errFile) || !errors.Is(err, errKey) {
		t.Errorf("failed cleanup: %v", err)
	}
	files.removeErr, f.keys.dstrErr = nil, nil
	// The key stays attached: the next upload is refused until the pending
	// purge.
	if err := upload(pend.Secret.ID, bytes.NewReader(stream)); !errors.Is(err, ErrSecretState) {
		t.Errorf("after a failed cleanup: %v", err)
	}
	if _, _, err := f.repo.PurgePending(ctx, f.now.Add(2*time.Hour), 10); err != nil {
		t.Fatal(err)
	}
	f.assertNoOrphanKeys(t, "purge after a failed cleanup")

	// A declared size below a TTE2 stream: refused before any write.
	tiny := f.create(ctx, t, f.a, withFile(f.input(newProofs()), 10))
	if err := upload(tiny.Secret.ID, bytes.NewReader(stream)); !errors.Is(err, ErrSecretFileFormat) {
		t.Errorf("tiny declared size: %v", err)
	}
	f.assertNoOrphanKeys(t, "tiny declared size")

	// Deleted while it uploads: refused, the deletion destroyed the key.
	del := f.create(ctx, t, f.a, withFile(f.input(newProofs()), size))
	body := &deleteOnRead{r: bytes.NewReader(stream), fn: func() {
		if _, err := f.repo.DeleteByAdmin(ctx, f.a, del.Secret.ID, f.now); err != nil {
			t.Error(err)
		}
	}}
	if err := upload(del.Secret.ID, body); !errors.Is(err, ErrSecretState) {
		t.Errorf("deleted during the upload: %v", err)
	}
	f.assertNoOrphanKeys(t, "deleted during the upload")

	// Database faults of the upload.
	live := f.create(ctx, t, f.a, withFile(f.input(newProofs()), size))
	for i, s := range []struct {
		op, match string
		after     int
	}{
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0},
		{faultExec, "SET file_key_id = ?, file_storage_name = ? WHERE", 0},
		{faultExec, "SET file_uploaded_at = ?, state = 'active'", 0},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 1},
	} {
		plan.add(s.op, s.match, s.after)
		if err := upload(live.Secret.ID, bytes.NewReader(stream)); !errors.Is(err, errInjected) {
			t.Errorf("upload step %d: %v", i, err)
		}
		plan.reset()
		f.assertNoOrphanKeys(t, "upload faults")
	}
	plan.add(faultExec, "SET file_key_id = NULL", 0)
	if err := upload(live.Secret.ID, failingReader{errFile}); !errors.Is(err, errInjected) || !errors.Is(err, errFile) {
		t.Errorf("abort fault: %v", err)
	}
	plan.reset()
	if _, _, err := f.repo.PurgePending(ctx, f.now.Add(3*time.Hour), 10); err != nil {
		t.Fatal(err)
	}

	// Faults of the send call.
	mail := f.input(newProofs())
	mail.Delivery, mail.RecipientEmail = SecretDeliveryEmail, "carol@example.org"
	ms := f.create(ctx, t, f.a, mail)
	for i, s := range []struct {
		op, match string
		after     int
	}{
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0},
		{faultQuery, "SELECT token_hash FROM secrets", 0},
		{faultExec, "SET state = 'active', activated_at", 0},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 1},
	} {
		plan.add(s.op, s.match, s.after)
		if _, err := f.repo.ActivateForSend(ctx, f.a, ms.Secret.ID, alice, ms.Token, f.now); !errors.Is(err, errInjected) {
			t.Errorf("send step %d: %v", i, err)
		}
		plan.reset()
	}

	// A revealed secret with a file, for the download faults.
	p := newProofs()
	fs := f.create(ctx, t, f.a, withFile(f.input(p), size))
	if err := upload(fs.Secret.ID, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	f.repo.newGrant = func() (string, error) { return "", errKey }
	if _, err := f.repo.Reveal(ctx, f.a, fs.Token, p.key, p.proof, f.now); !errors.Is(err, errKey) {
		t.Errorf("grant failure: %v", err)
	}
	f.repo.newGrant = db.Secrets(nil).newGrant
	plan.add(faultExec, "file_grant_hash = ?, file_grant_expires_at = ?", 0)
	if _, err := f.repo.Reveal(ctx, f.a, fs.Token, p.key, p.proof, f.now); !errors.Is(err, errInjected) {
		t.Errorf("grant update fault: %v", err)
	}
	plan.reset()
	rv, err := f.repo.Reveal(ctx, f.a, fs.Token, p.key, p.proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	open := func() error {
		d, err := f.repo.OpenFile(ctx, f.a, fs.Token, rv.FileGrant, files, f.now)
		if err == nil {
			_ = d.Close()
		}
		return err
	}
	plan.add(faultQuery, "file_key_id, file_grant_hash", 0)
	if err := open(); !errors.Is(err, errInjected) {
		t.Errorf("grant read fault: %v", err)
	}
	plan.reset()
	f.keys.openErr = errKey
	if err := open(); !errors.Is(err, errKey) {
		t.Errorf("OpenTx failure: %v", err)
	}
	f.keys.openErr = nil
	files.openErr = errFile
	if err := open(); !errors.Is(err, errFile) {
		t.Errorf("open file failure: %v", err)
	}
	files.openErr = nil
	// A truncated stored file: no header.
	trunc, err := files.Store.CreateSecretFile(f.a, rv.Secret.FileStorageName)
	if err != nil {
		t.Fatal(err)
	}
	_ = trunc.Close()
	if err := open(); !errors.Is(err, crypto.ErrTruncated) {
		t.Errorf("truncated file: %v", err)
	}
	for i, s := range []struct {
		op, match string
		after     int
	}{
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0},
		{faultExec, "SET file_downloaded_at = ?", 0},
	} {
		plan.add(s.op, s.match, s.after)
		if _, _, err := f.repo.CompleteFileDownload(ctx, f.a, fs.Secret.ID, rv.FileGrant, f.now); !errors.Is(err, errInjected) {
			t.Errorf("complete step %d: %v", i, err)
		}
		plan.reset()
	}
	for i, s := range []struct {
		op, match string
		after     int
	}{
		{faultQuery, "WHERE file_grant_hash IS NOT NULL", 0},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0},
		{faultExec, "file_grant_expires_at <= ?", 0},
	} {
		plan.add(s.op, s.match, s.after)
		if _, _, err := f.repo.ExpireGrants(ctx, f.now.Add(time.Hour), 10); !errors.Is(err, errInjected) {
			t.Errorf("grant sweep step %d: %v", i, err)
		}
		plan.reset()
	}
	// The grant sweep skips a row that changed meanwhile: gone, or whose
	// grant is not due.
	if err := writeScoped(ctx, f.db, f.a, "sweep", func(tx *ScopedTx) error {
		for _, secID := range []string{"sec_00000000000000000000000000", fs.Secret.ID} {
			e, ok, err := f.repo.sweepGrantTx(ctx, tx, secID, toMillis(f.now))
			if ok || err != nil || e.RemovedFile != "" {
				t.Errorf("%s = %v, %v", secID, ok, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Faults of the quota, the receipts and the references.
	plan.add(faultQuery, "sum(file_size)", 0)
	if _, err := f.repo.Create(ctx, f.a, withFile(f.input(newProofs()), size)); !errors.Is(err, errInjected) {
		t.Errorf("quota fault: %v", err)
	}
	plan.reset()
	plan.add(faultQuery, "sum(total_bytes)", 0)
	if _, err := f.repo.Create(ctx, f.a, withFile(f.input(newProofs()), size)); !errors.Is(err, errInjected) {
		t.Errorf("transfer quota fault: %v", err)
	}
	plan.reset()
	plan.add(faultQuery, "sum(file_size)", 0)
	if _, err := f.db.Transfers().UsedBytesAll(ctx); !errors.Is(err, errInjected) {
		t.Errorf("UsedBytesAll fault: %v", err)
	}
	plan.reset()
	plan.add(faultQuery, "sum(total_bytes)", 0)
	if _, err := f.db.Transfers().UsedBytesAll(ctx); !errors.Is(err, errInjected) {
		t.Errorf("UsedBytesAll transfer fault: %v", err)
	}
	plan.reset()
	plan.add(faultScanNil, "sum(file_size)", 0)
	if _, err := f.db.Transfers().UsedBytesAll(ctx); err == nil {
		t.Error("UsedBytesAll scan fault: no error")
	}
	plan.reset()
	plan.add(faultExec, "SET receipt_sent_at", 0)
	if _, err := f.repo.MarkReceiptSent(ctx, f.a, fs.Secret.ID, f.now); !errors.Is(err, errInjected) {
		t.Errorf("receipt fault: %v", err)
	}
	plan.reset()
	plan.add(faultQuery, "SELECT file_storage_name, file_key_id", 0)
	if _, err := f.repo.SecretFileRefs(ctx, f.a); !errors.Is(err, errInjected) {
		t.Errorf("refs fault: %v", err)
	}
	plan.reset()
	plan.add(faultScanNil, "SELECT file_storage_name, file_key_id", 0)
	if _, err := f.repo.SecretFileRefs(ctx, f.a); err == nil {
		t.Error("refs scan fault: no error")
	}
	plan.reset()
}

// failingWriter fails every write.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// TestCopySecretFileWriteError covers a write failure of the copy.
func TestCopySecretFileWriteError(t *testing.T) {
	t.Parallel()
	stream := tte2Stream(t, 10)
	v, err := tte2.NewValidator(int64(len(stream)))
	if err != nil {
		t.Fatal(err)
	}
	errDisk := errors.New("disk full")
	if err := copySecretFile(failingWriter{errDisk}, bytes.NewReader(stream), v); !errors.Is(err, errDisk) {
		t.Fatalf("copy = %v", err)
	}
}
