package tenantops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// secret stores an active link secret of tn sent by sender and returns its
// ID. With withFile it declares a file (so the secret stays pending), whose
// ciphertext is written under the secret directory of the tenant.
func (ev *env) secret(tn *tenant.Tenant, sender string, withFile bool) string {
	ev.t.Helper()
	var kp, p [32]byte
	_, _ = rand.Read(kp[:])
	_, _ = rand.Read(p[:])
	kv, v := sha256.Sum256(kp[:]), sha256.Sum256(p[:])
	in := store.CreateSecret{
		CreatorKind: store.SecretCreatorInternal, SenderEmail: sender, Delivery: store.SecretDeliveryLink,
		Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("sealed-text_", 5),
		Duration: tenant.SecretDuration1d, Now: ev.clock.Now(),
	}
	if withFile {
		in.FileSize, in.FileMetadata, in.FileStorageName = 1024, strings.Repeat("meta_", 6), storage.NewName()
		dir := filepath.Join(ev.root, string(tn.ID), "secrets")
		mustNoErr(ev.t, "mkdir", os.MkdirAll(dir, 0o750))
		mustNoErr(ev.t, "write", os.WriteFile(filepath.Join(dir, in.FileStorageName), []byte("ciphertext"), 0o600))
	}
	cs, err := ev.db.Secrets(ev.vault).Create(context.Background(), tn.ID, in)
	mustNoErr(ev.t, "create secret", err)
	return cs.Secret.ID
}

// secretFiles counts the files of the secrets of tn on disk.
func (ev *env) secretFiles(tn *tenant.Tenant) int {
	ev.t.Helper()
	ents, err := os.ReadDir(filepath.Join(ev.root, string(tn.ID), "secrets"))
	if err != nil {
		return 0
	}
	return len(ents)
}

func TestListSecrets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.secret(ev.a, alice, false)
		ev.clock.Advance(1)
		ev.secret(ev.a, carol, false)
		ev.secret(ev.a, alice, true)
		other := ev.secret(ev.b, alice, false)

		page, err := ev.svc.ListSecrets(ctx, ev.adminA, ev.a.ID, SecretFilter{})
		mustNoErr(t, "list", err)
		if len(page.Items) != 3 {
			t.Fatalf("list = %d secrets, want 3 (A's)", len(page.Items))
		}
		for _, s := range page.Items {
			if s.ID == other {
				t.Error("the secret of tenant B is listed")
			}
		}
		for name, c := range map[string]struct {
			f    SecretFilter
			want int
		}{
			"active": {SecretFilter{State: "active"}, 2}, "pending": {SecretFilter{State: "pending"}, 1},
			"deleted": {SecretFilter{State: "deleted"}, 0}, "sender": {SecretFilter{Sender: "ALICE@entity-a.example.com"}, 2},
			"both": {SecretFilter{State: "active", Sender: alice}, 1},
		} {
			page, err := ev.svc.ListSecrets(ctx, ev.super, ev.a.ID, c.f)
			mustNoErr(t, name, err)
			if len(page.Items) != c.want {
				t.Errorf("%s: %d secrets, want %d", name, len(page.Items), c.want)
			}
		}
		// Pagination.
		page, err = ev.svc.ListSecrets(ctx, ev.adminA, ev.a.ID, SecretFilter{Limit: 2})
		mustNoErr(t, "page 1", err)
		next, err := ev.svc.ListSecrets(ctx, ev.adminA, ev.a.ID, SecretFilter{Limit: 2, Cursor: page.NextCursor})
		mustNoErr(t, "page 2", err)
		if len(page.Items) != 2 || len(next.Items) != 1 || next.NextCursor != "" {
			t.Fatalf("pages = %d, %d", len(page.Items), len(next.Items))
		}

		for name, f := range map[string]SecretFilter{
			"state": {State: "nope"}, "address": {Sender: "not an address"}, "limit": {Limit: store.MaxPageSize + 1},
			"cursor": {Cursor: "bad"},
		} {
			_, err := ev.svc.ListSecrets(ctx, ev.adminA, ev.a.ID, f)
			wantErr(t, name, err, ErrInvalid)
		}
		ev.faults("listSecrets")
		_, err = ev.svc.ListSecrets(ctx, ev.adminA, ev.a.ID, SecretFilter{})
		wantErr(t, "failing store", err, errBoom)
	})
}

func TestDeleteSecret(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		active := ev.secret(ev.a, alice, false)
		withFile := ev.secret(ev.a, alice, true)
		other := ev.secret(ev.b, alice, false)
		if ev.secretFiles(ev.a) != 1 {
			t.Fatal("fixture file missing")
		}

		mustNoErr(t, "delete active", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, active, clientIP))
		mustNoErr(t, "delete pending with a file", ev.svc.DeleteSecret(ctx, ev.super, ev.a.ID, withFile, clientIP))
		if ev.secretFiles(ev.a) != 0 {
			t.Error("the file of the deleted secret is left")
		}
		got, err := ev.db.Secrets(nil).Get(ctx, ev.a.ID, active)
		mustNoErr(t, "get", err)
		if got.State != store.SecretDeleted || got.EndReason != store.SecretEndDeletedByAdmin {
			t.Errorf("tombstone = %+v", got)
		}
		events := ev.auditEvents(ev.a.ID, audit.ActionSecretDeleted)
		if len(events) != 2 {
			t.Fatalf("%d secret.deleted events, want 2", len(events))
		}
		for _, e := range events {
			if e.ActorKind != store.ActorAdmin || e.ObjectKind != audit.ObjectSecret || e.IP != clientIP {
				t.Errorf("event = %+v", e)
			}
			ev.details(e)
		}

		// Already ended: a no-op without audit.
		mustNoErr(t, "delete again", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, active, clientIP))
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionSecretDeleted)); n != 2 {
			t.Errorf("%d secret.deleted events after a no-op, want 2", n)
		}
		// Another tenant's secret, a malformed ID, a missing one.
		wantErr(t, "secret of B by A's admin", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, other, clientIP), ErrNotFound)
		wantErr(t, "secret of B on B by A's admin", ev.svc.DeleteSecret(ctx, ev.adminA, ev.b.ID, other, clientIP), ErrNotFound)
		wantErr(t, "malformed ID", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, "sec_x", clientIP), ErrNotFound)
		wantErr(t, "missing", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, "sec_01JAB00000000000000000000Z", clientIP), ErrNotFound)
		if _, err := ev.db.Secrets(nil).Get(ctx, ev.b.ID, other); err != nil {
			t.Errorf("B's secret after the attacks: %v", err)
		}

		// Failures: the store, the scrub (logged only), the audit (logged only).
		third := ev.secret(ev.a, alice, false)
		ev.faults("deleteSecret")
		wantErr(t, "failing store", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, third, clientIP), errBoom)
		ev.faults("scrub", "audit")
		mustNoErr(t, "failing scrub and audit", ev.svc.DeleteSecret(ctx, ev.adminA, ev.a.ID, third, clientIP))
		for _, want := range []string{"scrub after a secret deletion failed", "audit write failed"} {
			if !strings.Contains(ev.logs.String(), want) {
				t.Errorf("log %q missing:\n%s", want, ev.logs.String())
			}
		}
	})
}

// failingSecretFiles fails every removal.
type failingSecretFiles struct{}

func (failingSecretFiles) RemoveSecretFile(tenant.ID, string) error { return errBoom }

// TestDeleteSecretFileLeft logs a file that cannot be removed: the keys are
// destroyed, the deletion succeeds.
func TestDeleteSecretFileLeft(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		sec := ev.secret(ev.a, alice, true)
		ev.svc.secretFiles = failingSecretFiles{}
		mustNoErr(t, "delete", ev.svc.DeleteSecret(context.Background(), ev.adminA, ev.a.ID, sec, clientIP))
		if !strings.Contains(ev.logs.String(), "secret file left on disk") || ev.secretFiles(ev.a) != 1 {
			t.Errorf("file left = %d\nlogs:\n%s", ev.secretFiles(ev.a), ev.logs.String())
		}
	})
}
