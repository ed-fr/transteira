package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// expiredOutside stores a transfer of tn expired at the current time of the
// clock, its keys destroyed as the expiry task does.
func (ev *env) expiredOutside(tn *tenant.Tenant) fixture {
	ev.t.Helper()
	ctx := context.Background()
	fx := ev.available(tn, 1, false)
	d := ev.get(fx)
	if err := ev.uploads.RemoveFiles(ctx, tn.ID, d.Files); err != nil {
		ev.t.Fatal(err)
	}
	ev.tx(tn, func(tx *store.ScopedTx) error {
		if err := ev.vault.DestroyTx(ctx, tx, d.DownloadTokenKeyID); err != nil {
			return err
		}
		return ev.db.Transfers().MarkExpiredTx(ctx, tx, fx.id, ev.clock.Now())
	})
	return fx
}

// tenantData is what a tenant holds besides its transfers.
type tenantData struct {
	// smtpKey is the wrapped key of the SMTP password.
	smtpKey string
	// spareKey is a sealed secret referenced by nothing.
	spareKey string
}

// populate gives tn an SMTP password, a spare secret, branding assets and
// an audit event.
func (ev *env) populate(tn *tenant.Tenant) tenantData {
	ev.t.Helper()
	ctx := context.Background()
	var td tenantData
	ev.tx(tn, func(tx *store.ScopedTx) error {
		var err error
		if td.smtpKey, err = ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte("smtp-password")); err != nil {
			return err
		}
		if td.spareKey, err = ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte("spare")); err != nil {
			return err
		}
		return ev.db.SMTPSettings().PutTx(ctx, tx, store.SMTPConfig{
			Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: "relay",
			PasswordKeyID: td.smtpKey, FromAddress: "noreply@entity.example.com",
		})
	})
	ev.write(tn, "logo.png", t0)
	ev.write(tn, "background.jpg", t0)
	if _, err := ev.db.AuditEvents().Append(ctx, store.AuditEvent{
		TenantID: tn.ID, ActorKind: store.ActorSystem, Actor: "system", Action: "transfer.deleted",
		ObjectKind: "transfer", ObjectID: "trf_01hzzzzzzzzzzzzzzzzzzzzzzz",
	}); err != nil {
		ev.t.Fatal(err)
	}
	return td
}

// startDeletion moves tn to tenant.StatusDeleting.
func (ev *env) startDeletion(tn *tenant.Tenant) {
	ev.t.Helper()
	if err := ev.db.Tenants().SetStatus(context.Background(), tn.ID, tenant.StatusDeleting); err != nil {
		ev.t.Fatal(err)
	}
}

// tenantFixtures stores, for tn, two available transfers (one with a
// download state), an uploading one with a checkpoint, a rejected one
// keeping its file keys, and expired and deleted ones, and returns the
// transfers with their details read before the erasure.
func (ev *env) tenantFixtures(tn *tenant.Tenant) ([]fixture, []store.TransferDetails) {
	ev.t.Helper()
	fxs := []fixture{
		ev.due(tn, 2),
		ev.available(tn, 1, false),
		ev.uploading(tn, 1, 1, t0, t0),
		ev.rejected(tn, 1),
		ev.expiredOutside(tn),
		ev.ended(tn),
	}
	before := make([]store.TransferDetails, len(fxs))
	for i, fx := range fxs {
		before[i] = ev.get(fx)
	}
	return fxs, before
}

// assertTenantErased checks that tn and all its data are gone, its audit
// events kept.
func (ev *env) assertTenantErased(tn *tenant.Tenant, fxs []fixture, before []store.TransferDetails, td tenantData) {
	ev.t.Helper()
	ctx := context.Background()
	if _, err := ev.db.Tenants().Get(ctx, tn.ID); !errors.Is(err, store.ErrNotFound) {
		ev.t.Fatalf("tenant row: %v, want ErrNotFound", err)
	}
	if _, err := os.Lstat(filepath.Join(ev.root, string(tn.ID))); !errors.Is(err, fs.ErrNotExist) {
		ev.t.Fatalf("tenant directory: %v, want gone", err)
	}
	if ids, err := ev.db.WrappedKeys().ListIDs(ctx, tn.ID, "", 0); err != nil || len(ids) != 0 {
		ev.t.Fatalf("wrapped keys left: %v, %v", ids, err)
	}
	for _, k := range []string{td.smtpKey, td.spareKey} {
		if ev.keyExists(tn, k) {
			ev.t.Fatal("tenant key not destroyed")
		}
	}
	for i, fx := range fxs {
		if !ev.gone(fx) {
			ev.t.Fatalf("transfer %d row kept", i)
		}
		if b := before[i]; b.DownloadTokenKeyID != "" && ev.keyExists(tn, b.DownloadTokenKeyID) {
			ev.t.Fatalf("transfer %d token key kept", i)
		}
		for _, f := range before[i].Files {
			if f.DEKKeyID != "" && ev.keyExists(tn, f.DEKKeyID) {
				ev.t.Fatalf("transfer %d file key kept", i)
			}
		}
	}
	// The event of populate is kept, and the erasure recorded once.
	if kept := ev.tenantAudit(tn.ID, ""); len(kept) != 2 {
		ev.t.Fatalf("audit events of the tenant: %d, want 2", len(kept))
	}
	ev.assertTenantDeletedAudit(tn)
}

// tenantAudit returns the audit events of tid with action (any when "").
func (ev *env) tenantAudit(tid tenant.ID, action string) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: action})
	if err != nil {
		ev.t.Fatal(err)
	}
	var out []store.AuditEvent
	for _, e := range page.Items {
		if e.TenantID == tid {
			out = append(out, e)
		}
	}
	return out
}

// assertTenantDeletedAudit checks that exactly one ActionTenantDeleted was
// recorded for tn, by SystemActor, with its name and FQDN and nothing else.
func (ev *env) assertTenantDeletedAudit(tn *tenant.Tenant) {
	ev.t.Helper()
	evs := ev.tenantAudit(tn.ID, string(ActionTenantDeleted))
	if len(evs) != 1 {
		ev.t.Fatalf("%s events: %d, want 1", ActionTenantDeleted, len(evs))
	}
	e := evs[0]
	if e.ActorKind != store.ActorSystem || e.Actor != SystemActor || e.IP.IsValid() ||
		e.ObjectKind != "tenant" || e.ObjectID != string(tn.ID) {
		ev.t.Fatalf("%s event = %+v", ActionTenantDeleted, e)
	}
	var details map[string]string
	if err := json.Unmarshal(e.Details, &details); err != nil {
		ev.t.Fatal(err)
	}
	if want := map[string]string{"name": tn.Name, "fqdn": tn.FQDN}; !maps.Equal(details, want) {
		ev.t.Fatalf("%s details = %v, want %v", ActionTenantDeleted, details, want)
	}
}

func TestEraseTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		fxs, before := ev.tenantFixtures(ev.a)
		td := ev.populate(ev.a)
		keepB := ev.available(ev.b, 2, false)
		tdB := ev.populate(ev.b)

		// Refused before the deletion started, without touching anything.
		if err := ev.s.EraseTenant(ctx, ev.a.ID); !errors.Is(err, ErrTenantNotDeleting) {
			t.Fatalf("EraseTenant(active) = %v, want ErrTenantNotDeleting", err)
		}
		ev.assertIntact(fxs[1])
		ev.startDeletion(ev.a)
		ev.s.purgeBatch = 1 // page through the ended transfers
		if err := ev.s.EraseTenant(ctx, ev.a.ID); err != nil {
			t.Fatalf("EraseTenant: %v\nlogs:\n%s", err, ev.logs.all())
		}
		ev.assertTenantErased(ev.a, fxs, before, td)
		if ev.logs.count("lifecycle: tenant erased tenant="+string(ev.a.ID)+" transfers=6 keys=2") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		// Idempotent: a tenant already gone is a success.
		if err := ev.s.EraseTenant(ctx, ev.a.ID); err != nil {
			t.Fatalf("second EraseTenant: %v", err)
		}
		// Isolation: the other tenant is untouched.
		ev.assertIntact(keepB)
		for _, k := range []string{tdB.smtpKey, tdB.spareKey} {
			if !ev.keyExists(ev.b, k) {
				t.Fatal("key of the other tenant destroyed")
			}
		}
		if !ev.exists(ev.b, "logo.png") {
			t.Fatal("asset of the other tenant removed")
		}
		if _, err := ev.db.Tenants().Get(ctx, ev.b.ID); err != nil {
			t.Fatalf("other tenant: %v", err)
		}
	})
}

func TestEraseTenantResumes(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		// Two more live transfers than the faults that leave one behind,
		// so that every fault finds a transfer to fail on.
		fxs, before := ev.tenantFixtures(ev.a)
		for range 6 {
			fx := ev.available(ev.a, 1, false)
			fxs, before = append(fxs, fx), append(before, ev.get(fx))
		}
		td := ev.populate(ev.a)
		keepB := ev.available(ev.b, 1, false)
		ev.startDeletion(ev.a)
		ev.s.keyBatch = 1 // one transaction per key
		for _, step := range []string{
			"getTenant", "transferIDs", "lock", "transfer", "remove", "removeAfter", "state", "finish",
			// lock again: on an ended transfer, the live ones being erased.
			"listEnded", "lock", "keyIDs", "destroyKeys", "destroy", "removeDir", "deleteTenant",
		} {
			ev.f.set(step, 1, nil)
			if err := ev.s.EraseTenant(ctx, ev.a.ID); !errors.Is(err, errFault) &&
				(err == nil || !strings.Contains(err.Error(), "left for the next run")) {
				t.Fatalf("EraseTenant with a fault on %s = %v", step, err)
			}
			if _, err := ev.db.Tenants().Get(ctx, ev.a.ID); err != nil {
				t.Fatalf("tenant gone after a fault on %s: %v", step, err)
			}
			if ev.f.called(step) == 0 {
				t.Fatalf("fault %s never reached", step)
			}
		}
		if err := ev.s.EraseTenant(ctx, ev.a.ID); err != nil {
			t.Fatalf("resumed EraseTenant: %v\nlogs:\n%s", err, ev.logs.all())
		}
		ev.assertTenantErased(ev.a, fxs, before, td)
		ev.assertIntact(keepB)
	})
}

// TestEraseTenantLateWrites checks that a directory recreated during the
// erasure (by a request that resolved the tenant before) is removed after
// the row, and that a failure of that second pass, or of the audit write,
// is logged without failing the erasure.
func TestEraseTenantLateWrites(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.available(ev.a, 1, false)
		ev.startDeletion(ev.a)
		// The directory reappears between the first pass and the row.
		ev.f.onCall("deleteTenant", func() { ev.write(ev.a, "late.part", t0) })
		if err := ev.s.EraseTenant(ctx, ev.a.ID); err != nil {
			t.Fatalf("EraseTenant: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(ev.root, string(ev.a.ID))); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("recreated tenant directory: %v, want gone", err)
		}
		ev.assertTenantDeletedAudit(ev.a)

		// The second pass fails: logged, the erasure completes and is
		// recorded; the audit write fails: logged, nothing recorded.
		ev.startDeletion(ev.b)
		ev.f.onCall("deleteTenant", func() { ev.f.set("removeDir", 1, nil) })
		ev.f.set("audit", 1, nil)
		if err := ev.s.EraseTenant(ctx, ev.b.ID); err != nil {
			t.Fatalf("EraseTenant with late failures: %v", err)
		}
		if _, err := ev.db.Tenants().Get(ctx, ev.b.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("tenant row: %v, want ErrNotFound", err)
		}
		if ev.logs.count("lifecycle: tenant directory left after the erasure tenant="+string(ev.b.ID)) != 1 ||
			ev.logs.count("lifecycle: audit write failed action=tenant.deleted tenant="+string(ev.b.ID)) != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		if n := len(ev.tenantAudit(ev.b.ID, string(ActionTenantDeleted))); n != 0 {
			t.Fatalf("%s events after a failed write: %d", ActionTenantDeleted, n)
		}
		// A tenant already gone records nothing more.
		if err := ev.s.EraseTenant(ctx, ev.a.ID); err != nil {
			t.Fatal(err)
		}
		ev.assertTenantDeletedAudit(ev.a)
	})
}

func TestEraseTenantCanceled(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.available(ev.a, 1, false)
	ev.available(ev.a, 1, false)
	ev.startDeletion(ev.a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ev.s.EraseTenant(ctx, ev.a.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("EraseTenant(canceled) = %v", err)
	}
	// Canceled while erasing the first transfer: the second is not started.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	ev.f.onCall("lock", cancel)
	if err := ev.s.EraseTenant(ctx, ev.a.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("EraseTenant canceled during the transfers = %v", err)
	}
	if got := ev.f.called("lock"); got != 1 {
		t.Fatalf("lock called %d times, want 1", got)
	}
	if err := ev.s.EraseTenant(context.Background(), ev.a.ID); err != nil {
		t.Fatalf("resumed EraseTenant: %v", err)
	}
}

func TestTenantDeletionsTask(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		fxs, before := ev.tenantFixtures(ev.a)
		td := ev.populate(ev.a)
		keepB := ev.available(ev.b, 1, false)
		ev.startDeletion(ev.a)

		// A failed listing, then a failed erasure: logged, LastRun unmoved.
		ev.f.set("deletingTenants", 1, nil)
		if err := ev.s.RunTask(ctx, TaskTenantDeletions); !errors.Is(err, errFault) {
			t.Fatalf("RunTask with a failed listing = %v", err)
		}
		ev.f.set("removeDir", 1, nil)
		if err := ev.s.RunTask(ctx, TaskTenantDeletions); !errors.Is(err, errFault) {
			t.Fatalf("RunTask with a failed erasure = %v", err)
		}
		if ev.logs.count("lifecycle: tenant erasure left for the next run tenant="+string(ev.a.ID)) != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		if !ev.s.LastRun(TaskTenantDeletions).IsZero() {
			t.Fatal("LastRun moved by a failed run")
		}
		// The next run completes the deletion.
		ev.runTask(TaskTenantDeletions)
		ev.assertTenantErased(ev.a, fxs, before, td)
		ev.assertIntact(keepB)
		if !ev.s.LastRun(TaskTenantDeletions).Equal(ev.clock.Now()) {
			t.Fatal("LastRun not recorded")
		}
		// Nothing left: a no-op.
		ev.runTask(TaskTenantDeletions)
	})
}

func TestTenantDeletionsCanceled(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.startDeletion(ev.a)
	ev.startDeletion(ev.b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ev.f.onCall("getTenant", cancel)
	if err := ev.s.RunTask(ctx, TaskTenantDeletions); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunTask canceled = %v", err)
	}
	if got := ev.f.called("getTenant"); got != 1 {
		t.Fatalf("tenantStatus called %d times, want 1 (the run stops)", got)
	}
	if ev.logs.count("left for the next run") != 0 {
		t.Fatalf("a canceled erasure was logged as failed:\n%s", ev.logs.all())
	}
}

func TestStoreRepoDestroyKeysInvalidTenant(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	r := storeRepo{db: ev.db, vault: ev.vault}
	if err := r.destroyKeys(context.Background(), "ten_bad", []string{"wk_x"}); err == nil {
		t.Fatal("destroyKeys accepted a malformed tenant")
	}
}
