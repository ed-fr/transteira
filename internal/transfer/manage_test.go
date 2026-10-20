package transfer

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestEligibility(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())
		ev.complete(t, d.ID, "")
		dx := ev.mustCreate(t, ev.external(), request())

		outside := internalSender()
		outside.ClientIP = externalIP
		otherDomain := internalSender()
		otherDomain.Email = "alice@elsewhere.example.org"
		missing := ev.external()
		missing.InvitationID = id.New(id.Invitation)
		mismatch := ev.external()
		mismatch.InvitationID = ev.invite(t, ev.a, "zoe@partner.example.org", alice).ID

		check := func(name string, sender Sender, trfID, reason string) {
			t.Helper()
			before := len(ev.seclog.reasons())
			if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s: Create err = %v", name, err)
			}
			if _, err := ev.svc.Finalize(ctx, ev.a, sender, trfID); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s: Finalize err = %v", name, err)
			}
			got := ev.seclog.reasons()[before:]
			if !reflect.DeepEqual(got, []string{reason, reason}) {
				t.Errorf("%s: reasons = %v, want %s twice", name, got, reason)
			}
		}
		check("outside the IP ranges", outside, d.ID, securitylog.ReasonIP)
		check("other domain", otherDomain, d.ID, securitylog.ReasonDomain)
		check("unknown invitation", missing, dx.ID, securitylog.ReasonInvitation)
		check("invitation of another address", mismatch, dx.ID, securitylog.ReasonInvitation)

		ev.seclog.mu.Lock()
		last := ev.seclog.events[len(ev.seclog.events)-1]
		ev.seclog.mu.Unlock()
		if last.Tenant != hostA || last.IP != externalIP {
			t.Errorf("event = %+v", last)
		}

		// Revoked after the session started.
		if err := ev.db.Invitations().Revoke(ctx, ev.a.ID, ev.inv.ID, ev.clock.Now()); err != nil {
			t.Fatal(err)
		}
		check("revoked invitation", ev.external(), dx.ID, securitylog.ReasonInvitation)

		// Blocklisted after the session started: the address, then the domain.
		ev.block(t, ev.a, store.BlockEmail, alice)
		check("blocklisted address", internalSender(), d.ID, securitylog.ReasonBlocklist)
		ev.block(t, ev.a, store.BlockDomain, "partner.example.org")
		other := ev.external()
		other.InvitationID = mismatch.InvitationID
		other.Email = "zoe@partner.example.org"
		check("blocklisted domain", other, dx.ID, securitylog.ReasonBlocklist)

		// Tenant B is not affected by the blocklist of A.
		if _, err := ev.svc.Create(ctx, ev.b, internalSender(), request(), ""); err != nil {
			t.Errorf("B: %v", err)
		}
	})
}

func TestMalformedSender(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	bad := []Sender{
		{Depositor: store.Depositor{Email: "not an address", Kind: store.DepositorInternal}},
		{Depositor: store.Depositor{Email: alice, Kind: "robot"}},
		{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternal, InvitationID: ev.inv.ID}},
		{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal}},
	}
	for _, s := range bad {
		if _, err := ev.svc.Create(ctx, ev.a, s, request(), ""); err == nil || errors.Is(err, ErrForbidden) {
			t.Errorf("Create(%+v): err = %v", s, err)
		}
		if _, err := ev.svc.Get(ctx, ev.a, s, id.New(id.Transfer)); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%+v): err = %v", s, err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, s, id.New(id.Transfer)); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Cancel(%+v): err = %v", s, err)
		}
	}
	if len(ev.seclog.reasons()) != 0 {
		t.Error("a wiring error was logged as a refusal")
	}
}

func TestSecurityLogFailure(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.seclog.err = errFault
	s := internalSender()
	s.ClientIP = externalIP
	if _, err := ev.svc.Create(context.Background(), ev.a, s, request(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("err = %v", err)
	}
}

func TestGet(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())
		ev.clock.Advance(time.Hour)
		activity := testStart.Add(time.Hour)
		ev.uploads.activity = activity
		ev.uploads.offsets = map[string]int64{d.Files[0].ID: 64, d.Files[1].ID: 128}
		ev.uploads.seenAct = nil
		got, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Files[0].UploadOffset != 64 || got.Files[1].UploadOffset != 128 ||
			!got.UploadExpiresAt.Equal(activity.Add(uploadTTL)) || got.Files[0].UploadID == "" {
			t.Errorf("Get = %+v", got)
		}
		// The transfer activity is read once and passed to every Offset.
		if len(ev.uploads.seenAct) != 2 || !ev.uploads.seenAct[0].Equal(activity) || !ev.uploads.seenAct[1].Equal(activity) {
			t.Errorf("Offset activities = %v", ev.uploads.seenAct)
		}
		ev.uploads.actErr = errFault
		if _, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("activity failure: err = %v", err)
		}
		ev.uploads.actErr = nil
		// A completed file reports its size without asking the engine.
		d2 := ev.mustCreate(t, internalSender(), request())
		ev.complete(t, d.ID, "")
		ev.uploads.offsetErr = errFault
		got, err = ev.svc.Get(ctx, ev.a, internalSender(), d.ID)
		if err != nil || got.Files[0].UploadOffset != 100 || got.Files[1].UploadOffset != 200 || got.Files[0].SHA256 == "" {
			t.Errorf("completed: %+v, %v", got, err)
		}
		if _, err := ev.svc.Get(ctx, ev.a, internalSender(), d2.ID); !errors.Is(err, errFault) {
			t.Errorf("offset failure: err = %v", err)
		}
		ev.uploads.offsetErr = nil
		// After the finalization: no upload URL nor upload expiry.
		fin, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err = ev.svc.Get(ctx, ev.a, internalSender(), d.ID)
		if err != nil || !reflect.DeepEqual(got, fin) {
			t.Errorf("Get after Finalize = %+v, %v; want %+v", got, err, fin)
		}
		if got.Files[0].UploadID != "" || !got.UploadExpiresAt.IsZero() {
			t.Errorf("finalized = %+v", got)
		}
		// A store failure is internal.
		ev.faults().fail["transfer"] = errFault
		if _, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("store failure: err = %v", err)
		}
	})
}

// TestIsolation checks that a transfer is invisible to another tenant and
// to another sender of the same tenant, for every operation.
func TestIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())
		dx := ev.mustCreate(t, ev.external(), request())
		ev.complete(t, d.ID, "")
		ev.complete(t, dx.ID, "")
		carolS := internalSender()
		carolS.Email = carol
		otherInv := ev.external()
		otherInv.InvitationID = ev.invite(t, ev.a, bob, carol).ID
		cases := []struct {
			name   string
			sender Sender
			trfID  string
			tn     string
		}{
			{"other tenant", internalSender(), d.ID, "b"},
			{"other sender", carolS, d.ID, "a"},
			{"external on internal", ev.external(), d.ID, "a"},
			{"other invitation", otherInv, dx.ID, "a"},
			{"internal on external", internalSender(), dx.ID, "a"},
			{"unknown", internalSender(), id.New(id.Transfer), "a"},
			{"malformed", internalSender(), "trf_nope", "a"},
		}
		for _, tc := range cases {
			tn := ev.a
			if tc.tn == "b" {
				tn = ev.b
			}
			if _, err := ev.svc.Get(ctx, tn, tc.sender, tc.trfID); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: Get err = %v", tc.name, err)
			}
			if _, err := ev.svc.Finalize(ctx, tn, tc.sender, tc.trfID); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: Finalize err = %v", tc.name, err)
			}
			if err := ev.svc.Cancel(ctx, tn, tc.sender, tc.trfID); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: Cancel err = %v", tc.name, err)
			}
		}
		if ops := ev.uploads.opsSnapshot(); len(ops) != 0 {
			t.Errorf("engine operations = %v", ops)
		}
		for _, trfID := range []string{d.ID, dx.ID} {
			got, err := ev.db.Transfers().Get(ctx, ev.a.ID, trfID)
			if err != nil || got.Status != store.TransferUploading {
				t.Errorf("transfer %s changed: %+v, %v", trfID, got.Transfer, err)
			}
		}
	})
}

func TestCancel(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		want := []string{"lock", "remove:" + d.Files[0].ID, "remove:" + d.Files[1].ID, "unlock"}
		if got := ev.uploads.opsSnapshot(); !reflect.DeepEqual(got, want) {
			t.Errorf("ops = %v, want %v", got, want)
		}
		if _, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("transfer remains: %v", err)
		}
		for _, f := range stored.Files {
			if _, err := ev.db.WrappedKeys().Get(ctx, ev.a.ID, f.DEKKeyID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("key %s remains: %v", f.DEKKeyID, err)
			}
		}
		if ev.usedBytes(t, ev.a) != 0 {
			t.Error("quota not released")
		}
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("second Cancel: %v", err)
		}
	})
}

func TestCancelErrors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())

		ev.uploads.lockErr = busy
		err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID)
		if !errors.Is(err, ErrBusy) || !errors.Is(err, ErrConflict) {
			t.Errorf("busy: err = %v", err)
		}
		ev.uploads.lockErr = errFault
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) || errors.Is(err, ErrBusy) {
			t.Errorf("lock failure: err = %v", err)
		}
		ev.uploads.lockErr = nil

		// A failed removal leaves the transfer without keys: Finalize
		// refuses it, and canceling again finishes.
		ev.complete(t, d.ID, "")
		ev.uploads.removeErr = errFault
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("remove failure: err = %v", err)
		}
		if ev.uploads.locked != 0 {
			t.Error("locks not released")
		}
		ev.uploads.removeErr = nil
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrConflict) {
			t.Errorf("Finalize after a partial cancel: err = %v", err)
		}

		r := ev.faults()
		r.fail["deleteTransfer"] = errFault
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("delete failure: err = %v", err)
		}
		r.fail["deleteTransfer"] = store.ErrNotFound
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleted meanwhile: err = %v", err)
		}
		delete(r.fail, "deleteTransfer")
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); err != nil {
			t.Errorf("retry: %v", err)
		}

		// A finalized transfer cannot be canceled by its sender.
		d = ev.mustCreate(t, internalSender(), request())
		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrConflict) {
			t.Errorf("scanning: err = %v", err)
		}

		// Finalized by a concurrent request between the read and the lock.
		d = ev.mustCreate(t, internalSender(), request())
		ev.complete(t, d.ID, "")
		ev.uploads.onLock = func() { ev.finalizeDirect(t, d.ID) }
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrConflict) {
			t.Errorf("finalized under the lock: err = %v", err)
		}
		// Store failure on the second read.
		d = ev.mustCreate(t, internalSender(), request())
		r.fail["transfer"], r.skip["transfer"] = errFault, 1
		if err := ev.svc.Cancel(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("second read: err = %v", err)
		}
		if ev.uploads.locked != 0 {
			t.Error("locks not released")
		}
	})
}

// finalizeDirect finalizes a transfer of A through the store.
func (ev *env) finalizeDirect(t *testing.T, trfID string) {
	t.Helper()
	s, err := ev.db.Scoped(ev.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		return ev.db.Transfers().FinalizeTx(context.Background(), tx, trfID, ev.clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinalize(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		req := request()
		req.Files = append(req.Files, FileDeclaration{Name: "a.txt"}, FileDeclaration{Name: "b.txt"}) // same SHA-256
		d := ev.mustCreate(t, internalSender(), req)

		_, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
		var fe *FilesError
		if !errors.As(err, &fe) || !errors.Is(err, ErrIncomplete) ||
			!reflect.DeepEqual(fe.FileIDs, []string{d.Files[0].ID, d.Files[1].ID}) {
			t.Fatalf("incomplete: err = %v", err)
		}
		ev.complete(t, d.ID, "")
		ev.clock.Advance(time.Hour)
		now := ev.clock.Now()
		got, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		if got.Status != store.TransferScanning || !got.FinalizedAt.Equal(now) ||
			!got.ExpiresAt.Equal(now.Add(7*24*time.Hour)) || !got.UploadExpiresAt.IsZero() {
			t.Errorf("finalized = %+v", got)
		}
		for _, f := range got.Files {
			if f.UploadID != "" || f.SHA256 == "" {
				t.Errorf("file = %+v", f)
			}
		}
		ev.mu.Lock()
		finalized := slices.Clone(ev.finalized)
		ev.mu.Unlock()
		if !slices.Equal(finalized, []string{string(ev.a.ID) + "/" + d.ID}) {
			t.Errorf("OnFinalized calls = %v", finalized)
		}
		if ops := ev.uploads.opsSnapshot(); !slices.Equal(ops[len(ops)-2:], []string{"lock", "unlock"}) {
			t.Errorf("ops = %v", ops)
		}
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrConflict) {
			t.Errorf("second Finalize: err = %v", err)
		}
	})
}

func TestFinalizeErrors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()

		// Checksum mismatch.
		req := request()
		req.Files[1].ExpectedSHA256 = emptySHA
		req.Files = append(req.Files, FileDeclaration{Name: "e", ExpectedSHA256: emptySHA})
		d := ev.mustCreate(t, internalSender(), req)
		ev.complete(t, d.ID, "")
		_, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
		var fe *FilesError
		if !errors.As(err, &fe) || !errors.Is(err, ErrChecksumMismatch) || !reflect.DeepEqual(fe.FileIDs, []string{d.Files[1].ID}) {
			t.Errorf("mismatch: err = %v", err)
		}

		// Blocklisted fingerprint (T-27).
		d = ev.mustCreate(t, internalSender(), request())
		blockedSum := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		ev.complete(t, d.ID, blockedSum)
		ev.block(t, ev.a, store.BlockSHA256, blockedSum)
		before := len(ev.seclog.reasons())
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrBlockedFile) {
			t.Errorf("blocked: err = %v", err)
		}
		if got := ev.seclog.reasons()[before:]; !reflect.DeepEqual(got, []string{securitylog.ReasonBlocklist}) {
			t.Errorf("reasons = %v", got)
		}
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || stored.Status != store.TransferUploading {
			t.Errorf("blocked transfer = %+v, %v", stored.Transfer, err)
		}

		// Busy and lock failures.
		d = ev.mustCreate(t, internalSender(), request())
		ev.complete(t, d.ID, "")
		ev.uploads.lockErr = busy
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrBusy) {
			t.Errorf("busy: err = %v", err)
		}
		ev.uploads.lockErr = nil

		// No file left (every upload terminated).
		empty := ev.mustCreate(t, internalSender(), request())
		ev.dropFiles(t, empty.ID)
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), empty.ID); !errors.Is(err, ErrConflict) {
			t.Errorf("no file: err = %v", err)
		}

		// Store failures.
		r := ev.faults()
		r.fail["blocked"], r.skip["blocked"] = errFault, 1
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("blocklist failure: err = %v", err)
		}
		delete(r.fail, "blocked")
		for _, fault := range []error{store.ErrConflict, store.ErrNotFound, errFault} {
			r.fail["finalize"] = fault
			_, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
			want := map[error]error{store.ErrConflict: ErrConflict, store.ErrNotFound: ErrNotFound, errFault: errFault}[fault]
			if !errors.Is(err, want) {
				t.Errorf("finalize %v: err = %v", fault, err)
			}
		}
		delete(r.fail, "finalize")
		r.fail["transfer"], r.skip["transfer"] = errFault, 2
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
			t.Errorf("read back: err = %v", err)
		}
	})
}

// dropFiles deletes every file of a transfer of A, as tus terminations do.
func (ev *env) dropFiles(t *testing.T, trfID string) {
	t.Helper()
	ctx := context.Background()
	d, err := ev.db.Transfers().Get(ctx, ev.a.ID, trfID)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ev.db.Scoped(ev.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		for _, f := range d.Files {
			if err := ev.vault.DestroyTx(ctx, tx, f.DEKKeyID); err != nil {
				return err
			}
			if err := ev.db.TransferFiles().DeleteTx(ctx, tx, f.ID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
