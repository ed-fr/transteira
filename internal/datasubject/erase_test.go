package datasubject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// seeded holds the fixtures of the address in every role.
type seeded struct {
	sent, invited, recvShared, recvSole, recvEnded, recvScanning, unrelated, viaInvitation string
	invAsInvitee, invAsInviter                                                             string
	session, daveSession                                                                   []byte
}

// seed stores, in tn, carol in every role, plus data of others that must
// stay.
func (ev *env) seed(tn *tenant.Tenant) seeded {
	ev.t.Helper()
	var s seeded
	s.sent = ev.transfer(tn, carol, "", []string{dave}, stateAvailable)
	s.invAsInvitee = ev.invitation(tn, carol, alice)
	s.invited = ev.transfer(tn, carol, s.invAsInvitee, []string{alice}, stateScanning)
	s.recvShared = ev.transfer(tn, alice, "", []string{carol, dave}, stateAvailable)
	s.recvSole = ev.transfer(tn, alice, "", []string{carol}, stateAvailable)
	s.recvEnded = ev.transfer(tn, alice, "", []string{erin, carol}, stateDeleted)
	s.recvScanning = ev.transfer(tn, alice, "", []string{carol, dave}, stateScanning)
	s.unrelated = ev.transfer(tn, alice, "", []string{dave}, stateUploading)
	s.invAsInviter = ev.invitation(tn, dave, carol)
	s.viaInvitation = ev.transfer(tn, dave, s.invAsInviter, []string{carol, alice}, stateAvailable)
	s.session = ev.depositRows(tn, carol, "")
	ev.depositRows(tn, carol, s.invAsInvitee)
	s.daveSession = ev.depositRows(tn, dave, s.invAsInviter)
	ev.auditActor(tn, carol, 3)
	ev.auditActor(tn, dave, 2)
	return s
}

func TestEraseEveryRole(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		s := ev.seed(ev.a)
		ev.seed(ev.b)
		beforeB := ev.search(ev.b, carol)

		got := ev.search(ev.a, subjectInput)
		want := Summary{
			Email: carol, VerifiedAddress: true, TransfersAsSender: 2, TransfersAsRecipient: 5,
			Invitations: 2, AuditEvents: 3,
		}
		if got != want {
			t.Fatalf("Search before = %+v, want %+v", got, want)
		}

		rep := ev.erase(ev.a, subjectInput)
		wantRep := EraseReport{
			TransfersDeleted: 3, RecipientEntriesRemoved: 4, VerifiedAddressDeleted: true,
			InvitationsDeleted: 1, LogEntriesPseudonymised: 3,
		}
		if rep != wantRep {
			t.Fatalf("Erase = %+v, want %+v", rep, wantRep)
		}

		// Transfers.
		for name, trfID := range map[string]string{"sent": s.sent, "invited": s.invited, "sole": s.recvSole} {
			if ev.transferExists(ev.a, trfID) {
				t.Errorf("transfer %s still exists", name)
			}
		}
		for name, c := range map[string]struct {
			id   string
			want []string
		}{
			"shared": {s.recvShared, []string{dave}}, "ended": {s.recvEnded, []string{erin}},
			"scanning": {s.recvScanning, []string{dave}}, "unrelated": {s.unrelated, []string{dave}},
			"via invitation": {s.viaInvitation, []string{alice}},
		} {
			d, err := ev.db.Transfers().Get(ctx, ev.a.ID, c.id)
			if err != nil {
				t.Fatalf("transfer %s: %v", name, err)
			}
			if !slices.Equal(d.Recipients, c.want) {
				t.Errorf("transfer %s recipients = %v, want %v", name, d.Recipients, c.want)
			}
		}
		if holds, releases := ev.holder.counts(); holds != releases || holds < 4 {
			t.Errorf("holds = %d, releases = %d", holds, releases)
		}
		// The recipient removals hold for an edit, the sweeper for an
		// erasure.
		if !slices.Contains(ev.holder.intents, lifecycle.HoldForEdit) ||
			!slices.Contains(ev.holder.intents, lifecycle.HoldForErase) {
			t.Errorf("hold intents = %v", ev.holder.intents)
		}

		// Invitations: the invitee one is gone, the inviter one revoked
		// and pseudonymised.
		if _, err := ev.db.Invitations().Get(ctx, ev.a.ID, s.invAsInvitee); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("invitation as invitee: %v", err)
		}
		inv, err := ev.db.Invitations().Get(ctx, ev.a.ID, s.invAsInviter)
		if err != nil {
			t.Fatal(err)
		}
		pseudonym := inv.InvitedBy
		if !store.IsPseudonym(pseudonym) || inv.RevokedAt.IsZero() || inv.Email != dave {
			t.Errorf("invitation as inviter = %+v", inv)
		}

		// Deposit rows: carol's gone, dave's kept.
		if _, err := ev.db.DepositSessions().GetByTokenHash(ctx, ev.a.ID, s.session, testStart); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("carol session: %v", err)
		}
		if _, err := ev.db.DepositSessions().GetByTokenHash(ctx, ev.a.ID, s.daveSession, testStart); err != nil {
			t.Errorf("dave session: %v", err)
		}
		if n, err := ev.db.Challenges().CountSince(ctx, ev.a.ID, carol, testStart.AddDate(-1, 0, 0)); err != nil || n != 0 {
			t.Errorf("carol challenges = %d, %v", n, err)
		}
		if n, err := ev.db.Challenges().CountSince(ctx, ev.a.ID, dave, testStart.AddDate(-1, 0, 0)); err != nil || n != 1 {
			t.Errorf("dave challenges = %d, %v", n, err)
		}

		// Audit: one pseudonym for the whole erasure.
		var pseudonymised, daves int
		for _, a := range ev.auditEvents(ev.a.ID, "") {
			switch a.Actor {
			case pseudonym:
				pseudonymised++
			case dave:
				daves++
			case carol:
				t.Errorf("audit event still names the address: %+v", a)
			}
		}
		if pseudonymised != 3 || daves != 2 {
			t.Errorf("pseudonymised = %d, dave = %d", pseudonymised, daves)
		}
		erased := ev.auditEvents(ev.a.ID, audit.ActionDataSubjectErased)
		if len(erased) != 1 {
			t.Fatalf("erased events = %d", len(erased))
		}
		ee := erased[0]
		if ee.ObjectID != pseudonym || ee.ObjectKind != audit.ObjectDataSubject || ee.Actor != "root" ||
			ee.ActorKind != store.ActorAdmin || ee.IP != clientIP || strings.Contains(string(ee.Details), "@") {
			t.Errorf("erased event = %+v", ee)
		}
		var details map[string]any
		if err := json.Unmarshal(ee.Details, &details); err != nil {
			t.Fatal(err)
		}
		if details["transfersDeleted"] != 3.0 || details["recipientEntriesRemoved"] != 4.0 ||
			details["verifiedAddressDeleted"] != true || details["invitationsDeleted"] != 1.0 ||
			details["logEntriesPseudonymised"] != 3.0 || details["complete"] != true {
			t.Errorf("erased details = %v", details)
		}
		searched := ev.auditEvents(ev.a.ID, audit.ActionDataSubjectSearched)
		if len(searched) != 1 || !store.IsPseudonym(searched[0].ObjectID) || searched[0].ObjectID == pseudonym ||
			strings.Contains(string(searched[0].Details), "@") {
			t.Errorf("searched events = %+v", searched)
		}

		// Nothing left: the search and a second erasure report zeros.
		if got := ev.search(ev.a, carol); got != (Summary{Email: carol}) {
			t.Errorf("Search after = %+v", got)
		}
		if rep := ev.erase(ev.a, carol); rep != (EraseReport{}) {
			t.Errorf("second Erase = %+v", rep)
		}
		erased = ev.auditEvents(ev.a.ID, audit.ActionDataSubjectErased)
		if len(erased) != 2 || erased[0].ObjectID == erased[1].ObjectID {
			t.Errorf("pseudonyms of two erasures: %+v", erased)
		}

		// The other tenant is untouched.
		if got := ev.search(ev.b, carol); got != beforeB {
			t.Errorf("tenant B after = %+v, want %+v", got, beforeB)
		}
	})
}

func TestEraseResumesAfterInterruption(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.seed(ev.a)

		// A recipient removal fails after the first one.
		f := ev.faults("removeRecipient")
		f.after["removeRecipient"] = 1
		if _, err := ev.svc.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol); !errors.Is(err, errBoom) {
			t.Fatalf("Erase = %v, want boom", err)
		}
		erased := ev.auditEvents(ev.a.ID, audit.ActionDataSubjectErased)
		if len(erased) != 1 || !strings.Contains(string(erased[0].Details), `"complete":false`) ||
			!strings.Contains(string(erased[0].Details), `"transfersDeleted":2`) {
			t.Fatalf("interrupted erasure event = %+v", erased)
		}

		// The transfer erasure fails once.
		ev.svc.repo = f.repo
		ev.eraser.err = errBoom
		if _, err := ev.svc.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol); !errors.Is(err, errBoom) {
			t.Fatalf("Erase = %v, want boom", err)
		}

		rep := ev.erase(ev.a, carol)
		if rep.TransfersDeleted != 1 || rep.RecipientEntriesRemoved != 3 || rep.InvitationsDeleted != 1 ||
			rep.LogEntriesPseudonymised != 3 || rep.VerifiedAddressDeleted {
			t.Errorf("resumed Erase = %+v", rep)
		}
		if got := ev.search(ev.a, carol); got != (Summary{Email: carol}) {
			t.Errorf("Search after = %+v", got)
		}
	})
}

func TestEraseBusyTransfer(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.transfer(ev.a, carol, "", []string{dave}, stateAvailable)

		// Busy a few times: retried.
		ev.eraser.busy = BusyAttempts - 1
		if rep := ev.erase(ev.a, carol); rep.TransfersDeleted != 1 || ev.sleeps != BusyAttempts-1 {
			t.Fatalf("Erase = %+v, sleeps = %d", rep, ev.sleeps)
		}

		// Busy every time: ErrBusy, nothing lost, a new call completes.
		trfID := ev.transfer(ev.a, carol, "", []string{dave}, stateAvailable)
		ev.eraser.busy, ev.sleeps = BusyAttempts, 0
		_, err := ev.svc.Erase(ctx, ev.super, clientIP, ev.a.ID, carol)
		wantErr(t, "Erase busy", err, ErrBusy)
		if ev.sleeps != BusyAttempts-1 || !ev.transferExists(ev.a, trfID) {
			t.Fatalf("sleeps = %d, exists = %v", ev.sleeps, ev.transferExists(ev.a, trfID))
		}

		// The wait is interrupted.
		ev.eraser.busy = 1
		ev.svc.sleep = func(context.Context, time.Duration) error { return context.Canceled }
		_, err = ev.svc.Erase(ctx, ev.super, clientIP, ev.a.ID, carol)
		wantErr(t, "Erase canceled", err, context.Canceled)

		// A request canceled before an attempt starts none.
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		calls := ev.eraser.calls
		err = ev.svc.eraseTransfer(canceled, ev.a.ID, trfID, &EraseReport{})
		wantErr(t, "eraseTransfer canceled", err, context.Canceled)
		if ev.eraser.calls != calls || !ev.transferExists(ev.a, trfID) {
			t.Fatalf("calls = %d (was %d), exists = %v", ev.eraser.calls, calls, ev.transferExists(ev.a, trfID))
		}

		// A request canceled during an attempt does not stop it: the
		// eraser gets a context that is never canceled.
		live, stop := context.WithCancel(ctx)
		ev.eraser.before = func(ectx context.Context) {
			stop()
			if ectx.Err() != nil || ectx.Done() != nil {
				t.Error("the eraser context can be canceled")
			}
		}
		rep := &EraseReport{}
		if err := ev.svc.eraseTransfer(live, ev.a.ID, trfID, rep); err != nil || rep.TransfersDeleted != 1 {
			t.Fatalf("eraseTransfer canceled meanwhile = %+v, %v", rep, err)
		}
		ev.eraser.before = nil
		trfID = ev.transfer(ev.a, carol, "", []string{dave}, stateAvailable)

		if rep := ev.erase(ev.a, carol); rep.TransfersDeleted != 1 || ev.transferExists(ev.a, trfID) {
			t.Fatalf("Erase after busy = %+v", rep)
		}
	})
}

// TestEraseSoleRecipientUnderEditHold erases a transfer whose only
// recipient is the address while the edit hold is still held: a scan
// conclusion committed during that hold has its deferred mails canceled by
// the erasure hold, so none reaches the address. A shared transfer keeps
// its deferred mails for the remaining recipients.
func TestEraseSoleRecipientUnderEditHold(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.holder.conclude = true
		sole := ev.transfer(ev.a, alice, "", []string{carol}, stateScanning)
		rep := ev.erase(ev.a, carol)
		if rep.TransfersDeleted != 1 || ev.transferExists(ev.a, sole) {
			t.Fatalf("Erase = %+v, exists = %v", rep, ev.transferExists(ev.a, sole))
		}
		if n := ev.holder.deferredSends(); n != 0 {
			t.Fatalf("deferred sends after the erasure of a sole-recipient transfer = %d, want 0", n)
		}
		if holds, releases := ev.holder.counts(); holds != releases || holds != 2 {
			t.Fatalf("holds = %d, releases = %d", holds, releases)
		}
		if !slices.Equal(ev.holder.intents, []lifecycle.HoldIntent{lifecycle.HoldForEdit, lifecycle.HoldForErase}) {
			t.Fatalf("hold intents = %v", ev.holder.intents)
		}

		shared := ev.transfer(ev.a, alice, "", []string{carol, dave}, stateScanning)
		if rep := ev.erase(ev.a, carol); rep.RecipientEntriesRemoved != 1 || !ev.transferExists(ev.a, shared) {
			t.Fatalf("Erase shared = %+v", rep)
		}
		if n := ev.holder.deferredSends(); n != 1 {
			t.Fatalf("deferred sends after a recipient removal = %d, want 1", n)
		}
	})
}

func TestEraseInvitationConflict(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.faults()
		f.errs["eraseInvitations"] = store.ErrConflict
		_, err := ev.svc.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol)
		wantErr(t, "Erase", err, ErrBusy)
	})
}

func TestEraseTransferGoneMeanwhile(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		trfID := ev.transfer(ev.a, carol, "", []string{dave}, stateAvailable)
		ev.eraser.err = lifecycleNotFound(trfID)
		if rep := ev.erase(ev.a, carol); rep.TransfersDeleted != 0 {
			t.Fatalf("Erase = %+v", rep)
		}
	})
}

func TestEraseStepFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.seed(ev.a)
		for _, m := range []string{
			"deleteDepositRows", "deleteVerified", "senderTransfers", "inviteeInvitations", "invitationTransfers",
			"recipientTransfers", "removeRecipient", "eraseInvitations", "pseudonymiseAudit",
		} {
			ev.faults(m)
			_, err := ev.svc.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol)
			wantErr(t, m, err, errBoom)
		}

		// The antivirus hold fails.
		ev.faults()
		ev.transfer(ev.a, alice, "", []string{carol, dave}, stateAvailable)
		ev.holder.err = errBoom
		_, err := ev.svc.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol)
		wantErr(t, "hold", err, errBoom)

		// Scrub and audit failures are logged, never returned.
		f := ev.faults("audit")
		f.errs["scrub"] = store.ErrScrubBusy
		ev.erase(ev.a, carol)
		f.errs["scrub"] = errBoom
		ev.erase(ev.a, carol)
		logs := ev.logs.String()
		for _, want := range []string{"audit write failed", "may remain in the database WAL", "scrub of the deleted data failed"} {
			if !strings.Contains(logs, want) {
				t.Errorf("logs miss %q:\n%s", want, logs)
			}
		}
	})
}

// lifecycleNotFound is the error of the sweeper for a transfer gone.
func lifecycleNotFound(trfID string) error {
	return fmt.Errorf("%w: %s", lifecycle.ErrNotFound, trfID)
}

func TestEraseTransferOfInvitationFromAnotherSender(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		invID := ev.invitation(ev.a, carol, alice)
		trfID := ev.transfer(ev.a, dave, invID, []string{alice}, stateAvailable)
		if rep := ev.erase(ev.a, carol); rep.TransfersDeleted != 1 || rep.InvitationsDeleted != 1 || ev.transferExists(ev.a, trfID) {
			t.Fatalf("Erase = %+v", rep)
		}
	})
}
