package transfer

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// remoteSender returns alice of A depositing from outside the ranges.
func remoteSender() Sender {
	return Sender{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternalRemote}, ClientIP: externalIP}
}

// allowRemote turns the deposit from outside of tn on or off in the
// database. The in-memory tn keeps the value it had, so that the tests show
// the service reads the current one.
func (ev *env) allowRemote(t *testing.T, tn *tenant.Tenant, on bool) {
	t.Helper()
	c := tn.Clone()
	c.AllowRemoteInternalDeposit = on
	if _, err := ev.db.Tenants().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// verify records email as verified in tn, from inside when internal.
func (ev *env) verify(t *testing.T, tn *tenant.Tenant, email string, internal bool) {
	t.Helper()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	v := store.VerifiedAddress{Email: email, FirstVerifiedAt: ev.clock.Now(), FirstVerifiedIP: externalIP}
	if internal {
		v.FirstVerifiedIP, v.InternalVerifiedAt, v.InternalVerifiedIP = internalIP, ev.clock.Now(), internalIP
	}
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		_, err := ev.db.VerifiedAddresses().UpsertTx(context.Background(), tx, v)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// remoteEnv returns an env whose tenant A allows the deposit from outside
// and where alice was verified from inside.
func remoteEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ev := newEnv(t, e)
	ev.allowRemote(t, ev.a, true)
	ev.a.AllowRemoteInternalDeposit = true
	ev.verify(t, ev.a, alice, true)
	return ev
}

func TestRemoteSender(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := remoteEnv(t, e)
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		sender := remoteSender()

		// Created with free recipients, kept as a remote transfer.
		d := ev.mustCreate(t, sender, request())
		if !reflect.DeepEqual(d.Recipients, []string{dave}) || d.SenderEmail != alice {
			t.Errorf("details = %+v", d)
		}
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || stored.SenderKind != store.DepositorInternalRemote {
			t.Fatalf("stored kind = %q, %v", stored.SenderKind, err)
		}
		// Only a remote session of the same address owns it.
		if _, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get by the internal session: %v", err)
		}
		if _, err := ev.svc.Get(ctx, ev.a, sender, d.ID); err != nil {
			t.Errorf("Get: %v", err)
		}
		// Finalized from outside.
		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		// A remote session that moved inside keeps its kind and still works.
		inside := sender
		inside.ClientIP = internalIP
		x := ev.mustCreate(t, inside, request())
		if err := ev.svc.Cancel(ctx, ev.a, sender, x.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		if n := len(ev.seclog.reasons()); n != 0 {
			t.Errorf("%d refusals logged", n)
		}

		events, _, errs := h.audit.snapshot()
		if len(errs) != 0 || len(events) != 4 {
			t.Fatalf("events = %+v, errors %v", events, errs)
		}
		wantEvent(t, events[0], audit.ActionTransferCreated, alice, externalIP, d.ID, map[string]any{
			"fileCount": 2, "totalBytes": int64(300), "origin": "internal", "remote": true, "confidentialityLevel": "internal",
		})
		wantEvent(t, events[1], audit.ActionTransferFinalized, alice, externalIP, d.ID,
			map[string]any{"fileCount": 2, "totalBytes": int64(300)})
		wantEvent(t, events[2], audit.ActionTransferCreated, alice, internalIP, x.ID, map[string]any{
			"fileCount": 2, "totalBytes": int64(300), "origin": "internal", "remote": true, "confidentialityLevel": "internal",
		})
		wantEvent(t, events[3], audit.ActionTransferDeleted, alice, externalIP, x.ID, map[string]any{"by": "sender"})

		// An internal transfer has no remote flag.
		y := ev.mustCreate(t, internalSender(), request())
		events, _, _ = h.audit.snapshot()
		wantEvent(t, events[4], audit.ActionTransferCreated, alice, internalIP, y.ID, map[string]any{
			"fileCount": 2, "totalBytes": int64(300), "origin": "internal", "confidentialityLevel": "internal",
		})
	})
}

func TestRemoteEligibility(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := remoteEnv(t, e)
		d := ev.mustCreate(t, remoteSender(), request())
		ev.complete(t, d.ID, "")

		check := func(name string, sender Sender, reason string) {
			t.Helper()
			before := len(ev.seclog.reasons())
			if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s: Create err = %v", name, err)
			}
			if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s: Finalize err = %v", name, err)
			}
			if got := ev.seclog.reasons()[before:]; !reflect.DeepEqual(got, []string{reason, reason}) {
				t.Errorf("%s: reasons = %v, want %s twice", name, got, reason)
			}
		}
		with := func(email string) Sender {
			s := remoteSender()
			s.Email = email
			return s
		}

		// An internal session used from outside is refused, even though the
		// remote rule holds for its address.
		outside := internalSender()
		outside.ClientIP = externalIP
		check("internal session from outside", outside, securitylog.ReasonIP)
		// A remote session without a client IP fails closed.
		noIP := remoteSender()
		noIP.ClientIP = netip.Addr{}
		check("no client ip", noIP, securitylog.ReasonIP)

		// Verified, but never from inside.
		ev.verify(t, ev.a, carol, false)
		check("never verified from inside", with(carol), securitylog.ReasonIP)
		check("never verified", with("zoe@entity-a.example.com"), securitylog.ReasonIP)
		// Verified from inside, but outside the internal domains.
		ev.verify(t, ev.a, "alice@elsewhere.example.org", true)
		check("other domain", with("alice@elsewhere.example.org"), securitylog.ReasonDomain)
		// Only tenant A allows it.
		ev.verify(t, ev.b, alice, true)
		if _, err := ev.svc.Create(ctx, ev.b, remoteSender(), request(), ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("B: %v", err)
		}

		// The option turned off meanwhile (the in-memory tenant still says on).
		ev.allowRemote(t, ev.a, false)
		check("option turned off", remoteSender(), securitylog.ReasonIP)
		ev.allowRemote(t, ev.a, true)
		if _, err := ev.svc.Finalize(ctx, ev.a, remoteSender(), d.ID); err != nil {
			t.Fatalf("Finalize once allowed again: %v", err)
		}

		// Blocklisted.
		ev.block(t, ev.a, store.BlockEmail, carol)
		check("blocklisted", with(carol), securitylog.ReasonBlocklist)

		// Erased (GDPR) meanwhile.
		if _, err := ev.db.VerifiedAddresses().Delete(ctx, ev.a.ID, alice); err != nil {
			t.Fatal(err)
		}
		check("erased address", remoteSender(), securitylog.ReasonIP)

		// Expired: unused for longer than the retention.
		ev.verify(t, ev.a, alice, true)
		if _, err := ev.svc.Create(ctx, ev.a, remoteSender(), request(), ""); err != nil {
			t.Fatalf("Create once verified again: %v", err)
		}
		ev.clock.Advance(time.Duration(store.VerifiedRetentionMonths+1) * 31 * 24 * time.Hour)
		check("expired address", remoteSender(), securitylog.ReasonIP)
	})
}

func TestRemoteFaults(t *testing.T) {
	ev := remoteEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	f := ev.faults()

	f.fail["tenant"] = errFault
	if _, err := ev.svc.Create(ctx, ev.a, remoteSender(), request(), ""); !errors.Is(err, errFault) {
		t.Errorf("tenant fault: %v", err)
	}
	// A tenant deleted meanwhile: refused like a rule that no longer holds.
	f.fail["tenant"] = store.ErrNotFound
	if _, err := ev.svc.Create(ctx, ev.a, remoteSender(), request(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("tenant gone: %v", err)
	}
	delete(f.fail, "tenant")
	f.fail["verifiedAddress"] = errFault
	if _, err := ev.svc.Create(ctx, ev.a, remoteSender(), request(), ""); !errors.Is(err, errFault) || errors.Is(err, ErrForbidden) {
		t.Errorf("verified address fault: %v", err)
	}
	if got := ev.seclog.reasons(); !reflect.DeepEqual(got, []string{securitylog.ReasonIP}) {
		t.Errorf("reasons = %v", got)
	}
}

func TestRemoteMalformed(t *testing.T) {
	ev := remoteEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	bad := []Sender{
		// A remote sender has no invitation.
		{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternalRemote, InvitationID: ev.inv.ID}},
		// An API token is never remote.
		{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternalRemote, APITokenID: id.New(id.APIToken)}},
	}
	for _, s := range bad {
		if _, err := ev.svc.Create(ctx, ev.a, s, request(), ""); err == nil || errors.Is(err, ErrForbidden) {
			t.Errorf("Create(%+v): err = %v", s, err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, s, id.New(id.Transfer)); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Cancel(%+v): err = %v", s, err)
		}
	}
}

func TestRemotePolicies(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := remoteEnv(t, e)
		sender := remoteSender()

		// The recipients are validated like an internal sender's.
		req := request()
		req.Recipients = nil
		var ve *ValidationError
		if _, err := ev.svc.Create(ctx, ev.a, sender, req, ""); !errors.As(err, &ve) || ve.Fields[0].Pointer != FieldRecipients {
			t.Errorf("no recipient: %v", err)
		}
		// The rules of a level apply.
		ev.setLevels(t, ev.a, strictLevels())
		req = request()
		req.ConfidentialityLevel = "secret"
		_, err := ev.svc.Create(ctx, ev.a, sender, req, "")
		if fields := ruleFields(t, err, ErrConfidentialityRule); len(fields) == 0 {
			t.Error("no broken rule")
		}
		// The recipient domain rules apply, audited with the internal origin.
		h := ev.withHooks(&auditSpy{})
		ev.setRecipientRules(t, ev.a, nil, []string{"customer.example.net"})
		_, err = ev.svc.Create(ctx, ev.a, sender, request(), "")
		if fields := ruleFields(t, err, ErrRecipientDomainRefused); len(fields) != 1 {
			t.Errorf("fields = %+v", fields)
		}
		events, _, _ := h.audit.snapshot()
		if len(events) != 1 || events[0].Action != audit.ActionTransferRecipientRefused || events[0].Details["origin"] != "internal" {
			t.Errorf("events = %+v", events)
		}
		if n := ev.transferCount(t, ev.a); n != 0 {
			t.Errorf("%d transfers created", n)
		}
	})
}
