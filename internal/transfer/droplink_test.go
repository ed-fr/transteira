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

// dropLink creates an enabled drop link of tn to carol and alice, valid 7
// days, at the level "open" of strictLevels.
func (ev *env) dropLink(t *testing.T, tn *tenant.Tenant) store.DropLink {
	t.Helper()
	tok, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	l, err := ev.db.DropLinks().Create(context.Background(), tn.ID, store.DropLink{
		ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: "Invoices",
		Recipients: []string{carol, alice}, ValidityDays: 7, ConfidentialityLevel: "open", Enabled: true, CreatedBy: "adm_1",
	})
	if err != nil {
		t.Fatalf("create drop link: %v", err)
	}
	return l
}

// dropSender returns bob depositing through l (a link of A) in a new
// deposit session opened now.
func (ev *env) dropSender(t *testing.T, l store.DropLink) Sender {
	t.Helper()
	tok, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	now := ev.clock.Now()
	s := store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: id.HashToken(tok), Email: bob, Kind: store.DepositorDropLink,
		DropLinkID: l.ID, CreatedAt: now, ExpiresAt: now.Add(4 * time.Hour),
	}
	if err := ev.db.DepositSessions().Create(context.Background(), ev.a.ID, s); err != nil {
		t.Fatalf("create drop link session: %v", err)
	}
	return Sender{
		Depositor: store.Depositor{Email: bob, Kind: store.DepositorDropLink, DropLinkID: l.ID},
		ClientIP:  externalIP,
		SessionID: s.ID,
	}
}

// dropRequest is a drop link request: recipients omitted, the validity of
// the link.
func dropRequest() CreateRequest {
	req := request()
	req.Recipients = nil
	return req
}

// TestCreateDropLink deposits through a drop link: the recipients, the
// validity and the level of the link are imposed, the transfer records the
// link and is audited with origin drop_link; the session deposits once.
func TestCreateDropLink(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.setLevels(t, ev.a, strictLevels())
		spy := &auditSpy{writer: audit.New(ev.db)}
		ev.withHooks(spy)
		l := ev.dropLink(t, ev.a)
		sender := ev.dropSender(t, l)

		d, err := ev.svc.Create(ctx, ev.a, sender, dropRequest(), "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// The recipients stay hidden from the depositor (T-311).
		if len(d.Recipients) != 0 || len(d.RecipientTracking) != 0 || d.DropLinkLabel != l.Label || d.ExpiryDays != 7 ||
			d.ConfidentialityLevel != "open" || d.LinkOnly {
			t.Errorf("drop link transfer = %+v", d)
		}
		got, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || got.DropLinkID != l.ID || got.SenderKind != store.DepositorDropLink || got.SenderEmail != bob ||
			!reflect.DeepEqual(got.Recipients, l.Recipients) {
			t.Fatalf("stored = %+v, %v", got.Transfer, err)
		}
		events, _, errs := spy.snapshot()
		if len(errs) != 0 || len(events) != 1 || events[0].Details["origin"] != originDropLink ||
			events[0].Details["dropLinkId"] != l.ID {
			t.Errorf("audit = %+v %v", events, errs)
		}
		// The sender owns it: read and finalize.
		if _, err := ev.svc.Get(ctx, ev.a, sender, d.ID); err != nil {
			t.Errorf("Get: %v", err)
		}
		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); err != nil {
			t.Errorf("Finalize: %v", err)
		}
		// The same session deposits once.
		if _, err := ev.svc.Create(ctx, ev.a, sender, dropRequest(), ""); !errors.Is(err, ErrDropLinkUsed) || !errors.Is(err, ErrForbidden) {
			t.Errorf("second deposit: %v", err)
		}
		// A new session deposits again, naming the level of the link.
		ev.clock.Advance(time.Minute)
		next := ev.dropSender(t, l)
		req := dropRequest()
		req.ConfidentialityLevel = "open"
		if _, err := ev.svc.Create(ctx, ev.a, next, req, "k1"); err != nil {
			t.Fatalf("new session: %v", err)
		}
		// Its replay with the same key returns the same transfer.
		again, err := ev.svc.Create(ctx, ev.a, next, req, "k1")
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		// Canceling the transfer does not free the session (T-310).
		if err := ev.svc.Cancel(ctx, ev.a, next, again.ID); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if _, err := ev.svc.Create(ctx, ev.a, next, dropRequest(), ""); !errors.Is(err, ErrDropLinkUsed) {
			t.Errorf("deposit after cancel: %v", err)
		}
		// Another link of the same session is not owned.
		other := ev.dropLink(t, ev.a)
		if _, err := ev.svc.Get(ctx, ev.a, ev.dropSender(t, other), d.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get by another link: %v", err)
		}
	})
}

// TestCreateDropLinkRefusals covers the mismatches with the link, the
// link-only option, a link no longer usable and the isolation.
func TestCreateDropLinkRefusals(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ev.setLevels(t, ev.a, strictLevels())
	ev.allowLinkOnly(t, ev.a, true)
	l := ev.dropLink(t, ev.a)
	sender := ev.dropSender(t, l)

	req := dropRequest()
	req.Recipients, req.ExpiryDays, req.ConfidentialityLevel = []string{carol}, 1, "secret"
	_, err := ev.svc.Create(ctx, ev.a, sender, req, "")
	wantFields(t, err, []FieldError{
		{Pointer: FieldRecipients, Code: CodeNotAllowed},
		{Pointer: FieldExpiryDays, Code: CodeNotAllowed, Allowed: []int{7}},
		{Pointer: FieldConfidentialityLevel, Code: CodeNotAllowed},
	})
	// Any recipient list is refused the same way, whatever its values:
	// the exact recipients of the link, a malformed address (no oracle).
	for _, rcpts := range [][]string{{carol, alice}, {carol, "Carol <x@y.example>"}} {
		req = dropRequest()
		req.Recipients = rcpts
		_, err = ev.svc.Create(ctx, ev.a, sender, req, "")
		wantFields(t, err, []FieldError{{Pointer: FieldRecipients, Code: CodeNotAllowed}})
	}

	req = dropRequest()
	req.LinkOnly = true
	if _, err := ev.svc.Create(ctx, ev.a, sender, req, ""); !errors.Is(err, ErrLinkOnlyForbidden) {
		t.Errorf("link-only: %v", err)
	}
	// The link of A is unknown in B.
	if _, err := ev.svc.Create(ctx, ev.b, sender, dropRequest(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("tenant B: %v", err)
	}
	// Blocklisted depositor.
	ev.block(t, ev.a, store.BlockEmail, bob)
	if _, err := ev.svc.Create(ctx, ev.a, sender, dropRequest(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("blocklist: %v", err)
	}
	// A disabled link.
	other := ev.dropLink(t, ev.a)
	if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, other.ID, store.DropLinkUpdate{Enabled: new(false)}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	carolSender := ev.dropSender(t, other)
	carolSender.Email = dave
	if _, err := ev.svc.Create(ctx, ev.a, carolSender, dropRequest(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("disabled link: %v", err)
	}
	// A recipient left the internal domains: refused like a disabled
	// link (T-312).
	if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-z.example.com"}); err != nil {
		t.Fatal(err)
	}
	daveSender := ev.dropSender(t, ev.dropLink(t, ev.a))
	daveSender.Email = dave
	if _, err := ev.svc.Create(ctx, ev.a, daveSender, dropRequest(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("external recipient: %v", err)
	}
	if n := ev.transferCount(t, ev.a); n != 0 {
		t.Errorf("%d transfers created", n)
	}
}

// TestCreateDropLinkFaults covers the store failures of the drop link
// paths and the malformed drop link senders.
func TestCreateDropLinkFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ev.setLevels(t, ev.a, strictLevels())
	l := ev.dropLink(t, ev.a)
	f := ev.faults()
	f.fail["dropLink"] = errFault
	if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("read link: %v", err)
	}
	delete(f.fail, "dropLink")
	// The view of a drop link transfer reads the label of its link: a
	// failure is an internal error, a link gone shows no label.
	viewer := ev.dropSender(t, l)
	d, err := ev.svc.Create(ctx, ev.a, viewer, dropRequest(), "")
	if err != nil {
		t.Fatal(err)
	}
	f.fail["dropLink"] = errFault
	if _, err := ev.svc.Get(ctx, ev.a, viewer, d.ID); !errors.Is(err, errFault) {
		t.Errorf("Get with dropLink failing: %v", err)
	}
	f.fail["dropLink"] = store.ErrNotFound
	if got, err := ev.svc.Get(ctx, ev.a, viewer, d.ID); err != nil || got.DropLinkLabel != "" || len(got.Recipients) != 0 {
		t.Errorf("Get with the link gone = %+v, %v", got, err)
	}
	delete(f.fail, "dropLink")
	f.fail["networkRules"] = errFault
	if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("read network rules: %v", err)
	}
	delete(f.fail, "networkRules")
	f.fail["useDropLinkSession"] = errFault
	if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("use session: %v", err)
	}
	for name, mutate := range map[string]func(*Sender){
		"no link":       func(s *Sender) { s.DropLinkID = "" },
		"link, no kind": func(s *Sender) { s.Kind = store.DepositorInternal },
		"bad link":      func(s *Sender) { s.DropLinkID = "drl_x" },
		"no session":    func(s *Sender) { s.SessionID = "" },
		"invitation":    func(s *Sender) { s.InvitationID = ev.inv.ID },
	} {
		s := ev.dropSender(t, l)
		mutate(&s)
		if _, err := ev.svc.Create(ctx, ev.a, s, dropRequest(), ""); err == nil || isClientError(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	tok := tokenSender(id.New(id.APIToken))
	tok.Email, tok.DropLinkID = carol, l.ID
	if _, err := normalize(tok); err == nil {
		t.Error("an api token sender with a drop link is accepted")
	}
}

// missOnce is a repo whose first idempotency key lookup misses.
type missOnce struct {
	repo
	n int
}

func (m *missOnce) transferByKey(ctx context.Context, tid tenant.ID, o owner, key string, since time.Time) (store.TransferDetails, error) {
	m.n++
	if m.n == 1 {
		return store.TransferDetails{}, store.ErrNotFound
	}
	return m.repo.transferByKey(ctx, tid, o, key, since)
}

// TestCreateDropLinkReplayAfterUse replays, rather than refuses, a
// creation whose key a concurrent request of the same session committed
// first: the first key lookup misses (as for a request racing the commit),
// the session is then seen as used, and the second lookup replays.
func TestCreateDropLinkReplayAfterUse(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ev.setLevels(t, ev.a, strictLevels())
	l := ev.dropLink(t, ev.a)
	sender := ev.dropSender(t, l)
	first, err := ev.svc.Create(ctx, ev.a, sender, dropRequest(), "k")
	if err != nil {
		t.Fatal(err)
	}
	ev.svc.repo = &missOnce{repo: ev.svc.repo}
	got, err := ev.svc.Create(ctx, ev.a, sender, dropRequest(), "k")
	if err != nil || got.ID != first.ID {
		t.Errorf("replay = %+v, %v", got.ID, err)
	}
}

// TestCreateDropLinkLimits covers the hourly deposit cap of a link, all
// depositors together, enforced in the creation transaction, and its
// expiry (threat model P63).
func TestCreateDropLinkLimits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.setLevels(t, ev.a, strictLevels())
		l := ev.dropLink(t, ev.a)
		end := ev.clock.Now().Add(3 * time.Hour)
		l, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, l.ID, store.DropLinkUpdate{MaxDepositsPerHour: 2, ExpiresAt: &end}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		as := func(email string) Sender {
			s := ev.dropSender(t, l)
			s.Email = email
			return s
		}
		if _, err := ev.svc.Create(ctx, ev.a, as(bob), dropRequest(), ""); err != nil {
			t.Fatalf("first: %v", err)
		}
		ev.clock.Advance(10 * time.Minute)
		daveSender := as(dave)
		second, err := ev.svc.Create(ctx, ev.a, daveSender, dropRequest(), "")
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		// Canceling a transfer frees neither its session nor its slot
		// (threat model T-310).
		if err := ev.svc.Cancel(ctx, ev.a, daveSender, second.ID); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if _, err := ev.svc.Create(ctx, ev.a, daveSender, dropRequest(), ""); !errors.Is(err, ErrRateLimited) {
			t.Errorf("same session after cancel, link full: %v", err)
		}
		// The third depositor of the hour is refused, until the first
		// transfer leaves the window.
		_, err = ev.svc.Create(ctx, ev.a, as("erin@partner.example.org"), dropRequest(), "")
		var rl *RateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter != 50*time.Minute {
			t.Fatalf("over the cap: err = %v", err)
		}
		ev.seclog.mu.Lock()
		last := ev.seclog.events[len(ev.seclog.events)-1]
		ev.seclog.mu.Unlock()
		if last.Type != securitylog.RateLimited || last.Fields[0].Value != "drop_link" || last.IP != externalIP {
			t.Errorf("event = %+v", last)
		}
		if n := ev.transferCount(t, ev.a); n != 1 {
			t.Errorf("%d transfers, want 1 (one canceled)", n)
		}
		ev.clock.Advance(50 * time.Minute)
		if _, err := ev.svc.Create(ctx, ev.a, as("erin@partner.example.org"), dropRequest(), ""); err != nil {
			t.Errorf("after the window: %v", err)
		}
		// Expired: refused like a disabled link.
		ev.clock.Advance(2 * time.Hour)
		if _, err := ev.svc.Create(ctx, ev.a, as("frank@partner.example.org"), dropRequest(), ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("expired link: %v", err)
		}
	})
}

// TestCreateDropLinkUsageFault covers a failing count of the hourly cap.
func TestCreateDropLinkUsageFault(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ev.setLevels(t, ev.a, strictLevels())
	l := ev.dropLink(t, ev.a)
	f := ev.faults()
	f.fail["dropLinkUsage"] = errFault
	if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("usage: %v", err)
	}
}
