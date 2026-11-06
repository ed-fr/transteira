package deposit

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

const supplier = "Supplier@Partner.example.org" // third party, as typed

// newDropLink creates a usable drop link of tn with level ("" for the
// tenant default) and returns it with its token.
func (ev *env) newDropLink(t *testing.T, tn *tenant.Tenant, level string) (store.DropLink, string) {
	t.Helper()
	tok, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	l, err := ev.db.DropLinks().Create(context.Background(), tn.ID, store.DropLink{
		ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: "Supplier invoices",
		Recipients: []string{"ap@entity-a.example.com"}, ValidityDays: 7, ConfidentialityLevel: level,
		Enabled: true, CreatedBy: "adm_1",
	})
	if err != nil {
		t.Fatalf("Create drop link: %v", err)
	}
	return l, tok
}

// dropSession opens a drop link session through the code.
func (ev *env) dropSession(t *testing.T, tn *tenant.Tenant, email, tok string) Session {
	t.Helper()
	ctx := context.Background()
	ch, err := ev.svc.StartDropLink(ctx, tn, externalIP, "", email, tok)
	if err != nil {
		t.Fatalf("StartDropLink: %v", err)
	}
	s, err := ev.svc.Confirm(ctx, tn, externalIP, ch.ID, codeOf(t, ev.queue.last(t)), ev.known)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	return s
}

func TestPublicDropLink(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		def, defTok := ev.newDropLink(t, ev.a, "")
		_, confTok := ev.newDropLink(t, ev.a, "confidential")

		got, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "fr-CH, en;q=0.5", defTok)
		if err != nil {
			t.Fatal(err)
		}
		if got.Label != def.Label || got.ValidityDays != 7 || got.Level == nil || got.Level.Key != "internal" ||
			got.Level.Label != "Interne" || got.Level.Rules.ExpiryDaysMask == 0 {
			t.Errorf("default level link = %+v (%+v)", got, got.Level)
		}
		got, err = ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", confTok)
		if err != nil || got.Level == nil || got.Level.Key != "confidential" || !strings.HasPrefix(got.Level.Label, "Confidential") {
			t.Errorf("link level = %+v, %v", got.Level, err)
		}

		// Every invalid link gets the same answer and a log line.
		disabled, disabledTok := ev.newDropLink(t, ev.a, "")
		no := false
		if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, disabled.ID, store.DropLinkUpdate{Enabled: &no}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		revoked, revokedTok := ev.newDropLink(t, ev.a, "")
		if _, _, err := ev.db.DropLinks().Revoke(ctx, ev.a.ID, revoked.ID, time.Time{}); err != nil {
			t.Fatal(err)
		}
		_, otherTok := ev.newDropLink(t, ev.b, "")
		invalid := map[string]string{
			"malformed": "ttd_short", "other prefix": unknownToken(t, id.InvitationTokenPrefix), "unknown": unknownToken(t, id.DropTokenPrefix),
			"disabled": disabledTok, "revoked": revokedTok, "other tenant": otherTok,
		}
		for what, tok := range invalid {
			_, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok)
			wantErr(t, "PublicDropLink("+what+")", err, ErrDropLinkInvalid)
		}
		ev.wantLogged(t, "drop_link_invalid", `ip=`+externalIP.String(), len(invalid))
		ev.wantLogged(t, "drop_link_invalid", hostA, len(invalid))

		// A tenant without any level of that key shows none (safety net).
		ev.svc.repo = levelsRepo{repo: ev.svc.repo}
		if got, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", defTok); err != nil || got.Level != nil {
			t.Errorf("without levels = %+v, %v", got, err)
		}
	})
}

// levelsRepo answers no confidentiality level.
type levelsRepo struct{ repo }

func (levelsRepo) levels(context.Context, tenant.ID) ([]store.ConfidentialityLevel, error) {
	return nil, nil
}

func TestDropLinkDeposit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		ev.withAudit(spy)
		link, tok := ev.newDropLink(t, ev.a, "")

		// Refusals before any code: address, client IP, link, blocklist.
		_, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "not an address", tok)
		wantInvalid(t, "StartDropLink(bad email)", err, FieldEmail)
		_, err = ev.svc.StartDropLink(ctx, ev.a, netipZero(), "", supplier, tok)
		wantErr(t, "StartDropLink(no ip)", err, ErrForbidden)
		_, err = ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, "ttd_bad")
		wantErr(t, "StartDropLink(malformed)", err, ErrDropLinkInvalid)
		_, err = ev.svc.StartDropLink(ctx, ev.b, externalIP, "", supplier, tok)
		wantErr(t, "StartDropLink(other tenant)", err, ErrDropLinkInvalid)
		ev.wantLogged(t, "drop_link_invalid", "", 2)
		blocked := ev.block(t, ev.a, store.BlockEmail, "mallory@partner.example.org")
		_, err = ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "mallory@partner.example.org", tok)
		wantErr(t, "StartDropLink(blocklisted)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 1)
		if ev.queue.count() != 0 {
			t.Fatalf("%d mails sent before a valid start", ev.queue.count())
		}

		// A code, then a drop_link session bound to the link.
		s := ev.dropSession(t, ev.a, supplier, tok)
		if s.Kind != KindDropLink || s.CanInvite || s.Recognition != "" || s.Invitation != nil || s.Reply != nil ||
			s.DropLink == nil || s.DropLink.ID != link.ID || s.DropLink.Label != link.Label || s.DropLink.ValidityDays != 7 ||
			len(s.Limits.ExpiryDays) != 1 || s.Limits.ExpiryDays[0] != 7 || s.OpenedAt.IsZero() || s.Email != "supplier@partner.example.org" {
			t.Errorf("session = %+v", s.SessionInfo)
		}
		got, err := ev.svc.Session(ctx, ev.a, s.Token)
		if err != nil || got.DropLink == nil || got.DropLink.ID != link.ID || got.Kind != KindDropLink ||
			!got.OpenedAt.Equal(s.OpenedAt) || len(got.Limits.ExpiryDays) != 1 {
			t.Errorf("Session = %+v, %v", got, err)
		}
		used, err := ev.db.DropLinks().Get(ctx, ev.a.ID, link.ID)
		if err != nil || used.LastUsedAt.IsZero() {
			t.Errorf("link last use = %v, %v", used.LastUsedAt, err)
		}
		v, err := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, "supplier@partner.example.org")
		if err != nil || !v.InternalVerifiedAt.IsZero() {
			t.Errorf("verified = %+v, %v", v, err)
		}
		events, _, errs := spy.snapshot()
		if len(errs) != 0 || len(events) != 1 {
			t.Fatalf("audit = %+v, errors %v", events, errs)
		}
		wantEvent(t, events[0], audit.ActionAddressVerified, "supplier@partner.example.org", audit.ObjectDepositSession, s.ID,
			map[string]any{"origin": originDropLink, "dropLinkId": link.ID})

		// The code is required again, even verified and with a cookie.
		ev.known = ev.entryFor(t, ev.a, supplier, 0)
		before := ev.queue.count()
		if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok); err != nil || ev.queue.count() != before+1 {
			t.Errorf("second start: %v, %d mails", err, ev.queue.count()-before)
		}
		if s2 := ev.dropSession(t, ev.a, supplier, tok); s2.Recognition != "" || s2.Token == s.Token {
			t.Error("second session reused or recognized")
		}

		// Blocklisted between the code and its confirmation.
		ch, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "trent@partner.example.org", tok)
		if err != nil {
			t.Fatal(err)
		}
		ev.block(t, ev.a, store.BlockEmail, "trent@partner.example.org")
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, codeOf(t, ev.queue.last(t)), "")
		wantErr(t, "Confirm(blocklisted since)", err, ErrForbidden)
		_ = blocked

		// Disabled between the code and its confirmation; the session ends.
		ch, err = ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "victor@partner.example.org", tok)
		if err != nil {
			t.Fatal(err)
		}
		code := codeOf(t, ev.queue.last(t))
		no := false
		if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, link.ID, store.DropLinkUpdate{Enabled: &no}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		logged := len(ev.logLines("drop_link_invalid"))
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, "")
		wantErr(t, "Confirm(disabled since)", err, ErrDropLinkInvalid)
		if n := len(ev.logLines("drop_link_invalid")); n != logged+1 {
			t.Errorf("drop_link_invalid lines %d, want %d", n, logged+1)
		}
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "Session(disabled link)", err, ErrUnauthenticated)
		_, err = ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok)
		wantErr(t, "StartDropLink(disabled)", err, ErrDropLinkInvalid)
	})
}

// TestDropLinkFaults injects failures in the drop link steps.
func TestDropLinkFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		real := ev.svc.repo
		logs := ev.withAudit(&auditSpy{})
		_, tok := ev.newDropLink(t, ev.a, "")
		s := ev.dropSession(t, ev.a, supplier, tok)
		pending := func(t *testing.T) (string, string) {
			t.Helper()
			ch, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok)
			if err != nil {
				t.Fatal(err)
			}
			return ch.ID, codeOf(t, ev.queue.last(t))
		}
		chID, code := pending(t)
		with := func(fails map[string]error) { ev.svc.repo = faultRepo{repo: real, fails: fails} }

		calls := map[string]func() error{
			"dropLinkByHash": func() error { _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok); return err },
			"levels":         func() error { _, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok); return err },
			"dropLink":       func() error { _, err := ev.svc.Session(ctx, ev.a, s.Token); return err },
			"tx.dropLink":    func() error { _, err := ev.svc.Confirm(ctx, ev.a, externalIP, chID, code, ""); return err },
		}
		for op, call := range calls {
			with(map[string]error{op: errFault})
			if err := call(); !errors.Is(err, errFault) || isSentinel(err) {
				t.Errorf("%s failing: err = %v, want an internal error", op, err)
			}
		}
		with(map[string]error{"dropLinkByHash": errFault})
		if _, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok); !errors.Is(err, errFault) {
			t.Errorf("PublicDropLink with dropLinkByHash failing: %v", err)
		}
		// The recheck of the challenge reads the link outside the
		// transaction.
		with(map[string]error{"dropLink": errFault})
		if _, err := ev.svc.Confirm(ctx, ev.a, externalIP, chID, code, ""); !errors.Is(err, errFault) || isSentinel(err) {
			t.Errorf("Confirm with dropLink failing: %v", err)
		}

		// Gone under the transaction or at the insertion: invalid link.
		for _, op := range []string{"tx.dropLink", "createSession"} {
			chID, code := pending(t)
			with(map[string]error{op: store.ErrNotFound})
			_, err := ev.svc.Confirm(ctx, ev.a, externalIP, chID, code, "")
			wantErr(t, "Confirm with "+op+" not found", err, ErrDropLinkInvalid)
		}
		// The store only returns usable links: a disabled one by token is
		// still refused.
		ev.svc.repo = disabledByHash{faultRepo{repo: real}}
		_, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok)
		wantErr(t, "PublicDropLink(disabled by hash)", err, ErrDropLinkInvalid)

		// The last use is best effort.
		ev.svc.repo = real
		chID, code = pending(t)
		with(map[string]error{"touchDropLink": errFault})
		if _, err := ev.svc.Confirm(ctx, ev.a, externalIP, chID, code, ""); err != nil {
			t.Errorf("Confirm with touchDropLink failing: %v", err)
		}
		if !strings.Contains(logs.String(), "recording the use of a drop link failed") {
			t.Error("touch failure not logged")
		}
		ev.svc.repo = real
	})
}

// disabledByHash returns the links by token as disabled.
type disabledByHash struct{ faultRepo }

func (d disabledByHash) dropLinkByHash(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.DropLink, error) {
	l, err := d.faultRepo.dropLinkByHash(ctx, tid, hash, now)
	l.Enabled = false
	return l, err
}

// usageRepo answers a fixed use of every drop link.
type usageRepo struct {
	repo
	usage store.DropLinkUsage
}

func (u usageRepo) dropLinkUsage(context.Context, tenant.ID, string, time.Time) (store.DropLinkUsage, error) {
	return u.usage, nil
}

// TestDropLinkHourlyCap checks the hourly deposit cap of a link (threat
// model P63): checked before any code is sent, logged with scope
// drop_link, with the time until the window frees a slot.
func TestDropLinkHourlyCap(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		real := ev.svc.repo
		link, tok := ev.newDropLink(t, ev.a, "")
		if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, link.ID, store.DropLinkUpdate{MaxDepositsPerHour: 2}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		now := ev.clock.Now()

		// Below the cap: a code is sent.
		ev.svc.repo = usageRepo{repo: real, usage: store.DropLinkUsage{Count: 1, Oldest: now.Add(-15 * time.Minute)}}
		if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok); err != nil || ev.queue.count() != 1 {
			t.Fatalf("below the cap: %v, %d mails", err, ev.queue.count())
		}
		// At the cap: refused, no code, logged.
		ev.svc.repo = usageRepo{repo: real, usage: store.DropLinkUsage{Count: 2, Oldest: now.Add(-15 * time.Minute)}}
		_, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "other@partner.example.org", tok)
		var rle *RateLimitError
		if !errors.As(err, &rle) || !errors.Is(err, ErrRateLimited) || rle.RetryAfter != 45*time.Minute {
			t.Errorf("at the cap: err = %v", err)
		}
		if ev.queue.count() != 1 {
			t.Errorf("%d mails sent through a busy link", ev.queue.count()-1)
		}
		ev.wantLogged(t, "rate_limited", `scope="drop_link"`, 1)

		// The real count: no transfer yet.
		ev.svc.repo = real
		if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok); err != nil {
			t.Errorf("real count: %v", err)
		}
		// A failing count is an internal error.
		ev.svc.repo = faultRepo{repo: real, fails: map[string]error{"dropLinkUsage": errFault}}
		if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok); !errors.Is(err, errFault) || isSentinel(err) {
			t.Errorf("dropLinkUsage failing: %v", err)
		}
	})
}

// TestDropLinkCodeCap checks the cap on the codes sent through one link,
// whatever the address (threat model T-310): DropLinkCodesFactor times the
// hourly deposit cap, counted with the code, logged with scope drop_link.
func TestDropLinkCodeCap(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		link, tok := ev.newDropLink(t, ev.a, "")
		if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, link.ID, store.DropLinkUpdate{MaxDepositsPerHour: 1}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		other, otherTok := ev.newDropLink(t, ev.a, "")
		for i := range DropLinkCodesFactor {
			addr := "p" + strconv.Itoa(i) + "@partner.example.org"
			if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", addr, tok); err != nil {
				t.Fatalf("code %d: %v", i, err)
			}
		}
		_, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "rotated@partner.example.org", tok)
		var rle *RateLimitError
		if !errors.As(err, &rle) || rle.RetryAfter != RateWindow {
			t.Errorf("over the code cap: %v", err)
		}
		if ev.queue.count() != DropLinkCodesFactor {
			t.Errorf("%d mails, want %d", ev.queue.count(), DropLinkCodesFactor)
		}
		ev.wantLogged(t, "rate_limited", `scope="drop_link"`, 1)
		// Another link has its own budget.
		if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "rotated@partner.example.org", otherTok); err != nil {
			t.Errorf("other link %s: %v", other.ID, err)
		}
		// A failing count is an internal error.
		ev.svc.repo = faultRepo{repo: ev.svc.repo, fails: map[string]error{"countByDropLink": errFault}}
		if _, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "x@partner.example.org", otherTok); !errors.Is(err, errFault) || isSentinel(err) {
			t.Errorf("countByDropLink failing: %v", err)
		}
	})
}

// TestDropLinkRecipientsRechecked checks that a link whose recipient no
// longer has an internal domain answers like a disabled one, at the
// landing page, the code and the confirmation (T-312); an open session
// stays readable, the transfer service refusing its creation.
func TestDropLinkRecipientsRechecked(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		real := ev.svc.repo
		_, tok := ev.newDropLink(t, ev.a, "")
		s := ev.dropSession(t, ev.a, supplier, tok)
		ch, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok)
		if err != nil {
			t.Fatal(err)
		}
		code := codeOf(t, ev.queue.last(t))
		mails := ev.queue.count()
		if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID,
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"other.example.com"}); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok)
		wantErr(t, "PublicDropLink", err, ErrDropLinkInvalid)
		_, err = ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok)
		wantErr(t, "StartDropLink", err, ErrDropLinkInvalid)
		if ev.queue.count() != mails {
			t.Error("a code was sent through a link with an external recipient")
		}
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, "")
		wantErr(t, "Confirm", err, ErrDropLinkInvalid)
		if _, err := ev.svc.Session(ctx, ev.a, s.Token); err != nil {
			t.Errorf("Session: %v", err)
		}
		// A failing read of the rules is an internal error.
		ev.svc.repo = faultRepo{repo: real, fails: map[string]error{"networkRules": errFault}}
		if _, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok); !errors.Is(err, errFault) || isSentinel(err) {
			t.Errorf("networkRules failing: %v", err)
		}
	})
}

// TestDropLinkExpiry checks that an expired link behaves like a disabled
// one: no landing page, no code, no session, and its sessions end.
func TestDropLinkExpiry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		link, tok := ev.newDropLink(t, ev.a, "")
		end := ev.clock.Now().Add(10 * time.Minute)
		if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, link.ID, store.DropLinkUpdate{ExpiresAt: &end}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		s := ev.dropSession(t, ev.a, supplier, tok)
		ch, err := ev.svc.StartDropLink(ctx, ev.a, externalIP, "", "victor@partner.example.org", tok)
		if err != nil {
			t.Fatal(err)
		}
		code := codeOf(t, ev.queue.last(t))

		ev.clock.Advance(11 * time.Minute) // the code is still valid, the link is not
		logged := len(ev.logLines("drop_link_invalid"))
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, "")
		wantErr(t, "Confirm(expired since)", err, ErrDropLinkInvalid)
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "Session(expired link)", err, ErrUnauthenticated)
		_, err = ev.svc.StartDropLink(ctx, ev.a, externalIP, "", supplier, tok)
		wantErr(t, "StartDropLink(expired)", err, ErrDropLinkInvalid)
		_, err = ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok)
		wantErr(t, "PublicDropLink(expired)", err, ErrDropLinkInvalid)
		if n := len(ev.logLines("drop_link_invalid")); n != logged+3 {
			t.Errorf("drop_link_invalid lines %d, want %d", n, logged+3)
		}

		// An admin removes the expiry: usable again.
		if _, _, err := ev.db.DropLinks().Update(ctx, ev.a.ID, link.ID, store.DropLinkUpdate{ExpiresAt: &time.Time{}}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.PublicDropLink(ctx, ev.a, externalIP, "", tok); err != nil {
			t.Errorf("PublicDropLink(expiry removed) = %v", err)
		}
	})
}
