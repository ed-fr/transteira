package deposit

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// remoteDecoy checks that Start of email from ip (outside the ranges), with
// the recognition cookie of the test browser, answers a challenge shaped
// like the one of an eligible address, sends no mail and logs one more
// deposit_refused line with reason ip (threat T-215).
func (ev *env) remoteDecoy(t *testing.T, tn *tenant.Tenant, ip netip.Addr, email, what string) *Challenge {
	t.Helper()
	before := len(ev.logLines("deposit_refused"))
	mails := ev.queue.count()
	res, err := ev.svc.Start(context.Background(), tn, ip, "", email, "", ev.known)
	if err != nil || res.Session != nil || res.Challenge == nil {
		t.Fatalf("%s: Start = %+v, %v, want a decoy challenge", what, res, err)
	}
	ch := res.Challenge
	if !validToken(id.ChallengeTokenPrefix, ch.ID) || ch.Email != strings.ToLower(email) ||
		!ch.ExpiresAt.Equal(ev.clock.Now().Add(CodeTTL)) || ch.AttemptsRemaining != store.MaxChallengeAttempts {
		t.Errorf("%s: decoy challenge = %+v", what, ch)
	}
	lines := ev.logLines("deposit_refused")
	if len(lines) != before+1 || !strings.Contains(lines[len(lines)-1], `reason="ip"`) {
		t.Errorf("%s: security log = %v, want one more line with reason ip", what, lines)
	}
	if ev.queue.count() != mails {
		t.Errorf("%s: a mail was sent", what)
	}
	return ch
}

// wantDecoyExhausted confirms challenge chID, whose first spent attempts
// are already used, from ip with each of codes in turn and expects the
// wrong-code outcome, then ErrChallengeGone: never a session, never
// ErrForbidden.
func (ev *env) wantDecoyExhausted(t *testing.T, tn *tenant.Tenant, ip netip.Addr, chID, what string, spent int, codes ...string) {
	t.Helper()
	for j, code := range codes {
		i := spent + j
		s, err := ev.svc.Confirm(context.Background(), tn, ip, chID, code, ev.known)
		var wce *WrongCodeError
		switch {
		case s.ID != "" || errors.Is(err, ErrForbidden):
			t.Fatalf("%s: Confirm #%d = %+v, %v", what, i+1, s.SessionInfo, err)
		case i < store.MaxChallengeAttempts-1:
			if !errors.As(err, &wce) || wce.Remaining != store.MaxChallengeAttempts-1-i {
				t.Errorf("%s: Confirm #%d = %v, want a wrong code", what, i+1, err)
			}
		default:
			wantErr(t, what+": Confirm after the last attempt", err, ErrChallengeGone)
		}
	}
}

// remoteRefused checks that Start of email from outside (tenant option
// off), with the
// recognition cookie of the test browser, answers the generic refusal and
// logs one more deposit_refused line with reason ip.
func (ev *env) remoteRefused(t *testing.T, tn *tenant.Tenant, email, what string) {
	t.Helper()
	before := len(ev.logLines("deposit_refused"))
	mails := ev.queue.count()
	res, err := ev.svc.Start(context.Background(), tn, externalIP, "", email, "", ev.known)
	if !errors.Is(err, ErrForbidden) || errors.Is(err, errDecoy) || res.Session != nil || res.Challenge != nil {
		t.Errorf("%s: Start = %+v, %v, want exactly ErrForbidden", what, res, err)
	}
	lines := ev.logLines("deposit_refused")
	if len(lines) != before+1 || !strings.Contains(lines[len(lines)-1], `reason="ip"`) {
		t.Errorf("%s: security log = %v, want one more line with reason ip", what, lines)
	}
	if ev.queue.count() != mails {
		t.Errorf("%s: a mail was sent", what)
	}
}

func TestRemoteDeposit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		ev.withAudit(spy)

		// alice verified her address at the office; gus, of the internal
		// domain too, only through an invitation.
		ev.mustSession(t, ev.a, internalIP, alice, "")
		_, gusToken := ev.mustInvite(t, "gus@entity-a.example.com")
		ev.mustSession(t, ev.a, externalIP, "gus@entity-a.example.com", gusToken)
		before, err := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)
		if err != nil || before.InternalVerifiedAt.IsZero() {
			t.Fatalf("alice verified = %+v, %v", before, err)
		}

		// Option off: the generic refusal, even for an address verified at
		// the office.
		ev.remoteRefused(t, ev.a, alice, "option off")

		// Option on: a decoy challenge for an address never verified
		// internally, for an unknown address and for a foreign domain, all
		// shaped like a genuine one; no code confirms them.
		ev.a.AllowRemoteInternalDeposit = true
		for _, c := range []struct{ email, what string }{
			{"gus@entity-a.example.com", "verified through an invitation only"},
			{"hal@entity-a.example.com", "never verified"},
			{bob, "foreign domain"},
		} {
			ch := ev.remoteDecoy(t, ev.a, externalIP, c.email, c.what)
			ev.wantDecoyExhausted(t, ev.a, externalIP, ch.ID, c.what, 0, "000000", "999999", "123456")
		}
		// Inside the ranges a foreign domain is still refused (reason domain).
		_, err = ev.svc.Start(ctx, ev.a, internalIP, "", bob, "", "")
		wantErr(t, "Start(foreign domain, inside, option on)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="domain"`, 1)
		// The option of another tenant changes nothing.
		ev.remoteRefused(t, ev.b, alice, "other tenant")

		// Internally verified: a code, even with a valid recognition cookie.
		if ev.known == "" {
			t.Fatal("no recognition cookie")
		}
		mails := ev.queue.count()
		ev.clock.Advance(time.Minute)
		res, err := ev.svc.Start(ctx, ev.a, externalIP, "", alice, "", ev.known)
		if err != nil || res.Session != nil || res.Challenge == nil {
			t.Fatalf("Start(remote) = %+v, %v, want a challenge", res, err)
		}
		if ev.queue.count() != mails+1 {
			t.Fatal("no code sent")
		}
		code := codeOf(t, ev.queue.last(t))
		ev.clock.Advance(time.Minute)
		s, err := ev.svc.Confirm(ctx, ev.a, externalIP, res.Challenge.ID, code, ev.known)
		if err != nil {
			t.Fatalf("Confirm(remote): %v", err)
		}
		if s.Kind != KindInternalRemote || s.CanInvite || s.Recognition != "" || s.Invitation != nil || s.Email != aliceNorm {
			t.Errorf("remote session = %+v, recognition %q", s.SessionInfo, s.Recognition)
		}
		after, err := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)
		if err != nil || !after.InternalVerifiedAt.Equal(before.InternalVerifiedAt) ||
			after.InternalVerifiedIP != before.InternalVerifiedIP || after.FirstVerifiedIP != before.FirstVerifiedIP ||
			after.RecognitionSalt != before.RecognitionSalt || !after.LastUsedAt.Equal(ev.clock.Now()) {
			t.Errorf("verified after remote = %+v (before %+v), %v", after, before, err)
		}
		events, _, errs := spy.snapshot()
		if len(errs) != 0 {
			t.Fatalf("audit errors: %v", errs)
		}
		wantEvent(t, events[len(events)-1], audit.ActionAddressVerified, aliceNorm, audit.ObjectDepositSession, s.ID,
			map[string]any{"origin": "remote"})

		// The session reads back with its kind, and cannot invite, from
		// outside or from the office.
		info, err := ev.svc.Session(ctx, ev.a, s.Token)
		if err != nil || info.Kind != KindInternalRemote || info.CanInvite || info.Invitation != nil {
			t.Errorf("Session(remote) = %+v, %v", info, err)
		}
		_, err = ev.svc.Invite(ctx, ev.a, info, externalIP, "", "ivy@partner.example.org", "", "")
		wantErr(t, "Invite(remote session, outside)", err, ErrForbidden)
		_, err = ev.svc.Invite(ctx, ev.a, info, internalIP, "", "ivy@partner.example.org", "", "")
		wantErr(t, "Invite(remote session, inside)", err, ErrForbidden)
		// An internal session used from outside does not invite either.
		internal := ev.mustSession(t, ev.a, internalIP, alice, "")
		_, err = ev.svc.Invite(ctx, ev.a, internal.SessionInfo, externalIP, "", "ivy@partner.example.org", "", "")
		wantErr(t, "Invite(internal session, outside)", err, ErrForbidden)

		// The domain removed from the tenant rules: the internal session no
		// longer invites, even from the office (reason domain).
		if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID,
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"other.example.com"}); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.Invite(ctx, ev.a, internal.SessionInfo, internalIP, "", "ivy@partner.example.org", "", "")
		wantErr(t, "Invite(domain removed)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="domain"`, 2)
		ev.remoteDecoy(t, ev.a, externalIP, alice, "domain removed")
		if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID,
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-a.example.com"}); err != nil {
			t.Fatal(err)
		}

		// Blocklisted: refused with reason blocklist, before the remote rule.
		entry := ev.block(t, ev.a, store.BlockEmail, aliceNorm)
		_, err = ev.svc.Start(ctx, ev.a, externalIP, "", alice, "", "")
		wantErr(t, "Start(remote, blocklisted)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 1)
		if err := ev.db.Blocklist().Delete(ctx, ev.a.ID, entry.ID); err != nil {
			t.Fatal(err)
		}

		// Unused for 12 months: no longer active, refused.
		ev.clock.Advance(13 * 31 * 24 * time.Hour)
		ev.remoteDecoy(t, ev.a, externalIP, alice, "inactive address")
	})
}

// TestRemoteConfirmFollowsTheClient checks decision 1: the kind of a
// challenge without invitation is computed again when the code is entered.
func TestRemoteConfirmFollowsTheClient(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.mustSession(t, ev.a, internalIP, alice, "")
		before, _ := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)

		// Requested at the office, entered from outside, option off: refused
		// and the code is kept (no attempt spent).
		ch := ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code := codeOf(t, ev.queue.last(t))
		_, err := ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, ev.known)
		wantErr(t, "Confirm(outside, option off)", err, ErrForbidden)

		// Option on: an internal_remote session, no cookie, no internal
		// verification recorded.
		ev.a.AllowRemoteInternalDeposit = true
		ev.clock.Advance(time.Minute)
		s, err := ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, ev.known)
		if err != nil || s.Kind != KindInternalRemote || s.CanInvite || s.Recognition != "" {
			t.Fatalf("Confirm(outside, option on) = %+v, %q, %v", s.SessionInfo, s.Recognition, err)
		}
		after, _ := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)
		if !after.InternalVerifiedAt.Equal(before.InternalVerifiedAt) || !after.LastUsedAt.Equal(ev.clock.Now()) {
			t.Errorf("verified = %+v, before %+v", after, before)
		}

		// A new address requested at the office and entered from outside is
		// not verified internally yet: even with the right code the answer
		// is a wrong code (no oracle, threat T-215), an attempt is spent and
		// deposit_refused is logged.
		ch = ev.mustChallenge(t, ev.a, internalIP, "jo@entity-a.example.com", "")
		code = codeOf(t, ev.queue.last(t))
		refused := len(ev.logLines("deposit_refused"))
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, "")
		var wce *WrongCodeError
		if !errors.As(err, &wce) || wce.Remaining != store.MaxChallengeAttempts-1 {
			t.Errorf("Confirm(new address, outside) = %v, want a wrong code", err)
		}
		if n := len(ev.logLines("deposit_refused")); n != refused+1 {
			t.Errorf("deposit_refused lines = %d, want %d", n, refused+1)
		}
		if _, err := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, "jo@entity-a.example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("jo verified from outside: %v", err)
		}
		// Entered at the office instead: internal, verified internally.
		s, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		if err != nil || s.Kind != KindInternal || !s.CanInvite || s.Recognition == "" {
			t.Fatalf("Confirm(new address, inside) = %+v, %v", s.SessionInfo, err)
		}

		// Requested from outside, entered at the office: internal session.
		res, err := ev.svc.Start(ctx, ev.a, externalIP, "", alice, "", "")
		if err != nil || res.Challenge == nil {
			t.Fatalf("Start(remote) = %+v, %v", res, err)
		}
		s, err = ev.svc.Confirm(ctx, ev.a, internalIP, res.Challenge.ID, codeOf(t, ev.queue.last(t)), "")
		if err != nil || s.Kind != KindInternal || !s.CanInvite || s.Recognition == "" {
			t.Errorf("Confirm(remote challenge, inside) = %+v, %v", s.SessionInfo, err)
		}
	})
}

// TestRemoteDecoy covers the decoy of threat T-215 beyond TestRemoteDeposit:
// a decoy stays unusable once its address becomes eligible, counts against
// both rate limits like a genuine challenge, needs the tenant SMTP settings
// like one, and the blocklist still answers 403 at both steps.
func TestRemoteDecoy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.mustSession(t, ev.a, internalIP, alice, "")
		ev.a.AllowRemoteInternalDeposit = true
		ev.c.AllowRemoteInternalDeposit = true
		const hal = "hal@entity-a.example.com"

		// A decoy for hal, then hal verifies at the office: the decoy still
		// opens nothing, from outside (now eligible) or from the office.
		decoy := ev.remoteDecoy(t, ev.a, externalIP, hal, "never verified")
		ev.mustSession(t, ev.a, internalIP, hal, "")
		ev.wantDecoyExhausted(t, ev.a, externalIP, decoy.ID, "eligible since, outside", 0, "000000")
		ev.wantDecoyExhausted(t, ev.a, internalIP, decoy.ID, "eligible since, inside", 1, "111111")
		// hal is now eligible: a genuine remote code.
		mails := ev.queue.count()
		ev.mustChallenge(t, ev.a, externalIP, hal, "")
		if ev.queue.count() != mails+1 {
			t.Error("no code mailed to an eligible address")
		}

		// Blocklisted: 403 at Start and at Confirm, reason blocklist.
		jo := ev.mustChallenge(t, ev.a, internalIP, "jo@entity-a.example.com", "")
		entry := ev.block(t, ev.a, store.BlockDomain, "entity-a.example.com")
		_, err := ev.svc.Start(ctx, ev.a, externalIP, "", "kim@entity-a.example.com", "", "")
		wantErr(t, "Start(blocklisted, option on)", err, ErrForbidden)
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, jo.ID, "000000", "")
		wantErr(t, "Confirm(blocklisted, option on)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 2)
		if err := ev.db.Blocklist().Delete(ctx, ev.a.ID, entry.ID); err != nil {
			t.Fatal(err)
		}

		// Per address: decoys count like genuine codes, the 6th is refused.
		ev.clock.Advance(2 * time.Hour)
		for range MaxCodesPerAddress {
			ev.remoteDecoy(t, ev.a, externalIP, bob, "per address")
		}
		_, err = ev.svc.Start(ctx, ev.a, externalIP, "", bob, "", "")
		var rle *RateLimitError
		if !errors.As(err, &rle) || rle.RetryAfter != RateWindow {
			t.Fatalf("Start(6th decoy) = %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="verification_address"`, 1)

		// Per IP, mixed: 4 genuine codes of alice and 16 decoys from one
		// IP; the 21st request answers 429, decoy or genuine alike.
		ev.clock.Advance(2 * time.Hour)
		ip := netip.MustParseAddr("198.51.100.9")
		for range 4 {
			ev.mustChallenge(t, ev.a, ip, alice, "")
		}
		for i := range MaxCodesPerIP - 4 {
			ev.remoteDecoy(t, ev.a, ip, "u"+string(rune('a'+i))+"@partner.example.org", "per ip")
		}
		for _, email := range []string{"zed@partner.example.org", alice} {
			_, err = ev.svc.Start(ctx, ev.a, ip, "", email, "", "")
			if !errors.As(err, &rle) || rle.RetryAfter != RateWindow {
				t.Errorf("Start(21st code from one ip, %s) = %v", email, err)
			}
		}
		ev.wantLogged(t, "rate_limited", `scope="verification_ip"`, 2)

		// A tenant without SMTP settings: ErrMailUnavailable and nothing
		// written, as for a genuine code.
		_, err = ev.svc.Start(ctx, ev.c, externalIP, "", bob, "", "")
		wantErr(t, "Start(decoy without smtp)", err, ErrMailUnavailable)
		n, err := ev.db.Challenges().CountByIPSince(ctx, ev.c.ID, externalIP, ev.clock.Now().Add(-time.Hour))
		if err != nil || n != 0 {
			t.Errorf("challenges written without smtp: %d, %v", n, err)
		}
	})
}

// abuseSpy is a fake AbuseDetector.
type abuseSpy struct {
	mu      sync.Mutex
	limit   int
	err     error
	reached []string
	tenants []tenant.ID
	limits  []int
}

func (a *abuseSpy) InvitationLimit(_ context.Context, _ tenant.ID) (int, error) {
	return a.limit, a.err
}

func (a *abuseSpy) InvitationLimitReached(_ context.Context, t *tenant.Tenant, inviter string, limit int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reached, a.tenants, a.limits = append(a.reached, inviter), append(a.tenants, t.ID), append(a.limits, limit)
}

func TestInvitationLimitFromAbuseSettings(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &abuseSpy{limit: 2}
		ev.svc.abuse = spy
		s := ev.mustSession(t, ev.a, internalIP, alice, "")
		invite := func(to string) error {
			_, err := ev.svc.Invite(ctx, ev.a, s.SessionInfo, internalIP, "", to, "", "")
			return err
		}
		for _, to := range []string{"k1@partner.example.org", "k2@partner.example.org"} {
			if err := invite(to); err != nil {
				t.Fatalf("Invite(%s): %v", to, err)
			}
		}
		err := invite("k3@partner.example.org")
		var rle *RateLimitError
		if !errors.As(err, &rle) || rle.RetryAfter != RateWindow {
			t.Fatalf("Invite over the tenant limit: %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="invitation"`, 1)
		spy.mu.Lock()
		if len(spy.reached) != 1 || spy.reached[0] != aliceNorm || spy.tenants[0] != ev.a.ID || spy.limits[0] != 2 {
			t.Errorf("InvitationLimitReached calls = %v %v %v", spy.reached, spy.tenants, spy.limits)
		}
		spy.mu.Unlock()

		// A higher tenant limit allows more.
		spy.limit = 3
		if err := invite("k4@partner.example.org"); err != nil {
			t.Errorf("Invite under the raised limit: %v", err)
		}

		// The limit cannot be read: an internal error, nothing created.
		spy.err = errFault
		err = invite("k5@partner.example.org")
		if !errors.Is(err, errFault) || isSentinel(err) {
			t.Errorf("Invite with a failing limit: %v", err)
		}
	})
}

func TestNewWiresAbuse(t *testing.T) {
	spy := &abuseSpy{}
	s := New(nil, nil, nil, nil, nil, Options{Abuse: spy})
	if s.abuse != spy {
		t.Error("Options.Abuse not wired")
	}
	if New(nil, nil, nil, nil, nil, Options{}).abuse != nil {
		t.Error("nil Options.Abuse should stay nil")
	}
}
