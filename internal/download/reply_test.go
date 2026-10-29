package download

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// internalDomain is the internal mail domain of tenant A in the reply
// tests: the domain of alice.
const internalDomain = "entity-a.example.com"

// allowReply turns the reply option of tn on or off in the database only:
// the *tenant.Tenant of the tests keeps its old value, as the request
// context of a running server would.
func (ev *env) allowReply(tn *tenant.Tenant, on bool) {
	ev.t.Helper()
	ctx := context.Background()
	cur, err := ev.db.Tenants().Get(ctx, tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	cur.AllowTransferReply = on
	if _, err := ev.db.Tenants().Update(ctx, cur); err != nil {
		ev.t.Fatal(err)
	}
}

// internalDomains replaces the internal mail domains of tn.
func (ev *env) internalDomains(tn *tenant.Tenant, domains ...string) {
	ev.t.Helper()
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if _, err := ev.db.NetworkRules().Replace(context.Background(), tn.ID, cidrs, domains); err != nil {
		ev.t.Fatal(err)
	}
}

// block adds value of kind k to the blocklist of tn and returns a function
// removing it.
func (ev *env) block(tn *tenant.Tenant, k store.BlocklistKind, value string) func() {
	ev.t.Helper()
	ctx := context.Background()
	entry, err := ev.db.Blocklist().Create(ctx, tn.ID, store.BlocklistEntry{Kind: k, Value: value, CreatedBy: "admin"})
	if err != nil {
		ev.t.Fatal(err)
	}
	return func() {
		ev.t.Helper()
		if err := ev.db.Blocklist().Delete(ctx, tn.ID, entry.ID); err != nil {
			ev.t.Fatal(err)
		}
	}
}

// newReplyEnv builds an env whose tenant A allows replies and has alice's
// domain as internal domain.
func newReplyEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ev := newEnv(t, e, nil)
	ev.allowReply(ev.a, true)
	ev.internalDomains(ev.a, internalDomain)
	return ev
}

// replySpec makes sp a per-recipient transfer for dave and erin, without
// the recipient verification option.
func replySpec(sp spec) spec {
	sp.perRecipient, sp.recipients = true, []string{dave, erin}
	if len(sp.contents) == 0 {
		sp.contents = [][]byte{random(100)}
	}
	return sp
}

// fromExternal makes the sender of a transfer of tn an invited external.
func (ev *env) fromExternal(tn *tenant.Tenant) func(*store.Transfer) {
	ev.t.Helper()
	hash := sha256.Sum256(random(32))
	inv := store.Invitation{ID: id.New(id.Invitation), TokenHash: hash[:], Email: "carol@customer.example.net", InvitedBy: alice}
	if err := ev.db.Invitations().Create(context.Background(), tn.ID, inv); err != nil {
		ev.t.Fatal(err)
	}
	return func(tr *store.Transfer) {
		tr.SenderKind, tr.InvitationID, tr.SenderEmail = store.DepositorExternal, inv.ID, inv.Email
	}
}

// fromAPIToken makes a transfer of tn created by a new API token.
func (ev *env) fromAPIToken(tn *tenant.Tenant) func(*store.Transfer) {
	ev.t.Helper()
	hash := sha256.Sum256(random(32))
	tok, err := ev.db.APITokens().Create(context.Background(), tn.ID, store.APIToken{
		ID: id.New(id.APIToken), Name: "scanner", Prefix: "tt_abc", TokenHash: hash[:], CreatedBy: "admin",
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return func(tr *store.Transfer) { tr.APITokenID = tok.ID }
}

// fromReplyTo makes a transfer a reply of dave to the transfer src.
func fromReplyTo(src published) func(*store.Transfer) {
	return func(tr *store.Transfer) {
		tr.SenderKind, tr.ReplyToTransferID, tr.SenderEmail = store.DepositorReply, src.id, dave
	}
}

// fromRemote makes the sender an internal depositing from outside.
func fromRemote(tr *store.Transfer) { tr.SenderKind = store.DepositorInternalRemote }

// startReply asks a reply code for p from ipOne.
func (ev *env) startReply(p published, cookie string) (*Challenge, error) {
	return ev.svc.StartVerification(context.Background(), p.tn, p.token, ipOne, true, "en", cookie)
}

// verifyReply asks a reply code for p, confirms it and returns the
// verification cookie built on cookie.
func (ev *env) verifyReply(p published, cookie string) string {
	ev.t.Helper()
	if _, err := ev.startReply(p, cookie); err != nil {
		ev.t.Fatalf("StartVerification(reply): %v", err)
	}
	code := ev.notifier.lastCode(ev.t)
	ev.secrets = append(ev.secrets, code)
	c, err := ev.svc.ConfirmVerification(context.Background(), p.tn, p.token, ipOne, code, cookie)
	if err != nil {
		ev.t.Fatalf("ConfirmVerification(reply): %v", err)
	}
	return c
}

// replyAccess calls ReplyAccess for p from ipOne.
func (ev *env) replyAccess(p published, cookie string) (ReplyTarget, error) {
	return ev.svc.ReplyAccess(context.Background(), p.tn, p.token, cookie, ipOne)
}

// refusals returns the transfer.recipient_refused events of tenant tid.
func (ev *env) refusals(tid tenant.ID) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{
		TenantID: tid, Action: string(audit.ActionTransferRecipientRefused), Limit: store.MaxPageSize,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// TestReplyEligibility: only a recipient link of a transfer sent by an
// internal depositor (or an API token) of a tenant allowing replies may
// reply; the option is read from the database, not from the request
// tenant (T-222, T-224, P33).
func TestReplyEligibility(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newReplyEnv(t, e)
		ctx := context.Background()
		internal := ev.publish(ev.a, replySpec(spec{}))
		cases := []struct {
			name      string
			p         published
			eligible  bool
			fromReply bool
		}{
			{name: "internal", p: internal, eligible: true},
			{name: "internal remote", p: ev.publish(ev.a, replySpec(spec{sender: fromRemote})), eligible: true},
			{name: "api token", p: ev.publish(ev.a, replySpec(spec{sender: ev.fromAPIToken(ev.a)})), eligible: true},
			{name: "shared link", p: ev.publish(ev.a, spec{contents: [][]byte{random(10)}})},
			{name: "invited external", p: ev.publish(ev.a, replySpec(spec{sender: ev.fromExternal(ev.a)}))},
			{name: "reply", p: ev.publish(ev.a, replySpec(spec{sender: fromReplyTo(internal)})), fromReply: true},
		}
		for _, c := range cases {
			v, err := ev.svc.Resolve(ctx, ev.a, c.p.token, Cookies{})
			if err != nil || v.ReplyAllowed != c.eligible || v.Reply != c.fromReply {
				t.Fatalf("%s: view %+v, %v", c.name, v, err)
			}
			_, err = ev.startReply(c.p, "")
			if c.eligible && err != nil || !c.eligible && !errors.Is(err, ErrReplyNotAllowed) {
				t.Fatalf("%s: start reply %v", c.name, err)
			}
			// Without a proved address, the refusal never tells whether the
			// sender was internal (nor a shared link from another).
			if _, err := ev.replyAccess(c.p, ""); !errors.Is(err, ErrRecipientVerificationRequired) {
				t.Fatalf("%s: reply access %v", c.name, err)
			}
		}
		// With a proved address (recipient verification option), an
		// ineligible sender is refused as such.
		for name, sender := range map[string]func(*store.Transfer){
			"invited external": ev.fromExternal(ev.a), "reply": fromReplyTo(internal),
		} {
			p := ev.publish(ev.a, ev.verifiedSpec(spec{sender: sender}))
			_, err := ev.replyAccess(p, ev.verify(p, ""))
			if !errors.Is(err, ErrReplyNotAllowed) {
				t.Fatalf("%s: verified reply access %v", name, err)
			}
		}

		// Turning the option off applies at once, whatever the request
		// tenant says.
		ev.a.AllowTransferReply = true
		ev.allowReply(ev.a, false)
		if v, err := ev.svc.Resolve(ctx, ev.a, internal.token, Cookies{}); err != nil || v.ReplyAllowed {
			t.Fatalf("option off: %+v, %v", v, err)
		}
		_, err := ev.startReply(internal, "")
		wantErr(t, err, ErrReplyNotAllowed)
		ev.allowReply(ev.a, true)

		// A tenant being deleted allows nothing; a failed read is internal.
		ev.f.set("tenant", 1, store.ErrNotFound)
		if v, err := ev.svc.Resolve(ctx, ev.a, internal.token, Cookies{}); err != nil || v.ReplyAllowed {
			t.Fatalf("deleted tenant: %+v, %v", v, err)
		}
		ev.f.set("tenant", 1, nil)
		_, err = ev.svc.Resolve(ctx, ev.a, internal.token, Cookies{})
		wantInternal(t, err)
	})
}

// TestReplyViewLocked: ReplyAllowed and Reply are never part of a locked
// view.
func TestReplyViewLocked(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newReplyEnv(t, e)
		ctx := context.Background()
		protected := ev.publish(ev.a, replySpec(spec{password: true}))
		v, err := ev.svc.Resolve(ctx, ev.a, protected.token, Cookies{})
		if err != nil || !v.Locked || v.ReplyAllowed || v.Reply {
			t.Fatalf("locked view %+v, %v", v, err)
		}
		grant := ev.unlock(protected, "")
		if v, err := ev.svc.Resolve(ctx, ev.a, protected.token, Cookies{Grant: grant}); err != nil || v.Locked || !v.ReplyAllowed {
			t.Fatalf("unlocked view %+v, %v", v, err)
		}

		awaiting := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		if v, err := ev.svc.Resolve(ctx, ev.a, awaiting.token, Cookies{}); err != nil || !v.Locked || v.ReplyAllowed {
			t.Fatalf("awaiting view %+v, %v", v, err)
		}
		cookie := ev.verify(awaiting, "")
		if v, err := ev.svc.Resolve(ctx, ev.a, awaiting.token, Cookies{Verification: cookie}); err != nil || v.Locked || !v.ReplyAllowed {
			t.Fatalf("verified view %+v, %v", v, err)
		}

		reply := ev.publish(ev.a, replySpec(spec{password: true, sender: fromReplyTo(protected)}))
		if v, err := ev.svc.Resolve(ctx, ev.a, reply.token, Cookies{}); err != nil || !v.Locked || v.Reply || v.ReplyAllowed {
			t.Fatalf("locked reply view %+v, %v", v, err)
		}
		grant = ev.unlock(reply, "")
		if v, err := ev.svc.Resolve(ctx, ev.a, reply.token, Cookies{Grant: grant}); err != nil || !v.Reply || v.ReplyAllowed {
			t.Fatalf("unlocked reply view %+v, %v", v, err)
		}
	})
}

// TestReplyVerificationWithoutOption: a reply code is sent and confirmed
// for a transfer without the recipient verification option (P33); the
// cookie entry then opens the reply, and a held entry answers without a
// code. The download verification of such a link is still refused.
func TestReplyVerificationWithoutOption(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newReplyEnv(t, e)
		ctx := context.Background()
		p := ev.publish(ev.a, replySpec(spec{password: true}))

		_, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, false, "", "")
		wantErr(t, err, ErrVerificationNotNeeded)
		_, err = ev.confirm(p, "123456")
		wantErr(t, err, ErrNoChallenge)
		_, err = ev.svc.StartVerification(ctx, ev.a, p.token, netip.Addr{}, true, "", "")
		wantErr(t, err, ErrNoClientIP)

		ch, err := ev.startReply(p, "")
		if err != nil || ch == nil || ch.EmailMasked != MaskEmail(dave) || ch.AttemptsRemaining != store.MaxChallengeAttempts {
			t.Fatalf("start reply = %+v, %v", ch, err)
		}
		stored, err := ev.db.Challenges().LatestByLink(ctx, ev.a.ID, p.links[0].ID)
		if err != nil || stored.RecipientIntent != store.IntentReply || stored.Purpose != store.ChallengeRecipient {
			t.Fatalf("challenge %+v, %v", stored, err)
		}
		code := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, code)
		_, err = ev.confirm(p, wrongOf(code))
		var wrong *WrongCodeError
		if !errors.As(err, &wrong) {
			t.Fatalf("wrong reply code: %v", err)
		}
		cookie, err := ev.confirm(p, code)
		if err != nil {
			t.Fatalf("confirm reply: %v", err)
		}
		links, err := ev.db.RecipientLinks().ListByTransfer(ctx, ev.a.ID, p.id)
		if err != nil || links[0].VerifiedAt.IsZero() || !links[1].VerifiedAt.IsZero() {
			t.Fatalf("links %+v, %v", links, err)
		}
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{
			TenantID: ev.a.ID, Action: string(audit.ActionRecipientVerified), Limit: store.MaxPageSize,
		})
		if err != nil || len(page.Items) != 1 || !strings.Contains(string(page.Items[0].Details), `"intent":"reply"`) {
			t.Fatalf("audit %+v, %v", page.Items, err)
		}

		// The entry is held: no new code, and the reply opens without the
		// transfer password.
		if ch, err := ev.startReply(p, cookie); ch != nil || err != nil {
			t.Fatalf("start reply when verified = %+v, %v", ch, err)
		}
		target, err := ev.replyAccess(p, cookie)
		if err != nil {
			t.Fatalf("ReplyAccess: %v", err)
		}
		d := ev.get(p)
		want := ReplyTarget{
			TransferID: p.id, LinkID: p.links[0].ID, Email: dave, Recipient: alice,
			TransferExpiresAt: d.ExpiresAt, OriginalCreatedAt: d.CreatedAt,
		}
		if target != want {
			t.Fatalf("target %+v, want %+v", target, want)
		}
		// The entry is bound to its link: erin's link still needs a code.
		if _, err := ev.svc.ReplyAccess(ctx, ev.a, p.link(1).token, cookie, ipOne); !errors.Is(err, ErrRecipientVerificationRequired) {
			t.Fatalf("other link: %v", err)
		}
		if ch, err := ev.startReply(p.link(1), cookie); err != nil || ch == nil {
			t.Fatalf("start reply on the other link = %+v, %v", ch, err)
		}

		// A download code on a link without the option is never accepted
		// (it cannot be created through the service).
		dl := stored
		dl.ID, dl.RecipientIntent, dl.CreatedAt = "vch_0000000000000000000002", store.IntentDownload, ev.clock.now().Add(time.Second)
		if err := ev.db.Challenges().Create(ctx, ev.a.ID, dl); err != nil {
			t.Fatal(err)
		}
		_, err = ev.confirm(p, code)
		wantErr(t, err, ErrNoChallenge)

		// Without the reply option, confirming is not needed at all.
		ev.allowReply(ev.a, false)
		_, err = ev.confirm(p, code)
		wantErr(t, err, ErrVerificationNotNeeded)
		ev.allowReply(ev.a, true)

		// Failures of the tenant read and of the cookie check are internal.
		ev.f.set("tenant", 1, nil)
		_, err = ev.startReply(p, "")
		wantInternal(t, err)
		ev.f.set("tenant", 1, nil)
		_, err = ev.confirm(p, code)
		wantInternal(t, err)
		ev.f.set("verifyMAC", 1, nil)
		_, err = ev.startReply(p, cookie)
		wantInternal(t, err)
	})
}

// TestReplyVerificationWithOption: on a transfer with the option, a reply
// code and a download code confirm alike and give the same entry; the
// newest code of the link only is checked.
func TestReplyVerificationWithOption(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newReplyEnv(t, e)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))

		// A download code first, then a reply code: the download code is
		// replaced.
		ev.start(p, "")
		first := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, first)
		ev.clock.advance(time.Second) // a strictly newer code
		if _, err := ev.startReply(p, ""); err != nil {
			t.Fatal(err)
		}
		code := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, code)
		if first != code {
			_, err := ev.confirm(p, first)
			wantErr(t, err, ErrWrongCode)
		}
		cookie, err := ev.confirm(p, code)
		if err != nil {
			t.Fatalf("confirm reply code: %v", err)
		}
		// The reply code opens the download page too.
		if v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Verification: cookie}); err != nil || v.Locked || !v.Verified || !v.ReplyAllowed {
			t.Fatalf("view %+v, %v", v, err)
		}
		// Held: neither a download nor a reply code is sent.
		for _, reply := range []bool{false, true} {
			if ch, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, reply, "", cookie); ch != nil || err != nil {
				t.Fatalf("reply %v: start when verified = %+v, %v", reply, ch, err)
			}
		}
		if _, err := ev.replyAccess(p, cookie); err != nil {
			t.Fatalf("ReplyAccess: %v", err)
		}

		// A download code confirms as before, even when replies are off;
		// a reply code is refused then.
		ev.allowReply(ev.a, false)
		other := p.link(1)
		_, err = ev.startReply(other, "")
		wantErr(t, err, ErrReplyNotAllowed)
		if c := ev.verify(other, ""); c == "" {
			t.Fatal("no cookie")
		}
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{
			TenantID: ev.a.ID, Action: string(audit.ActionRecipientVerified), Limit: store.MaxPageSize,
		})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("audit %+v, %v", page.Items, err)
		}
		for _, it := range page.Items {
			hasIntent := strings.Contains(string(it.Details), `"intent":"reply"`)
			if hasIntent != (it.Actor == dave) {
				t.Fatalf("audit event of %s: %s", it.Actor, it.Details)
			}
		}
	})
}

// TestReplyAccessOrder checks every refusal of ReplyAccess, in the order of
// the specification.
func TestReplyAccessOrder(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newReplyEnv(t, e)
		ctx := context.Background()
		p := ev.publish(ev.a, replySpec(spec{maxDownloads: 1}))
		cookie := ev.verifyReply(p, "")

		_, err := ev.svc.ReplyAccess(ctx, ev.a, p.token, cookie, netip.Addr{})
		wantErr(t, err, ErrNoClientIP)
		// 1. Unknown, malformed, or of another tenant.
		_, err = ev.svc.ReplyAccess(ctx, ev.a, "dl_bad", cookie, ipOne)
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.ReplyAccess(ctx, ev.b, p.token, cookie, ipOne)
		wantErr(t, err, ErrNotFound)
		ev.f.set("linkByToken", 1, nil)
		_, err = ev.replyAccess(p, cookie)
		wantInternal(t, err)

		// 2. The tenant no longer allows replies, with or without a
		// verified cookie (before the cookie); a failed tenant read is
		// internal.
		ev.allowReply(ev.a, false)
		_, err = ev.replyAccess(p, cookie)
		wantErr(t, err, ErrReplyNotAllowed)
		_, err = ev.replyAccess(p, "")
		wantErr(t, err, ErrReplyNotAllowed)
		ev.allowReply(ev.a, true)
		ev.f.set("tenant", 1, nil)
		_, err = ev.replyAccess(p, cookie)
		wantInternal(t, err)

		// 3. No valid entry for this link, before the kind checks: a shared
		// link and the link of an ineligible sender answer the same.
		_, err = ev.replyAccess(p, "")
		wantErr(t, err, ErrRecipientVerificationRequired)
		ev.f.set("verifyMAC", 1, nil)
		_, err = ev.replyAccess(p, cookie)
		wantInternal(t, err)
		shared := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		_, err = ev.replyAccess(shared, cookie)
		wantErr(t, err, ErrRecipientVerificationRequired)
		ext := ev.publish(ev.a, replySpec(spec{sender: ev.fromExternal(ev.a)}))
		_, err = ev.replyAccess(ext, cookie)
		wantErr(t, err, ErrRecipientVerificationRequired)

		// 4. The sender kind: see TestReplyEligibility.

		// 5. The original sender is blocklisted or no longer internal:
		// refused, audited, never in the security log.
		events := len(ev.seclog.all())
		ev.f.set("blocked", 1, nil)
		_, err = ev.replyAccess(p, cookie)
		wantInternal(t, err)
		ev.f.set("networkRules", 1, nil)
		_, err = ev.replyAccess(p, cookie)
		wantInternal(t, err)
		ev.internalDomains(ev.a, "entity-z.example.com")
		_, err = ev.replyAccess(p, cookie)
		wantErr(t, err, ErrReplyNotAllowed)
		// Without its own audit write, the refusal stands.
		ev.f.set("record", 1, nil)
		_, err = ev.replyAccess(p, cookie)
		wantErr(t, err, ErrReplyNotAllowed)
		if ev.logs.count("audit write failed") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		ev.internalDomains(ev.a, internalDomain)
		unblock := ev.block(ev.a, store.BlockDomain, internalDomain)
		_, err = ev.replyAccess(p, cookie)
		wantErr(t, err, ErrReplyNotAllowed)
		unblock()
		unblock = ev.block(ev.a, store.BlockEmail, alice)
		_, err = ev.replyAccess(p, cookie)
		wantErr(t, err, ErrReplyNotAllowed)
		unblock()
		reasons := map[string]int{}
		for _, r := range ev.refusals(ev.a.ID) {
			if r.Actor != dave || r.ObjectID != p.id || !strings.Contains(string(r.Details), `"origin":"reply"`) ||
				strings.Contains(string(r.Details), "@") {
				t.Fatalf("refusal %+v %s", r, r.Details)
			}
			for _, reason := range []string{"blocklist", "domain"} {
				if strings.Contains(string(r.Details), `"reason":"`+reason+`"`) {
					reasons[reason]++
				}
			}
		}
		if reasons["blocklist"] != 2 || reasons["domain"] != 1 {
			t.Fatalf("refusal reasons %v", reasons)
		}
		if n := len(ev.seclog.all()); n != events {
			t.Fatalf("%d security events for a policy refusal", n-events)
		}

		// 6. The original is no longer available: download limit reached,
		// or ended.
		if _, err := ev.replyAccess(p, cookie); err != nil {
			t.Fatalf("ReplyAccess: %v", err)
		}
		f := ev.open(p, p.files[0].ID)
		if err := f.Content.Begin(true); err != nil {
			t.Fatal(err)
		}
		if err := f.Content.Close(ctx); err != nil {
			t.Fatal(err)
		}
		_, err = ev.replyAccess(p, cookie)
		wantErr(t, err, ErrGone)

		q := ev.publish(ev.a, replySpec(spec{}))
		qc := ev.verifyReply(q, "")
		ev.setStatus(q, store.TransferExpired)
		_, err = ev.replyAccess(q, qc)
		wantErr(t, err, ErrGone)
		// Gone comes last: a gone transfer that could not be replied to is
		// refused as such, and so is one of a blocklisted sender.
		unblock = ev.block(ev.a, store.BlockEmail, alice)
		_, err = ev.replyAccess(q, qc)
		wantErr(t, err, ErrReplyNotAllowed)
		unblock()
		ev.allowReply(ev.a, false)
		_, err = ev.replyAccess(q, qc)
		wantErr(t, err, ErrReplyNotAllowed)
	})
}

// TestReplyAccessExpiry: a reply is refused once the original transfer has
// expired, even before the sweep.
func TestReplyAccessExpiry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newReplyEnv(t, e)
		p := ev.publish(ev.a, replySpec(spec{}))
		d := ev.get(p)
		ev.clock.advance(d.ExpiresAt.Sub(ev.clock.now()) - VerificationTTL/2)
		cookie := ev.verifyReply(p, "")
		ev.clock.advance(VerificationTTL / 2)
		_, err := ev.replyAccess(p, cookie)
		wantErr(t, err, ErrGone)
	})
}
