package download

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/vcode"
)

// erin is a second recipient of the per-recipient transfers.
const erin = "erin@partner.example.org"

// verified publishes spec sp as a per-recipient transfer of tn requiring
// the recipient verification, for dave and erin.
func (ev *env) verifiedSpec(sp spec) spec {
	sp.perRecipient, sp.verify, sp.recipients = true, true, []string{dave, erin}
	if len(sp.contents) == 0 {
		sp.contents = [][]byte{random(3000), random(10)}
	}
	return sp
}

// start asks a code for p from ipOne and returns the challenge.
func (ev *env) start(p published, cookie string) *Challenge {
	ev.t.Helper()
	ch, err := ev.svc.StartVerification(context.Background(), p.tn, p.token, ipOne, false, "fr", cookie)
	if err != nil {
		ev.t.Fatalf("StartVerification: %v", err)
	}
	return ch
}

// verify asks a code for p, confirms it and returns the verification
// cookie built on cookie.
func (ev *env) verify(p published, cookie string) string {
	ev.t.Helper()
	ev.start(p, cookie)
	c, err := ev.svc.ConfirmVerification(context.Background(), p.tn, p.token, ipOne, ev.notifier.lastCode(ev.t), cookie)
	if err != nil {
		ev.t.Fatalf("ConfirmVerification: %v", err)
	}
	return c
}

// confirm submits code for p from ipOne.
func (ev *env) confirm(p published, code string) (string, error) {
	return ev.svc.ConfirmVerification(context.Background(), p.tn, p.token, ipOne, code, "")
}

// wrongOf returns a 6-digit code different from code.
func wrongOf(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// codeMails returns the recipient code mails enqueued.
func (ev *env) codeMails() []mail.Job {
	var out []mail.Job
	for _, j := range ev.queue.snapshot() {
		if j.Template == mail.TemplateRecipientVerificationCode {
			out = append(out, j)
		}
	}
	return out
}

func TestMaskEmail(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"carol@customer.example.net": "c***@customer.example.net",
		"élodie@example.com":         "é***@example.com",
		"@example.com":               "***@example.com",
		"\xff@example.com":           "***@example.com",
		"no-at-sign":                 "***",
	} {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRecipientLinkResolution: a recipient link resolves its own transfer,
// a shared V1 link still resolves, and a link is never valid under another
// tenant (P9, T-204).
func TestRecipientLinkResolution(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}})
		for i := range p.tokens {
			v, err := ev.svc.Resolve(ctx, ev.a, p.link(i).token, Cookies{})
			if err != nil || v.TransferID != p.id || v.Locked || v.VerificationRequired || v.RecipientEmailMasked != "" || len(v.Files) != 1 {
				t.Fatalf("link %d: %+v, %v", i, v, err)
			}
		}
		shared := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		if v, err := ev.svc.Resolve(ctx, ev.a, shared.token, Cookies{}); err != nil || v.TransferID != shared.id {
			t.Fatalf("shared link: %+v, %v", v, err)
		}
		// Under the FQDN of tenant B: unknown, for every operation.
		_, err := ev.svc.Resolve(ctx, ev.b, p.token, Cookies{})
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.OpenFile(ctx, ev.b, p.token, ipOne, Cookies{}, p.files[0].ID)
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.PrepareArchive(ctx, ev.b, p.token, ipOne, Cookies{})
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.Unlock(ctx, ev.b, p.token, ipOne, password, Cookies{})
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.StartVerification(ctx, ev.b, p.token, ipOne, false, "", "")
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.ConfirmVerification(ctx, ev.b, p.token, ipOne, "123456", "")
		wantErr(t, err, ErrNotFound)

		// A failure of the link lookup is internal; a transfer gone between
		// the two reads is unknown.
		ev.f.set("linkByToken", 1, nil)
		_, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		wantInternal(t, err)
		ev.f.set("transfer", 1, store.ErrNotFound)
		_, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		wantErr(t, err, ErrNotFound)
		ev.f.set("transfer", 1, nil)
		_, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		wantInternal(t, err)

		// An ended transfer is gone through its links too.
		ev.setStatus(p, store.TransferExpired)
		_, err = ev.svc.Resolve(ctx, ev.a, p.link(1).token, Cookies{})
		wantErr(t, err, ErrGone)
	})
}

// TestVerificationNotNeeded: a shared link, a per-recipient transfer
// without the option, and a reply get ErrVerificationNotNeeded.
func TestVerificationNotNeeded(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		shared := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		plain := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, perRecipient: true})
		withOption := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		for _, p := range []published{shared, plain} {
			_, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, false, "", "")
			wantErr(t, err, ErrVerificationNotNeeded)
			_, err = ev.svc.ConfirmVerification(ctx, ev.a, p.token, ipOne, "123456", "")
			wantErr(t, err, ErrVerificationNotNeeded)
		}
		_, err := ev.svc.StartVerification(ctx, ev.a, withOption.token, ipOne, true, "", "")
		wantErr(t, err, ErrVerificationNotNeeded)
		_, err = ev.svc.StartVerification(ctx, ev.a, "dl_bad", ipOne, false, "", "")
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.ConfirmVerification(ctx, ev.a, withOption.token, ipOne, "12345a", "")
		wantErr(t, err, ErrInvalidCode)
		if len(ev.codeMails()) != 0 {
			t.Fatal("a code was mailed")
		}
	})
}

// TestVerificationLocksTheLink: without a valid verification entry, the page
// is the minimal locked view and nothing else is served (T-200, T-203).
func TestVerificationLocksTheLink(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{password: true, level: true, maxDownloads: 3}))
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		want := View{
			TransferID: p.id, SenderEmail: alice, ExpiresAt: ev.get(p).ExpiresAt, PasswordProtected: true, Locked: true,
			VerificationRequired: true, RecipientEmailMasked: "d***@customer.example.net",
		}
		if v.Message != "" || v.Files != nil || v.Confidentiality != nil || v.DownloadsRemaining != nil || v.ArchiveAvailable ||
			v.TransferID != want.TransferID || v.SenderEmail != want.SenderEmail || !v.ExpiresAt.Equal(want.ExpiresAt) ||
			v.PasswordProtected != want.PasswordProtected || v.Locked != want.Locked || v.Verified ||
			v.VerificationRequired != want.VerificationRequired || v.RecipientEmailMasked != want.RecipientEmailMasked {
			t.Fatalf("locked view %+v", v)
		}
		if v, _ := ev.svc.Resolve(ctx, ev.a, p.link(1).token, Cookies{}); v.RecipientEmailMasked != "e***@partner.example.org" {
			t.Fatalf("second link masked %q", v.RecipientEmailMasked)
		}
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		wantErr(t, err, ErrVerificationRequired)
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		wantErr(t, err, ErrVerificationRequired)
		// No password attempt is counted before the verification.
		for range store.MaxPasswordFailures + 1 {
			_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong", Cookies{})
			wantErr(t, err, ErrVerificationRequired)
		}
		if n := ev.seclog.count(securitylog.TransferPasswordInvalid); n != 0 {
			t.Fatalf("%d password events", n)
		}
		rv := ev.verify(p, "")
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong", Cookies{Verification: rv})
		var wrong *WrongPasswordError
		if !errors.As(err, &wrong) || wrong.Remaining != store.MaxPasswordFailures-1 {
			t.Fatalf("first wrong password after verification: %v", err)
		}
		// Verified but not unlocked: still locked, without the masked address.
		v, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Verification: rv})
		if err != nil || !v.Locked || !v.Verified || !v.VerificationRequired || v.RecipientEmailMasked != "" || v.Files != nil {
			t.Fatalf("verified, locked view %+v, %v", v, err)
		}
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{Verification: rv}, p.files[0].ID)
		wantErr(t, err, ErrDownloadLocked)
		grant, err := ev.svc.Unlock(ctx, ev.a, p.token, ipOne, password, Cookies{Verification: rv})
		if err != nil {
			t.Fatal(err)
		}
		both := Cookies{Grant: grant, Verification: rv}
		v, err = ev.svc.Resolve(ctx, ev.a, p.token, both)
		if err != nil || v.Locked || !v.Verified || len(v.Files) != 2 || v.Confidentiality == nil || v.DownloadsRemaining == nil {
			t.Fatalf("open view %+v, %v", v, err)
		}
		// The grant alone does not open the link.
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{Grant: grant}, p.files[0].ID)
		wantErr(t, err, ErrVerificationRequired)
		// Both cookies are worthless for the other link of the transfer.
		v, err = ev.svc.Resolve(ctx, ev.a, p.link(1).token, both)
		if err != nil || !v.Locked || v.Verified {
			t.Fatalf("other link with the cookies of the first: %+v, %v", v, err)
		}
	})
}

// TestVerificationFlow walks the codes of a link: sent to its own address,
// two attempts, replaced by a new code, consumed once, and the cookie.
func TestVerificationFlow(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		now := ev.clock.now()

		// Never requested.
		_, err := ev.confirm(p, "123456")
		wantErr(t, err, ErrNoChallenge)

		ch := ev.start(p, "")
		if ch == nil || ch.EmailMasked != "d***@customer.example.net" || !ch.ExpiresAt.Equal(now.Add(vcode.TTL)) ||
			ch.AttemptsRemaining != store.MaxChallengeAttempts {
			t.Fatalf("challenge %+v", ch)
		}
		mails := ev.codeMails()
		if len(mails) != 1 || len(mails[0].Message.To) != 1 || mails[0].Message.To[0] != dave {
			t.Fatalf("code mails %+v", mails)
		}
		code := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, code)
		if !strings.Contains(mails[0].Message.Text, code) {
			t.Fatal("the mail does not carry the code")
		}

		// Two wrong codes exhaust it; each one is a security event.
		_, err = ev.confirm(p, wrongOf(code))
		var wrong *WrongCodeError
		if !errors.As(err, &wrong) || wrong.Remaining != 1 {
			t.Fatalf("first wrong code: %v", err)
		}
		_, err = ev.confirm(p, wrongOf(code))
		wantErr(t, err, ErrVerificationExhausted)
		_, err = ev.confirm(p, code)
		wantErr(t, err, ErrVerificationExhausted)
		events := ev.seclog.all()
		if len(events) != 2 {
			t.Fatalf("security events %+v", events)
		}
		for _, sev := range events {
			if sev.Type != securitylog.VerificationCodeInvalid || sev.IP != ipOne || sev.Tenant != hostA || len(sev.Fields) != 2 ||
				sev.Fields[0] != (securitylog.Field{Key: keyTransfer, Value: p.id[:transferIDLogLen]}) ||
				sev.Fields[1] != (securitylog.Field{Key: securitylog.KeyPurpose, Value: securitylog.PurposeRecipient}) {
				t.Fatalf("security event %+v", sev)
			}
		}

		// A new code replaces the exhausted one; the old code is worthless.
		ev.clock.advance(time.Second)
		ev.start(p, "")
		second := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, second)
		if second != code {
			if _, err := ev.confirm(p, code); !errors.Is(err, ErrWrongCode) {
				t.Fatalf("old code accepted or refused oddly: %v", err)
			}
		}
		ev.clock.advance(time.Second)
		ev.start(p, "")
		third := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, third)
		cookie, err := ev.confirm(p, third)
		if err != nil || !strings.HasPrefix(cookie, VerificationCookiePrefix) {
			t.Fatalf("confirm = %q, %v", cookie, err)
		}
		// Used once.
		_, err = ev.confirm(p, third)
		wantErr(t, err, ErrNoChallenge)

		links, err := ev.db.RecipientLinks().ListByTransfer(ctx, ev.a.ID, p.id)
		if err != nil || !links[0].VerifiedAt.Equal(ev.clock.now()) || !links[1].VerifiedAt.IsZero() {
			t.Fatalf("links %+v, %v", links, err)
		}
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{
			TenantID: ev.a.ID, Action: string(audit.ActionRecipientVerified), Limit: store.MaxPageSize,
		})
		if err != nil || len(page.Items) != 1 || page.Items[0].Actor != dave || page.Items[0].ObjectID != p.id ||
			!strings.Contains(string(page.Items[0].Details), p.links[0].ID) || strings.Contains(string(page.Items[0].Details), third) {
			t.Fatalf("audit %+v, %v", page.Items, err)
		}

		// The browser is verified: no new code, and the page opens.
		if ch, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, false, "", cookie); ch != nil || err != nil {
			t.Fatalf("start when verified = %+v, %v", ch, err)
		}
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Verification: cookie})
		if err != nil || v.Locked || !v.Verified || !v.VerificationRequired || len(v.Files) != 2 {
			t.Fatalf("verified view %+v, %v", v, err)
		}
		// The cookie expires with its entry.
		ev.clock.advance(VerificationTTL)
		if v, _ := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Verification: cookie}); !v.Locked || v.Verified {
			t.Fatalf("expired cookie still verifies: %+v", v)
		}

		// A code expires after vcode.TTL.
		ev.start(p, "")
		ev.clock.advance(vcode.TTL)
		_, err = ev.confirm(p, ev.notifier.lastCode(t))
		wantErr(t, err, ErrNoChallenge)
	})
}

// TestVerificationCookie: an entry is bound to its link and its tenant, the
// grant cookie never verifies, and the entries of several links share one
// cookie (T-200, T-204).
func TestVerificationCookie(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		q := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		r := ev.publish(ev.b, ev.verifiedSpec(spec{}))
		cookie := ev.verify(p, "")
		for name, other := range map[string]published{"other link": p.link(1), "other transfer": q, "other tenant": r} {
			v, err := ev.svc.Resolve(ctx, other.tn, other.token, Cookies{Verification: cookie})
			if err != nil || !v.Locked || v.Verified {
				t.Errorf("%s: %+v, %v", name, v, err)
			}
		}
		// The same entry under the grant prefix, or the grant cookie of the
		// link under the verification prefix, verifies nothing.
		asGrant := GrantCookiePrefix + strings.TrimPrefix(cookie, VerificationCookiePrefix)
		if ok, err := ev.svc.granted(asGrant, ev.a.ID, p.links[0].ID, ev.clock.now()); ok || err != nil {
			t.Fatalf("verification entry accepted as a grant: %v, %v", ok, err)
		}
		grant, err := ev.svc.grant("", ev.a.ID, p.links[0].ID, ev.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		asVerification := VerificationCookiePrefix + strings.TrimPrefix(grant, GrantCookiePrefix)
		if v, _ := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Verification: asVerification}); v.Verified {
			t.Fatal("grant entry accepted as a verification")
		}
		// A second link verified on the same browser keeps the first one.
		both := ev.verify(q, cookie)
		if n := len(parseVerifications(both)); n != 2 {
			t.Fatalf("%d entries", n)
		}
		for _, x := range []published{p, q} {
			if v, _ := ev.svc.Resolve(ctx, ev.a, x.token, Cookies{Verification: both}); !v.Verified {
				t.Fatalf("link of %s not verified by the shared cookie", x.id)
			}
		}
		// A MAC failure while checking the cookie is internal.
		ev.f.set("verifyMAC", 1, nil)
		_, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Verification: cookie})
		wantInternal(t, err)
	})
}

// TestVerificationBudgets: 5 codes per link and hour, 20 per IP and hour
// shared with the deposit codes, both written to the security log; the
// window slides (T-201, T-202).
func TestVerificationBudgets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		for range vcode.MaxPerAddress {
			ev.start(p, "")
			ev.clock.advance(time.Minute)
		}
		_, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, false, "", "")
		var limited *RateLimitError
		if !errors.As(err, &limited) || limited.RetryAfter != vcode.Window {
			t.Fatalf("sixth code: %v", err)
		}
		if got := ev.seclog.all(); len(got) != 1 || got[0].Type != securitylog.RateLimited ||
			got[0].Fields[1] != (securitylog.Field{Key: securitylog.KeyScope, Value: scopeCodesPerLink}) {
			t.Fatalf("security events %+v", got)
		}
		// The other link has its own budget.
		ev.start(p.link(1), "")
		// An hour after the first code, the budget allows a new one, and the code
		// works.
		ev.clock.advance(vcode.Window - time.Duration(vcode.MaxPerAddress)*time.Minute + time.Millisecond)
		ev.start(p, "")
		if _, err := ev.confirm(p, ev.notifier.lastCode(t)); err != nil {
			t.Fatalf("code after the window: %v", err)
		}

		// The per-IP budget counts the deposit codes too.
		q := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		now := ev.clock.now()
		for range vcode.MaxPerIP {
			chID, err := id.NewToken(id.ChallengeTokenPrefix, id.ChallengeTokenBytes)
			if err != nil {
				t.Fatal(err)
			}
			err = ev.db.Challenges().Create(ctx, ev.a.ID, store.Challenge{
				ID: chID, Email: alice, CodeMAC: []byte{1}, AttemptsRemaining: 1, ClientIP: ipTwo,
				CreatedAt: now, ExpiresAt: now.Add(vcode.TTL),
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		_, err = ev.svc.StartVerification(ctx, ev.a, q.token, ipTwo, false, "", "")
		if !errors.As(err, &limited) {
			t.Fatalf("code over the IP budget: %v", err)
		}
		last := ev.seclog.all()[len(ev.seclog.all())-1]
		if last.Fields[1].Value != scopeCodesPerIP {
			t.Fatalf("scope %+v", last)
		}
		_, err = ev.svc.StartVerification(ctx, ev.a, q.token, netip.Addr{}, false, "", "")
		wantErr(t, err, ErrNoClientIP)
	})
}

// TestVerificationMailFailures: the tenant without SMTP, the queue refusing
// the code mail (the challenge is then discarded) and the mail that cannot
// be built.
func TestVerificationMailFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		c := ev.publish(ev.c, ev.verifiedSpec(spec{}))
		_, err := ev.svc.StartVerification(ctx, ev.c, c.token, ipOne, false, "", "")
		wantErr(t, err, ErrMailUnavailable)

		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		start := func() error {
			_, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, false, "en", "")
			return err
		}
		ev.queue.errs = []error{mail.ErrQueueFull}
		var limited *RateLimitError
		if err := start(); !errors.As(err, &limited) || limited.RetryAfter != vcode.QueueFullRetryAfter {
			t.Fatalf("queue full: %v", err)
		}
		for _, qerr := range []error{mail.ErrQueueClosed, mail.ErrCircuitOpen, mail.ErrInvalidSettings} {
			ev.queue.errs = []error{qerr}
			wantErr(t, start(), ErrMailUnavailable)
		}
		ev.queue.errs = []error{errFault}
		wantInternal(t, start())
		// Every refused code was discarded: none counts against the budget,
		// and no code is pending.
		n, err := ev.db.Challenges().CountByLinkSince(ctx, ev.a.ID, p.links[0].ID, ev.clock.now().Add(-time.Hour))
		if err != nil || n != 0 {
			t.Fatalf("%d challenges left, %v", n, err)
		}
		_, err = ev.confirm(p, "123456")
		wantErr(t, err, ErrNoChallenge)
		// A discard failure is logged.
		ev.queue.errs = []error{mail.ErrQueueClosed}
		ev.f.set("deleteChallenge", 1, nil)
		wantErr(t, start(), ErrMailUnavailable)
		if ev.logs.count("unsent verification challenge not discarded") != 1 {
			t.Fatal("discard failure not logged")
		}
		ev.f.set("codeMail", 1, nil)
		wantInternal(t, start())
	})
}

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestVerificationFaults covers the internal failures of both operations.
func TestVerificationFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		start := func() error {
			_, err := ev.svc.StartVerification(ctx, ev.a, p.token, ipOne, false, "", "")
			return err
		}
		for _, fault := range []string{"mac", "createChallenge"} {
			ev.f.set(fault, 1, nil)
			wantInternal(t, start())
		}
		// Even a conflict on the identifier is an internal error: it is
		// random, so a collision never happens in practice.
		ev.f.set("createChallenge", 1, store.ErrConflict)
		wantInternal(t, start())
		// The identifier cannot be generated.
		ev.svc.newToken = func(string, int) (string, error) { return "", io.ErrUnexpectedEOF }
		wantInternal(t, start())
		ev.svc.newToken = id.NewToken
		// The random source failing.
		ev.svc.rand = failingReader{}
		wantInternal(t, start())
		ev.svc.rand = rand.Reader

		// Confirmation.
		ev.clock.advance(time.Second)
		ev.start(p, "")
		code := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, code)
		for _, fault := range []string{"latestChallenge", "verifyMAC", "verified"} {
			ev.f.set(fault, 1, nil)
			_, err := ev.confirm(p, code)
			wantInternal(t, err)
		}
		ev.f.set("verified", 1, store.ErrNotFound)
		_, err := ev.confirm(p, code)
		wantErr(t, err, ErrNoChallenge)
		ev.f.set("spend", 1, nil)
		_, err = ev.confirm(p, wrongOf(code))
		wantInternal(t, err)
		ev.f.set("spend", 1, store.ErrNotFound)
		_, err = ev.confirm(p, wrongOf(code))
		wantErr(t, err, ErrVerificationExhausted)
		// The cookie cannot be computed.
		ev.f.hook["verified"] = func() { ev.f.set("mac", 1, nil) }
		_, err = ev.confirm(p, code)
		wantInternal(t, err)
	})
}

// TestVerificationIgnoresReplyCodes: only the newest code of the link is
// checked, and a reply code never verifies a download, even when it is the
// newest.
func TestVerificationIgnoresReplyCodes(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		ev.start(p, "")
		code := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, code)
		ch, err := ev.svc.repo.latestChallenge(ctx, ev.a.ID, p.links[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		reply := ch
		reply.ID, reply.RecipientIntent = "vch_0000000000000000000001", store.IntentReply
		reply.CreatedAt = ch.CreatedAt.Add(time.Second)
		if err := ev.db.Challenges().Create(ctx, ev.a.ID, reply); err != nil {
			t.Fatal(err)
		}
		_, err = ev.confirm(p, code)
		wantErr(t, err, ErrNoChallenge)
	})
}

// TestVerificationMaxDownloads sends no code through a link whose transfer
// reached its download limit: the answer is the one of the page.
func TestVerificationMaxDownloads(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{maxDownloads: 1}))
		cookie := ev.verify(p, "")
		f, err := ev.svc.OpenFile(ctx, p.tn, p.token, ipOne, Cookies{Verification: cookie}, p.files[0].ID)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if err := f.Content.Begin(true); err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if err := f.Content.Close(ctx); err != nil {
			t.Fatal(err)
		}
		sent := len(ev.codeMails())
		_, err = ev.svc.StartVerification(ctx, ev.a, p.link(1).token, ipOne, false, "", "")
		wantErr(t, err, ErrMaxDownloads)
		if len(ev.codeMails()) != sent {
			t.Fatal("a code was sent for a transfer at its download limit")
		}
	})
}

// TestConfirmVerificationNeedsClientIP refuses a confirmation without a
// valid client IP before spending an attempt.
func TestConfirmVerificationNeedsClientIP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{}))
		ev.start(p, "")
		code := ev.notifier.lastCode(t)
		ev.secrets = append(ev.secrets, code)
		_, err := ev.svc.ConfirmVerification(ctx, p.tn, p.token, netip.Addr{}, wrongOf(code), "")
		wantErr(t, err, ErrNoClientIP)
		if n := len(ev.seclog.all()); n != 0 {
			t.Fatalf("%d security events", n)
		}
		_, err = ev.confirm(p, wrongOf(code))
		var wrong *WrongCodeError
		if !errors.As(err, &wrong) || wrong.Remaining != store.MaxChallengeAttempts-1 {
			t.Fatalf("an attempt was spent without client IP: %v", err)
		}
	})
}
