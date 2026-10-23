package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// The tests of this file exercise the identification of depositors end to
// end (CLAUDE.md sections 6 to 9, 16.2 and 16.3; threats T-09 to T-22,
// T-93 and T-101): the real server, both database engines, tenants on
// *.localhost hosts configured through the store, and Mailpit receiving
// the mails over a plain SMTP relay. Cross-tenant access for every
// operation is covered by test/isolation/http; only real-flow checks are
// added here.

// TestDepositInternalFlow covers the internal depositor: a code mailed in
// the negotiated language, the session cookie and its attributes, the
// session body, CSRF protection of the unsafe method and the end of the
// session.
func TestDepositInternalFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)

		subjects := map[string]string{
			"fr": "Votre code de vérification pour " + nameA,
			"en": "Your verification code for " + nameA,
			"":   "Your verification code for " + nameA, // tenant default
		}
		for _, lang := range []string{"fr", "en", ""} {
			c := d.newDepositor()
			c.lang = lang
			email := uniqueEmail(t, "lang"+lang, domainA)
			expectChallenge(t, c.start(t, email, ""), email)
			msg, _ := d.codeMail(t, email)
			if msg.Subject != subjects[lang] {
				t.Errorf("Accept-Language %q: subject %q, want %q", lang, msg.Subject, subjects[lang])
			}
			want := lang
			if want == "" {
				want = "en"
			}
			if !strings.Contains(msg.HTML, `lang="`+want+`"`) {
				t.Errorf("Accept-Language %q: HTML part not in %s", lang, want)
			}
			if msg.From.Address != "noreply@"+domainA || msg.From.Name != nameA {
				t.Errorf("From = %+v, want the tenant sender", msg.From)
			}
		}

		c := d.newDepositor()
		c.lang = "fr-FR,fr;q=0.9"
		email := uniqueEmail(t, "Alice", domainA)
		ch := expectChallenge(t, c.start(t, email, ""), email)
		msg, code := d.codeMail(t, email)
		if !strings.HasPrefix(msg.Subject, "Votre code") {
			t.Errorf("subject %q, want French", msg.Subject)
		}
		s, token := expectSession(t, c.confirm(t, ch.ChallengeID, code), email)
		if s.Kind != "internal" || !s.CanInvite || s.Invitation != nil {
			t.Errorf("session = %+v, want internal, canInvite, no invitation", s)
		}
		c.cookie = token

		resp := c.current(t)
		if resp.status != http.StatusOK {
			t.Fatalf("current: %d %s", resp.status, resp.body)
		}
		cur := expectSessionBody(t, resp.body, email)
		if cur.CSRFToken != s.CSRFToken || cur.Kind != "internal" || !cur.ExpiresAt.Equal(s.ExpiresAt) {
			t.Errorf("current = %+v, want the session opened by confirm %+v", cur, s)
		}
		c.csrf = cur.CSRFToken

		// The code is single-use.
		expectProblem(t, c.confirm(t, ch.ChallengeID, code), http.StatusGone, "verification-exhausted")

		for _, tc := range []struct {
			name  string
			extra http.Header
		}{
			{"no CSRF token", nil},
			{"forged CSRF token", http.Header{hdrCSRF: {"csrf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}},
			{"foreign Origin", c.withCSRF("Origin", "https://evil.example.net")},
			{"plain http Origin", c.withCSRF("Origin", "http://"+hostA)},
			{"cross-site fetch", c.withCSRF("Sec-Fetch-Site", "cross-site")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resp := c.end(t, tc.extra)
				expectProblem(t, resp, http.StatusForbidden, "csrf-invalid")
				if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
					t.Errorf("refused DELETE sets a cookie: %q", sc)
				}
			})
		}
		if st := c.current(t).status; st != http.StatusOK {
			t.Fatalf("session ended by a refused DELETE: current %d", st)
		}

		resp = c.end(t, c.withCSRF("Origin", "https://"+hostA, "Sec-Fetch-Site", "same-origin"))
		if resp.status != http.StatusNoContent || len(resp.body) != 0 {
			t.Fatalf("end: %d %q, want an empty 204", resp.status, resp.body)
		}
		cleared, err := http.ParseSetCookie(resp.header.Get("Set-Cookie"))
		if err != nil || cleared.Name != depositCookieName || cleared.Value != "" || cleared.MaxAge >= 0 ||
			!cleared.Secure || !cleared.HttpOnly || cleared.Path != "/" {
			t.Errorf("end Set-Cookie = %q (%v), want the cookie cleared", resp.header.Get("Set-Cookie"), err)
		}
		expectProblem(t, c.current(t), http.StatusUnauthorized, "unauthenticated")
		expectProblem(t, c.end(t, c.withCSRF()), http.StatusUnauthorized, "unauthenticated")

		noSecretInLogs(t, d.server, code, token, s.CSRFToken, ch.ChallengeID)
		if sec := strings.Join(d.securityLines(t), "\n"); strings.Contains(strings.ToLower(sec), strings.ToLower(email)) {
			t.Error("the security log contains the depositor's address")
		}
	})
}

// TestDepositLoopbackPeer covers the client IP read from the TCP peer when
// no trusted proxy is declared: the loopback in a tenant range is
// internal, and an X-Forwarded-For header naming an internal address is
// ignored (T-05).
func TestDepositLoopbackPeer(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		mp := mailpitEnv(t)
		s := startServer(t, e, serverOptions{})
		db, err := store.Open(context.Background(), e.Config())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		d := &depositEnv{server: s, db: db, mp: mp}
		if err := db.SMTPSettings().Put(context.Background(), s.tenantA.ID, store.SMTPConfig{
			Host: mp.host, Port: mp.port, Security: store.SMTPSecurityNone, FromAddress: "noreply@" + domainA,
		}); err != nil {
			t.Fatal(err)
		}

		// Only 192.0.2.0/24 is internal: a spoofed XFF does not help.
		d.setRules(t, true, []string{internalNetA}, domainA)
		c := &depositor{d: d, host: hostA, ip: insideA}
		expectProblem(t, c.start(t, uniqueEmail(t, "spoof", domainA), ""), http.StatusForbidden, "deposit-not-allowed")
		refused := eventsOf(t, d.securityLines(t), "deposit_refused")
		if len(refused) != 1 || refused[0].ip != "127.0.0.1" || refused[0].fields != ` reason="ip"` {
			t.Errorf("deposit_refused lines = %+v, want one with ip=127.0.0.1 reason ip", refused)
		}

		// The loopback itself is internal.
		d.setRules(t, true, []string{"127.0.0.0/8"}, domainA)
		c.ip = ""
		email := uniqueEmail(t, "loop", domainA)
		c.openSession(t, email, "")
		if st := c.current(t).status; st != http.StatusOK {
			t.Errorf("current: %d, want 200", st)
		}
	})
}

// TestDepositAlreadyVerified covers spec 7 with decision B: a verified
// internal address gets a session at once (201) only from a browser
// presenting the recognition cookie set when that address confirmed a
// code; any other browser (no cookie, junk, another address's entry) gets
// a code again (202).
func TestDepositAlreadyVerified(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		email := uniqueEmail(t, "verified", domainA)
		first := d.newDepositor()
		s1 := first.openSession(t, email, "")
		if first.known == "" {
			t.Fatal("confirm did not set the recognition cookie")
		}

		// Another browser of the same internal network: a code again.
		other := d.newDepositor()
		expectChallenge(t, other.start(t, email, ""), email)

		// A junk or tampered cookie is ignored: a code again.
		// (At most 5 codes per address and hour: this test uses all 5.)
		for _, junk := range []string{"junk%zz", first.known + "x"} {
			c := d.newDepositor()
			c.known = junk
			expectChallenge(t, c.start(t, email, ""), email)
		}

		// The entry of another verified address does not open this one.
		colleague := uniqueEmail(t, "colleague", domainA)
		peer := d.newDepositor()
		peer.openSession(t, colleague, "")
		foreign := d.newDepositor()
		foreign.known = peer.known
		expectChallenge(t, foreign.start(t, email, ""), email)

		// The browser that confirmed the code: a session at once, and the
		// recognition cookie renewed.
		second := d.newDepositor()
		second.known = first.known
		s2, token, renewed := expectSessionWithKnown(t, second.start(t, strings.ToUpper(email), ""), email)
		if s2.Kind != "internal" || !s2.CanInvite {
			t.Errorf("second session = %+v, want internal", s2)
		}
		if renewed == "" {
			t.Error("the recognition cookie was not renewed")
		}
		if token == first.cookie || s2.CSRFToken == s1.CSRFToken {
			t.Error("the second start reused the first session")
		}
		second.cookie = token
		if st := second.current(t).status; st != http.StatusOK {
			t.Errorf("second session current: %d", st)
		}
		if st := first.current(t).status; st != http.StatusOK {
			t.Errorf("first session ended by the second: current %d", st)
		}

		// A browser remembering both addresses (entries separated by ".")
		// opens either at once.
		both := d.newDepositor()
		both.known = peer.known + "." + first.known
		expectSession(t, both.start(t, email, ""), email)
		expectSession(t, both.start(t, colleague, ""), colleague)

		// Mails: the first code and one per start without a valid cookie
		// (other browser, 2 junk cookies, foreign entry), never the
		// recognized starts. Mails of one tenant are delivered in order, so
		// once a later one is handled every earlier one was too.
		sentinel := uniqueEmail(t, "sentinel", domainA)
		expectChallenge(t, d.newDepositor().start(t, sentinel, ""), sentinel)
		d.waitMailSent(t, sentinel)
		if n := d.mailSentLines(t, email); n != 5 {
			t.Errorf("%d mails sent to the verified address, want 5", n)
		}

		// The rule is still enforced for a recognized address.
		outsider := &depositor{d: d, host: hostA, ip: outside, known: first.known}
		expectProblem(t, outsider.start(t, email, ""), http.StatusForbidden, "deposit-not-allowed")
	})
}

// TestDepositWrongCode covers spec 7: two wrong codes invalidate the
// challenge (422 with one attempt left, then 410, after which even the
// right code is refused), each logged as verification_code_invalid
// without any code.
func TestDepositWrongCode(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		c := d.newDepositor()
		email := uniqueEmail(t, "wrong", domainA)
		ch := expectChallenge(t, c.start(t, email, ""), email)
		_, code := d.codeMail(t, email)
		n, _ := strconv.Atoi(code)
		wrong1, wrong2 := fmt.Sprintf("%06d", (n+1)%1_000_000), fmt.Sprintf("%06d", (n+500_000)%1_000_000)

		// A malformed code spends no attempt.
		expectProblem(t, c.confirm(t, ch.ChallengeID, "12345"), http.StatusBadRequest, "validation-failed")

		resp := c.confirm(t, ch.ChallengeID, wrong1)
		expectProblem(t, resp, http.StatusUnprocessableEntity, "verification-code-invalid")
		var p struct {
			AttemptsRemaining *int `json:"attemptsRemaining"`
		}
		mustJSON(t, resp.body, &p)
		if p.AttemptsRemaining == nil || *p.AttemptsRemaining != 1 {
			t.Errorf("attemptsRemaining = %v, want 1; body %s", p.AttemptsRemaining, resp.body)
		}
		expectProblem(t, c.confirm(t, ch.ChallengeID, wrong2), http.StatusGone, "verification-exhausted")
		resp = c.confirm(t, ch.ChallengeID, code)
		expectProblem(t, resp, http.StatusGone, "verification-exhausted")
		if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
			t.Errorf("exhausted challenge sets a cookie: %q", sc)
		}
		expectProblem(t, c.confirm(t, "vch_AAAAAAAAAAAAAAAAAAAAAA", code), http.StatusNotFound, "not-found")

		lines := eventsOf(t, d.securityLines(t), "verification_code_invalid")
		if len(lines) != 2 {
			t.Fatalf("%d verification_code_invalid lines, want 2", len(lines))
		}
		for _, l := range lines {
			if l.ip != insideA || l.tenant != hostA || l.fields != "" {
				t.Errorf("line %q, want ip %s, tenant %s and no field", l.raw, insideA, hostA)
			}
		}
		noSecretInLogs(t, d.server, code, wrong1, wrong2, ch.ChallengeID)

		// A new code can be requested.
		if ch2 := expectChallenge(t, c.start(t, email, ""), email); ch2.ChallengeID == ch.ChallengeID {
			t.Error("the new challenge reuses the exhausted one")
		}
	})
}

// TestDepositRateLimits covers spec 7: at most 5 codes per address and 20
// per client IP within an hour, then 429 with Retry-After and a
// rate_limited line. The global HTTP limiter (burst 100) is not reached.
func TestDepositRateLimits(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)

		t.Run("per address", func(t *testing.T) {
			email := uniqueEmail(t, "peraddr", domainA)
			// Five codes from five client IPs: only the address counts.
			for i := range 5 {
				c := &depositor{d: d, host: hostA, ip: fmt.Sprintf("192.0.2.%d", 100+i)}
				expectChallenge(t, c.start(t, email, ""), email)
			}
			c := &depositor{d: d, host: hostA, ip: "192.0.2.110"}
			resp := c.start(t, email, "")
			p := expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
			if resp.header.Get(hdrRetryAfter) != "3600" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
				t.Errorf("Retry-After = %q, retryAfterSeconds = %v, want 3600", resp.header.Get(hdrRetryAfter), p.RetryAfterSeconds)
			}
			rl := eventsOf(t, d.securityLines(t), "rate_limited")
			if len(rl) != 1 || rl[0].ip != "192.0.2.110" || rl[0].tenant != hostA || rl[0].fields != ` scope="verification_address"` {
				t.Errorf("rate_limited lines = %+v, want one verification_address line for 192.0.2.110", rl)
			}
		})

		t.Run("per IP", func(t *testing.T) {
			const ip = "192.0.2.200"
			c := &depositor{d: d, host: hostA, ip: ip}
			for i := range 20 {
				email := uniqueEmail(t, fmt.Sprintf("perip%d", i), domainA)
				expectChallenge(t, c.start(t, email, ""), email)
			}
			resp := c.start(t, uniqueEmail(t, "perip-over", domainA), "")
			p := expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
			if resp.header.Get(hdrRetryAfter) != "3600" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
				t.Errorf("Retry-After = %q, retryAfterSeconds = %v, want 3600", resp.header.Get(hdrRetryAfter), p.RetryAfterSeconds)
			}
			var got []logLine
			for _, l := range eventsOf(t, d.securityLines(t), "rate_limited") {
				if l.ip == ip {
					got = append(got, l)
				}
			}
			if len(got) != 1 || got[0].fields != ` scope="verification_ip"` {
				t.Errorf("rate_limited lines for %s = %+v, want one verification_ip line", ip, got)
			}
			// Another client IP keeps its own budget.
			other := &depositor{d: d, host: hostA, ip: "192.0.2.201"}
			email := uniqueEmail(t, "perip-other", domainA)
			expectChallenge(t, other.start(t, email, ""), email)
		})
	})
}

// TestDepositRefusals covers spec 6.2, 8.1 and 15.2 (T-12, T-13): a domain
// not allowed, an IP outside the ranges, a blocklisted address or domain
// and an unusable invitation all get the same 403 body (no oracle), and a
// deposit_refused line with the reason.
func TestDepositRefusals(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, false)
		const blockedDomain = "blocked." + domainA
		d.setRules(t, true, []string{internalNetA}, domainA, blockedDomain)
		blockedAddr := "mallory@" + domainA
		d.block(t, store.BlockEmail, blockedAddr)
		d.block(t, store.BlockDomain, blockedDomain)

		cases := []struct {
			name, ip, email, invitation, reason string
		}{
			{"domain not allowed", insideA, "eve@" + externalDomain, "", "domain"},
			{"IP outside the ranges", outside, "bob@" + domainA, "", "ip"},
			{"IP of another tenant", "203.0.113.10", "bob@" + domainA, "", "ip"},
			{"blocklisted address", insideA, blockedAddr, "", "blocklist"},
			{"blocklisted address, other case", insideA, "Mallory@Entity-A.localhost", "", "blocklist"},
			{"blocklisted domain", insideA, "carol@" + blockedDomain, "", "blocklist"},
			{"blocklisted sub-domain", insideA, "dave@x." + blockedDomain, "", "blocklist"},
			{"blocklist before invitation", outside, blockedAddr, "inv_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "blocklist"},
			{"unknown invitation", outside, "eve@" + externalDomain, "inv_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "invitation"},
			{"malformed invitation", outside, "eve@" + externalDomain, "not-a-token", "invitation"},
		}
		var first string
		var want []string
		for _, tc := range cases {
			c := &depositor{d: d, host: hostA, ip: tc.ip}
			resp := c.start(t, tc.email, tc.invitation)
			expectProblem(t, resp, http.StatusForbidden, "deposit-not-allowed")
			expectSecurityHeaders(t, tc.name, resp.header)
			if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
				t.Errorf("%s: refusal sets a cookie: %q", tc.name, sc)
			}
			body := problemWithoutInstance(t, resp.body)
			if first == "" {
				first = body
			} else if body != first {
				t.Errorf("%s: body %s differs from %s (refusal oracle)", tc.name, body, first)
			}
			want = append(want, tc.reason)
		}
		got := reasons(t, d.server)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("deposit_refused reasons = %v, want %v", got, want)
		}
		for _, l := range eventsOf(t, d.securityLines(t), "deposit_refused") {
			if l.tenant != hostA || (l.ip != insideA && l.ip != outside && l.ip != "203.0.113.10") {
				t.Errorf("line %q: want tenant %s and the client IP", l.raw, hostA)
			}
			if strings.Contains(l.raw, "@") {
				t.Errorf("line %q contains an address", l.raw)
			}
		}
	})
}

// invitationLinkRE extracts the invitation link of the invitation mail.
var invitationLinkRE = regexp.MustCompile(`https?://[^\s"<>]+/i/(inv_[A-Za-z0-9_-]+)`)

// TestDepositInvitationFlow covers spec 9 (T-18 to T-22, T-03): an
// internal depositor invites an external person, whose link is built from
// the tenant FQDN; the invited person verifies the invited address and
// gets an external session that cannot invite; another address cannot use
// the link; revoking the invitation ends the external session.
func TestDepositInvitationFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		inviter := d.newDepositor()
		inviterEmail := uniqueEmail(t, "inviter", domainA)
		inviter.openSession(t, inviterEmail, "")
		guestEmail := uniqueEmail(t, "guest", externalDomain)

		// A Host differing from the stored FQDN only by case, trailing dot
		// and port still selects tenant A; the link must use the stored
		// FQDN, never the request Host.
		inviter.host = "Transfer.Entity-A.Localhost.:8443"
		resp := inviter.invite(t, `{"email":"`+guestEmail+`","message":"Merci d'envoyer les pièces.","language":"fr"}`, inviter.withCSRF())
		inviter.host = hostA
		if resp.status != http.StatusCreated {
			t.Fatalf("createInvitation: %d %s", resp.status, resp.body)
		}
		var inv struct {
			ID        string    `json:"id"`
			Email     string    `json:"email"`
			InvitedBy string    `json:"invitedBy"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"createdAt"`
			ExpiresAt time.Time `json:"expiresAt"`
		}
		mustJSON(t, resp.body, &inv)
		if !strings.HasPrefix(inv.ID, "inv_") || inv.Email != guestEmail || inv.InvitedBy != inviterEmail || inv.Status != "pending" {
			t.Errorf("invitation = %+v", inv)
		}
		if want := inv.CreatedAt.AddDate(1, 0, 0); !inv.ExpiresAt.Equal(want) {
			t.Errorf("expiresAt = %s, want 12 months after creation (%s)", inv.ExpiresAt, want)
		}

		d.waitMailSent(t, guestEmail)
		msg := d.mp.only(t, guestEmail)
		if want := inviterEmail + " vous invite à envoyer des fichiers à " + nameA; msg.Subject != want {
			t.Errorf("invitation subject %q, want %q", msg.Subject, want)
		}
		m := invitationLinkRE.FindStringSubmatch(msg.Text)
		if m == nil {
			t.Fatalf("no invitation link in:\n%s", msg.Text)
		}
		if want := "https://" + hostA + "/i/" + m[1]; m[0] != want {
			t.Errorf("invitation link %q, want %q (stored FQDN)", m[0], want)
		}
		if !strings.Contains(msg.HTML, m[0]) || !strings.Contains(msg.Text, "Merci d'envoyer les pièces.") {
			t.Error("the invitation mail lacks the link in HTML or the message")
		}
		token := m[1]
		if token == inv.ID {
			t.Error("the link token is the invitation record identifier")
		}

		// The landing page.
		resp = d.get(t, hostA, pathInvitations+"/"+token)
		if resp.status != http.StatusOK {
			t.Fatalf("getInvitation: %d %s", resp.status, resp.body)
		}
		var pub map[string]any
		mustJSON(t, resp.body, &pub)
		if pub["email"] != guestEmail || pub["invitedBy"] != inviterEmail || pub["message"] != "Merci d'envoyer les pièces." ||
			pub["expiresAt"] == nil || len(pub) != 4 {
			t.Errorf("PublicInvitation = %s", resp.body)
		}

		// Another address cannot use the link.
		thief := &depositor{d: d, host: hostA, ip: outside}
		expectProblem(t, thief.start(t, uniqueEmail(t, "thief", externalDomain), token), http.StatusForbidden, "deposit-not-allowed")

		// The invited person, from outside the tenant ranges. The code
		// mail follows the language of the invitation.
		guest := &depositor{d: d, host: hostA, ip: outside}
		ch := expectChallenge(t, guest.start(t, strings.ToUpper(guestEmail), token), guestEmail)
		codeMsg := d.mp.find(t, guestEmail, func(m mpMessage) bool { return strings.HasPrefix(m.Subject, "Votre code de vérification") })
		code := codeRE.FindStringSubmatch(codeMsg.Text)
		if code == nil {
			t.Fatalf("no code in %s", codeMsg.Text)
		}
		s, cookie, known := expectSessionWithKnown(t, guest.confirm(t, ch.ChallengeID, code[1]), guestEmail)
		if known != "" {
			t.Errorf("an external confirmation set the recognition cookie %q", known)
		}
		if s.Kind != "external" || s.CanInvite || s.Invitation == nil || s.Invitation.InvitedBy != inviterEmail {
			t.Errorf("external session = %+v, want external, no invite right, invited by %s", s, inviterEmail)
		}
		guest.cookie, guest.csrf = cookie, s.CSRFToken
		if st := guest.current(t).status; st != http.StatusOK {
			t.Fatalf("external current: %d", st)
		}

		// Decision A: the address is now verified, yet every deposit
		// through the invitation needs a code (a forwarded link opens
		// nothing by itself), and a new code mail is sent.
		again := &depositor{d: d, host: hostA, ip: outside, known: inviter.known}
		expectChallenge(t, again.start(t, guestEmail, token), guestEmail)
		deadline := time.Now().Add(waitTimeout)
		for len(d.mp.messagesTo(t, guestEmail)) < 3 { // invitation + 2 codes
			if time.Now().After(deadline) {
				t.Fatalf("no second code mail for the verified invited address")
			}
			time.Sleep(mailpitPollInterval)
		}

		// An external depositor cannot invite.
		expectProblem(t, guest.invite(t, `{"email":"`+uniqueEmail(t, "next", externalDomain)+`"}`, guest.withCSRF()),
			http.StatusForbidden, "invitation-not-allowed")

		// An internal session used from outside the ranges cannot invite
		// either: the network rule is checked again.
		inviter.ip = outside
		expectProblem(t, inviter.invite(t, `{"email":"`+uniqueEmail(t, "remote", externalDomain)+`"}`, inviter.withCSRF()),
			http.StatusForbidden, "deposit-not-allowed")
		inviter.ip = insideA

		// Revocation by the administration ends the external session.
		if err := d.db.Invitations().Revoke(context.Background(), d.tenantA.ID, inv.ID, time.Now()); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		expectProblem(t, guest.current(t), http.StatusUnauthorized, "unauthenticated")
		expectProblem(t, d.get(t, hostA, pathInvitations+"/"+token), http.StatusGone, "invitation-gone")
		guest.cookie = ""
		expectProblem(t, guest.start(t, guestEmail, token), http.StatusGone, "invitation-gone")
		// The inviter is unaffected.
		if st := inviter.current(t).status; st != http.StatusOK {
			t.Errorf("inviter current after revocation: %d", st)
		}

		got := reasons(t, d.server)
		if strings.Join(got, ",") != "invitation,ip,invitation" {
			t.Errorf("deposit_refused reasons = %v, want [invitation ip invitation]", got)
		}
		noSecretInLogs(t, d.server, code[1], cookie, s.CSRFToken, token)
	})
}

// TestDepositMailUnavailable covers a tenant without SMTP settings: 503
// mail-unavailable, and no challenge is left behind (nor counted against
// the rate limits).
func TestDepositMailUnavailable(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, false)
		c := &depositor{d: d, host: hostB, ip: "203.0.113.10"}
		email := uniqueEmail(t, "nomail", domainB)
		since := time.Now().Add(-time.Minute)
		for range 6 {
			resp := c.start(t, email, "")
			expectProblem(t, resp, http.StatusServiceUnavailable, "mail-unavailable")
			if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
				t.Errorf("503 sets a cookie: %q", sc)
			}
		}
		ctx := context.Background()
		n, err := d.db.Challenges().CountSince(ctx, d.tenantB.ID, email, since)
		if err != nil || n != 0 {
			t.Errorf("challenges for the address = %d (%v), want 0", n, err)
		}
		if _, err := d.db.VerifiedAddresses().Get(ctx, d.tenantB.ID, email); err == nil {
			t.Error("the address was recorded as verified")
		}
		if lines := eventsOf(t, d.securityLines(t), "rate_limited"); len(lines) != 0 {
			t.Errorf("rate_limited lines = %+v, want none", lines)
		}
	})
}

// TestDepositMaintenance covers maintenance mode (CLAUDE.md section 4):
// startDepositSession and createInvitation, which declare 503, are refused
// even for an authenticated depositor; confirming a code already sent,
// reading and ending a session, which do not, still work.
func TestDepositMaintenance(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		flag := new(maintenanceFlag)
		d := startDeposit(t, e, serverOptions{flag: flag}, true)
		c := d.newDepositor()
		c.openSession(t, uniqueEmail(t, "maint", domainA), "")
		pending := d.newDepositor()
		pendingEmail := uniqueEmail(t, "pending", domainA)
		ch := expectChallenge(t, pending.start(t, pendingEmail, ""), pendingEmail)
		_, code := d.codeMail(t, pendingEmail)

		flag.Store(true)
		resp := d.newDepositor().start(t, uniqueEmail(t, "during", domainA), "")
		expectProblem(t, resp, http.StatusServiceUnavailable, "maintenance")
		if resp.header.Get(hdrRetryAfter) != "300" {
			t.Errorf("Retry-After = %q, want 300", resp.header.Get(hdrRetryAfter))
		}
		expectProblem(t, c.invite(t, `{"email":"`+uniqueEmail(t, "g", externalDomain)+`"}`, c.withCSRF()),
			http.StatusServiceUnavailable, "maintenance")
		expectSession(t, pending.confirm(t, ch.ChallengeID, code), pendingEmail)
		if st := c.current(t).status; st != http.StatusOK {
			t.Errorf("current in maintenance: %d, want 200", st)
		}
		if st := c.end(t, c.withCSRF()).status; st != http.StatusNoContent {
			t.Errorf("end in maintenance: %d, want 204", st)
		}

		flag.Store(false)
		email := uniqueEmail(t, "after", domainA)
		expectChallenge(t, d.newDepositor().start(t, email, ""), email)
	})
}

// TestDepositCrossTenantRealFlow complements test/isolation/http with
// resources created by real flows: tenant A's session cookie, pending
// challenge and invitation token are useless under tenant B's host, and
// trying them there does not spend or end them under A.
func TestDepositCrossTenantRealFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		a := d.newDepositor()
		aEmail := uniqueEmail(t, "alice", domainA)
		a.openSession(t, aEmail, "")

		atB := &depositor{d: d, host: hostB, ip: "203.0.113.10", cookie: a.cookie, csrf: a.csrf}
		for name, resp := range map[string]response{
			"current": atB.current(t),
			"end":     atB.end(t, atB.withCSRF()),
			"invite":  atB.invite(t, `{"email":"`+uniqueEmail(t, "x", externalDomain)+`"}`, atB.withCSRF()),
		} {
			p := expectProblem(t, resp, http.StatusUnauthorized, "unauthenticated")
			if strings.Contains(string(resp.body), aEmail) || strings.Contains(string(resp.body), nameA) || p.Detail == aEmail {
				t.Errorf("%s under B leaks tenant A data: %s", name, resp.body)
			}
			if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
				t.Errorf("%s under B sets a cookie: %q", name, sc)
			}
		}
		if st := a.current(t).status; st != http.StatusOK {
			t.Fatalf("A's session ended by the requests under B: current %d", st)
		}

		// A pending challenge of A: unknown under B, even with the right
		// code, and still usable under A afterwards.
		other := d.newDepositor()
		otherEmail := uniqueEmail(t, "other", domainA)
		ch := expectChallenge(t, other.start(t, otherEmail, ""), otherEmail)
		_, code := d.codeMail(t, otherEmail)
		otherAtB := &depositor{d: d, host: hostB, ip: insideA}
		for range 3 {
			expectProblem(t, otherAtB.confirm(t, ch.ChallengeID, code), http.StatusNotFound, "not-found")
		}
		expectSession(t, other.confirm(t, ch.ChallengeID, code), otherEmail)

		// An invitation of A: unknown under B.
		guestEmail := uniqueEmail(t, "guest", externalDomain)
		if resp := a.invite(t, `{"email":"`+guestEmail+`"}`, a.withCSRF()); resp.status != http.StatusCreated {
			t.Fatalf("createInvitation: %d %s", resp.status, resp.body)
		}
		d.waitMailSent(t, guestEmail)
		m := invitationLinkRE.FindStringSubmatch(d.mp.only(t, guestEmail).Text)
		if m == nil {
			t.Fatal("no invitation link")
		}
		expectProblem(t, d.get(t, hostB, pathInvitations+"/"+m[1]), http.StatusNotFound, "not-found")
		guestAtB := &depositor{d: d, host: hostB, ip: outside}
		expectProblem(t, guestAtB.start(t, guestEmail, m[1]), http.StatusForbidden, "deposit-not-allowed")
		if resp := d.get(t, hostA, pathInvitations+"/"+m[1]); resp.status != http.StatusOK {
			t.Errorf("A's invitation after the attempts under B: %d", resp.status)
		}
		for _, l := range eventsOf(t, d.securityLines(t), "deposit_refused") {
			if l.tenant != hostB {
				t.Errorf("refusal under B logged for tenant %s: %q", l.tenant, l.raw)
			}
		}
	})
}

// TestDepositRecognitionCrossTenant covers decision B across tenants: an
// address verified under both tenants, the recognition cookie of one
// tenant never opens a session under the other (202 and a code), while
// each tenant's own cookie does (201).
func TestDepositRecognitionCrossTenant(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		// Tenant B also accepts domainA from its own range, and mails
		// through Mailpit.
		d.setRules(t, false, []string{internalNetB}, domainB, domainA)
		if err := d.db.SMTPSettings().Put(context.Background(), d.tenantB.ID, store.SMTPConfig{
			Host: d.mp.host, Port: d.mp.port, Security: store.SMTPSecurityNone, FromAddress: "noreply@" + domainB,
		}); err != nil {
			t.Fatalf("put SMTP settings of B: %v", err)
		}
		email := uniqueEmail(t, "both", domainA)

		onA := d.newDepositor()
		onA.openSession(t, email, "")

		// Under B, with tenant A's cookie: a code, which verifies the
		// address under B and sets B's own cookie.
		onB := &depositor{d: d, host: hostB, ip: "203.0.113.10", known: onA.known}
		ch := expectChallenge(t, onB.start(t, email, ""), email)
		code := d.waitCode(t, email, 2)
		_, _, knownB := expectSessionWithKnown(t, onB.confirm(t, ch.ChallengeID, code), email)
		if knownB == "" || knownB == onA.known {
			t.Fatalf("recognition cookie under B = %q, want a value of its own", knownB)
		}
		// The service keeps the entries the browser presented (A's, which
		// a real browser would never send to B's host-only cookie) after
		// the new one: keep B's own entry only.
		knownB, _, _ = strings.Cut(knownB, ".")
		if knownB == onA.known {
			t.Fatalf("tenant B's entry %q equals tenant A's", knownB)
		}

		// Each tenant's own cookie opens a session at once there...
		expectSession(t, (&depositor{d: d, host: hostA, ip: insideA, known: onA.known}).start(t, email, ""), email)
		expectSession(t, (&depositor{d: d, host: hostB, ip: "203.0.113.10", known: knownB}).start(t, email, ""), email)
		// ...never under the other one.
		expectChallenge(t, (&depositor{d: d, host: hostB, ip: "203.0.113.10", known: onA.known}).start(t, email, ""), email)
		expectChallenge(t, (&depositor{d: d, host: hostA, ip: insideA, known: knownB}).start(t, email, ""), email)
	})
}

// TestDepositInvitationLimit covers the per-inviter limit: 20 invitations
// per hour and inviting address, then 429 with Retry-After.
func TestDepositInvitationLimit(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		inviter := d.newDepositor()
		inviter.openSession(t, uniqueEmail(t, "prolific", domainA), "")
		for i := range 20 {
			body := `{"email":"` + uniqueEmail(t, fmt.Sprintf("guest%d", i), externalDomain) + `"}`
			if resp := inviter.invite(t, body, inviter.withCSRF()); resp.status != http.StatusCreated {
				t.Fatalf("invitation %d: %d %s", i+1, resp.status, resp.body)
			}
		}
		resp := inviter.invite(t, `{"email":"`+uniqueEmail(t, "guest21", externalDomain)+`"}`, inviter.withCSRF())
		p := expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
		if resp.header.Get(hdrRetryAfter) != "3600" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
			t.Errorf("Retry-After = %q, retryAfterSeconds = %v, want 3600", resp.header.Get(hdrRetryAfter), p.RetryAfterSeconds)
		}
		// Another internal user keeps their own budget.
		colleague := d.newDepositor()
		colleague.openSession(t, uniqueEmail(t, "colleague", domainA), "")
		if resp := colleague.invite(t, `{"email":"`+uniqueEmail(t, "guest22", externalDomain)+`"}`, colleague.withCSRF()); resp.status != http.StatusCreated {
			t.Errorf("colleague invitation: %d %s", resp.status, resp.body)
		}
	})
}

// TestDepositMalformedEmail: a malformed address when opening a deposit
// session, inviting or naming the recipients of a transfer is refused with
// the pointer of its field and the code invalid-email; a display-name form
// is never rewritten into the bare address.
func TestDepositMalformedEmail(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		for _, bad := range []string{"not an address", "Bob <bob@" + domainA + ">", "<bob@" + domainA + ">"} {
			c := &depositor{d: d, host: hostA, ip: insideA}
			expectEmailError(t, c.start(t, bad, ""), "/email")
			expectEmailError(t, alice.invite(t, `{"email":`+strconv.Quote(bad)+`}`, alice.withCSRF()), "/email")
			expectEmailError(t, alice.createTransfer(t, transferCreate{
				Recipients: []string{"carol@example.net", bad}, ExpiryDays: 7, Files: []fileDecl{{Name: "a.txt", Size: 1}},
			}, ""), "/recipients/1")
		}
	})
}
