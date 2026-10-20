package deposit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestInternalFlow(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		res, err := ev.svc.Start(ctx, ev.a, internalIP, "fr-CH, en;q=0.5", " "+alice+" ", "", "")
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		ch := res.Challenge
		if res.Session != nil || ch == nil {
			t.Fatal("Start: want a challenge only")
		}
		if !id.TokenValid("vch", ch.ID, 22, 43) || ch.Email != aliceNorm || ch.AttemptsRemaining != 2 ||
			!ch.ExpiresAt.Equal(testStart.Add(15*time.Minute)) {
			t.Errorf("challenge = email %s attempts %d expires %v", ch.Email, ch.AttemptsRemaining, ch.ExpiresAt)
		}
		job := ev.queue.last(t)
		if job.Template != mail.TemplateVerificationCode || job.TenantID != ev.a.ID.String() ||
			!slices.Equal(job.Message.To, []string{"Alice@entity-a.example.com"}) || job.Message.Language != "fr" {
			t.Errorf("job = template %s tenant %s to %v lang %s", job.Template, job.TenantID, job.Message.To, job.Message.Language)
		}
		if job.Settings.Password != smtpPassword || job.Settings.Username != "mailer" ||
			job.Settings.Security != mail.SecurityStartTLS || job.Settings.FromName != "Entity A" {
			t.Errorf("settings = %v", job.Settings)
		}
		code := codeOf(t, job)

		ev.clock.Advance(time.Minute)
		s, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		now := testStart.Add(time.Minute)
		if s.Recognition == "" || strings.Contains(strings.ToLower(s.Recognition), "alice") ||
			len(parseRecognition(s.Recognition)) != 1 {
			t.Errorf("recognition cookie = %q", s.Recognition)
		}
		if !id.TokenValid("ds", s.Token, 43, 43) || !id.Valid(id.DepositSession, s.ID) {
			t.Error("malformed session token or id")
		}
		if s.Email != aliceNorm || s.Kind != KindInternal || !s.CanInvite || s.Invitation != nil ||
			!s.ExpiresAt.Equal(now.Add(4*time.Hour)) || s.Limits.MaxTransferBytes != 1<<30 ||
			!slices.Equal(s.Limits.ExpiryDays, []int{1, 7, 30}) || !strings.HasPrefix(s.CSRFToken, CSRFPrefix) {
			t.Errorf("session = %+v", s.SessionInfo)
		}
		if !ev.svc.CheckCSRF(s.Token, s.CSRFToken) {
			t.Error("CheckCSRF(own token) = false")
		}
		v, err := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)
		if err != nil || !v.InternalVerifiedAt.Equal(now) || v.InternalVerifiedIP != internalIP ||
			v.FirstVerifiedIP != internalIP || !v.LastUsedAt.Equal(now) {
			t.Errorf("verified = %+v, %v", v, err)
		}

		// The session reads back with the same details and CSRF token.
		info, err := ev.svc.Session(ctx, ev.a, s.Token)
		if err != nil {
			t.Fatalf("Session: %v", err)
		}
		if info.ID != s.ID || info.Email != s.Email || info.CSRFToken != s.CSRFToken || !info.ExpiresAt.Equal(s.ExpiresAt) ||
			!info.CanInvite || info.Kind != KindInternal {
			t.Errorf("Session = %+v", info)
		}

		// A used challenge cannot be confirmed again.
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		wantErr(t, "Confirm(used)", err, ErrChallengeGone)

		// Already verified, with the recognition cookie of this browser:
		// immediate session, no mail, last use refreshed, cookie renewed.
		mails := ev.queue.count()
		ev.clock.Advance(time.Hour)
		res, err = ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", s.Recognition)
		if err != nil || res.Session == nil || res.Challenge != nil {
			t.Fatalf("Start(verified) = session %v, %v", res.Session != nil, err)
		}
		if res.Session.Token == s.Token || !ev.svc.CheckCSRF(res.Session.Token, res.Session.CSRFToken) {
			t.Error("second session reuses the token or has a bad csrf token")
		}
		if res.Session.Recognition != s.Recognition {
			t.Errorf("renewed cookie = %q, want %q", res.Session.Recognition, s.Recognition)
		}
		if ev.queue.count() != mails {
			t.Error("a verified address got a code")
		}
		v, _ = ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)
		if !v.LastUsedAt.Equal(now.Add(time.Hour)) || !v.FirstVerifiedAt.Equal(now) {
			t.Errorf("verified after reuse = %+v", v)
		}

		// End: the session is gone, ending again is unauthenticated.
		if err := ev.svc.End(ctx, ev.a, s.Token); err != nil {
			t.Fatalf("End: %v", err)
		}
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "Session(ended)", err, ErrUnauthenticated)
		wantErr(t, "End(ended)", ev.svc.End(ctx, ev.a, s.Token), ErrUnauthenticated)
		wantErr(t, "End(malformed)", ev.svc.End(ctx, ev.a, "ds_short"), ErrUnauthenticated)
		_, err = ev.svc.Session(ctx, ev.a, "not-a-token")
		wantErr(t, "Session(malformed)", err, ErrUnauthenticated)

		// The second session expires after the TTL.
		ev.clock.Advance(4 * time.Hour)
		_, err = ev.svc.Session(ctx, ev.a, res.Session.Token)
		wantErr(t, "Session(expired)", err, ErrUnauthenticated)

		// An address unused for 12 months must be verified again, even with
		// the cookie.
		ev.clock.Advance(365 * 24 * time.Hour)
		res, err = ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", s.Recognition)
		if err != nil || res.Challenge == nil {
			t.Fatalf("Start(expired, cookie) = %v", err)
		}
		// The new verification starts over, from this IP.
		later := ev.clock.Now()
		if _, err := ev.svc.Confirm(ctx, ev.a, internalIP.Next(), res.Challenge.ID, codeOf(t, ev.queue.last(t)), ""); err != nil {
			t.Fatalf("Confirm(expired): %v", err)
		}
		v, _ = ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, aliceNorm)
		if !v.FirstVerifiedAt.Equal(later) || v.FirstVerifiedIP != internalIP.Next() || !v.InternalVerifiedAt.Equal(later) {
			t.Errorf("verified after expiry = %+v", v)
		}
	})
}

func TestStartRefusals(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		for _, bad := range []string{"", "alice", "Alice <alice@entity-a.example.com>", "alice@localhost", "a\r\nb@entity-a.example.com"} {
			_, err := ev.svc.Start(ctx, ev.a, internalIP, "", bad, "", "")
			wantInvalid(t, "Start(bad email)", err, FieldEmail)
		}

		refused := func(what string, ip string, email string) {
			t.Helper()
			addr := internalIP
			switch ip {
			case "external":
				addr = externalIP
			case "zero":
				addr = netipZero()
			}
			_, err := ev.svc.Start(ctx, ev.a, addr, "", email, "", "")
			wantErr(t, what, err, ErrForbidden)
		}
		refused("zero ip", "zero", alice)
		refused("external ip", "external", alice)
		refused("other domain", "internal", "carol@entity-b.example.com")
		ev.wantLogged(t, "deposit_refused", `reason="ip"`, 2)
		ev.wantLogged(t, "deposit_refused", `reason="domain"`, 1)

		ev.block(t, ev.a, store.BlockEmail, alice)
		refused("blocked address", "internal", alice)
		ev.block(t, ev.a, store.BlockDomain, "entity-a.example.com")
		refused("blocked domain", "internal", "dave@entity-a.example.com")
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 2)

		// The blocklist of A does not apply to B.
		ev.mustChallenge(t, ev.b, internalIP, alice, "")
		if ev.queue.count() != 1 {
			t.Errorf("%d mails queued, want 1", ev.queue.count())
		}

		// The security log never holds an address, and names the tenant.
		log := strings.ToLower(ev.seclog.String())
		if strings.Contains(log, "alice") || strings.Contains(log, "dave") || strings.Contains(log, "carol") {
			t.Error("the security log contains an address")
		}
		if !strings.Contains(log, "tenant="+hostA) {
			t.Error("the security log does not name the tenant")
		}
	})
}

func TestInvitationFlow(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		created, token := ev.mustInvite(t, "Bob@Partner.Example.org")
		if !id.Valid(id.Invitation, created.ID) || created.Email != bob || created.InvitedBy != aliceNorm ||
			created.Status != InvitationPending || created.Language != "en" || !created.CreatedAt.Equal(testStart) ||
			!created.ExpiresAt.Equal(testStart.AddDate(1, 0, 0)) {
			t.Errorf("invitation = %+v", created)
		}
		job := ev.queue.last(t)
		host, _ := linkOf(t, job)
		if host != hostA || job.Template != mail.TemplateInvitation || job.Message.Language != "en" ||
			!slices.Equal(job.Message.To, []string{"Bob@partner.example.org"}) ||
			!strings.Contains(job.Message.Text, "Please send the contract.") {
			t.Errorf("invitation mail: host %s template %s lang %s to %v", host, job.Template, job.Message.Language, job.Message.To)
		}
		if !id.TokenValid("inv", token, 43, 43) {
			t.Error("malformed invitation token")
		}

		pub, err := ev.svc.PublicInvitation(ctx, ev.a, token)
		if err != nil || pub.Email != bob || pub.InvitedBy != aliceNorm || pub.Message != "Please send the contract." ||
			!pub.ExpiresAt.Equal(created.ExpiresAt) {
			t.Errorf("PublicInvitation = %+v, %v", pub, err)
		}
		_, err = ev.svc.PublicInvitation(ctx, ev.a, "inv_bad")
		wantErr(t, "PublicInvitation(malformed)", err, ErrNotFound)
		_, err = ev.svc.PublicInvitation(ctx, ev.a, unknownToken(t, "inv"))
		wantErr(t, "PublicInvitation(unknown)", err, ErrNotFound)

		// The invited person, from outside, with another address: refused.
		for _, tc := range []struct{ what, email, token string }{
			{"other address", "eve@partner.example.org", token},
			{"malformed token", bob, "inv_bad"},
			{"unknown token", bob, unknownToken(t, "inv")},
		} {
			_, err := ev.svc.Start(ctx, ev.a, externalIP, "", tc.email, tc.token, "")
			wantErr(t, "Start("+tc.what+")", err, ErrForbidden)
		}
		ev.wantLogged(t, "deposit_refused", `reason="invitation"`, 3)

		// With the right address: a code in the invitation language, then an
		// external session.
		ev.clock.Advance(time.Hour)
		res, err := ev.svc.Start(ctx, ev.a, externalIP, "", bob, token, "")
		if err != nil || res.Challenge == nil {
			t.Fatalf("Start(invited) = %v", err)
		}
		if lang := ev.queue.last(t).Message.Language; lang != "en" {
			t.Errorf("code mail language = %s, want the invitation language", lang)
		}
		ch, err := ev.db.Challenges().Get(ctx, ev.a.ID, res.Challenge.ID)
		if err != nil || ch.InvitationID != created.ID {
			t.Errorf("challenge invitation = %q, %v", ch.InvitationID, err)
		}
		s, err := ev.svc.Confirm(ctx, ev.a, externalIP, res.Challenge.ID, codeOf(t, ev.queue.last(t)), "")
		if err != nil {
			t.Fatalf("Confirm(invited): %v", err)
		}
		used := testStart.Add(time.Hour)
		if s.Kind != KindExternal || s.CanInvite || s.Invitation == nil || s.Invitation.InvitedBy != aliceNorm ||
			s.Invitation.ID != created.ID || !s.Invitation.ExpiresAt.Equal(used.AddDate(1, 0, 0)) {
			t.Errorf("external session = %+v", s.SessionInfo)
		}
		stored, _ := ev.db.Invitations().Get(ctx, ev.a.ID, created.ID)
		if !stored.LastUsedAt.Equal(used) || !stored.ExpiresAt.Equal(s.Invitation.ExpiresAt) {
			t.Errorf("stored invitation = %+v", stored)
		}
		v, _ := ev.db.VerifiedAddresses().Get(ctx, ev.a.ID, bob)
		if !v.InternalVerifiedAt.IsZero() || v.InternalVerifiedIP.IsValid() || v.FirstVerifiedIP != externalIP {
			t.Errorf("verified external = %+v", v)
		}
		if s.Recognition != "" {
			t.Errorf("an external session got a recognition cookie: %q", s.Recognition)
		}
		info, err := ev.svc.Session(ctx, ev.a, s.Token)
		if err != nil || info.Invitation == nil || info.Invitation.InvitedBy != aliceNorm || info.CanInvite {
			t.Errorf("Session(external) = %+v, %v", info, err)
		}

		// An external session cannot invite.
		_, err = ev.svc.Invite(ctx, ev.a, info, internalIP, "", "frank@partner.example.org", "", "")
		wantErr(t, "Invite(external)", err, ErrForbidden)

		// Already verified: an invitation still requires a code (decision
		// A), even with a recognition cookie of bob from an internal
		// verification; an earlier expiry is kept (the invitation was just
		// extended).
		ev.clock.Advance(time.Hour)
		cookie := ev.entryFor(t, ev.a, bob, 0)
		res, err = ev.svc.Start(ctx, ev.a, externalIP, "", bob, token, cookie)
		if err != nil || res.Session != nil || res.Challenge == nil {
			t.Fatalf("Start(invited, verified) = %v, session %v", err, res.Session != nil)
		}
		s2, err := ev.svc.Confirm(ctx, ev.a, externalIP, res.Challenge.ID, codeOf(t, ev.queue.last(t)), cookie)
		if err != nil || s2.Kind != KindExternal || s2.Recognition != "" ||
			!s2.Invitation.ExpiresAt.Equal(used.Add(time.Hour).AddDate(1, 0, 0)) {
			t.Fatalf("Confirm(invited, verified) = %+v, %v", s2, err)
		}

		// A challenge pending while the invitation is revoked dies with it.
		created2, token2 := ev.mustInvite(t, "grace@partner.example.org")
		pending := ev.mustChallenge(t, ev.a, externalIP, "grace@partner.example.org", token2)
		code2 := codeOf(t, ev.queue.last(t))

		// Revoking the invitation kills its sessions and its challenges.
		if err := ev.db.Invitations().Revoke(ctx, ev.a.ID, created.ID, ev.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if err := ev.db.Invitations().Revoke(ctx, ev.a.ID, created2.ID, ev.clock.Now()); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "Session(revoked invitation)", err, ErrUnauthenticated)
		_, err = ev.svc.Start(ctx, ev.a, externalIP, "", bob, token, "")
		wantErr(t, "Start(revoked)", err, ErrInvitationGone)
		_, err = ev.svc.PublicInvitation(ctx, ev.a, token)
		wantErr(t, "PublicInvitation(revoked)", err, ErrInvitationGone)
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, pending.ID, code2, "")
		wantErr(t, "Confirm(revoked invitation)", err, ErrInvitationGone)

		// An invitation unused for 12 months expires.
		_, token3 := ev.mustInvite(t, "heidi@partner.example.org")
		ev.clock.Advance(366 * 24 * time.Hour)
		_, err = ev.svc.Start(ctx, ev.a, externalIP, "", "heidi@partner.example.org", token3, "")
		wantErr(t, "Start(expired)", err, ErrInvitationGone)
		_, err = ev.svc.PublicInvitation(ctx, ev.a, token3)
		wantErr(t, "PublicInvitation(expired)", err, ErrInvitationGone)
	})
}

func TestInvite(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.mustSession(t, ev.a, internalIP, alice, "")
		invite := func(ip string, email, message, lang, accept string) (Invitation, error) {
			addr := internalIP
			if ip == "external" {
				addr = externalIP
			}
			return ev.svc.Invite(ctx, ev.a, s.SessionInfo, addr, accept, email, message, lang)
		}

		_, err := invite("internal", "not an address", "", "", "")
		wantInvalid(t, "Invite(bad email)", err, FieldEmail)
		_, err = invite("internal", bob, strings.Repeat("é", MaxMessageRunes+1), "", "")
		wantInvalid(t, "Invite(long message)", err, FieldMessage)
		_, err = invite("internal", bob, "bad \xff utf-8", "", "")
		wantInvalid(t, "Invite(invalid utf-8)", err, FieldMessage)
		_, err = invite("internal", bob, "", "de", "")
		wantInvalid(t, "Invite(language)", err, FieldLanguage)
		if ev.queue.count() != 1 {
			t.Errorf("invalid invitations queued mails")
		}

		// The inviter must still be on the internal network.
		_, err = invite("external", bob, "", "", "")
		wantErr(t, "Invite(from outside)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="ip"`, 1)

		// Message of exactly the maximum length; language negotiated.
		inv, err := invite("internal", bob, strings.Repeat("é", MaxMessageRunes), "", "fr-FR,fr;q=0.9")
		if err != nil || inv.Language != "fr" || ev.queue.last(t).Message.Language != "fr" {
			t.Fatalf("Invite(max message) = %+v, %v", inv, err)
		}
		// Tenant default language when the browser offers nothing usable.
		inv, err = invite("internal", "ivan@partner.example.org", "", "", "de")
		if err != nil || inv.Language != "en" {
			t.Errorf("Invite(default language) = %+v, %v", inv, err)
		}
		stored, err := ev.db.Invitations().Get(ctx, ev.a.ID, inv.ID)
		if err != nil || stored.InvitedBy != aliceNorm || stored.Email != "ivan@partner.example.org" || stored.Language != "en" {
			t.Errorf("stored invitation = %+v, %v", stored, err)
		}

		// Blocklisted invitee, then blocklisted inviter.
		ev.block(t, ev.a, store.BlockDomain, "partner.example.org")
		_, err = invite("internal", "judy@partner.example.org", "", "", "")
		wantErr(t, "Invite(blocked invitee)", err, ErrForbidden)
		ev.block(t, ev.a, store.BlockEmail, aliceNorm)
		_, err = invite("internal", "kim@other.example.net", "", "", "")
		wantErr(t, "Invite(blocked inviter)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 2)
	})
}

func TestConfirmErrors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ch := ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code := codeOf(t, ev.queue.last(t))
		wrong := wrongCodeFor(code)

		_, err := ev.svc.Confirm(ctx, ev.a, internalIP, "vch_bad", code, "")
		wantErr(t, "Confirm(malformed id)", err, ErrNotFound)
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, unknownToken(t, "vch"), code, "")
		wantErr(t, "Confirm(unknown)", err, ErrNotFound)
		for _, bad := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦"} {
			_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, bad, "")
			wantInvalid(t, "Confirm(malformed code)", err, FieldCode)
		}

		// The IP rule is checked again: no attempt is spent from outside.
		_, err = ev.svc.Confirm(ctx, ev.a, externalIP, ch.ID, code, "")
		wantErr(t, "Confirm(from outside)", err, ErrForbidden)
		_, err = ev.svc.Confirm(ctx, ev.a, netipZero(), ch.ID, code, "")
		wantErr(t, "Confirm(no ip)", err, ErrForbidden)

		// First wrong code: 422 with one attempt left; second: 410.
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, wrong, "")
		var wce *WrongCodeError
		if !errors.As(err, &wce) || wce.Remaining != 1 || !errors.Is(err, ErrWrongCode) {
			t.Fatalf("Confirm(wrong) = %v", err)
		}
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, wrong, "")
		wantErr(t, "Confirm(second wrong)", err, ErrChallengeGone)
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		wantErr(t, "Confirm(after exhaustion)", err, ErrChallengeGone)

		// The security log records each wrong code, never the code itself.
		lines := ev.logLines("verification_code_invalid")
		if len(lines) != 2 {
			t.Errorf("%d verification_code_invalid lines, want 2", len(lines))
		}
		log := ev.seclog.String()
		if strings.Contains(log, code) || strings.Contains(log, wrong) || strings.Contains(log, ch.ID) {
			t.Error("the security log contains a code or a challenge id")
		}

		// Expiry after 15 minutes, exactly.
		ch = ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code = codeOf(t, ev.queue.last(t))
		ev.clock.Advance(15 * time.Minute)
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		wantErr(t, "Confirm(expired)", err, ErrChallengeGone)

		// Blocked between the code and its confirmation.
		ch = ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code = codeOf(t, ev.queue.last(t))
		ev.block(t, ev.a, store.BlockEmail, alice)
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		wantErr(t, "Confirm(blocked)", err, ErrForbidden)
	})
}

func TestConcurrentConfirm(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ch := ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code := codeOf(t, ev.queue.last(t))
		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = ev.svc.Confirm(context.Background(), ev.a, internalIP, ch.ID, code, "")
			})
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, ErrChallengeGone):
				t.Errorf("concurrent Confirm: %v", err)
			}
		}
		if won != 1 {
			t.Errorf("%d concurrent confirmations succeeded, want 1", won)
		}
	})
}

func TestRateLimits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		// Per address: 5 codes in the sliding hour, the 6th is refused.
		for i := range MaxCodesPerAddress {
			ev.mustChallenge(t, ev.a, internalIP, alice, "")
			if i == 0 {
				ev.clock.Advance(time.Minute)
			}
		}
		_, err := ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", "")
		var rle *RateLimitError
		if !errors.As(err, &rle) || rle.RetryAfter != time.Hour || !errors.Is(err, ErrRateLimited) {
			t.Fatalf("Start(6th code) = %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="verification_address"`, 1)
		// One hour after the first code, that code still counts (>= since).
		ev.clock.Advance(59 * time.Minute)
		_, err = ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", "")
		wantErr(t, "Start(at the window edge)", err, ErrRateLimited)
		// One millisecond later it no longer does.
		ev.clock.Advance(time.Millisecond)
		ev.mustChallenge(t, ev.a, internalIP, alice, "")
		// The limit is per tenant.
		ev.mustChallenge(t, ev.b, internalIP, alice, "")

		// Per IP: 20 codes in the sliding hour, whatever the address.
		ev.clock.Advance(2 * time.Hour)
		for i := range MaxCodesPerIP {
			ev.mustChallenge(t, ev.a, internalIP, "user"+string(rune('a'+i))+"@entity-a.example.com", "")
		}
		_, err = ev.svc.Start(ctx, ev.a, internalIP, "", "zed@entity-a.example.com", "", "")
		if !errors.As(err, &rle) || rle.RetryAfter != time.Hour {
			t.Fatalf("Start(21st code from one ip) = %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="verification_ip"`, 1)
		ev.mustChallenge(t, ev.a, internalIP.Next(), "zed@entity-a.example.com", "")

		// A full queue answers 429 and leaves no challenge to count.
		ev.clock.Advance(2 * time.Hour)
		ev.queue.setErr(mail.ErrQueueFull)
		for range MaxCodesPerAddress + 1 {
			_, err = ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", "")
			if !errors.As(err, &rle) || rle.RetryAfter != QueueFullRetryAfter {
				t.Fatalf("Start(queue full) = %v", err)
			}
		}
		n, err := ev.db.Challenges().CountSince(ctx, ev.a.ID, alice, ev.clock.Now().Add(-time.Hour))
		if err != nil || n != 0 {
			t.Errorf("challenges after refused jobs = %d, %v", n, err)
		}
		ev.queue.setErr(nil)
		ev.mustChallenge(t, ev.a, internalIP, alice, "")
	})
}

func TestIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		// Tenants A and B have identical network rules: only the tenant
		// differs.
		_, invToken := ev.mustInvite(t, bob)
		session, err := ev.svc.Session(ctx, ev.a, ev.mustSession(t, ev.a, internalIP, alice, "").Token)
		if err != nil {
			t.Fatal(err)
		}
		ch := ev.mustChallenge(t, ev.a, internalIP, "mallory@entity-a.example.com", "")
		code := codeOf(t, ev.queue.last(t))
		sessA := ev.mustSession(t, ev.a, internalIP, alice, "")

		_, err = ev.svc.Confirm(ctx, ev.b, internalIP, ch.ID, code, "")
		wantErr(t, "Confirm(A's challenge on B)", err, ErrNotFound)
		_, err = ev.svc.Session(ctx, ev.b, sessA.Token)
		wantErr(t, "Session(A's token on B)", err, ErrUnauthenticated)
		wantErr(t, "End(A's token on B)", ev.svc.End(ctx, ev.b, sessA.Token), ErrUnauthenticated)
		_, err = ev.svc.PublicInvitation(ctx, ev.b, invToken)
		wantErr(t, "PublicInvitation(A's token on B)", err, ErrNotFound)
		_, err = ev.svc.Start(ctx, ev.b, externalIP, "", bob, invToken, "")
		wantErr(t, "Start(A's invitation on B)", err, ErrForbidden)

		// A's verified address is not verified for B.
		ev.mustChallenge(t, ev.b, internalIP, alice, "")

		// Everything still works on A.
		if _, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, ""); err != nil {
			t.Errorf("Confirm on A: %v", err)
		}
		if _, err := ev.svc.Session(ctx, ev.a, session.ID); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Session(record id as token) = %v", err)
		}
		if _, err := ev.svc.Session(ctx, ev.a, sessA.Token); err != nil {
			t.Errorf("Session on A: %v", err)
		}
	})
}
