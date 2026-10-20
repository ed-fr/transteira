package deposit

import (
	"context"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestParseRecognition(t *testing.T) {
	t.Parallel()
	entry := func(b byte) string {
		raw := make([]byte, recognitionRawLen)
		raw[0] = b
		return recognitionEncoding.EncodeToString(raw)
	}
	e1, e2 := entry(1), entry(2)
	if len(e1) != recognitionEntryLen {
		t.Fatalf("entry length %d, want %d", len(e1), recognitionEntryLen)
	}
	six := strings.Join([]string{entry(1), entry(2), entry(3), entry(4), entry(5), entry(6)}, ".")
	cases := []struct {
		name, raw string
		want      int
	}{
		{"empty", "", 0},
		{"one", e1, 1},
		{"two", e1 + "." + e2, 2},
		{"duplicates collapse", e1 + "." + e1 + "." + e2, 2},
		{"junk ignored", "junk." + e1 + "..%%%." + strings.Repeat("!", recognitionEntryLen) + "." + e2, 2},
		{"padded base64 ignored", e1 + "=", 0},
		{"standard base64 ignored", strings.Repeat("+", recognitionEntryLen), 0},
		{"wrong size ignored", recognitionEncoding.EncodeToString(make([]byte, crypto.MACSize)), 0},
		{"cap at five", six, RecognitionMaxEntries},
		{"too long ignored", e1 + "." + strings.Repeat("x", maxRecognitionInput), 0},
	}
	for _, c := range cases {
		if got := parseRecognition(c.raw); len(got) != c.want {
			t.Errorf("%s: %d entries, want %d", c.name, len(got), c.want)
		}
	}
	if got := parseRecognition(six); got[0][0] != 1 || got[4][0] != 5 {
		t.Error("the cap does not keep the first entries in order")
	}
}

func TestRecognition(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.mustSession(t, ev.a, internalIP, alice, "")
		cookie := s.Recognition
		if cookie == "" || strings.Contains(strings.ToLower(cookie), "alice") || strings.Contains(cookie, "entity-a") {
			t.Fatalf("cookie %q is empty or reveals the address", cookie)
		}
		start := func(email, recognition string) Result {
			t.Helper()
			res, err := ev.svc.Start(ctx, ev.a, internalIP, "", email, "", recognition)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			return res
		}
		wantCode := func(what string, res Result) {
			t.Helper()
			if res.Session != nil || res.Challenge == nil {
				t.Errorf("%s: got a session, want a code (202)", what)
			}
		}

		// The right cookie: 201.
		if res := start(alice, cookie); res.Session == nil || res.Session.Recognition != cookie {
			t.Fatal("verified address with its cookie: no session")
		}
		// No cookie, a wrong one, a malformed one: 202.
		wantCode("no cookie", start(alice, ""))
		saltA := ev.saltOf(t, ev.a, alice)
		other := ev.entryWith(t, ev.a.ID, "zoe@entity-a.example.com", saltA, 0)
		wantCode("cookie of another address", start(alice, other))
		ofB := ev.entryWith(t, ev.b.ID, aliceNorm, saltA, 0)
		wantCode("cookie of another tenant", start(alice, ofB))
		tampered := []byte(cookie)
		tampered[0] ^= 1
		if tampered[0] == '.' {
			tampered[0] = 'A'
		}
		wantCode("tampered cookie", start(alice, string(tampered)))
		ev.clock.Advance(RateWindow + time.Millisecond) // clear the per-address code limit
		wantCode("malformed cookie", start(alice, "not a cookie;"+strings.Repeat("A", 50)))
		wantCode("oversized cookie", start(alice, cookie+"."+strings.Repeat("A", maxRecognitionInput)))
		// A cookie of the right address does not help an address that is
		// not verified.
		zoeCookie := other
		wantCode("unverified address with its cookie", start("zoe@entity-a.example.com", zoeCookie))

		// Junk around the right entry is ignored and dropped from the
		// renewed value.
		res := start(alice, "junk."+cookie+".%%")
		if res.Session == nil || res.Session.Recognition != cookie {
			t.Errorf("cookie with junk: session %v, renewed %q", res.Session != nil, res.Session.Recognition)
		}

		// The renewed value puts the address first, keeps the others in
		// their order without duplicates, and holds at most five entries.
		var entries []string
		for _, who := range []string{"u1", "u2", "u3", "u4", "u5"} {
			entries = append(entries, ev.entryFor(t, ev.a, who+"@entity-a.example.com", 0))
		}
		full := strings.Join(append(entries[:4:4], cookie), ".")
		res = start(alice, full)
		if res.Session == nil {
			t.Fatal("alice in fifth position not recognized")
		}
		want := strings.Join(append([]string{cookie}, entries[:4]...), ".")
		if res.Session.Recognition != want {
			t.Errorf("renewed = %q, want alice first then the others", res.Session.Recognition)
		}
		// Confirming a new address on a full browser evicts the oldest.
		ch := ev.mustChallenge(t, ev.a, internalIP, "carol@entity-a.example.com", "")
		sc, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, codeOf(t, ev.queue.last(t)), want)
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		got := strings.Split(sc.Recognition, ".")
		carol := ev.entryFor(t, ev.a, "carol@entity-a.example.com", 0)
		if len(got) != RecognitionMaxEntries || got[0] != carol || got[1] != cookie || got[4] != entries[2] {
			t.Errorf("after a sixth address: %v", got)
		}
		if strings.Contains(strings.ToLower(sc.Recognition), "carol") {
			t.Error("the cookie reveals an address")
		}
		// Confirming an address already present moves it to the front.
		ch = ev.mustChallenge(t, ev.a, internalIP, alice, "")
		sa, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, codeOf(t, ev.queue.last(t)), sc.Recognition)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Split(sa.Recognition, "."); len(got) != RecognitionMaxEntries || got[0] != cookie || got[1] != carol {
			t.Errorf("alice again: %v", got)
		}

		// The cookie never helps from outside: the internal rule applies
		// first.
		_, err = ev.svc.Start(ctx, ev.a, externalIP, "", alice, "", cookie)
		wantErr(t, "Start(outside, cookie)", err, ErrForbidden)

		// Failing keys while computing the renewed value of Confirm: the
		// code is not consumed.
		ch = ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code := codeOf(t, ev.queue.last(t))
		realKeys := ev.svc.keys
		ev.svc.keys = failKeys{Keys: realKeys, mac: true}
		_, err = ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, "")
		wantErr(t, "Confirm with failing MAC", err, errFault)
		ev.svc.keys = realKeys
		if _, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, ""); err != nil {
			t.Errorf("Confirm after the failure: %v", err)
		}
	})
}

func TestSanitizeMessage(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Hello,\r\nplease send\tit.":                      "Hello,\nplease send\tit.",
		"nul\x00 bell\x07 esc\x1b del\x7f c1\u0085\u009f": "nul bell esc del c1",
		"zw\u200bj\u200cn\u200d lrm\u200e rlm\u200f":      "zwjn lrm rlm",
		"bidi \u202aa\u202bb\u202cc\u202dd\u202ee":        "bidi abcde",
		"iso \u2066a\u2067b\u2068c\u2069 bom\ufeff":       "iso abc bom",
		"kept: é 漢字 ‐ \u2028 ⁰":                           "kept: é 漢字 ‐ \u2028 ⁰",
	}
	for in, want := range cases {
		if got := sanitizeMessage(in); got != want {
			t.Errorf("sanitizeMessage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInviteRules(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.mustSession(t, ev.a, internalIP, alice, "")

		// The message is stored and mailed without its control and
		// invisible characters.
		inv, err := ev.svc.Invite(ctx, ev.a, s.SessionInfo, internalIP, "", bob, "Hi\r\n\u202ebob\u2066\x00!", "")
		if err != nil {
			t.Fatalf("Invite: %v", err)
		}
		stored, err := ev.db.Invitations().Get(ctx, ev.a.ID, inv.ID)
		if err != nil || stored.Message != "Hi\nbob!" {
			t.Errorf("stored message = %q, %v", stored.Message, err)
		}
		// Invisible characters do not count against the limit.
		long := strings.Repeat("a", MaxMessageRunes) + "\u200b\u200b"
		if _, err := ev.svc.Invite(ctx, ev.a, s.SessionInfo, internalIP, "", bob, long, ""); err != nil {
			t.Errorf("Invite(max message + invisible) = %v", err)
		}

		// Per inviter: MaxInvitationsPerInviter per hour, then 429.
		for i := 2; i < MaxInvitationsPerInviter; i++ {
			if _, err := ev.svc.Invite(ctx, ev.a, s.SessionInfo, internalIP, "", bob, "", ""); err != nil {
				t.Fatalf("Invite #%d: %v", i+1, err)
			}
		}
		_, err = ev.svc.Invite(ctx, ev.a, s.SessionInfo, internalIP, "", bob, "", "")
		var rle *RateLimitError
		if !errors.As(err, &rle) || rle.RetryAfter != RateWindow {
			t.Fatalf("Invite over the limit = %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="invitation"`, 1)
		// Another inviter has its own allowance.
		dave := ev.mustSession(t, ev.a, internalIP, "dave@entity-a.example.com", "")
		if _, err := ev.svc.Invite(ctx, ev.a, dave.SessionInfo, internalIP, "", bob, "", ""); err != nil {
			t.Errorf("Invite by another inviter = %v", err)
		}
		// One hour later the window has slid.
		ev.clock.Advance(RateWindow + time.Millisecond)
		if _, err := ev.svc.Invite(ctx, ev.a, s.SessionInfo, internalIP, "", bob, "", ""); err != nil {
			t.Errorf("Invite after the window = %v", err)
		}

		// A refused mail revokes the invitation.
		ev.queue.setErr(mail.ErrQueueClosed)
		_, err = ev.svc.Invite(ctx, ev.a, dave.SessionInfo, internalIP, "", "erin@partner.example.org", "", "")
		wantErr(t, "Invite with a closed queue", err, ErrMailUnavailable)
		ev.queue.setErr(nil)

		// Check order: the blocklist comes before the internal rule.
		ev.block(t, ev.a, store.BlockEmail, "dave@entity-a.example.com")
		_, err = ev.svc.Invite(ctx, ev.a, dave.SessionInfo, externalIP, "", bob, "", "")
		wantErr(t, "Invite(blocked, from outside)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 1)
		ev.wantLogged(t, "deposit_refused", `reason="ip"`, 0)
	})
}

// TestConcurrentStarts checks that the code rate limit holds under
// concurrent requests: the counts run in the inserting transaction. On
// PostgreSQL the server default isolation is set to REPEATABLE READ for the
// connections, to check that the store still runs READ COMMITTED.
func TestConcurrentStarts(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		if e.Driver == config.DriverPostgres {
			u, err := url.Parse(e.DSN)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			q.Set("default_transaction_isolation", "repeatable read")
			u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20") // pgx does not decode "+"
			e.DSN = u.String()
		}
		ev := newEnv(t, e)
		const n = 12
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = ev.svc.Start(context.Background(), ev.a, internalIP, "", alice, "", "")
			})
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrRateLimited):
				t.Errorf("concurrent Start: %v", err)
			}
		}
		count, err := ev.db.Challenges().CountSince(context.Background(), ev.a.ID, alice, testStart.Add(-RateWindow))
		if err != nil || ok != MaxCodesPerAddress || count != MaxCodesPerAddress {
			t.Errorf("%d concurrent Starts succeeded, %d challenges (%v); want %d", ok, count, err, MaxCodesPerAddress)
		}
	})
}

// TestRecognitionLifetime checks the server-side lifetime and revocation of
// the recognition entries: issue day, salt rotation and renewal.
func TestRecognitionLifetime(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.mustSession(t, ev.a, internalIP, alice, "")
		start := func(recognition string) Result {
			t.Helper()
			ev.clock.Advance(RateWindow + time.Millisecond) // stay under the code limit
			res, err := ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", recognition)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			return res
		}
		today := dayOf(ev.clock.Now().Add(RateWindow + time.Millisecond))

		// An entry is accepted up to RecognitionMaxAgeDays after its issue
		// day, never before it, and is renewed with today's date.
		res := start(ev.entryFor(t, ev.a, alice, RecognitionMaxAgeDays))
		if res.Session == nil {
			t.Fatal("entry of exactly 365 days refused")
		}
		renewed := parseRecognition(res.Session.Recognition)
		if len(renewed) != 1 || binary.BigEndian.Uint32(renewed[0][:recognitionDayLen]) != today {
			t.Errorf("renewal does not carry today's date: %q", res.Session.Recognition)
		}
		if res := start(ev.entryFor(t, ev.a, alice, RecognitionMaxAgeDays+1)); res.Session != nil {
			t.Error("entry older than 365 days accepted")
		}
		if res := start(ev.entryFor(t, ev.a, alice, -1)); res.Session != nil {
			t.Error("entry issued in the future accepted")
		}
		// Tampering with the clear issue day breaks the MAC.
		old := parseRecognition(ev.entryFor(t, ev.a, alice, 10))[0]
		binary.BigEndian.PutUint32(old[:recognitionDayLen], today)
		if res := start(recognitionEncoding.EncodeToString(old)); res.Session != nil {
			t.Error("entry with a rewritten issue day accepted")
		}

		// Renewal drops stale entries and earlier entries of the address.
		cookie := ev.entryFor(t, ev.a, alice, 3) + "." + ev.entryFor(t, ev.a, "u1@entity-a.example.com", 400) + "." +
			ev.entryFor(t, ev.a, "u2@entity-a.example.com", 2) + "." + ev.entryFor(t, ev.a, alice, 5)
		res = start(cookie)
		if res.Session == nil {
			t.Fatal("cookie with an old entry of the address refused")
		}
		got := strings.Split(res.Session.Recognition, ".")
		if len(got) != 2 || got[1] != ev.entryFor(t, ev.a, "u2@entity-a.example.com", 2) {
			t.Errorf("renewed = %v, want alice (today) then u2", got)
		}

		// Rotating the salt revokes every entry of the address.
		current := res.Session.Recognition
		if err := ev.db.VerifiedAddresses().ResetRecognition(ctx, ev.a.ID, alice); err != nil {
			t.Fatal(err)
		}
		if res := start(current); res.Session != nil {
			t.Error("entry accepted after a salt rotation")
		}

		// A recognition VerifyMAC failure while renewing in Confirm aborts it
		// without consuming the code.
		ch := ev.mustChallenge(t, ev.a, internalIP, alice, "")
		code := codeOf(t, ev.queue.last(t))
		foreign := ev.entryFor(t, ev.a, "u3@entity-a.example.com", 0)
		realKeys := ev.svc.keys
		ev.svc.keys = failKeys{Keys: realKeys, verify: true, only: crypto.MACPurposeRecognition}
		_, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, foreign)
		wantErr(t, "Confirm with failing recognition VerifyMAC", err, errFault)
		ev.svc.keys = realKeys
		s, err := ev.svc.Confirm(ctx, ev.a, internalIP, ch.ID, code, foreign)
		if err != nil || len(strings.Split(s.Recognition, ".")) != 2 {
			t.Errorf("Confirm after the failure = %q, %v", s.Recognition, err)
		}
	})
}

// TestNoWritesWithoutSMTP checks that a tenant without SMTP settings gets
// ErrMailUnavailable before any challenge or invitation is written.
func TestNoWritesWithoutSMTP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		_, err := ev.svc.Start(ctx, ev.c, internalIP, "", alice, "", "")
		wantErr(t, "Start without smtp", err, ErrMailUnavailable)
		n, err := ev.db.Challenges().CountByIPSince(ctx, ev.c.ID, internalIP, testStart.Add(-time.Hour))
		if err != nil || n != 0 {
			t.Errorf("challenges written without smtp: %d, %v", n, err)
		}
		// An internal session of C, then an invitation: nothing written.
		ev.putSMTP(t, ev.c, store.SMTPConfig{Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-c.example.com"})
		s := ev.mustSession(t, ev.c, internalIP, alice, "")
		repo := ev.svc.repo
		ev.svc.repo = faultRepo{repo: repo, fails: map[string]error{"smtp": store.ErrNotFound}}
		_, err = ev.svc.Invite(ctx, ev.c, s.SessionInfo, internalIP, "", bob, "", "")
		wantErr(t, "Invite without smtp", err, ErrMailUnavailable)
		ev.svc.repo = repo
		var count int
		err = storeRepo{db: ev.db}.tx(ctx, ev.c.ID, func(tx txRepo) error {
			var err error
			count, err = tx.countInvitations(ctx, aliceNorm, testStart.Add(-time.Hour))
			return err
		})
		if err != nil || count != 0 {
			t.Errorf("invitations written without smtp: %d, %v", count, err)
		}
	})
}
