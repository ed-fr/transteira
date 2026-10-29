package mytransfers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestRequestLinkSamePathForKnownAndUnknown checks P32 / T-207: the request
// path of a known and of an unknown address makes the same storage calls,
// returns the same result and writes nothing to the security log; only the
// worker tells them apart, and an unknown address leaves no trace.
func TestRequestLinkSamePathForKnownAndUnknown(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.verify(ev.a, alice)
		const unknown = "nobody@entity-a.example.com"

		results := map[string]error{}
		calls := map[string][]call{}
		for _, addr := range []string{alice, unknown} {
			ev.repo.reset()
			results[addr] = ev.svc.RequestLink(ctx, ev.a, clientIP, "en", addr, "")
			calls[addr] = ev.repo.recorded()
		}
		if results[alice] != nil || results[unknown] != nil {
			t.Fatalf("RequestLink = %v (known), %v (unknown), want nil", results[alice], results[unknown])
		}
		want := []call{{"smtp", ev.a.ID}, {"recordRequest", ev.a.ID}}
		if !reflect.DeepEqual(calls[alice], want) || !reflect.DeepEqual(calls[unknown], want) {
			t.Fatalf("request path calls: known %v, unknown %v, want %v for both", calls[alice], calls[unknown], want)
		}
		if len(ev.svc.jobs) != 2 || ev.queue.count() != 0 || ev.seclog.String() != "" {
			t.Fatalf("after the requests: %d jobs queued, %d mails, security log %q", len(ev.svc.jobs), ev.queue.count(), ev.seclog.String())
		}
		// Both requests were counted for their own address.
		for _, addr := range []string{aliceNorm, unknown} {
			mac, err := ev.keys.MAC(crypto.MACPurposeAccessRate, []byte(addr))
			if err != nil {
				t.Fatal(err)
			}
			c, err := ev.db.SenderAccess().RecordRequest(ctx, ev.a.ID, mac, otherIP, ev.clock.Now())
			if err != nil || c.ByAddress != 1 {
				t.Errorf("%s: counted %+v, %v, want 1 request", addr, c, err)
			}
		}

		ev.drain()
		if ev.queue.count() != 1 {
			t.Fatalf("%d mails, want 1 (the known address only)", ev.queue.count())
		}
		job := ev.queue.last(t)
		if !reflect.DeepEqual(job.Message.To, []string{"Alice@entity-a.example.com"}) || job.Message.Language != "en" {
			t.Errorf("mail to %v in %q", job.Message.To, job.Message.Language)
		}
		evs := ev.auditEvents(ev.a.ID, audit.ActionMyTransfersLinkRequested)
		if len(evs) != 1 || evs[0].Actor != aliceNorm || evs[0].ObjectKind != audit.ObjectAccessLink ||
			!strings.HasPrefix(evs[0].ObjectID, "sal_") || evs[0].IP != clientIP {
			t.Errorf("audit = %+v", evs)
		}
		if strings.Contains(ev.logs.String(), "nobody") || ev.seclog.String() != "" {
			t.Errorf("the unknown address left a trace: logs %q, security log %q", ev.logs.String(), ev.seclog.String())
		}
	})
}

func TestRequestLinkValidation(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	for _, email := range []string{"", "not-an-address", "Alice <alice@entity-a.example.com>", "a@[10.0.0.1]", "user@example.123"} {
		wantInvalid(t, fmt.Sprintf("email %q", email), ev.svc.RequestLink(ctx, ev.a, clientIP, "", email, ""), FieldEmail)
	}
	wantInvalid(t, "language", ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, "de"), FieldLanguage)
	if calls := ev.repo.recorded(); len(calls) != 0 {
		t.Errorf("invalid requests reached the storage: %v", calls)
	}
}

func TestRequestLinkMailUnavailable(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		// Tenant C has no SMTP settings: 503 whatever the address.
		ev.verify(ev.c, alice)
		for _, addr := range []string{alice, "nobody@entity-a.example.com"} {
			wantErr(t, "no smtp", ev.svc.RequestLink(ctx, ev.c, clientIP, "", addr, ""), ErrMailUnavailable)
		}
		// A storage failure is an internal error.
		ev.fail("smtp")
		err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, "")
		if err == nil || errors.Is(err, ErrMailUnavailable) || !errors.Is(err, errBoom) {
			t.Errorf("smtp read failure: %v", err)
		}
		// A closed service refuses every request.
		if err := ev.svc.Close(ctx); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "closed", ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""), ErrMailUnavailable)
	})
}

func TestRequestLinkLimits(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)

		// Per address: the sixth request of the hour is silently dropped.
		for i := range MaxRequestsPerAddress + 1 {
			if err := ev.svc.RequestLink(ctx, ev.a, otherIP, "", alice, ""); err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
		}
		if n := len(ev.svc.jobs); n != MaxRequestsPerAddress {
			t.Errorf("%d jobs queued, want %d", n, MaxRequestsPerAddress)
		}
		if ev.seclog.String() != "" {
			t.Errorf("the address limit was logged: %q", ev.seclog.String())
		}
		ev.drain()

		// Per IP: the 21st request of the hour from one IP is refused and
		// logged, whatever the address.
		for i := range MaxRequestsPerIP {
			if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", fmt.Sprintf("user%d@entity-a.example.com", i), ""); err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
		}
		err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", "late@entity-a.example.com", "")
		var rl *RateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter != RequestWindow {
			t.Fatalf("21st request = %v, want a rate limit of %s", err, RequestWindow)
		}
		lines := ev.logLines(string(securitylog.RateLimited))
		if len(lines) != 1 || !strings.Contains(lines[0], `scope="`+ScopeRequestIP+`"`) ||
			!strings.Contains(lines[0], "ip="+clientIP.String()) || !strings.Contains(lines[0], "tenant="+hostA) {
			t.Errorf("security log = %q", ev.seclog.String())
		}
		// The refused requests were not recorded: they cost the address
		// no budget (M1).
		for range 3 {
			_ = ev.svc.RequestLink(ctx, ev.a, clientIP, "", "late@entity-a.example.com", "")
		}
		lateMAC, err := ev.keys.MAC(crypto.MACPurposeAccessRate, []byte("late@entity-a.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if c, err := ev.db.SenderAccess().RecordRequest(ctx, ev.a.ID, lateMAC, otherIP, ev.clock.Now()); err != nil || c.ByAddress != 0 {
			t.Errorf("refused requests counted for the address: %+v, %v", c, err)
		}
		// Another tenant counts its own requests.
		if err := ev.svc.RequestLink(ctx, ev.b, clientIP, "", "late@entity-a.example.com", ""); err != nil {
			t.Errorf("tenant B: %v", err)
		}
		// The window slides.
		ev.clock.Advance(RequestWindow + time.Millisecond)
		if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", "later@entity-a.example.com", ""); err != nil {
			t.Errorf("after the window: %v", err)
		}
	})
}

func TestRequestLinkLanguage(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	ev.verify(ev.a, alice)
	for _, c := range []struct{ accept, lang, want string }{
		{"", "", "en"},                // tenant default
		{"fr-CH, en;q=0.5", "", "fr"}, // negotiated
		{"fr", "en", "en"},            // chosen
	} {
		if err := ev.svc.RequestLink(ctx, ev.a, clientIP, c.accept, alice, c.lang); err != nil {
			t.Fatal(err)
		}
		ev.drain()
		if got := ev.queue.last(t).Message.Language; got != c.want {
			t.Errorf("accept %q, language %q: mail in %q, want %q", c.accept, c.lang, got, c.want)
		}
	}
}

func TestRequestLinkFailures(t *testing.T) {
	t.Parallel()

	t.Run("mac", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		ev.svc.keys = faultKeys{Keys: ev.keys, fail: map[crypto.MACPurpose]bool{crypto.MACPurposeAccessRate: true}}
		if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""); !errors.Is(err, errBoom) {
			t.Errorf("RequestLink = %v", err)
		}
	})
	t.Run("record", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		ev.fail("recordRequest")
		if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""); !errors.Is(err, errBoom) {
			t.Errorf("RequestLink = %v", err)
		}
	})
	t.Run("security log", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		ev.svc.seclog = securitylog.New(failingWriter{})
		for i := range MaxRequestsPerIP + 1 {
			_ = ev.svc.RequestLink(ctx, ev.a, clientIP, "", fmt.Sprintf("user%d@entity-a.example.com", i), "")
		}
		if !strings.Contains(ev.logs.String(), "security log write failed") {
			t.Errorf("logs = %q", ev.logs.String())
		}
	})
	t.Run("queue full", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.QueueSize = 1 })
		for range 2 {
			if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""); err != nil {
				t.Fatal(err)
			}
		}
		if len(ev.svc.jobs) != 1 || !strings.Contains(ev.logs.String(), "link request dropped") ||
			strings.Contains(strings.ToLower(ev.logs.String()), "alice") {
			t.Errorf("jobs %d, logs %q", len(ev.svc.jobs), ev.logs.String())
		}
	})
}

// TestSendLinkSkips checks that the worker sends nothing, silently, to an
// address that is unknown, no longer active or blocklisted.
func TestSendLinkSkips(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.verify(ev.a, alice)
		ev.verify(ev.a, bob)
		ev.verify(ev.b, "carol@entity-c.example.com")
		if _, err := ev.db.Blocklist().Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: bob, CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.db.Blocklist().Create(ctx, ev.b.ID, store.BlocklistEntry{Kind: store.BlockDomain, Value: "entity-c.example.com", CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name  string
			job   linkJob
			setup func()
		}{
			{"unknown", linkJob{tenant: ev.a, mailbox: "nobody@entity-a.example.com", email: "nobody@entity-a.example.com", lang: "en"}, nil},
			{"other tenant", linkJob{tenant: ev.b, mailbox: alice, email: aliceNorm, lang: "en"}, nil},
			{"blocked address", linkJob{tenant: ev.a, mailbox: bob, email: bob, lang: "en"}, nil},
			{"blocked domain", linkJob{tenant: ev.b, mailbox: "carol@entity-c.example.com", email: "carol@entity-c.example.com", lang: "en"}, nil},
			{"expired", linkJob{tenant: ev.a, mailbox: alice, email: aliceNorm, lang: "en"}, func() {
				ev.clock.Advance(time.Duration(store.VerifiedRetentionMonths) * 31 * 24 * time.Hour)
			}},
		} {
			if c.setup != nil {
				c.setup()
			}
			ev.svc.process(ctx, c.job)
			if ev.queue.count() != 0 || ev.logs.String() != "" || ev.seclog.String() != "" {
				t.Errorf("%s: %d mails, logs %q, security log %q", c.name, ev.queue.count(), ev.logs.String(), ev.seclog.String())
			}
		}
		if evs := ev.auditEvents(ev.a.ID, audit.ActionMyTransfersLinkRequested); len(evs) != 0 {
			t.Errorf("audit = %+v", evs)
		}
	})
}

func TestSendLinkFailures(t *testing.T) {
	t.Parallel()
	job := func(ev *env) linkJob { return linkJob{tenant: ev.a, mailbox: alice, email: aliceNorm, lang: "en"} }
	for _, c := range []struct {
		name  string
		setup func(ev *env)
	}{
		{"verified", func(ev *env) { ev.fail("verified") }},
		{"blocked", func(ev *env) { ev.fail("blocked") }},
		{"token", func(ev *env) {
			ev.svc.newToken = func(string, int) (string, error) { return "", errBoom }
		}},
		{"create link", func(ev *env) { ev.fail("createLink") }},
		{"mail", func(ev *env) { ev.svc.notifier = failingNotifier{} }},
		{"queue", func(ev *env) { ev.queue.err = errBoom }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ev := newEnv(t, storetest.SQLite(t))
			ev.verify(ev.a, alice)
			c.setup(ev)
			ev.svc.process(t.Context(), job(ev))
			logs := ev.logs.String()
			if !strings.Contains(logs, "my transfers link not sent") || strings.Contains(strings.ToLower(logs), "alice") {
				t.Errorf("logs = %q", logs)
			}
			if ev.queue.count() != 0 || len(ev.auditEvents(ev.a.ID, audit.ActionMyTransfersLinkRequested)) != 0 {
				t.Error("a link was sent or audited")
			}
		})
	}
}

// TestSendLinkMailBuiltBeforeLink checks that a mail that cannot be built
// leaves no access link behind: the link is only stored once its mail is
// ready.
func TestSendLinkMailBuiltBeforeLink(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ev.verify(ev.a, alice)
	ev.svc.notifier = failingNotifier{}
	ev.svc.process(t.Context(), linkJob{tenant: ev.a, mailbox: alice, email: aliceNorm, lang: "en"})
	for _, c := range ev.repo.recorded() {
		if c.method == "createLink" {
			t.Error("an access link was stored for a mail that could not be built")
		}
	}
}

func TestSendLinkAuditFailure(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.Audit = failingAudit{} })
	ev.verify(ev.a, alice)
	ev.mustLink(ev.a, alice)
	if !strings.Contains(ev.logs.String(), "audit write failed") {
		t.Errorf("logs = %q", ev.logs.String())
	}
}

func TestSendLinkWithoutAudit(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.Audit = nil })
	ev.svc.audit = nil
	ev.verify(ev.a, alice)
	ev.mustLink(ev.a, alice)
	if len(ev.auditEvents(ev.a.ID, audit.ActionMyTransfersLinkRequested)) != 0 {
		t.Error("audited without a recorder")
	}
}

func TestErrorMessages(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err    error
		target error
		want   string
	}{
		{invalid(FieldEmail), ErrInvalid, "mytransfers: invalid /email"},
		{&RateLimitError{RetryAfter: time.Hour}, ErrRateLimited, "mytransfers: rate limited, retry after 1h0m0s"},
		{&NotAllowedError{Allowed: []int{1, 7}}, ErrNotAllowed, "mytransfers: duration not allowed, allowed [1 7]"},
		{&BusyError{RetryAfter: time.Second}, ErrBusy, "mytransfers: an upload of the transfer is in progress, retry after 1s"},
	} {
		if c.err.Error() != c.want || !errors.Is(c.err, c.target) {
			t.Errorf("%T: %q, want %q matching %v", c.err, c.err.Error(), c.want, c.target)
		}
	}
}
