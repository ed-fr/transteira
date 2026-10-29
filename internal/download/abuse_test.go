package download

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeAlerter records the reports it is told about.
type fakeAlerter struct {
	mu      sync.Mutex
	reports []store.AbuseReport
	tenants []tenant.ID
	ctxErr  []error
}

func (f *fakeAlerter) Reported(ctx context.Context, t *tenant.Tenant, r store.AbuseReport) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports, f.tenants, f.ctxErr = append(f.reports, r), append(f.tenants, t.ID), append(f.ctxErr, ctx.Err())
}

func (f *fakeAlerter) last(t *testing.T) store.AbuseReport {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		t.Fatal("no report alerted")
	}
	return f.reports[len(f.reports)-1]
}

func (f *fakeAlerter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reports)
}

// abuseEnv is an env whose service alerts a fakeAlerter.
func abuseEnv(t *testing.T, e storetest.Engine) (*env, *fakeAlerter) {
	al := &fakeAlerter{}
	return newEnv(t, e, func(o *Options) { o.Abuse = al }), al
}

// report files a report on p from ip with cookie.
func (ev *env) report(p published, ip netip.Addr, cookie, category, message string) error {
	return ev.svc.ReportAbuse(context.Background(), p.tn, p.token, ip, cookie, category, message)
}

// stored reads back the report r and checks it equals what was alerted.
func (ev *env) stored(r store.AbuseReport) store.AbuseReport {
	ev.t.Helper()
	got, err := ev.db.AbuseReports().Get(context.Background(), ev.a.ID, r.ID)
	if err != nil {
		ev.t.Fatalf("Get(%s): %v", r.ID, err)
	}
	if got.ID != r.ID || got.ReporterEmail != r.ReporterEmail || got.Message != r.Message || got.Status != store.AbuseReportOpen ||
		!got.CreatedAt.Equal(r.CreatedAt) {
		ev.t.Fatalf("stored %+v, alerted %+v", got, r)
	}
	return got
}

// TestReportAbuseLinks: a shared link reports without a recipient; a
// recipient link reports its link and position, unverified without a
// cookie; the report is audited and alerted, and nothing happens to the
// transfer (T-220, P36).
func TestReportAbuseLinks(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev, al := abuseEnv(t, e)
		ctx := context.Background()

		shared := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		if err := ev.report(shared, ipOne, "", "phishing", "Fake login page"); err != nil {
			t.Fatalf("report shared: %v", err)
		}
		r := ev.stored(al.last(t))
		if r.TransferID != shared.id || r.RecipientLinkID != "" || r.RecipientPosition != nil || r.SenderEmail != alice ||
			r.ReporterVerified || r.ReporterEmail != "" || r.ReporterIP != ipOne || r.Category != store.AbuseCategoryPhishing ||
			r.Message != "Fake login page" || !r.CreatedAt.Equal(ev.clock.now()) {
			t.Fatalf("shared report %+v", r)
		}
		if al.tenants[0] != ev.a.ID || al.ctxErr[0] != nil {
			t.Fatalf("alert tenant %v ctx %v", al.tenants[0], al.ctxErr[0])
		}

		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}})
		if err := ev.report(p.link(1), ipTwo, "", "other", ""); err != nil {
			t.Fatalf("report link: %v", err)
		}
		r = ev.stored(al.last(t))
		if r.TransferID != p.id || r.RecipientLinkID != p.links[1].ID || r.RecipientPosition == nil || *r.RecipientPosition != 1 ||
			r.ReporterVerified || r.ReporterEmail != "" || r.Message != "" {
			t.Fatalf("link report %+v", r)
		}

		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{
			TenantID: ev.a.ID, Action: string(audit.ActionAbuseReported), Limit: store.MaxPageSize,
		})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("audit %+v, %v", page.Items, err)
		}
		for _, it := range page.Items {
			var d map[string]any
			if err := json.Unmarshal(it.Details, &d); err != nil {
				t.Fatal(err)
			}
			if it.ActorKind != store.ActorRecipient || it.Actor != linkActor || it.ObjectKind != audit.ObjectAbuseReport ||
				d["verified"] != false || strings.Contains(string(it.Details), "login") {
				t.Fatalf("audit item %+v %s", it, it.Details)
			}
			switch it.ObjectID {
			case r.ID:
				if d["transferId"] != p.id || d["category"] != "other" || d["link"] != p.links[1].ID {
					t.Fatalf("link audit %s", it.Details)
				}
			default:
				if d["transferId"] != shared.id || d["category"] != "phishing" || d["link"] != nil {
					t.Fatalf("shared audit %s", it.Details)
				}
			}
		}

		// No automatic action: the transfer is still served.
		if v, err := ev.svc.Resolve(ctx, ev.a, shared.token, Cookies{}); err != nil || v.Locked {
			t.Fatalf("after report %+v, %v", v, err)
		}
		if len(ev.queue.snapshot()) != 0 {
			t.Fatal("a mail was sent by the download service")
		}
	})
}

// TestReportAbuseVerifiedReporter: the reporter address is recorded only
// with a live verification entry of this very link and tenant (T-220).
func TestReportAbuseVerifiedReporter(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev, al := abuseEnv(t, e)
		ctx := context.Background()
		p := ev.publish(ev.a, ev.verifiedSpec(spec{password: true}))
		cookie := ev.verify(p.link(0), "")

		if err := ev.report(p.link(0), ipOne, cookie, "malware", "x"); err != nil {
			t.Fatal(err)
		}
		r := ev.stored(al.last(t))
		if !r.ReporterVerified || r.ReporterEmail != dave || r.RecipientLinkID != p.links[0].ID || *r.RecipientPosition != 0 {
			t.Fatalf("verified report %+v", r)
		}
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{
			TenantID: ev.a.ID, Action: string(audit.ActionAbuseReported), Limit: store.MaxPageSize,
		})
		if err != nil || len(page.Items) != 1 || page.Items[0].Actor != dave || !strings.Contains(string(page.Items[0].Details), `"verified":true`) {
			t.Fatalf("audit %+v, %v", page.Items, err)
		}

		// The entry of link 0 proves nothing on link 1.
		if err := ev.report(p.link(1), ipOne, cookie, "malware", ""); err != nil {
			t.Fatal(err)
		}
		if r := ev.stored(al.last(t)); r.ReporterVerified || r.ReporterEmail != "" || r.RecipientLinkID != p.links[1].ID {
			t.Fatalf("other link %+v", r)
		}
		// An entry of the same link under another tenant proves nothing.
		forged, err := ev.svc.add(verificationSpec, "", ev.b.ID, p.links[0].ID, ev.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		if err := ev.report(p.link(0), ipTwo, forged, "spam", ""); err != nil {
			t.Fatal(err)
		}
		if r := ev.stored(al.last(t)); r.ReporterVerified {
			t.Fatalf("other tenant entry %+v", r)
		}
		// An expired entry proves nothing.
		ev.clock.advance(VerificationTTL + time.Second)
		if err := ev.report(p.link(1), ipTwo, cookie, "spam", ""); err != nil {
			t.Fatal(err)
		}
		if r := ev.stored(al.last(t)); r.ReporterVerified {
			t.Fatalf("expired entry %+v", r)
		}

		// A link of a transfer without the option is proved by its entry
		// too (a reply verification), and an entry of another link is not.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, perRecipient: true, recipients: []string{dave, erin}})
		entry, err := ev.svc.add(verificationSpec, "", ev.a.ID, q.links[1].ID, ev.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		if err := ev.report(q.link(1), ipOne, entry, "other", ""); err != nil {
			t.Fatal(err)
		}
		if r := ev.stored(al.last(t)); !r.ReporterVerified || r.ReporterEmail != erin {
			t.Fatalf("entry without the option %+v", r)
		}
		if err := ev.report(q.link(0), ipOne, entry, "other", ""); err != nil {
			t.Fatal(err)
		}
		if r := ev.stored(al.last(t)); r.ReporterVerified {
			t.Fatalf("entry of another link %+v", r)
		}
		// A failing MAC check of that entry is internal.
		ev.f.set("verifyMAC", 1, nil)
		wantInternal(t, ev.report(q.link(1), ipOne, entry, "other", ""))
	})
}

// TestReportAbuseAccess: unknown and foreign tokens are not found, ended
// transfers gone; a locked or unverified transfer is still reportable.
func TestReportAbuseAccess(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev, al := abuseEnv(t, e)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		v := ev.publish(ev.a, ev.verifiedSpec(spec{}))

		for _, tok := range []string{"", "dl_short", "dl_" + strings.Repeat("A", 43)} {
			q := p
			q.token = tok
			wantErr(t, ev.report(q, ipOne, "", "spam", ""), ErrNotFound)
		}
		foreign := p
		foreign.tn = ev.b
		wantErr(t, ev.report(foreign, ipOne, "", "spam", ""), ErrNotFound)
		wantErr(t, ev.report(p, netip.Addr{}, "", "spam", ""), ErrNoClientIP)

		if err := ev.report(p, ipOne, "", "spam", ""); err != nil {
			t.Fatalf("password protected: %v", err)
		}
		if err := ev.report(v.link(1), ipOne, "", "spam", ""); err != nil {
			t.Fatalf("verification required: %v", err)
		}
		if al.count() != 2 {
			t.Fatalf("%d alerts", al.count())
		}

		ev.setStatus(p, store.TransferDeleted)
		wantErr(t, ev.report(p, ipOne, "", "spam", ""), ErrGone)
		ev.clock.advance(8 * 24 * time.Hour)
		wantErr(t, ev.report(v.link(0), ipOne, "", "spam", ""), ErrGone)
		if al.count() != 2 {
			t.Fatalf("%d alerts", al.count())
		}
	})
}

// TestReportAbuseValidation: closed category, message of at most 1000
// characters once sanitized, in UTF-8.
func TestReportAbuseValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev, al := abuseEnv(t, e)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})

		for _, c := range []string{"", "Phishing", "virus", "other "} {
			wantErr(t, ev.report(p, ipOne, "", c, ""), ErrInvalidCategory)
		}
		wantErr(t, ev.report(p, ipOne, "", "spam", "bad \xff byte"), ErrInvalidMessage)
		wantErr(t, ev.report(p, ipOne, "", "spam", strings.Repeat("é", MaxReportMessageRunes+1)), ErrInvalidMessage)
		if al.count() != 0 {
			t.Fatal("an invalid report was recorded")
		}

		// Hidden characters are removed before the length is checked.
		// U+202E (RLO), U+200B (zero width space) and U+2066 (LRI), as UTF-8 bytes.
		hidden := "\xe2\x80\xaeevil\xe2\x80\x8b\x00\r\n" + strings.Repeat("a", MaxReportMessageRunes-5) + "\xe2\x81\xa6"
		if err := ev.report(p, ipOne, "", "illegal_content", hidden); err != nil {
			t.Fatal(err)
		}
		r := ev.stored(al.last(t))
		if r.Message != "evil\n"+strings.Repeat("a", MaxReportMessageRunes-5) {
			t.Fatalf("message %q", r.Message)
		}
	})
}

// TestReportAbuseLimits: 3 reports per link per day, 5 per IP per hour,
// refused with a Retry-After and a rate_limited security event (D13).
func TestReportAbuseLimits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev, al := abuseEnv(t, e)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, perRecipient: true, recipients: []string{dave, erin}})
		ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")}
		for i := range store.DefaultAbuseReportsPerLink {
			if err := ev.report(p.link(0), ips[i], "", "spam", ""); err != nil {
				t.Fatalf("report %d: %v", i, err)
			}
		}
		err := ev.report(p.link(0), ips[3], "", "spam", "")
		var limited *RateLimitError
		if !errors.As(err, &limited) || limited.RetryAfter != 24*time.Hour || !errors.Is(err, ErrRateLimited) {
			t.Fatalf("4th report on the link: %v", err)
		}
		ev.wantScope(scopeReportsPerLink, p.id)
		// The link limit is per link: the other link still reports.
		if err := ev.report(p.link(1), ips[3], "", "spam", ""); err != nil {
			t.Fatal(err)
		}

		// Per IP: 5 per hour across links and transfers.
		var links []published
		for range 3 {
			q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, perRecipient: true, recipients: []string{dave, erin}})
			links = append(links, q.link(0), q.link(1))
		}
		for i := range store.DefaultAbuseReportsPerIP {
			if err := ev.report(links[i], ipOne, "", "spam", ""); err != nil {
				t.Fatalf("report %d from one IP: %v", i, err)
			}
		}
		err = ev.report(links[5], ipOne, "", "spam", "")
		if !errors.As(err, &limited) || limited.RetryAfter != time.Hour {
			t.Fatalf("6th report from the IP: %v", err)
		}
		ev.wantScope(scopeReportsPerIP, links[5].id)
		if al.count() != store.DefaultAbuseReportsPerLink+1+store.DefaultAbuseReportsPerIP {
			t.Fatalf("%d alerts", al.count())
		}
		// The IP window slides.
		ev.clock.advance(time.Hour + time.Second)
		if err := ev.report(links[5], ipOne, "", "spam", ""); err != nil {
			t.Fatal(err)
		}

		// A store failure is internal, and nothing is alerted.
		n := al.count()
		ev.f.set("report", 1, nil)
		wantInternal(t, ev.report(links[4], ipTwo, "", "spam", ""))
		if al.count() != n {
			t.Fatal("a failed report was alerted")
		}
	})
}

// wantScope fails unless the last security event is a rate_limited event
// of scope about the transfer trfID (truncated).
func (ev *env) wantScope(scope, trfID string) {
	ev.t.Helper()
	all := ev.seclog.all()
	if len(all) == 0 {
		ev.t.Fatal("no security event")
	}
	last := all[len(all)-1]
	var gotScope, gotTrf string
	for _, f := range last.Fields {
		switch f.Key {
		case securitylog.KeyScope:
			gotScope = f.Value
		case keyTransfer:
			gotTrf = f.Value
		}
	}
	if last.Type != securitylog.RateLimited || gotScope != scope || !strings.HasPrefix(trfID, gotTrf) || gotTrf == "" ||
		last.Tenant != ev.a.FQDN {
		ev.t.Fatalf("security event %+v", last)
	}
}

// TestReportAbuseWithoutAlerter: without Options.Abuse the report is still
// recorded.
func TestReportAbuseWithoutAlerter(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		if err := ev.report(p, ipOne, "", "unknown_sender", ""); err != nil {
			t.Fatal(err)
		}
		page, err := ev.db.AbuseReports().List(context.Background(), ev.a.ID, "", store.MaxPageSize, "")
		if err != nil || len(page.Items) != 1 || page.Items[0].Category != store.AbuseCategoryUnknownSender {
			t.Fatalf("reports %+v, %v", page.Items, err)
		}
	})
}
