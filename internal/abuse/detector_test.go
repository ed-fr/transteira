package abuse

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

var clientIP = netip.MustParseAddr("203.0.113.7")

func TestNew(t *testing.T) {
	t.Parallel()
	n, m := &fakeNotifier{}, &fakeMailer{}
	if _, err := New(nil, n, m, failAuditor{}, Options{AdminLink: adminLink}); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("nil db: %v", err)
	}
	db := &store.DB{}
	for name, c := range map[string]struct {
		n    Notifier
		m    Mailer
		a    Auditor
		link string
	}{
		"notifier": {nil, m, failAuditor{}, adminLink},
		"mailer":   {n, nil, failAuditor{}, adminLink},
		"auditor":  {n, m, nil, adminLink},
		"empty":    {n, m, failAuditor{}, ""},
		"relative": {n, m, failAuditor{}, "/admin"},
		"scheme":   {n, m, failAuditor{}, "ftp://admin.example.com"},
		"parse":    {n, m, failAuditor{}, "https://admin.example.com/%zz"},
	} {
		if _, err := New(db, c.n, c.m, c.a, Options{AdminLink: c.link}); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for link, want := range map[string]string{
		"https://admin.example.com/admin":  "https://admin.example.com",
		"https://admin.example.com/admin/": "https://admin.example.com",
		"http://admin.example.com":         "http://admin.example.com",
	} {
		d, err := New(db, n, m, failAuditor{}, Options{AdminLink: link})
		if err != nil || d.adminBase != want || d.now == nil || d.logger == nil || d.events == nil {
			t.Errorf("%s: %+v %v", link, d, err)
		}
	}
}

func TestCheckCreateTx(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		blocking := func(s *store.AbuseSettings) {
			s.BlockOnExceed = true
			s.MaxDailyBytesPerSender, s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = i64p(1000), intp(3), intp(2)
			s.ExternalMaxDailyBytes, s.ExternalMaxDailyDeposits = i64p(500), intp(2)
		}
		a := ev.tenant(settings(blocking))
		// Same thresholds without blocking.
		b := ev.tenant(settings(func(s *store.AbuseSettings) { blocking(s); s.BlockOnExceed = false }))
		// Paris day of t0: 2026-10-22. Yesterday's 900 bytes are not counted.
		ev.transfer(a, alice, store.DepositorInternal, 900, t0.Add(-24*time.Hour))
		ev.transfer(a, alice, store.DepositorInternal, 400, t0.Add(-time.Hour))
		ev.transfer(a, alice, store.DepositorInternalRemote, 100, t0.Add(-2*time.Hour))
		ev.transfer(b, alice, store.DepositorInternal, 1<<30, t0.Add(-time.Hour))

		facts := Facts{SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 500, Recipients: []string{ext}, At: t0}
		if blk, err := ev.check(a, facts); err != nil || blk != nil {
			t.Fatalf("1000 of 1000 bytes: %+v %v", blk, err)
		}
		facts.Bytes = 501
		blk, err := ev.check(a, facts)
		if err != nil || blk == nil || blk.Rule != store.AbuseRuleDailyBytes || blk.Value != 1001 || blk.Threshold != 1000 {
			t.Fatalf("1001 bytes: %+v %v", blk, err)
		}
		// Not blocking tenant (B has 1 GiB today): no block, no query.
		if blk, err := ev.check(b, facts); err != nil || blk != nil {
			t.Fatalf("tenant B: %+v %v", blk, err)
		}
		// Third and fourth transfers of the day.
		ev.transfer(a, alice, store.DepositorInternal, 0, t0.Add(-3*time.Hour))
		facts.Bytes = 0
		if blk, _ := ev.check(a, facts); blk == nil || blk.Rule != store.AbuseRuleDailyTransfers || blk.Value != 4 || blk.Threshold != 3 {
			t.Fatalf("4 transfers: %+v", blk)
		}
		// Recipients, for another sender (no activity).
		other := Facts{SenderEmail: "dave@entity-a.example.com", Kind: store.DepositorInternal, Recipients: []string{"a@x.example", "b@x.example", "c@x.example"}, At: t0}
		if blk, _ := ev.check(a, other); blk == nil || blk.Rule != store.AbuseRuleRecipients || blk.Value != 3 || blk.Threshold != 2 {
			t.Fatalf("recipients: %+v", blk)
		}
		// External quota: kind external only, bytes variant first.
		ev.transfer(a, ext, store.DepositorExternal, 300, t0.Add(-time.Hour))
		extFacts := Facts{SenderEmail: ext, Kind: store.DepositorExternal, Bytes: 200, Recipients: []string{alice}, At: t0}
		if blk, err := ev.check(a, extFacts); err != nil || blk != nil {
			t.Fatalf("external 500 of 500: %+v %v", blk, err)
		}
		extFacts.Bytes = 201
		blk, _ = ev.check(a, extFacts)
		if blk == nil || blk.Rule != store.AbuseRuleExternalQuota || blk.Value != 501 || !blk.bytes {
			t.Fatalf("external bytes: %+v", blk)
		}
		ev.transfer(a, ext, store.DepositorExternal, 0, t0.Add(-time.Hour))
		extFacts.Bytes = 0
		blk, _ = ev.check(a, extFacts)
		if blk == nil || blk.Rule != store.AbuseRuleExternalQuota || blk.Value != 3 || blk.Threshold != 2 || blk.bytes {
			t.Fatalf("external deposits: %+v", blk)
		}
		// An external depositor is governed by the external quota alone:
		// neither the recipients nor the daily per-sender rules apply.
		eve := Facts{SenderEmail: "eve@elsewhere.example", Kind: store.DepositorExternal, Recipients: []string{alice, "b@x.example", "c@x.example"}, At: t0}
		if blk, err := ev.check(a, eve); err != nil || blk != nil {
			t.Fatalf("per-sender rules applied to an external depositor: %+v %v", blk, err)
		}
		// The external transfers of an address do not count in its daily
		// internal activity.
		frank := "frank@entity-a.example.com"
		ev.transfer(a, frank, store.DepositorExternal, 2000, t0.Add(-time.Hour))
		if blk, err := ev.check(a, Facts{SenderEmail: frank, Kind: store.DepositorInternalRemote, Bytes: 10, At: t0}); err != nil || blk != nil {
			t.Fatalf("external activity counted as internal: %+v %v", blk, err)
		}
		// The same address depositing as an internal kind is not subject to
		// the external quota.
		intFacts := extFacts
		intFacts.Kind = store.DepositorInternal
		if blk, _ := ev.check(a, intFacts); blk != nil {
			t.Fatalf("external quota applied to an internal kind: %+v", blk)
		}
		// A zero At uses the clock.
		facts.At, facts.Bytes = time.Time{}, 0
		if blk, _ := ev.check(a, facts); blk == nil {
			t.Fatal("zero At: no block")
		}
		// CheckCreateTx never writes: no alert row, no audit event.
		if len(ev.audits(a, audit.ActionAbuseThresholdExceeded)) != 0 || len(ev.events.all()) != 0 {
			t.Fatal("CheckCreateTx wrote")
		}

		// Failures.
		ev.fault.settingsTxErr = errBoom
		if _, err := ev.check(a, facts); !errors.Is(err, errBoom) {
			t.Errorf("settings: %v", err)
		}
		ev.fault.settingsTxErr = nil
		ev.fault.activityTxErr, ev.fault.activityTxErrMain = errBoom, true
		if _, err := ev.check(a, facts); !errors.Is(err, errBoom) {
			t.Errorf("activity: %v", err)
		}
		ev.fault.activityTxErrMain, ev.fault.activityTxErrExt = false, true
		if _, err := ev.check(a, extFacts); !errors.Is(err, errBoom) {
			t.Errorf("external activity: %v", err)
		}
	})
}

func TestBlocked(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(nil))
		ev.admin(store.RoleDelegatedAdmin, "admin-a@entity-a.example.com", a.ID)
		ev.admin(store.RoleSuperAdmin, "root@example.com")
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // ignored: best effort
		f := Facts{SenderEmail: ext, Kind: store.DepositorExternal, Bytes: 10, At: t0, ClientIP: clientIP}
		blk := Block{Rule: store.AbuseRuleExternalQuota, Value: 600, Threshold: 500, bytes: true}
		// The later refusals of the day are only counted: one audit event.
		ev.det.Blocked(ctx, a, f, blk)
		ev.det.Blocked(ctx, a, f, blk)
		ev.det.Blocked(ctx, a, f, blk)

		rows := ev.audits(a, audit.ActionAbuseThresholdExceeded)
		if len(rows) != 1 {
			t.Fatalf("audits = %d", len(rows))
		}
		r := rows[0]
		d := details(t, r)
		if r.ActorKind != store.ActorDepositor || r.Actor != ext || r.IP != clientIP || r.ObjectKind != audit.ObjectTenant ||
			r.ObjectID != string(a.ID) || d["rule"] != "external_quota" || d["value"] != float64(600) ||
			d["threshold"] != float64(500) || d["blocked"] != true || d["transferId"] != nil {
			t.Fatalf("audit = %+v %v", r, d)
		}
		mails := ev.notifier.alertData()
		if len(mails) != 1 || ev.mailer.count() != 1 {
			t.Fatalf("mails = %d, sends = %d", len(mails), ev.mailer.count())
		}
		m := mails[0]
		if m.Rule != "external_quota" || !m.Bytes || !m.Blocked || m.Day != "2026-10-22" || m.SenderEmail != ext ||
			m.Value != 600 || m.Threshold != 500 || m.AdminLink != "https://admin.example.com/admin/tenants/"+string(a.ID)+"/audit" {
			t.Fatalf("mail = %+v", m)
		}
		// Delegated admins only (not the super admin).
		if rc := ev.notifier.recipients[0]; len(rc) != 1 || rc[0].Email != "admin-a@entity-a.example.com" || rc[0].Language != "fr" {
			t.Fatalf("recipients = %+v", rc)
		}
		evs := ev.events.all()
		if len(evs) != 1 {
			t.Fatalf("events = %d", len(evs))
		}
		x := evs[0]
		if x.Type != events.AbuseThresholdExceeded || x.Severity != events.SeverityWarning || x.TenantID != string(a.ID) ||
			x.Counts["value"] != 600 || x.Counts["threshold"] != 500 || x.Addresses == nil || x.Addresses.Sender != ext ||
			x.AdminPath != events.AdminPathTenantAudit(string(a.ID)) || !x.OccurredAt.Equal(t0) {
			t.Fatalf("event = %+v", x)
		}

		// Settings failure: UTC day, still recorded.
		ev.fault.settingsErr = errBoom
		late := f
		late.At = time.Date(2026, 10, 22, 23, 30, 0, 0, time.UTC) // 2026-10-23 in Paris
		ev.det.Blocked(context.Background(), a, late, blk)
		ev.fault.settingsErr = nil
		if mails := ev.notifier.alertData(); len(mails) != 1 {
			t.Fatalf("UTC day 2026-10-22 alerted again: %d", len(mails))
		}
		ev.wantLog("abuse: failed to read the abuse settings")
		ev.det.Blocked(context.Background(), a, late, blk)
		if mails := ev.notifier.alertData(); len(mails) != 2 || mails[1].Day != "2026-10-23" {
			t.Fatalf("Paris day 2026-10-23: %+v", mails)
		}
		if n := len(ev.audits(a, audit.ActionAbuseThresholdExceeded)); n != 2 {
			t.Fatalf("audits after the second day = %d", n)
		}
	})
}

// TestBlockedAfterAlert checks that an alert-only alert earlier in the day
// does not mask a refusal of the same sender and rule, and conversely.
func TestBlockedAfterAlert(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(func(s *store.AbuseSettings) { s.MaxDailyBytesPerSender = i64p(100) }))
		ev.admin(store.RoleSuperAdmin, "root@example.com")
		ctx := context.Background()
		trf := ev.transfer(a, alice, store.DepositorInternal, 200, t0)
		created := Facts{TransferID: trf, SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 200, At: t0}
		ev.det.AfterCreate(ctx, a, created)
		ev.det.AfterCreate(ctx, a, created)
		blk := Block{Rule: store.AbuseRuleDailyBytes, Value: 300, Threshold: 100}
		refused := Facts{SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 100, At: t0.Add(time.Minute)}
		ev.det.Blocked(ctx, a, refused, blk)
		ev.det.Blocked(ctx, a, refused, blk)
		ev.det.AfterCreate(ctx, a, created)

		mails := ev.notifier.alertData()
		if len(mails) != 2 || mails[0].Blocked || !mails[1].Blocked || len(ev.events.all()) != 2 {
			t.Fatalf("mails = %+v, events = %d", mails, len(ev.events.all()))
		}
		var alerts, refusals int
		for _, r := range ev.audits(a, audit.ActionAbuseThresholdExceeded) {
			if details(t, r)["blocked"] == true {
				refusals++
			} else {
				alerts++
			}
		}
		// Every created transfer is audited, the refusal once.
		if alerts != 3 || refusals != 1 {
			t.Fatalf("alerts = %d, refusals = %d", alerts, refusals)
		}
	})
}

func TestAfterCreate(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		all := func(s *store.AbuseSettings) {
			s.BlockOnExceed = true // AfterCreate alerts only
			s.MaxDailyBytesPerSender, s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = i64p(1000), intp(1), intp(1)
			s.UnusualVolumePct, s.UnusualMinHistoryDays = intp(200), 2
			s.LargeExternalTransferBytes = i64p(500)
			s.OfficeStartMinute, s.OfficeEndMinute = intp(8*60), intp(10*60) // 11:00 Paris is off hours
		}
		a := ev.tenant(settings(all))
		b := ev.tenant(settings(nil))
		ev.admin(store.RoleSuperAdmin, "root@example.com")
		// History: 100 bytes on two days of the window (average 200/30).
		ev.transfer(a, alice, store.DepositorInternal, 100, t0.AddDate(0, 0, -3))
		ev.transfer(a, alice, store.DepositorInternal, 100, t0.AddDate(0, 0, -10))
		ev.transfer(a, alice, store.DepositorInternal, 0, t0.Add(-time.Hour))
		trf := ev.transfer(a, alice, store.DepositorInternalRemote, 2000, t0)
		// Tenant B: same sender, no threshold.
		ev.transfer(b, alice, store.DepositorInternal, 1<<30, t0)
		f := Facts{
			TransferID: trf, SenderEmail: alice, Kind: store.DepositorInternalRemote, Bytes: 2000,
			Recipients: []string{"carol@entity-a.example.com", ext}, At: t0, ClientIP: clientIP,
		}
		ev.det.AfterCreate(context.Background(), a, f)

		threshold := ev.audits(a, audit.ActionAbuseThresholdExceeded)
		unusual := ev.audits(a, audit.ActionAbuseUnusualActivity)
		rules := map[string]map[string]any{}
		for _, r := range append(threshold, unusual...) {
			d := details(t, r)
			rules[d["rule"].(string)] = d
			if r.Actor != alice || r.ObjectKind != audit.ObjectTransfer || r.ObjectID != trf || d["transferId"] != trf || d["blocked"] != false {
				t.Errorf("audit = %+v %v", r, d)
			}
		}
		if len(threshold) != 3 || len(unusual) != 3 || len(rules) != 6 {
			t.Fatalf("rules = %v", rules)
		}
		if d := rules["daily_bytes"]; d["value"] != float64(2000) || d["threshold"] != float64(1000) {
			t.Errorf("daily bytes = %v", d)
		}
		if d := rules["daily_transfers"]; d["value"] != float64(2) || d["threshold"] != float64(1) {
			t.Errorf("daily transfers = %v", d)
		}
		if d := rules["recipients"]; d["value"] != float64(2) {
			t.Errorf("recipients = %v", d)
		}
		if d := rules["unusual_volume"]; math.Abs(d["value"].(float64)-300) > 1e-9 || d["threshold"] != float64(2) {
			t.Errorf("unusual = %v", d)
		}
		if d := rules["large_external"]; d["value"] != float64(2000) || d["threshold"] != float64(500) {
			t.Errorf("large external = %v", d)
		}
		if d := rules["off_hours"]; d["value"] != float64(11*60) {
			t.Errorf("off hours = %v", d)
		}
		if n := len(ev.notifier.alertData()); n != 6 || ev.mailer.count() != 6 || len(ev.events.all()) != 6 {
			t.Fatalf("mails = %d, events = %d", n, len(ev.events.all()))
		}
		for _, m := range ev.notifier.alertData() {
			if m.Rule == "off_hours" && !m.At.Equal(t0) {
				t.Errorf("off hours At = %v", m.At)
			}
		}
		// Super admin fallback.
		if rc := ev.notifier.recipients[0]; len(rc) != 1 || rc[0].Email != "root@example.com" {
			t.Errorf("recipients = %+v", rc)
		}
		types := map[events.Type]int{}
		for _, x := range ev.events.all() {
			types[x.Type]++
		}
		if types[events.AbuseThresholdExceeded] != 3 || types[events.AbuseUnusualActivity] != 3 {
			t.Errorf("event types = %v", types)
		}

		// Second evaluation the same day: audited again, no mail nor event.
		ev.det.AfterCreate(context.Background(), a, f)
		if len(ev.audits(a, audit.ActionAbuseThresholdExceeded)) != 6 || len(ev.notifier.alertData()) != 6 || len(ev.events.all()) != 6 {
			t.Fatal("deduplication failed")
		}
		// Cross-tenant: the thresholds of A never apply to B.
		ev.det.AfterCreate(context.Background(), b, Facts{SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 1 << 30, Recipients: []string{ext, ext}, At: t0})
		if len(ev.audits(b, audit.ActionAbuseThresholdExceeded))+len(ev.audits(b, audit.ActionAbuseUnusualActivity)) != 0 {
			t.Fatal("tenant B alerted with the settings of A")
		}
	})
}

func TestAfterCreateKinds(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(func(s *store.AbuseSettings) {
			s.ExternalMaxDailyBytes, s.ExternalMaxDailyDeposits = i64p(100), intp(5)
			s.MaxDailyBytesPerSender, s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = i64p(1), intp(1), intp(1)
			s.UnusualVolumePct, s.UnusualMinHistoryDays = intp(200), 1
			s.LargeExternalTransferBytes = i64p(1)
			s.OfficeStartMinute, s.OfficeEndMinute = intp(0), intp(60)
		}))
		ev.admin(store.RoleSuperAdmin, "root@example.com")
		ev.transfer(a, ext, store.DepositorExternal, 50, t0.AddDate(0, 0, -2))
		trf := ev.transfer(a, ext, store.DepositorExternal, 150, t0)
		// External sender: only the external quota (bytes); neither the
		// per-sender limits nor the internal behavior rules apply.
		ev.det.AfterCreate(context.Background(), a, Facts{TransferID: trf, SenderEmail: ext, Kind: store.DepositorExternal, Bytes: 150, Recipients: []string{"x@elsewhere.example", "y@elsewhere.example"}, At: t0})
		rows := ev.audits(a, audit.ActionAbuseThresholdExceeded)
		if len(rows) != 1 || len(ev.audits(a, audit.ActionAbuseUnusualActivity)) != 0 {
			t.Fatalf("external: %d threshold events", len(rows))
		}
		if d := details(t, rows[0]); d["rule"] != "external_quota" || d["value"] != float64(150) {
			t.Fatalf("external quota = %v", d)
		}
		if m := ev.notifier.alertData(); len(m) != 1 || !m[0].Bytes {
			t.Fatalf("mail = %+v", m)
		}
		// Internal sender with no activity of the day (not stored): no
		// unusual volume query; 00:30 Paris is in office hours here.
		ev.det.AfterCreate(context.Background(), a, Facts{
			SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 0, Recipients: []string{alice},
			At: time.Date(2026, 10, 21, 22, 30, 0, 0, time.UTC),
		})
		if len(ev.audits(a, audit.ActionAbuseUnusualActivity)) != 0 {
			t.Fatal("internal sender without volume alerted")
		}
	})
}

func TestAfterCreateFailures(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(func(s *store.AbuseSettings) {
			s.MaxDailyBytesPerSender, s.UnusualVolumePct, s.UnusualMinHistoryDays = i64p(1), intp(200), 1
			s.LargeExternalTransferBytes, s.MaxRecipientsPerTransfer = i64p(1), intp(1)
			s.ExternalMaxDailyBytes = i64p(1)
		}))
		ev.transfer(a, alice, store.DepositorInternal, 10, t0)
		internal := Facts{SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 10, Recipients: []string{ext, ext}, At: t0}
		external := Facts{SenderEmail: ext, Kind: store.DepositorExternal, Bytes: 10, Recipients: []string{alice}, At: t0}
		ctx := context.Background()

		ev.fault.settingsErr = errBoom
		ev.det.AfterCreate(ctx, a, internal)
		ev.fault.settingsErr = nil
		ev.wantLog("failed to read the abuse settings")
		if len(ev.audits(a, audit.ActionAbuseThresholdExceeded)) != 0 {
			t.Fatal("alerted without settings")
		}

		// Activity, history, domains and external activity failures: the
		// other rules still alert.
		ev.fault.activityErr, ev.fault.domainsErr, ev.fault.extActivityErr = errBoom, errBoom, errBoom
		ev.det.AfterCreate(ctx, a, internal)
		ev.det.AfterCreate(ctx, a, external)
		ev.fault.activityErr, ev.fault.domainsErr, ev.fault.extActivityErr = nil, nil, nil
		ev.wantLog("failed to sum the sender activity")
		ev.wantLog("failed to read the internal domains")
		ev.wantLog("failed to sum the external activity")
		if n := len(ev.audits(a, audit.ActionAbuseThresholdExceeded)); n != 1 { // recipients of the internal one
			t.Fatalf("threshold events = %d", n)
		}
		ev.fault.historyErr = errBoom
		ev.det.AfterCreate(ctx, a, internal)
		ev.fault.historyErr = nil
		ev.wantLog("failed to list the sender history")
		if n := len(ev.audits(a, audit.ActionAbuseUnusualActivity)); n != 1 { // large external only
			t.Fatalf("unusual events = %d", n)
		}
	})
}

func TestAlertFailures(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(nil))
		ctx := context.Background()
		blk := Block{Rule: store.AbuseRuleDailyBytes, Value: 2, Threshold: 1}
		facts := func(sender string) Facts { return Facts{SenderEmail: sender, At: t0} }

		// Audit failure: logged, the alert still goes out.
		ev.det.auditor = failAuditor{}
		ev.det.Blocked(ctx, a, facts("s1@entity-a.example.com"), blk)
		ev.det.auditor = audit.New(ev.db)
		ev.wantLog("failed to record the audit event")
		if len(ev.events.all()) != 1 {
			t.Fatal("no event after an audit failure")
		}
		// No administrator at all.
		ev.wantLog("abuse: no administrator to notify")

		// Deduplication failure: no event, no mail.
		ev.fault.alertErr = errBoom
		ev.det.Blocked(ctx, a, facts("s2@entity-a.example.com"), blk)
		ev.fault.alertErr = nil
		ev.wantLog("failed to record the alert")
		if len(ev.events.all()) != 1 {
			t.Fatal("event after a deduplication failure")
		}
		// The refusal is still audited.
		audited := 0
		for _, r := range ev.audits(a, audit.ActionAbuseThresholdExceeded) {
			if r.Actor == "s2@entity-a.example.com" {
				audited++
			}
		}
		if audited != 1 {
			t.Fatalf("refusal audited %d times after a deduplication failure", audited)
		}

		ev.admin(store.RoleDelegatedAdmin, "admin-a@entity-a.example.com", a.ID)
		ev.fault.contactsErr = errBoom
		ev.det.Blocked(ctx, a, facts("s3@entity-a.example.com"), blk)
		ev.fault.contactsErr = nil
		ev.wantLog("failed to list the administrators to notify")

		ev.notifier.err = notify.ErrNoSMTP
		ev.det.Blocked(ctx, a, facts("s4@entity-a.example.com"), blk)
		ev.wantLog("abuse: no abuse alert sent: the tenant has no SMTP settings")
		ev.notifier.err = errBoom
		ev.det.Blocked(ctx, a, facts("s5@entity-a.example.com"), blk)
		ev.wantLog("failed to build the abuse alert mails")
		ev.notifier.err = nil
		if ev.mailer.count() != 0 {
			t.Fatalf("sends = %d", ev.mailer.count())
		}

		// A malformed tenant never reaches the store.
		if _, err := (storeRepo{db: ev.db}).tryAlert(ctx, "bad tenant", alice, blk.Rule, "2026-10-22", true, t0); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("tryAlert(bad tenant) = %v", err)
		}

		// Super admin lookup failure (no delegated admin on B).
		b := ev.tenant(settings(nil))
		ev.fault.superErr = errBoom
		ev.det.Blocked(ctx, b, facts("s6@entity-a.example.com"), blk)
		ev.fault.superErr = nil
		if ev.mailer.count() != 0 {
			t.Fatal("mail sent without contacts")
		}
	})
}

func TestAfterExtend(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(func(s *store.AbuseSettings) {
			s.BlockOnExceed = true
			s.MaxDailyBytesPerSender, s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = i64p(100), intp(1), intp(1)
			s.OfficeStartMinute, s.OfficeEndMinute = intp(0), intp(1)
		}))
		b := ev.tenant(settings(func(s *store.AbuseSettings) { s.MaxRecipientsPerTransfer = intp(1) }))
		trf := ev.transfer(a, alice, store.DepositorInternal, 200, t0)
		ev.transfer(a, alice, store.DepositorInternal, 1, t0)
		f := Facts{TransferID: trf, SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 200, Recipients: []string{ext, ext}, At: t0}
		ev.det.AfterExtend(context.Background(), a, f)
		rows := ev.audits(a, audit.ActionAbuseThresholdExceeded)
		if len(rows) != 2 || len(ev.audits(a, audit.ActionAbuseUnusualActivity)) != 0 {
			t.Fatalf("events = %d", len(rows))
		}
		for _, r := range rows {
			d := details(t, r)
			if d["blocked"] != false || (d["rule"] != "daily_bytes" && d["rule"] != "daily_transfers") {
				t.Errorf("extend = %v", d)
			}
		}
		// An external depositor: the daily rules do not apply.
		ev.transfer(a, ext, store.DepositorExternal, 500, t0)
		ev.det.AfterExtend(context.Background(), a, Facts{SenderEmail: ext, Kind: store.DepositorExternal, Bytes: 500, At: t0})
		if n := len(ev.audits(a, audit.ActionAbuseThresholdExceeded)); n != 2 {
			t.Fatalf("external extension alerted: %d events", n)
		}
		// No daily threshold on B: nothing evaluated.
		ev.det.AfterExtend(context.Background(), b, f)
		if len(ev.audits(b, audit.ActionAbuseThresholdExceeded)) != 0 {
			t.Fatal("tenant B alerted")
		}
		ev.fault.settingsErr = errBoom
		ev.det.AfterExtend(context.Background(), a, f)
		ev.fault.settingsErr = nil
		ev.wantLog("failed to read the abuse settings")
		ev.fault.activityErr = errBoom
		ev.det.AfterExtend(context.Background(), a, f)
		ev.fault.activityErr = nil
		ev.wantLog("failed to sum the sender activity")
		if len(ev.audits(a, audit.ActionAbuseThresholdExceeded)) != 2 {
			t.Fatal("alerted after a failure")
		}
	})
}

func TestInvitations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(func(s *store.AbuseSettings) { s.MaxInvitationsPerInviter = 7 }))
		b := ev.tenant(settings(nil))
		ctx := context.Background()
		if n, err := ev.det.InvitationLimit(ctx, a.ID); err != nil || n != 7 {
			t.Fatalf("limit A = %d %v", n, err)
		}
		if n, err := ev.det.InvitationLimit(ctx, b.ID); err != nil || n != store.DefaultMaxInvitationsPerInviter {
			t.Fatalf("limit B = %d %v", n, err)
		}
		ev.fault.settingsErr = errBoom
		if _, err := ev.det.InvitationLimit(ctx, a.ID); !errors.Is(err, errBoom) {
			t.Fatalf("limit error = %v", err)
		}
		ev.fault.settingsErr = nil

		ev.det.InvitationLimitReached(ctx, a, alice, 7)
		ev.det.InvitationLimitReached(ctx, a, alice, 7)
		rows := ev.audits(a, audit.ActionAbuseThresholdExceeded)
		if len(rows) != 2 || len(ev.events.all()) != 1 {
			t.Fatalf("audits = %d, events = %d", len(rows), len(ev.events.all()))
		}
		d := details(t, rows[0])
		if rows[0].Actor != alice || rows[0].IP.IsValid() || d["rule"] != "invitations" || d["value"] != float64(7) || d["threshold"] != float64(7) {
			t.Fatalf("audit = %+v %v", rows[0], d)
		}
		if len(ev.audits(b, audit.ActionAbuseThresholdExceeded)) != 0 {
			t.Fatal("tenant B recorded")
		}
	})
}

func TestReported(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(nil))
		ev.admin(store.RoleDelegatedAdmin, "admin-a@entity-a.example.com", a.ID)
		pos := 1
		verified := store.AbuseReport{
			ID: "abr_1", TransferID: "trf_1", RecipientLinkID: "rcl_1", RecipientPosition: &pos, SenderEmail: alice,
			ReporterEmail: ext, ReporterVerified: true, Category: store.AbuseCategory("phishing"), Message: "Looks <b>bad</b>",
		}
		ev.det.Reported(context.Background(), a, verified)
		shared := store.AbuseReport{ID: "abr_2", TransferID: "trf_2", SenderEmail: alice, Category: "spam"}
		ev.det.Reported(context.Background(), a, shared)
		// Unverified: the address of the report is never passed on.
		unverified := verified
		unverified.ReporterVerified = false
		ev.det.Reported(context.Background(), a, unverified)

		reps := ev.notifier.reports
		if len(reps) != 3 || ev.mailer.count() != 3 {
			t.Fatalf("reports = %d", len(reps))
		}
		link := "https://admin.example.com/admin/tenants/" + string(a.ID) + "/abuse-reports"
		if r := reps[0]; r.TenantName != a.Name || r.TransferID != "trf_1" || r.SenderEmail != alice || r.Category != "phishing" ||
			r.Message != "Looks <b>bad</b>" || r.ReporterEmail != ext || r.RecipientIndex != 2 || r.AdminLink != link {
			t.Fatalf("verified = %+v", r)
		}
		if r := reps[1]; r.ReporterEmail != "" || r.RecipientIndex != 0 || r.Category != "spam" {
			t.Fatalf("shared = %+v", r)
		}
		if r := reps[2]; r.ReporterEmail != "" || r.RecipientIndex != 2 {
			t.Fatalf("unverified = %+v", r)
		}
		evs := ev.events.all()
		if len(evs) != 3 {
			t.Fatalf("events = %d", len(evs))
		}
		if x := evs[0]; x.Type != events.AbuseReported || x.Severity != events.SeverityWarning || x.TenantID != string(a.ID) ||
			x.Addresses.Sender != alice || x.Addresses.Reporter != ext || x.AdminPath != events.AdminPathTenantAbuseReports(string(a.ID)) {
			t.Fatalf("event = %+v", x)
		}
		if evs[2].Addresses.Reporter != "" {
			t.Fatal("unverified reporter published")
		}
	})
}

// TestCheckCreateTxReplies counts the replies of section 10 in the external
// quota of their address, together with its invited deposits, and never in
// the per-sender daily rules of an internal address.
func TestCheckCreateTxReplies(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ev := newEnv(t, e)
		a := ev.tenant(settings(func(s *store.AbuseSettings) {
			s.BlockOnExceed = true
			s.MaxDailyBytesPerSender, s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = i64p(1000), intp(1), intp(1)
			s.ExternalMaxDailyBytes, s.ExternalMaxDailyDeposits = i64p(500), intp(2)
		}))
		// External quota, bytes: an earlier reply of 300 bytes counts.
		ev.transfer(a, ext, store.DepositorReply, 300, t0.Add(-time.Hour))
		reply := Facts{SenderEmail: ext, Kind: store.DepositorReply, Bytes: 200, Recipients: []string{alice}, At: t0}
		if blk, err := ev.check(a, reply); err != nil || blk != nil {
			t.Fatalf("reply 500 of 500: %+v %v", blk, err)
		}
		reply.Bytes = 201
		if blk, _ := ev.check(a, reply); blk == nil || blk.Rule != store.AbuseRuleExternalQuota || blk.Value != 501 || !blk.bytes {
			t.Fatalf("reply bytes: %+v", blk)
		}
		// External quota, deposits: an invited deposit and a reply of the
		// same address count together, whichever kind the new one is.
		eve := "eve@elsewhere.example"
		ev.transfer(a, eve, store.DepositorExternal, 0, t0.Add(-time.Hour))
		ev.transfer(a, eve, store.DepositorReply, 0, t0.Add(-time.Hour))
		for _, kind := range []store.DepositorKind{store.DepositorReply, store.DepositorExternal} {
			blk, _ := ev.check(a, Facts{SenderEmail: eve, Kind: kind, Recipients: []string{alice}, At: t0})
			if blk == nil || blk.Rule != store.AbuseRuleExternalQuota || blk.Value != 3 || blk.Threshold != 2 || blk.bytes {
				t.Fatalf("%s deposits: %+v", kind, blk)
			}
		}
		// A reply is governed by the external quota alone: the recipients
		// rule does not apply.
		many := Facts{SenderEmail: "zoe@elsewhere.example", Kind: store.DepositorReply, Recipients: []string{alice, "b@x.example"}, At: t0}
		if blk, err := ev.check(a, many); err != nil || blk != nil {
			t.Fatalf("per-sender rules applied to a reply: %+v %v", blk, err)
		}
		// The replies of an internal address never count in its daily
		// internal activity (2 replies, 4000 bytes: no daily_* block).
		frank := "frank@entity-a.example.com"
		ev.transfer(a, frank, store.DepositorReply, 2000, t0.Add(-time.Hour))
		ev.transfer(a, frank, store.DepositorReply, 2000, t0.Add(-time.Hour))
		if blk, err := ev.check(a, Facts{SenderEmail: frank, Kind: store.DepositorInternal, Bytes: 10, Recipients: []string{ext}, At: t0}); err != nil || blk != nil {
			t.Fatalf("replies counted as internal activity: %+v %v", blk, err)
		}
	})
}
