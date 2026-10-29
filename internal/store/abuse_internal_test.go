package store

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// abuseFixture is a transferFixture with one abuse report of the fixture
// transfer and one alert of its sender.
type abuseFixture struct {
	*transferFixture
	report AbuseReport
}

// newAbuseFixture builds an abuseFixture.
func newAbuseFixture(t *testing.T) *abuseFixture {
	t.Helper()
	ctx := context.Background()
	f := &abuseFixture{transferFixture: newTransferFixture(t)}
	var err error
	f.report, err = f.db.AbuseReports().Create(ctx, f.tid, testAbuseReport(f.trf.ID), AbuseReportLimits{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	err = f.tx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.AbuseAlerts().TryInsertTx(ctx, tx, fixtureEmail, AbuseRuleDailyBytes, "2026-10-19", false, time.Time{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// textReport adds a report of the fixture transfer whose message quotes
// the fixture sender.
func (f *abuseFixture) textReport(ctx context.Context) error {
	r := testAbuseReport(f.trf.ID)
	r.SenderEmail, r.ReporterEmail, r.ReporterVerified, r.Message = "bob@b.example.org", "", false, "From "+fixtureEmail
	r.RecipientLinkID, r.RecipientPosition = "", nil
	_, err := f.db.AbuseReports().Create(ctx, f.tid, r, AbuseReportLimits{}, time.Time{})
	return err
}

// testAbuseReport returns a valid verified report of trfID.
func testAbuseReport(trfID string) AbuseReport {
	pos := 0
	return AbuseReport{
		TransferID: trfID, RecipientLinkID: id.New(id.RecipientLink), RecipientPosition: &pos,
		SenderEmail: fixtureEmail, ReporterEmail: "bob@b.example.org", ReporterVerified: true,
		ReporterIP: netip.MustParseAddr("192.0.2.1"), Category: AbuseCategorySpam,
	}
}

// TestAbuseDriverFaults makes each statement of the abuse repositories
// fail and checks that the error surfaces.
func TestAbuseDriverFaults(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	note := "n"
	steps := []struct {
		name, op, match string
		run             func(context.Context, *abuseFixture) error
	}{
		{"get settings", faultQuery, "FROM tenant_abuse_settings", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseSettings().Get(ctx, f.tid)
			return err
		}},
		{"get settings tx", faultQuery, "FROM tenant_abuse_settings", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseSettings().GetTx(ctx, tx)
				return err
			})
		}},
		{"put settings", faultExec, "UPDATE tenant_abuse_settings", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseSettings().Put(ctx, f.tid, DefaultAbuseSettings())
			return err
		}},
		{"alert increment", faultExec, "UPDATE abuse_alerts SET attempts", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseAlerts().TryInsertTx(ctx, tx, fixtureEmail, AbuseRuleOffHours, "2026-10-19", true, now)
				return err
			})
		}},
		{"alert increment rows", faultRows, "UPDATE abuse_alerts SET attempts", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseAlerts().TryInsertTx(ctx, tx, fixtureEmail, AbuseRuleOffHours, "2026-10-19", true, now)
				return err
			})
		}},
		{"alert insert", faultExec, "INSERT INTO abuse_alerts", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseAlerts().TryInsertTx(ctx, tx, fixtureEmail, AbuseRuleOffHours, "2026-10-19", false, now)
				return err
			})
		}},
		{"alert delete", faultExec, "DELETE FROM abuse_alerts WHERE tenant_id = ? AND sender_email", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseAlerts().DeleteByEmailTx(ctx, tx, fixtureEmail)
				return err
			})
		}},
		{"alert purge", faultExec, "DELETE FROM abuse_alerts WHERE tenant_id = ? AND created_at", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseAlerts().Purge(ctx, f.tid, now)
			return err
		}},
		{"activity", faultQuery, "GROUP BY sender_kind", func(ctx context.Context, f *abuseFixture) error {
			_, _, err := f.db.Transfers().SenderActivity(ctx, f.tid, fixtureEmail, time.Time{}, time.Now().Add(24*time.Hour), nil)
			return err
		}},
		{"activity scan", faultScanNil, "GROUP BY sender_kind", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, _, err := f.db.Transfers().SenderActivityTx(ctx, tx, fixtureEmail, time.Time{}, time.Now().Add(24*time.Hour), nil)
				return err
			})
		}},
		{"history", faultQuery, "SELECT created_at, total_bytes", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.Transfers().SenderHistory(ctx, f.tid, fixtureEmail, time.Time{}, 10)
			return err
		}},
		{"history scan", faultScanNil, "SELECT created_at, total_bytes", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.Transfers().SenderHistory(ctx, f.tid, fixtureEmail, time.Time{}, 10)
			return err
		}},
		{"report count link", faultQuery, "recipient_link_id = ? AND created_at", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseReports().Create(ctx, f.tid, testAbuseReport(f.trf.ID), DefaultAbuseReportLimits(), now)
			return err
		}},
		{"report count ip", faultQuery, "reporter_ip = ? AND created_at", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().CreateTx(ctx, tx, testAbuseReport(f.trf.ID), DefaultAbuseReportLimits(), now)
				return err
			})
		}},
		{"report insert", faultExec, "INSERT INTO abuse_reports", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseReports().Create(ctx, f.tid, testAbuseReport(f.trf.ID), AbuseReportLimits{}, now)
			return err
		}},
		{"report list", faultQuery, "FROM abuse_reports WHERE tenant_id = ? AND (created_at", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseReports().List(ctx, f.tid, "", 0, "")
			return err
		}},
		{"report list status", faultScanNil, "FROM abuse_reports WHERE tenant_id = ? AND status", func(ctx context.Context, f *abuseFixture) error {
			_, err := f.db.AbuseReports().List(ctx, f.tid, AbuseReportOpen, 0, "")
			return err
		}},
		{"report get", faultQuery, "FROM abuse_reports WHERE tenant_id = ? AND id = ?", func(ctx context.Context, f *abuseFixture) error {
			_, _, err := f.db.AbuseReports().SetStatus(ctx, f.tid, f.report.ID, AbuseReportClosed, "admin", nil, now)
			return err
		}},
		{"report reread", faultQuery, "FROM abuse_reports WHERE tenant_id = ? AND id = ?", func(ctx context.Context, f *abuseFixture) error {
			f.plan.reset()
			f.plan.add(faultQuery, "FROM abuse_reports WHERE tenant_id = ? AND id = ?", 1)
			_, _, err := f.db.AbuseReports().SetStatus(ctx, f.tid, f.report.ID, AbuseReportClosed, "admin", &note, now)
			return err
		}},
		{"report close", faultExec, "UPDATE abuse_reports SET status", func(ctx context.Context, f *abuseFixture) error {
			_, _, err := f.db.AbuseReports().SetStatus(ctx, f.tid, f.report.ID, AbuseReportClosed, "admin", nil, now)
			return err
		}},
		{"report close rows", faultRows, "UPDATE abuse_reports SET status", func(ctx context.Context, f *abuseFixture) error {
			_, _, err := f.db.AbuseReports().SetStatus(ctx, f.tid, f.report.ID, AbuseReportClosed, "admin", nil, now)
			return err
		}},
		{"report count email", faultQuery, "sender_email = ? OR reporter_email", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().PseudonymiseTx(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef")
				return err
			})
		}},
		{"report pseudonymise sender", faultExec, "SET sender_email", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().PseudonymiseTx(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef")
				return err
			})
		}},
		{"report pseudonymise reporter", faultExec, "SET reporter_email", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().PseudonymiseTx(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef")
				return err
			})
		}},
		{"report texts", faultQuery, "SELECT id, sender_email, reporter_email, message", func(ctx context.Context, f *abuseFixture) error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().PseudonymiseTx(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef")
				return err
			})
		}},
		{"report texts scan", faultScanNil, "SELECT id, sender_email, reporter_email, message", func(ctx context.Context, f *abuseFixture) error {
			if err := f.textReport(ctx); err != nil {
				return nil
			}
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().PseudonymiseTx(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef")
				return err
			})
		}},
		{"report pseudonymise text", faultExec, "SET message = ?, note", func(ctx context.Context, f *abuseFixture) error {
			if err := f.textReport(ctx); err != nil {
				return nil
			}
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.AbuseReports().PseudonymiseTx(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef")
				return err
			})
		}},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newAbuseFixture(t)
			f.plan.add(s.op, s.match, 0)
			if err := s.run(ctx, f); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestAbuseLockFailure checks that a failing tenant lock (PostgreSQL only)
// aborts the deduplication insert and the report creation.
func TestAbuseLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAbuseFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	err := f.tx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.AbuseAlerts().TryInsertTx(ctx, tx, fixtureEmail, AbuseRuleOffHours, "2026-10-19", false, time.Time{})
		return err
	})
	if err == nil {
		t.Error("TryInsertTx with a failing lock succeeded")
	}
	if _, err := f.db.AbuseReports().Create(ctx, f.tid, testAbuseReport(f.trf.ID), DefaultAbuseReportLimits(), time.Time{}); err == nil {
		t.Error("Create with a failing lock succeeded")
	}
}

// TestAbuseSettingsInsert checks that Put inserts the row of a tenant that
// has none (a tenant created before the seed, in theory), and that Get
// reads the defaults meanwhile.
func TestAbuseSettingsInsert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAbuseFixture(t)
	err := f.tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.tx.ExecContext(ctx, `DELETE FROM tenant_abuse_settings WHERE tenant_id = ?`, string(f.tid))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.db.AbuseSettings().Get(ctx, f.tid); err != nil || !reflect.DeepEqual(got, DefaultAbuseSettings()) {
		t.Fatalf("Get(no row) = %+v, %v", got, err)
	}
	s := DefaultAbuseSettings()
	s.MaxDailyBytesPerSender = new(int64)
	*s.MaxDailyBytesPerSender = 1 << 20
	out, err := f.db.AbuseSettings().Put(ctx, f.tid, s)
	if err != nil {
		t.Fatalf("Put(no row) = %v", err)
	}
	if got, err := f.db.AbuseSettings().Get(ctx, f.tid); err != nil || !reflect.DeepEqual(got, out) {
		t.Errorf("Get = %+v, %v; want %+v", got, err, out)
	}
}

// TestAbuseReportsErrorsWrap checks the wrapping of the creation errors:
// the rate limit sentinels pass through CreateTx.
func TestAbuseReportsErrorsWrap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAbuseFixture(t)
	r := testAbuseReport(f.trf.ID)
	r.RecipientLinkID = f.report.RecipientLinkID
	err := f.tx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.AbuseReports().CreateTx(ctx, tx, r, AbuseReportLimits{PerLinkPerDay: 1}, time.Time{})
		return err
	})
	if !errors.Is(err, ErrAbuseReportLinkLimit) {
		t.Errorf("CreateTx over the link limit = %v", err)
	}
}

// TestAbuseReportsIDFailure checks that a failing ID generator aborts the
// creation of a report without an ID.
func TestAbuseReportsIDFailure(t *testing.T) {
	t.Parallel()
	f := newAbuseFixture(t)
	f.db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	if _, err := f.db.AbuseReports().Create(context.Background(), f.tid, testAbuseReport(f.trf.ID), AbuseReportLimits{}, time.Time{}); !errors.Is(err, errInjected) {
		t.Errorf("Create with a failing ID generator = %v", err)
	}
}

// TestAbuseReportsStatusConflict checks that a status change whose guarded
// update matches no row (a concurrent change, simulated by a trigger
// ignoring the update) reports ErrConflict.
func TestAbuseReportsStatusConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAbuseFixture(t)
	if _, err := f.db.write.ExecContext(ctx, `CREATE TRIGGER ignore_report_update BEFORE UPDATE ON abuse_reports
		BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	_, changed, err := f.db.AbuseReports().SetStatus(ctx, f.tid, f.report.ID, AbuseReportClosed, "admin", nil, time.Time{})
	if !errors.Is(err, ErrConflict) || changed {
		t.Errorf("SetStatus(concurrent change) = %v, %v", changed, err)
	}
}

// TestAbuseAlertAttempts checks that a deduplicated occurrence increments
// the attempts of its own row (alert-only or blocked) only.
func TestAbuseAlertAttempts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tid := newTestTenant(ctx, t, db, "a.example.com")
		sc, err := db.Scoped(tid)
		if err != nil {
			t.Fatal(err)
		}
		try := func(blocked bool) bool {
			t.Helper()
			var ok bool
			err := sc.Tx(ctx, func(tx *ScopedTx) error {
				var err error
				ok, err = db.AbuseAlerts().TryInsertTx(ctx, tx, "Alice@a.example.com", AbuseRuleDailyBytes, "2026-10-19", blocked, time.Time{})
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		got := []bool{try(true), try(true), try(true), try(false)}
		if !slices.Equal(got, []bool{true, false, false, true}) {
			t.Errorf("TryInsertTx = %v", got)
		}
		attempts := func(blocked string) int64 {
			return rawInt(ctx, t, db, `SELECT attempts FROM abuse_alerts WHERE sender_email = 'alice@a.example.com' AND blocked = `+blocked)
		}
		if b, a := attempts("true"), attempts("false"); b != 3 || a != 1 {
			t.Errorf("attempts blocked %d, alert-only %d; want 3 and 1", b, a)
		}
	})
}

// TestPseudonymiseTextsBatches pages through the reports to rewrite.
func TestPseudonymiseTextsBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAbuseFixture(t)
	for range 3 {
		if err := f.textReport(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var n int64
	err := f.tx(ctx, func(tx *ScopedTx) error {
		var err error
		n, err = pseudonymiseTexts(ctx, tx, fixtureEmail, PseudonymPrefix+"0123456789abcdef", 2)
		return err
	})
	if err != nil || n != 3 {
		t.Fatalf("pseudonymiseTexts = %d, %v; want 3", n, err)
	}
}

func TestReplaceAddress(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta("al.ice@a.example.com"))
	for text, want := range map[string]string{
		"":                                               "",
		"none":                                           "none",
		"AL.ICE@A.EXAMPLE.COM":                           "P",
		"(al.ice@a.example.com)":                         "(P)",
		"al.ice@a.example.com.":                          "P.",
		"al.ice@a.example.com. Next":                     "P. Next",
		"to al.ice@a.example.com, thanks":                "to P, thanks",
		"é al.ice@a.example.com é":                       "é P é",
		"xal.ice@a.example.com":                          "xal.ice@a.example.com",
		"x.al.ice@a.example.com":                         "x.al.ice@a.example.com",
		"éal.ice@a.example.com":                          "éal.ice@a.example.com",
		"al.ice@a.example.com.org":                       "al.ice@a.example.com.org",
		"al.ice@a.example.comé":                          "al.ice@a.example.comé",
		"al.ice@a.example.com-x":                         "al.ice@a.example.com-x",
		"al.ice@a.example.com_x":                         "al.ice@a.example.com_x",
		"al.ice@a.example.com7":                          "al.ice@a.example.com7",
		"a al.ice@a.example.com b xal.ice@a.example.com": "a P b xal.ice@a.example.com",
	} {
		got, changed := replaceAddress(re, text, "P")
		if got != want || changed != (got != text) {
			t.Errorf("replaceAddress(%q) = %q, %v; want %q", text, got, changed, want)
		}
	}
}

func TestValidateTimeZone(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"UTC", "Europe/Paris", "America/New_York", "Asia/Kolkata"} {
		if err := ValidateTimeZone(ok); err != nil {
			t.Errorf("ValidateTimeZone(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Local", "Mars/Olympus", "../etc/passwd", "Europe/\nParis", strings.Repeat("a", 65), "Europe/Paris\n"} {
		if err := ValidateTimeZone(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateTimeZone(%q) = %v; want ErrInvalid", bad, err)
		}
	}
}
