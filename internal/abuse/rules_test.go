package abuse

import (
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
)

func paris(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestLocation(t *testing.T) {
	t.Parallel()
	if location("Not/AZone") != time.UTC {
		t.Error("an unknown zone must fall back to UTC")
	}
	if location("Europe/Paris").String() != "Europe/Paris" {
		t.Error("Europe/Paris not loaded")
	}
}

func TestDayWindow(t *testing.T) {
	t.Parallel()
	p := paris(t)
	for _, c := range []struct {
		name  string
		at    time.Time
		loc   *time.Location
		day   string
		hours float64
	}{
		{"utc", time.Date(2026, 10, 22, 23, 59, 59, 0, time.UTC), time.UTC, "2026-10-22", 24},
		{"utc midnight", time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), time.UTC, "2026-10-22", 24},
		// 22:30 UTC is already the next day in Paris.
		{"paris after local midnight", time.Date(2026, 10, 21, 22, 30, 0, 0, time.UTC), p, "2026-10-22", 24},
		{"paris before local midnight", time.Date(2026, 10, 21, 21, 59, 0, 0, time.UTC), p, "2026-10-21", 24},
		{"spring forward", time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC), p, "2026-03-29", 23},
		{"fall back", time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), p, "2026-10-25", 25},
	} {
		start, end, day := dayWindow(c.at, c.loc)
		if day != c.day || end.Sub(start).Hours() != c.hours || c.at.Before(start) || !c.at.Before(end) {
			t.Errorf("%s: [%v, %v) %s", c.name, start, end, day)
		}
		if h, m, s := start.In(c.loc).Clock(); h+m+s != 0 {
			t.Errorf("%s: start %v is not a local midnight", c.name, start)
		}
	}
}

func TestHistoryStart(t *testing.T) {
	t.Parallel()
	p := paris(t)
	// The 30 days before 2026-04-10 cross the spring change.
	start, _, _ := dayWindow(time.Date(2026, 4, 10, 10, 0, 0, 0, time.UTC), p)
	got := historyStart(start, p)
	if want := time.Date(2026, 3, 11, 0, 0, 0, 0, p); !got.Equal(want) {
		t.Fatalf("historyStart = %v, want %v", got, want)
	}
}

func TestThresholdRules(t *testing.T) {
	t.Parallel()
	none := store.DefaultAbuseSettings()
	if dailyFindings(none, usage{1 << 40, 1000}) != nil || recipientsFinding(none, 100) != nil ||
		externalFindings(none, store.DepositorExternal, usage{1 << 40, 1000}) != nil {
		t.Fatal("disabled thresholds raised findings")
	}
	s := settings(func(s *store.AbuseSettings) {
		s.MaxDailyBytesPerSender, s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = i64p(100), intp(3), intp(5)
		s.ExternalMaxDailyBytes, s.ExternalMaxDailyDeposits = i64p(50), intp(2)
	})
	if fs := dailyFindings(s, usage{100, 3}); fs != nil {
		t.Errorf("equal values must not exceed: %+v", fs)
	}
	fs := dailyFindings(s, usage{101, 4})
	if len(fs) != 2 || fs[0].rule != store.AbuseRuleDailyBytes || fs[0].value != 101 || fs[0].threshold != 100 ||
		fs[1].rule != store.AbuseRuleDailyTransfers || fs[1].value != 4 || fs[1].threshold != 3 || fs[0].bytes {
		t.Errorf("daily = %+v", fs)
	}
	if recipientsFinding(s, 5) != nil {
		t.Error("5 recipients of 5 exceeded")
	}
	if fs := recipientsFinding(s, 6); len(fs) != 1 || fs[0].value != 6 || fs[0].threshold != 5 {
		t.Errorf("recipients = %+v", fs)
	}
	for _, k := range []store.DepositorKind{store.DepositorInternal, store.DepositorInternalRemote} {
		if externalFindings(s, k, usage{1000, 100}) != nil {
			t.Errorf("external quota applied to %s", k)
		}
	}
	if externalFindings(s, store.DepositorExternal, usage{50, 2}) != nil {
		t.Error("equal external usage exceeded")
	}
	fs = externalFindings(s, store.DepositorExternal, usage{51, 3})
	if len(fs) != 2 || !fs[0].bytes || fs[0].value != 51 || fs[1].bytes || fs[1].value != 3 ||
		fs[0].rule != store.AbuseRuleExternalQuota || fs[1].rule != store.AbuseRuleExternalQuota {
		t.Errorf("external = %+v", fs)
	}
}

func TestFindingKinds(t *testing.T) {
	t.Parallel()
	for rule, want := range map[store.AbuseRule]bool{
		store.AbuseRuleDailyBytes: false, store.AbuseRuleDailyTransfers: false, store.AbuseRuleRecipients: false,
		store.AbuseRuleExternalQuota: false, store.AbuseRuleInvitations: false,
		store.AbuseRuleUnusualVolume: true, store.AbuseRuleLargeExternal: true, store.AbuseRuleOffHours: true,
	} {
		if (finding{rule: rule}).unusual() != want {
			t.Errorf("unusual(%s) != %v", rule, want)
		}
	}
	if !isInternal(store.DepositorInternal) || !isInternal(store.DepositorInternalRemote) || isInternal(store.DepositorExternal) {
		t.Error("isInternal")
	}
}

func TestUnusualFinding(t *testing.T) {
	t.Parallel()
	p := paris(t)
	dayStart, _, _ := dayWindow(time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC), p)
	s := settings(func(s *store.AbuseSettings) { s.UnusualVolumePct, s.UnusualMinHistoryDays = intp(300), 3 })
	// day returns 10:00 Paris time n local days before dayStart.
	day := func(n int) time.Time { return dayStart.AddDate(0, 0, -n).Add(10 * time.Hour) }
	vol := func(at time.Time, b int64) store.SenderTransferVolume {
		return store.SenderTransferVolume{CreatedAt: at, TotalBytes: b}
	}
	// 3 active days of 100 bytes over the window: average 300/30 = 10.
	hist := []store.SenderTransferVolume{
		vol(dayStart.Add(time.Hour), 1_000_000), // today: ignored
		vol(day(1), 50), vol(day(1).Add(time.Hour), 50),
		vol(day(2), 100),
		vol(day(30), 100),   // first day of the window
		vol(day(31), 1<<40), // before the window: ignored
	}
	if fs := unusualFinding(store.DefaultAbuseSettings(), 1000, hist, dayStart, p); fs != nil {
		t.Error("disabled rule raised")
	}
	if fs := unusualFinding(s, 0, hist, dayStart, p); fs != nil {
		t.Error("no volume today raised")
	}
	if fs := unusualFinding(s, 30, hist, dayStart, p); fs != nil {
		t.Errorf("ratio equal to the factor raised: %+v", fs)
	}
	fs := unusualFinding(s, 31, hist, dayStart, p)
	if len(fs) != 1 || fs[0].rule != store.AbuseRuleUnusualVolume || fs[0].threshold != 3 || fs[0].value != 3.1 {
		t.Fatalf("unusual = %+v", fs)
	}
	// Two active days only: below the minimum history.
	if fs := unusualFinding(s, 1000, hist[:4], dayStart, p); fs != nil {
		t.Errorf("short history raised: %+v", fs)
	}
	// Rows bucketed by local day: 23:30 Paris, then 00:30 and 01:00 Paris
	// the next day (22:30 and 23:00 UTC, one UTC day) make two local days.
	late := dayStart.AddDate(0, 0, -5).Add(-30 * time.Minute)
	local := []store.SenderTransferVolume{vol(late, 10), vol(late.Add(time.Hour), 10), vol(late.Add(90*time.Minute), 10)}
	if fs := unusualFinding(s, 1000, local, dayStart, p); fs != nil {
		t.Error("two local days counted as three")
	}
	if fs := unusualFinding(s, 1000, append(local, vol(day(3), 10)), dayStart, p); len(fs) != 1 {
		t.Error("three local days not counted")
	}
	// Active days of empty transfers: no average.
	empty := []store.SenderTransferVolume{vol(day(1), 0), vol(day(2), 0), vol(day(3), 0)}
	if fs := unusualFinding(s, 1000, empty, dayStart, p); fs != nil {
		t.Error("zero average raised")
	}
}

func TestLargeExternalFinding(t *testing.T) {
	t.Parallel()
	domains := []string{"entity-a.example.com"}
	if largeExternalFinding(store.DefaultAbuseSettings(), 1<<40, []string{ext}, domains) != nil {
		t.Error("disabled rule raised")
	}
	s := settings(func(s *store.AbuseSettings) { s.LargeExternalTransferBytes = i64p(1000) })
	if largeExternalFinding(s, 999, []string{ext}, domains) != nil {
		t.Error("small transfer raised")
	}
	if largeExternalFinding(s, 5000, []string{alice, "Carol@ENTITY-A.example.com"}, domains) != nil {
		t.Error("internal recipients raised")
	}
	fs := largeExternalFinding(s, 1000, []string{alice, ext}, domains)
	if len(fs) != 1 || fs[0].rule != store.AbuseRuleLargeExternal || fs[0].value != 1000 || fs[0].threshold != 1000 {
		t.Errorf("large external = %+v", fs)
	}
}

func TestOffHoursFinding(t *testing.T) {
	t.Parallel()
	p := paris(t)
	if offHoursFinding(store.DefaultAbuseSettings(), t0, p) != nil {
		t.Error("disabled rule raised")
	}
	// Monday to Friday, 08:00 to 18:00 Paris.
	s := settings(func(s *store.AbuseSettings) { s.OfficeStartMinute, s.OfficeEndMinute = intp(8*60), intp(18*60) })
	at := func(y int, m time.Month, d, h, mi int) time.Time { return time.Date(y, m, d, h, mi, 0, 0, p) }
	for _, c := range []struct {
		name string
		at   time.Time
		off  bool
	}{
		{"thursday 11:00", at(2026, 10, 22, 11, 0), false},
		{"start", at(2026, 10, 22, 8, 0), false},
		{"before start", at(2026, 10, 22, 7, 59), true},
		{"last minute", at(2026, 10, 22, 17, 59), false},
		{"end", at(2026, 10, 22, 18, 0), true},
		{"monday", at(2026, 10, 19, 9, 0), false},
		{"friday", at(2026, 10, 23, 9, 0), false},
		{"saturday", at(2026, 10, 24, 11, 0), true},
		{"sunday", at(2026, 10, 25, 11, 0), true},
		// 07:30 UTC is 08:30 in winter (office), 06:30 UTC 07:30 (off).
		{"winter utc", time.Date(2026, 10, 26, 7, 30, 0, 0, time.UTC), false},
		{"winter utc early", time.Date(2026, 10, 26, 6, 30, 0, 0, time.UTC), true},
	} {
		fs := offHoursFinding(s, c.at, p)
		if (fs != nil) != c.off {
			t.Errorf("%s: off = %v", c.name, fs != nil)
			continue
		}
		if c.off {
			l := c.at.In(p)
			if fs[0].rule != store.AbuseRuleOffHours || fs[0].value != float64(l.Hour()*60+l.Minute()) || !fs[0].at.Equal(c.at) {
				t.Errorf("%s: %+v", c.name, fs)
			}
		}
	}
	// Every day of the week.
	s.OfficeWeekdays = store.AllWeekdays
	if offHoursFinding(s, at(2026, 10, 25, 11, 0), p) != nil {
		t.Error("sunday is an office day of the full mask")
	}
	s.OfficeWeekdays = 0
	if offHoursFinding(s, at(2026, 10, 22, 11, 0), p) == nil {
		t.Error("no office day must be off hours")
	}
}
