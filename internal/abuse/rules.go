package abuse

import (
	"time"

	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
)

// historyDays is the window of the unusual volume average, in local days
// before the current one.
const historyDays = 30

// externalKinds are the sender kinds of the external quota.
var externalKinds = []store.DepositorKind{store.DepositorExternal}

// internalKinds are the sender kinds of the per-sender daily rules: the
// internal users, from the internal network or from outside (API tokens
// create internal transfers).
var internalKinds = []store.DepositorKind{store.DepositorInternal, store.DepositorInternalRemote}

// usage is the activity of a sender over a local day.
type usage struct {
	bytes int64
	count int
}

// finding is an exceeded rule.
type finding struct {
	rule      store.AbuseRule
	value     float64
	threshold float64
	// bytes tells that value and threshold of external_quota are sizes.
	bytes bool
	// at is the time shown by off_hours.
	at time.Time
}

// unusual reports whether the rule describes a behavior
// (abuse.unusual_activity) rather than a threshold.
func (f finding) unusual() bool {
	switch f.rule {
	case store.AbuseRuleUnusualVolume, store.AbuseRuleLargeExternal, store.AbuseRuleOffHours:
		return true
	}
	return false
}

// isExternal reports whether kind is subject to the external quota.
func isExternal(kind store.DepositorKind) bool {
	return kind == store.DepositorExternal
}

// isInternal reports whether kind is an internal user, from the internal
// network or from outside.
func isInternal(kind store.DepositorKind) bool {
	return kind == store.DepositorInternal || kind == store.DepositorInternalRemote
}

// location returns the time zone tz, UTC when it does not load (the
// administration checks it with store.ValidateTimeZone before storing it;
// the store embeds the IANA database).
func location(tz string) *time.Location {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

// dayWindow returns the local day of at in loc: its [start, end) bounds
// and its "YYYY-MM-DD" name. The bounds are local midnights, so that a day
// with a daylight saving time change lasts 23 or 25 hours.
func dayWindow(at time.Time, loc *time.Location) (start, end time.Time, day string) {
	y, m, d := at.In(loc).Date()
	start = time.Date(y, m, d, 0, 0, 0, 0, loc)
	end = time.Date(y, m, d+1, 0, 0, 0, 0, loc)
	return start, end, start.Format(time.DateOnly)
}

// historyStart returns the start of the unusual volume window: the local
// midnight historyDays days before the day starting at dayStart.
func historyStart(dayStart time.Time, loc *time.Location) time.Time {
	y, m, d := dayStart.In(loc).Date()
	return time.Date(y, m, d-historyDays, 0, 0, 0, 0, loc)
}

// over returns the finding of rule when value is strictly above the
// threshold limit (nil: the rule is disabled).
func over[T int | int64](rule store.AbuseRule, value int64, limit *T, bytes bool) []finding {
	if limit == nil || value <= int64(*limit) {
		return nil
	}
	return []finding{{rule: rule, value: float64(value), threshold: float64(*limit), bytes: bytes}}
}

// dailyFindings evaluates the per-sender daily rules on u.
func dailyFindings(s store.AbuseSettings, u usage) []finding {
	fs := over(store.AbuseRuleDailyBytes, u.bytes, s.MaxDailyBytesPerSender, false)
	return append(fs, over(store.AbuseRuleDailyTransfers, int64(u.count), s.MaxDailyTransfersPerSender, false)...)
}

// recipientsFinding evaluates the recipients rule on n recipients.
func recipientsFinding(s store.AbuseSettings, n int) []finding {
	return over(store.AbuseRuleRecipients, int64(n), s.MaxRecipientsPerTransfer, false)
}

// externalFindings evaluates the external quota on u, the external
// activity of a sender of kind kind (nothing for another kind).
func externalFindings(s store.AbuseSettings, kind store.DepositorKind, u usage) []finding {
	if !isExternal(kind) {
		return nil
	}
	fs := over(store.AbuseRuleExternalQuota, u.bytes, s.ExternalMaxDailyBytes, true)
	return append(fs, over(store.AbuseRuleExternalQuota, int64(u.count), s.ExternalMaxDailyDeposits, false)...)
}

// unusualFinding evaluates the unusual volume rule for a sender whose
// volume of the day starting at dayStart is today, from history, its
// creations since [historyStart] (those of the day itself are ignored).
// See the package documentation for the average.
func unusualFinding(s store.AbuseSettings, today int64, history []store.SenderTransferVolume, dayStart time.Time, loc *time.Location) []finding {
	if s.UnusualVolumePct == nil || today <= 0 {
		return nil
	}
	since := historyStart(dayStart, loc)
	days := map[string]bool{}
	var total int64
	for _, h := range history {
		if h.CreatedAt.Before(since) || !h.CreatedAt.Before(dayStart) {
			continue
		}
		days[h.CreatedAt.In(loc).Format(time.DateOnly)] = true
		total += h.TotalBytes
	}
	if len(days) < s.UnusualMinHistoryDays || total <= 0 {
		return nil
	}
	factor := float64(*s.UnusualVolumePct) / 100
	ratio := float64(today) / (float64(total) / historyDays)
	if ratio <= factor {
		return nil
	}
	return []finding{{rule: store.AbuseRuleUnusualVolume, value: ratio, threshold: factor}}
}

// largeExternalFinding evaluates the large external transfer rule on a
// transfer of size bytes to recipients, domains being the internal mail
// domains of the tenant.
func largeExternalFinding(s store.AbuseSettings, size int64, recipients, domains []string) []finding {
	limit := s.LargeExternalTransferBytes
	if limit == nil || size < *limit {
		return nil
	}
	rules := netpolicy.Rules{Domains: domains}
	for _, r := range recipients {
		if !netpolicy.DomainInternal(rules, r) {
			return []finding{{rule: store.AbuseRuleLargeExternal, value: float64(size), threshold: float64(*limit)}}
		}
	}
	return nil
}

// weekdayBit returns the bit of the weekday of local in an office weekday
// mask (bit 0 = Monday ... bit 6 = Sunday).
func weekdayBit(local time.Time) int {
	return 1 << ((int(local.Weekday()) + 6) % 7)
}

// offHoursFinding evaluates the office hours rule at at. The value is the
// minute of the local day, the threshold 0 (the mail shows the time).
func offHoursFinding(s store.AbuseSettings, at time.Time, loc *time.Location) []finding {
	if s.OfficeStartMinute == nil || s.OfficeEndMinute == nil {
		return nil
	}
	local := at.In(loc)
	minute := local.Hour()*60 + local.Minute()
	if s.OfficeWeekdays&weekdayBit(local) != 0 && minute >= *s.OfficeStartMinute && minute < *s.OfficeEndMinute {
		return nil
	}
	return []finding{{rule: store.AbuseRuleOffHours, value: float64(minute), at: at}}
}
