package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// JSON pointers of the abuse thresholds body (OpenAPI AbuseThresholds).
const (
	FieldMaxDailyBytesPerSender     = "/maxDailyBytesPerSender"
	FieldMaxDailyTransfersPerSender = "/maxDailyTransfersPerSender"
	FieldMaxRecipientsPerTransfer   = "/maxRecipientsPerTransfer"
	FieldUnusualVolumeFactor        = "/unusualVolumeFactor"
	FieldUnusualMinHistoryDays      = "/unusualMinHistoryDays"
	FieldLargeExternalTransferBytes = "/largeExternalTransferBytes"
	FieldOfficeHours                = "/officeHours"
	FieldOfficeHoursWeekdays        = "/officeHours/weekdays"
	FieldTimeZone                   = "/timeZone"
	FieldMaxInvitationsPerInviter   = "/maxInvitationsPerInviter"
	FieldExternalMaxDailyBytes      = "/externalMaxDailyBytes"
	FieldExternalMaxDailyDeposits   = "/externalMaxDailyDeposits"
)

// maxRecipientsLimit is the largest maxRecipientsPerTransfer (OpenAPI).
const maxRecipientsLimit = 100

// AbuseThresholds returns the abuse detection settings of tenant tid,
// readable by any administrator attached to it.
func (s *Service) AbuseThresholds(ctx context.Context, p adminauth.Principal, tid tenant.ID) (store.AbuseSettings, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return store.AbuseSettings{}, err
	}
	cur, err := s.repo.abuseSettings(ctx, tid)
	if err != nil {
		return store.AbuseSettings{}, fmt.Errorf("tenantadmin: get abuse settings: %w", err)
	}
	return cur, nil
}

// UpdateAbuseThresholds replaces the abuse detection settings of tenant
// tid, which requires the right to change it, and returns the stored
// settings. A value out of its bounds, office hours whose start is not
// before the end, or a time zone that store.ValidateTimeZone refuses
// ("Local" included), is an *InvalidError
// naming the field, checked once access is granted. The audit event
// tenant.abuse_settings_updated lists the changed fields by their API
// names; nothing is recorded when nothing changes.
func (s *Service) UpdateAbuseThresholds(ctx context.Context, p adminauth.Principal, tid tenant.ID, in store.AbuseSettings, ip netip.Addr) (store.AbuseSettings, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return store.AbuseSettings{}, err
	}
	if err := validateAbuse(in); err != nil {
		return store.AbuseSettings{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.repo.abuseSettings(ctx, tid)
	if err != nil {
		return store.AbuseSettings{}, fmt.Errorf("tenantadmin: get abuse settings: %w", err)
	}
	changed := changedAbuseFields(cur, in)
	if len(changed) == 0 {
		return cur, nil
	}
	in.UpdatedAt = s.now()
	in.UpdatedBy = p.Admin.ID
	out, err := s.repo.putAbuseSettings(ctx, tid, in)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.AbuseSettings{}, ErrNotFound
	case errors.Is(err, store.ErrInvalid):
		// The checks above mirror those of the store, so this cannot
		// happen unless they drift apart.
		return store.AbuseSettings{}, invalid("", "invalid abuse settings")
	case err != nil:
		return store.AbuseSettings{}, fmt.Errorf("tenantadmin: put abuse settings: %w", err)
	}
	s.record(ctx, p, ip, tid, ActionTenantAbuseSettingsUpdated, map[string]any{"fields": changed})
	return out, nil
}

// validateAbuse checks s field by field, naming the first one in error.
func validateAbuse(s store.AbuseSettings) error {
	switch {
	case !positiveInt64(s.MaxDailyBytesPerSender):
		return invalid(FieldMaxDailyBytesPerSender, "must be positive")
	case !positiveInt(s.MaxDailyTransfersPerSender, 0):
		return invalid(FieldMaxDailyTransfersPerSender, "must be positive")
	case !positiveInt(s.MaxRecipientsPerTransfer, maxRecipientsLimit):
		return invalid(FieldMaxRecipientsPerTransfer, "must be between 1 and %d", maxRecipientsLimit)
	case s.UnusualVolumePct != nil && (*s.UnusualVolumePct < store.MinUnusualVolumePct ||
		*s.UnusualVolumePct > store.MaxUnusualVolumePct || *s.UnusualVolumePct%10 != 0):
		return invalid(FieldUnusualVolumeFactor, "must be between 1.5 and 100, in steps of 0.1")
	case s.UnusualMinHistoryDays < 1 || s.UnusualMinHistoryDays > store.MaxUnusualMinHistoryDays:
		return invalid(FieldUnusualMinHistoryDays, "must be between 1 and %d", store.MaxUnusualMinHistoryDays)
	case !positiveInt64(s.LargeExternalTransferBytes):
		return invalid(FieldLargeExternalTransferBytes, "must be positive")
	case (s.OfficeStartMinute == nil) != (s.OfficeEndMinute == nil):
		return invalid(FieldOfficeHours, "needs a start and an end")
	case s.OfficeStartMinute != nil && (*s.OfficeStartMinute < 0 || *s.OfficeEndMinute > store.MaxOfficeMinute ||
		*s.OfficeStartMinute >= *s.OfficeEndMinute):
		return invalid(FieldOfficeHours, "the start must be before the end, within the day")
	case s.OfficeStartMinute != nil && s.OfficeWeekdays == 0:
		return invalid(FieldOfficeHoursWeekdays, "needs at least one weekday")
	case s.OfficeWeekdays < 0 || s.OfficeWeekdays > store.AllWeekdays:
		return invalid(FieldOfficeHoursWeekdays, "weekdays must be from 1 to 7")
	case s.MaxInvitationsPerInviter < 1 || s.MaxInvitationsPerInviter > store.MaxInvitationsPerInviterLimit:
		return invalid(FieldMaxInvitationsPerInviter, "must be between 1 and %d", store.MaxInvitationsPerInviterLimit)
	case !positiveInt64(s.ExternalMaxDailyBytes):
		return invalid(FieldExternalMaxDailyBytes, "must be positive")
	case !positiveInt(s.ExternalMaxDailyDeposits, 0):
		return invalid(FieldExternalMaxDailyDeposits, "must be positive")
	}
	if store.ValidateTimeZone(s.TimeZone) != nil {
		return invalid(FieldTimeZone, "must be an IANA time zone name")
	}
	return nil
}

// positiveInt64 reports whether p is nil or positive.
func positiveInt64(p *int64) bool { return p == nil || *p > 0 }

// positiveInt reports whether p is nil or positive and, when limit is not
// 0, at most limit.
func positiveInt(p *int, limit int) bool {
	return p == nil || (*p > 0 && (limit == 0 || *p <= limit))
}

// changedAbuseFields returns the API names of the fields that differ.
func changedAbuseFields(a, b store.AbuseSettings) []string {
	var out []string
	add := func(diff bool, name string) {
		if diff {
			out = append(out, name)
		}
	}
	add(!equalPtr(a.MaxDailyBytesPerSender, b.MaxDailyBytesPerSender), "maxDailyBytesPerSender")
	add(!equalPtr(a.MaxDailyTransfersPerSender, b.MaxDailyTransfersPerSender), "maxDailyTransfersPerSender")
	add(!equalPtr(a.MaxRecipientsPerTransfer, b.MaxRecipientsPerTransfer), "maxRecipientsPerTransfer")
	add(a.BlockOnExceed != b.BlockOnExceed, "blockOnExceed")
	add(!equalPtr(a.UnusualVolumePct, b.UnusualVolumePct), "unusualVolumeFactor")
	add(a.UnusualMinHistoryDays != b.UnusualMinHistoryDays, "unusualMinHistoryDays")
	add(!equalPtr(a.LargeExternalTransferBytes, b.LargeExternalTransferBytes), "largeExternalTransferBytes")
	add(!equalPtr(a.OfficeStartMinute, b.OfficeStartMinute) || !equalPtr(a.OfficeEndMinute, b.OfficeEndMinute) ||
		a.OfficeWeekdays != b.OfficeWeekdays, "officeHours")
	add(a.TimeZone != b.TimeZone, "timeZone")
	add(a.MaxInvitationsPerInviter != b.MaxInvitationsPerInviter, "maxInvitationsPerInviter")
	add(!equalPtr(a.ExternalMaxDailyBytes, b.ExternalMaxDailyBytes), "externalMaxDailyBytes")
	add(!equalPtr(a.ExternalMaxDailyDeposits, b.ExternalMaxDailyDeposits), "externalMaxDailyDeposits")
	return slices.Clip(out)
}

// equalPtr reports whether two optional values are both unset or equal.
func equalPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
