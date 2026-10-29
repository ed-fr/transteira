package tenantadmin

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// fullAbuse returns settings with every field set.
func fullAbuse() store.AbuseSettings {
	return store.AbuseSettings{
		MaxDailyBytesPerSender: ptr(int64(5 << 30)), MaxDailyTransfersPerSender: ptr(40),
		MaxRecipientsPerTransfer: ptr(20), BlockOnExceed: true, UnusualVolumePct: ptr(300),
		UnusualMinHistoryDays: 10, LargeExternalTransferBytes: ptr(int64(1 << 30)),
		OfficeStartMinute: ptr(8 * 60), OfficeEndMinute: ptr(18 * 60), OfficeWeekdays: 31,
		TimeZone: "Europe/Paris", MaxInvitationsPerInviter: 15,
		ExternalMaxDailyBytes: ptr(int64(2 << 30)), ExternalMaxDailyDeposits: ptr(5),
	}
}

func abuseFields(t *testing.T, ev *env) [][]string {
	t.Helper()
	var out [][]string
	for _, e := range ev.auditEvents(t, ev.a.ID, ActionTenantAbuseSettingsUpdated) {
		var d struct{ Fields []string }
		mustNoErr(t, "details", json.Unmarshal(e.Details, &d))
		out = append(out, d.Fields)
	}
	return out
}

func TestAbuseThresholds(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		def, err := ev.svc.AbuseThresholds(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get default", err)
		if def.TimeZone != "UTC" || def.MaxDailyBytesPerSender != nil || def.MaxInvitationsPerInviter != 20 {
			t.Fatalf("default = %+v", def)
		}

		// An unchanged body records nothing.
		_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, def, clientIP)
		mustNoErr(t, "unchanged", err)
		if n := len(abuseFields(t, ev)); n != 0 {
			t.Fatalf("audit events for an unchanged body: %d", n)
		}

		in := fullAbuse()
		out, err := ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
		mustNoErr(t, "update", err)
		if out.UpdatedBy != ev.adminA.Admin.ID || out.UpdatedAt.IsZero() || *out.MaxDailyBytesPerSender != 5<<30 || out.TimeZone != "Europe/Paris" {
			t.Fatalf("stored = %+v", out)
		}
		got, err := ev.svc.AbuseThresholds(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "get", err)
		if *got.MaxRecipientsPerTransfer != 20 || !got.BlockOnExceed || *got.OfficeEndMinute != 18*60 {
			t.Fatalf("got = %+v", got)
		}
		fields := abuseFields(t, ev)
		want := []string{
			"maxDailyBytesPerSender", "maxDailyTransfersPerSender", "maxRecipientsPerTransfer", "blockOnExceed",
			"unusualVolumeFactor", "unusualMinHistoryDays", "largeExternalTransferBytes", "officeHours", "timeZone",
			"maxInvitationsPerInviter", "externalMaxDailyBytes", "externalMaxDailyDeposits",
		}
		if len(fields) != 1 || !slices.Equal(fields[0], want) {
			t.Fatalf("audited fields = %v", fields)
		}

		// A single change names a single field; clearing a threshold counts.
		in.OfficeWeekdays = 127
		in.ExternalMaxDailyDeposits = nil
		_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "second", err)
		fields = abuseFields(t, ev)
		if len(fields) != 2 || !slices.Contains(fields[0], "officeHours") || !slices.Contains(fields[1], "externalMaxDailyDeposits") && !slices.Contains(fields[0], "externalMaxDailyDeposits") {
			t.Fatalf("audited fields = %v", fields)
		}

		// Tenant B is untouched and B's admin cannot reach A.
		if b, _ := ev.svc.AbuseThresholds(ctx, ev.adminB, ev.b.ID); b.TimeZone != "UTC" {
			t.Fatalf("B changed: %+v", b)
		}
		_, err = ev.svc.AbuseThresholds(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant get", err, ErrNotFound)
		_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminB, ev.a.ID, in, clientIP)
		wantErr(t, "other tenant update", err, ErrNotFound)
	})
}

func TestAbuseThresholdsValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	for name, tc := range map[string]struct {
		mod   func(s *store.AbuseSettings)
		field string
	}{
		"bytes":          {func(s *store.AbuseSettings) { s.MaxDailyBytesPerSender = ptr(int64(0)) }, FieldMaxDailyBytesPerSender},
		"transfers":      {func(s *store.AbuseSettings) { s.MaxDailyTransfersPerSender = ptr(0) }, FieldMaxDailyTransfersPerSender},
		"recipients":     {func(s *store.AbuseSettings) { s.MaxRecipientsPerTransfer = ptr(101) }, FieldMaxRecipientsPerTransfer},
		"factor low":     {func(s *store.AbuseSettings) { s.UnusualVolumePct = ptr(140) }, FieldUnusualVolumeFactor},
		"factor high":    {func(s *store.AbuseSettings) { s.UnusualVolumePct = ptr(10010) }, FieldUnusualVolumeFactor},
		"factor step":    {func(s *store.AbuseSettings) { s.UnusualVolumePct = ptr(155) }, FieldUnusualVolumeFactor},
		"history":        {func(s *store.AbuseSettings) { s.UnusualMinHistoryDays = 31 }, FieldUnusualMinHistoryDays},
		"large external": {func(s *store.AbuseSettings) { s.LargeExternalTransferBytes = ptr(int64(-1)) }, FieldLargeExternalTransferBytes},
		"half hours":     {func(s *store.AbuseSettings) { s.OfficeStartMinute = ptr(60) }, FieldOfficeHours},
		"start after end": {func(s *store.AbuseSettings) {
			s.OfficeStartMinute, s.OfficeEndMinute = ptr(600), ptr(540)
		}, FieldOfficeHours},
		"start equals end": {func(s *store.AbuseSettings) {
			s.OfficeStartMinute, s.OfficeEndMinute = ptr(600), ptr(600)
		}, FieldOfficeHours},
		"end too late": {func(s *store.AbuseSettings) {
			s.OfficeStartMinute, s.OfficeEndMinute = ptr(0), ptr(1441)
		}, FieldOfficeHours},
		"negative start": {func(s *store.AbuseSettings) {
			s.OfficeStartMinute, s.OfficeEndMinute = ptr(-1), ptr(60)
		}, FieldOfficeHours},
		"no weekday": {func(s *store.AbuseSettings) {
			s.OfficeStartMinute, s.OfficeEndMinute, s.OfficeWeekdays = ptr(60), ptr(120), 0
		}, FieldOfficeHoursWeekdays},
		"weekdays mask": {func(s *store.AbuseSettings) { s.OfficeWeekdays = 128 }, FieldOfficeHoursWeekdays},
		"zone empty":    {func(s *store.AbuseSettings) { s.TimeZone = "" }, FieldTimeZone},
		"zone local":    {func(s *store.AbuseSettings) { s.TimeZone = "Local" }, FieldTimeZone},
		"zone unknown":  {func(s *store.AbuseSettings) { s.TimeZone = "Mars/Olympus" }, FieldTimeZone},
		"zone long":     {func(s *store.AbuseSettings) { s.TimeZone = strings.Repeat("a", 65) }, FieldTimeZone},
		"invitations":   {func(s *store.AbuseSettings) { s.MaxInvitationsPerInviter = 1001 }, FieldMaxInvitationsPerInviter},
		"ext bytes":     {func(s *store.AbuseSettings) { s.ExternalMaxDailyBytes = ptr(int64(0)) }, FieldExternalMaxDailyBytes},
		"ext deposits":  {func(s *store.AbuseSettings) { s.ExternalMaxDailyDeposits = ptr(-3) }, FieldExternalMaxDailyDeposits},
	} {
		in := store.DefaultAbuseSettings()
		tc.mod(&in)
		_, err := ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
		wantInvalid(t, name, err, tc.field)
	}
	// Office hours up to the end of the day are valid.
	in := store.DefaultAbuseSettings()
	in.OfficeStartMinute, in.OfficeEndMinute = ptr(0), ptr(1440)
	_, err := ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
	mustNoErr(t, "full day", err)

	f := ev.faults("abuseSettings")
	_, err = ev.svc.AbuseThresholds(ctx, ev.adminA, ev.a.ID)
	wantErr(t, "get", err, errBoom)
	in.MaxInvitationsPerInviter = 21
	_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
	wantErr(t, "read before update", err, errBoom)
	delete(f.errs, "abuseSettings")
	f.errs["putAbuseSettings"] = errBoom
	_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
	wantErr(t, "put", err, errBoom)
	f.errs["putAbuseSettings"] = store.ErrNotFound
	_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
	wantErr(t, "gone", err, ErrNotFound)
	f.errs["putAbuseSettings"] = store.ErrInvalid
	_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, ev.a.ID, in, clientIP)
	wantInvalid(t, "store invalid", err, "")
}

func TestUpdateTenantRemoteDeposit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.GetTenant(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if v.AllowRemoteInternalDeposit {
			t.Fatal("on by default")
		}
		v, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{AllowRemoteInternalDeposit: ptr(true)}, clientIP)
		mustNoErr(t, "on", err)
		if !v.AllowRemoteInternalDeposit {
			t.Fatalf("not stored: %+v", v)
		}
		if b, err := ev.db.Tenants().Get(ctx, ev.b.ID); err != nil || b.AllowRemoteInternalDeposit {
			t.Fatalf("tenant B changed: %+v, %v", b, err)
		}
		found := false
		for _, e := range ev.auditEvents(t, ev.a.ID, ActionTenantUpdated) {
			var d struct{ Fields []string }
			mustNoErr(t, "details", json.Unmarshal(e.Details, &d))
			found = found || slices.Equal(d.Fields, []string{"allowRemoteInternalDeposit"})
		}
		if !found {
			t.Fatal("no audit event naming allowRemoteInternalDeposit")
		}
		_, err = ev.svc.UpdateTenant(ctx, ev.adminB, ev.a.ID, TenantUpdate{AllowRemoteInternalDeposit: ptr(false)}, clientIP)
		wantErr(t, "other tenant", err, ErrNotFound)
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{AllowRemoteInternalDeposit: ptr(false)}, clientIP)
		mustNoErr(t, "off", err)
		if v.AllowRemoteInternalDeposit {
			t.Fatalf("still on: %+v", v)
		}
	})
}
