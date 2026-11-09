package tenantadmin

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestSecretSettings(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		got, err := ev.svc.GetSecretSettings(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get defaults", err)
		if want := SecretSettingsOf(tenant.DefaultSecretSettings()); !equalSettings(got, want) {
			t.Fatalf("defaults = %+v, want %+v", got, want)
		}
		if !slices.Equal(got.Durations, []string{"1h", "1d", "7d"}) {
			t.Fatalf("durations = %v", got.Durations)
		}

		in := SecretSettingsInput{
			Enabled: true, Durations: []string{"30d", "1h", "12h"}, DefaultDuration: "30d", FileAllowed: false,
			FileMaxBytes: tenant.MaxSecretFileBytes, EmailAllowed: true, EmailRequiresPassphrase: true,
		}
		out, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP)
		mustNoErr(t, "update", err)
		if !slices.Equal(out.Durations, []string{"1h", "12h", "30d"}) || out.DefaultDuration != "30d" || out.FileAllowed ||
			out.FileMaxBytes != tenant.MaxSecretFileBytes || !out.EmailRequiresPassphrase {
			t.Fatalf("stored = %+v", out)
		}
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "read back", err)
		if tn.Secrets.FileMaxBytes != tenant.MaxSecretFileBytes || !tn.Secrets.EmailRequiresPassphrase {
			t.Errorf("tenant settings = %+v", tn.Secrets)
		}
		if !slices.Contains(ev.cache.tenants, ev.a.ID) {
			t.Error("the tenant cache was not invalidated")
		}
		events := ev.auditEvents(t, ev.a.ID, audit.ActionSecretSettingsUpdated)
		if len(events) != 1 {
			t.Fatalf("%d audit events", len(events))
		}
		var d struct{ Changed []string }
		mustNoErr(t, "details", json.Unmarshal(events[0].Details, &d))
		if want := []string{"durations", "defaultDuration", "fileAllowed", "fileMaxBytes", "emailRequiresPassphrase"}; !slices.Equal(d.Changed, want) {
			t.Errorf("changed = %v, want %v", d.Changed, want)
		}
		// Nothing changed: an empty list, not null.
		_, err = ev.svc.UpdateSecretSettings(ctx, ev.super, ev.a.ID, out, clientIP)
		mustNoErr(t, "same settings", err)
		events = ev.auditEvents(t, ev.a.ID, audit.ActionSecretSettingsUpdated)
		if len(events) != 2 || string(events[0].Details) != `{"changed":[]}` && string(events[1].Details) != `{"changed":[]}` {
			t.Errorf("audit after a no-op = %+v", events)
		}

		// B is untouched, and A's admin cannot reach B.
		other, _ := ev.svc.GetSecretSettings(ctx, ev.super, ev.b.ID)
		if !equalSettings(other, SecretSettingsOf(tenant.DefaultSecretSettings())) {
			t.Errorf("tenant B changed: %+v", other)
		}
		_, err = ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.b.ID, in, clientIP)
		wantErr(t, "A's admin on B", err, ErrNotFound)
		_, err = ev.svc.GetSecretSettings(ctx, ev.adminA, ev.b.ID)
		wantErr(t, "A's admin reads B", err, ErrNotFound)

		ev.faults("setSecretSettings")
		_, err = ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP)
		wantErr(t, "failing store", err, errBoom)
	})
}

func TestSecretSettingsValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ok := SecretSettingsOf(tenant.DefaultSecretSettings())
		for name, c := range map[string]struct {
			mod   func(*SecretSettingsInput)
			field string
		}{
			"no duration":      {func(s *SecretSettingsInput) { s.Durations = nil }, FieldDurations},
			"unknown duration": {func(s *SecretSettingsInput) { s.Durations = []string{"1h", "2d"} }, FieldDurations + "/1"},
			"duplicate":        {func(s *SecretSettingsInput) { s.Durations = []string{"1h", "1h"} }, FieldDurations + "/1"},
			"unknown default":  {func(s *SecretSettingsInput) { s.DefaultDuration = "2d" }, FieldDefaultDuration},
			"default not offered": {func(s *SecretSettingsInput) {
				s.Durations, s.DefaultDuration = []string{"1h"}, "7d"
			}, FieldDefaultDuration},
			"file too small": {func(s *SecretSettingsInput) { s.FileMaxBytes = tenant.MinSecretFileBytes - 1 }, FieldFileMaxBytes},
			"file too large": {func(s *SecretSettingsInput) { s.FileMaxBytes = tenant.MaxSecretFileBytes + 1 }, FieldFileMaxBytes},
		} {
			in := ok
			in.Durations = slices.Clone(ok.Durations)
			c.mod(&in)
			_, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP)
			wantInvalid(t, name, err, c.field)
			// Access is checked first: the other tenant's admin gets 404.
			_, err = ev.svc.UpdateSecretSettings(ctx, ev.adminB, ev.a.ID, in, clientIP)
			wantErr(t, name+" by B's admin", err, ErrNotFound)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, audit.ActionSecretSettingsUpdated)); n != 0 {
			t.Errorf("%d audit events after refused updates", n)
		}
		// The store refusing what the checks accepted is an invalid-input error.
		f := ev.faults()
		f.errs["setSecretSettings"] = store.ErrInvalid
		_, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, ok, clientIP)
		wantInvalid(t, "store refusal", err, "")
		f.errs["setSecretSettings"] = store.ErrNotFound
		_, err = ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, ok, clientIP)
		wantErr(t, "tenant gone", err, ErrNotFound)
	})
}

func TestPublicSecretFeatures(t *testing.T) {
	t.Parallel()
	tn := &tenant.Tenant{Secrets: tenant.DefaultSecretSettings()}
	got := PublicSecretFeatures(tn)
	if got.DefaultDuration != "1h" || !slices.Equal(got.Durations, []string{"1h", "1d", "7d"}) || !got.Enabled {
		t.Errorf("features = %+v", got)
	}
	tn.Secrets.DefaultDuration = tenant.SecretDuration1d
	if got := PublicSecretFeatures(tn); got.DefaultDuration != "1d" {
		t.Errorf("explicit default = %q", got.DefaultDuration)
	}
}

// equalSettings compares two settings.
func equalSettings(a, b SecretSettingsInput) bool {
	return a.Enabled == b.Enabled && slices.Equal(a.Durations, b.Durations) && a.DefaultDuration == b.DefaultDuration &&
		a.FileAllowed == b.FileAllowed && a.FileMaxBytes == b.FileMaxBytes && a.EmailAllowed == b.EmailAllowed &&
		a.EmailRequiresPassphrase == b.EmailRequiresPassphrase
}
