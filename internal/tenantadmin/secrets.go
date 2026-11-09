package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SecretSettingsInput are the one-time secrets settings of a tenant as the
// API carries them (OpenAPI SecretSettings, since 2.1): the durations are
// codes ("1h", "1d"...). The update replaces every setting.
type SecretSettingsInput struct {
	Enabled bool
	// Durations are the offered duration codes, at least one.
	Durations []string
	// DefaultDuration is the preselected code, one of Durations; "" for the
	// shortest offered one.
	DefaultDuration         string
	FileAllowed             bool
	FileMaxBytes            int64
	EmailAllowed            bool
	EmailRequiresPassphrase bool
}

// SecretSettingsOf converts the stored settings to their API form, the
// durations in ascending order.
func SecretSettingsOf(s tenant.SecretSettings) SecretSettingsInput {
	codes := s.Durations.Codes()
	out := SecretSettingsInput{
		Enabled: s.Enabled, Durations: make([]string, len(codes)), DefaultDuration: string(s.DefaultDuration),
		FileAllowed: s.FileAllowed, FileMaxBytes: s.FileMaxBytes, EmailAllowed: s.EmailAllowed,
		EmailRequiresPassphrase: s.EmailRequiresPassphrase,
	}
	for i, c := range codes {
		out.Durations[i] = string(c)
	}
	return out
}

// secretSettings validates in and returns the settings to store. Every
// problem is an *InvalidError naming the member (FieldDurations followed by
// "/<index>" for one code, FieldDefaultDuration, FieldFileMaxBytes). A
// default duration that is a known code but not offered is refused here,
// unlike in the store, which resets it: an administrator who names it
// wants it.
func secretSettings(in SecretSettingsInput) (tenant.SecretSettings, error) {
	codes := make([]tenant.SecretDuration, len(in.Durations))
	seen := make(map[tenant.SecretDuration]bool, len(in.Durations))
	for i, raw := range in.Durations {
		d := tenant.SecretDuration(raw)
		at := FieldDurations + "/" + strconv.Itoa(i)
		switch {
		case !d.Valid():
			return tenant.SecretSettings{}, invalid(at, "unknown duration")
		case seen[d]:
			return tenant.SecretSettings{}, invalid(at, "must not repeat a duration")
		}
		seen[d], codes[i] = true, d
	}
	set, _ := tenant.NewSecretDurationSet(codes...) // known and distinct: cannot fail
	if set.Empty() {
		return tenant.SecretSettings{}, invalid(FieldDurations, "at least one duration is required")
	}
	def := tenant.SecretDuration(in.DefaultDuration)
	if def != "" && (!def.Valid() || !set.Has(def)) {
		return tenant.SecretSettings{}, invalid(FieldDefaultDuration, "must be one of the offered durations")
	}
	if in.FileMaxBytes < tenant.MinSecretFileBytes || in.FileMaxBytes > tenant.MaxSecretFileBytes {
		return tenant.SecretSettings{}, invalid(FieldFileMaxBytes, "must be between %d and %d bytes",
			tenant.MinSecretFileBytes, tenant.MaxSecretFileBytes)
	}
	return tenant.SecretSettings{
		Enabled: in.Enabled, Durations: set, DefaultDuration: def, FileAllowed: in.FileAllowed,
		FileMaxBytes: in.FileMaxBytes, EmailAllowed: in.EmailAllowed, EmailRequiresPassphrase: in.EmailRequiresPassphrase,
	}, nil
}

// GetSecretSettings returns the one-time secrets settings of tenant tid
// (since 2.1). It is a configuration read, closed to the auditor role.
func (s *Service) GetSecretSettings(ctx context.Context, p adminauth.Principal, tid tenant.ID) (SecretSettingsInput, error) {
	t, err := s.readable(ctx, p, tid)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	return SecretSettingsOf(t.Secrets), nil
}

// UpdateSecretSettings replaces the one-time secrets settings of tenant tid
// (since 2.1) and returns the stored ones. The delegated admins of the
// tenant and the super admin may call it. The settings apply to the secrets
// created afterwards: the existing ones are untouched. Audited as
// secret.settings_updated with the names of the changed members.
func (s *Service) UpdateSecretSettings(ctx context.Context, p adminauth.Principal, tid tenant.ID, in SecretSettingsInput, ip netip.Addr) (SecretSettingsInput, error) {
	before, err := s.writable(ctx, p, tid)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	next, err := secretSettings(in)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	t, err := s.repo.setSecretSettings(ctx, tid, next)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return SecretSettingsInput{}, ErrNotFound
	case errors.Is(err, store.ErrInvalid):
		// The checks above mirror the store's, so this cannot happen
		// unless they drift apart.
		return SecretSettingsInput{}, invalid("", "invalid secret settings")
	case err != nil:
		return SecretSettingsInput{}, fmt.Errorf("tenantadmin: set secret settings: %w", err)
	}
	s.invalidate(tid, t.FQDN)
	s.record(ctx, p, ip, tid, audit.ActionSecretSettingsUpdated, map[string]any{
		"changed": changedSecretSettings(SecretSettingsOf(before.Secrets), SecretSettingsOf(t.Secrets)),
	})
	return SecretSettingsOf(t.Secrets), nil
}

// changedSecretSettings returns the API names of the members that differ
// between a and b, always a non-nil list.
func changedSecretSettings(a, b SecretSettingsInput) []string {
	changed := []string{}
	for _, m := range []struct {
		name string
		diff bool
	}{
		{"enabled", a.Enabled != b.Enabled},
		{"durations", fmt.Sprint(a.Durations) != fmt.Sprint(b.Durations)},
		{"defaultDuration", a.DefaultDuration != b.DefaultDuration},
		{"fileAllowed", a.FileAllowed != b.FileAllowed},
		{"fileMaxBytes", a.FileMaxBytes != b.FileMaxBytes},
		{"emailAllowed", a.EmailAllowed != b.EmailAllowed},
		{"emailRequiresPassphrase", a.EmailRequiresPassphrase != b.EmailRequiresPassphrase},
	} {
		if m.diff {
			changed = append(changed, m.name)
		}
	}
	return changed
}

// PublicSecretFeatures returns the secrets settings of t for the public
// configuration (OpenAPI SecretFeatures): the real rules of the creation
// form, the default duration resolved.
func PublicSecretFeatures(t *tenant.Tenant) SecretSettingsInput {
	out := SecretSettingsOf(t.Secrets)
	out.DefaultDuration = string(t.Secrets.EffectiveDefaultDuration())
	return out
}
