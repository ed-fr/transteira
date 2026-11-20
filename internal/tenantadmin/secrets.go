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
// codes ("1h", "1d"...). The update replaces every setting of the 2.1
// module.
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
	// ExpressEnabled, ExpressPerHourPerIP, ExpressPerHourPerToken and
	// ExpressMaxPending are the settings of the express secrets (since
	// 2.3, tenant.ExpressSettings). In an update a nil member keeps its
	// stored value (a 2.1 client does not know them); the reads and the
	// answers of the service set all four. [SecretSettingsOf] leaves them
	// nil.
	ExpressEnabled         *bool
	ExpressPerHourPerIP    *int
	ExpressPerHourPerToken *int
	ExpressMaxPending      *int
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

// secretSettingsOfTenant returns the secrets settings of t in their API
// form, the express members included (a zero limit read as its default).
func secretSettingsOfTenant(t *tenant.Tenant) SecretSettingsInput {
	out := SecretSettingsOf(t.Secrets)
	e := t.Express.WithDefaults()
	out.ExpressEnabled, out.ExpressPerHourPerIP = &e.Enabled, &e.PerHourPerIP
	out.ExpressPerHourPerToken, out.ExpressMaxPending = &e.PerHourPerToken, &e.MaxPending
	return out
}

// expressPatch returns the members of the express settings set in in, as
// a change to store. Every limit set is checked against its bounds, an
// *InvalidError naming its member (FieldExpressPerHourPerIP,
// FieldExpressPerHourPerToken or FieldExpressMaxPending).
func expressPatch(in SecretSettingsInput) (store.ExpressPatch, error) {
	for _, m := range []struct {
		in       *int
		field    string
		min, max int
	}{
		{in.ExpressPerHourPerIP, FieldExpressPerHourPerIP, tenant.MinExpressPerHourPerIP, tenant.MaxExpressPerHourPerIP},
		{in.ExpressPerHourPerToken, FieldExpressPerHourPerToken, tenant.MinExpressPerHourPerToken, tenant.MaxExpressPerHourPerToken},
		{in.ExpressMaxPending, FieldExpressMaxPending, tenant.MinExpressMaxPending, tenant.MaxExpressMaxPending},
	} {
		if m.in != nil && (*m.in < m.min || *m.in > m.max) {
			return store.ExpressPatch{}, &InvalidError{
				Field: m.field, Code: CodeOutOfRange, Reason: fmt.Sprintf("must be between %d and %d", m.min, m.max),
			}
		}
	}
	return store.ExpressPatch{
		Enabled: in.ExpressEnabled, PerHourPerIP: in.ExpressPerHourPerIP,
		PerHourPerToken: in.ExpressPerHourPerToken, MaxPending: in.ExpressMaxPending,
	}, nil
}

// expressRaised reports whether in sets an express limit above both its
// default and its stored value (a zero stored limit read as its default):
// what only the super admin may do (threat model T-418). A delegated admin
// may lower a limit, set it back to its default, or send back unchanged a
// value the super admin raised; the express ciphertexts are kept in the
// database shared by every tenant, outside the storage quota.
func expressRaised(stored tenant.ExpressSettings, in SecretSettingsInput) bool {
	cur, def := stored.WithDefaults(), tenant.DefaultExpressSettings()
	for _, m := range []struct {
		in           *int
		stored, dflt int
	}{
		{in.ExpressPerHourPerIP, cur.PerHourPerIP, def.PerHourPerIP},
		{in.ExpressPerHourPerToken, cur.PerHourPerToken, def.PerHourPerToken},
		{in.ExpressMaxPending, cur.MaxPending, def.MaxPending},
	} {
		if m.in != nil && *m.in > max(m.stored, m.dflt) {
			return true
		}
	}
	return false
}

// expressSettings returns the express settings stored with the members of
// in that are set, checked as [expressPatch] does (a zero stored limit
// read as its default).
func expressSettings(stored tenant.ExpressSettings, in SecretSettingsInput) (tenant.ExpressSettings, error) {
	p, err := expressPatch(in)
	if err != nil {
		return tenant.ExpressSettings{}, err
	}
	return p.Apply(stored.WithDefaults()), nil
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
// (since 2.1), with the settings of its express secrets (since 2.3, the
// stored value of the anonymous mode, whatever the instance kill switch).
// It is a configuration read, closed to the auditor role.
func (s *Service) GetSecretSettings(ctx context.Context, p adminauth.Principal, tid tenant.ID) (SecretSettingsInput, error) {
	t, err := s.readable(ctx, p, tid)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	return secretSettingsOfTenant(t), nil
}

// UpdateSecretSettings replaces the one-time secrets settings of tenant tid
// (since 2.1) and returns the stored ones; the settings of the express
// secrets (since 2.3) set in in replace the stored ones, the others are
// kept, both written in one transaction. An express member left out keeps
// the value stored at the time of the write, not of the read (one
// statement, store.ExpressPatch): a 2.1 client never writes back an
// anonymous mode that a concurrent update just closed. The delegated admins of the
// tenant and the super admin may call it, the anonymous mode of the
// express secrets included. The three express limits only go down for a
// delegated admin (since 2.3, threat model T-418): a limit set above both
// its default and its stored value is ErrForbidden and nothing is stored;
// the super admin sets them within their bounds. The body is checked
// first, so an invalid member (a limit out of bounds included) is an
// *InvalidError for every administrator, as UpdateTenant checks the bounds
// of the transfer limit before its ceiling. The read of the stored limits,
// the check and the write are serialized with the other changes of the
// tenant rows (Service.mu), so that a stale replacement never writes a
// limit above both its default and the value stored at the time of the
// write; a client that sends every express member back may still restore
// a limit up to its default, or reopen the anonymous mode (the
// administration screen sends only the members the admin changed). The
// settings apply to the secrets created
// afterwards: the existing ones are untouched (lowering the cap of live
// express secrets deletes nothing), except that turning the anonymous mode
// off closes the reading of the anonymous express secrets. Audited as
// secret.settings_updated with the names of the changed members; a refusal
// is not audited.
func (s *Service) UpdateSecretSettings(ctx context.Context, p adminauth.Principal, tid tenant.ID, in SecretSettingsInput, ip netip.Addr) (SecretSettingsInput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.writable(ctx, p, tid)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	next, err := secretSettings(in)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	express, err := expressPatch(in)
	if err != nil {
		return SecretSettingsInput{}, err
	}
	if superAdmin(p) != nil && expressRaised(before.Express, in) {
		return SecretSettingsInput{}, ErrForbidden
	}
	t, err := s.repo.setSecretSettings(ctx, tid, next, express)
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
	out := secretSettingsOfTenant(t)
	s.record(ctx, p, ip, tid, audit.ActionSecretSettingsUpdated, map[string]any{
		"changed": changedSecretSettings(secretSettingsOfTenant(before), out),
	})
	return out, nil
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
		{"expressEnabled", !samePtr(a.ExpressEnabled, b.ExpressEnabled)},
		{"expressPerHourPerIp", !samePtr(a.ExpressPerHourPerIP, b.ExpressPerHourPerIP)},
		{"expressPerHourPerToken", !samePtr(a.ExpressPerHourPerToken, b.ExpressPerHourPerToken)},
		{"expressMaxPending", !samePtr(a.ExpressMaxPending, b.ExpressMaxPending)},
	} {
		if m.diff {
			changed = append(changed, m.name)
		}
	}
	return changed
}

// samePtr reports whether a and b are both nil or point to equal values.
func samePtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// PublicSecretFeatures returns the secrets settings of t for the public
// configuration (OpenAPI SecretFeatures): the real rules of the creation
// form, the default duration resolved.
func PublicSecretFeatures(t *tenant.Tenant) SecretSettingsInput {
	out := SecretSettingsOf(t.Secrets)
	out.DefaultDuration = string(t.Secrets.EffectiveDefaultDuration())
	return out
}
