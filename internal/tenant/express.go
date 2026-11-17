package tenant

import "fmt"

// Bounds and defaults of the express secret settings (OpenAPI
// SecretSettings.express*, since 2.3), also the checks of the tenants
// columns of migration 0036.
const (
	// MinExpressPerHourPerIP and MaxExpressPerHourPerIP bound
	// [ExpressSettings.PerHourPerIP]; DefaultExpressPerHourPerIP is the
	// value of a new tenant.
	MinExpressPerHourPerIP     = 1
	MaxExpressPerHourPerIP     = 1000
	DefaultExpressPerHourPerIP = 10
	// MinExpressPerHourPerToken and MaxExpressPerHourPerToken bound
	// [ExpressSettings.PerHourPerToken]; DefaultExpressPerHourPerToken is
	// the value of a new tenant.
	MinExpressPerHourPerToken     = 1
	MaxExpressPerHourPerToken     = 10000
	DefaultExpressPerHourPerToken = 100
	// MinExpressMaxPending and MaxExpressMaxPending bound
	// [ExpressSettings.MaxPending]; DefaultExpressMaxPending is the value
	// of a new tenant.
	MinExpressMaxPending     = 1
	MaxExpressMaxPending     = 100000
	DefaultExpressMaxPending = 1000
)

// expressDurations are the only durations of an express secret, fixed by
// the specification (section 22.2) whatever the tenant offers to the 2.1
// secrets ([SecretSettings.Durations]).
var expressDurations = [...]SecretDuration{SecretDuration1h, SecretDuration1d, SecretDuration7d}

// ExpressDurations returns the duration codes of the express secrets (1h,
// 1d and 7d), in ascending order of duration.
func ExpressDurations() []SecretDuration {
	out := make([]SecretDuration, len(expressDurations))
	copy(out, expressDurations[:])
	return out
}

// ExpressDuration reports whether d is a duration of the express secrets.
func (d SecretDuration) ExpressDuration() bool {
	for _, e := range expressDurations {
		if d == e {
			return true
		}
	}
	return false
}

// ExpressSettings are the settings of the express secrets of a tenant
// (OpenAPI SecretSettings.expressEnabled, expressPerHourPerIp,
// expressPerHourPerToken and expressMaxPending, since 2.3), managed by its
// delegated admin and by the super admin. They are independent of the
// switch of the 2.1 module ([SecretSettings.Enabled]). It is a plain value.
type ExpressSettings struct {
	// Enabled offers the anonymous express secrets (creation without
	// credential, and the reading of the anonymous ones); off by default.
	// The creations with an API token allowed for the express secrets do
	// not depend on it. A new tenant, imported configurations included,
	// always starts with it off (threat model P92).
	Enabled bool
	// PerHourPerIP bounds the anonymous creations of a client (IPv4
	// address or IPv6 /64) in the sliding last hour, from
	// MinExpressPerHourPerIP to MaxExpressPerHourPerIP (default
	// DefaultExpressPerHourPerIP).
	PerHourPerIP int
	// PerHourPerToken bounds the creations of an API token in the sliding
	// last hour, from MinExpressPerHourPerToken to
	// MaxExpressPerHourPerToken (default DefaultExpressPerHourPerToken).
	PerHourPerToken int
	// MaxPending bounds the live express secrets of the tenant, anonymous
	// and token ones together; beyond it the anonymous creations are
	// refused, from MinExpressMaxPending to MaxExpressMaxPending (default
	// DefaultExpressMaxPending).
	MaxPending int
}

// DefaultExpressSettings returns the settings of a new tenant, the column
// defaults of migration 0036: the anonymous mode off, 10 creations per
// client and hour, 100 per API token and hour, 1 000 live secrets.
func DefaultExpressSettings() ExpressSettings {
	return ExpressSettings{
		PerHourPerIP:    DefaultExpressPerHourPerIP,
		PerHourPerToken: DefaultExpressPerHourPerToken,
		MaxPending:      DefaultExpressMaxPending,
	}
}

// WithDefaults returns s with each limit left at zero replaced by its
// default (a zero limit is never valid). Enabled and the limits set are
// kept.
func (s ExpressSettings) WithDefaults() ExpressSettings {
	d := DefaultExpressSettings()
	if s.PerHourPerIP == 0 {
		s.PerHourPerIP = d.PerHourPerIP
	}
	if s.PerHourPerToken == 0 {
		s.PerHourPerToken = d.PerHourPerToken
	}
	if s.MaxPending == 0 {
		s.MaxPending = d.MaxPending
	}
	return s
}

// Validate checks that every limit is within its bounds. It returns an
// error wrapping ErrInvalidTenant.
func (s ExpressSettings) Validate() error {
	switch {
	case s.PerHourPerIP < MinExpressPerHourPerIP || s.PerHourPerIP > MaxExpressPerHourPerIP:
		return fmt.Errorf("%w: the express secrets per client and hour must be %d to %d",
			ErrInvalidTenant, MinExpressPerHourPerIP, MaxExpressPerHourPerIP)
	case s.PerHourPerToken < MinExpressPerHourPerToken || s.PerHourPerToken > MaxExpressPerHourPerToken:
		return fmt.Errorf("%w: the express secrets per API token and hour must be %d to %d",
			ErrInvalidTenant, MinExpressPerHourPerToken, MaxExpressPerHourPerToken)
	case s.MaxPending < MinExpressMaxPending || s.MaxPending > MaxExpressMaxPending:
		return fmt.Errorf("%w: the live express secrets must be %d to %d",
			ErrInvalidTenant, MinExpressMaxPending, MaxExpressMaxPending)
	}
	return nil
}
