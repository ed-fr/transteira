package tenant

import (
	"fmt"
	"strings"
	"time"
)

// SecretDuration is a duration code of the one-time secrets (OpenAPI
// SecretDuration, since 2.1, CLAUDE.md section 22.1): how long a secret
// stays readable once activated. The same codes are offered by a tenant
// ([SecretSettings.Durations]) and recorded on each secret.
type SecretDuration string

// Secret duration codes, in ascending order of duration.
const (
	SecretDuration1h  SecretDuration = "1h"
	SecretDuration12h SecretDuration = "12h"
	SecretDuration1d  SecretDuration = "1d"
	SecretDuration3d  SecretDuration = "3d"
	SecretDuration7d  SecretDuration = "7d"
	SecretDuration30d SecretDuration = "30d"
)

// secretDurations lists the codes in ascending order of duration; the
// index of a code is its bit in a [SecretDurationSet].
var secretDurations = [...]struct {
	code SecretDuration
	d    time.Duration
}{
	{SecretDuration1h, time.Hour},
	{SecretDuration12h, 12 * time.Hour},
	{SecretDuration1d, 24 * time.Hour},
	{SecretDuration3d, 3 * 24 * time.Hour},
	{SecretDuration7d, 7 * 24 * time.Hour},
	{SecretDuration30d, 30 * 24 * time.Hour},
}

// AllSecretDurations returns every secret duration code, in ascending
// order of duration.
func AllSecretDurations() []SecretDuration {
	out := make([]SecretDuration, len(secretDurations))
	for i, d := range secretDurations {
		out[i] = d.code
	}
	return out
}

// index returns the position of d in secretDurations, or -1.
func (d SecretDuration) index() int {
	for i, sd := range secretDurations {
		if sd.code == d {
			return i
		}
	}
	return -1
}

// Valid reports whether d is a known duration code ("" is not).
func (d SecretDuration) Valid() bool { return d.index() >= 0 }

// Duration returns the length of d, or 0 for an unknown code.
func (d SecretDuration) Duration() time.Duration {
	if i := d.index(); i >= 0 {
		return secretDurations[i].d
	}
	return 0
}

// SecretDurationSet is a set of secret duration codes. It is a plain
// value (a bit set), so that a [Tenant] stays copyable by assignment; the
// zero value is the empty set.
type SecretDurationSet uint8

// NewSecretDurationSet returns the set of codes. It returns an error
// wrapping ErrInvalidTenant for an unknown or duplicated code.
func NewSecretDurationSet(codes ...SecretDuration) (SecretDurationSet, error) {
	var s SecretDurationSet
	for _, c := range codes {
		i := c.index()
		if i < 0 {
			return 0, fmt.Errorf("%w: unknown secret duration %q", ErrInvalidTenant, truncate(string(c)))
		}
		if s&(1<<i) != 0 {
			return 0, fmt.Errorf("%w: duplicate secret duration %q", ErrInvalidTenant, c)
		}
		s |= 1 << i
	}
	return s, nil
}

// ParseSecretDurationSet parses the comma-separated list of codes of
// tenants.secret_durations (as written by [SecretDurationSet.String]).
// It returns an error wrapping ErrInvalidTenant for an empty list, an
// unknown or a duplicated code.
func ParseSecretDurationSet(csv string) (SecretDurationSet, error) {
	if csv == "" {
		return 0, fmt.Errorf("%w: empty secret duration list", ErrInvalidTenant)
	}
	parts := strings.Split(csv, ",")
	codes := make([]SecretDuration, len(parts))
	for i, p := range parts {
		codes[i] = SecretDuration(p)
	}
	return NewSecretDurationSet(codes...)
}

// Has reports whether d belongs to s.
func (s SecretDurationSet) Has(d SecretDuration) bool {
	i := d.index()
	return i >= 0 && s&(1<<i) != 0
}

// Empty reports whether s holds no code.
func (s SecretDurationSet) Empty() bool { return s&s.all() == 0 }

// all is the mask of the known codes.
func (SecretDurationSet) all() SecretDurationSet { return 1<<len(secretDurations) - 1 }

// Codes returns the codes of s in ascending order of duration.
func (s SecretDurationSet) Codes() []SecretDuration {
	var out []SecretDuration
	for i, sd := range secretDurations {
		if s&(1<<i) != 0 {
			out = append(out, sd.code)
		}
	}
	return out
}

// Shortest returns the shortest code of s, or "" when s is empty.
func (s SecretDurationSet) Shortest() SecretDuration {
	if c := s.Codes(); len(c) > 0 {
		return c[0]
	}
	return ""
}

// String returns the codes of s in ascending order of duration, separated
// by commas (the format of tenants.secret_durations).
func (s SecretDurationSet) String() string {
	c := s.Codes()
	parts := make([]string, len(c))
	for i, d := range c {
		parts[i] = string(d)
	}
	return strings.Join(parts, ",")
}

// Bounds and defaults of the secret file size (ciphertext bytes).
const (
	// MinSecretFileBytes is the smallest file limit a tenant may set (1 MiB).
	MinSecretFileBytes int64 = 1 << 20
	// MaxSecretFileBytes is the instance hard limit of a secret file
	// (25 MiB), also the bound of secrets.file_size.
	MaxSecretFileBytes int64 = 25 << 20
	// DefaultSecretFileBytes is the file limit of a new tenant (10 MiB).
	DefaultSecretFileBytes int64 = 10 << 20
)

// SecretSettings are the settings of the one-time secret module of a
// tenant (OpenAPI SecretSettings, since 2.1), managed by its delegated
// admin and by the super admin. It is a plain value.
type SecretSettings struct {
	// Enabled turns the module on (the default).
	Enabled bool
	// Durations are the duration codes the creators may choose, never
	// empty (default 1h, 1d and 7d).
	Durations SecretDurationSet
	// DefaultDuration is the code preselected by the web app, one of
	// Durations; "" means the shortest offered one
	// ([SecretSettings.EffectiveDefaultDuration]).
	DefaultDuration SecretDuration
	// FileAllowed lets a secret carry a file (the default).
	FileAllowed bool
	// FileMaxBytes bounds the ciphertext size of that file, from
	// MinSecretFileBytes to MaxSecretFileBytes (default
	// DefaultSecretFileBytes).
	FileMaxBytes int64
	// EmailAllowed offers the e-mail delivery besides the link (the
	// default).
	EmailAllowed bool
	// EmailRequiresPassphrase refuses an e-mail secret without passphrase
	// (threat model P83); off by default.
	EmailRequiresPassphrase bool
}

// DefaultSecretSettings returns the settings of a new tenant, the column
// defaults of migration 0033.
func DefaultSecretSettings() SecretSettings {
	return SecretSettings{
		Enabled:      true,
		Durations:    1<<SecretDuration1h.index() | 1<<SecretDuration1d.index() | 1<<SecretDuration7d.index(),
		FileAllowed:  true,
		FileMaxBytes: DefaultSecretFileBytes,
		EmailAllowed: true,
	}
}

// EffectiveDefaultDuration returns DefaultDuration when set, the shortest
// offered code otherwise.
func (s SecretSettings) EffectiveDefaultDuration() SecretDuration {
	if s.DefaultDuration != "" {
		return s.DefaultDuration
	}
	return s.Durations.Shortest()
}

// Validate checks the settings: at least one known duration, a default
// duration that is offered (or ""), and a file limit within bounds. It
// returns an error wrapping ErrInvalidTenant.
func (s SecretSettings) Validate() error {
	if s.Durations.Empty() || s.Durations&^s.Durations.all() != 0 {
		return fmt.Errorf("%w: the secret durations must name at least one known code", ErrInvalidTenant)
	}
	if s.DefaultDuration != "" && !s.Durations.Has(s.DefaultDuration) {
		return fmt.Errorf("%w: the default secret duration %q is not offered", ErrInvalidTenant, truncate(string(s.DefaultDuration)))
	}
	if s.FileMaxBytes < MinSecretFileBytes || s.FileMaxBytes > MaxSecretFileBytes {
		return fmt.Errorf("%w: the secret file limit must be %d to %d bytes", ErrInvalidTenant, MinSecretFileBytes, MaxSecretFileBytes)
	}
	return nil
}
