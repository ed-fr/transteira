package tenant

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxTransferLimit is the hard upper bound of a single transfer (20 GiB,
// CLAUDE.md §8.5). A tenant may only lower it.
const MaxTransferLimit int64 = 20 << 30

// Default colors of a tenant that has not chosen its own (OpenAPI
// HexColor). Both reach the WCAG AA contrast ratio for normal text on white
// and with white text: DefaultPrimaryColor about 8.7:1 (AAA), and
// DefaultAccentColor about 5.2:1.
const (
	DefaultPrimaryColor = "#1F4E79"
	DefaultAccentColor  = "#C2410C"
)

// Status is the lifecycle state of a tenant.
type Status string

// Tenant statuses.
const (
	// StatusActive is the normal state of a tenant.
	StatusActive Status = "active"
	// StatusDeleting marks a tenant whose deletion has started: it no
	// longer resolves from its FQDN and accepts no new use, while the
	// deletion (which resumes after an interruption) erases its data.
	StatusDeleting Status = "deleting"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool { return s == StatusActive || s == StatusDeleting }

// Name length bounds, aligned with the OpenAPI Tenant schema.
const (
	minNameLen = 1
	maxNameLen = 100
)

// ErrInvalidTenant reports a tenant whose fields fail validation.
var ErrInvalidTenant = errors.New("tenant: invalid tenant")

// languages lists the supported UI languages (ISO 639-1).
var languages = map[string]struct{}{"fr": {}, "en": {}}

// Languages returns the supported UI language codes, in a stable order.
func Languages() []string { return []string{"en", "fr"} }

// IsLanguage reports whether code is a supported UI language.
func IsLanguage(code string) bool {
	_, ok := languages[code]
	return ok
}

// colorLen is the length of a "#RRGGBB" color.
const colorLen = 7

// ValidColor reports whether s is a "#RRGGBB" hexadecimal color (OpenAPI
// HexColor, either case).
func ValidColor(s string) bool {
	return len(s) == colorLen && s[0] == '#' &&
		strings.Trim(s[1:], "0123456789abcdefABCDEF") == ""
}

// Tenant is an entity sharing the TransTeira instance. All of its fields are
// plain values, so copying the struct yields an independent copy.
type Tenant struct {
	// ID is the tenant identifier.
	ID ID
	// Name is the display name of the entity (1 to 100 characters).
	Name string
	// FQDN is the normalised host name serving the tenant (see NormalizeHost).
	FQDN string
	// DefaultLanguage is the language used when the browser offers none of
	// the supported ones ("fr" or "en").
	DefaultLanguage string
	// MaxTransferBytes is the maximum total size of one transfer, at most
	// MaxTransferCeiling.
	MaxTransferBytes int64
	// MaxTransferCeiling is the ceiling of MaxTransferBytes set by the
	// super admin, at most MaxTransferLimit: a delegated admin may lower
	// MaxTransferBytes under it, never raise it above.
	MaxTransferCeiling int64
	// StorageQuotaBytes is the global storage quota of the tenant.
	StorageQuotaBytes int64
	// Status is the lifecycle state of the tenant.
	Status Status
	// PrimaryColor and AccentColor are the "#RRGGBB" colors of the
	// tenant's pages.
	PrimaryColor string
	AccentColor  string
	// HasLogo and HasBackground tell whether the tenant uploaded its own
	// logo and background image (stored in its folder, not in the
	// database); the default ones are used otherwise.
	HasLogo       bool
	HasBackground bool
	// WebhookIncludeAddresses tells whether the tenant webhooks receive the
	// sender and recipient addresses concerned by an event; off by default
	// (minimal payloads, decision P31).
	WebhookIncludeAddresses bool
	// AllowRemoteInternalDeposit lets an internal user whose address was
	// already verified once from the tenant's IP ranges deposit from
	// outside them, with a verification code at every deposit (spec 6.4);
	// off by default.
	AllowRemoteInternalDeposit bool
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// UpdatedAt is the time of the last modification.
	UpdatedAt time.Time
}

// Clone returns an independent copy of t, or nil when t is nil.
func (t *Tenant) Clone() *Tenant {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// WithDefaults returns a copy of t with its unset settings filled in: the
// MaxTransferBytes as MaxTransferCeiling, the active status and the default
// colors. Set fields are kept as they are.
func (t *Tenant) WithDefaults() *Tenant {
	c := *t
	if c.MaxTransferCeiling == 0 {
		c.MaxTransferCeiling = c.MaxTransferBytes
	}
	if c.Status == "" {
		c.Status = StatusActive
	}
	if c.PrimaryColor == "" {
		c.PrimaryColor = DefaultPrimaryColor
	}
	if c.AccentColor == "" {
		c.AccentColor = DefaultAccentColor
	}
	return &c
}

// Validate checks the tenant's business invariants. The ID is checked only
// when set, so that a tenant can be validated before it is created. The
// FQDN must already be in normalised form.
func (t *Tenant) Validate() error {
	if !t.ID.IsZero() {
		if err := t.ID.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidTenant, err)
		}
	}
	if n := utf8.RuneCountInString(t.Name); n < minNameLen || n > maxNameLen || !utf8.ValidString(t.Name) {
		return fmt.Errorf("%w: name must be %d to %d characters", ErrInvalidTenant, minNameLen, maxNameLen)
	}
	norm, err := NormalizeHost(t.FQDN)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTenant, err)
	}
	if norm != t.FQDN {
		return fmt.Errorf("%w: fqdn %q is not normalised (want %q)", ErrInvalidTenant, truncate(t.FQDN), norm)
	}
	if !IsLanguage(t.DefaultLanguage) {
		return fmt.Errorf("%w: unsupported language %q", ErrInvalidTenant, truncate(t.DefaultLanguage))
	}
	if t.MaxTransferCeiling <= 0 || t.MaxTransferCeiling > MaxTransferLimit {
		return fmt.Errorf("%w: max transfer ceiling must be in 1..%d bytes", ErrInvalidTenant, MaxTransferLimit)
	}
	if t.MaxTransferBytes <= 0 || t.MaxTransferBytes > t.MaxTransferCeiling {
		return fmt.Errorf("%w: max transfer size must be positive and at most the ceiling", ErrInvalidTenant)
	}
	if t.StorageQuotaBytes <= 0 {
		return fmt.Errorf("%w: storage quota must be positive", ErrInvalidTenant)
	}
	if !t.Status.Valid() {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidTenant, truncate(string(t.Status)))
	}
	if !ValidColor(t.PrimaryColor) || !ValidColor(t.AccentColor) {
		return fmt.Errorf("%w: colors must be #RRGGBB", ErrInvalidTenant)
	}
	return nil
}
