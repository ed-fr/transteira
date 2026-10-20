package tenant

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// MaxTransferLimit is the hard upper bound of a single transfer (20 GiB,
// CLAUDE.md §8.5). A tenant may only lower it.
const MaxTransferLimit int64 = 20 << 30

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
	// MaxTransferLimit.
	MaxTransferBytes int64
	// StorageQuotaBytes is the global storage quota of the tenant.
	StorageQuotaBytes int64
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
	if t.MaxTransferBytes <= 0 || t.MaxTransferBytes > MaxTransferLimit {
		return fmt.Errorf("%w: max transfer size must be in 1..%d bytes", ErrInvalidTenant, MaxTransferLimit)
	}
	if t.StorageQuotaBytes <= 0 {
		return fmt.Errorf("%w: storage quota must be positive", ErrInvalidTenant)
	}
	return nil
}
