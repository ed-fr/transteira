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

// SetupState tells whether a tenant is still being configured (OpenAPI
// TenantSetupState, since V1.2). It has no default: every creation names
// it explicitly (threat model T-261), and the zero value "" is invalid.
type SetupState string

// Setup states. The only transition is from SetupStateSetup to
// SetupStateActive, when the setup is completed.
const (
	// SetupStateSetup marks a tenant being configured: its public
	// operations, but the tenant information, assets and legal texts,
	// answer 503 tenant-in-setup.
	SetupStateSetup SetupState = "setup"
	// SetupStateActive marks a tenant open to deposits.
	SetupStateActive SetupState = "active"
)

// Valid reports whether s is a known setup state ("" is not).
func (s SetupState) Valid() bool { return s == SetupStateSetup || s == SetupStateActive }

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

// maxPresetLen is the maximum length of a background preset identifier
// (the CHECK of tenants.background_preset).
const maxPresetLen = 32

// ValidPresetID reports whether s has the syntax of a background preset
// identifier: a lowercase letter followed by up to 31 lowercase letters,
// digits or hyphens (^[a-z][a-z0-9-]{0,31}$). It does not tell whether the
// preset exists: the library belongs to package branding.
func ValidPresetID(s string) bool {
	if len(s) == 0 || len(s) > maxPresetLen || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
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
	// BackgroundPreset is the identifier of the background preset of the
	// library served when HasBackground is false; "" means the default
	// preset (stored as NULL). The list of valid identifiers belongs to
	// package branding: this package checks the syntax only (ValidPresetID).
	BackgroundPreset string
	// WebhookIncludeAddresses tells whether the tenant webhooks receive the
	// sender and recipient addresses concerned by an event; off by default
	// (minimal payloads, decision P31).
	WebhookIncludeAddresses bool
	// AllowRemoteInternalDeposit lets an internal user whose address was
	// already verified once from the tenant's IP ranges deposit from
	// outside them, with a verification code at every deposit (spec 6.4);
	// off by default.
	AllowRemoteInternalDeposit bool
	// AllowTransferReply lets the recipient of a transfer sent by an
	// internal user send files back to its sender through a reply link,
	// without invitation, after verifying their address by code (spec 10);
	// off by default.
	AllowTransferReply bool
	// SetupState is the setup state of the tenant (V1.2). It is set at
	// creation and only changes from SetupStateSetup to SetupStateActive,
	// by the completion of the setup; the general update never writes it.
	SetupState SetupState
	// SMTPTestedAt stamps the SMTP configuration of the tenant that last
	// passed a test send: it is the modification time of that
	// configuration (store.SMTPConfig.UpdatedAt), zero when none passed.
	// Every change of the SMTP settings gives them a new, strictly later
	// modification time, so the stamp no longer matches: the "smtp" item
	// of the setup checklist is done only while it equals the modification
	// time of the current settings.
	SMTPTestedAt time.Time
	// MailTemplatesReviewedAt is the time an administrator marked the mail
	// templates as reviewed while completing the setup, zero when never.
	MailTemplatesReviewedAt time.Time
	// AntivirusEnabled tells whether the files of the tenant are analyzed
	// by the antivirus (on for every new tenant; only the super admin
	// turns it off). The analysis really happens only when the instance
	// engine is not "none" as well (antivirusEffective). It is read at
	// finalization (decision D8).
	AntivirusEnabled bool
	// ProvisionedBy is the identifier ("prv_" + ULID) of the provisioning
	// token that created the tenant, "" for a tenant created by a super
	// admin (V1.2). It is set at creation only, by the store.
	ProvisionedBy string
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// UpdatedAt is the time of the last modification.
	UpdatedAt time.Time
}

// AntivirusEffective reports whether the files of t finalized now are
// analyzed by the antivirus: its switch is on and the instance engine is
// not "none" (instanceDisabled false). It is the rule of the OpenAPI
// Tenant.antivirusEffective and TenantFeatures.antivirus.
func (t *Tenant) AntivirusEffective(instanceDisabled bool) bool {
	return t.AntivirusEnabled && !instanceDisabled
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
// colors. Set fields are kept as they are. The setup state has no default
// (T-261): it stays as given.
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
	if !t.SetupState.Valid() {
		return fmt.Errorf("%w: unknown setup state %q", ErrInvalidTenant, truncate(string(t.SetupState)))
	}
	if !ValidColor(t.PrimaryColor) || !ValidColor(t.AccentColor) {
		return fmt.Errorf("%w: colors must be #RRGGBB", ErrInvalidTenant)
	}
	if t.BackgroundPreset != "" && !ValidPresetID(t.BackgroundPreset) {
		return fmt.Errorf("%w: invalid background preset %q", ErrInvalidTenant, truncate(t.BackgroundPreset))
	}
	return nil
}
