package mail

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"
)

// Security is the transport security mode of an SMTP connection.
type Security string

// SMTP security modes (CLAUDE.md section 12.1).
const (
	// SecurityNone is plain TCP, without TLS and without authentication. It
	// exists for an SMTP relay on the internal Docker network (for example a
	// relay to Microsoft Graph) and must never cross an untrusted network
	// (threat T-85). A Username is refused in this mode: credentials are
	// never sent in clear.
	SecurityNone Security = "none"
	// SecurityStartTLS connects in clear and upgrades with STARTTLS. The
	// upgrade is mandatory: a server that does not offer STARTTLS is an error,
	// never a silent downgrade.
	SecurityStartTLS Security = "starttls"
	// SecurityTLS is implicit TLS from the first byte (usually port 465).
	SecurityTLS Security = "tls"
)

// Limits on settings fields.
const (
	maxHostLen     = 253
	maxUsernameLen = 320
	maxPasswordLen = 1024
	maxNameLen     = 100
)

// redacted replaces secrets in any printed form.
const redacted = "[REDACTED]"

// Settings is the SMTP configuration of one tenant (CLAUDE.md section 12.1).
//
// Password is the clear-text SMTP password. It is only ever held in memory:
// the caller unseals it from the database just before building a [Job] and
// it is never persisted, logged or printed by this package. [Settings.String],
// [Settings.GoString] and [Settings.LogValue] redact it, and SMTP errors are
// scrubbed of it.
type Settings struct {
	// Host is the SMTP server name or IP address. It is also the TLS server
	// name checked against the certificate.
	Host string
	// Port is the TCP port (1 to 65535).
	Port int
	// Security is the transport security mode.
	Security Security
	// Username enables AUTH PLAIN when non-empty (TLS modes only).
	Username string
	// Password is the SMTP password, in memory only.
	Password string
	// FromAddress is the envelope sender and From address.
	FromAddress string
	// FromName is the optional display name of the From header.
	FromName string
}

// Validate checks the settings: Host and Port are mandatory, Security must
// be a known mode, FromAddress must be a valid address, FromName must be a
// safe single-line display name, and credentials are only allowed with TLS.
// Errors wrap [ErrInvalidSettings] and never contain the password.
func (s Settings) Validate() error {
	if err := validateHost(s.Host); err != nil {
		return err
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalidSettings)
	}
	switch s.Security {
	case SecurityNone, SecurityStartTLS, SecurityTLS:
	default:
		return fmt.Errorf("%w: unknown security mode", ErrInvalidSettings)
	}
	if _, err := ParseAddress(s.FromAddress); err != nil {
		return fmt.Errorf("%w: from address: %w", ErrInvalidSettings, err)
	}
	if err := validateDisplayName(s.FromName); err != nil {
		return fmt.Errorf("%w: from name: %w", ErrInvalidSettings, err)
	}
	if len(s.Username) > maxUsernameLen || hasControl(s.Username) {
		return fmt.Errorf("%w: invalid username", ErrInvalidSettings)
	}
	if len(s.Password) > maxPasswordLen || hasControl(s.Password) {
		return fmt.Errorf("%w: invalid password", ErrInvalidSettings)
	}
	if s.Username == "" && s.Password != "" {
		return fmt.Errorf("%w: password set without username", ErrInvalidSettings)
	}
	if s.Username != "" && s.Security == SecurityNone {
		return fmt.Errorf("%w: authentication requires starttls or tls", ErrInvalidSettings)
	}
	return nil
}

// validateHost accepts a DNS name or an IP literal, without port, spaces or
// control characters.
func validateHost(h string) error {
	if h == "" {
		return fmt.Errorf("%w: host is required", ErrInvalidSettings)
	}
	if len(h) > maxHostLen {
		return fmt.Errorf("%w: host too long", ErrInvalidSettings)
	}
	for i := range len(h) {
		c := h[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == ':' || c == '_'
		if !ok {
			return fmt.Errorf("%w: invalid character in host", ErrInvalidSettings)
		}
	}
	return nil
}

// String describes the settings with the password redacted.
func (s Settings) String() string {
	pw := ""
	if s.Password != "" {
		pw = " password=" + redacted
	}
	return fmt.Sprintf("smtp{host=%s port=%d security=%s username=%q%s from=%q}",
		s.Host, s.Port, s.Security, s.Username, pw, s.FromAddress)
}

// GoString is the %#v form, with the password redacted.
func (s Settings) GoString() string {
	return "mail.Settings" + strings.TrimPrefix(s.String(), "smtp")
}

// LogValue implements [slog.LogValuer]: the password is never logged, only
// whether one is set.
func (s Settings) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", s.Host),
		slog.Int("port", s.Port),
		slog.String("security", string(s.Security)),
		slog.String("username", s.Username),
		slog.Bool("password_set", s.Password != ""),
		slog.String("from", s.FromAddress),
	)
}

// validateDisplayName accepts an optional single-line display name of at
// most maxNameLen characters, in valid UTF-8, without control characters.
func validateDisplayName(name string) error {
	if !utf8.ValidString(name) {
		return errors.New("invalid UTF-8")
	}
	if utf8.RuneCountInString(name) > maxNameLen {
		return errors.New("too long")
	}
	if hasControl(name) {
		return errors.New("control character")
	}
	return nil
}

// hasControl reports whether s contains a C0 or C1 control character
// (including CR, LF, TAB and NUL), DEL or a Unicode line or paragraph
// separator.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}
