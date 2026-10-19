package config

import (
	"fmt"
	"log/slog"
)

// Redacted is the placeholder printed instead of a secret value.
const Redacted = "[REDACTED]"

// Secret holds a sensitive configuration value (database DSN, setup token...).
//
// Every formatting path (fmt verbs, String, GoString, JSON, text marshaling and
// slog) prints [Redacted] instead of the value, so that a Secret cannot leak
// into logs or error messages by accident. The value is only reachable through
// the explicit [Secret.Reveal] method.
type Secret struct {
	value string
}

// NewSecret wraps a sensitive value. It is mainly useful in tests and when
// building a Config by hand.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// Reveal returns the secret value. Callers must never log or print it.
func (s Secret) Reveal() string {
	return s.value
}

// IsSet reports whether the secret holds a non-empty value.
func (s Secret) IsSet() bool {
	return s.value != ""
}

// String implements fmt.Stringer and always returns [Redacted].
func (Secret) String() string {
	return Redacted
}

// GoString implements fmt.GoStringer and always returns [Redacted].
func (Secret) GoString() string {
	return Redacted
}

// Format implements fmt.Formatter so that every verb (%v, %s, %q, %x, %#v...)
// prints [Redacted].
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(Redacted))
}

// MarshalJSON implements json.Marshaler and always emits "[REDACTED]".
func (Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Redacted + `"`), nil
}

// MarshalText implements encoding.TextMarshaler and always emits [Redacted].
func (Secret) MarshalText() ([]byte, error) {
	return []byte(Redacted), nil
}

// LogValue implements slog.LogValuer and always logs [Redacted].
func (Secret) LogValue() slog.Value {
	return slog.StringValue(Redacted)
}
