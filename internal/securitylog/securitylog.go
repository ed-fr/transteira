// Package securitylog writes the TransTeira security log: one line per
// security-relevant event (failed verification code, wrong transfer password,
// failed admin login, invalid API token, unknown FQDN, refused deposit, rate
// limiting), in a stable format read by fail2ban and CrowdSec
// (CLAUDE.md section 16.3, threat model decision P22).
//
// A line looks like:
//
//	2026-10-20T07:41:00.123Z ip=203.0.113.7 tenant=transfer.entity-a.example.com event=unknown_fqdn host="evil.example.net"
//
// The timestamp (RFC 3339, UTC, milliseconds) is always first and the client
// IP always second, taken from a [netip.Addr] and never from free text.
// Every free-form value comes last, double-quoted and escaped, so that an
// attacker-controlled value can neither break the line nor forge an ip= token
// that a ban filter would trust (threat T-99). The full specification lives
// in docs/operations/security-log.md.
//
// Every line written is also published as an events.LogSecurity event on
// the event bus given with [WithPublisher] (the syslog export subscribes to
// it); the line itself never depends on it.
package securitylog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/events"
)

// EventType identifies a kind of security event. It is written as the
// event= token and must match [a-z][a-z0-9_]* (at most 64 bytes).
type EventType string

// Event types of CLAUDE.md section 16.3. The values are part of the stable
// log format: never rename one, only add new ones.
const (
	// VerificationCodeInvalid: a wrong e-mail verification code was entered.
	VerificationCodeInvalid EventType = "verification_code_invalid"
	// TransferPasswordInvalid: a wrong transfer password was entered.
	TransferPasswordInvalid EventType = "transfer_password_invalid"
	// AdminLoginFailed: an admin login failed; field reason=password|totp|recovery_code|setup_token.
	AdminLoginFailed EventType = "admin_login_failed"
	// APITokenInvalid: an unknown, revoked or expired API token was presented.
	APITokenInvalid EventType = "api_token_invalid"
	// UnknownFQDN: a request carried a Host that matches no tenant; field host.
	UnknownFQDN EventType = "unknown_fqdn"
	// DepositRefused: a deposit was refused; field reason=ip|domain|blocklist|invitation.
	DepositRefused EventType = "deposit_refused"
	// RateLimited: a rate limit was exceeded; field scope names the limiter.
	RateLimited EventType = "rate_limited"
	// MetricsTokenInvalid: a wrong monitoring token was presented to
	// /metrics or /status (since 1.1).
	MetricsTokenInvalid EventType = "metrics_token_invalid"
)

// Well-known field keys.
const (
	// KeyReason qualifies AdminLoginFailed and DepositRefused.
	KeyReason = "reason"
	// KeyScope names the limiter of a RateLimited event.
	KeyScope = "scope"
	// KeyHost carries the offending Host header of an UnknownFQDN event.
	KeyHost = "host"
)

// Well-known values of the reason field.
const (
	// ReasonPassword: wrong admin password.
	ReasonPassword = "password"
	// ReasonTOTP: wrong admin TOTP code.
	ReasonTOTP = "totp"
	// ReasonRecoveryCode: wrong admin recovery code.
	ReasonRecoveryCode = "recovery_code"
	// ReasonSetupToken: wrong or missing setup token at the first-run setup.
	ReasonSetupToken = "setup_token"
	// ReasonIP: deposit attempted from outside the tenant's IP ranges.
	ReasonIP = "ip"
	// ReasonDomain: deposit attempted with an address outside the allowed domains.
	ReasonDomain = "domain"
	// ReasonBlocklist: address, domain or file hash on the tenant's blocklist.
	ReasonBlocklist = "blocklist"
	// ReasonInvitation: missing, unknown or expired invitation.
	ReasonInvitation = "invitation"
)

// Format limits.
const (
	// MaxValueLen is the maximum number of input bytes kept from a field
	// value; longer values are cut on a UTF-8 boundary before escaping.
	MaxValueLen = 256
	// MaxEventLen is the maximum length of an event type.
	MaxEventLen = 64
	// MaxKeyLen is the maximum length of a field key.
	MaxKeyLen = 32
	// MaxTenantLen is the maximum length of a tenant FQDN (RFC 1035).
	MaxTenantLen = 253
	// TimeLayout is the layout of the leading timestamp (always UTC).
	TimeLayout = "2006-01-02T15:04:05.000Z"
	// FileMode is the permission of a log file created by [Open].
	FileMode os.FileMode = 0o640
)

// Errors returned by [Logger.Log] and [Logger.Reopen].
var (
	// ErrInvalidEvent reports an event type that is not a valid identifier.
	ErrInvalidEvent = errors.New("securitylog: invalid event type")
	// ErrInvalidKey reports a field key outside [a-z_]+ or a reserved key.
	ErrInvalidKey = errors.New("securitylog: invalid field key")
	// ErrClosed reports a use of a closed logger.
	ErrClosed = errors.New("securitylog: logger closed")
)

// Event is one security event.
type Event struct {
	// Type is the event type, written as event=.
	Type EventType
	// IP is the real client IP (from the trusted-proxy aware middleware).
	// An invalid (zero) address is written as ip=- and never matches the
	// ban filters. IPv4-mapped IPv6 addresses are written as IPv4 and the
	// zone is dropped.
	IP netip.Addr
	// Tenant is the normalised FQDN of the current tenant, or "" when the
	// request is not bound to a tenant. Anything outside [a-z0-9.-] is
	// written as tenant=-.
	Tenant string
	// Fields are extra key="value" pairs, written in order after event=.
	Fields []Field
}

// Field is one extra key="value" pair of an [Event].
type Field struct {
	// Key must match [a-z_]+ (at most 32 bytes) and must not be one of the
	// fixed tokens ip, tenant or event.
	Key string
	// Value is free text: it is quoted, escaped and truncated.
	Value string
}

// Option configures a [Logger].
type Option func(*Logger)

// WithClock replaces the clock used for timestamps (tests).
func WithClock(now func() time.Time) Option {
	return func(l *Logger) { l.now = now }
}

// WithPublisher publishes every line written as an events.LogSecurity
// event on p. A nil p publishes nothing (the default).
func WithPublisher(p events.Publisher) Option {
	return func(l *Logger) { l.publisher = events.OrDiscard(p) }
}

// WithErrorHandler sets a callback receiving the errors of reopenings
// triggered by [Logger.HandleSIGHUP], which has no caller to return them to.
func WithErrorHandler(fn func(error)) Option {
	return func(l *Logger) { l.onErr = fn }
}

// openFile opens the log file; replaced in tests to simulate failures.
var openFile = func(path string) (io.WriteCloser, error) {
	// The path comes from the operator configuration (TT_LOG_DIR), not from
	// a request.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, FileMode) //nolint:gosec // G304: operator-supplied path
	if err != nil {
		return nil, err
	}
	tightenMode(f)
	return f, nil
}

// tightenModeEnabled reports whether [tightenMode] acts. Windows has no
// Unix permission bits (Chmod only toggles the read-only attribute), so the
// check is skipped there; tests override it.
var tightenModeEnabled = runtime.GOOS != "windows"

// modeFile is the part of *os.File used by [tightenMode].
type modeFile interface {
	Stat() (os.FileInfo, error)
	Chmod(mode os.FileMode) error
}

// tightenMode removes the permission bits outside [FileMode] from an
// existing log file (O_CREATE only applies the mode to new files), so that
// a file left world-readable by an earlier deployment or a rotation tool
// stops exposing client IPs. It is best effort: a failure (file owned by
// another user, read-only mount) leaves the file as it is.
func tightenMode(f modeFile) {
	if !tightenModeEnabled {
		return
	}
	info, err := f.Stat()
	if err != nil {
		return
	}
	if perm := info.Mode().Perm(); perm&^FileMode != 0 {
		_ = f.Chmod(perm & FileMode)
	}
}

// Logger writes security events. It is safe for concurrent use: each event
// is formatted in full and written with a single Write call under a mutex,
// so lines from concurrent goroutines never interleave.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer // non-nil only for files opened by Open
	path   string    // "" for loggers built by New
	closed bool
	now    func() time.Time
	onErr  func(error)
	buf    bytes.Buffer
	// publisher receives the lines written (events.Discard by default).
	publisher events.Publisher
}

// Open opens (or creates, mode 0640) the log file at path in append mode.
// The directory must exist. On Unix, the permissions of an existing file
// wider than 0640 are tightened (best effort).
func Open(path string, opts ...Option) (*Logger, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, fmt.Errorf("securitylog: open %s: %w", path, err)
	}
	l := newLogger(f, opts)
	l.closer = f
	l.path = path
	return l, nil
}

// New returns a logger writing to w. The caller keeps ownership of w:
// [Logger.Close] does not close it and [Logger.Reopen] is a no-op.
func New(w io.Writer, opts ...Option) *Logger {
	return newLogger(w, opts)
}

func newLogger(w io.Writer, opts []Option) *Logger {
	l := &Logger{w: w, now: time.Now, onErr: func(error) {}, publisher: events.Discard}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Log formats ev and appends it as one line. It returns [ErrInvalidEvent]
// or [ErrInvalidKey] (nothing is written) for a malformed event, which is
// a programming error, and the write error otherwise.
func (l *Logger) Log(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	l.buf.Reset()
	now := l.now()
	if err := appendLine(&l.buf, now, ev); err != nil {
		return err
	}
	if _, err := l.w.Write(l.buf.Bytes()); err != nil {
		return fmt.Errorf("securitylog: write: %w", err)
	}
	// Published under the mutex, so that the events keep the order of the
	// lines; Publish never blocks.
	l.publisher.Publish(record(now, ev, l.buf.Bytes()))
	return nil
}

// record returns the events.LogSecurity event of ev, written at now as
// line (its line feed included).
func record(now time.Time, ev Event, line []byte) events.Event {
	tenant := formatTenant(ev.Tenant)
	if tenant == "-" {
		tenant = ""
	}
	fields := make([]events.Field, len(ev.Fields))
	for i, f := range ev.Fields {
		fields[i] = events.Field{Key: f.Key, Value: truncate(f.Value, MaxValueLen)}
	}
	return events.Event{
		Type: events.LogSecurity, Severity: events.SeverityInfo, OccurredAt: now,
		Log: &events.LogRecord{
			Stream: events.StreamSecurity, Time: now, Tenant: tenant, Action: string(ev.Type),
			IP: ev.IP, Fields: fields, Line: string(line[:len(line)-1]),
		},
	}
}

// Reopen closes and reopens the log file at the same path, so that the
// logger follows a logrotate rename. The old file stays in use if the new
// one cannot be opened. It is a no-op for loggers built by [New].
func (l *Logger) Reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if l.path == "" {
		return nil
	}
	f, err := openFile(l.path)
	if err != nil {
		return fmt.Errorf("securitylog: reopen %s: %w", l.path, err)
	}
	old := l.closer
	l.w, l.closer = f, f
	if err := old.Close(); err != nil {
		return fmt.Errorf("securitylog: close previous file: %w", err)
	}
	return nil
}

// Close closes the log file opened by [Open]. Further calls to Log and
// Reopen return [ErrClosed]; closing twice is harmless.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.closer == nil {
		return nil
	}
	if err := l.closer.Close(); err != nil {
		return fmt.Errorf("securitylog: close: %w", err)
	}
	return nil
}

// reopenOn reopens the file each time a value arrives on sig, until ctx is
// done. Reopen errors go to the error handler.
func (l *Logger) reopenOn(ctx context.Context, sig <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			// ErrClosed only means that a signal raced with Close during
			// shutdown: there is nothing left to reopen.
			if err := l.Reopen(); err != nil && !errors.Is(err, ErrClosed) {
				l.onErr(err)
			}
		}
	}
}

// appendLine writes the formatted line of ev, newline included, to b.
func appendLine(b *bytes.Buffer, now time.Time, ev Event) error {
	if !validEvent(ev.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidEvent, string(ev.Type))
	}
	for _, f := range ev.Fields {
		if !validKey(f.Key) {
			return fmt.Errorf("%w: %q", ErrInvalidKey, f.Key)
		}
	}
	b.WriteString(now.UTC().Format(TimeLayout))
	b.WriteString(" ip=")
	b.WriteString(FormatIP(ev.IP))
	b.WriteString(" tenant=")
	b.WriteString(formatTenant(ev.Tenant))
	b.WriteString(" event=")
	b.WriteString(string(ev.Type))
	for _, f := range ev.Fields {
		b.WriteByte(' ')
		b.WriteString(f.Key)
		b.WriteString(`="`)
		appendEscaped(b, truncate(f.Value, MaxValueLen))
		b.WriteByte('"')
	}
	b.WriteByte('\n')
	return nil
}

// FormatIP returns the ip= token of addr: "-" for an invalid address,
// otherwise the unmapped, zone-less netip form (IPv6 without brackets).
func FormatIP(addr netip.Addr) string {
	if !addr.IsValid() {
		return "-"
	}
	// The zone is free text (WithZone accepts any string): never write it.
	return addr.Unmap().WithZone("").String()
}

func formatTenant(t string) string {
	if t == "" || len(t) > MaxTenantLen {
		return "-"
	}
	for i := range len(t) {
		c := t[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return "-"
		}
	}
	return t
}

func validEvent(e EventType) bool {
	if e == "" || len(e) > MaxEventLen || e[0] < 'a' || e[0] > 'z' {
		return false
	}
	for i := range len(e) {
		c := e[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func validKey(k string) bool {
	if k == "" || len(k) > MaxKeyLen || k == "ip" || k == "tenant" || k == "event" {
		return false
	}
	for i := range len(k) {
		if c := k[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

// truncate keeps at most n bytes of s, cutting on a rune boundary when s is
// valid UTF-8 there.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for i := 0; i < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(s[cut]); i++ {
		cut--
	}
	if !utf8.RuneStart(s[cut]) {
		cut = n // invalid UTF-8: plain byte cut, bytes get \xNN-escaped
	}
	return s[:cut]
}

// appendEscaped writes s with backslash escapes: \\ and \" for the quoting,
// \n \r \t, \xNN for other ASCII control bytes and for invalid UTF-8 bytes,
// \uNNNN or \UNNNNNNNN for non-printable runes (C1 controls, line and
// paragraph separators, bidi overrides, ...).
func appendEscaped(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\x`)
			b.WriteByte(hex[s[i]>>4])
			b.WriteByte(hex[s[i]&0xf])
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		case r >= utf8.RuneSelf && !unicode.IsPrint(r):
			q := strconv.QuoteRuneToASCII(r) // e.g. backslash-u2028 or backslash-U000e0001
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
}
