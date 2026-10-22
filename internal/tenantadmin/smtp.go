package tenantadmin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Limits of the SMTP settings (OpenAPI SmtpSettingsUpdate).
const (
	maxSMTPHostLen     = 253
	maxSMTPUsernameLen = 320
	maxSMTPPasswordLen = 1024
	maxSMTPFromNameLen = 100
	maxPort            = 65535
	// maxReplyLen bounds the server reply returned by an SMTP test, in
	// characters.
	maxReplyLen = 300
)

// redacted replaces a credential in an SMTP reply.
const redacted = "[REDACTED]"

// SMTP test stages: how far the SMTP exchange went ([SMTPTestResult]).
const (
	StageSettings = "settings"
	StageConnect  = "connect"
	StageTLS      = "tls"
	StageGreeting = "greeting"
	StageStartTLS = "starttls"
	StageAuth     = "auth"
	StageEnvelope = "envelope"
	StageData     = "data"
	StageDone     = "done"
	StageUnknown  = "unknown"
)

// SMTPView is the SMTP configuration of a tenant as returned to an
// administrator (OpenAPI SmtpSettings): the password is never returned.
type SMTPView struct {
	Host        string
	Port        int
	Security    store.SMTPSecurity
	Username    string
	PasswordSet bool
	FromAddress string
	FromName    string
}

// SMTPUpdate is the input of [Service.UpdateSMTP] (OpenAPI
// SmtpSettingsUpdate).
type SMTPUpdate struct {
	Host     string
	Port     int
	Security store.SMTPSecurity
	// Username is "" without authentication.
	Username string
	// Password is the new password; nil keeps the stored one.
	Password *string
	// RemovePassword removes the stored password; it cannot be combined
	// with Password.
	RemovePassword bool
	FromAddress    string
	FromName       string
}

// SMTPTestResult is the result of an SMTP test (OpenAPI SmtpTestResult).
type SMTPTestResult struct {
	// Success reports that the server accepted the message.
	Success bool
	// Duration is the time the exchange took.
	Duration time.Duration
	// Stage is how far the exchange went (StageDone on success).
	Stage string
	// Error is the failure, sanitized and truncated: it never contains a
	// credential nor a control character.
	Error string
}

// viewOf converts a stored configuration.
func viewOf(c store.SMTPConfig) SMTPView {
	return SMTPView{
		Host: c.Host, Port: c.Port, Security: c.Security, Username: c.Username,
		PasswordSet: c.PasswordKeyID != "", FromAddress: c.FromAddress, FromName: c.FromName,
	}
}

// GetSMTP returns the SMTP settings of tenant tid, or ErrNotFound when it
// has none.
func (s *Service) GetSMTP(ctx context.Context, p adminauth.Principal, tid tenant.ID) (SMTPView, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return SMTPView{}, err
	}
	c, err := s.smtpConfig(ctx, tid)
	if err != nil {
		return SMTPView{}, err
	}
	return viewOf(c), nil
}

// smtpConfig returns the stored SMTP settings of tid.
func (s *Service) smtpConfig(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	c, err := s.repo.smtp(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.SMTPConfig{}, ErrNotFound
	case err != nil:
		return store.SMTPConfig{}, fmt.Errorf("tenantadmin: get smtp settings: %w", err)
	}
	return c, nil
}

// UpdateSMTP replaces the SMTP settings of tenant tid. A host given as an
// IP literal inside the denied networks is refused. To keep a stored
// password from being sent to another server, Password or RemovePassword
// is required whenever the host, port or username changes while a password
// is stored (checked inside the transaction that saves the settings). A
// new password is sealed with the master key; the replaced one is
// destroyed (crypto-erase). Access is checked first: the refusal on a
// tenant out of reach never depends on the settings.
func (s *Service) UpdateSMTP(ctx context.Context, p adminauth.Principal, tid tenant.ID, in SMTPUpdate, ip netip.Addr) (SMTPView, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return SMTPView{}, err
	}
	next, err := s.checkSMTP(in)
	if err != nil {
		return SMTPView{}, err
	}
	cur, err := s.repo.smtp(ctx, tid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return SMTPView{}, fmt.Errorf("tenantadmin: get smtp settings: %w", err)
	}
	update := passwordUpdate{keep: in.Password == nil && !in.RemovePassword}
	credentials := "kept"
	switch {
	case in.Password != nil:
		update.password = []byte(*in.Password)
		defer clear(update.password)
		credentials = "changed"
	case in.RemovePassword:
		credentials = "removed"
	}
	err = s.repo.putSMTP(ctx, tid, next, update)
	switch {
	case errors.Is(err, errPasswordRequired):
		return SMTPView{}, invalid(FieldPassword, "required when the host, port or username of a stored password changes")
	case errors.Is(err, store.ErrInvalid):
		return SMTPView{}, invalid("", "invalid smtp settings")
	case errors.Is(err, store.ErrNotFound):
		return SMTPView{}, ErrNotFound
	case err != nil:
		return SMTPView{}, fmt.Errorf("tenantadmin: put smtp settings: %w", err)
	}
	saved, err := s.smtpConfig(ctx, tid)
	if err != nil {
		return SMTPView{}, err
	}
	s.record(ctx, p, ip, tid, ActionTenantSMTPUpdated, map[string]any{
		"fields": smtpChanges(cur, saved), "credentials": credentials,
	})
	return viewOf(saved), nil
}

// checkSMTP validates in and returns the configuration to store, without
// password key.
func (s *Service) checkSMTP(in SMTPUpdate) (store.SMTPConfig, error) {
	host := strings.TrimSpace(in.Host)
	switch {
	case !validSMTPHost(host):
		return store.SMTPConfig{}, invalid(FieldHost, "must be a host name or an IP address")
	case s.deniedHost(host):
		return store.SMTPConfig{}, invalid(FieldHost, "address in a denied network (TT_SMTP_DENY_NETWORKS)")
	case in.Port < 1 || in.Port > maxPort:
		return store.SMTPConfig{}, invalid(FieldPort, "must be between 1 and %d", maxPort)
	}
	switch in.Security {
	case store.SMTPSecurityNone, store.SMTPSecuritySTARTTLS, store.SMTPSecurityTLS:
	default:
		return store.SMTPConfig{}, invalid(FieldSecurity, "must be none, starttls or tls")
	}
	switch {
	case len(in.Username) > maxSMTPUsernameLen || !safeLine(in.Username):
		return store.SMTPConfig{}, invalid(FieldUsername, "must be text of at most %d bytes", maxSMTPUsernameLen)
	case in.Username != "" && in.Security == store.SMTPSecurityNone:
		return store.SMTPConfig{}, invalid(FieldUsername, "authentication requires starttls or tls")
	case in.Password != nil && in.RemovePassword:
		return store.SMTPConfig{}, invalid(FieldPassword, "cannot be combined with removePassword")
	case in.Password != nil && (*in.Password == "" || len(*in.Password) > maxSMTPPasswordLen || !safeLine(*in.Password)):
		return store.SMTPConfig{}, invalid(FieldPassword, "must be 1 to %d bytes without control characters", maxSMTPPasswordLen)
	case in.Password != nil && in.Username == "":
		return store.SMTPConfig{}, invalid(FieldPassword, "requires a username")
	case utf8.RuneCountInString(in.FromName) > maxSMTPFromNameLen || !safeLine(in.FromName):
		return store.SMTPConfig{}, invalid(FieldFromName, "must be text of at most %d characters", maxSMTPFromNameLen)
	}
	from, err := mail.ParseAddress(in.FromAddress)
	if err != nil {
		return store.SMTPConfig{}, invalid(FieldFromAddress, "must be a mail address")
	}
	return store.SMTPConfig{
		Host: host, Port: in.Port, Security: in.Security, Username: in.Username,
		FromAddress: from, FromName: in.FromName,
	}, nil
}

// validSMTPHost reports whether h looks like a host name, a Docker service
// name or an IP address.
func validSMTPHost(h string) bool {
	if h == "" || len(h) > maxSMTPHostLen {
		return false
	}
	return strings.Trim(h, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:") == ""
}

// deniedHost reports whether host is an IP literal in a denied network.
func (s *Service) deniedHost(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && netpolicy.Contains(s.deny, addr)
}

// safeLine reports whether v is valid UTF-8 without control, bidi or line
// separator characters.
func safeLine(v string) bool {
	return utf8.ValidString(v) && !strings.ContainsFunc(v, unsafeRune)
}

// unsafeRune reports the characters refused in a single line of text.
func unsafeRune(r rune) bool {
	return textsafe.IsControl(r) || textsafe.IsBidiControl(r) || textsafe.IsLineSeparator(r)
}

// smtpChanges returns the API names of the settings that differ.
func smtpChanges(a, b store.SMTPConfig) []string {
	var out []string
	for _, f := range []struct {
		diff bool
		name string
	}{
		{a.Host != b.Host, "host"},
		{a.Port != b.Port, "port"},
		{a.Security != b.Security, "security"},
		{a.Username != b.Username, "username"},
		{a.FromAddress != b.FromAddress, "fromAddress"},
		{a.FromName != b.FromName, "fromName"},
	} {
		if f.diff {
			out = append(out, f.name)
		}
	}
	return out
}

// TestSMTP sends a fixed test mail to the address to with the SMTP settings
// of tenant tid and reports how the exchange went. It is limited per
// administrator and tenant (*RateLimitError). The result is returned even
// when the delivery fails; an error means the test could not run.
func (s *Service) TestSMTP(ctx context.Context, p adminauth.Principal, tid tenant.ID, to string, ip netip.Addr) (SMTPTestResult, error) {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return SMTPTestResult{}, err
	}
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return SMTPTestResult{}, invalid(FieldTo, "must be a mail address")
	}
	if ok, retry := s.smtpTests.Allow(p.Admin.ID + "|" + string(tid)); !ok {
		return SMTPTestResult{}, &RateLimitError{RetryAfter: max(retry, time.Second)}
	}
	c, err := s.smtpConfig(ctx, tid)
	if err != nil {
		return SMTPTestResult{}, err
	}
	settings := mail.Settings{
		Host: c.Host, Port: c.Port, Security: mail.Security(c.Security), Username: c.Username,
		FromAddress: c.FromAddress, FromName: c.FromName,
	}
	if c.PasswordKeyID != "" {
		pw, err := s.repo.openSecret(ctx, tid, c.PasswordKeyID)
		if err != nil {
			return SMTPTestResult{}, fmt.Errorf("tenantadmin: unseal smtp password: %w", err)
		}
		settings.Password = string(pw)
		clear(pw)
	}
	start := s.now()
	if s.deniedHost(settings.Host) {
		// Saved before the deny list was widened: never connect.
		err = fmt.Errorf("%w: %s", ErrAddressDenied, settings.Host)
	} else {
		err = s.mailer.Send(ctx, settings, testMessage(t, rcpt))
	}
	res := SMTPTestResult{Success: err == nil, Duration: s.now().Sub(start), Stage: StageDone}
	if err != nil {
		res.Stage = stageOf(err)
		res.Error = testError(res.Stage, err, settings)
	}
	s.record(ctx, p, ip, tid, ActionTenantSMTPTested, map[string]any{"success": res.Success, "stage": res.Stage})
	return res, nil
}

// testMessage is the fixed test mail.
func testMessage(t *tenant.Tenant, to string) mail.Message {
	return mail.Message{
		To:       []string{to},
		Subject:  "TransTeira SMTP test - " + t.Name,
		Language: "en",
		Text: "This message was sent by TransTeira to test the SMTP settings of " + t.Name + ".\n" +
			"Ce message a été envoyé par TransTeira pour tester les paramètres SMTP de " + t.Name + ".\n",
	}
}

// stageMarkers map the texts of the mail errors to the stage that failed,
// in the order they are tested.
var stageMarkers = []struct{ marker, stage string }{
	{"connect:", StageConnect},
	{"TLS handshake", StageTLS},
	{"greeting", StageGreeting},
	{"EHLO", StageGreeting},
	{"STARTTLS", StageStartTLS},
	{"MAIL FROM", StageEnvelope},
	{"RCPT TO", StageEnvelope},
	{"DATA", StageData},
}

// stageOf returns the stage at which an SMTP delivery failed.
func stageOf(err error) string {
	switch {
	case errors.Is(err, ErrAddressDenied):
		return StageConnect
	case errors.Is(err, mail.ErrInvalidSettings), errors.Is(err, mail.ErrInvalidMessage),
		errors.Is(err, mail.ErrInvalidAddress):
		return StageSettings
	case errors.Is(err, mail.ErrStartTLSUnavailable):
		return StageStartTLS
	case errors.Is(err, mail.ErrAuthUnavailable), errors.Is(err, mail.ErrAuthFailed):
		return StageAuth
	}
	msg := err.Error()
	for _, m := range stageMarkers {
		if strings.Contains(msg, m.marker) {
			return m.stage
		}
	}
	return StageUnknown
}

// Messages of a failure at the connect stage of an SMTP test.
const (
	connectDenied = "the server address is in a denied network (TT_SMTP_DENY_NETWORKS)"
	connectFailed = "could not connect to the server"
)

// testError returns the error reported by an SMTP test failing at stage.
// A connect failure only gets a generic message: the resolved addresses
// and the OS error would let an administrator probe the network of the
// instance. Later stages report the sanitized server replies.
func testError(stage string, err error, st mail.Settings) string {
	if stage == StageConnect {
		if errors.Is(err, ErrAddressDenied) {
			return connectDenied
		}
		return connectFailed
	}
	return sanitizeReply(err.Error(), st)
}

// minRedactedUsername is the shortest username redacted from the server
// replies: a shorter one would garble the reply without hiding anything.
const minRedactedUsername = 3

// sanitizeReply removes the credentials of st (in clear and as an AUTH
// PLAIN response) and the control characters from msg, and truncates it.
func sanitizeReply(msg string, st mail.Settings) string {
	var pairs []string
	if st.Password != "" {
		plain := base64.StdEncoding.EncodeToString([]byte("\x00" + st.Username + "\x00" + st.Password))
		pairs = append(pairs, plain, redacted, st.Password, redacted)
	}
	if utf8.RuneCountInString(st.Username) >= minRedactedUsername {
		pairs = append(pairs, st.Username, redacted)
	}
	msg = strings.NewReplacer(pairs...).Replace(strings.ToValidUTF8(msg, "?"))
	msg = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return ' '
		}
		return r
	}, msg)
	if r := []rune(msg); len(r) > maxReplyLen {
		msg = string(r[:maxReplyLen]) + "..."
	}
	return msg
}
