package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultTimeout bounds a whole SMTP delivery (dial, TLS, exchange) when
// [SMTPOptions.Timeout] is zero (TT_SMTP_TIMEOUT, CLAUDE.md threat T-89).
const DefaultTimeout = 30 * time.Second

// defaultHelloName is the EHLO name used when none is configured.
const defaultHelloName = "localhost"

// Sender delivers one message with the given settings.
type Sender interface {
	// Send delivers msg using s. It honors ctx cancellation and deadline.
	Send(ctx context.Context, s Settings, msg Message) error
}

// SMTPOptions configures an [SMTPSender].
type SMTPOptions struct {
	// Timeout bounds each delivery; zero means DefaultTimeout.
	Timeout time.Duration
	// HelloName is the name sent with EHLO; empty means "localhost". Some
	// servers and relays reject or penalize "localhost" (spam scoring,
	// RFC 5321 section 4.1.1.1 asks for the client's FQDN): set it to the
	// public host name of the instance, for example
	// "transfer.entity-a.example.com". It must be a plain host name: it is
	// written on the SMTP command line as is.
	HelloName string
	// RootCAs overrides the system roots used to verify the server
	// certificate (tests, private CA). Nil means the system roots.
	RootCAs *x509.CertPool
}

// SMTPSender is the SMTP implementation of [Sender], built on net/smtp.
//
// Modes (see [Security]): "none" is plain TCP without AUTH, for an internal
// relay only; "starttls" requires the server to offer STARTTLS and fails
// otherwise; "tls" is implicit TLS. TLS uses at least TLS 1.2 and checks the
// certificate against Settings.Host. AUTH PLAIN is used only when a Username
// is set, which [Settings.Validate] only allows with TLS; net/smtp also
// refuses PLAIN over a clear connection to anything but localhost, and that
// guard is kept.
//
// Errors wrap [ErrSMTP], [ErrStartTLSUnavailable], [ErrAuthUnavailable],
// [ErrAuthFailed] or the validation errors, and never contain the password.
// An SMTPSender is safe for concurrent use.
type SMTPSender struct {
	timeout   time.Duration
	helloName string
	rootCAs   *x509.CertPool
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSMTPSender returns an SMTP sender.
func NewSMTPSender(opts SMTPOptions) *SMTPSender {
	s := &SMTPSender{
		timeout:   opts.Timeout,
		helloName: opts.HelloName,
		rootCAs:   opts.RootCAs,
		dial:      (&net.Dialer{}).DialContext,
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	if s.helloName == "" {
		s.helloName = defaultHelloName
	}
	return s
}

// Send implements [Sender]. The message is built and validated before any
// connection is opened.
func (s *SMTPSender) Send(ctx context.Context, settings Settings, msg Message) error {
	data, err := Build(settings, msg)
	if err != nil {
		return err
	}
	to, _ := msg.validate()                       // validated by Build
	from, _ := ParseAddress(settings.FromAddress) // validated by Build

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	err = s.deliver(ctx, settings, from, to, data)
	if err == nil {
		return nil
	}
	return scrub(withContextError(ctx, err), settings)
}

// deliver runs the SMTP exchange.
func (s *SMTPSender) deliver(ctx context.Context, st Settings, from string, to []string, data []byte) error {
	addr := net.JoinHostPort(st.Host, strconv.Itoa(st.Port))
	conn, err := s.dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("%w: connect: %w", ErrSMTP, err)
	}
	defer func() { _ = conn.Close() }()

	// One deadline covers every read and write; canceling ctx moves it to
	// the past, which aborts any blocked I/O at once.
	deadline, _ := ctx.Deadline() // always set by Send
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	tlsConfig := &tls.Config{
		ServerName: st.Host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.rootCAs,
	}
	if st.Security == SecurityTLS {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("%w: TLS handshake: %w", ErrSMTP, err)
		}
		conn = tlsConn
	}

	c, err := smtp.NewClient(conn, st.Host)
	if err != nil {
		return fmt.Errorf("%w: greeting: %w", ErrSMTP, err)
	}
	if err := c.Hello(s.helloName); err != nil {
		return fmt.Errorf("%w: EHLO: %w", ErrSMTP, err)
	}
	if st.Security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return ErrStartTLSUnavailable
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("%w: STARTTLS: %w", ErrSMTP, err)
		}
	}
	if st.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return ErrAuthUnavailable
		}
		if err := c.Auth(smtp.PlainAuth("", st.Username, st.Password, st.Host)); err != nil {
			// The server text is dropped: a hostile server could echo the
			// credentials back. Only the reply code is kept.
			return fmt.Errorf("%w%s", ErrAuthFailed, replyCode(err))
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("%w: MAIL FROM: %w", ErrSMTP, err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("%w: RCPT TO: %w", ErrSMTP, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("%w: DATA: %w", ErrSMTP, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("%w: DATA: %w", ErrSMTP, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: end of DATA: %w", ErrSMTP, err)
	}
	// The message is accepted once DATA is acknowledged: a failed QUIT is
	// not a delivery failure.
	_ = c.Quit()
	return nil
}

// withContextError makes timeouts consistent for callers: the error matches
// context.Canceled or context.DeadlineExceeded whenever the delivery was cut
// short by ctx or by the timeout. The connection deadline equals the context
// deadline, so an I/O timeout (os.ErrDeadlineExceeded) can fire a moment
// before ctx reports it is done; such a timeout always comes from that
// shared deadline and is mapped to context.DeadlineExceeded.
func withContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(err, ctxErr) {
			return err
		}
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w: %w", context.DeadlineExceeded, err)
	}
	return err
}

// replyCode returns " (code NNN)" when err is an SMTP reply, else "".
func replyCode(err error) string {
	var te *textproto.Error
	if errors.As(err, &te) {
		return " (code " + strconv.Itoa(te.Code) + ")"
	}
	return ""
}

// scrubbedError is an error whose text had the password removed. It keeps
// the sentinel errors of the original chain reachable through errors.Is.
type scrubbedError struct {
	msg       string
	sentinels []error
}

// Error implements error.
func (e *scrubbedError) Error() string { return e.msg }

// Unwrap exposes the sentinels found in the original chain.
func (e *scrubbedError) Unwrap() []error { return e.sentinels }

// scrub guarantees that the password, in clear or inside the base64 AUTH
// PLAIN response, never appears in a returned error, whatever a server or a
// lower layer put in it.
func scrub(err error, st Settings) error {
	if st.Password == "" {
		return err
	}
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + st.Username + "\x00" + st.Password))
	msg := err.Error()
	if !strings.Contains(msg, st.Password) && !strings.Contains(msg, plain) {
		return err
	}
	msg = strings.NewReplacer(plain, redacted, st.Password, redacted).Replace(msg)
	var sentinels []error
	for _, s := range []error{
		ErrSMTP, ErrAuthFailed, ErrAuthUnavailable, ErrStartTLSUnavailable,
		context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, s) {
			sentinels = append(sentinels, s)
		}
	}
	return &scrubbedError{msg: msg, sentinels: sentinels}
}
