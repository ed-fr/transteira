// Package syslog exports the audit and security logs of TransTeira to a
// remote syslog server, typically a SIEM (CLAUDE.md section 19, threat
// model T-187 to T-190 and decision P41).
//
// The [Exporter] subscribes to the log.audit and log.security events of the
// event bus and sends every enabled line as one RFC 5424 message:
//
//	<PRI>1 TIMESTAMP HOSTNAME transteira PROCID MSGID [transteira@32473 stream="…" tenant="…" …] MSG
//
// The message is built by code, never by free concatenation: the
// structured data values escape `"`, `\` and `]`, and every control or
// invisible character (C0, DEL, C1, U+2028, U+2029, bidi controls...) is
// written in a visible backslash form, as in the security log (P22), so
// that one event always gives one message. Over TCP and TLS the messages
// are framed by octet counting (RFC 6587), which makes any line feed
// harmless; over UDP each message is one datagram of at most MaxDatagram
// bytes, shortened without ever cutting a structured data value.
//
// The export never blocks the application: the bus queue of the
// subscriber is the bounded buffer, the connection is opened lazily and
// reopened with an exponential backoff, and the messages that cannot be
// sent meanwhile are dropped, counted ([Exporter.Dropped]) and reported in
// the local application log at most once per minute. The local logs stay
// the reference and never depend on this export.
package syslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/events"
)

// Transport protocols (Options.Protocol).
const (
	// ProtocolUDP sends one datagram per message, in clear text, without
	// any delivery guarantee: for a trusted internal network only.
	ProtocolUDP = "udp"
	// ProtocolTCP sends octet-counted messages over TCP, in clear text:
	// for a trusted internal network only.
	ProtocolTCP = "tcp"
	// ProtocolTLS sends octet-counted messages over TLS 1.2 or later, the
	// server certificate being always verified (P41).
	ProtocolTLS = "tls"
)

// Defaults.
const (
	// SubscriberName is the name of the exporter on the event bus.
	SubscriberName = "syslog"
	// DefaultPortUDP and DefaultPortTCP are the ports used when
	// Options.Addr has none, for udp and tcp (RFC 5426, RFC 6587).
	DefaultPortUDP = "514"
	DefaultPortTCP = "514"
	// DefaultPortTLS is the port used when Options.Addr has none, for tls
	// (RFC 5425).
	DefaultPortTLS = "6514"
	// DefaultTimeout bounds every connection attempt and every write.
	DefaultTimeout = 5 * time.Second
	// DefaultMinBackoff is the delay before the first reconnection
	// attempt after a failure; it doubles at each new failure. A message
	// whose sending fails, even after the retry on a new connection, counts
	// one failure.
	DefaultMinBackoff = time.Second
	// DefaultMaxBackoff caps the reconnection delay.
	DefaultMaxBackoff = time.Minute
	// DefaultWarnInterval is the shortest delay between two warnings of
	// the local log about the failures and the dropped messages.
	DefaultWarnInterval = time.Minute
	// MaxDatagram is the largest UDP message sent, in bytes (RFC 5426
	// recommends that receivers accept 2048 bytes): a longer message loses
	// the end of its MSG part first, then whole structured data parameters
	// from the end, stream, tenant, action and ip last.
	MaxDatagram = 2048
	// MaxHostnameLen is the maximum length of the HOSTNAME field.
	MaxHostnameLen = 255
	// MaxValueLen is the maximum number of input bytes kept from a
	// structured data value, before escaping.
	MaxValueLen = 256
	// SDID is the identifier of the structured data element. 32473 is the
	// private enterprise number reserved for documentation (RFC 5612).
	SDID = "transteira@32473"
	// AppName is the APP-NAME field.
	AppName = "transteira"
)

// Severities of the messages (RFC 5424 section 6.2.1).
const (
	severityWarning = 4 // security lines
	severityNotice  = 5 // audit lines
)

// Header field limits (RFC 5424 section 6).
const (
	maxMsgIDLen  = 32
	maxSDNameLen = 32
	maxFacility  = 23
)

var (
	// ErrInvalidOptions is returned by [New] for invalid options.
	ErrInvalidOptions = errors.New("syslog: invalid options")
	// ErrClosed reports a use of a closed exporter.
	ErrClosed = errors.New("syslog: exporter closed")
	// errBackoff reports a message dropped while waiting before the next
	// reconnection attempt.
	errBackoff = errors.New("syslog: waiting before the next reconnection attempt")
)

// osHostname returns the host name of the machine (a variable for the
// tests).
var osHostname = os.Hostname

// Options configure an [Exporter].
type Options struct {
	// Addr is the server address, "host:port" or "host" (the default port
	// of the protocol is then used). Required.
	Addr string
	// Protocol is ProtocolUDP, ProtocolTCP or ProtocolTLS (the default
	// when empty).
	Protocol string
	// Streams are the logs exported: "audit" and/or "security". At least
	// one is required.
	Streams []string
	// Facility is the syslog facility, from 0 to 23 (16 for local0).
	Facility int
	// CAFile is the PEM file of the certificate authorities trusted for
	// the tls protocol; empty for the system roots. The verification of
	// the server certificate can never be disabled.
	CAFile string
	// Hostname is the HOSTNAME field (os.Hostname when empty), reduced to
	// printable US-ASCII and MaxHostnameLen bytes.
	Hostname string
	// Logger receives the warnings about the failures and the dropped
	// messages, never their contents (discarded when nil).
	Logger *slog.Logger
	// Now is the clock of the backoff and of the warnings (time.Now).
	Now func() time.Time
	// Dial opens the network connection (a net.Dialer when nil); the TLS
	// handshake is made on top of it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds every connection attempt and write (DefaultTimeout).
	Timeout time.Duration
	// MinBackoff and MaxBackoff bound the reconnection delay
	// (DefaultMinBackoff, DefaultMaxBackoff).
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// WarnInterval is the shortest delay between two warnings
	// (DefaultWarnInterval).
	WarnInterval time.Duration
	// Buffer is the length of the bus queue of the exporter
	// (events.DefaultBuffer when 0 or less).
	Buffer int
}

// Exporter sends the audit and security log lines to a syslog server. Its
// methods are safe for concurrent use.
type Exporter struct {
	network      string
	addr         string
	tlsConfig    *tls.Config
	streams      map[events.Stream]bool
	format       formatter
	logger       *slog.Logger
	now          func() time.Time
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout      time.Duration
	minBackoff   time.Duration
	maxBackoff   time.Duration
	warnInterval time.Duration
	buffer       int

	// sem guards the connection state below; it is a channel rather than
	// a mutex so that Close can give up when its context is done.
	sem         chan struct{}
	conn        net.Conn
	closed      bool
	failures    int
	nextAttempt time.Time
	lastWarn    time.Time

	sent    atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64
}

// New validates opts and returns an exporter, which connects to the server
// only when it has a first message to send. It returns an error wrapping
// ErrInvalidOptions for an empty or malformed address, an unknown protocol
// or stream, no stream, a facility outside 0 to 23 or a CA file that
// cannot be read or holds no certificate.
func New(opts Options) (*Exporter, error) {
	e := &Exporter{
		streams: map[events.Stream]bool{}, logger: opts.Logger, now: opts.Now, dial: opts.Dial,
		timeout: opts.Timeout, minBackoff: opts.MinBackoff, maxBackoff: opts.MaxBackoff,
		warnInterval: opts.WarnInterval, buffer: opts.Buffer, sem: make(chan struct{}, 1),
	}
	protocol := opts.Protocol
	if protocol == "" {
		protocol = ProtocolTLS
	}
	var port string
	switch protocol {
	case ProtocolUDP:
		e.network, port = "udp", DefaultPortUDP
	case ProtocolTCP:
		e.network, port = "tcp", DefaultPortTCP
	case ProtocolTLS:
		e.network, port = "tcp", DefaultPortTLS
	default:
		return nil, fmt.Errorf("%w: unknown protocol %q (udp, tcp or tls)", ErrInvalidOptions, opts.Protocol)
	}
	host, addr, err := normalizeAddr(opts.Addr, port)
	if err != nil {
		return nil, err
	}
	e.addr = addr
	if len(opts.Streams) == 0 {
		return nil, fmt.Errorf("%w: no stream (audit, security)", ErrInvalidOptions)
	}
	for _, s := range opts.Streams {
		switch st := events.Stream(s); st {
		case events.StreamAudit, events.StreamSecurity:
			e.streams[st] = true
		default:
			return nil, fmt.Errorf("%w: unknown stream %q (audit, security)", ErrInvalidOptions, s)
		}
	}
	if opts.Facility < 0 || opts.Facility > maxFacility {
		return nil, fmt.Errorf("%w: facility %d outside 0 to %d", ErrInvalidOptions, opts.Facility, maxFacility)
	}
	if protocol == ProtocolTLS {
		if e.tlsConfig, err = tlsConfig(host, opts.CAFile); err != nil {
			return nil, err
		}
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = osHostname() // "" on error, written as "-"
	}
	e.format = formatter{facility: opts.Facility, hostname: sanitizeHostname(hostname), procID: strconv.Itoa(os.Getpid())}
	if protocol == ProtocolUDP {
		e.format.maxLen = MaxDatagram
	}
	e.setDefaults()
	return e, nil
}

// setDefaults fills the optional settings left empty.
func (e *Exporter) setDefaults() {
	if e.logger == nil {
		e.logger = slog.New(slog.DiscardHandler)
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.dial == nil {
		e.dial = (&net.Dialer{}).DialContext
	}
	if e.timeout <= 0 {
		e.timeout = DefaultTimeout
	}
	if e.minBackoff <= 0 {
		e.minBackoff = DefaultMinBackoff
	}
	if e.maxBackoff < e.minBackoff {
		e.maxBackoff = max(DefaultMaxBackoff, e.minBackoff)
	}
	if e.warnInterval <= 0 {
		e.warnInterval = DefaultWarnInterval
	}
}

// normalizeAddr returns the host of addr and addr with port added when it
// has none.
func normalizeAddr(addr, port string) (host, hostPort string, err error) {
	if addr == "" {
		return "", "", fmt.Errorf("%w: empty address", ErrInvalidOptions)
	}
	host, p, err := net.SplitHostPort(addr)
	hostPort = addr
	if err != nil { // no port: the default one is added
		host = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
		p, hostPort = port, net.JoinHostPort(host, port)
	}
	if host == "" || p == "" || strings.ContainsAny(host, "[]/ ") {
		return "", "", fmt.Errorf("%w: malformed address %q (host or host:port)", ErrInvalidOptions, addr)
	}
	return host, hostPort, nil
}

// tlsConfig returns the TLS configuration for the server host, trusting
// the authorities of caFile (the system roots when empty).
func tlsConfig(host, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile) // #nosec G304 -- path set by the operator
	if err != nil {
		return nil, fmt.Errorf("%w: CA file: %w", ErrInvalidOptions, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: CA file %q holds no PEM certificate", ErrInvalidOptions, caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// sanitizeHostname keeps the printable US-ASCII bytes of h, at most
// MaxHostnameLen of them; "-" (the nil value) when none is left.
func sanitizeHostname(h string) string {
	b := make([]byte, 0, min(len(h), MaxHostnameLen))
	for i := 0; i < len(h) && len(b) < MaxHostnameLen; i++ {
		if isPrintASCII(h[i]) {
			b = append(b, h[i])
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}

// Register subscribes the exporter to the bus, for the log events of its
// enabled streams. It must be called before bus.Start and returns the
// error of [events.Bus.Subscribe].
func (e *Exporter) Register(bus *events.Bus) error {
	if bus == nil {
		return fmt.Errorf("%w: nil bus", ErrInvalidOptions)
	}
	return bus.Subscribe(SubscriberName, e.accepts, e.buffer, e.handle)
}

// accepts reports whether the event type t is a log event of an enabled
// stream.
func (e *Exporter) accepts(t events.Type) bool {
	switch t {
	case events.LogAudit:
		return e.streams[events.StreamAudit]
	case events.LogSecurity:
		return e.streams[events.StreamSecurity]
	}
	return false
}

// handle sends the log line of ev, or drops and counts it when it cannot
// be sent now. The bus calls it sequentially.
func (e *Exporter) handle(ctx context.Context, ev events.Event) {
	rec := ev.Log
	if rec == nil || !e.streams[rec.Stream] {
		return
	}
	msg := e.frame(e.format.format(rec, ev.OccurredAt))
	e.sem <- struct{}{}
	defer func() { <-e.sem }()
	if err := e.send(ctx, msg); err != nil {
		e.dropped.Add(1)
		e.warn(ctx, err)
		return
	}
	e.sent.Add(1)
}

// send writes msg, connecting first when needed. A write failing on a
// connection kept from a previous message (closed by the server meanwhile)
// is retried at once on a new connection. One failed sending counts one
// failure, whatever the number of attempts: the backoff then starts at its
// minimum. The caller holds sem.
func (e *Exporter) send(ctx context.Context, msg []byte) error {
	switch {
	case e.closed:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	}
	reused := e.conn != nil
	err := e.connect(ctx, false)
	if errors.Is(err, errBackoff) {
		return err
	}
	if err == nil {
		err = e.write(ctx, msg)
		if err != nil && reused {
			if err = e.connect(ctx, true); err == nil {
				err = e.write(ctx, msg)
			}
		}
	}
	if err != nil {
		e.fail()
		return err
	}
	e.failures = 0
	return nil
}

// connect opens the connection when there is none, unless the backoff
// delay is still running and force is false (errBackoff). The caller
// counts the failure.
func (e *Exporter) connect(ctx context.Context, force bool) error {
	if e.conn != nil {
		return nil
	}
	if !force && e.now().Before(e.nextAttempt) {
		return errBackoff
	}
	conn, err := e.open(ctx)
	if err != nil {
		return err
	}
	e.conn = conn
	return nil
}

// open dials the server and, for tls, makes the handshake, within the
// timeout.
func (e *Exporter) open(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	conn, err := e.dial(ctx, e.network, e.addr)
	if err != nil {
		return nil, err
	}
	if e.tlsConfig == nil {
		return conn, nil
	}
	tc := tls.Client(conn, e.tlsConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

// write writes msg on the connection within the timeout, aborted when ctx
// is canceled. On failure the connection is closed; the caller counts the
// failure.
func (e *Exporter) write(ctx context.Context, msg []byte) error {
	conn := e.conn
	// Deadlines are wall-clock times: never derived from the test clock.
	_ = conn.SetWriteDeadline(time.Now().Add(e.timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Unix(1, 0)) })
	_, err := conn.Write(msg)
	stop()
	if err != nil {
		_ = conn.Close()
		e.conn = nil
	}
	return err
}

// fail counts a failed sending and delays the next connection attempt by
// the exponential backoff: MinBackoff after the first failure, doubling at
// each new one up to MaxBackoff.
func (e *Exporter) fail() {
	e.failed.Add(1)
	e.failures++
	d := e.minBackoff
	for i := 1; i < e.failures && d < e.maxBackoff; i++ {
		d *= 2
	}
	e.nextAttempt = e.now().Add(min(d, e.maxBackoff))
}

// warn logs, at most once per warning interval, that messages are being
// dropped, with the reason and the counters; never a message content. The
// caller holds sem.
func (e *Exporter) warn(ctx context.Context, reason error) {
	now := e.now()
	if !e.lastWarn.IsZero() && now.Sub(e.lastWarn) < e.warnInterval {
		return
	}
	e.lastWarn = now
	e.logger.WarnContext(ctx, "syslog: export failing, messages dropped",
		slog.String("addr", e.addr), slog.String("error", reason.Error()),
		slog.Uint64("dropped_total", e.dropped.Load()), slog.Uint64("failed_total", e.failed.Load()))
}

// frame returns msg ready for the transport: unchanged for udp (the
// formatter already keeps it within MaxDatagram), prefixed by its length
// (RFC 6587 octet counting) otherwise.
func (e *Exporter) frame(msg []byte) []byte {
	if e.network == "udp" {
		return msg
	}
	out := make([]byte, 0, len(msg)+8)
	out = strconv.AppendInt(out, int64(len(msg)), 10)
	out = append(out, ' ')
	return append(out, msg...)
}

// truncate keeps at most n bytes of b, cutting on a rune boundary.
func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	cut := n
	for i := 0; i < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(b[cut]); i++ {
		cut--
	}
	if !utf8.RuneStart(b[cut]) {
		cut = n // not UTF-8 there: plain byte cut
	}
	return b[:cut]
}

// Close closes the connection; the messages received afterwards are
// dropped. It waits for a message being sent, at most until ctx is done,
// and then returns ctx.Err(). Calling it more than once is harmless.
func (e *Exporter) Close(ctx context.Context) error {
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-e.sem }()
	e.closed = true
	if e.conn == nil {
		return nil
	}
	err := e.conn.Close()
	e.conn = nil
	return err
}

// Sent returns the number of messages written to the server.
func (e *Exporter) Sent() uint64 { return e.sent.Load() }

// Dropped returns the number of messages that could not be sent (server
// unreachable, backoff running, write error, exporter closed). The events
// dropped by the bus because the queue was full are counted by
// events.Bus.Dropped(SubscriberName).
func (e *Exporter) Dropped() uint64 { return e.dropped.Load() }

// Failed returns the number of failed sendings (connection or write
// errors). A message failing on a stale connection and again on the new
// one counts once; one sent after replacing a stale connection counts
// none.
func (e *Exporter) Failed() uint64 { return e.failed.Load() }
