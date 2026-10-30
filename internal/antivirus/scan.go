package antivirus

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/textsafe"
)

// Scan defaults, used when the matching option is not given.
const (
	// DefaultMaxScanBytes is the largest size sent to the antivirus engine
	// (2 GiB, the practical limit of clamd).
	DefaultMaxScanBytes int64 = 2 << 30
	// DefaultScanTimeout bounds a whole scan exchange (INSTREAM for clamd,
	// RESPMOD for ICAP).
	DefaultScanTimeout = 10 * time.Minute
	// DefaultIdleTimeout bounds each write to the engine: a stream that stops
	// progressing for that long is cut, whatever the overall timeout.
	DefaultIdleTimeout = time.Minute
)

// Protocol constants.
const (
	// chunkSize is the payload size of one INSTREAM chunk.
	chunkSize = 64 << 10
	// maxScanReplyLen bounds the size of an INSTREAM reply.
	maxScanReplyLen = 4 << 10
	// MaxSignatureLen bounds the length in bytes of Result.Signature.
	MaxSignatureLen = 200
	// earlyReplyWait bounds the wait for a reply clamd may have sent before
	// closing the connection in the middle of a stream.
	earlyReplyWait = time.Second
)

var (
	instreamCommand = []byte("zINSTREAM\x00")
	endOfStream     = []byte{0, 0, 0, 0}

	streamPrefix   = "stream: "
	okReply        = "stream: OK"
	foundSuffix    = " FOUND"
	sizeLimitReply = "INSTREAM size limit exceeded. ERROR"
	// limitsPrefix and encryptedPrefix start the heuristic signatures clamd
	// reports, with AlertExceedsMax and AlertEncryptedArchive, for content
	// it could not analyze completely.
	limitsPrefix    = "Heuristics.Limits.Exceeded"
	encryptedPrefix = "Heuristics.Encrypted"
	aLongTimeAgo    = time.Unix(1, 0)
	errClosedNoData = fmt.Errorf("%w: connection closed without reply", ErrProtocol)
)

// Error classes returned by the Scan method of every engine. Every error
// wraps exactly one of them.
var (
	// ErrUnavailable means the antivirus engine could not be reached or did
	// not complete the exchange: dial failure, connection reset or closed
	// before the reply, engine reporting itself overloaded (ICAP 503), or
	// cancellation. The file was not analyzed and the scan should
	// be retried later; the file must stay unavailable meanwhile
	// (fail-closed, decision P10). When the connection was lost after a
	// successful dial, the error also wraps ErrConnectionLost: the engine
	// may have crashed on this very content, which the caller can tell apart
	// with a Ping. When the caller's context is done, the error also wraps
	// its error (context.Canceled or context.DeadlineExceeded).
	ErrUnavailable = errors.New("antivirus: engine unavailable")
	// ErrTimeout means the engine accepted the connection but did not
	// complete the exchange in time: the scan timeout fired, or the engine
	// stopped reading the stream for longer than the idle timeout, while
	// the caller's context was still live. It is specific to the content (a
	// file that blocks the engine) and counts toward the scan_error status.
	ErrTimeout = errors.New("antivirus: engine did not complete the analysis in time")
	// ErrProtocol means the engine answered something unexpected, which is
	// never taken for a clean verdict (fail-closed, decision P44). It is
	// specific to the exchange and counts toward the scan_error status.
	ErrProtocol = errors.New("antivirus: unexpected engine reply")
	// ErrSource means the content to analyze could not be read, or did not
	// have the declared size. It also counts toward the scan_error status.
	ErrSource = errors.New("antivirus: cannot read the content to scan")
)

// ErrConnectionLost is wrapped, together with ErrUnavailable, by the
// errors of Scan that happen after a successful dial (connection reset or
// closed in the middle of the stream or before the reply).
var ErrConnectionLost = errors.New("antivirus: connection to the engine lost during the exchange")

// ErrUnexpectedReply is returned by Ping when the engine answers something
// unexpected. It is the same error as ErrProtocol.
var ErrUnexpectedReply = ErrProtocol

// Verdict is the outcome of a completed analysis. The zero value is not a
// valid verdict, so that an unset Result is never taken for Clean.
type Verdict int

// Verdicts.
const (
	// Clean means the engine found nothing.
	Clean Verdict = iota + 1
	// Infected means the engine found a signature, given in
	// Result.Signature.
	Infected
	// TooLarge means the content was not analyzed, or not completely,
	// because of its size: above the client limit (never sent to any
	// engine), refused by clamd (StreamMaxLength), or with parts skipped past clamd's archive
	// limits (Heuristics.Limits.Exceeded.*). Result.Detail tells which.
	TooLarge
	// Unscannable means clamd could not look inside the content: an
	// encrypted archive (Heuristics.Encrypted.*).
	Unscannable
)

// Details of a TooLarge result that do not come from a heuristic signature.
const (
	// DetailClientLimit means the content is above the client limit
	// (WithMaxScanBytes, WithICAPMaxScanBytes) and was never sent to the
	// engine.
	DetailClientLimit = "client limit"
	// DetailStreamLimit means clamd refused the stream as larger than its
	// StreamMaxLength: the clamd limits are below the client limit and
	// should be aligned on it.
	DetailStreamLimit = "clamd StreamMaxLength"
)

// String returns a lowercase name for logs.
func (v Verdict) String() string {
	switch v {
	case Clean:
		return "clean"
	case Infected:
		return "infected"
	case TooLarge:
		return "too_large"
	case Unscannable:
		return "unscannable"
	default:
		return fmt.Sprintf("verdict(%d)", int(v))
	}
}

// Result is the outcome of the Scan method of every engine.
type Result struct {
	Verdict Verdict
	// Signature is the name of the detected signature when Verdict is
	// Infected, empty otherwise. It is valid UTF-8, contains no control or
	// hidden character and is at most MaxSignatureLen bytes long, but it
	// comes from the engine and must still be escaped when displayed.
	Signature string
	// Detail tells why the content was not fully analyzed when Verdict is
	// TooLarge or Unscannable: DetailClientLimit, DetailStreamLimit, or the
	// heuristic signature clamd reported (sanitized like Signature). It is
	// empty otherwise.
	Detail string
}

// WithMaxScanBytes sets the largest size Scan sends to clamd; larger
// contents are reported TooLarge without contacting clamd. Non-positive
// values are ignored.
func WithMaxScanBytes(n int64) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxScanBytes = n
		}
	}
}

// WithScanTimeout sets the maximum duration of a whole INSTREAM exchange,
// from the dial to the reply. Non-positive values are ignored.
func WithScanTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.scanTimeout = d
		}
	}
}

// WithIdleTimeout sets the maximum duration of each write to clamd during
// a scan, so that a stalled stream is cut long before the scan timeout.
// Non-positive values are ignored.
func WithIdleTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.idleTimeout = d
		}
	}
}

// Scan analyzes the size bytes read from r with the clamd INSTREAM command.
//
// A content larger than the client limit (WithMaxScanBytes) is reported
// TooLarge without contacting clamd. Otherwise r is streamed in chunks of
// 64 KiB; r must yield exactly size bytes, so that what is analyzed is what
// will be served (threat T-44). The exchange is bounded by ctx, by the scan
// timeout and, for each write, by the idle timeout.
//
// A non-nil error wraps ErrUnavailable, ErrTimeout, ErrProtocol or
// ErrSource.
func (c *Client) Scan(ctx context.Context, r io.Reader, size int64) (Result, error) {
	if size < 0 {
		return Result{}, fmt.Errorf("%w: negative size %d", ErrSource, size)
	}
	if size > c.maxScanBytes {
		return Result{Verdict: TooLarge, Detail: DetailClientLimit}, nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, c.scanTimeout)
	defer cancel()

	conn, err := c.dial(ctx, c.network, c.address)
	if err != nil {
		return Result{}, unavailable(parent, "dial", err)
	}
	defer func() { _ = conn.Close() }()
	sc := &scanConn{conn: conn}
	stop := context.AfterFunc(ctx, sc.expire)
	defer stop()
	overall, _ := ctx.Deadline()

	if err := c.send(sc, r, size, overall); err != nil {
		if errors.Is(err, ErrSource) {
			return Result{}, err
		}
		// clamd answers and closes the connection when the stream exceeds
		// its StreamMaxLength. Only that reply is accepted here: a verdict
		// on a partial stream would analyze less than what is stored.
		deadline := time.Now().Add(earlyReplyWait)
		if res, rerr := sc.result(earliest(deadline, overall)); rerr == nil && res.Verdict == TooLarge {
			return res, nil
		}
		return Result{}, exchangeError(parent, ctx, "write", err)
	}
	res, err := sc.result(overall)
	if err != nil && !errors.Is(err, ErrProtocol) {
		return Result{}, exchangeError(parent, ctx, "read", err)
	}
	return res, err
}

// exchangeError classifies a failure after a successful dial: a timeout
// while the caller's context is live is ErrTimeout; anything else is
// ErrUnavailable with ErrConnectionLost (or with the caller's context error
// when it is done).
func exchangeError(parent, ctx context.Context, op string, err error) error {
	if parent.Err() != nil || parentExpired(parent) {
		return unavailable(parent, op, err)
	}
	if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w: %s: %w", ErrTimeout, op, err)
	}
	return fmt.Errorf("%w: %w: %s: %w", ErrUnavailable, ErrConnectionLost, op, err)
}

// send writes the INSTREAM command, the chunks and the end-of-stream marker.
func (c *Client) send(sc *scanConn, r io.Reader, size int64, overall time.Time) error {
	if err := sc.write(instreamCommand, c.idleTimeout, overall); err != nil {
		return err
	}
	buf := make([]byte, 4+chunkSize)
	for remaining := size; remaining > 0; {
		n := int(min(remaining, chunkSize))
		if _, err := io.ReadFull(r, buf[4:4+n]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: content shorter than its declared size %d", ErrSource, size)
			}
			return fmt.Errorf("%w: %w", ErrSource, err)
		}
		binary.BigEndian.PutUint32(buf, uint32(n))
		if err := sc.write(buf[:4+n], c.idleTimeout, overall); err != nil {
			return err
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	switch _, err := io.ReadFull(r, extra[:]); {
	case err == nil:
		return fmt.Errorf("%w: content longer than its declared size %d", ErrSource, size)
	case !errors.Is(err, io.EOF):
		return fmt.Errorf("%w: %w", ErrSource, err)
	}
	return sc.write(endOfStream, c.idleTimeout, overall)
}

// unavailable wraps err in ErrUnavailable, adding the error of the caller's
// context when it is done (or its deadline passed, which the connection
// deadline may notice before the context does).
func unavailable(parent context.Context, op string, err error) error {
	cerr := parent.Err()
	if cerr == nil && parentExpired(parent) {
		cerr = context.DeadlineExceeded
	}
	if cerr != nil {
		return fmt.Errorf("%w: %s: %w (%w)", ErrUnavailable, op, err, cerr)
	}
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, op, err)
}

// parentExpired reports whether the deadline of the caller's context has
// passed.
func parentExpired(parent context.Context) bool {
	d, ok := parent.Deadline()
	return ok && !time.Now().Before(d)
}

// scanConn serializes deadline updates with the expiry of the exchange
// context, so that a deadline set after the expiry never revives the
// connection.
type scanConn struct {
	mu      sync.Mutex
	conn    net.Conn
	expired bool
}

// expire cuts any pending and future I/O.
func (s *scanConn) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expired = true
	_ = s.conn.SetDeadline(aLongTimeAgo)
}

// setDeadline sets the read and write deadline, unless the exchange expired.
func (s *scanConn) setDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expired {
		t = aLongTimeAgo
	}
	return s.conn.SetDeadline(t)
}

// write writes p within the idle timeout, capped by the overall deadline.
func (s *scanConn) write(p []byte, idle time.Duration, overall time.Time) error {
	if err := s.setDeadline(earliest(time.Now().Add(idle), overall)); err != nil {
		return err
	}
	_, err := s.conn.Write(p)
	return err
}

// result reads and parses the INSTREAM reply before deadline. Errors that
// do not wrap ErrProtocol mean clamd is unavailable.
func (s *scanConn) result(deadline time.Time) (Result, error) {
	if err := s.setDeadline(deadline); err != nil {
		return Result{}, err
	}
	reply, err := readReply(s.conn, maxScanReplyLen)
	if errors.Is(err, errClosedNoData) {
		return Result{}, io.EOF
	}
	if err != nil {
		return Result{}, err
	}
	return parseScanReply(reply)
}

// parseScanReply maps an INSTREAM reply (without its terminator) to a
// Result.
func parseScanReply(reply []byte) (Result, error) {
	s := string(reply)
	switch {
	case s == okReply:
		return Result{Verdict: Clean}, nil
	case s == sizeLimitReply:
		return Result{Verdict: TooLarge, Detail: DetailStreamLimit}, nil
	case strings.HasPrefix(s, streamPrefix) && strings.HasSuffix(s, foundSuffix):
		sig := sanitizeSignature(s[len(streamPrefix) : len(s)-len(foundSuffix)])
		switch {
		case sig == "":
			return Result{}, fmt.Errorf("%w: detection without signature", ErrProtocol)
		case strings.HasPrefix(sig, limitsPrefix):
			return Result{Verdict: TooLarge, Detail: sig}, nil
		case strings.HasPrefix(sig, encryptedPrefix):
			return Result{Verdict: Unscannable, Detail: sig}, nil
		}
		return Result{Verdict: Infected, Signature: sig}, nil
	default:
		return Result{}, fmt.Errorf("%w to INSTREAM (%d bytes)", ErrProtocol, len(reply))
	}
}

// sanitizeSignature makes a signature name safe to store and log: invalid
// UTF-8 replaced, control and hidden characters removed, surrounding spaces
// trimmed and length bounded to MaxSignatureLen bytes on a rune boundary.
func sanitizeSignature(s string) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	s = strings.Map(func(r rune) rune {
		if textsafe.IsControl(r) || textsafe.IsHidden(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= MaxSignatureLen {
		return s
	}
	cut := MaxSignatureLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

// earliest returns the earlier of a and b.
func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
