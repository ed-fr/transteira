package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults of a zero [Policy].
const (
	// DefaultMaxAttempts is the number of attempts of a request (the first
	// one included), as in docs/api/integration.md section 5.
	DefaultMaxAttempts = 20
	// DefaultBaseDelay is the pause after the first failure; it doubles at
	// each further failure.
	DefaultBaseDelay = time.Second
	// DefaultMaxDelay caps the growing pause.
	DefaultMaxDelay = 60 * time.Second
	// DefaultMaxRetryAfter caps a Retry-After delay from the server.
	DefaultMaxRetryAfter = 10 * time.Minute
	// DefaultMaxResponseBytes caps a JSON answer decoded by [Client.JSON].
	DefaultMaxResponseBytes = 4 << 20
)

// ErrBodyNotReplayable is returned by [Client.Do] for a request with a
// body but no GetBody: it could not be sent again after a failure.
var ErrBodyNotReplayable = errors.New("request body cannot be sent again: set GetBody")

// Policy says how [Client.Do] sends one request. The zero value retries up
// to DefaultMaxAttempts times with the default delays and sends the token.
type Policy struct {
	// MaxAttempts is the number of attempts, the first one included; 0
	// means DefaultMaxAttempts, 1 disables retries (tus PATCH, whose
	// resume logic belongs to the caller).
	MaxAttempts int
	// BaseDelay, MaxDelay and MaxRetryAfter override the defaults when
	// positive.
	BaseDelay, MaxDelay, MaxRetryAfter time.Duration
	// Jitter draws each growing pause uniformly between half and all of
	// its value (not applied to a Retry-After delay).
	Jitter bool
	// Anonymous never sends the Authorization header (download links,
	// which are bearer secrets of their own).
	Anonymous bool
	// MaxResponseBytes caps the answer decoded by [Client.JSON]; 0 means
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// OnRetry, when set, is called before each pause with the attempt
	// that failed (1-based), its error and the pause.
	OnRetry func(attempt int, err error, wait time.Duration)
}

func (p Policy) attempts() int {
	if p.MaxAttempts > 0 {
		return p.MaxAttempts
	}
	return DefaultMaxAttempts
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// RequestError is a failure to get an answer (connection, TLS, timeout).
// Its message never contains the query string or a full token, unlike
// the *url.Error of net/http.
type RequestError struct {
	// Method and Path describe the request; Path is redacted.
	Method, Path string
	// Err is the underlying error (url.Error unwrapped).
	Err error
	// Temporary reports whether sending again may succeed: false for
	// certificate and TLS protocol errors and for the end of the context.
	Temporary bool
}

// Error returns "METHOD path: cause".
func (e *RequestError) Error() string {
	return e.Method + " " + e.Path + ": " + Redact(e.Err.Error())
}

// Unwrap returns the underlying error.
func (e *RequestError) Unwrap() error { return e.Err }

// IsRetryable reports whether a request that failed with err may be sent
// again as is: a temporary [*RequestError], or a [*Problem] with a status
// of 408, 429 or 5xx other than 501 and 507. 401 (including
// invalid-credentials, whose repetition locks the address out), 403, 404,
// 409, 410, 413, 507 and redirects are never retryable.
func IsRetryable(err error) bool {
	var p *Problem
	if errors.As(err, &p) {
		return p.Retryable()
	}
	var re *RequestError
	return errors.As(err, &re) && re.Temporary
}

// Delay returns the pause before the attempt that follows the failed
// attempt number attempt (1-based) with err: the Retry-After of a
// [*Problem] when present (capped by MaxRetryAfter), else BaseDelay doubled
// at each attempt, capped by MaxDelay, with the optional jitter.
func (p Policy) Delay(attempt int, err error) time.Duration {
	var prob *Problem
	if errors.As(err, &prob) && prob.RetryAfter > 0 {
		return min(prob.RetryAfter, orDefault(p.MaxRetryAfter, DefaultMaxRetryAfter))
	}
	maxDelay := orDefault(p.MaxDelay, DefaultMaxDelay)
	d := orDefault(p.BaseDelay, DefaultBaseDelay)
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	if p.Jitter {
		d = d/2 + jitter(d/2+1)
	}
	return d
}

// jitter returns a random duration in [0, n) from crypto/rand (the linter
// forbids math/rand).
func jitter(n time.Duration) time.Duration {
	var b [8]byte
	_, _ = rand.Read(b[:])                                          // never fails since Go 1.24
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(n)) //nolint:gosec // G115: n > 0, the result is below n
}

// Pause waits [Policy.Delay] for attempt and err (calling OnRetry first),
// or until ctx ends. It is for callers running their own retry loop, such
// as the tus uploader (HEAD then resume after a failed PATCH).
func (c *Client) Pause(ctx context.Context, attempt int, err error, p Policy) error {
	wait := p.Delay(attempt, err)
	if p.OnRetry != nil {
		p.OnRetry(attempt, err, wait)
	}
	return c.sleep(ctx, wait)
}

// Do sends req under policy and returns the answer when its status is 2xx;
// the caller closes its body. req must come from [Client.NewRequest] (or
// target the configured origin): another origin gives [ErrForeignOrigin]
// without any connection. A body needs GetBody ([ErrBodyNotReplayable]).
//
// Each attempt sets the User-Agent and, unless policy.Anonymous or when no
// token is configured, "Authorization: Bearer"; any Authorization set by
// the caller is dropped. Redirects are not followed. A non-2xx answer is
// returned as a [*Problem] (body read up to MaxProblemBytes, then closed),
// a failure to get an answer as a [*RequestError]. Retryable failures
// ([IsRetryable]) are retried after [Policy.Delay] until MaxAttempts; the
// last error is returned. The end of ctx stops at once with ctx.Err().
func (c *Client) Do(ctx context.Context, req *http.Request, policy Policy) (*http.Response, error) {
	if req.URL == nil || !c.sameOrigin(req.URL) {
		return nil, ErrForeignOrigin
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return nil, ErrBodyNotReplayable
	}
	attempts := policy.attempts()
	for attempt := 1; ; attempt++ {
		resp, err := c.attempt(ctx, req, policy, attempt)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt >= attempts || !IsRetryable(err) {
			return nil, err
		}
		if err := c.Pause(ctx, attempt, err, policy); err != nil {
			return nil, err
		}
	}
}

// attempt sends req once.
func (c *Client) attempt(ctx context.Context, req *http.Request, policy Policy, attempt int) (*http.Response, error) {
	r := req.Clone(ctx)
	if attempt > 1 && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, &RequestError{Method: req.Method, Path: Redact(req.URL.Path), Err: err}
		}
		r.Body = body
	}
	r.Header.Del("Authorization")
	if c.cfg.Token != "" && !policy.Anonymous {
		r.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.userAgent != "" {
		r.Header.Set("User-Agent", c.userAgent)
	}
	start := c.now()
	resp, err := c.http.Do(r)
	elapsed := c.now().Sub(start)
	path := Redact(req.URL.Path)
	if err != nil {
		c.logf("%s %s attempt %d: error after %s: %s", req.Method, path, attempt, elapsed.Round(time.Millisecond), Redact(cause(err).Error()))
		return nil, &RequestError{Method: req.Method, Path: path, Err: cause(err), Temporary: temporary(err)}
	}
	c.logf("%s %s attempt %d: %d request-id=%s %s", req.Method, path, attempt, resp.StatusCode,
		printable(resp.Header.Get("X-Request-Id")), elapsed.Round(time.Millisecond))
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return resp, nil
	}
	p := readProblem(resp, c.now())
	p.Method, p.Path = req.Method, path
	return nil, p
}

// cause unwraps the *url.Error of net/http, whose message quotes the full
// URL (query string and tokens included).
func cause(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// temporary classifies a transport error: certificate and TLS protocol
// failures (local, or an alert from the server such as "protocol version
// not supported"), and the end of the context, are permanent.
func temporary(err error) bool {
	var (
		opErr       *net.OpError
		unknownCA   x509.UnknownAuthorityError
		hostname    x509.HostnameError
		invalid     x509.CertificateInvalidError
		verifyError *tls.CertificateVerificationError
		alert       tls.AlertError
		header      tls.RecordHeaderError
	)
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &unknownCA), errors.As(err, &hostname), errors.As(err, &invalid),
		errors.As(err, &verifyError), errors.As(err, &alert), errors.As(err, &header):
		return false
	case errors.As(err, &opErr) && opErr.Op == "remote error":
		return false
	}
	return !strings.HasPrefix(err.Error(), "tls: ")
}

// logf writes one line of the verbose log.
func (c *Client) logf(format string, args ...any) {
	if c.log != nil {
		_, _ = fmt.Fprintf(c.log, "transteira-cli: "+format+"\n", args...)
	}
}

// JSONResult is what [Client.JSON] keeps of a 2xx answer once its body is
// decoded and closed.
type JSONResult struct {
	// StatusCode is the HTTP status (201 for a new transfer, 200 for the
	// same Idempotency-Key replayed...).
	StatusCode int
	// Header holds the answer headers (Location, X-Request-Id...).
	Header http.Header
}

// JSON sends a JSON request and decodes a JSON answer. in, when not nil,
// is encoded as the body (Content-Type: application/json); out, when not
// nil, receives the answer of a 2xx status other than 204, which must be
// JSON and at most policy.MaxResponseBytes. header adds request headers
// (Idempotency-Key...). The answer body is always closed; the result keeps
// the status and the headers, and is returned with decoding errors too.
// Errors are those of [Client.Do], plus encoding and decoding errors.
func (c *Client) JSON(ctx context.Context, method, path string, in, out any, header http.Header, policy Policy) (*JSONResult, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("%s %s: encoding the request: %w", method, Redact(path), err)
		}
		body = bytes.NewReader(data)
	}
	req, err := c.NewRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	for name, values := range header {
		req.Header[name] = values
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	resp, err := c.Do(ctx, req, policy)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	res := &JSONResult{StatusCode: resp.StatusCode, Header: resp.Header}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return res, nil
	}
	if !isJSON(resp.Header.Get("Content-Type")) {
		return res, fmt.Errorf("%s %s: the answer is not JSON", method, Redact(path))
	}
	limit := policy.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return res, &RequestError{Method: method, Path: Redact(path), Err: err}
	}
	if int64(len(data)) > limit {
		return res, fmt.Errorf("%s %s: the answer is larger than %d bytes", method, Redact(path), limit)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return res, fmt.Errorf("%s %s: decoding the answer: %w", method, Redact(path), err)
	}
	return res, nil
}
