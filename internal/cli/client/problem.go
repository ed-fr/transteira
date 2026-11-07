package client

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxProblemBytes is the largest problem body decoded; a larger body is
// ignored and the [Problem] keeps only the status and the headers.
const MaxProblemBytes = 64 << 10

// Problem is a non-2xx answer of the server, decoded from an RFC 9457
// application/problem+json body when there is one. tus answers often have
// no body: the Problem then carries only the status and the headers.
// Strings that come from the server are made safe for a terminal by Error;
// the fields hold them as received.
type Problem struct { //nolint:errname // the RFC 9457 name reads better than ProblemError for callers
	// Status is the HTTP status of the answer (always set).
	Status int
	// Type, Title, Detail, Instance and Code are the RFC 9457 members and
	// the stable TransTeira code (docs/api/errors.md), or empty.
	Type, Title, Detail, Instance, Code string
	// RequestID is the X-Request-Id header, else the instance member.
	RequestID string
	// RetryAfter is the Retry-After header, else retryAfterSeconds, or 0.
	RetryAfter time.Duration
	// AttemptsRemaining is the attemptsRemaining member, or nil.
	AttemptsRemaining *int
	// Errors are the field-level errors (validation-failed and others).
	Errors []FieldError
	// Extensions holds every member of the body other than type, title,
	// status, detail, instance and code, undecoded (attemptsRemaining,
	// maxTransferBytes, files...).
	Extensions map[string]json.RawMessage
	// Method and Path describe the request; Path is already redacted.
	Method, Path string
}

// FieldError is one entry of the errors member of a problem.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Error returns a one-line message: request, status, code, title, detail
// and request identifier, made safe for a terminal.
func (p *Problem) Error() string {
	var b strings.Builder
	if p.Method != "" {
		b.WriteString(p.Method + " " + p.Path + ": ")
	}
	b.WriteString("HTTP " + strconv.Itoa(p.Status))
	if p.Code != "" {
		b.WriteString(" " + printable(p.Code))
	}
	title := p.Title
	if title == "" {
		title = http.StatusText(p.Status)
	}
	if title != "" {
		b.WriteString(": " + printable(title))
	}
	if p.Detail != "" {
		b.WriteString(" (" + printable(p.Detail) + ")")
	}
	if p.RequestID != "" {
		b.WriteString(" [request " + printable(p.RequestID) + "]")
	}
	return b.String()
}

// Retryable reports whether the request may be sent again as is: 408, 429
// and 5xx except 501 (not implemented) and 507 (quota exceeded).
func (p *Problem) Retryable() bool { return retryableStatus(p.Status) }

// retryableStatus is the status classification of [Problem.Retryable].
func retryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	case http.StatusNotImplemented, http.StatusInsufficientStorage:
		return false
	}
	return status >= 500 && status <= 599
}

// problemMembers are the standard members decoded into fields.
var problemMembers = map[string]bool{
	"type": true, "title": true, "status": true, "detail": true, "instance": true, "code": true,
}

// readProblem builds the Problem of a non-2xx answer and closes its body.
// The body is decoded only when it is JSON and at most MaxProblemBytes.
func readProblem(resp *http.Response, now time.Time) *Problem {
	p := &Problem{Status: resp.StatusCode, RequestID: resp.Header.Get("X-Request-Id")}
	if d, ok := ParseRetryAfter(resp.Header.Get("Retry-After"), now); ok {
		p.RetryAfter = d
	}
	defer func() { _ = resp.Body.Close() }()
	if !isJSON(resp.Header.Get("Content-Type")) {
		return p
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxProblemBytes+1))
	if err != nil || len(data) > MaxProblemBytes {
		return p
	}
	p.decode(data)
	return p
}

// decode fills the problem from a JSON body; an invalid body is ignored.
func (p *Problem) decode(data []byte) {
	var members map[string]json.RawMessage
	if json.Unmarshal(data, &members) != nil {
		return
	}
	str := func(name string) string {
		var s string
		if raw, ok := members[name]; ok {
			_ = json.Unmarshal(raw, &s)
		}
		return s
	}
	p.Type, p.Title, p.Detail = str("type"), str("title"), str("detail")
	p.Instance, p.Code = str("instance"), str("code")
	if p.RequestID == "" {
		p.RequestID = p.Instance
	}
	for name, raw := range members {
		if problemMembers[name] {
			continue
		}
		if p.Extensions == nil {
			p.Extensions = map[string]json.RawMessage{}
		}
		p.Extensions[name] = raw
	}
	var n int
	if raw, ok := members["attemptsRemaining"]; ok && json.Unmarshal(raw, &n) == nil && n >= 0 {
		p.AttemptsRemaining = &n
	}
	var secs int64
	if raw, ok := members["retryAfterSeconds"]; ok && p.RetryAfter == 0 &&
		json.Unmarshal(raw, &secs) == nil && secs > 0 {
		p.RetryAfter = capSeconds(secs)
	}
	if raw, ok := members["errors"]; ok {
		var errs []FieldError
		if json.Unmarshal(raw, &errs) == nil {
			p.Errors = errs
		}
	}
}

// isJSON reports whether a Content-Type is application/json,
// application/problem+json or another +json type.
func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

// maxRetryAfterSeconds bounds a Retry-After value (one day) before the
// policy cap applies, so that the conversion to a Duration cannot overflow.
const maxRetryAfterSeconds = 86400

// capSeconds converts seconds to a Duration, bounded by one day.
func capSeconds(secs int64) time.Duration {
	return time.Duration(min(secs, maxRetryAfterSeconds)) * time.Second
}

// ParseRetryAfter parses a Retry-After header (RFC 9110 section 10.2.3):
// a number of seconds or an HTTP date, the latter relative to now. A date
// in the past gives 0. The result is at most one day. ok is false for an
// empty or invalid value.
func ParseRetryAfter(value string, now time.Time) (d time.Duration, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if value[0] >= '0' && value[0] <= '9' {
		if strings.TrimLeft(value, "0123456789") != "" {
			return 0, false
		}
		if len(value) > 10 {
			return capSeconds(maxRetryAfterSeconds), true
		}
		secs, _ := strconv.ParseInt(value, 10, 64)
		return capSeconds(secs), true
	}
	t, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	wait := t.Sub(now)
	if wait <= 0 {
		return 0, true
	}
	return min(wait, capSeconds(maxRetryAfterSeconds)), true
}
