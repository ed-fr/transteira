// Package problem builds RFC 9457 Problem Details responses
// (application/problem+json) for the TransTeira API and holds the catalog
// of stable error codes with their default HTTP status and English title.
//
// Handlers return or wrap a *Problem as an error; the HTTP layer converts any
// error with From and renders it with Write. Unknown errors are always
// reported as a generic internal-error so that no internal detail leaks.
package problem

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"
)

// ContentType is the media type of a Problem Details body.
const ContentType = "application/problem+json"

// FieldError describes one invalid request field (validation-failed only).
type FieldError struct {
	// Field is the path of the invalid field, e.g. "recipients[0]".
	Field string `json:"field"`
	// Code is a short machine-readable reason, e.g. "invalid-email".
	Code string `json:"code"`
	// Allowed optionally lists the accepted values.
	Allowed []any `json:"allowed,omitempty"`
	// Line and Column optionally locate the problem inside the field
	// (1-based, the column in characters), for a mail template; 0 omits
	// them.
	Line   int `json:"line,omitempty"`
	Column int `json:"column,omitempty"`
	// Message optionally explains the problem, in English (mail
	// templates).
	Message string `json:"message,omitempty"`
}

// Problem is an RFC 9457 Problem Details object with the TransTeira
// extension members. It implements error.
type Problem struct { //nolint:errname // "Problem" is the RFC 9457 term and the OpenAPI schema name.
	// Type is the documentation URI of the problem type.
	Type string `json:"type"`
	// Title is a short, localized summary.
	Title string `json:"title"`
	// Status is the HTTP status code.
	Status int `json:"status"`
	// Detail is a localized human-readable explanation.
	Detail string `json:"detail,omitempty"`
	// Instance is the request identifier.
	Instance string `json:"instance,omitempty"`
	// Code is the stable error code.
	Code Code `json:"code"`
	// Errors lists field-level validation errors.
	Errors []FieldError `json:"errors,omitempty"`
	// AttemptsRemaining is the number of attempts left before lockout.
	AttemptsRemaining *int `json:"attemptsRemaining,omitempty"`
	// RetryAfterSeconds is the delay before retrying; also sent as Retry-After.
	RetryAfterSeconds *int `json:"retryAfterSeconds,omitempty"`
	// MaxTransferBytes is the per-transfer size limit of the tenant.
	MaxTransferBytes *int64 `json:"maxTransferBytes,omitempty"`
	// Files lists the identifiers of the files concerned.
	Files []string `json:"files,omitempty"`
}

// Option customizes a Problem built by New.
type Option func(*Problem)

// New returns a Problem for code with its catalog status and title, then
// applies opts. An unknown code is replaced by CodeInternalError.
func New(code Code, opts ...Option) *Problem {
	def, ok := catalog[code]
	if !ok {
		code = CodeInternalError
		def = catalog[code]
	}
	p := &Problem{
		Type:   code.TypeURI(),
		Title:  def.Title,
		Status: def.Status,
		Code:   code,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithTitle overrides the default English title (e.g. with a localized one).
// An empty title is ignored.
func WithTitle(title string) Option {
	return func(p *Problem) {
		if title != "" {
			p.Title = title
		}
	}
}

// WithDetail sets the human-readable explanation.
func WithDetail(detail string) Option {
	return func(p *Problem) { p.Detail = detail }
}

// WithInstance sets the request identifier.
func WithInstance(instance string) Option {
	return func(p *Problem) { p.Instance = instance }
}

// WithFieldErrors appends field-level validation errors.
func WithFieldErrors(errs ...FieldError) Option {
	return func(p *Problem) { p.Errors = append(p.Errors, errs...) }
}

// WithAttemptsRemaining sets the number of attempts left (negative values
// are clamped to zero).
func WithAttemptsRemaining(n int) Option {
	return func(p *Problem) {
		v := max(n, 0)
		p.AttemptsRemaining = &v
	}
}

// WithRetryAfter sets the retry delay, rounded up to the whole second and
// clamped to zero. It is rendered both in the body and in the Retry-After
// header.
func WithRetryAfter(d time.Duration) Option {
	return func(p *Problem) {
		s := max(int(math.Ceil(d.Seconds())), 0)
		p.RetryAfterSeconds = &s
	}
}

// WithMaxTransferBytes sets the per-transfer size limit.
func WithMaxTransferBytes(n int64) Option {
	return func(p *Problem) { p.MaxTransferBytes = &n }
}

// WithFiles appends identifiers of the files concerned.
func WithFiles(ids ...string) Option {
	return func(p *Problem) { p.Files = append(p.Files, ids...) }
}

// Error implements error. It returns the code and title only, never the
// detail, so that logging the error stays concise.
func (p *Problem) Error() string {
	return string(p.Code) + ": " + p.Title
}

// From converts err to a Problem. If err is or wraps a non-nil *Problem,
// that Problem is returned. Otherwise (including a nil err) a generic
// internal-error Problem is returned, without any text from err.
func From(err error) *Problem {
	var p *Problem
	if errors.As(err, &p) && p != nil {
		return p
	}
	return New(CodeInternalError)
}

// fallbackBody is written when a Problem cannot be encoded.
const fallbackBody = `{"type":"` + TypeBaseURI + `internal-error","title":"Internal error","status":500,"code":"internal-error"}`

// Write renders p as an application/problem+json response. A nil p, or a p
// whose status is outside 400-599, is rendered as internal-error (keeping
// only the instance identifier) so that the status header and body agree.
// If encoding fails, a minimal internal-error body is written instead.
// Write never mutates p and never panics on a nil or malformed Problem.
func Write(w http.ResponseWriter, p *Problem) {
	switch {
	case p == nil:
		p = New(CodeInternalError)
	case p.Status < 400 || p.Status > 599:
		p = New(CodeInternalError, WithInstance(p.Instance))
	}
	status := p.Status
	retryAfter := p.RetryAfterSeconds
	body, err := json.Marshal(p)
	if err != nil {
		status = http.StatusInternalServerError
		retryAfter = nil
		body = []byte(fallbackBody)
	}

	h := w.Header()
	h.Set("Content-Type", ContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Del("Content-Length")
	if retryAfter != nil {
		h.Set("Retry-After", strconv.Itoa(*retryAfter))
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
