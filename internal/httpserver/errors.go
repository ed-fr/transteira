package httpserver

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/stubs"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// Field error codes of parameter validation failures.
const (
	fieldRequired      = "required"
	fieldInvalidFormat = "invalid-format"
	fieldTooManyValues = "too-many-values"
)

// writeProblem renders p with the request identifier as instance. p is
// copied, never mutated, since handlers may return shared Problems.
func writeProblem(w http.ResponseWriter, r *http.Request, p *problem.Problem) {
	cp := *p
	cp.Instance = middleware.RequestID(r.Context())
	problem.Write(w, &cp)
}

// errorHandlers maps the errors of the generated router and strict handler
// to Problems. Error texts are logged, never sent to the client.
type errorHandlers struct {
	logger *slog.Logger
}

// paramError handles path, query and header parameters that failed to
// parse: 400 validation-failed naming the parameter, or the bodyless tus
// answers of tusParamError for a tus operation.
func (h errorHandlers) paramError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.DebugContext(r.Context(), "invalid request parameter",
		slog.String("request_id", middleware.RequestID(r.Context())),
		slog.String("error", err.Error()))
	if isTusPattern(r.Pattern) {
		tusParamError(w, r, err)
		return
	}
	opts := []problem.Option{}
	if fe, ok := fieldErrorOf(err); ok {
		opts = append(opts, problem.WithFieldErrors(fe))
	}
	writeProblem(w, r, problem.New(problem.CodeValidationFailed, opts...))
}

// fieldErrorOf describes the parameter error err, if it is one of the
// generated parameter error types.
func fieldErrorOf(err error) (problem.FieldError, bool) {
	var (
		required   *gen.RequiredParamError
		header     *gen.RequiredHeaderError
		format     *gen.InvalidParamFormatError
		unmarshal  *gen.UnmarshalingParamError
		cookie     *gen.UnescapedCookieParamError
		tooMany    *gen.TooManyValuesForParamError
		fieldError problem.FieldError
	)
	switch {
	case errors.As(err, &required):
		fieldError = problem.FieldError{Field: required.ParamName, Code: fieldRequired}
	case errors.As(err, &header):
		fieldError = problem.FieldError{Field: header.ParamName, Code: fieldRequired}
	case errors.As(err, &format):
		fieldError = problem.FieldError{Field: format.ParamName, Code: fieldInvalidFormat}
	case errors.As(err, &unmarshal):
		fieldError = problem.FieldError{Field: unmarshal.ParamName, Code: fieldInvalidFormat}
	case errors.As(err, &cookie):
		fieldError = problem.FieldError{Field: cookie.ParamName, Code: fieldInvalidFormat}
	case errors.As(err, &tooMany):
		fieldError = problem.FieldError{Field: tooMany.ParamName, Code: fieldTooManyValues}
	default:
		return problem.FieldError{}, false
	}
	return fieldError, true
}

// requestError handles request bodies that could not be decoded: 413
// payload-too-large when the body limit was hit, 400 validation-failed
// otherwise.
func (h errorHandlers) requestError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.DebugContext(r.Context(), "invalid request body",
		slog.String("request_id", middleware.RequestID(r.Context())),
		slog.String("error", err.Error()))
	code := problem.CodeValidationFailed
	if middleware.IsBodyTooLarge(err) {
		code = problem.CodePayloadTooLarge
	}
	writeProblem(w, r, problem.New(code))
}

// responseError handles the errors returned by the operations: a stub
// answers 404 not-found, a Problem is rendered as is, and anything else is
// a 500 internal-error whose cause is only logged.
//
// When the error comes from writing the response (a Visit method failing
// mid-stream) after the response has started, a Problem can no longer be
// sent cleanly: the error is logged and the handler panics with
// [http.ErrAbortHandler] so that net/http aborts the connection and the
// client sees a truncated response rather than a seemingly complete one.
// A client that went away is logged at Debug level, and a client cut for
// not reading within the write idle timeout ([os.ErrDeadlineExceeded]) at
// Info level, since neither is a server fault. Likewise, a server error
// returned once the client went away (its request context is done, for
// instance while the operation waited between retries) is only logged at
// Debug level.
func (h errorHandlers) responseError(w http.ResponseWriter, r *http.Request, err error) {
	if middleware.ResponseStarted(w) {
		level := slog.LevelError
		switch {
		case r.Context().Err() != nil:
			level = slog.LevelDebug // the client went away
		case errors.Is(err, os.ErrDeadlineExceeded):
			level = slog.LevelInfo // the client stopped reading (idle timeout)
		}
		h.logger.Log(r.Context(), level, "response failed after it started",
			slog.String("request_id", middleware.RequestID(r.Context())),
			slog.String("route", r.Pattern),
			slog.String("error", err.Error()))
		panic(http.ErrAbortHandler)
	}
	if errors.Is(err, stubs.ErrNotImplemented) {
		writeProblem(w, r, problem.New(problem.CodeNotFound))
		return
	}
	if middleware.IsBodyTooLarge(err) {
		writeProblem(w, r, problem.New(problem.CodePayloadTooLarge))
		return
	}
	p := problem.From(err)
	if p.Status >= http.StatusInternalServerError {
		level := slog.LevelError
		switch {
		case p.Code == problem.CodeMaintenance:
			level = slog.LevelDebug
		case r.Context().Err() != nil:
			// The client went away (or its deadline passed) while the
			// operation ran, typically during a wait between retries: not
			// a server fault, and nobody reads the answer.
			level = slog.LevelDebug
		}
		h.logger.Log(r.Context(), level, "request failed",
			slog.String("request_id", middleware.RequestID(r.Context())),
			slog.String("route", r.Pattern),
			slog.String("error", err.Error()))
	}
	writeProblem(w, r, p)
}
