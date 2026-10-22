package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DepositService identifies depositors. *deposit.Service implements it; the
// session lookup and the CSRF check are done by the middlewares (see
// httpserver), not by the handlers.
type DepositService interface {
	Start(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, acceptLanguage, email, invitationToken, recognition string) (deposit.Result, error)
	Confirm(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, challengeID, code, recognition string) (deposit.Session, error)
	End(ctx context.Context, t *tenant.Tenant, rawToken string) error
	Invite(ctx context.Context, t *tenant.Tenant, session deposit.SessionInfo, clientIP netip.Addr, acceptLanguage, email, message, language string) (deposit.Invitation, error)
	PublicInvitation(ctx context.Context, t *tenant.Tenant, rawToken string) (deposit.PublicInvitation, error)
}

// errNoDepositService reports a server built without WithDeposit: a wiring
// error, answered 500.
var errNoDepositService = errors.New("public: no deposit service configured")

// Field error codes of the deposit operations.
const (
	fieldInvalidEmail  = "invalid-email"
	fieldInvalidFormat = "invalid-format"
	fieldRequired      = "required"
)

// technicalCookie returns the Set-Cookie value of a technical cookie: host
// only (no Domain, as the __Host- prefix requires), Path=/, Secure,
// HttpOnly and SameSite=Strict. maxAge is rounded down to the second and
// kept at least 1, since 0 would delete the cookie.
func technicalCookie(name, value string, maxAge time.Duration) string {
	c := http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: max(int(maxAge/time.Second), 1),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
	return c.String()
}

// sessionCookies returns the Set-Cookie values opening sess: the session
// cookie, valid until the session expires, then the recognition cookie when
// the service returned a new value for it.
func (s *Server) sessionCookies(sess deposit.Session) []string {
	cookies := []string{technicalCookie(middleware.DepositCookie, sess.Token, sess.ExpiresAt.Sub(s.now()))}
	if sess.Recognition != "" {
		cookies = append(cookies, technicalCookie(deposit.RecognitionCookie, sess.Recognition, deposit.RecognitionMaxAge))
	}
	return cookies
}

// sessionCreated is the 201 answer of startDepositSession and
// confirmVerificationChallenge. The generated responses can carry one
// Set-Cookie header only (they call Header().Set), while a new session may
// set two cookies, which RFC 6265 forbids folding into one header: this
// type renders the same DepositSession body with one Set-Cookie header per
// cookie. It implements the generated response interfaces of both
// operations, which the strict handler accepts like the generated types.
type sessionCreated struct {
	body    gen.DepositSession
	cookies []string
}

// Compile-time checks of the response interfaces.
var (
	_ gen.StartDepositSessionResponseObject          = sessionCreated{}
	_ gen.ConfirmVerificationChallengeResponseObject = sessionCreated{}
)

// visit writes the 201 response.
func (r sessionCreated) visit(w http.ResponseWriter) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(r.body); err != nil {
		return err
	}
	h := w.Header()
	for _, c := range r.cookies {
		h.Add("Set-Cookie", c)
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err := buf.WriteTo(w)
	return err
}

// VisitStartDepositSessionResponse implements
// gen.StartDepositSessionResponseObject.
func (r sessionCreated) VisitStartDepositSessionResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

// VisitConfirmVerificationChallengeResponse implements
// gen.ConfirmVerificationChallengeResponseObject.
func (r sessionCreated) VisitConfirmVerificationChallengeResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

// clearDepositCookie returns the Set-Cookie value expiring the deposit
// session cookie.
func clearDepositCookie() string {
	c := http.Cookie{
		Name: middleware.DepositCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
	return c.String()
}

// depositTenant returns the tenant of the request and the deposit service,
// or the error to answer.
func (s *Server) depositTenant(ctx context.Context) (*tenant.Tenant, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	if s.deposit == nil {
		return nil, errNoDepositService
	}
	return t, nil
}

// currentSession returns the session and cookie token stored by the
// session middleware. Their absence means the route was wired without it:
// the request is refused as unauthenticated.
func currentSession(ctx context.Context) (deposit.SessionInfo, string, error) {
	info, ok := middleware.SessionFrom[deposit.SessionInfo](ctx)
	token, tokOK := middleware.SessionToken(ctx)
	if !ok || !tokOK {
		return deposit.SessionInfo{}, "", problem.New(problem.CodeUnauthenticated)
	}
	return info, token, nil
}

// StartDepositSession identifies a depositor by email address: 201 with the
// session cookie when the address is already verified, 202 with a
// verification challenge otherwise.
func (s *Server) StartDepositSession(ctx context.Context, req gen.StartDepositSessionRequestObject) (gen.StartDepositSessionResponseObject, error) {
	t, err := s.depositTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(deposit.FieldEmail, fieldRequired)
	}
	invitation := ""
	if req.Body.InvitationToken != nil {
		invitation = *req.Body.InvitationToken
	}
	res, err := s.deposit.Start(ctx, t, middleware.ClientIP(ctx), deref(req.Params.AcceptLanguage),
		string(req.Body.Email), invitation, deref(req.Params.UnderscoreUnderscoreHostTtKnown))
	if err != nil {
		return nil, depositError(err)
	}
	if res.Session != nil {
		return sessionCreated{body: sessionBody(res.Session.SessionInfo), cookies: s.sessionCookies(*res.Session)}, nil
	}
	if res.Challenge == nil {
		return nil, errors.New("public: deposit start returned neither a session nor a challenge")
	}
	ch := res.Challenge
	return gen.StartDepositSession202JSONResponse{
		ChallengeId: ch.ID, Email: gen.Email(ch.Email), ExpiresAt: ch.ExpiresAt, AttemptsRemaining: ch.AttemptsRemaining,
	}, nil
}

// ConfirmVerificationChallenge checks a verification code and opens a
// deposit session (201 with the session cookie).
func (s *Server) ConfirmVerificationChallenge(ctx context.Context, req gen.ConfirmVerificationChallengeRequestObject) (gen.ConfirmVerificationChallengeResponseObject, error) {
	t, err := s.depositTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(deposit.FieldCode, fieldRequired)
	}
	sess, err := s.deposit.Confirm(ctx, t, middleware.ClientIP(ctx), req.ChallengeId, req.Body.Code,
		deref(req.Params.UnderscoreUnderscoreHostTtKnown))
	if err != nil {
		return nil, depositError(err)
	}
	return sessionCreated{body: sessionBody(sess.SessionInfo), cookies: s.sessionCookies(sess)}, nil
}

// GetCurrentDepositSession returns the session authenticated by the session
// middleware, with its CSRF token.
func (s *Server) GetCurrentDepositSession(ctx context.Context, _ gen.GetCurrentDepositSessionRequestObject) (gen.GetCurrentDepositSessionResponseObject, error) {
	if _, ok := tenant.FromContext(ctx); !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	info, _, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetCurrentDepositSession200JSONResponse(sessionBody(info)), nil
}

// EndDepositSession ends the current session and clears its cookie (204).
func (s *Server) EndDepositSession(ctx context.Context, _ gen.EndDepositSessionRequestObject) (gen.EndDepositSessionResponseObject, error) {
	t, err := s.depositTenant(ctx)
	if err != nil {
		return nil, err
	}
	_, token, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.deposit.End(ctx, t, token); err != nil {
		return nil, depositError(err)
	}
	cookie := clearDepositCookie()
	return gen.EndDepositSession204Response{Headers: gen.EndDepositSession204ResponseHeaders{SetCookie: &cookie}}, nil
}

// CreateInvitation lets an internal depositor invite an external person
// (201). An external depositor gets 403 invitation-not-allowed.
func (s *Server) CreateInvitation(ctx context.Context, req gen.CreateInvitationRequestObject) (gen.CreateInvitationResponseObject, error) {
	t, err := s.depositTenant(ctx)
	if err != nil {
		return nil, err
	}
	info, _, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if info.Kind != deposit.KindInternal {
		return nil, problem.New(problem.CodeInvitationNotAllowed)
	}
	if req.Body == nil {
		return nil, validationFailed(deposit.FieldEmail, fieldRequired)
	}
	language := ""
	if req.Body.Language != nil {
		language = string(*req.Body.Language)
	}
	inv, err := s.deposit.Invite(ctx, t, info, middleware.ClientIP(ctx), deref(req.Params.AcceptLanguage),
		string(req.Body.Email), deref(req.Body.Message), language)
	if err != nil {
		return nil, depositError(err)
	}
	return gen.CreateInvitation201JSONResponse{
		Id: inv.ID, Email: gen.Email(inv.Email), InvitedBy: inv.InvitedBy, Status: gen.InvitationStatus(inv.Status),
		CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt,
	}, nil
}

// GetInvitation returns what the landing page of an invitation link shows.
func (s *Server) GetInvitation(ctx context.Context, req gen.GetInvitationRequestObject) (gen.GetInvitationResponseObject, error) {
	t, err := s.depositTenant(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := s.deposit.PublicInvitation(ctx, t, req.InvitationToken)
	if err != nil {
		return nil, depositError(err)
	}
	resp := gen.GetInvitation200JSONResponse{Email: gen.Email(inv.Email), InvitedBy: gen.Email(inv.InvitedBy), ExpiresAt: inv.ExpiresAt}
	if inv.Message != "" {
		msg := inv.Message
		resp.Message = &msg
	}
	return resp, nil
}

// sessionBody renders a session as the OpenAPI DepositSession. The session
// and invitation record identifiers stay on the server.
func sessionBody(info deposit.SessionInfo) gen.DepositSession {
	body := gen.DepositSession{
		Email: gen.Email(info.Email), Kind: gen.DepositorKind(info.Kind), CsrfToken: info.CSRFToken,
		ExpiresAt: info.ExpiresAt, CanInvite: info.CanInvite,
	}
	body.Limits.MaxTransferBytes = info.Limits.MaxTransferBytes
	body.Limits.ExpiryDays = make([]gen.ExpiryDays, len(info.Limits.ExpiryDays))
	for i, d := range info.Limits.ExpiryDays {
		body.Limits.ExpiryDays[i] = gen.ExpiryDays(d)
	}
	if inv := info.Invitation; inv != nil {
		body.Invitation = &struct {
			ExpiresAt time.Time `json:"expiresAt"`
			InvitedBy gen.Email `json:"invitedBy"`
		}{ExpiresAt: inv.ExpiresAt, InvitedBy: gen.Email(inv.InvitedBy)}
	}
	return body
}

// validationFailed returns a 400 validation-failed Problem naming field.
func validationFailed(field, code string) *problem.Problem {
	return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(problem.FieldError{Field: field, Code: code}))
}

// depositError maps an error of the deposit service to the error the
// strict handler renders. Server errors keep their cause, which is logged
// (the deposit service never puts an address, a token or a code in it).
func depositError(err error) error {
	var (
		invalid   *deposit.InvalidError
		wrongCode *deposit.WrongCodeError
		limited   *deposit.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		code := fieldInvalidFormat
		if invalid.Field == deposit.FieldEmail {
			code = fieldInvalidEmail
		}
		return validationFailed(invalid.Field, code)
	case errors.As(err, &wrongCode):
		return problem.New(problem.CodeVerificationCodeInvalid, problem.WithAttemptsRemaining(wrongCode.Remaining))
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, deposit.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, deposit.ErrForbidden):
		return problem.New(problem.CodeDepositNotAllowed)
	case errors.Is(err, deposit.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, deposit.ErrInvitationGone):
		return problem.New(problem.CodeInvitationGone)
	case errors.Is(err, deposit.ErrChallengeGone):
		return problem.New(problem.CodeVerificationExhausted)
	case errors.Is(err, deposit.ErrMailUnavailable):
		return fmt.Errorf("%w: %w", problem.New(problem.CodeMailUnavailable), err)
	default:
		return err
	}
}

// deref returns *p, or the zero value when p is nil.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
