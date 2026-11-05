package oidc

import (
	"errors"

	"github.com/ed-fr/transteira/internal/securitylog"
)

// Reasons of an [Error]: the values of the reason field of the sso_failed
// security event (securitylog.SSOFailed) this package can produce.
const (
	// ReasonStateInvalid: missing, unknown, expired, already used or
	// tampered flow cookie, or a state that does not match.
	ReasonStateInvalid = securitylog.ReasonStateInvalid
	// ReasonTokenInvalid: code refused by the provider, or ID token
	// missing or invalid (signature, algorithm, issuer, audience,
	// authorized party, times, nonce, subject).
	ReasonTokenInvalid = securitylog.ReasonTokenInvalid
	// ReasonIssuerError: the provider is unreachable or misbehaves, the
	// RFC 9207 iss parameter does not match, the provider answered with an
	// error, or the configuration differs from the one of the flow.
	ReasonIssuerError = securitylog.ReasonIssuerError
)

// Stages of a discovery, the values of SsoTestResult.stage.
const (
	StageSettings  = "settings"
	StageConnect   = "connect"
	StageTLS       = "tls"
	StageDiscovery = "discovery"
	StageIssuer    = "issuer"
	StageEndpoints = "endpoints"
	StageDone      = "done"
	StageUnknown   = "unknown"
)

// Categories of a failed discovery, the values of SsoTestResult.error.
const (
	CategoryDNS             = "dns_error"
	CategoryConnect         = "connect_error"
	CategoryTLS             = "tls_error"
	CategoryTimeout         = "timeout"
	CategoryHTTPStatus      = "http_status"
	CategoryInvalidDocument = "invalid_document"
	CategoryIssuerMismatch  = "issuer_mismatch"
	CategoryMissingEndpoint = "missing_endpoint"
	CategoryInternal        = "internal_error"
)

// Errors of the issuer rules ([CheckIssuer]) and of the configuration.
var (
	// ErrIssuerInvalid reports an issuer that is not an https URL of 9 to
	// 512 characters without credentials, query or fragment.
	ErrIssuerInvalid = errors.New("oidc: invalid issuer")
	// ErrIssuerNotAllowed reports a Microsoft Entra ID multi-tenant issuer
	// (common, organizations, consumers) or a template issuer
	// ({tenantid}), which would accept users of any Entra tenant (T-288).
	// The API maps it to sso-issuer-not-allowed.
	ErrIssuerNotAllowed = errors.New("oidc: issuer not allowed")
	// ErrConfigInvalid reports a [Config] with a missing or malformed
	// field (tenant ID, client ID, client secret or redirect URL).
	ErrConfigInvalid = errors.New("oidc: invalid configuration")
)

// Error is a failure of a single sign-on step. Its fields only ever hold
// values of closed lists, so that it may be logged and audited as is: the
// cause (a remote text, a library message) is deliberately dropped.
type Error struct {
	// Reason is the reason of the sso_failed security event:
	// ReasonStateInvalid, ReasonTokenInvalid or ReasonIssuerError.
	Reason string
	// Stage and Category, set for a failure of a request to the provider
	// (discovery, keys, token), are a Stage* and a Category* constant.
	Stage, Category string
}

// Error returns "oidc: <reason>", followed by the stage and category when
// set.
func (e *Error) Error() string {
	s := "oidc: " + e.Reason
	if e.Category != "" {
		s += " (" + e.Stage + ": " + e.Category + ")"
	}
	return s
}

// ReasonOf returns the reason of err when it is an [*Error], else
// ReasonIssuerError (an unexpected failure is blamed on the provider side,
// never on the user).
func ReasonOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return ReasonIssuerError
}

// ProviderError returns the error of an authorization response carrying
// the error parameter (the user canceled, the provider refused): nil for
// an empty parameter, else an [*Error] with ReasonIssuerError. The value of
// the parameter is never kept. The caller consumes the flow ([Flows.Consume])
// first, so that the flow is used once whatever the answer.
func ProviderError(errParam string) error {
	if errParam == "" {
		return nil
	}
	return &Error{Reason: ReasonIssuerError}
}

// failure returns an [*Error] of reason r.
func failure(r string) *Error { return &Error{Reason: r} }
