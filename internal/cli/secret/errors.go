package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// Sentinel errors, to be tested with errors.Is. The errors returned wrap
// one of them and, when the server refused, the [*client.Problem] of its
// answer (method, redacted path, status, code and request identifier).
var (
	// ErrDisabled: the express secret service is closed. At creation, the
	// entity does not accept anonymous express secrets or the instance
	// disabled them; at reading, the secret is blocked, nothing is
	// consumed, and the link works again if the service reopens before
	// the secret expires.
	ErrDisabled = errors.New("express secrets are not available")
	// ErrTokenNotAllowed: the API token lacks the opt-in expressAllowed.
	ErrTokenNotAllowed = errors.New("the API token is not allowed to create express secrets")
	// ErrTokenRefused: the API token is unknown, revoked, expired, of
	// another entity, or used from an address outside its allowed ranges.
	ErrTokenRefused = errors.New("the API token was refused")
	// ErrRateLimited: too many requests from this client (or this token);
	// the message gives the delay announced by the server.
	ErrRateLimited = errors.New("too many requests")
	// ErrLimitReached: the entity holds as many unread express secrets as
	// it allows; anonymous creations wait until some are read or expire.
	ErrLimitReached = errors.New("too many express secrets are waiting to be read on this entity")
	// ErrNotOffered: the server has no express secrets (older than 2.3).
	ErrNotOffered = errors.New("the server does not offer express secrets (TransTeira 2.3 or later is needed)")
	// ErrRefused: the server refused the request as malformed, which means
	// a client and a server that do not agree on the format.
	ErrRefused = errors.New("the server refused the secret as malformed")
	// ErrInvalidAnswer: the server answered something this client cannot
	// use.
	ErrInvalidAnswer = errors.New("invalid answer from the server")
	// ErrNotFound: no secret behind the link (wrong link, link of another
	// entity, or a secret that ended more than 30 days ago).
	ErrNotFound = errors.New("no secret behind this link: check the link, or the secret ended long ago")
	// ErrGone: the secret ended; the message gives the reason (read,
	// expired, deleted, locked).
	ErrGone = errors.New("the secret is no longer available")
	// ErrUnsupported: the secret has a passphrase or a file, which this
	// client does not handle. Nothing was consumed.
	ErrUnsupported = errors.New("secret not supported by the command-line client")
	// ErrWrongKey: the server refused the proof derived from the key of
	// the link. Without passphrase nothing is consumed.
	ErrWrongKey = errors.New("the key of the link was refused: the link is incomplete or altered")
	// ErrIntegrity: the revealed text does not open with the key of the
	// link. The secret is consumed.
	ErrIntegrity = errors.New("the secret could not be opened with the key of the link")
)

// Problem codes of the API (docs/api/errors.md).
const (
	codeExpressDisabled  = "express-secrets-disabled"
	codeTokenNotAllowed  = "express-token-not-allowed"
	codeLimitReached     = "express-secret-limit-reached"
	codeProofInvalid     = "secret-proof-invalid"
	codeIPNotAllowed     = "ip-not-allowed"
	codeValidationFailed = "validation-failed"
	codeFormatInvalid    = "secret-format-invalid"
)

// problemOf returns the problem answered by the server in err, or nil.
func problemOf(err error) *client.Problem {
	var p *client.Problem
	if errors.As(err, &p) {
		return p
	}
	return nil
}

// retryHint describes the Retry-After of p.
func retryHint(p *client.Problem) string {
	if p.RetryAfter <= 0 {
		return "try again later"
	}
	return "try again in " + p.RetryAfter.Round(time.Second).String()
}

// createError maps the failure of createExpressSecret; tokenSent says
// whether the request carried the API token.
func createError(err error, tokenSent bool) error {
	p := problemOf(err)
	if p == nil {
		return err
	}
	switch {
	case p.Code == codeExpressDisabled && tokenSent:
		return fmt.Errorf("%w: the server instance disabled them (%w)", ErrDisabled, err)
	case p.Code == codeExpressDisabled:
		return fmt.Errorf("%w: the entity does not accept anonymous express secrets (or the server instance disabled them); "+
			"an API token allowed to create express secrets may still do it (%w)", ErrDisabled, err)
	case p.Code == codeTokenNotAllowed:
		return fmt.Errorf("%w: an admin of the entity must allow express secrets on the token (expressAllowed), "+
			"or create the secret without the token with --anonymous (%w)", ErrTokenNotAllowed, err)
	case p.Code == codeIPNotAllowed:
		return fmt.Errorf("%w: it is not allowed from this IP address (allowed ranges of the token); "+
			"--anonymous creates the secret without it (%w)", ErrTokenRefused, err)
	case p.Status == http.StatusUnauthorized:
		return fmt.Errorf("%w: it is unknown, revoked, expired or of another entity; "+
			"--anonymous creates the secret without it (%w)", ErrTokenRefused, err)
	case p.Code == codeLimitReached:
		return fmt.Errorf("%w: try again later (they free up when they are read or expire), "+
			"or use an API token allowed to create express secrets (%w)", ErrLimitReached, err)
	case p.Status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s (%w)", ErrRateLimited, retryHint(p), err)
	case p.Status == http.StatusNotFound:
		return fmt.Errorf("%w (%w)", ErrNotOffered, err)
	case p.Code == codeValidationFailed || p.Code == codeFormatInvalid:
		return fmt.Errorf("%w: the client and the server versions may not match (%w)", ErrRefused, err)
	}
	return err
}

// linkError maps the failure of getSecretLink and revealSecret.
func linkError(err error) error {
	p := problemOf(err)
	if p == nil {
		return err
	}
	switch {
	case p.Code == codeExpressDisabled:
		return fmt.Errorf("%w: the entity closed the express secret service; nothing was consumed, and the link "+
			"works again if the service reopens before the secret expires (%w)", ErrDisabled, err)
	case p.Status == http.StatusNotFound:
		return fmt.Errorf("%w (%w)", ErrNotFound, err)
	case p.Status == http.StatusGone:
		return fmt.Errorf("%w: %s (%w)", ErrGone, goneReason(p), err)
	case p.Code == codeProofInvalid && p.AttemptsRemaining != nil:
		return fmt.Errorf("%w: %d attempt(s) left before the secret is locked (%w)", ErrWrongKey, *p.AttemptsRemaining, err)
	case p.Code == codeProofInvalid:
		return fmt.Errorf("%w; nothing was consumed (%w)", ErrWrongKey, err)
	case p.Status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s (%w)", ErrRateLimited, retryHint(p), err)
	}
	return err
}

// goneReason explains the reason member of a secret-gone problem.
func goneReason(p *client.Problem) string {
	var reason string
	_ = json.Unmarshal(p.Extensions["reason"], &reason)
	switch reason {
	case "read":
		return "it was already read, and a secret is read once only: if you did not read it, someone else did, tell its sender"
	case "expired":
		return "it expired before it was read"
	case "deleted":
		return "it was deleted by its creator or an admin of the entity"
	case "locked":
		return "it was locked after too many wrong passphrases"
	}
	return "it ended"
}
