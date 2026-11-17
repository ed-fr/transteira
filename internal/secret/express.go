package secret

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Security log scopes of the rate_limited events of the express secrets
// (since 2.3, docs/operations/security-log.md).
const (
	// ScopeExpressIP is the scope of the per-client limit of the anonymous
	// creations (tenant.ExpressSettings.PerHourPerIP), counted by the
	// shipped fail2ban and CrowdSec rules.
	ScopeExpressIP = "express_ip"
	// ScopeExpressToken is the scope of the per-token limit of the
	// creations with an API token (tenant.ExpressSettings.PerHourPerToken),
	// never counted by the shipped rules.
	ScopeExpressToken = "express_token"
)

// ExpressEventInterval is the minimum interval between two security
// events of the express secrets for the same key, event and reason or
// scope (docs/operations/security-log.md, "Log throttling"): a flood of
// refused calls writes about 6 lines per minute, every call is still
// refused.
const ExpressEventInterval = 10 * time.Second

// Actor of the audit events of an anonymous creation: the client IP is
// the only trace of its creator (OpenAPI AuditEvent.actor, id "-").
const anonymousActor = "-"

// ExpressCreator is the caller of an express secret creation
// ([Service.CreateExpress]), built by the HTTP layer.
type ExpressCreator struct {
	// ClientIP is the real client IP, read from the trusted proxies only.
	ClientIP netip.Addr
	// APITokenID is the API token of the request ("tok_" + ULID), "" for
	// an anonymous creation. The HTTP layer has authenticated it on the
	// tenant of the request (401 invalid-credentials otherwise, never
	// downgraded to an anonymous creation) and checked its allowed ranges
	// against ClientIP (403 ip-not-allowed, deposit_refused), as for any
	// operation with an API token; the store checks again, in its
	// transaction, that the token is still usable and allowed.
	APITokenID string
	// ExpressAllowed is the opt-in of the token for the express secrets
	// (apitoken.Principal.ExpressAllowed); ignored without APITokenID.
	ExpressAllowed bool
}

// ExpressCreateRequest is the body of an express secret creation (OpenAPI
// ExpressSecretCreate).
type ExpressCreateRequest struct {
	// EncryptedText is the sealed text (e2e-format.md 3.3.9).
	EncryptedText string
	// Verifier and KeyVerifier are the SHA-256 of the proofs, 64
	// lowercase hexadecimal characters each.
	Verifier    string
	KeyVerifier string
	// ExpiresIn is 1h, 1d or 7d.
	ExpiresIn string
	// Extra are the JSON pointers of the members of the body outside the
	// schema (such as /passphrase or /file), which the HTTP layer reports
	// in the order of the body: each one is refused (CodeNotAllowed).
	Extra []string
}

// expressPlan is a validated express creation request.
type expressPlan struct {
	verifier    []byte
	keyVerifier []byte
	duration    tenant.SecretDuration
}

// CreateExpress creates an express secret of tenant t (since 2.3, CLAUDE.md
// section 22.2, threat model T-389 to T-398): a one-time text secret,
// link delivery, without passphrase, file, read receipt nor creator
// address, active at once. The maintenance mode and the setup state of the
// tenant are refused by the HTTP layer before the call (503), as for
// [Service.Create]. In order:
//
//  1. the switches: the instance kill switch (Options.ExpressKillSwitch)
//     refuses every creation, an API token without the express opt-in is
//     ErrExpressTokenNotAllowed, and an anonymous creation on a tenant
//     whose anonymous mode is off is ErrExpressDisabled; each refusal is
//     written to the security log as express_refused (reason disabled or
//     token). The switch of the 2.1 secrets (tenant.SecretSettings.Enabled)
//     does not apply;
//  2. the schema rules (*ValidationError: the sealed text bounds, the
//     verifiers, a duration other than 1h, 1d and 7d, any extra member),
//     then the keyless framing of the sealed text (*FormatError: not
//     canonical, wrong version byte, or empty, since an express secret has
//     no file): a malformed call counts against no limit;
//  3. the per-client limit of an anonymous creation: at most
//     tenant.ExpressSettings.PerHourPerIP creations per tenant and client
//     (IPv4 address or IPv6 /64) in the sliding last hour, in memory
//     (Options.ExpressPerIP); beyond, a *RateLimitError, written as
//     rate_limited (scope express_ip). A new client refused because the
//     limiter of the tenant is saturated (ExpressIPMaxKeys clients at
//     their limit) is not at fault: ErrExpressLimit, written as
//     express_refused reason limit, which the shipped fail2ban and
//     CrowdSec rules ignore (threat model T-405);
//  4. the store, which checks again in its transaction that the token is
//     usable (ErrTokenInvalid, written as api_token_invalid, when it was
//     revoked or expired since the authentication) and allowed
//     (ErrExpressTokenNotAllowed, with express_refused reason token), the
//     tenant out of its setup (ErrTenantInSetup) and, for an anonymous
//     creation, its anonymous mode (ErrExpressDisabled) and its cap of
//     live express secrets (ErrExpressLimit, with express_refused reason
//     limit), and for a token its hourly limit (a *RateLimitError written
//     as rate_limited, scope express_token).
//
// The security events are throttled per client key (per token for
// express_token), event and reason or scope (Options.EventThrottle). On
// success it audits secret.created (details express and creatorKind; the
// actor is anonymous with the client IP, or the API token, which is then
// also audited as api_token.used) and counts the secret in Options.Usage.
// Nothing secret (the sealed text, the verifiers, the token) is ever
// logged or audited.
func (s *Service) CreateExpress(ctx context.Context, t *tenant.Tenant, creator ExpressCreator, req ExpressCreateRequest) (Created, error) {
	token := creator.APITokenID != ""
	switch {
	case s.killSwitch:
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressDisabled)
		return Created{}, ErrExpressDisabled
	case token && !creator.ExpressAllowed:
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressToken)
		return Created{}, ErrExpressTokenNotAllowed
	case !token && !t.Express.Enabled:
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressDisabled)
		return Created{}, ErrExpressDisabled
	}
	p, err := validateExpress(req)
	if err != nil {
		return Created{}, err
	}
	if err := checkFraming(CreateRequest{EncryptedText: req.EncryptedText}); err != nil {
		return Created{}, err
	}
	if !token {
		key := clientKey(creator.ClientIP)
		ok, retry, saturated := s.perIP.Allow(string(t.ID), key, t.Express.WithDefaults().PerHourPerIP)
		switch {
		case saturated:
			s.expressRefused(ctx, t, creator, securitylog.ReasonExpressLimit)
			return Created{}, ErrExpressLimit
		case !ok:
			s.throttledEvent(ctx, t, creator.ClientIP, key, securitylog.RateLimited, securitylog.KeyScope, ScopeExpressIP)
			return Created{}, &RateLimitError{RetryAfter: retry}
		}
	}
	out, err := s.repo.CreateExpress(ctx, t.ID, store.CreateExpressSecret{
		APITokenID: creator.APITokenID, Verifier: p.verifier, KeyVerifier: p.keyVerifier,
		SealedText: req.EncryptedText, Duration: p.duration, Now: s.now(),
	})
	if err != nil {
		return Created{}, s.expressError(ctx, t, creator, err)
	}
	s.recordExpressCreated(ctx, t, creator, out.Secret)
	s.usage.SecretCreated(t.ID, out.Secret.CreatedAt)
	return Created{ID: out.Secret.ID, Token: out.Token, State: out.Secret.State, ExpiresAt: out.Secret.ExpiresAt}, nil
}

// validateExpress checks req against the rules of the OpenAPI schema
// ExpressSecretCreate, collecting every invalid field, and returns the
// decoded values.
func validateExpress(req ExpressCreateRequest) (expressPlan, error) {
	var (
		v validator
		p expressPlan
	)
	switch t := req.EncryptedText; {
	case t == "":
		v.add(FieldEncryptedText, CodeRequired)
	case len(t) > store.MaxSecretSealedTextLen:
		v.add(FieldEncryptedText, CodeTooLong)
	case len(t) < store.MinSecretSealedTextLen || !isBase64URL(t):
		v.add(FieldEncryptedText, CodeInvalidFormat)
	}
	p.verifier = parseVerifier(&v, FieldVerifier, req.Verifier)
	p.keyVerifier = parseVerifier(&v, FieldKeyVerifier, req.KeyVerifier)
	switch d := tenant.SecretDuration(req.ExpiresIn); {
	case d == "":
		v.add(FieldExpiresIn, CodeRequired)
	case !d.ExpressDuration():
		v.add(FieldExpiresIn, CodeNotAllowed, durationCodes(tenant.ExpressDurations())...)
	default:
		p.duration = d
	}
	for _, pointer := range req.Extra {
		v.add(pointer, CodeNotAllowed)
	}
	if len(v.errs) > 0 {
		return expressPlan{}, &ValidationError{Fields: v.errs}
	}
	return p, nil
}

// expressError maps an error of the store creation of an express secret
// by creator, writing the security event of a refusal.
func (s *Service) expressError(ctx context.Context, t *tenant.Tenant, creator ExpressCreator, err error) error {
	var rate *store.ExpressTokenRateError
	switch {
	case errors.As(err, &rate):
		s.throttledEvent(ctx, t, creator.ClientIP, creator.APITokenID, securitylog.RateLimited,
			securitylog.KeyScope, ScopeExpressToken)
		return &RateLimitError{RetryAfter: rate.RetryAfter}
	case errors.Is(err, store.ErrExpressLimit):
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressLimit)
		return ErrExpressLimit
	case errors.Is(err, store.ErrExpressDisabled):
		// The anonymous mode was turned off since the tenant was read.
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressDisabled)
		return ErrExpressDisabled
	case errors.Is(err, store.ErrExpressTokenNotAllowed):
		// The opt-in was withdrawn since the authentication.
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressToken)
		return ErrExpressTokenNotAllowed
	case errors.Is(err, store.ErrExpressTokenUnusable):
		// The token was revoked or expired since the authentication:
		// answered as the token middleware answers such a token (401
		// invalid-credentials, api_token_invalid), never as a missing
		// opt-in. Nothing created.
		s.logEvent(ctx, t, creator.ClientIP, securitylog.APITokenInvalid)
		return ErrTokenInvalid
	case errors.Is(err, store.ErrTenantInSetup):
		return ErrTenantInSetup
	case errors.Is(err, store.ErrNotFound):
		// The deletion of the tenant started: its service is closed.
		s.expressRefused(ctx, t, creator, securitylog.ReasonExpressDisabled)
		return ErrExpressDisabled
	}
	return fmt.Errorf("secret: create express secret: %w", err)
}

// expressRefused writes the express_refused event of reason for creator,
// throttled per client key and reason.
func (s *Service) expressRefused(ctx context.Context, t *tenant.Tenant, creator ExpressCreator, reason string) {
	s.throttledEvent(ctx, t, creator.ClientIP, clientKey(creator.ClientIP), securitylog.ExpressRefused, securitylog.KeyReason, reason)
}

// throttledEvent writes the security event typ with the field name=value
// for the client ip, at most once per key, event and value per
// Options.EventThrottle. extra fields come first, as in the other events
// of the same type.
func (s *Service) throttledEvent(ctx context.Context, t *tenant.Tenant, ip netip.Addr, key string, typ securitylog.EventType,
	name, value string, extra ...securitylog.Field,
) {
	if ok, _ := s.throttle.Allow(string(typ) + " " + value + " " + key); !ok {
		return
	}
	s.logEvent(ctx, t, ip, typ, append(extra, securitylog.Field{Key: name, Value: value})...)
}

// recordExpressCreated audits the creation of the express secret sec by
// creator: secret.created, whose actor is anonymous (the client IP being
// the only trace) or the API token, then, for a token, api_token.used with
// the token as actor (an express secret has no sender address).
func (s *Service) recordExpressCreated(ctx context.Context, t *tenant.Tenant, creator ExpressCreator, sec store.Secret) {
	ev := audit.Event{
		ActorKind: store.ActorAnonymous, Actor: anonymousActor, IP: creator.ClientIP,
		Action: audit.ActionSecretCreated, ObjectID: sec.ID,
		Details: map[string]any{
			"creatorKind": string(sec.CreatorKind), "express": true, "delivery": string(store.SecretDeliveryLink),
			"hasFile": false, "expiresIn": string(sec.Duration),
		},
	}
	if creator.APITokenID == "" {
		s.record(ctx, t, ev)
		return
	}
	ev.ActorKind, ev.Actor = store.ActorAPIToken, creator.APITokenID
	s.record(ctx, t, ev)
	s.record(ctx, t, audit.Event{
		ActorKind: store.ActorAPIToken, Actor: creator.APITokenID, IP: creator.ClientIP, Action: audit.ActionAPITokenUsed,
		ObjectKind: audit.ObjectAPIToken, ObjectID: creator.APITokenID,
		Details: map[string]any{"object": audit.ObjectSecret, "objectId": sec.ID},
	})
}
