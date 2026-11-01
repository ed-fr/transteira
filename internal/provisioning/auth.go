package provisioning

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
)

// Principal is the provisioning token that authenticated a request, with
// its scope as read at the authentication.
type Principal struct {
	// TokenID is the token identifier ("prv_" + ULID), the actor of the
	// audit events and the filter of every tenant read.
	TokenID string
	// Name is the label of the token.
	Name string
	// Prefix is its visible prefix.
	Prefix string
	// AllowedFQDNSuffixes are the normalized suffixes the FQDN of a
	// created tenant must end with.
	AllowedFQDNSuffixes []string
	// MaxStorageQuotaBytes caps the storage quota of a created tenant.
	MaxStorageQuotaBytes int64
	// MaxTransferBytes caps its transfer limit, 0 for no cap below 20 GiB.
	MaxTransferBytes int64
	// MaxTenants is the maximum number of live tenants of the token (the
	// store checks it again under a lock at each creation).
	MaxTenants int
}

// refuse returns the *AuthError of reason for the token tokID ("" when
// unknown).
func refuse(reason, tokID string) error {
	return &AuthError{Reason: reason, TokenID: tokID}
}

// Authenticate checks the provisioning token raw (the value after
// "Bearer ") presented from clientIP, the real client IP read from the
// trusted proxies only. The checks run in this order: the shape of the
// secret ("ttp_" and 43 base62 characters: a tenant API token "tt_..." is
// malformed here, T-269), the lookup of its SHA-256, a constant-time
// comparison of the hashes, the revocation, the expiry, then the client IP
// against the allowed ranges of the token (an invalid IP matches none).
// Every refusal returns the same *AuthError matching ErrInvalidToken
// (T-268); its Reason is for the application log only, never for the
// client. On success it records the use of the token, at most once per
// TouchInterval per token; a failure of that write is logged, not
// returned. Any other error is an internal failure of the store, which the
// caller must refuse as well.
func (s *Service) Authenticate(ctx context.Context, raw string, clientIP netip.Addr) (Principal, error) {
	if !ValidSecret(raw) {
		return Principal{}, refuse(ReasonMalformed, "")
	}
	hash := hashOf(raw)
	tok, err := s.repo.tokenByHash(ctx, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal{}, refuse(ReasonUnknown, "")
	case err != nil:
		return Principal{}, fmt.Errorf("provisioning: authenticate: %w", err)
	}
	now := s.now()
	// The lookup compared the hashes already; comparing them again in
	// constant time keeps the decision independent of the database
	// collation and timing.
	switch {
	case subtle.ConstantTimeCompare(tok.TokenHash, hash) != 1:
		return Principal{}, refuse(ReasonUnknown, "")
	case tok.Revoked():
		return Principal{}, refuse(ReasonRevoked, tok.ID)
	case tok.Expired(now):
		return Principal{}, refuse(ReasonExpired, tok.ID)
	case !netpolicy.Contains(tok.AllowedCIDRs, clientIP):
		return Principal{}, refuse(ReasonIPNotAllowed, tok.ID)
	}
	if s.touches.Due(tok.ID, now) {
		if err := s.repo.touch(ctx, tok.ID, now); err != nil {
			s.logger.WarnContext(ctx, "provisioning token last use not recorded", slog.String("token", tok.ID),
				slog.String("error", err.Error()))
		}
	}
	return Principal{
		TokenID: tok.ID, Name: tok.Name, Prefix: tok.Prefix, AllowedFQDNSuffixes: slices.Clone(tok.AllowedFQDNSuffixes),
		MaxStorageQuotaBytes: tok.MaxStorageQuotaBytes, MaxTransferBytes: tok.MaxTransferBytes, MaxTenants: tok.MaxTenants,
	}, nil
}
