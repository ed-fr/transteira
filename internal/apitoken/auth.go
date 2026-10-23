package apitoken

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Principal is the API token that authenticated a request.
type Principal struct {
	// TokenID is the token identifier ("tok_" + ULID), for the ownership
	// of the transfers, the audit log and the security log.
	TokenID string
	// Name is the label of the token.
	Name string
	// AllowedCIDRs are the ranges the token may be used from.
	AllowedCIDRs []netip.Prefix
}

// Authenticate checks the Authorization header of a request served on the
// host of tenant tid, coming from clientIP (the real client IP, read from
// the trusted proxies only). The checks run in this order, so that the
// answer to an unknown token never depends on the client IP:
//
//  1. no bearer token: ErrMissing;
//  2. a malformed token, or one that is unknown on this tenant (a token of
//     another tenant included, T-69), revoked or expired: ErrInvalid;
//  3. a client IP outside the allowed ranges of the token (an invalid IP
//     matches none): ErrIPNotAllowed, returned with the Principal so that
//     the caller can log the token.
//
// On success it records the use of the token, at most once per
// TouchInterval per token; a failure of that write is logged, not
// returned. Any other error is an internal failure of the store.
func (s *Service) Authenticate(ctx context.Context, tid tenant.ID, header string, clientIP netip.Addr) (Principal, error) {
	secret, err := ParseAuthorization(header)
	if err != nil {
		return Principal{}, err
	}
	hash := hashOf(secret)
	tok, err := s.repo.getByHash(ctx, tid, hash)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return Principal{}, ErrInvalid
	case err != nil:
		return Principal{}, fmt.Errorf("apitoken: authenticate: %w", err)
	}
	now := s.now()
	// The lookup compared the hashes already; comparing them again in
	// constant time keeps the decision independent of the database
	// collation and timing.
	if subtle.ConstantTimeCompare(tok.TokenHash, hash) != 1 || !tok.Usable(now) {
		return Principal{}, ErrInvalid
	}
	p := Principal{TokenID: tok.ID, Name: tok.Name, AllowedCIDRs: tok.AllowedCIDRs}
	if !netpolicy.Contains(tok.AllowedCIDRs, clientIP) {
		return p, ErrIPNotAllowed
	}
	if s.due(tok.ID, now) {
		if err := s.repo.touch(ctx, tid, tok.ID, now); err != nil {
			s.logger.WarnContext(ctx, "api token last use not recorded", slog.String("tenant", string(tid)),
				slog.String("token", tok.ID), slog.String("error", err.Error()))
		}
	}
	return p, nil
}

// due reports whether the use of token tokID at now must be recorded, and
// remembers it when so: the first use seen by this process, then at most
// one per TouchInterval. The memory is bounded by MaxTracked: when it is
// full, the entries older than the interval are dropped, and if none is,
// all of them (the next uses are then recorded again, which is harmless).
func (s *Service) due(tokID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.touched[tokID]; ok && now.Sub(last) < s.touchInterval && !now.Before(last) {
		return false
	}
	if _, ok := s.touched[tokID]; !ok && len(s.touched) >= s.maxTracked {
		for k, at := range s.touched {
			if now.Sub(at) >= s.touchInterval {
				delete(s.touched, k)
			}
		}
		if len(s.touched) >= s.maxTracked {
			clear(s.touched)
		}
	}
	s.touched[tokID] = now
	return true
}

// forget drops the throttling memory of token tokID (revoked).
func (s *Service) forget(tokID string) {
	s.mu.Lock()
	delete(s.touched, tokID)
	s.mu.Unlock()
}
