package apitoken

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Bounds of a token (OpenAPI ApiTokenCreate, AllowedCidrs).
const (
	// MaxNameLen bounds the name, in characters.
	MaxNameLen = store.MaxAPITokenNameLen
	// MaxCIDRs bounds the number of allowed ranges.
	MaxCIDRs = store.MaxAPITokenCIDRs
	// MaxCIDRLen bounds one range, in characters (an IPv6 prefix in full
	// form with its length).
	MaxCIDRLen = 43
	// MaxSenders bounds the number of allowed senders.
	MaxSenders = store.MaxAPITokenSenders
	// MaxSenderLen bounds one allowed sender, in bytes (the longest mail
	// address).
	MaxSenderLen = 254
)

// CreateInput is a new token (OpenAPI ApiTokenCreate).
type CreateInput struct {
	// Name is the label of the token.
	Name string
	// AllowedCIDRs are the IP ranges the token may be used from.
	AllowedCIDRs []string
	// AllowedSenders are the optional sender addresses and domains the
	// token may deposit as; nil or empty allows any internal address.
	AllowedSenders []string
	// ExpiresAt is the optional expiry, zero for none.
	ExpiresAt time.Time
}

// UpdateInput is a change of a token (OpenAPI ApiTokenUpdate, merge
// patch): a nil field keeps its value.
type UpdateInput struct {
	// Name is the new name, nil to keep it.
	Name *string
	// AllowedCIDRs replace the allowed ranges, nil to keep them.
	AllowedCIDRs []string
	// AllowedSenders replace the allowed senders, nil to keep them; an
	// empty non-nil slice allows any internal address again.
	AllowedSenders []string
}

// Created is a token just created, with its secret.
type Created struct {
	// Token is the stored record.
	Token store.APIToken
	// Secret is the token itself, returned this once only.
	Secret string
}

// checkName validates a token name and returns it trimmed.
func checkName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(name)
	if n == 0 || n > MaxNameLen || !utf8.ValidString(name) {
		return "", invalid(FieldName, "must be 1 to %d characters", MaxNameLen)
	}
	if strings.ContainsFunc(name, func(r rune) bool {
		return textsafe.IsControl(r) || textsafe.IsBidiControl(r) || textsafe.IsLineSeparator(r)
	}) {
		return "", invalid(FieldName, "must not contain control characters")
	}
	return name, nil
}

// checkCIDRs validates the allowed ranges ([netpolicy.ParsePrefix]: a bare
// address is a single host, host bits must be zero, no IPv6 zone,
// IPv4-mapped prefixes become IPv4) and returns them normalized. A range
// appearing twice once normalized is refused.
func checkCIDRs(raw []string) ([]netip.Prefix, error) {
	if len(raw) == 0 || len(raw) > MaxCIDRs {
		return nil, invalid(FieldAllowedCIDRs, "must hold 1 to %d ranges", MaxCIDRs)
	}
	out := make([]netip.Prefix, len(raw))
	seen := make(map[netip.Prefix]bool, len(raw))
	for i, item := range raw {
		field := FieldAllowedCIDRs + "/" + strconv.Itoa(i)
		item = strings.TrimSpace(item)
		if len(item) > MaxCIDRLen {
			return nil, invalid(field, "must be at most %d characters", MaxCIDRLen)
		}
		p, err := netpolicy.ParsePrefix(item)
		if err != nil {
			return nil, invalid(field, "%v", err)
		}
		if seen[p] {
			return nil, invalid(field, "duplicate range")
		}
		seen[p] = true
		out[i] = p
	}
	return out, nil
}

// checkSenders validates the allowed senders and returns them normalized,
// never nil. An entry holding an at sign is a full address, checked with
// the strict syntax of the recipients ([mail.ParseAddress], threat T-80)
// and normalized like the store ([store.NormalizeEmail]); any other entry
// is a mail domain, normalized to lowercase punycode without trailing dot
// ([store.BlockDomain]). An entry appearing twice once normalized is
// refused.
func checkSenders(raw []string) ([]string, error) {
	if len(raw) > MaxSenders {
		return nil, invalid(FieldAllowedSenders, "must hold at most %d entries", MaxSenders)
	}
	out := make([]string, len(raw))
	seen := make(map[string]bool, len(raw))
	for i, item := range raw {
		field := FieldAllowedSenders + "/" + strconv.Itoa(i)
		item = strings.TrimSpace(item)
		if item == "" || len(item) > MaxSenderLen {
			return nil, invalid(field, "must be 1 to %d characters", MaxSenderLen)
		}
		v, ok := normalizeSender(item)
		if !ok {
			return nil, invalid(field, "must be a mail address or a mail domain")
		}
		if seen[v] {
			return nil, invalid(field, "duplicate entry")
		}
		seen[v] = true
		out[i] = v
	}
	return out, nil
}

// normalizeSender returns the normalized form of one allowed sender (see
// checkSenders).
func normalizeSender(item string) (string, bool) {
	if strings.Contains(item, "@") {
		addr, err := mail.ParseAddress(item)
		if err != nil {
			return "", false
		}
		v, err := store.NormalizeEmail(addr)
		return v, err == nil
	}
	if strings.ContainsFunc(item, unicode.IsSpace) {
		return "", false
	}
	v, err := store.BlockDomain.Normalize(item)
	return v, err == nil
}

// List returns every token of tenant tid, revoked ones included, newest
// first, without their secrets.
func (s *Service) List(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]store.APIToken, error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return nil, err
	}
	list, err := s.repo.list(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("apitoken: list: %w", err)
	}
	return list, nil
}

// Create creates a token of tenant tid and returns it with its secret,
// which is never available again. The creator is the username of the
// administrator. It records api_token.created with the name (unless it
// holds an at sign), the number of ranges, the number of allowed senders
// (never the senders themselves: they are mail addresses) and the expiry,
// never the secret or its hash.
func (s *Service) Create(ctx context.Context, p adminauth.Principal, tid tenant.ID, in CreateInput, ip netip.Addr) (Created, error) {
	if err := s.writable(ctx, p, tid); err != nil {
		return Created{}, err
	}
	name, err := checkName(in.Name)
	if err != nil {
		return Created{}, err
	}
	cidrs, err := checkCIDRs(in.AllowedCIDRs)
	if err != nil {
		return Created{}, err
	}
	senders, err := checkSenders(in.AllowedSenders)
	if err != nil {
		return Created{}, err
	}
	now := s.now()
	if !in.ExpiresAt.IsZero() && !in.ExpiresAt.After(now) {
		return Created{}, invalid(FieldExpiresAt, "must be in the future")
	}
	gen, err := Generate()
	if err != nil {
		return Created{}, fmt.Errorf("apitoken: generate: %w", err)
	}
	tok, err := s.repo.create(ctx, tid, store.APIToken{
		ID: id.New(id.APIToken), Name: name, Prefix: gen.Prefix, TokenHash: gen.Hash, AllowedCIDRs: cidrs,
		AllowedSenders: senders, CreatedBy: p.Admin.Username, CreatedAt: now, ExpiresAt: in.ExpiresAt,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Created{}, ErrNotFound
	case err != nil:
		return Created{}, fmt.Errorf("apitoken: create: %w", err)
	}
	details := nameDetail(tok.Name)
	details["cidrCount"] = len(tok.AllowedCIDRs)
	details["senderCount"] = len(tok.AllowedSenders)
	if !tok.ExpiresAt.IsZero() {
		details["expiresAt"] = tok.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.record(ctx, p, ip, tid, audit.ActionAPITokenCreated, tok.ID, details)
	return Created{Token: tok, Secret: gen.Secret}, nil
}

// Update renames the token tokID of tenant tid or replaces its allowed
// ranges or senders (a nil field is kept) and returns it. A revoked token
// is ErrStateConflict. It records api_token.updated with the changed
// fields, the new name (unless it holds an at sign), the new number of
// ranges and the new number of allowed senders (never the senders); an
// update changing no field records nothing.
func (s *Service) Update(ctx context.Context, p adminauth.Principal, tid tenant.ID, tokID string, in UpdateInput, ip netip.Addr) (store.APIToken, error) {
	if err := s.writable(ctx, p, tid); err != nil {
		return store.APIToken{}, err
	}
	if !id.Valid(id.APIToken, tokID) {
		return store.APIToken{}, ErrNotFound
	}
	var (
		u      store.APITokenUpdate
		fields []string
	)
	details := map[string]any{}
	if in.Name != nil {
		name, err := checkName(*in.Name)
		if err != nil {
			return store.APIToken{}, err
		}
		u.Name = name
		fields = append(fields, "name")
		details = nameDetail(name)
	}
	if in.AllowedCIDRs != nil {
		cidrs, err := checkCIDRs(in.AllowedCIDRs)
		if err != nil {
			return store.APIToken{}, err
		}
		u.AllowedCIDRs = cidrs
		fields = append(fields, "allowedCidrs")
		details["cidrCount"] = len(cidrs)
	}
	if in.AllowedSenders != nil {
		senders, err := checkSenders(in.AllowedSenders)
		if err != nil {
			return store.APIToken{}, err
		}
		u.AllowedSenders = senders
		fields = append(fields, "allowedSenders")
		details["senderCount"] = len(senders)
	}
	tok, err := s.repo.update(ctx, tid, tokID, u)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.APIToken{}, ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return store.APIToken{}, ErrStateConflict
	case err != nil:
		return store.APIToken{}, fmt.Errorf("apitoken: update: %w", err)
	}
	if len(fields) > 0 {
		details["fields"] = fields
		s.record(ctx, p, ip, tid, audit.ActionAPITokenUpdated, tok.ID, details)
	}
	return tok, nil
}

// Revoke revokes the token tokID of tenant tid: it is refused from now on.
// Revoking a token already revoked changes nothing and records nothing;
// otherwise it records api_token.revoked with the name (unless it holds an
// at sign).
func (s *Service) Revoke(ctx context.Context, p adminauth.Principal, tid tenant.ID, tokID string, ip netip.Addr) error {
	if err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	if !id.Valid(id.APIToken, tokID) {
		return ErrNotFound
	}
	tok, revoked, err := s.repo.revoke(ctx, tid, tokID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("apitoken: revoke: %w", err)
	}
	if revoked {
		s.forget(tok.ID)
		s.record(ctx, p, ip, tid, audit.ActionAPITokenRevoked, tok.ID, nameDetail(tok.Name))
	}
	return nil
}

// nameDetail returns the audit details holding the name of a token, or
// none when the name holds an at sign: the audit log keeps mail addresses
// in its actor column only.
func nameDetail(name string) map[string]any {
	if strings.Contains(name, "@") {
		return map[string]any{}
	}
	return map[string]any{"name": name}
}
