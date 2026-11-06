package droplink

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
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

// Bounds of a link (OpenAPI DropLinkCreate).
const (
	// MaxLabelLen bounds the label, in characters.
	MaxLabelLen = store.MaxDropLinkLabelLen
	// MaxRecipients bounds the number of recipients.
	MaxRecipients = store.MaxDropLinkRecipients
	// MaxRecipientLen bounds one recipient, in bytes (the longest mail
	// address).
	MaxRecipientLen = 254
	// DefaultDepositsPerHour is the hourly deposit cap of a link created
	// without one (threat model P63).
	DefaultDepositsPerHour = store.DefaultDropLinkDepositsPerHour
	// MaxDepositsPerHour bounds the hourly deposit cap of a link.
	MaxDepositsPerHour = store.MaxDropLinkDepositsPerHour
	// UnusedMonths is how long a link that is neither used nor created
	// stays before it is flagged as unused (threat model T-314): the
	// retention of the lifecycle task, store.DropLinkRetentionMonths.
	UnusedMonths = store.DropLinkRetentionMonths
)

// Unused reports whether the link l is flagged as unused at now (OpenAPI
// DropLink.unused): not revoked, and its last use, else its creation, is
// more than UnusedMonths calendar months before now (the month arithmetic
// of the lifecycle purges).
func Unused(l store.DropLink, now time.Time) bool {
	if l.Revoked() {
		return false
	}
	last := l.CreatedAt
	if l.LastUsedAt.After(last) {
		last = l.LastUsedAt
	}
	return last.Before(now.AddDate(0, -UnusedMonths, 0))
}

// CreateInput is a new link (OpenAPI DropLinkCreate).
type CreateInput struct {
	// Label names the link.
	Label string
	// Recipients are the internal addresses the deposits go to.
	Recipients []string
	// ValidityDays is the validity of the deposited transfers: 1, 7 or 30.
	ValidityDays int
	// ConfidentialityLevel is the key of a level of the tenant, "" for the
	// default level.
	ConfidentialityLevel string
	// Enabled is whether the link accepts deposits; nil means true.
	Enabled *bool
	// ExpiresAt is the end of the link, which must be in the future; nil
	// for none.
	ExpiresAt *time.Time
	// MaxDepositsPerHour is the hourly deposit cap (1 to
	// MaxDepositsPerHour); nil means DefaultDepositsPerHour.
	MaxDepositsPerHour *int
}

// UpdateInput is a change of a link (OpenAPI DropLinkUpdate, merge patch):
// a nil field keeps its value.
type UpdateInput struct {
	// Label is the new label, nil to keep it.
	Label *string
	// Recipients replace the recipients, nil to keep them.
	Recipients []string
	// ValidityDays is the new validity, nil to keep it.
	ValidityDays *int
	// LevelSet tells that ConfidentialityLevel is changed; false keeps it.
	LevelSet bool
	// ConfidentialityLevel is the new level key when LevelSet, "" (JSON
	// null) for the default level.
	ConfidentialityLevel string
	// Enabled enables or disables the link, nil to keep it.
	Enabled *bool
	// ExpiresSet tells that ExpiresAt is changed; false keeps it.
	ExpiresSet bool
	// ExpiresAt is the new end of the link when ExpiresSet, in the future,
	// or the zero time (JSON null) to remove the expiry.
	ExpiresAt time.Time
	// MaxDepositsPerHour is the new hourly deposit cap, nil to keep it.
	MaxDepositsPerHour *int
}

// Created is a link just created or rotated, with its token.
type Created struct {
	// Link is the stored record.
	Link store.DropLink
	// Token is the token itself, returned this once only.
	Token string
	// URL is the landing page of the link on the host of the tenant.
	URL string
}

// checkLabel validates a label and returns it trimmed.
func checkLabel(raw string) (string, error) {
	label := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(label)
	if n == 0 || n > MaxLabelLen || !utf8.ValidString(label) {
		return "", invalid(FieldLabel, "must be 1 to %d characters", MaxLabelLen)
	}
	if strings.ContainsFunc(label, func(r rune) bool {
		return textsafe.IsControl(r) || textsafe.IsBidiControl(r) || textsafe.IsLineSeparator(r)
	}) {
		return "", invalid(FieldLabel, "must not contain control characters")
	}
	return label, nil
}

// checkRecipients validates the recipients (1 to MaxRecipients, strict
// address syntax [mail.ParseAddress], normalized like the store, distinct,
// each in an internal mail domain of the tenant) and returns them
// normalized.
func (s *Service) checkRecipients(ctx context.Context, tid tenant.ID, raw []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > MaxRecipients {
		return nil, invalid(FieldRecipients, "must hold 1 to %d addresses", MaxRecipients)
	}
	rules, err := s.repo.networkRules(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("droplink: read network rules: %w", err)
	}
	nr := netpolicy.Rules{Domains: rules.Domains}
	out := make([]string, len(raw))
	seen := make(map[string]bool, len(raw))
	for i, item := range raw {
		field := FieldRecipients + "/" + strconv.Itoa(i)
		item = strings.TrimSpace(item)
		if item == "" || len(item) > MaxRecipientLen {
			return nil, invalid(field, "must be 1 to %d characters", MaxRecipientLen)
		}
		v, err := normalizeAddress(item)
		if err != nil {
			return nil, invalid(field, "must be a mail address")
		}
		if !netpolicy.DomainInternal(nr, v) {
			return nil, invalid(field, "must belong to an internal mail domain of the entity")
		}
		if seen[v] {
			return nil, invalid(field, "duplicate address")
		}
		seen[v] = true
		out[i] = v
	}
	return out, nil
}

// normalizeAddress parses a recipient with the strict syntax of the
// recipients ([mail.ParseAddress], threat T-80) and normalizes it like the
// store.
func normalizeAddress(item string) (string, error) {
	addr, err := mail.ParseAddress(item)
	if err != nil {
		return "", err
	}
	return store.NormalizeEmail(addr)
}

// checkExpiry checks that a new expiry is after now.
func checkExpiry(at, now time.Time) error {
	if !at.After(now) {
		return invalid(FieldExpiresAt, "must be in the future")
	}
	return nil
}

// checkPerHour checks an hourly deposit cap.
func checkPerHour(n int) error {
	if n < 1 || n > MaxDepositsPerHour {
		return invalid(FieldMaxPerHour, "must be 1 to %d", MaxDepositsPerHour)
	}
	return nil
}

// expiryDetail renders an expiry for the audit details: RFC 3339 UTC, or
// nil for none.
func expiryDetail(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return at.UTC().Format(time.RFC3339)
}

// checkValidity checks that days is allowed by the level key of the tenant
// ("" for its default level) and that the level exists.
func (s *Service) checkValidity(ctx context.Context, tid tenant.ID, key string, days int) error {
	levels, err := s.repo.levels(ctx, tid)
	if err != nil {
		return fmt.Errorf("droplink: read confidentiality levels: %w", err)
	}
	var level *store.ConfidentialityLevel
	for i := range levels {
		if (key == "" && levels[i].IsDefault) || (key != "" && levels[i].Key == key) {
			level = &levels[i]
			break
		}
	}
	if level == nil {
		return invalid(FieldLevel, "unknown level")
	}
	if !level.Rules.AllowsExpiry(days) {
		return invalid(FieldValidity, "not allowed by the confidentiality level")
	}
	return nil
}

// List returns every link of tenant tid, revoked ones included, newest
// first, without their tokens. An auditor attached to the tenant may read.
func (s *Service) List(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]store.DropLink, error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return nil, err
	}
	list, err := s.repo.list(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("droplink: list: %w", err)
	}
	return list, nil
}

// Get returns the link linkID of tenant tid, without its token. An auditor
// attached to the tenant may read.
func (s *Service) Get(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string) (store.DropLink, error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.DropLink{}, err
	}
	if !id.Valid(id.DropLink, linkID) {
		return store.DropLink{}, ErrNotFound
	}
	l, err := s.repo.get(ctx, tid, linkID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.DropLink{}, ErrNotFound
	case err != nil:
		return store.DropLink{}, fmt.Errorf("droplink: get: %w", err)
	}
	return l, nil
}

// Create creates a link of tenant tid and returns it with its token and
// URL, which are never available again. The creator is the identifier of
// the administrator. It records drop_link.created with the label (unless
// it holds an at sign), the number of recipients, the validity, the level,
// the enabled state, the expiry and the hourly cap, never the token, its
// hash or the recipients.
func (s *Service) Create(ctx context.Context, p adminauth.Principal, tid tenant.ID, in CreateInput, ip netip.Addr) (Created, error) {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return Created{}, err
	}
	label, err := checkLabel(in.Label)
	if err != nil {
		return Created{}, err
	}
	recipients, err := s.checkRecipients(ctx, tid, in.Recipients)
	if err != nil {
		return Created{}, err
	}
	if err := s.checkValidity(ctx, tid, in.ConfidentialityLevel, in.ValidityDays); err != nil {
		return Created{}, err
	}
	now := s.now()
	var expires time.Time
	if in.ExpiresAt != nil {
		if err := checkExpiry(*in.ExpiresAt, now); err != nil {
			return Created{}, err
		}
		expires = *in.ExpiresAt
	}
	perHour := DefaultDepositsPerHour
	if in.MaxDepositsPerHour != nil {
		if err := checkPerHour(*in.MaxDepositsPerHour); err != nil {
			return Created{}, err
		}
		perHour = *in.MaxDepositsPerHour
	}
	tok, err := s.newToken()
	if err != nil {
		return Created{}, fmt.Errorf("droplink: generate: %w", err)
	}
	enabled := in.Enabled == nil || *in.Enabled
	l, err := s.repo.create(ctx, tid, store.DropLink{
		ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: label, Recipients: recipients,
		ValidityDays: in.ValidityDays, ConfidentialityLevel: in.ConfidentialityLevel, Enabled: enabled,
		CreatedBy: p.Admin.ID, CreatedAt: now, ExpiresAt: expires, MaxDepositsPerHour: perHour,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Created{}, ErrNotFound
	case errors.Is(err, store.ErrLimitReached):
		return Created{}, ErrLimitReached
	case errors.Is(err, store.ErrInvalid):
		return Created{}, invalid("", "rejected")
	case err != nil:
		return Created{}, fmt.Errorf("droplink: create: %w", err)
	}
	details := labelDetail(l.Label)
	details["recipientCount"] = len(l.Recipients)
	details["validityDays"] = l.ValidityDays
	details["confidentialityLevel"] = l.ConfidentialityLevel
	details["enabled"] = l.Enabled
	details["expiresAt"] = expiryDetail(l.ExpiresAt)
	details["maxDepositsPerHour"] = l.MaxDepositsPerHour
	s.record(ctx, p, ip, tid, audit.ActionDropLinkCreated, l.ID, details)
	return Created{Link: l, Token: tok, URL: id.DropURL(t.FQDN, tok)}, nil
}

// Update changes the link linkID of tenant tid (a nil field is kept) and
// returns it. A revoked link is ErrStateConflict. Recipients must be
// internal addresses; a validity or level change is checked against the
// rules of the resulting level; a new expiry must be in the future (the
// zero time removes it, which makes an expired link usable again). It
// records drop_link.updated with the changed fields and the new counts
// (never the recipients); an update changing nothing records nothing.
func (s *Service) Update(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string, in UpdateInput, ip netip.Addr) (store.DropLink, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return store.DropLink{}, err
	}
	if !id.Valid(id.DropLink, linkID) {
		return store.DropLink{}, ErrNotFound
	}
	cur, err := s.repo.get(ctx, tid, linkID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.DropLink{}, ErrNotFound
	case err != nil:
		return store.DropLink{}, fmt.Errorf("droplink: get: %w", err)
	}
	// The audit details list only the fields whose value changes.
	var u store.DropLinkUpdate
	details := map[string]any{}
	if in.Label != nil {
		label, err := checkLabel(*in.Label)
		if err != nil {
			return store.DropLink{}, err
		}
		u.Label = label
		if label != cur.Label {
			maps.Copy(details, labelDetail(label))
		}
	}
	if in.Recipients != nil {
		recipients, err := s.checkRecipients(ctx, tid, in.Recipients)
		if err != nil {
			return store.DropLink{}, err
		}
		u.Recipients = recipients
		if !slices.Equal(slices.Sorted(slices.Values(recipients)), slices.Sorted(slices.Values(cur.Recipients))) {
			details["recipientCount"] = len(recipients)
		}
	}
	level := cur.ConfidentialityLevel
	if in.LevelSet {
		level = in.ConfidentialityLevel
		u.ConfidentialityLevel = &level
		if level != cur.ConfidentialityLevel {
			details["confidentialityLevel"] = level
		}
	}
	days := cur.ValidityDays
	if in.ValidityDays != nil {
		days = *in.ValidityDays
		u.ValidityDays = days
		if days != cur.ValidityDays {
			details["validityDays"] = days
		}
	}
	// An enabled link always has a validity its level allows: checked
	// when the level or the validity changes, and when the link is
	// (re-)enabled, the level having possibly changed meanwhile.
	if in.LevelSet || in.ValidityDays != nil || (in.Enabled != nil && *in.Enabled) {
		if err := s.checkValidity(ctx, tid, level, days); err != nil {
			return store.DropLink{}, err
		}
	}
	if in.Enabled != nil {
		u.Enabled = in.Enabled
		if *in.Enabled != cur.Enabled {
			details["enabled"] = *in.Enabled
		}
	}
	now := s.now()
	if in.ExpiresSet {
		if !in.ExpiresAt.IsZero() {
			if err := checkExpiry(in.ExpiresAt, now); err != nil {
				return store.DropLink{}, err
			}
		}
		expires := in.ExpiresAt
		u.ExpiresAt = &expires
		if !expires.Truncate(time.Millisecond).Equal(cur.ExpiresAt) {
			details["expiresAt"] = expiryDetail(expires)
		}
	}
	if in.MaxDepositsPerHour != nil {
		if err := checkPerHour(*in.MaxDepositsPerHour); err != nil {
			return store.DropLink{}, err
		}
		u.MaxDepositsPerHour = *in.MaxDepositsPerHour
		if *in.MaxDepositsPerHour != cur.MaxDepositsPerHour {
			details["maxDepositsPerHour"] = *in.MaxDepositsPerHour
		}
	}
	l, changed, err := s.repo.update(ctx, tid, linkID, u, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.DropLink{}, ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return store.DropLink{}, ErrStateConflict
	case errors.Is(err, store.ErrInvalid):
		return store.DropLink{}, invalid("", "rejected")
	case err != nil:
		return store.DropLink{}, fmt.Errorf("droplink: update: %w", err)
	}
	if changed {
		s.record(ctx, p, ip, tid, audit.ActionDropLinkUpdated, l.ID, details)
	}
	return l, nil
}

// Rotate replaces the token of the link linkID of tenant tid: the previous
// token stops working at once. It returns the link with its new token and
// URL. A revoked link is ErrStateConflict. It records drop_link.rotated
// with the label (unless it holds an at sign), never a token or hash.
func (s *Service) Rotate(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string, ip netip.Addr) (Created, error) {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return Created{}, err
	}
	if !id.Valid(id.DropLink, linkID) {
		return Created{}, ErrNotFound
	}
	tok, err := s.newToken()
	if err != nil {
		return Created{}, fmt.Errorf("droplink: generate: %w", err)
	}
	l, err := s.repo.rotate(ctx, tid, linkID, id.HashToken(tok), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Created{}, ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return Created{}, ErrStateConflict
	case err != nil:
		return Created{}, fmt.Errorf("droplink: rotate: %w", err)
	}
	s.record(ctx, p, ip, tid, audit.ActionDropLinkRotated, l.ID, labelDetail(l.Label))
	return Created{Link: l, Token: tok, URL: id.DropURL(t.FQDN, tok)}, nil
}

// Revoke revokes the link linkID of tenant tid: it is refused from now on.
// Revoking a link already revoked changes nothing and records nothing;
// otherwise it records drop_link.revoked with the label (unless it holds
// an at sign).
func (s *Service) Revoke(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string, ip netip.Addr) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	if !id.Valid(id.DropLink, linkID) {
		return ErrNotFound
	}
	l, revoked, err := s.repo.revoke(ctx, tid, linkID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("droplink: revoke: %w", err)
	}
	if revoked {
		s.record(ctx, p, ip, tid, audit.ActionDropLinkRevoked, l.ID, labelDetail(l.Label))
	}
	return nil
}

// labelDetail returns the audit details holding the label of a link, or
// none when the label holds an at sign: the audit log keeps mail addresses
// in its actor column only.
func labelDetail(label string) map[string]any {
	if strings.Contains(label, "@") {
		return map[string]any{}
	}
	return map[string]any{"label": label}
}
