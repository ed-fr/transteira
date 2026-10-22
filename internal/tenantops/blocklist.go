package tenantops

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Bounds of a blocklist entry (OpenAPI BlocklistEntryCreate).
const (
	// MaxBlocklistValueLen bounds the value, in characters.
	MaxBlocklistValueLen = 320
	// MaxBlocklistCommentLen bounds the comment, in characters.
	MaxBlocklistCommentLen = 500
)

// Values of the "op" detail of the blocklist.updated audit events.
const (
	blocklistOpCreated = "created"
	blocklistOpDeleted = "deleted"
)

// BlocklistFilter selects a page of blocklist entries (OpenAPI
// listBlocklist).
type BlocklistFilter struct {
	// Kind keeps the entries of this kind ("" for all).
	Kind string
	// Cursor is the nextCursor of the previous page, "" for the first.
	Cursor string
	// Limit is the page size, 0 for store.DefaultPageSize.
	Limit int
}

// BlocklistInput is a new blocklist entry (OpenAPI BlocklistEntryCreate).
type BlocklistInput struct {
	Kind    string
	Value   string
	Comment string
}

// validKind reports whether k is a blocklist kind.
func validKind(k store.BlocklistKind) bool {
	switch k {
	case store.BlockEmail, store.BlockDomain, store.BlockSHA256:
		return true
	}
	return false
}

// ListBlocklist returns a page of the blocklist entries of tenant tid.
func (s *Service) ListBlocklist(ctx context.Context, p adminauth.Principal, tid tenant.ID, f BlocklistFilter) (store.Page[store.BlocklistEntry], error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.Page[store.BlocklistEntry]{}, err
	}
	kind := store.BlocklistKind(f.Kind)
	if f.Kind != "" && !validKind(kind) {
		return store.Page[store.BlocklistEntry]{}, invalid(FieldKindParam, "unknown blocklist kind")
	}
	if err := checkLimit(f.Limit); err != nil {
		return store.Page[store.BlocklistEntry]{}, err
	}
	page, err := s.repo.listBlocklist(ctx, tid, store.BlocklistFilter{Kind: kind, Cursor: f.Cursor, Limit: f.Limit})
	if err != nil {
		return store.Page[store.BlocklistEntry]{}, listError("list blocklist", err)
	}
	return page, nil
}

// CreateBlocklistEntry adds an entry to the blocklist of tenant tid. The
// value is trimmed and lowercased, then validated for its kind: a mail
// address, a domain name, or a SHA-256 fingerprint of 64 hexadecimal
// characters. A value already listed for the kind is ErrAlreadyExists. The
// creator is the username of the administrator. It records
// blocklist.updated with the kind and the entry ID, plus the value for a
// domain or a fingerprint only (never a mail address).
func (s *Service) CreateBlocklistEntry(ctx context.Context, p adminauth.Principal, tid tenant.ID, in BlocklistInput, ip netip.Addr) (store.BlocklistEntry, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return store.BlocklistEntry{}, err
	}
	kind := store.BlocklistKind(in.Kind)
	if !validKind(kind) {
		return store.BlocklistEntry{}, invalid(FieldKind, "must be email, domain or sha256")
	}
	value := strings.ToLower(strings.TrimSpace(in.Value))
	if value == "" || utf8.RuneCountInString(value) > MaxBlocklistValueLen {
		return store.BlocklistEntry{}, invalid(FieldValue, "must be 1 to %d characters", MaxBlocklistValueLen)
	}
	if _, err := kind.Normalize(value); err != nil {
		return store.BlocklistEntry{}, invalid(FieldValue, "malformed %s", kind)
	}
	if !utf8.ValidString(in.Comment) || utf8.RuneCountInString(in.Comment) > MaxBlocklistCommentLen {
		return store.BlocklistEntry{}, invalid(FieldComment, "must be text of at most %d characters", MaxBlocklistCommentLen)
	}
	e, err := s.repo.createBlocklistEntry(ctx, tid, store.BlocklistEntry{
		Kind: kind, Value: value, Comment: in.Comment, CreatedBy: p.Admin.Username,
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return store.BlocklistEntry{}, ErrAlreadyExists
	case err != nil:
		return store.BlocklistEntry{}, fmt.Errorf("tenantops: create blocklist entry: %w", err)
	}
	s.record(ctx, p, ip, tid, audit.ActionBlocklistUpdated, audit.ObjectBlocklistEntry, e.ID,
		blocklistDetails(blocklistOpCreated, e))
	return e, nil
}

// DeleteBlocklistEntry removes the entry entryID from the blocklist of
// tenant tid. It records blocklist.updated like [Service.CreateBlocklistEntry].
func (s *Service) DeleteBlocklistEntry(ctx context.Context, p adminauth.Principal, tid tenant.ID, entryID string, ip netip.Addr) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	if !id.Valid(id.Blocklist, entryID) {
		return ErrNotFound
	}
	e, err := s.repo.getBlocklistEntry(ctx, tid, entryID)
	if err == nil {
		err = s.repo.deleteBlocklistEntry(ctx, tid, entryID)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("tenantops: delete blocklist entry: %w", err)
	}
	s.record(ctx, p, ip, tid, audit.ActionBlocklistUpdated, audit.ObjectBlocklistEntry, entryID,
		blocklistDetails(blocklistOpDeleted, e))
	return nil
}

// blocklistDetails returns the audit details of a change of entry e: the
// operation, the kind and the entry ID, plus the value unless it is a mail
// address.
func blocklistDetails(op string, e store.BlocklistEntry) map[string]any {
	d := map[string]any{"op": op, "kind": string(e.Kind), "entryId": e.ID}
	if e.Kind != store.BlockEmail {
		d["value"] = e.Value
	}
	return d
}
