package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of a permanent drop link (since 2.0, OpenAPI DropLink).
const (
	// MaxDropLinks is the maximum number of drop links of a tenant,
	// revoked ones included until they are purged (OpenAPI
	// drop-link-limit-reached).
	MaxDropLinks = 100
	// MaxDropLinkLabelLen bounds the label of a link, in characters.
	MaxDropLinkLabelLen = 100
	// MaxDropLinkRecipients bounds the recipients of a link.
	MaxDropLinkRecipients = 20
	// maxDropLinkCreatedByLen bounds the admin identifier recorded as the
	// creator (the column check).
	maxDropLinkCreatedByLen = 64
	// dropLinkTouchInterval is the shortest interval between two writes
	// of the last use of a link.
	dropLinkTouchInterval = time.Minute
	// DropLinkRetentionMonths is the 12-month rule of the drop links
	// (spec 20, threat model T-314), in calendar months: a link neither
	// used nor created for that long is flagged as unused, and a revoked or
	// expired link is purged that long after its end. One constant for
	// both, so that they cannot drift apart.
	DropLinkRetentionMonths = 12
	// DefaultDropLinkDepositsPerHour is the hourly deposit cap of a link
	// created without one (threat model P63).
	DefaultDropLinkDepositsPerHour = 20
	// MaxDropLinkDepositsPerHour bounds the hourly deposit cap of a link.
	MaxDropLinkDepositsPerHour = 1000
)

// dropLinkColumns is the column list read by the drop link queries.
const dropLinkColumns = `id, token_hash, label, recipients, validity_days, confidentiality_level, enabled, ` +
	`created_by, created_at, updated_at, last_used_at, revoked_at, expires_at, max_deposits_per_hour`

// Statements of the DropLinks repository.
var (
	qDropLinkInsert = tenantQuery(
		`INSERT INTO drop_links (tenant_id, id, token_hash, label, recipients, validity_days, confidentiality_level,
		enabled, created_by, created_at, updated_at, expires_at, max_deposits_per_hour)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qDropLinkGet = tenantQuery(
		`SELECT ` + dropLinkColumns + ` FROM drop_links WHERE tenant_id = ? AND id = ?`)
	// qDropLinkGetByHash only returns a link that can be used: the last
	// argument is the current time, from which an expiry ends the link.
	qDropLinkGetByHash = tenantQuery(
		`SELECT ` + dropLinkColumns + ` FROM drop_links
		WHERE tenant_id = ? AND token_hash = ? AND enabled AND revoked_at IS NULL
		AND (expires_at IS NULL OR expires_at > ?)`)
	qDropLinkList = tenantQuery(
		`SELECT ` + dropLinkColumns + ` FROM drop_links WHERE tenant_id = ? ORDER BY created_at DESC, id DESC`)
	qDropLinkCount = tenantQuery(
		`SELECT count(*) FROM drop_links WHERE tenant_id = ?`)
	// qDropLinkCountID counts a link by identifier, for probe.
	qDropLinkCountID = tenantQuery(
		`SELECT count(*) FROM drop_links WHERE tenant_id = ? AND id = ?`)
	// qDropLinkUpdate only changes a link that is not revoked.
	qDropLinkUpdate = tenantQuery(
		`UPDATE drop_links SET label = ?, recipients = ?, validity_days = ?, confidentiality_level = ?, enabled = ?,
		expires_at = ?, max_deposits_per_hour = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`)
	// qDropLinkRotate only rotates a link that is not revoked.
	qDropLinkRotate = tenantQuery(
		`UPDATE drop_links SET token_hash = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`)
	// qDropLinkRevoke only revokes a link once.
	qDropLinkRevoke = tenantQuery(
		`UPDATE drop_links SET revoked_at = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`)
	// qDropLinkTouch writes the last use at most once per interval: the
	// last argument is the time before which a recorded use is replaced.
	qDropLinkTouch = tenantQuery(
		`UPDATE drop_links SET last_used_at = ?
		WHERE tenant_id = ? AND id = ? AND (last_used_at IS NULL OR last_used_at < ?)`)
	qDropLinkLevelExists = tenantQuery(
		`SELECT count(*) FROM confidentiality_levels WHERE tenant_id = ? AND key = ?`)
	// qDropLinkRecipients reads the recipient lists of the tenant (at most
	// MaxDropLinks rows), filtered by the caller: a JSON containment test
	// differs between the engines.
	qDropLinkRecipients = tenantQuery(
		`SELECT id, recipients FROM drop_links WHERE tenant_id = ? ORDER BY id`)
	// qDropLinkErase writes the recipient list left by an erasure, and
	// disables the link when it is empty (the second argument).
	qDropLinkErase = tenantQuery(
		`UPDATE drop_links SET recipients = ?, enabled = (enabled AND NOT ?), updated_at = ?
		WHERE tenant_id = ? AND id = ?`)
	// qDropLinkPurgeList lists the links revoked or expired before a time
	// (given twice).
	qDropLinkPurgeList = tenantQuery(
		`SELECT id FROM drop_links WHERE tenant_id = ? AND (revoked_at < ? OR expires_at < ?) AND id > ?
		ORDER BY id LIMIT ?`)
	qDropLinkPurge = tenantQuery(
		`DELETE FROM drop_links WHERE tenant_id = ? AND id = ? AND (revoked_at < ? OR expires_at < ?)`)
	qTransferCountByDropLink = tenantQuery(
		`SELECT count(*) FROM transfers WHERE tenant_id = ? AND drop_link_id = ?`)
)

// DropLink is a permanent drop link of a tenant (since 2.0, spec 22): a
// fixed address a service gives to third parties, who deposit files for
// its recipients after proving their own address by code at every use.
// The bearer token ("ttd_" + base62, [id.NewDropToken]) is shown at the
// creation and at each rotation only; the store keeps its SHA-256.
type DropLink struct {
	// ID is the identifier ("drl_" + ULID), assigned by the caller.
	ID string
	// TokenHash is the SHA-256 of the token ([id.HashToken], TokenHashSize
	// bytes), unique across tenants.
	TokenHash []byte
	// Label names the link for the admins and on its landing page (1 to
	// MaxDropLinkLabelLen characters on one line).
	Label string
	// Recipients are the internal addresses the deposits are addressed to,
	// normalized, distinct, in the order given: 1 to MaxDropLinkRecipients
	// for a new or enabled link. The store does not check the internal
	// domains (the caller does). A data-subject erasure may leave a link
	// without recipient ([DropLinks.RemoveRecipientTx]): it is then
	// disabled and can only be enabled again with new recipients.
	Recipients []string
	// ValidityDays is the validity of the transfers deposited through the
	// link: 1, 7 or 30 days.
	ValidityDays int
	// ConfidentialityLevel is the key of the level of the tenant applied
	// to the deposits, "" for the default rules. An enabled link always
	// refers to an existing level: the store checks it when the link is
	// created, changed or enabled, and [ConfidentialityLevels.Replace]
	// refuses to remove a level used by an enabled link.
	ConfidentialityLevel string
	// Enabled tells whether the link accepts deposits.
	Enabled bool
	// CreatedBy is the identifier of the admin who created the link (1 to
	// 64 characters on one line).
	CreatedBy string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// UpdatedAt is the time of the last change (creation, update, rotation,
	// revocation or erasure).
	UpdatedAt time.Time
	// LastUsedAt is the last recorded use ([DropLinks.TouchLastUsed]), zero
	// when never used.
	LastUsedAt time.Time
	// RevokedAt is the revocation time, zero while the link is not
	// revoked. A revoked link is kept (its transfers refer to it) and
	// purged 12 months later ([DropLinks.Purge]).
	RevokedAt time.Time
	// ExpiresAt is the optional end of the link (threat model P63), zero
	// for none. From then on the link behaves exactly like a revoked one
	// for the depositors, but the admins may still change it (a later
	// expiry, or none, makes it usable again). An expired link is purged
	// 12 months after its expiry, like a revoked one.
	ExpiresAt time.Time
	// MaxDepositsPerHour caps the transfers created through the link in the
	// sliding last hour, all depositors together (1 to
	// MaxDropLinkDepositsPerHour; 0 at creation means
	// DefaultDropLinkDepositsPerHour), on top of the external quotas.
	MaxDepositsPerHour int
}

// Revoked reports whether the link was revoked.
func (l DropLink) Revoked() bool { return !l.RevokedAt.IsZero() }

// Expired reports whether the link has an expiry reached at now.
func (l DropLink) Expired(now time.Time) bool {
	return !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt)
}

// Usable reports whether the link accepts deposits at now: enabled, not
// revoked and not expired. It is the rule of [DropLinks.GetByTokenHash]
// and of the checks made when a session, a challenge or a transfer is
// bound to the link.
func (l DropLink) Usable(now time.Time) bool { return l.Enabled && !l.Revoked() && !l.Expired(now) }

// DropLinkUpdate is a change of a drop link: a nil or zero field keeps its
// current value.
type DropLinkUpdate struct {
	// Label is the new label, "" to keep it.
	Label string
	// Recipients replace the recipients, nil to keep them (1 to
	// MaxDropLinkRecipients when given).
	Recipients []string
	// ValidityDays is the new validity, 0 to keep it.
	ValidityDays int
	// ConfidentialityLevel is the new level key, nil to keep it; a pointer
	// to "" selects the default rules.
	ConfidentialityLevel *string
	// Enabled enables or disables the link, nil to keep it.
	Enabled *bool
	// ExpiresAt is the new expiry, nil to keep it; a pointer to the zero
	// time removes the expiry.
	ExpiresAt *time.Time
	// MaxDepositsPerHour is the new hourly deposit cap, 0 to keep it (1 to
	// MaxDropLinkDepositsPerHour when given).
	MaxDepositsPerHour int
}

// DropLinkErasure is what [DropLinks.RemoveRecipientTx] did.
type DropLinkErasure struct {
	// Updated counts the links the address was removed from.
	Updated int
	// Disabled counts those of them left without recipient, hence
	// disabled (included in Updated; a link already disabled counts too).
	Disabled int
}

// DropLinks is the tenant-scoped repository of permanent drop links.
// Obtain it with [DB.DropLinks]. The writes that change the level or the
// enabled state of a link take the tenant lock, like
// [ConfidentialityLevels.Replace], so that an enabled link never refers to
// a level being removed.
type DropLinks struct {
	db *DB
}

// DropLinks returns the drop link repository.
func (db *DB) DropLinks() *DropLinks { return &DropLinks{db: db} }

// normalizeDropRecipients validates the recipients of a link (1 to
// MaxDropLinkRecipients distinct addresses, [NormalizeEmail]) and returns
// them normalized, in the order given, with their JSON text.
func normalizeDropRecipients(recipients []string) ([]string, string, error) {
	if len(recipients) == 0 || len(recipients) > MaxDropLinkRecipients {
		return nil, "", invalid("a drop link needs 1 to %d recipients", MaxDropLinkRecipients)
	}
	out := make([]string, len(recipients))
	seen := make(map[string]bool, len(recipients))
	for i, raw := range recipients {
		v, err := NormalizeEmail(raw)
		if err != nil {
			return nil, "", invalid("malformed drop link recipient")
		}
		if seen[v] {
			return nil, "", invalid("duplicate drop link recipient")
		}
		seen[v] = true
		out[i] = v
	}
	doc, _ := json.Marshal(out) // a []string always marshals
	return out, string(doc), nil
}

// recipientsDoc returns the JSON text of a normalized recipient list,
// "[]" for none.
func recipientsDoc(recipients []string) string {
	if len(recipients) == 0 {
		return "[]"
	}
	doc, _ := json.Marshal(recipients) // a []string always marshals
	return string(doc)
}

// validDropLinkLabel reports whether s is an acceptable link label.
func validDropLinkLabel(s string) bool {
	return s != "" && validText(s, MaxDropLinkLabelLen, true)
}

// scanDropLink reads one row of dropLinkColumns.
func scanDropLink(row interface{ Scan(...any) error }) (DropLink, error) {
	var (
		l                 DropLink
		recipients        string
		level             sql.NullString
		created, updated  int64
		lastUsed, revoked sql.NullInt64
		expires           sql.NullInt64
	)
	err := row.Scan(&l.ID, &l.TokenHash, &l.Label, &recipients, &l.ValidityDays, &level, &l.Enabled, &l.CreatedBy,
		&created, &updated, &lastUsed, &revoked, &expires, &l.MaxDepositsPerHour)
	if err != nil {
		return DropLink{}, err
	}
	if l.Recipients, err = parseSenders(recipients); err != nil {
		return DropLink{}, invalid("stored drop link recipients are malformed")
	}
	l.ConfidentialityLevel = level.String
	l.CreatedAt, l.UpdatedAt = fromMillis(created), fromMillis(updated)
	l.LastUsedAt, l.RevokedAt = nullMillis(lastUsed), nullMillis(revoked)
	l.ExpiresAt = nullMillis(expires)
	return l, nil
}

// checkDropLinkLevel verifies, inside tx, that key ("" for none) is a
// level of the tenant tx is bound to; ErrInvalid otherwise.
func checkDropLinkLevel(ctx context.Context, tx *ScopedTx, key string) error {
	if key == "" {
		return nil
	}
	var n int
	if err := tx.QueryRow(ctx, qDropLinkLevelExists, key).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return invalid("unknown confidentiality level")
	}
	return nil
}

// checkDropLink verifies, inside tx, that linkID is a drop link of the
// tenant tx is bound to usable at now: the composite foreign key of
// transfers.drop_link_id only proves that it exists in the tenant. A
// disabled, revoked or expired link is reported as ErrNotFound.
func checkDropLink(ctx context.Context, tx *ScopedTx, linkID string, now time.Time) error {
	l, err := scanDropLink(tx.QueryRow(ctx, qDropLinkGet, linkID))
	if err != nil {
		return err
	}
	if !l.Usable(now) {
		return ErrNotFound
	}
	return nil
}

// validDepositsPerHour reports whether n is an acceptable hourly deposit
// cap.
func validDepositsPerHour(n int) bool { return n >= 1 && n <= MaxDropLinkDepositsPerHour }

// Create stores the new link l for tenant tid and returns it as stored
// (recipients normalized, times set, UpdatedAt equal to CreatedAt, a zero
// MaxDepositsPerHour replaced by DefaultDropLinkDepositsPerHour). It
// returns ErrInvalid for a malformed field (a new link is neither used nor
// revoked, and its expiry, when set, follows its creation) or a level key
// that is not a level of the tenant,
// ErrLimitReached when the tenant has MaxDropLinks links already (revoked
// ones count until they are purged), ErrNotFound when the tenant does not
// exist and ErrConflict when the identifier or the token hash is already
// used.
func (r *DropLinks) Create(ctx context.Context, tid tenant.ID, l DropLink) (DropLink, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return DropLink{}, err
	}
	recipients, doc, err := normalizeDropRecipients(l.Recipients)
	if err != nil {
		return DropLink{}, err
	}
	l.Recipients = recipients
	if l.MaxDepositsPerHour == 0 {
		l.MaxDepositsPerHour = DefaultDropLinkDepositsPerHour
	}
	l.CreatedAt = fromMillis(toMillis(r.db.orNow(l.CreatedAt)))
	l.UpdatedAt = l.CreatedAt
	if !l.ExpiresAt.IsZero() {
		l.ExpiresAt = fromMillis(toMillis(l.ExpiresAt))
	}
	switch {
	case !id.Valid(id.DropLink, l.ID):
		return DropLink{}, invalid("malformed drop link id")
	case !validTokenHash(l.TokenHash):
		return DropLink{}, invalid("token hash must hold %d bytes", TokenHashSize)
	case !validDropLinkLabel(l.Label):
		return DropLink{}, invalid("label must be 1 to %d characters on one line", MaxDropLinkLabelLen)
	case !validExpiryDays(l.ValidityDays):
		return DropLink{}, invalid("validity must be 1, 7 or 30 days")
	case l.ConfidentialityLevel != "" && !ValidLevelKey(l.ConfidentialityLevel):
		return DropLink{}, invalid("malformed confidentiality level")
	case l.CreatedBy == "" || !validText(l.CreatedBy, maxDropLinkCreatedByLen, true):
		return DropLink{}, invalid("creator must be 1 to %d characters on one line", maxDropLinkCreatedByLen)
	case !l.LastUsedAt.IsZero() || !l.RevokedAt.IsZero():
		return DropLink{}, invalid("a new drop link is neither used nor revoked")
	case !validDepositsPerHour(l.MaxDepositsPerHour):
		return DropLink{}, invalid("deposits per hour must be 1 to %d", MaxDropLinkDepositsPerHour)
	case !l.ExpiresAt.IsZero() && !l.ExpiresAt.After(l.CreatedAt):
		return DropLink{}, invalid("a drop link must expire after its creation")
	}
	err = sc.Tx(ctx, func(tx *ScopedTx) error {
		if err := tx.lock(ctx); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, qDropLinkCount).Scan(&n); err != nil {
			return err
		}
		if n >= MaxDropLinks {
			return ErrLimitReached
		}
		if err := checkDropLinkLevel(ctx, tx, l.ConfidentialityLevel); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, qDropLinkInsert, l.ID, l.TokenHash, l.Label, doc, l.ValidityDays,
			nullText(l.ConfidentialityLevel), l.Enabled, l.CreatedBy, toMillis(l.CreatedAt), toMillis(l.UpdatedAt),
			nullTime(l.ExpiresAt), l.MaxDepositsPerHour)
		return err
	})
	if err != nil {
		return DropLink{}, wrap("create drop link", err)
	}
	return l, nil
}

// Get returns the link linkID of tenant tid, in whatever state it is (the
// caller checks [DropLink.Usable] when it binds a deposit to it), or
// ErrNotFound when it does not exist or belongs to another tenant.
func (r *DropLinks) Get(ctx context.Context, tid tenant.ID, linkID string) (DropLink, error) {
	return readScoped(ctx, r.db, tid, "get drop link", func(tx *ScopedTx) (DropLink, error) {
		return r.GetTx(ctx, tx, linkID)
	})
}

// GetTx is Get inside tx, for the tenant tx is bound to, returning the
// error unwrapped. After an error, the caller must abort the transaction.
func (r *DropLinks) GetTx(ctx context.Context, tx *ScopedTx, linkID string) (DropLink, error) {
	return scanDropLink(tx.QueryRow(ctx, qDropLinkGet, linkID))
}

// GetByTokenHash returns the link of tenant tid usable at now (the store's
// clock when zero) whose token hashes to hash ([id.HashToken]). The lookup
// runs in the tenant scope (under row-level security on PostgreSQL): an
// unknown token, the token of a disabled, revoked or expired link and the
// token of a link of another tenant are all reported as the same
// ErrNotFound (OpenAPI drop-link-invalid). It returns ErrInvalid for a
// hash of the wrong size.
func (r *DropLinks) GetByTokenHash(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (DropLink, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return DropLink{}, err
	}
	if !validTokenHash(hash) {
		return DropLink{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return readScoped(ctx, r.db, tid, "get drop link by hash", func(tx *ScopedTx) (DropLink, error) {
		return scanDropLink(tx.QueryRow(ctx, qDropLinkGetByHash, hash, toMillis(r.db.orNow(now))))
	})
}

// List returns every link of tenant tid, revoked ones included, newest
// first (creation time, then identifier).
func (r *DropLinks) List(ctx context.Context, tid tenant.ID) ([]DropLink, error) {
	return readScoped(ctx, r.db, tid, "list drop links", func(tx *ScopedTx) ([]DropLink, error) {
		rows, err := tx.Query(ctx, qDropLinkList)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (DropLink, error) { return scanDropLink(r) })
	})
}

// Update applies u to the link linkID of tenant tid at now (the store's
// clock when zero) and returns the link as it is afterwards, with whether
// anything changed: an update that changes nothing writes nothing (not
// even UpdatedAt) and reports false, so that the caller audits real
// changes only. The resulting link must be valid: an enabled link needs 1
// to MaxDropLinkRecipients recipients and an existing level (checked under
// the tenant lock, also when only Enabled changes). An expired link may be
// changed: a later expiry, or none, makes it usable again. The store does
// not compare a new expiry with the current time (the caller does).
//
// It returns ErrInvalid for a malformed field or an unknown level,
// ErrNotFound when the link does not exist (or belongs to another tenant)
// and ErrConflict when it is revoked.
func (r *DropLinks) Update(ctx context.Context, tid tenant.ID, linkID string, u DropLinkUpdate, now time.Time) (DropLink, bool, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return DropLink{}, false, err
	}
	switch {
	case u.Label != "" && !validDropLinkLabel(u.Label):
		return DropLink{}, false, invalid("label must be 1 to %d characters on one line", MaxDropLinkLabelLen)
	case u.ValidityDays != 0 && !validExpiryDays(u.ValidityDays):
		return DropLink{}, false, invalid("validity must be 1, 7 or 30 days")
	case u.ConfidentialityLevel != nil && *u.ConfidentialityLevel != "" && !ValidLevelKey(*u.ConfidentialityLevel):
		return DropLink{}, false, invalid("malformed confidentiality level")
	case u.MaxDepositsPerHour != 0 && !validDepositsPerHour(u.MaxDepositsPerHour):
		return DropLink{}, false, invalid("deposits per hour must be 1 to %d", MaxDropLinkDepositsPerHour)
	}
	var recipients []string
	if u.Recipients != nil {
		var err error
		if recipients, _, err = normalizeDropRecipients(u.Recipients); err != nil {
			return DropLink{}, false, err
		}
	}
	var changed bool
	l, err := writeScopedValue(ctx, r.db, tid, "update drop link", func(tx *ScopedTx) (DropLink, error) {
		if err := tx.lock(ctx); err != nil {
			return DropLink{}, err
		}
		cur, err := scanDropLink(tx.QueryRow(ctx, qDropLinkGet, linkID))
		if err != nil {
			return DropLink{}, err
		}
		if cur.Revoked() {
			return DropLink{}, ErrConflict
		}
		next := cur
		if u.Label != "" {
			next.Label = u.Label
		}
		if recipients != nil {
			next.Recipients = recipients
		}
		if u.ValidityDays != 0 {
			next.ValidityDays = u.ValidityDays
		}
		if u.ConfidentialityLevel != nil {
			next.ConfidentialityLevel = *u.ConfidentialityLevel
		}
		if u.Enabled != nil {
			next.Enabled = *u.Enabled
		}
		if u.ExpiresAt != nil {
			next.ExpiresAt = time.Time{}
			if !u.ExpiresAt.IsZero() {
				next.ExpiresAt = fromMillis(toMillis(*u.ExpiresAt))
			}
		}
		if u.MaxDepositsPerHour != 0 {
			next.MaxDepositsPerHour = u.MaxDepositsPerHour
		}
		if next.Label == cur.Label && slices.Equal(next.Recipients, cur.Recipients) &&
			next.ValidityDays == cur.ValidityDays && next.ConfidentialityLevel == cur.ConfidentialityLevel &&
			next.Enabled == cur.Enabled && next.ExpiresAt.Equal(cur.ExpiresAt) &&
			next.MaxDepositsPerHour == cur.MaxDepositsPerHour {
			return cur, nil
		}
		if !next.ExpiresAt.IsZero() && !next.ExpiresAt.After(cur.CreatedAt) {
			return DropLink{}, invalid("a drop link must expire after its creation")
		}
		if next.Enabled {
			if len(next.Recipients) == 0 {
				return DropLink{}, invalid("an enabled drop link needs recipients")
			}
			if err := checkDropLinkLevel(ctx, tx, next.ConfidentialityLevel); err != nil {
				return DropLink{}, err
			}
		}
		next.UpdatedAt = fromMillis(toMillis(r.db.orNow(now)))
		_, err = tx.Exec(ctx, qDropLinkUpdate, next.Label, recipientsDoc(next.Recipients), next.ValidityDays,
			nullText(next.ConfidentialityLevel), next.Enabled, nullTime(next.ExpiresAt), next.MaxDepositsPerHour,
			toMillis(next.UpdatedAt), linkID)
		if err != nil {
			return DropLink{}, err
		}
		changed = true
		return next, nil
	})
	if err != nil {
		return DropLink{}, false, err
	}
	return l, changed, nil
}

// Rotate replaces the token hash of the link linkID of tenant tid with
// hash at now (the store's clock when zero), in place: the previous token
// stops working at once. It returns the link as changed, ErrInvalid for a
// hash of the wrong size, ErrNotFound when the link does not exist (or
// belongs to another tenant) and ErrConflict when it is revoked or the
// hash is already used. A disabled link may be rotated.
func (r *DropLinks) Rotate(ctx context.Context, tid tenant.ID, linkID string, hash []byte, now time.Time) (DropLink, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return DropLink{}, err
	}
	if !validTokenHash(hash) {
		return DropLink{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return writeScopedValue(ctx, r.db, tid, "rotate drop link", func(tx *ScopedTx) (DropLink, error) {
		res, err := tx.Exec(ctx, qDropLinkRotate, hash, toMillis(r.db.orNow(now)), linkID)
		if err == nil {
			err = expectOne(res)
		}
		if errors.Is(err, ErrNotFound) {
			err = probe(ctx, tx, qDropLinkCountID, linkID, ErrConflict)
		}
		if err != nil {
			return DropLink{}, err
		}
		return scanDropLink(tx.QueryRow(ctx, qDropLinkGet, linkID))
	})
}

// Revoke revokes the link linkID of tenant tid at now (the store's clock
// when zero) and returns it. It reports whether this call revoked it:
// revoking a link already revoked changes nothing and reports false. A
// revoked link is never deleted by this call (its transfers keep their
// reference), cannot be changed, rotated or used again, and is purged 12
// months later. It returns ErrNotFound when the link does not exist or
// belongs to another tenant.
func (r *DropLinks) Revoke(ctx context.Context, tid tenant.ID, linkID string, now time.Time) (DropLink, bool, error) {
	var revoked bool
	l, err := writeScopedValue(ctx, r.db, tid, "revoke drop link", func(tx *ScopedTx) (DropLink, error) {
		ms := toMillis(r.db.orNow(now))
		res, err := tx.Exec(ctx, qDropLinkRevoke, ms, ms, linkID)
		if err != nil {
			return DropLink{}, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return DropLink{}, err
		}
		revoked = n == 1
		return scanDropLink(tx.QueryRow(ctx, qDropLinkGet, linkID))
	})
	if err != nil {
		return DropLink{}, false, err
	}
	return l, revoked, nil
}

// TouchLastUsed records at (the store's clock when zero) as the last use
// of the link linkID of tenant tid, at most once per minute: a use
// recorded less than a minute before at is kept, so that a busy link does
// not write on every request. An unknown link (or one of another tenant)
// changes nothing and is not an error.
func (r *DropLinks) TouchLastUsed(ctx context.Context, tid tenant.ID, linkID string, at time.Time) error {
	return writeScoped(ctx, r.db, tid, "touch drop link", func(tx *ScopedTx) error {
		at := r.db.orNow(at)
		_, err := tx.Exec(ctx, qDropLinkTouch, toMillis(at), linkID, toMillis(at.Add(-dropLinkTouchInterval)))
		return err
	})
}

// Purge deletes the links of tenant tid revoked, or expired, strictly
// before before (the lifecycle task passes now minus 12 months) that no
// transfer refers to: the foreign key from transfers has no cascade, so
// such a link goes once the rows of its transfers are deleted. Its deposit
// sessions and verification codes follow by cascade. It works in batches
// of PurgeBatchSize under the tenant lock, which the creation of a
// transfer takes too, and returns how many links it deleted.
func (r *DropLinks) Purge(ctx context.Context, tid tenant.ID, before time.Time) (int64, error) {
	ms := toMillis(before)
	return r.db.purge(ctx, tid, "purge drop links", true, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		ids, err := listIDs(ctx, tx, qDropLinkPurgeList, ms, ms, after, size)
		if err != nil {
			return 0, "", false, err
		}
		var deleted int64
		last := ""
		for _, linkID := range ids {
			last = linkID
			var refs int
			if err := tx.QueryRow(ctx, qTransferCountByDropLink, linkID).Scan(&refs); err != nil {
				return 0, "", false, err
			}
			if refs > 0 {
				continue
			}
			res, err := tx.Exec(ctx, qDropLinkPurge, linkID, ms, ms)
			if err != nil {
				return 0, "", false, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, "", false, err
			}
			deleted += n
		}
		return deleted, last, len(ids) == size, nil
	})
}

// dropLinkRecipients is a row of qDropLinkRecipients.
type dropLinkRecipients struct {
	id         string
	recipients []string
}

// listDropLinkRecipients reads the recipient lists of the tenant tx is
// bound to.
func listDropLinkRecipients(ctx context.Context, tx *ScopedTx) ([]dropLinkRecipients, error) {
	rows, err := tx.Query(ctx, qDropLinkRecipients)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (dropLinkRecipients, error) {
		var (
			row dropLinkRecipients
			doc string
		)
		if err := r.Scan(&row.id, &doc); err != nil {
			return row, err
		}
		list, err := parseSenders(doc)
		if err != nil {
			return row, invalid("stored drop link recipients are malformed")
		}
		row.recipients = list
		return row, nil
	})
}

// CountByRecipient returns the number of links of tenant tid, revoked
// ones included, whose recipients include the address email (normalized
// by the store): the data-subject search. It returns ErrInvalid for a
// malformed address.
func (r *DropLinks) CountByRecipient(ctx context.Context, tid tenant.ID, email string) (int, error) {
	addr, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	return readScoped(ctx, r.db, tid, "count drop links by recipient", func(tx *ScopedTx) (int, error) {
		rows, err := listDropLinkRecipients(ctx, tx)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, row := range rows {
			if slices.Contains(row.recipients, addr) {
				n++
			}
		}
		return n, nil
	})
}

// RemoveRecipientTx removes the address email (normalized by the store)
// from the recipients of every link of the tenant tx is bound to, revoked
// ones included, inside tx: the data-subject erasure (spec 20). A link left
// without any recipient is disabled (it keeps an empty list and can only be
// enabled again with new recipients). The changed links get UpdatedAt =
// now (the store's clock when zero). It takes the tenant lock and returns
// the counts; ErrInvalid for a malformed address. After an error, the
// caller must abort the transaction.
func (r *DropLinks) RemoveRecipientTx(ctx context.Context, tx *ScopedTx, email string, now time.Time) (DropLinkErasure, error) {
	out, err := r.removeRecipient(ctx, tx, email, now)
	if err != nil {
		return DropLinkErasure{}, wrap("erase drop link recipient", err)
	}
	return out, nil
}

// removeRecipient implements RemoveRecipientTx, returning raw errors.
func (r *DropLinks) removeRecipient(ctx context.Context, tx *ScopedTx, email string, now time.Time) (DropLinkErasure, error) {
	addr, err := NormalizeEmail(email)
	if err != nil {
		return DropLinkErasure{}, err
	}
	if err := tx.lock(ctx); err != nil {
		return DropLinkErasure{}, err
	}
	rows, err := listDropLinkRecipients(ctx, tx)
	if err != nil {
		return DropLinkErasure{}, err
	}
	ms := toMillis(r.db.orNow(now))
	var out DropLinkErasure
	for _, row := range rows {
		if !slices.Contains(row.recipients, addr) {
			continue
		}
		left := slices.DeleteFunc(row.recipients, func(s string) bool { return s == addr })
		if _, err := tx.Exec(ctx, qDropLinkErase, recipientsDoc(left), len(left) == 0, ms, row.id); err != nil {
			return DropLinkErasure{}, err
		}
		out.Updated++
		if len(left) == 0 {
			out.Disabled++
		}
	}
	return out, nil
}
