package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of the confidentiality levels (spec 8.3, data model D15).
const (
	// MaxConfidentialityLevels bounds the levels of a tenant (at least one
	// is required).
	MaxConfidentialityLevels = 10
	// MaxLevelKeyLen bounds the key of a level, in bytes.
	MaxLevelKeyLen = 32
	// MaxLevelLabelRunes bounds a label of a level, in characters.
	MaxLevelLabelRunes = 50
	// MaxLevelDescriptionRunes bounds a description of a level, in
	// characters.
	MaxLevelDescriptionRunes = 500
	// MaxLevelUpdatedByRunes bounds the author recorded with the levels.
	MaxLevelUpdatedByRunes = 64
	// MaxDownloadsLimit is the largest download limit of a transfer, and
	// the largest cap a level may impose on it.
	MaxDownloadsLimit = 1000
)

// Bits of ConfidentialityRules.ExpiryDaysMask, one per validity of spec
// 8.2.
const (
	// ExpiryMask1Day allows a validity of 1 day.
	ExpiryMask1Day = 1
	// ExpiryMask7Days allows a validity of 7 days.
	ExpiryMask7Days = 2
	// ExpiryMask30Days allows a validity of 30 days.
	ExpiryMask30Days = 4
	// ExpiryMaskAll allows every validity.
	ExpiryMaskAll = ExpiryMask1Day | ExpiryMask7Days | ExpiryMask30Days
)

// expiryBits lists the validities and their bit, shortest first.
var expiryBits = []struct{ days, bit int }{
	{1, ExpiryMask1Day}, {7, ExpiryMask7Days}, {30, ExpiryMask30Days},
}

// ExpiryDayBit returns the bit of ConfidentialityRules.ExpiryDaysMask
// allowing a validity of days, 0 when days is not a validity of spec 8.2
// (1, 7 or 30).
func ExpiryDayBit(days int) int {
	for _, e := range expiryBits {
		if e.days == days {
			return e.bit
		}
	}
	return 0
}

// ExpiryDaysMaskOf returns the mask allowing exactly the validities days
// (duplicates are ignored). It reports false when a value is not a
// validity of spec 8.2 or when days is empty.
func ExpiryDaysMaskOf(days []int) (int, bool) {
	mask := 0
	for _, d := range days {
		bit := ExpiryDayBit(d)
		if bit == 0 {
			return 0, false
		}
		mask |= bit
	}
	return mask, mask != 0
}

// ExpiryDaysOfMask returns the validities allowed by mask, shortest first
// (bits outside ExpiryMaskAll are ignored).
func ExpiryDaysOfMask(mask int) []int {
	out := make([]int, 0, len(expiryBits))
	for _, e := range expiryBits {
		if mask&e.bit != 0 {
			out = append(out, e.days)
		}
	}
	return out
}

// ConfidentialityRules are the rules a confidentiality level imposes on the
// transfers sent with it (spec 8.3). A transfer keeps a snapshot of them
// (Transfer.Rules).
type ConfidentialityRules struct {
	// ExpiryDaysMask is the bit mask of the allowed validities
	// (ExpiryMask1Day, ExpiryMask7Days, ExpiryMask30Days): 1 to
	// ExpiryMaskAll.
	ExpiryDaysMask int
	// MaxDownloadsCap is the largest download limit a transfer may choose
	// (1 to MaxDownloadsLimit), nil without cap. With a cap, a transfer
	// must have a limit, at most the cap.
	MaxDownloadsCap *int
	// RequirePassword requires a transfer password.
	RequirePassword bool
	// RequireRecipientVerification requires the verification of the
	// recipients by code.
	RequireRecipientVerification bool
	// InternalRecipientsOnly restricts the recipients to the internal mail
	// domains of the tenant.
	InternalRecipientsOnly bool
	// ForceDeleteAfterFirstDownload forces the deletion of the transfer
	// after its first download.
	ForceDeleteAfterFirstDownload bool
}

// AllowsExpiry reports whether the rules allow a validity of days.
func (r ConfidentialityRules) AllowsExpiry(days int) bool {
	bit := ExpiryDayBit(days)
	return bit != 0 && r.ExpiryDaysMask&bit != 0
}

// AllowedExpiryDays returns the validities the rules allow, shortest
// first.
func (r ConfidentialityRules) AllowedExpiryDays() []int {
	return ExpiryDaysOfMask(r.ExpiryDaysMask)
}

// AllowsMaxDownloads reports whether the rules allow the download limit n
// (nil: unlimited): any limit without cap, a limit of at most the cap with
// one.
func (r ConfidentialityRules) AllowsMaxDownloads(n *int) bool {
	if r.MaxDownloadsCap == nil {
		return true
	}
	return n != nil && *n <= *r.MaxDownloadsCap
}

// validate checks the ranges of the rules.
func (r ConfidentialityRules) validate() error {
	switch {
	case r.ExpiryDaysMask < 1 || r.ExpiryDaysMask > ExpiryMaskAll:
		return invalid("allowed validities must be a mask of 1 to %d", ExpiryMaskAll)
	case r.MaxDownloadsCap != nil && (*r.MaxDownloadsCap < 1 || *r.MaxDownloadsCap > MaxDownloadsLimit):
		return invalid("max downloads cap must be 1 to %d", MaxDownloadsLimit)
	}
	return nil
}

// clone returns a copy of r that shares no pointer with it.
func (r ConfidentialityRules) clone() ConfidentialityRules {
	r.MaxDownloadsCap = cloneInt(r.MaxDownloadsCap)
	return r
}

// ConfidentialityLevel is a confidentiality level of a tenant (spec 8.3):
// the senders choose one for each transfer, and it imposes its rules.
type ConfidentialityLevel struct {
	// Key identifies the level in the tenant: ^[a-z][a-z0-9_-]{0,31}$.
	Key string
	// Position is the rank of the level in the selector, from 0; Replace
	// assigns it from the order of the list.
	Position int
	// Labels are the names of the level by language: "fr" and "en", 1 to
	// MaxLevelLabelRunes characters on one line each.
	Labels map[string]string
	// Descriptions are the optional explanations of the level by language
	// (at most MaxLevelDescriptionRunes characters each); empty values are
	// dropped. Never nil once read.
	Descriptions map[string]string
	// IsDefault marks the level preselected for a new transfer; exactly
	// one level of a tenant is the default.
	IsDefault bool
	// Rules are the rules the level imposes.
	Rules ConfidentialityRules
	// UpdatedAt is when the list was last replaced (zero for the levels
	// seeded with the tenant).
	UpdatedAt time.Time
	// UpdatedBy is the administrator who last replaced the list, "" for
	// the seeded levels.
	UpdatedBy string
}

// levelColumns is the column list read by the confidentiality level
// queries.
const levelColumns = `key, position, labels, descriptions, is_default, require_recipient_verification, ` +
	`require_password, allowed_validity_days, internal_recipients_only, force_delete_after_download, ` +
	`max_downloads_cap, updated_at, updated_by`

// Statements of the ConfidentialityLevels repository.
var (
	qLevelList = tenantQuery(
		`SELECT ` + levelColumns + ` FROM confidentiality_levels WHERE tenant_id = ? ORDER BY position`)
	qLevelGet = tenantQuery(
		`SELECT ` + levelColumns + ` FROM confidentiality_levels WHERE tenant_id = ? AND key = ?`)
	qLevelDefault = tenantQuery(
		`SELECT ` + levelColumns + ` FROM confidentiality_levels WHERE tenant_id = ? AND is_default`)
	qLevelsDelete = tenantQuery(
		`DELETE FROM confidentiality_levels WHERE tenant_id = ?`)
	qLevelInsert = tenantQuery(
		`INSERT INTO confidentiality_levels (tenant_id, key, position, labels, descriptions, is_default,
		require_recipient_verification, require_password, allowed_validity_days, internal_recipients_only,
		force_delete_after_download, max_downloads_cap, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
)

// ConfidentialityLevels is the tenant-scoped repository of the
// confidentiality levels. Obtain it with [DB.ConfidentialityLevels].
// Tenants.Create seeds the default levels of a new tenant (public,
// internal as the default, confidential), as migration 0016 did for the
// existing ones.
type ConfidentialityLevels struct {
	db *DB
}

// ConfidentialityLevels returns the confidentiality level repository.
func (db *DB) ConfidentialityLevels() *ConfidentialityLevels { return &ConfidentialityLevels{db: db} }

// ValidLevelKey reports whether k matches ^[a-z][a-z0-9_-]{0,31}$, the
// well-formed key of a confidentiality level.
func ValidLevelKey(k string) bool {
	if k == "" || len(k) > MaxLevelKeyLen || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	return strings.Trim(k, "abcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}

// normalizeLevelLabels validates labels (exactly the supported languages,
// each a non-blank line of at most MaxLevelLabelRunes characters) and
// returns a copy.
func normalizeLevelLabels(labels map[string]string) (map[string]string, error) {
	langs := tenant.Languages()
	if len(labels) != len(langs) {
		return nil, invalid("labels must be given in every supported language")
	}
	out := make(map[string]string, len(langs))
	for _, lang := range langs {
		l, ok := labels[lang]
		if !ok || strings.TrimSpace(l) == "" || !validText(l, MaxLevelLabelRunes, true) {
			return nil, invalid("each label must hold 1 to %d characters on one line", MaxLevelLabelRunes)
		}
		out[lang] = l
	}
	return out, nil
}

// normalizeLevelDescriptions validates descriptions (supported languages,
// at most MaxLevelDescriptionRunes characters each) and returns a copy
// without the empty values.
func normalizeLevelDescriptions(descriptions map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(descriptions))
	for lang, d := range descriptions {
		if !tenant.IsLanguage(lang) {
			return nil, invalid("unsupported description language")
		}
		if !validText(d, MaxLevelDescriptionRunes, false) {
			return nil, invalid("each description must hold at most %d characters", MaxLevelDescriptionRunes)
		}
		if d != "" {
			out[lang] = d
		}
	}
	return out, nil
}

// normalizeLevels validates the list given to Replace and returns a copy
// with the positions assigned from the order and the author and time set.
func normalizeLevels(levels []ConfidentialityLevel, by string, now time.Time) ([]ConfidentialityLevel, error) {
	if len(levels) == 0 || len(levels) > MaxConfidentialityLevels {
		return nil, invalid("a tenant needs 1 to %d confidentiality levels", MaxConfidentialityLevels)
	}
	if !validText(by, MaxLevelUpdatedByRunes, true) {
		return nil, invalid("author must be a line of at most %d characters", MaxLevelUpdatedByRunes)
	}
	out := make([]ConfidentialityLevel, len(levels))
	seen := make(map[string]bool, len(levels))
	defaults := 0
	for i, l := range levels {
		if !ValidLevelKey(l.Key) {
			return nil, invalid("level key must match ^[a-z][a-z0-9_-]{0,31}$")
		}
		if seen[l.Key] {
			return nil, invalid("duplicate level key")
		}
		seen[l.Key] = true
		labels, err := normalizeLevelLabels(l.Labels)
		if err != nil {
			return nil, err
		}
		descriptions, err := normalizeLevelDescriptions(l.Descriptions)
		if err != nil {
			return nil, err
		}
		if err := l.Rules.validate(); err != nil {
			return nil, err
		}
		if l.IsDefault {
			defaults++
		}
		out[i] = ConfidentialityLevel{
			Key: l.Key, Position: i, Labels: labels, Descriptions: descriptions, IsDefault: l.IsDefault,
			Rules: l.Rules.clone(), UpdatedAt: now.Truncate(time.Millisecond), UpdatedBy: by,
		}
	}
	if defaults != 1 {
		return nil, invalid("exactly one level must be the default")
	}
	return out, nil
}

// scanLevel reads one row of levelColumns.
func scanLevel(row interface{ Scan(...any) error }) (ConfidentialityLevel, error) {
	var (
		l                    ConfidentialityLevel
		labels, descriptions string
		maxCap               sql.NullInt64
		updated              int64
	)
	err := row.Scan(&l.Key, &l.Position, &labels, &descriptions, &l.IsDefault, &l.Rules.RequireRecipientVerification,
		&l.Rules.RequirePassword, &l.Rules.ExpiryDaysMask, &l.Rules.InternalRecipientsOnly,
		&l.Rules.ForceDeleteAfterFirstDownload, &maxCap, &updated, &l.UpdatedBy)
	if err != nil {
		return ConfidentialityLevel{}, err
	}
	if json.Unmarshal([]byte(labels), &l.Labels) != nil || json.Unmarshal([]byte(descriptions), &l.Descriptions) != nil {
		return ConfidentialityLevel{}, invalid("stored confidentiality level is malformed")
	}
	if l.Descriptions == nil {
		l.Descriptions = map[string]string{}
	}
	l.Rules.MaxDownloadsCap, l.UpdatedAt = intPtr(maxCap), fromMillis(updated)
	return l, nil
}

// listLevels returns the levels of the tenant tx is bound to, by position.
func listLevels(ctx context.Context, tx *ScopedTx) ([]ConfidentialityLevel, error) {
	rows, err := tx.Query(ctx, qLevelList)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (ConfidentialityLevel, error) { return scanLevel(r) })
}

// List returns the confidentiality levels of tenant tid by position (empty
// for an unknown tenant).
func (r *ConfidentialityLevels) List(ctx context.Context, tid tenant.ID) ([]ConfidentialityLevel, error) {
	return readScoped(ctx, r.db, tid, "list confidentiality levels", func(tx *ScopedTx) ([]ConfidentialityLevel, error) {
		return listLevels(ctx, tx)
	})
}

// ListTx is List inside tx, for the tenant tx is bound to: a transfer
// creation reads the level it snapshots in its own transaction. After an
// error, the caller must abort the transaction.
func (r *ConfidentialityLevels) ListTx(ctx context.Context, tx *ScopedTx) ([]ConfidentialityLevel, error) {
	levels, err := listLevels(ctx, tx)
	if err != nil {
		return nil, wrap("list confidentiality levels", err)
	}
	return levels, nil
}

// Get returns the level key of tenant tid. It returns ErrInvalid for a
// malformed key and ErrNotFound when the tenant has no such level.
func (r *ConfidentialityLevels) Get(ctx context.Context, tid tenant.ID, key string) (ConfidentialityLevel, error) {
	if !ValidLevelKey(key) {
		return ConfidentialityLevel{}, invalid("malformed level key")
	}
	return readScoped(ctx, r.db, tid, "get confidentiality level", func(tx *ScopedTx) (ConfidentialityLevel, error) {
		return scanLevel(tx.QueryRow(ctx, qLevelGet, key))
	})
}

// Default returns the default level of tenant tid. It returns ErrNotFound
// when the tenant does not exist.
func (r *ConfidentialityLevels) Default(ctx context.Context, tid tenant.ID) (ConfidentialityLevel, error) {
	return readScoped(ctx, r.db, tid, "get default confidentiality level", func(tx *ScopedTx) (ConfidentialityLevel, error) {
		return scanLevel(tx.QueryRow(ctx, qLevelDefault))
	})
}

// Replace atomically replaces the confidentiality levels of tenant tid with
// levels, in that order (positions are assigned from it), recorded as
// changed by by (an administrator identifier, at most
// MaxLevelUpdatedByRunes characters) at now (the store's clock when zero).
// It returns the stored list.
//
// It returns ErrInvalid, changing nothing, unless the list holds 1 to
// MaxConfidentialityLevels levels with distinct well-formed keys, exactly
// one default, labels in every supported language (1 to
// MaxLevelLabelRunes characters), descriptions of at most
// MaxLevelDescriptionRunes characters in supported languages, and valid
// rules; ErrNotFound when the tenant does not exist. Concurrent replaces of
// a tenant are serialized. Past transfers keep their snapshot.
func (r *ConfidentialityLevels) Replace(ctx context.Context, tid tenant.ID, levels []ConfidentialityLevel, by string, now time.Time) ([]ConfidentialityLevel, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return nil, err
	}
	out, err := normalizeLevels(levels, by, r.db.orNow(now))
	if err != nil {
		return nil, err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		// Concurrent replaces would otherwise both delete, then collide on
		// insert (PostgreSQL, READ COMMITTED).
		if err := tx.lock(ctx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, qLevelsDelete); err != nil {
			return err
		}
		for _, l := range out {
			labels, _ := json.Marshal(l.Labels)             // a map[string]string always marshals
			descriptions, _ := json.Marshal(l.Descriptions) // same
			_, err := tx.Exec(ctx, qLevelInsert, l.Key, l.Position, string(labels), string(descriptions), l.IsDefault,
				l.Rules.RequireRecipientVerification, l.Rules.RequirePassword, l.Rules.ExpiryDaysMask,
				l.Rules.InternalRecipientsOnly, l.Rules.ForceDeleteAfterFirstDownload, nullInt(l.Rules.MaxDownloadsCap),
				toMillis(l.UpdatedAt), l.UpdatedBy)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrap("replace confidentiality levels", err)
	}
	return out, nil
}

// normalizeTransferLevel validates the confidentiality snapshot of a new
// transfer, mirroring the checks of migration 0014: a level key, its
// labels and its rules all together, or none of them. It replaces the
// label and the rules with copies.
func normalizeTransferLevel(t *Transfer) error {
	if t.ConfidentialityLevel == "" {
		if len(t.ConfidentialityLabel) != 0 || t.Rules != nil {
			return invalid("a transfer without confidentiality level has no label or rules")
		}
		t.ConfidentialityLabel = nil
		return nil
	}
	if !ValidLevelKey(t.ConfidentialityLevel) {
		return invalid("malformed confidentiality level")
	}
	labels, err := normalizeLevelLabels(t.ConfidentialityLabel)
	if err != nil {
		return err
	}
	if t.Rules == nil {
		return invalid("a transfer with a confidentiality level needs its rules")
	}
	if err := t.Rules.validate(); err != nil {
		return err
	}
	rules := t.Rules.clone()
	t.ConfidentialityLabel, t.Rules = labels, &rules
	return nil
}

// levelArgs returns the insert arguments of the confidentiality snapshot
// of the normalized transfer t: level, label, then the rule columns, all
// NULL without level.
func levelArgs(t Transfer) []any {
	if t.ConfidentialityLevel == "" {
		return []any{nil, nil, nil, nil, nil, nil, nil, nil}
	}
	label, _ := json.Marshal(t.ConfidentialityLabel) // a map[string]string always marshals
	r := t.Rules
	return []any{
		t.ConfidentialityLevel, string(label), r.ExpiryDaysMask, nullInt(r.MaxDownloadsCap),
		r.RequirePassword, r.RequireRecipientVerification, r.InternalRecipientsOnly, r.ForceDeleteAfterFirstDownload,
	}
}

// nullInt maps a nil pointer to SQL NULL.
func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// intPtr reads an optional integer: nil for SQL NULL.
func intPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int64)
	return &n
}

// cloneInt returns a copy of *p, nil for nil.
func cloneInt(p *int) *int {
	if p == nil {
		return nil
	}
	n := *p
	return &n
}

// LevelLabel picks a text of a confidentiality level (a label or a
// description, by language) in the first of langs that has a non-empty one,
// else in the smallest language that has one, so that a text is always
// shown when any exists; "" for none. Callers pass the preferred language,
// then the default language of the tenant, then "en".
func LevelLabel(texts map[string]string, langs ...string) string {
	for _, l := range langs {
		if v := texts[l]; v != "" {
			return v
		}
	}
	for _, k := range slices.Sorted(maps.Keys(texts)) {
		if v := texts[k]; v != "" {
			return v
		}
	}
	return ""
}
