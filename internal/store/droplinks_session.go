package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// qDropLinkUseSession marks a drop link session used, at most once
// (deposit_sessions.used_at, migration 0032).
var qDropLinkUseSession = tenantQuery(
	`UPDATE deposit_sessions SET used_at = ?
	WHERE tenant_id = ? AND id = ? AND drop_link_id = ? AND used_at IS NULL`)

// UseSessionTx marks, inside tx, the deposit session sessionID of the drop
// link linkID as used at now: a drop link session deposits one transfer
// only. The transfer service runs it in the creation transaction, under
// the tenant lock, after counting the hourly cap ([DropLinks.UsageSinceTx]):
// two concurrent creations cannot both pass, and the mark survives the
// cancellation of the transfer (which deletes its row). It returns
// ErrNotFound when the session is unknown, belongs to another link or
// tenant, or was already used, and ErrInvalid for a malformed identifier.
// After an error, the caller must abort the transaction.
func (r *DropLinks) UseSessionTx(ctx context.Context, tx *ScopedTx, sessionID, linkID string, now time.Time) error {
	switch {
	case !id.Valid(id.DepositSession, sessionID):
		return invalid("malformed deposit session id")
	case !id.Valid(id.DropLink, linkID):
		return invalid("malformed drop link id")
	}
	res, err := tx.Exec(ctx, qDropLinkUseSession, toMillis(now), sessionID, linkID)
	if err != nil {
		return wrap("use drop link session", err)
	}
	if err := expectOne(res); err != nil {
		return wrap("use drop link session", err)
	}
	return nil
}

// qDropLinkUsageSince counts the sessions of a drop link used since a
// time, with the oldest use (index deposit_sessions_drop_link_used_idx).
var qDropLinkUsageSince = tenantQuery(
	`SELECT count(*), min(used_at) FROM deposit_sessions WHERE tenant_id = ? AND drop_link_id = ? AND used_at > ?`)

// DropLinkUsage is the use of a drop link over a window: the hourly
// deposit cap of the link (threat model P63).
type DropLinkUsage struct {
	// Count is the number of transfers created through the link in the
	// window: the sessions of the link used in the window, so that
	// canceling a transfer does not free its slot.
	Count int
	// Oldest is the oldest of these uses, zero when none: the window frees
	// a slot one hour after it.
	Oldest time.Time
}

// DropLinkWindow is the sliding window of the hourly deposit cap of a drop
// link ([DropLink.MaxDepositsPerHour]).
const DropLinkWindow = time.Hour

// Full reports whether the usage reaches the cap max.
func (u DropLinkUsage) Full(max int) bool { return u.Count >= max }

// RetryAfter returns when, from now, the window frees a slot: one
// DropLinkWindow after the oldest use counted, at least one second
// (a full DropLinkWindow when none is counted, for a cap that a concurrent
// purge emptied).
func (u DropLinkUsage) RetryAfter(now time.Time) time.Duration {
	if u.Oldest.IsZero() {
		return DropLinkWindow
	}
	return max(u.Oldest.Add(DropLinkWindow).Sub(now), time.Second)
}

// scanDropLinkUsage runs qDropLinkUsageSince inside tx.
func scanDropLinkUsage(ctx context.Context, tx *ScopedTx, linkID string, since time.Time) (DropLinkUsage, error) {
	var (
		u      DropLinkUsage
		oldest sql.NullInt64
	)
	if err := tx.QueryRow(ctx, qDropLinkUsageSince, linkID, toMillis(since)).Scan(&u.Count, &oldest); err != nil {
		return DropLinkUsage{}, err
	}
	u.Oldest = nullMillis(oldest)
	return u, nil
}

// UsageSince returns the transfers of tenant tid created through the drop
// link linkID after since (exclusive: a use leaves the window exactly one
// DropLinkWindow after it), all depositors together: the sessions of the
// link marked used ([DropLinks.UseSessionTx]), whatever became of their
// transfer (canceled or purged). The cleanup keeps a used session one
// DropLinkWindow after its use. It is the check made before a verification
// code is sent through a busy link. It returns ErrInvalid for a malformed link identifier; an
// unknown link counts nothing.
func (r *DropLinks) UsageSince(ctx context.Context, tid tenant.ID, linkID string, since time.Time) (DropLinkUsage, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return DropLinkUsage{}, err
	}
	if !id.Valid(id.DropLink, linkID) {
		return DropLinkUsage{}, invalid("malformed drop link id")
	}
	return readScoped(ctx, r.db, tid, "count drop link transfers", func(tx *ScopedTx) (DropLinkUsage, error) {
		return scanDropLinkUsage(ctx, tx, linkID, since)
	})
}

// UsageSinceTx is [DropLinks.UsageSince] inside tx, for the tenant tx is bound
// to: run in the creation transaction of a transfer, under the tenant
// lock, two concurrent creations cannot both pass the hourly cap. After an
// error, the caller must abort the transaction.
func (r *DropLinks) UsageSinceTx(ctx context.Context, tx *ScopedTx, linkID string, since time.Time) (DropLinkUsage, error) {
	if !id.Valid(id.DropLink, linkID) {
		return DropLinkUsage{}, invalid("malformed drop link id")
	}
	u, err := scanDropLinkUsage(ctx, tx, linkID, since)
	if err != nil {
		return DropLinkUsage{}, wrap("count drop link transfers", err)
	}
	return u, nil
}
