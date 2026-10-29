package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// Transfer password lockout (spec 10, threat model T-48 and T-137): a key
// is locked for PasswordLockDuration as soon as it has MaxPasswordFailures
// wrong passwords within any span of PasswordFailureWindow (a true sliding
// window: the times of the latest failures are kept).
const (
	// MaxPasswordFailures is the number of wrong passwords that locks a
	// key. The schema keeps that many failure times per key (fail_1 to
	// fail_3): changing it needs a migration.
	MaxPasswordFailures = 3
	// PasswordLockDuration is how long a key stays locked.
	PasswordLockDuration = 15 * time.Minute
	// PasswordFailureWindow is the sliding window failures are counted in:
	// a failure stops counting PasswordFailureWindow after it happened.
	PasswordFailureWindow = 15 * time.Minute
	// MaxFailureKeys bounds the keys of one call (the download layer uses
	// two: the transfer and the client IP).
	MaxFailureKeys = 4
	// ipv6FailurePrefix is the prefix length an IPv6 client is keyed by.
	ipv6FailurePrefix = 64
)

// FailureScope is the scope of a password failure counter.
type FailureScope string

// Failure scopes.
const (
	// FailureScopeTransfer counts the failures on one transfer, all client
	// IPs together, or on one recipient link of a per-recipient transfer
	// (see LinkFailureKey).
	FailureScopeTransfer FailureScope = "transfer"
	// FailureScopeIP counts the failures of one client, all transfers of
	// the tenant together.
	FailureScopeIP FailureScope = "ip"
)

// FailureKey identifies a password failure counter of a tenant. Build it
// with [TransferFailureKey], [LinkFailureKey] or [IPFailureKey].
type FailureKey struct {
	// Scope is the scope of the counter.
	Scope FailureScope
	// Key is the transfer ID ("trf_" + ULID) or the recipient link ID
	// ("rcl_" + ULID) for FailureScopeTransfer, or the normalized client IP
	// for FailureScopeIP (see IPFailureKey).
	Key string
}

// TransferFailureKey returns the counter of the transfer trfID (shared
// link).
func TransferFailureKey(trfID string) FailureKey {
	return FailureKey{Scope: FailureScopeTransfer, Key: trfID}
}

// LinkFailureKey returns the counter of the recipient link linkID. The
// download layer uses it in place of [TransferFailureKey] for a
// per-recipient transfer (user decision: the password tries are counted
// per link, so that one recipient cannot lock the others out); the per-IP
// counter is unchanged. The two kinds of IDs never collide (distinct
// prefixes), so they share the transfer scope of the schema.
func LinkFailureKey(linkID string) FailureKey {
	return FailureKey{Scope: FailureScopeTransfer, Key: linkID}
}

// IPFailureKey returns the counter of the client ip. An IPv4 address (or an
// IPv4-mapped IPv6 address) is keyed by itself, "192.0.2.1"; an IPv6
// address by its /64 prefix, "2001:db8:1:2::/64", the smallest block
// usually assigned to one site, so that a client rotating its addresses
// within its block keeps the same counter. The zone is dropped. The key of
// the zero Addr is invalid (the repository methods reject it).
func IPFailureKey(ip netip.Addr) FailureKey {
	k := FailureKey{Scope: FailureScopeIP}
	ip = ip.Unmap().WithZone("")
	switch {
	case ip.Is4():
		k.Key = ip.String()
	case ip.Is6():
		p, _ := ip.Prefix(ipv6FailurePrefix) // never fails for a valid IPv6 address
		k.Key = p.String()
	}
	return k
}

// valid reports whether k is a well-formed key, in the exact form its
// constructor produces.
func (k FailureKey) valid() bool {
	switch k.Scope {
	case FailureScopeTransfer:
		return id.Valid(id.Transfer, k.Key) || id.Valid(id.RecipientLink, k.Key)
	case FailureScopeIP:
		if ip, err := netip.ParseAddr(k.Key); err == nil {
			return ip.Is4() && ip.String() == k.Key
		}
		p, err := netip.ParsePrefix(k.Key)
		return err == nil && p.Addr().Is6() && p.Bits() == ipv6FailurePrefix && p.Masked() == p && p.String() == k.Key
	}
	return false
}

// checkFailureKeys validates 1 to MaxFailureKeys distinct keys.
func checkFailureKeys(keys []FailureKey) error {
	if len(keys) == 0 || len(keys) > MaxFailureKeys {
		return invalid("1 to %d failure keys are required", MaxFailureKeys)
	}
	seen := make(map[FailureKey]bool, len(keys))
	for _, k := range keys {
		if !k.valid() {
			return invalid("malformed failure key")
		}
		if seen[k] {
			return invalid("duplicate failure key")
		}
		seen[k] = true
	}
	return nil
}

// Statements of the PasswordFailures repository.
var (
	qFailureGet = tenantQuery(
		`SELECT fail_1, fail_2, fail_3, locked_until FROM password_failures WHERE tenant_id = ? AND scope = ? AND key = ?`)
	qFailureInsert = tenantQuery(
		`INSERT INTO password_failures (tenant_id, scope, key, fail_1, fail_2, fail_3, locked_until)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	qFailureUpdate = tenantQuery(
		`UPDATE password_failures SET fail_1 = ?, fail_2 = ?, fail_3 = ?, locked_until = ?
		WHERE tenant_id = ? AND scope = ? AND key = ?`)
	qFailureDelete = tenantQuery(
		`DELETE FROM password_failures WHERE tenant_id = ? AND scope = ? AND key = ?`)
)

// failureRow is a stored counter: the times of the latest failures, oldest
// first (at most MaxPasswordFailures), and the end of its lock (zero when
// none is recorded).
type failureRow struct {
	times       []time.Time
	lockedUntil time.Time
}

// readFailure reads the counter k inside tx; found is false when it has no
// row.
func readFailure(ctx context.Context, tx *ScopedTx, k FailureKey) (row failureRow, found bool, err error) {
	var (
		f      [MaxPasswordFailures]sql.NullInt64
		locked sql.NullInt64
	)
	err = tx.QueryRow(ctx, qFailureGet, string(k.Scope), k.Key).Scan(&f[0], &f[1], &f[2], &locked)
	if errors.Is(err, ErrNotFound) {
		return failureRow{}, false, nil
	}
	if err != nil {
		return failureRow{}, false, err
	}
	for _, v := range f {
		if v.Valid {
			row.times = append(row.times, fromMillis(v.Int64))
		}
	}
	row.lockedUntil = nullMillis(locked)
	return row, true, nil
}

// writeFailure stores row as the counter k inside tx, inserting it when
// found is false.
func writeFailure(ctx context.Context, tx *ScopedTx, k FailureKey, row failureRow, found bool) error {
	var f [MaxPasswordFailures]any
	for i, at := range row.times {
		f[i] = toMillis(at)
	}
	var locked any
	if !row.lockedUntil.IsZero() {
		locked = toMillis(row.lockedUntil)
	}
	var err error
	if found {
		_, err = tx.Exec(ctx, qFailureUpdate, f[0], f[1], f[2], locked, string(k.Scope), k.Key)
	} else {
		_, err = tx.Exec(ctx, qFailureInsert, string(k.Scope), k.Key, f[0], f[1], f[2], locked)
	}
	return err
}

// FailureOutcome is the result of [PasswordFailures.RecordFailureTx].
type FailureOutcome struct {
	// Remaining is the number of wrong passwords still tolerated before a
	// lock: the minimum across the keys, 0 when one of them is locked.
	Remaining int
	// LockedUntil is the end of the lock when one of the keys is locked
	// (by this failure or before), the latest across the keys; zero
	// otherwise.
	LockedUntil time.Time
}

// PasswordFailures is the tenant-scoped repository of the transfer
// password failure counters (spec 10). Obtain it with
// [DB.PasswordFailures].
//
// The download layer passes two keys to each call, [TransferFailureKey]
// and [IPFailureKey], so that both the transfer (from any IP) and the
// client (on any transfer of the tenant) are locked after
// MaxPasswordFailures failures within any PasswordFailureWindow. Every call
// takes the tenant lock first, so that concurrent attempts are counted
// exactly. Locks expire by time, compared with the caller's now; no
// background job is needed for them.
//
// Only ResetTx deletes rows. A row is stale once its latest failure is
// PasswordFailureWindow old and its lock is over: the cleanup task must
// purge the rows stale for 15 minutes or more, which otherwise accumulate
// (one per client IP and per transfer ever mistyped).
type PasswordFailures struct {
	db *DB
}

// PasswordFailures returns the password failure repository.
func (db *DB) PasswordFailures() *PasswordFailures { return &PasswordFailures{db: db} }

// CheckTx reports, inside tx, whether any of keys is locked at now, for
// the tenant tx is bound to: it returns the latest end of lock among them
// (after now), or the zero time when none is locked. Callers check it
// before verifying the password, so that a locked client costs no
// password hashing. It takes the tenant lock first. It returns ErrInvalid
// unless 1 to MaxFailureKeys distinct, well-formed keys are given. After an
// error, the caller must abort the transaction.
func (r *PasswordFailures) CheckTx(ctx context.Context, tx *ScopedTx, keys []FailureKey, now time.Time) (time.Time, error) {
	until, err := checkFailures(ctx, tx, keys, now)
	if err != nil {
		return time.Time{}, wrap("check password failures", err)
	}
	return until, nil
}

// checkFailures implements CheckTx, returning raw errors.
func checkFailures(ctx context.Context, tx *ScopedTx, keys []FailureKey, now time.Time) (time.Time, error) {
	if err := checkFailureKeys(keys); err != nil {
		return time.Time{}, err
	}
	if err := tx.lock(ctx); err != nil {
		return time.Time{}, err
	}
	var until time.Time
	for _, k := range keys {
		row, _, err := readFailure(ctx, tx, k)
		if err != nil {
			return time.Time{}, err
		}
		if row.lockedUntil.After(now) {
			until = later(until, row.lockedUntil)
		}
	}
	return until, nil
}

// RecordFailureTx counts, inside tx, a wrong password at now on every key
// of keys, for the tenant tx is bound to, and takes the tenant lock first.
// For each key:
//
//   - a key still locked at now is left unchanged;
//   - otherwise the failures PasswordFailureWindow old or older are
//     forgotten, an expired lock is cleared, and now joins the failure
//     times (the latest MaxPasswordFailures are kept);
//   - a key that then has MaxPasswordFailures failures, all within the
//     window, is locked until now + PasswordLockDuration.
//
// The outcome gives the attempts remaining (the minimum across the keys)
// and the latest end of lock, if any. It returns ErrInvalid unless 1 to
// MaxFailureKeys distinct, well-formed keys are given. After an error, the
// caller must abort the transaction.
func (r *PasswordFailures) RecordFailureTx(ctx context.Context, tx *ScopedTx, keys []FailureKey, now time.Time) (FailureOutcome, error) {
	out, err := recordFailures(ctx, tx, keys, now)
	if err != nil {
		return FailureOutcome{}, wrap("record password failure", err)
	}
	return out, nil
}

// recordFailures implements RecordFailureTx, returning raw errors.
func recordFailures(ctx context.Context, tx *ScopedTx, keys []FailureKey, now time.Time) (FailureOutcome, error) {
	if err := checkFailureKeys(keys); err != nil {
		return FailureOutcome{}, err
	}
	if err := tx.lock(ctx); err != nil {
		return FailureOutcome{}, err
	}
	now = fromMillis(toMillis(now))
	out := FailureOutcome{Remaining: MaxPasswordFailures}
	for _, k := range keys {
		row, found, err := readFailure(ctx, tx, k)
		if err != nil {
			return FailureOutcome{}, err
		}
		if row.lockedUntil.After(now) {
			out.Remaining = 0
			out.LockedUntil = later(out.LockedUntil, row.lockedUntil)
			continue
		}
		var next failureRow
		for _, at := range row.times {
			if now.Sub(at) < PasswordFailureWindow {
				next.times = append(next.times, at)
			}
		}
		next.times = append(next.times, now)
		next.times = next.times[max(len(next.times)-MaxPasswordFailures, 0):]
		if len(next.times) == MaxPasswordFailures {
			next.lockedUntil = now.Add(PasswordLockDuration)
			out.LockedUntil = later(out.LockedUntil, next.lockedUntil)
		}
		out.Remaining = min(out.Remaining, MaxPasswordFailures-len(next.times))
		if err := writeFailure(ctx, tx, k, next, found); err != nil {
			return FailureOutcome{}, err
		}
	}
	return out, nil
}

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// RefundTx withdraws, inside tx, the failure recorded at at on every key of
// keys, for the tenant tx is bound to, and takes the tenant lock first. The
// download layer counts each attempt as a failure before verifying the
// password, so that concurrent attempts can never exceed the limit, and
// refunds it on the client IP key when the password was right. For each
// key, one failure recorded at at (to the millisecond) is forgotten, if
// there is one, and the lock is cleared only when that failure set it (the
// lock ends at at + PasswordLockDuration). The other failures, a lock set
// by another attempt and the row itself are kept. It returns ErrInvalid
// unless 1 to MaxFailureKeys distinct, well-formed keys are given. After an
// error, the caller must abort the transaction.
func (r *PasswordFailures) RefundTx(ctx context.Context, tx *ScopedTx, keys []FailureKey, at time.Time) error {
	if err := refundFailures(ctx, tx, keys, at); err != nil {
		return wrap("refund password failure", err)
	}
	return nil
}

// refundFailures implements RefundTx, returning raw errors.
func refundFailures(ctx context.Context, tx *ScopedTx, keys []FailureKey, at time.Time) error {
	if err := checkFailureKeys(keys); err != nil {
		return err
	}
	if err := tx.lock(ctx); err != nil {
		return err
	}
	at = fromMillis(toMillis(at))
	for _, k := range keys {
		row, found, err := readFailure(ctx, tx, k)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(row.times, at.Equal)
		if i < 0 {
			continue
		}
		row.times = slices.Delete(row.times, i, i+1)
		if row.lockedUntil.Equal(at.Add(PasswordLockDuration)) {
			row.lockedUntil = time.Time{}
		}
		if err := writeFailure(ctx, tx, k, row, found); err != nil {
			return err
		}
	}
	return nil
}

// ResetTx clears, inside tx, the counters of keys for the tenant tx is
// bound to, deleting their rows. The download layer resets the transfer
// key after a right password; the client IP key gets a refund instead
// (RefundTx). It takes the tenant lock first. Keys without failures are
// ignored. It returns ErrInvalid unless 1 to MaxFailureKeys distinct,
// well-formed keys are given. After an error, the caller must abort the
// transaction.
func (r *PasswordFailures) ResetTx(ctx context.Context, tx *ScopedTx, keys []FailureKey) error {
	if err := resetFailures(ctx, tx, keys); err != nil {
		return wrap("reset password failures", err)
	}
	return nil
}

// resetFailures implements ResetTx, returning raw errors.
func resetFailures(ctx context.Context, tx *ScopedTx, keys []FailureKey) error {
	if err := checkFailureKeys(keys); err != nil {
		return err
	}
	if err := tx.lock(ctx); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := tx.Exec(ctx, qFailureDelete, string(k.Scope), k.Key); err != nil {
			return err
		}
	}
	return nil
}
