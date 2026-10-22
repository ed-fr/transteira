package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// Admin login lockout (spec 16.2, threat model T-62): the login layer
// counts failed logins in two scopes, each with its own limit, sliding
// window and lock duration (5 failures per username and IP, 20 per IP, in
// 15 minutes, in the plan of the admin authentication). There is no lock
// per username alone, which would let anyone lock the super admin out.
//
// Design: one row per (scope, key) keeps the times of the latest failures
// (at most MaxAdminLoginFailures, comma-separated Unix milliseconds) and
// the end of its lock, like password_failures keeps fail_1 to fail_3: a
// true sliding window for any limit up to 20, without one column per
// failure. Every call takes the admin login lock first (PostgreSQL;
// SQLite serializes writers anyway), so that concurrent attempts are
// counted exactly.
const (
	// MaxAdminLoginFailures is the largest limit of a rule, and the number
	// of failure times a row keeps at most.
	MaxAdminLoginFailures = 20
	// MaxAdminLoginKeys bounds the keys of one call.
	MaxAdminLoginKeys = 4
)

// AdminLoginScope is the scope of an admin login failure counter.
type AdminLoginScope string

// Admin login failure scopes.
const (
	// AdminLoginScopeUserIP counts the failures of one username from one
	// client IP.
	AdminLoginScopeUserIP AdminLoginScope = "user_ip"
	// AdminLoginScopeIP counts the failures of one client IP, every
	// username together.
	AdminLoginScopeIP AdminLoginScope = "ip"
	// AdminLoginScopeTOTP counts the wrong second factors of one
	// administrator, from any client IP.
	AdminLoginScopeTOTP AdminLoginScope = "admin_totp"
)

// AdminLoginKey identifies an admin login failure counter. Build it with
// [AdminLoginUserIPKey] or [AdminLoginIPKey].
type AdminLoginKey struct {
	// Scope is the scope of the counter.
	Scope AdminLoginScope
	// Key is the hex SHA-256 of the username and IP key for
	// AdminLoginScopeUserIP, the IP key for AdminLoginScopeIP (see
	// IPFailureKey) and the administrator ID for AdminLoginScopeTOTP.
	Key string
}

// AdminLoginTOTPKey returns the second factor counter of the administrator
// adminID ("adm_" + ULID), shared by every client IP. The key of a
// malformed ID is invalid.
func AdminLoginTOTPKey(adminID string) AdminLoginKey {
	return AdminLoginKey{Scope: AdminLoginScopeTOTP, Key: adminID}
}

// AdminLoginIPKey returns the counter of the client ip: an IPv4 address is
// keyed by itself, an IPv6 address by its /64 prefix (see IPFailureKey).
// The key of the zero Addr is invalid.
func AdminLoginIPKey(ip netip.Addr) AdminLoginKey {
	return AdminLoginKey{Scope: AdminLoginScopeIP, Key: IPFailureKey(ip).Key}
}

// AdminLoginUserIPKey returns the counter of the username (as typed: it is
// trimmed and lower-cased, so that case variants share the counter, even
// for a malformed username) from the client ip. The key is the hex SHA-256
// of the folded username, a NUL byte and the IP key, so that the table
// never pairs a username with an IP in clear. The key of the zero Addr is
// invalid.
func AdminLoginUserIPKey(username string, ip netip.Addr) AdminLoginKey {
	ipKey := IPFailureKey(ip).Key
	if ipKey == "" {
		return AdminLoginKey{Scope: AdminLoginScopeUserIP}
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username)) + "\x00" + ipKey))
	return AdminLoginKey{Scope: AdminLoginScopeUserIP, Key: hex.EncodeToString(sum[:])}
}

// valid reports whether k is a well-formed key.
func (k AdminLoginKey) valid() bool {
	switch k.Scope {
	case AdminLoginScopeIP:
		return FailureKey{Scope: FailureScopeIP, Key: k.Key}.valid()
	case AdminLoginScopeUserIP:
		b, err := hex.DecodeString(k.Key)
		return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == k.Key
	case AdminLoginScopeTOTP:
		return id.Valid(id.Admin, k.Key)
	}
	return false
}

// AdminLoginRule is a counter with its limit: MaxFailures failures within
// any Window lock it for LockDuration.
type AdminLoginRule struct {
	// Key is the counter.
	Key AdminLoginKey
	// MaxFailures is the limit, 1 to MaxAdminLoginFailures.
	MaxFailures int
	// Window is the sliding window failures are counted in (positive).
	Window time.Duration
	// LockDuration is how long the counter stays locked (positive).
	LockDuration time.Duration
}

// checkLoginKeys validates 1 to MaxAdminLoginKeys distinct keys.
func checkLoginKeys(keys []AdminLoginKey) error {
	if len(keys) == 0 || len(keys) > MaxAdminLoginKeys {
		return invalid("1 to %d login failure keys are required", MaxAdminLoginKeys)
	}
	seen := make(map[AdminLoginKey]bool, len(keys))
	for _, k := range keys {
		if !k.valid() {
			return invalid("malformed login failure key")
		}
		if seen[k] {
			return invalid("duplicate login failure key")
		}
		seen[k] = true
	}
	return nil
}

// checkLoginRules validates the rules and their keys.
func checkLoginRules(rules []AdminLoginRule) error {
	keys := make([]AdminLoginKey, 0, len(rules))
	for _, r := range rules {
		if r.MaxFailures < 1 || r.MaxFailures > MaxAdminLoginFailures || r.Window <= 0 || r.LockDuration <= 0 {
			return invalid("a login failure rule needs 1 to %d failures and positive durations", MaxAdminLoginFailures)
		}
		keys = append(keys, r.Key)
	}
	return checkLoginKeys(keys)
}

// Statements of the AdminLoginFailures repository.
var (
	qLoginFailureGet = systemQuery(
		`SELECT failures, locked_until FROM admin_login_failures WHERE scope = ? AND key = ?`,
		reasonAdminAuth)
	qLoginFailureInsert = systemQuery(
		`INSERT INTO admin_login_failures (scope, key, failures, last_failure_at, locked_until) VALUES (?, ?, ?, ?, ?)`,
		reasonAdminAuth)
	qLoginFailureUpdate = systemQuery(
		`UPDATE admin_login_failures SET failures = ?, last_failure_at = ?, locked_until = ? WHERE scope = ? AND key = ?`,
		reasonAdminAuth)
	qLoginFailureDelete = systemQuery(
		`DELETE FROM admin_login_failures WHERE scope = ? AND key = ?`,
		reasonAdminAuth)
	qLoginFailurePurge = systemQuery(
		`DELETE FROM admin_login_failures WHERE (scope, key) IN (SELECT scope, key FROM admin_login_failures
		WHERE COALESCE(last_failure_at, 0) <= ? AND COALESCE(locked_until, 0) <= ? ORDER BY scope, key LIMIT ?)`,
		reasonAdminAuth)
)

// loginRow is a stored counter: failure times, oldest first, and the end
// of its lock (zero when none).
type loginRow struct {
	times       []time.Time
	lockedUntil time.Time
}

// errLoginRow reports a corrupted failures column.
var errLoginRow = errors.New("store: malformed admin login failure row")

// readLoginRow reads the counter k inside tx; found is false when it has no
// row.
func readLoginRow(ctx context.Context, tx *SystemTx, k AdminLoginKey) (row loginRow, found bool, err error) {
	var (
		list   string
		locked sql.NullInt64
	)
	err = tx.QueryRow(ctx, qLoginFailureGet, string(k.Scope), k.Key).Scan(&list, &locked)
	if errors.Is(err, ErrNotFound) {
		return loginRow{}, false, nil
	}
	if err != nil {
		return loginRow{}, false, err
	}
	if list != "" {
		for s := range strings.SplitSeq(list, ",") {
			ms, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return loginRow{}, false, errLoginRow
			}
			row.times = append(row.times, fromMillis(ms))
		}
	}
	row.lockedUntil = nullMillis(locked)
	return row, true, nil
}

// writeLoginRow stores row as the counter k inside tx, inserting it when
// found is false.
func writeLoginRow(ctx context.Context, tx *SystemTx, k AdminLoginKey, row loginRow, found bool) error {
	parts := make([]string, len(row.times))
	var last any
	for i, at := range row.times {
		parts[i] = strconv.FormatInt(toMillis(at), 10)
		last = toMillis(at)
	}
	var locked any
	if !row.lockedUntil.IsZero() {
		locked = toMillis(row.lockedUntil)
	}
	list := strings.Join(parts, ",")
	var err error
	if found {
		_, err = tx.Exec(ctx, qLoginFailureUpdate, list, last, locked, string(k.Scope), k.Key)
	} else {
		_, err = tx.Exec(ctx, qLoginFailureInsert, string(k.Scope), k.Key, list, last, locked)
	}
	return err
}

// AdminLoginFailures is the repository of the admin login failure
// counters. Its operations are system-scoped, each in its own transaction
// taking the admin login lock. Locks expire by time, compared with the
// caller's now.
//
// The login layer counts an attempt before verifying the password
// ([AdminLoginFailures.RecordFailure]), so that concurrent attempts can
// never exceed the limit, then, when the password was right, resets the
// username and IP counter ([AdminLoginFailures.Reset]) and refunds the IP
// counter ([AdminLoginFailures.Refund]). The cleanup task purges the stale
// rows ([AdminLoginFailures.Purge]).
type AdminLoginFailures struct {
	db *DB
}

// AdminLoginFailures returns the admin login failure repository.
func (db *DB) AdminLoginFailures() *AdminLoginFailures { return &AdminLoginFailures{db: db} }

// loginTx runs fn in a write transaction holding the admin login lock.
func (r *AdminLoginFailures) loginTx(ctx context.Context, op string, fn func(*SystemTx) error) error {
	return r.db.authWrite(ctx, op, func(tx *SystemTx) error {
		if err := tx.lock(ctx, lockAdminLogin); err != nil {
			return err
		}
		return fn(tx)
	})
}

// Check reports whether any of keys is locked at now: it returns the
// latest end of lock among them (after now), or the zero time when none is
// locked. It returns ErrInvalid unless 1 to MaxAdminLoginKeys distinct,
// well-formed keys are given.
func (r *AdminLoginFailures) Check(ctx context.Context, keys []AdminLoginKey, now time.Time) (time.Time, error) {
	if err := checkLoginKeys(keys); err != nil {
		return time.Time{}, err
	}
	var until time.Time
	err := r.loginTx(ctx, "check admin login failures", func(tx *SystemTx) error {
		for _, k := range keys {
			row, _, err := readLoginRow(ctx, tx, k)
			if err != nil {
				return err
			}
			if row.lockedUntil.After(now) {
				until = later(until, row.lockedUntil)
			}
		}
		return nil
	})
	return until, err
}

// RecordFailure counts a failed login at now on the counter of every rule.
// For each rule:
//
//   - a counter still locked at now is left unchanged;
//   - otherwise the failures Window old or older are forgotten, an expired
//     lock is cleared, and now joins the failure times (the latest
//     MaxFailures are kept);
//   - a counter that then has MaxFailures failures within the window is
//     locked until now + LockDuration.
//
// The outcome gives the attempts remaining (the minimum across the rules,
// 0 when one is locked) and the latest end of lock, if any. It returns
// ErrInvalid for a malformed rule or unless 1 to MaxAdminLoginKeys
// distinct keys are given.
func (r *AdminLoginFailures) RecordFailure(ctx context.Context, rules []AdminLoginRule, now time.Time) (FailureOutcome, error) {
	if err := checkLoginRules(rules); err != nil {
		return FailureOutcome{}, err
	}
	now = fromMillis(toMillis(now))
	out := FailureOutcome{Remaining: MaxAdminLoginFailures}
	err := r.loginTx(ctx, "record admin login failure", func(tx *SystemTx) error {
		for _, rule := range rules {
			row, found, err := readLoginRow(ctx, tx, rule.Key)
			if err != nil {
				return err
			}
			if row.lockedUntil.After(now) {
				out.Remaining = 0
				out.LockedUntil = later(out.LockedUntil, row.lockedUntil)
				continue
			}
			var next loginRow
			for _, at := range row.times {
				if now.Sub(at) < rule.Window {
					next.times = append(next.times, at)
				}
			}
			next.times = append(next.times, now)
			next.times = next.times[max(len(next.times)-rule.MaxFailures, 0):]
			if len(next.times) == rule.MaxFailures {
				next.lockedUntil = now.Add(rule.LockDuration)
				out.LockedUntil = later(out.LockedUntil, next.lockedUntil)
			}
			out.Remaining = min(out.Remaining, rule.MaxFailures-len(next.times))
			if err := writeLoginRow(ctx, tx, rule.Key, next, found); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return FailureOutcome{}, err
	}
	return out, nil
}

// Refund withdraws the failure recorded at at on the counter of every
// rule: one failure recorded at at (to the millisecond) is forgotten, if
// there is one, and the lock is cleared only when that failure set it (the
// lock ends at at + LockDuration). The other failures and a lock set by
// another attempt are kept. It returns ErrInvalid like RecordFailure.
func (r *AdminLoginFailures) Refund(ctx context.Context, rules []AdminLoginRule, at time.Time) error {
	if err := checkLoginRules(rules); err != nil {
		return err
	}
	at = fromMillis(toMillis(at))
	return r.loginTx(ctx, "refund admin login failure", func(tx *SystemTx) error {
		for _, rule := range rules {
			row, found, err := readLoginRow(ctx, tx, rule.Key)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(row.times, at.Equal)
			if i < 0 {
				continue
			}
			row.times = slices.Delete(row.times, i, i+1)
			if row.lockedUntil.Equal(at.Add(rule.LockDuration)) {
				row.lockedUntil = time.Time{}
			}
			if err := writeLoginRow(ctx, tx, rule.Key, row, found); err != nil {
				return err
			}
		}
		return nil
	})
}

// Reset clears the counters of keys, deleting their rows (keys without
// failures are ignored). It returns ErrInvalid unless 1 to
// MaxAdminLoginKeys distinct, well-formed keys are given.
func (r *AdminLoginFailures) Reset(ctx context.Context, keys []AdminLoginKey) error {
	if err := checkLoginKeys(keys); err != nil {
		return err
	}
	return r.loginTx(ctx, "reset admin login failures", func(tx *SystemTx) error {
		for _, k := range keys {
			if _, err := tx.Exec(ctx, qLoginFailureDelete, string(k.Scope), k.Key); err != nil {
				return err
			}
		}
		return nil
	})
}

// Purge deletes the counters that are stale at now: their latest failure
// is window old or older and no lock is running. window must be the
// longest Window of the rules in use (positive). It works in batches of
// PurgeBatchSize and returns how many it deleted.
func (r *AdminLoginFailures) Purge(ctx context.Context, now time.Time, window time.Duration) (int64, error) {
	if window <= 0 {
		return 0, invalid("the purge window must be positive")
	}
	return r.db.purgeSystem(ctx, reasonAdminAuth, "purge admin login failures", lockAdminLogin, qLoginFailurePurge,
		toMillis(now.Add(-window)), toMillis(now))
}
