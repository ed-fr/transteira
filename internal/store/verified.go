package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// VerifiedRetentionMonths is how long an unused verified address stays
// verified (spec 7 and 20): after that, the cleanup job purges it, and until
// then [VerifiedAddress.Active] reports it as expired.
const VerifiedRetentionMonths = 12

// RecognitionSaltSize is the size of the random salt of a verified address
// that keys its browser recognition cookie entries.
const RecognitionSaltSize = 16

// verifiedColumns is the column list read by the verified address queries.
const verifiedColumns = `email, first_verified_at, first_verified_ip, internal_verified_at, internal_verified_ip, recognition_salt, last_used_at`

// Statements of the VerifiedAddresses repository.
var (
	qVerifiedGet = tenantQuery(
		`SELECT ` + verifiedColumns + ` FROM verified_addresses WHERE tenant_id = ? AND email = ?`)
	qVerifiedLastUsed = tenantQuery(
		`SELECT last_used_at, recognition_salt FROM verified_addresses WHERE tenant_id = ? AND email = ?`)
	qVerifiedResetSalt = tenantQuery(
		`UPDATE verified_addresses SET recognition_salt = ? WHERE tenant_id = ? AND email = ?`)
	qVerifiedTouch = tenantQuery(
		`UPDATE verified_addresses SET last_used_at = ? WHERE tenant_id = ? AND email = ?`)
	// qVerifiedReverify records a new verification of an active address: the
	// first verification details stay, the internal ones are only filled in
	// when still unset.
	qVerifiedReverify = tenantQuery(
		`UPDATE verified_addresses SET last_used_at = ?, internal_verified_at = COALESCE(internal_verified_at, ?),
		internal_verified_ip = COALESCE(internal_verified_ip, ?) WHERE tenant_id = ? AND email = ?`)
	// qVerifiedReset records the verification of an expired address as a
	// first verification, with a new recognition salt.
	qVerifiedReset = tenantQuery(
		`UPDATE verified_addresses SET first_verified_at = ?, first_verified_ip = ?, internal_verified_at = ?,
		internal_verified_ip = ?, recognition_salt = ?, last_used_at = ? WHERE tenant_id = ? AND email = ?`)
	qVerifiedInsert = tenantQuery(
		`INSERT INTO verified_addresses (tenant_id, email, first_verified_at, first_verified_ip,
		internal_verified_at, internal_verified_ip, recognition_salt, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
)

// VerifiedAddress is a mail address that passed the code verification once
// (spec 7). An address unused for VerifiedRetentionMonths is purged by the
// cleanup job; until then it is returned, and callers check
// [VerifiedAddress.Active].
type VerifiedAddress struct {
	// Email is the address, normalized by the store.
	Email string
	// FirstVerifiedAt is the time of the first verification; the store's
	// clock is used when it is zero.
	FirstVerifiedAt time.Time
	// FirstVerifiedIP is the client IP of the first verification.
	FirstVerifiedIP netip.Addr
	// InternalVerifiedAt is the time of the first verification done through
	// the internal rule (a code confirmed by an internal depositor, from an
	// internal IP), zero if none yet. It is the extension point of the V1.1
	// deposit from outside (spec 6.4), which requires such a verification.
	InternalVerifiedAt time.Time
	// InternalVerifiedIP is the client IP of that verification; it is set
	// exactly when InternalVerifiedAt is.
	InternalVerifiedIP netip.Addr
	// RecognitionSalt is the random salt (crypto/rand) of the browser
	// recognition cookie entries of the address. The store draws it at the
	// first verification and again when an expired address is verified anew
	// or [VerifiedAddresses.ResetRecognition] is called; the value given to
	// UpsertTx is ignored.
	RecognitionSalt [RecognitionSaltSize]byte
	// LastUsedAt is the time of the last use; FirstVerifiedAt is used when
	// it is zero.
	LastUsedAt time.Time
}

// Active reports whether the address is still verified at now: used within
// the last VerifiedRetentionMonths.
func (v VerifiedAddress) Active(now time.Time) bool {
	return verifiedActive(v.LastUsedAt, now)
}

// verifiedActive reports whether an address last used at lastUsed is still
// verified at now.
func verifiedActive(lastUsed, now time.Time) bool {
	return now.Before(lastUsed.AddDate(0, VerifiedRetentionMonths, 0))
}

// VerifiedAddresses is the tenant-scoped repository of verified addresses.
// Obtain it with [DB.VerifiedAddresses].
type VerifiedAddresses struct {
	db *DB
}

// VerifiedAddresses returns the verified address repository.
func (db *DB) VerifiedAddresses() *VerifiedAddresses { return &VerifiedAddresses{db: db} }

// Get returns the verified address email of tenant tid, or ErrNotFound when
// the address was never verified for this tenant. A malformed address
// yields ErrInvalid.
func (r *VerifiedAddresses) Get(ctx context.Context, tid tenant.ID, email string) (VerifiedAddress, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return VerifiedAddress{}, err
	}
	if email, err = NormalizeEmail(email); err != nil {
		return VerifiedAddress{}, err
	}
	var v VerifiedAddress
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var (
			ip          string
			internalIP  sql.NullString
			internalAt  sql.NullInt64
			salt        []byte
			first, last int64
		)
		err := tx.QueryRow(ctx, qVerifiedGet, email).Scan(&v.Email, &first, &ip, &internalAt, &internalIP, &salt, &last)
		copy(v.RecognitionSalt[:], salt)
		v.FirstVerifiedAt, v.FirstVerifiedIP, v.LastUsedAt = fromMillis(first), parseIP(ip), fromMillis(last)
		v.InternalVerifiedAt, v.InternalVerifiedIP = nullMillis(internalAt), parseIP(internalIP.String)
		return err
	})
	if err != nil {
		return VerifiedAddress{}, wrap("get verified address", err)
	}
	return v, nil
}

// Touch records a use of the verified address email of tenant tid at now,
// in its own transaction (see [VerifiedAddresses.TouchTx]).
func (r *VerifiedAddresses) Touch(ctx context.Context, tid tenant.ID, email string, now time.Time) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return touchVerified(ctx, tx, email, now) }); err != nil {
		return wrap("touch verified address", err)
	}
	return nil
}

// TouchTx records a use of the verified address email at now (its last use
// time), inside tx. It returns ErrNotFound when the address is not verified
// for the tenant tx is bound to and ErrInvalid for a malformed address.
func (r *VerifiedAddresses) TouchTx(ctx context.Context, tx *ScopedTx, email string, now time.Time) error {
	if err := touchVerified(ctx, tx, email, now); err != nil {
		return wrap("touch verified address", err)
	}
	return nil
}

// touchVerified updates the last use of email in tx, returning raw errors.
func touchVerified(ctx context.Context, tx *ScopedTx, email string, now time.Time) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	res, err := tx.Exec(ctx, qVerifiedTouch, toMillis(now), email)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// UpsertTx records a verification of v.Email for the tenant tx is bound to,
// inside tx (with the challenge consumption and the session creation), and
// returns the recognition salt of the address after the change. The
// verification time is v.LastUsedAt, or FirstVerifiedAt when it is zero.
//
//   - A new address is inserted with all the fields of v and a new salt.
//   - An active address (see [VerifiedAddress.Active], at the verification
//     time) keeps its first verification details and its salt, and gets the
//     new LastUsedAt; its internal verification details are set from v only
//     when it has none yet.
//   - An expired address is verified anew: every field is overwritten and
//     the salt is drawn again, which revokes its old recognition entries.
//
// InternalVerifiedAt and InternalVerifiedIP must be both set or both zero.
// It returns ErrInvalid for a malformed address or IP and ErrNotFound when
// the tenant does not exist. After an error, the caller must abort the
// transaction.
func (r *VerifiedAddresses) UpsertTx(ctx context.Context, tx *ScopedTx, v VerifiedAddress) ([RecognitionSaltSize]byte, error) {
	salt, err := r.upsert(ctx, tx, v)
	if err != nil {
		return [RecognitionSaltSize]byte{}, wrap("upsert verified address", err)
	}
	return salt, nil
}

// upsert validates and upserts v in tx, returning raw errors.
func (r *VerifiedAddresses) upsert(ctx context.Context, tx *ScopedTx, v VerifiedAddress) ([RecognitionSaltSize]byte, error) {
	var none [RecognitionSaltSize]byte
	email, err := NormalizeEmail(v.Email)
	if err != nil {
		return none, err
	}
	ip, err := ipText(v.FirstVerifiedIP)
	if err != nil {
		return none, err
	}
	var internalAt, internalIP any
	switch {
	case v.InternalVerifiedAt.IsZero() && !v.InternalVerifiedIP.IsValid():
	case v.InternalVerifiedAt.IsZero() || !v.InternalVerifiedIP.IsValid():
		return none, invalid("internal verification time and ip go together")
	default:
		text, _ := ipText(v.InternalVerifiedIP) // valid: checked above
		internalAt, internalIP = toMillis(v.InternalVerifiedAt), text
	}
	first := r.db.orNow(v.FirstVerifiedAt)
	last := first
	if !v.LastUsedAt.IsZero() {
		last = v.LastUsedAt
	}
	// The tenant lock serializes concurrent upserts of the tenant on
	// PostgreSQL, so that two transactions cannot both miss the row.
	if err := tx.lock(ctx); err != nil {
		return none, err
	}
	var (
		stored     int64
		storedSalt []byte
	)
	salt := newRecognitionSalt()
	err = tx.QueryRow(ctx, qVerifiedLastUsed, email).Scan(&stored, &storedSalt)
	switch {
	case errors.Is(err, ErrNotFound):
		_, err = tx.Exec(ctx, qVerifiedInsert, email, toMillis(first), ip, internalAt, internalIP, salt[:], toMillis(last))
	case err != nil:
	case verifiedActive(fromMillis(stored), last):
		copy(salt[:], storedSalt)
		_, err = tx.Exec(ctx, qVerifiedReverify, toMillis(last), internalAt, internalIP, email)
	default:
		_, err = tx.Exec(ctx, qVerifiedReset, toMillis(first), ip, internalAt, internalIP, salt[:], toMillis(last), email)
	}
	if err != nil {
		return none, err
	}
	return salt, nil
}

// newRecognitionSalt draws a recognition salt from crypto/rand, whose Read
// never returns an error (it aborts the program instead).
func newRecognitionSalt() [RecognitionSaltSize]byte {
	var salt [RecognitionSaltSize]byte
	_, _ = rand.Read(salt[:])
	return salt
}

// ResetRecognition draws a new recognition salt for the verified address
// email of tenant tid: every recognition cookie entry issued for it stops
// matching, so that the next deposit from any browser asks for a code
// again. The address stays verified. It is meant for the erasure of a
// person's data (spec 20) and for administration actions (a lost or shared
// computer). It returns ErrNotFound when the address is not verified for
// the tenant and ErrInvalid for a malformed address.
func (r *VerifiedAddresses) ResetRecognition(ctx context.Context, tid tenant.ID, email string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if email, err = NormalizeEmail(email); err != nil {
		return err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		salt := newRecognitionSalt()
		res, err := tx.Exec(ctx, qVerifiedResetSalt, salt[:], email)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("reset recognition", err)
	}
	return nil
}
