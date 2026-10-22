package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// InvitationValidityMonths is the validity of an invitation (spec 9 and
// 20): it expires 12 months after its creation or its last use, whichever
// is later.
const InvitationValidityMonths = 12

// MaxInvitationMessageLen bounds the message of an invitation, in
// characters (OpenAPI InvitationCreate).
const MaxInvitationMessageLen = 2000

// invitationColumns is the column list read by the invitation queries.
const invitationColumns = `id, token_hash, email, invited_by, message, language, created_at, expires_at, last_used_at, revoked_at`

// Statements of the Invitations repository.
var (
	qInvitationInsert = tenantQuery(
		`INSERT INTO invitations (tenant_id, id, token_hash, email, invited_by, message, language, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qInvitationGet = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations WHERE tenant_id = ? AND id = ?`)
	qInvitationGetByHash = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations WHERE tenant_id = ? AND token_hash = ?`)
	// qInvitationTouch records a use of an active invitation and moves its
	// expiry to the new end of validity when that is later. Arguments after
	// the tenant: last use, new expiry (twice), ID, now.
	qInvitationTouch = tenantQuery(
		`UPDATE invitations SET last_used_at = ?, expires_at = (CASE WHEN expires_at < ? THEN ? ELSE expires_at END)
		WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL AND expires_at > ?`)
	qInvitationCountInviter = tenantQuery(
		`SELECT count(*) FROM invitations WHERE tenant_id = ? AND invited_by = ? AND created_at >= ?`)
	qInvitationDelete = tenantQuery(
		`DELETE FROM invitations WHERE tenant_id = ? AND id = ?`)
	qInvitationRevoke = tenantQuery(
		`UPDATE invitations SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`)
)

// InvitationExpiry returns the end of validity of an invitation created or
// last used at t: InvitationValidityMonths later.
func InvitationExpiry(t time.Time) time.Time {
	return t.AddDate(0, InvitationValidityMonths, 0)
}

// Invitation lets an external person deposit files for the internal user
// who invited them (spec 9). The link carries a bearer token whose SHA-256
// is TokenHash; the store never sees the token.
type Invitation struct {
	// ID is the administration identifier ("inv_" + ULID), assigned by the
	// caller. It is distinct from the link token.
	ID string
	// TokenHash is the SHA-256 of the link token (TokenHashSize bytes).
	TokenHash []byte
	// Email is the invited address, normalized by the store.
	Email string
	// InvitedBy is the address of the internal user who issued the
	// invitation, normalized by the store.
	InvitedBy string
	// Message is an optional message for the invited person (at most
	// MaxInvitationMessageLen characters).
	Message string
	// Language is the language of the invitation mail, "" for the tenant
	// default.
	Language string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// ExpiresAt is the end of validity; InvitationExpiry(CreatedAt) when it
	// is zero. [Invitations.TouchTx] moves it forward on each use.
	ExpiresAt time.Time
	// LastUsedAt is the time of the last use, zero if never used.
	LastUsedAt time.Time
	// RevokedAt is the revocation time, zero if not revoked.
	RevokedAt time.Time
}

// Active reports whether the invitation can be used at now: neither
// revoked nor expired. The lookups return invitations in any state, so
// that callers can tell them apart; [Invitations.TouchTx] checks the same
// conditions atomically.
func (inv Invitation) Active(now time.Time) bool {
	return inv.RevokedAt.IsZero() && now.Before(inv.ExpiresAt)
}

// Invitations is the tenant-scoped repository of external invitations.
// Obtain it with [DB.Invitations].
//
// Retention: the per-inviter rate limit counts the invitations created
// during the last hour, whatever their state. A future purge of revoked or
// expired invitations must keep every row at least until CreatedAt + 1 hour
// (the RateWindow of the deposit service).
type Invitations struct {
	db *DB
}

// Invitations returns the invitation repository.
func (db *DB) Invitations() *Invitations { return &Invitations{db: db} }

// Create stores inv for tenant tid in its own transaction (see
// [Invitations.CreateTx]).
func (r *Invitations) Create(ctx context.Context, tid tenant.ID, inv Invitation) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return r.create(ctx, tx, inv) }); err != nil {
		return wrap("create invitation", err)
	}
	return nil
}

// CreateTx stores inv for the tenant tx is bound to, inside tx. It returns
// ErrInvalid for a malformed field, ErrNotFound when the tenant does not
// exist and ErrConflict when the ID or the token hash is already used.
// After an error, the caller must abort the transaction.
func (r *Invitations) CreateTx(ctx context.Context, tx *ScopedTx, inv Invitation) error {
	if err := r.create(ctx, tx, inv); err != nil {
		return wrap("create invitation", err)
	}
	return nil
}

// create validates and inserts inv in tx, returning raw errors.
func (r *Invitations) create(ctx context.Context, tx *ScopedTx, inv Invitation) error {
	email, err := NormalizeEmail(inv.Email)
	if err != nil {
		return err
	}
	by, err := NormalizeEmail(inv.InvitedBy)
	if err != nil {
		return err
	}
	created := r.db.orNow(inv.CreatedAt)
	expires := inv.ExpiresAt
	if expires.IsZero() {
		expires = InvitationExpiry(created)
	}
	switch {
	case !id.Valid(id.Invitation, inv.ID):
		return invalid("malformed invitation id")
	case !validTokenHash(inv.TokenHash):
		return invalid("token hash must hold %d bytes", TokenHashSize)
	case !validText(inv.Message, MaxInvitationMessageLen, false):
		return invalid("message must be text of at most %d characters", MaxInvitationMessageLen)
	case inv.Language != "" && !tenant.IsLanguage(inv.Language):
		return invalid("unsupported language")
	case !expires.After(created):
		return invalid("invitation must expire after its creation")
	case !inv.LastUsedAt.IsZero() || !inv.RevokedAt.IsZero():
		return invalid("a new invitation cannot be used or revoked")
	}
	_, err = tx.Exec(ctx, qInvitationInsert, inv.ID, inv.TokenHash, email, by, inv.Message, inv.Language,
		toMillis(created), toMillis(expires))
	return err
}

// CountByInviterSinceTx returns the number of invitations issued by the
// address inviter in the tenant tx is bound to at or after since, whatever
// their state: the per-inviter rate limit. Like [Challenges.CountSinceTx],
// it first takes the tenant lock, so that a count followed by
// [Invitations.CreateTx] in the same transaction is atomic against
// concurrent invitations of the tenant. It returns ErrInvalid for a
// malformed address. After an error, the caller must abort the transaction.
func (r *Invitations) CountByInviterSinceTx(ctx context.Context, tx *ScopedTx, inviter string, since time.Time) (int, error) {
	inviter, err := NormalizeEmail(inviter)
	if err != nil {
		return 0, err
	}
	return countTx(ctx, tx, qInvitationCountInviter, inviter, since, "count invitations")
}

// scanInvitation reads one row of invitationColumns.
func scanInvitation(row interface{ Scan(...any) error }) (Invitation, error) {
	var (
		inv              Invitation
		created, expires int64
		used, revoked    sql.NullInt64
	)
	err := row.Scan(&inv.ID, &inv.TokenHash, &inv.Email, &inv.InvitedBy, &inv.Message, &inv.Language,
		&created, &expires, &used, &revoked)
	if err != nil {
		return Invitation{}, err
	}
	inv.CreatedAt, inv.ExpiresAt = fromMillis(created), fromMillis(expires)
	inv.LastUsedAt, inv.RevokedAt = nullMillis(used), nullMillis(revoked)
	return inv, nil
}

// get runs a single-invitation lookup.
func (r *Invitations) get(ctx context.Context, tid tenant.ID, q TenantQuery, arg any) (Invitation, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return Invitation{}, err
	}
	var inv Invitation
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var err error
		inv, err = scanInvitation(tx.QueryRow(ctx, q, arg))
		return err
	})
	if err != nil {
		return Invitation{}, wrap("get invitation", err)
	}
	return inv, nil
}

// Get returns the invitation invID of tenant tid in whatever state it is
// (see [Invitation.Active]), or ErrNotFound when it does not exist or
// belongs to another tenant.
func (r *Invitations) Get(ctx context.Context, tid tenant.ID, invID string) (Invitation, error) {
	return r.get(ctx, tid, qInvitationGet, invID)
}

// GetByTokenHash returns the invitation of tenant tid whose link token
// hashes to hash, in whatever state it is (see [Invitation.Active]). It
// returns ErrNotFound when there is none, including for an invitation of
// another tenant (the lookup runs in the tenant scope, under row-level
// security on PostgreSQL), and ErrInvalid for a hash of the wrong size.
func (r *Invitations) GetByTokenHash(ctx context.Context, tid tenant.ID, hash []byte) (Invitation, error) {
	if !validTokenHash(hash) {
		return Invitation{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return r.get(ctx, tid, qInvitationGetByHash, hash)
}

// TouchTx records a use of the invitation invID at now, inside tx (when the
// invited person opens a deposit session): LastUsedAt becomes now and
// ExpiresAt moves to InvitationExpiry(now) when that is later, so that an
// invitation expires 12 months after its creation or its last use,
// whichever is later. It only applies to an invitation active at now (see
// [Invitation.Active]): otherwise, or when the invitation does not exist or
// belongs to another tenant, it returns ErrNotFound. After an error, the
// caller must abort the transaction.
func (r *Invitations) TouchTx(ctx context.Context, tx *ScopedTx, invID string, now time.Time) error {
	ms, until := toMillis(now), toMillis(InvitationExpiry(now))
	res, err := tx.Exec(ctx, qInvitationTouch, ms, until, until, invID, ms)
	if err == nil {
		err = expectOne(res)
	}
	if err != nil {
		return wrap("touch invitation", err)
	}
	return nil
}

// Revoke revokes the invitation invID of tenant tid at now. It returns
// ErrNotFound when the invitation does not exist, belongs to another tenant
// or is already revoked. Revoking does not end the deposit sessions opened
// with the invitation; callers end them if needed.
func (r *Invitations) Revoke(ctx context.Context, tid tenant.ID, invID string, now time.Time) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		res, err := tx.Exec(ctx, qInvitationRevoke, toMillis(now), invID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("revoke invitation", err)
	}
	return nil
}

// Delete removes the invitation invID of tenant tid, whatever its state,
// together with (by cascade) the verification challenges and deposit
// sessions opened with it. The deposit service uses it for an invitation
// whose mail could not be queued, which nothing references yet, so that it
// neither lingers nor counts against the per-inviter limit. It returns
// ErrNotFound when the invitation does not exist or belongs to another
// tenant.
func (r *Invitations) Delete(ctx context.Context, tid tenant.ID, invID string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		res, err := tx.Exec(ctx, qInvitationDelete, invID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("delete invitation", err)
	}
	return nil
}
