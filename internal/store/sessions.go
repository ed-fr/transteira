package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DepositorKind tells how a depositor was allowed to deposit (OpenAPI
// DepositorKind).
type DepositorKind string

// Depositor kinds. Later versions add others (drop_link), with a migration
// of the kind constraint.
const (
	// DepositorInternal is an internal user: internal IP and domain.
	DepositorInternal DepositorKind = "internal"
	// DepositorExternal is an external user holding an invitation.
	DepositorExternal DepositorKind = "external"
	// DepositorInternalRemote is an internal user depositing from outside
	// the tenant's IP ranges (spec 6.4): an address of an allowed domain,
	// already verified once from inside, proving it again by code at every
	// deposit. It has the invariants of an internal depositor (no
	// invitation; an API token is allowed by the schema).
	DepositorInternalRemote DepositorKind = "internal_remote"
	// DepositorReply is the recipient of a transfer sending files back to
	// its sender through a reply link (spec 10): the address of the
	// recipient link, verified by code. It follows the rules of an
	// external depositor (quotas, antivirus, abuse detection), has no
	// invitation and no API token, and is bound to its source transfer.
	DepositorReply DepositorKind = "reply"
)

// IsInternal reports whether k is an internal kind: [DepositorInternal]
// or [DepositorInternalRemote].
func (k DepositorKind) IsInternal() bool {
	return k == DepositorInternal || k == DepositorInternalRemote
}

// IsExternal reports whether k is a kind subject to the external rules
// and quotas (spec 15.2): [DepositorExternal] or [DepositorReply].
func (k DepositorKind) IsExternal() bool {
	return k == DepositorExternal || k == DepositorReply
}

// validDepositorKind reports whether k is a kind the store accepts for a
// deposit session or a transfer.
func validDepositorKind(k DepositorKind) bool {
	return k.IsInternal() || k.IsExternal()
}

// sessionColumns is the column list read by the deposit session queries.
const sessionColumns = `id, token_hash, email, kind, invitation_id, created_at, expires_at, reply_to_transfer_id, ` +
	`recipient_link_id`

// Statements of the DepositSessions repository.
var (
	qSessionInsert = tenantQuery(
		`INSERT INTO deposit_sessions (tenant_id, id, token_hash, email, kind, invitation_id, created_at, expires_at,
		reply_to_transfer_id, recipient_link_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	// qSessionReplyLink counts the recipient link of a reply session when
	// it belongs to the source transfer, in the same tenant: the composite
	// foreign keys prove the tenant of each, not that they match.
	qSessionReplyLink = tenantQuery(
		`SELECT count(*) FROM recipient_links WHERE tenant_id = ? AND id = ? AND transfer_id = ?`)
	// qSessionCountLiveReply counts the reply sessions of a recipient link
	// that are neither ended nor expired.
	qSessionCountLiveReply = tenantQuery(
		`SELECT count(*) FROM deposit_sessions
		WHERE tenant_id = ? AND recipient_link_id = ? AND ended_at IS NULL AND expires_at > ?`)
	// qSessionGet only returns a session that is neither ended nor expired.
	qSessionGet = tenantQuery(
		`SELECT ` + sessionColumns + ` FROM deposit_sessions
		WHERE tenant_id = ? AND token_hash = ? AND ended_at IS NULL AND expires_at > ?`)
	qSessionEnd = tenantQuery(
		`UPDATE deposit_sessions SET ended_at = ?
		WHERE tenant_id = ? AND token_hash = ? AND ended_at IS NULL AND expires_at > ?`)
)

// DepositSession is a deposit session opened after the depositor's address
// was verified, carried by a cookie. Only the SHA-256 of the cookie token
// is stored.
type DepositSession struct {
	// ID is the internal identifier ("ds_" + ULID), assigned by the caller.
	// It never leaves the server.
	ID string
	// TokenHash is the SHA-256 of the cookie token (TokenHashSize bytes).
	TokenHash []byte
	// Email is the verified address of the depositor, normalized by the
	// store.
	Email string
	// Kind is the depositor kind.
	Kind DepositorKind
	// InvitationID is the invitation of an external depositor ("inv_" +
	// ULID, same tenant), "" for any other kind. Deleting the invitation
	// deletes the session; revoking it does not end the session.
	InvitationID string
	// ReplyToTransferID is the source transfer of a reply session ("trf_" +
	// ULID, same tenant), "" for any other kind. Deleting the source
	// transfer row deletes the session.
	ReplyToTransferID string
	// RecipientLinkID is the recipient link of the source transfer that
	// verified the replier ("rcl_" + ULID, same tenant and transfer), ""
	// unless the session is a reply. Deleting the link deletes the
	// session.
	RecipientLinkID string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// ExpiresAt is the absolute end of the session, after CreatedAt.
	ExpiresAt time.Time
	// EndedAt is when the depositor ended the session; always zero in the
	// sessions returned by [DepositSessions.GetByTokenHash].
	EndedAt time.Time
}

// DepositSessions is the tenant-scoped repository of deposit sessions.
// Obtain it with [DB.DepositSessions].
type DepositSessions struct {
	db *DB
}

// DepositSessions returns the deposit session repository.
func (db *DB) DepositSessions() *DepositSessions { return &DepositSessions{db: db} }

// Create stores s for tenant tid in its own transaction (see
// [DepositSessions.CreateTx]).
func (r *DepositSessions) Create(ctx context.Context, tid tenant.ID, s DepositSession) error {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := sc.Tx(ctx, func(tx *ScopedTx) error { return r.create(ctx, tx, s) }); err != nil {
		return wrap("create deposit session", err)
	}
	return nil
}

// CreateTx stores s for the tenant tx is bound to, inside tx (with the
// challenge consumption and the address verification). It returns
// ErrInvalid for a malformed field (an external session needs an
// invitation, every other kind none; a reply session needs its source
// transfer and recipient link, every other kind none), ErrNotFound when the
// tenant, the invitation, the source transfer or the recipient link does
// not exist (or belongs to another tenant), or when the link is not one of
// the source transfer, and ErrConflict when the ID or the token hash is
// already used. After an error, the caller must abort the transaction.
func (r *DepositSessions) CreateTx(ctx context.Context, tx *ScopedTx, s DepositSession) error {
	if err := r.create(ctx, tx, s); err != nil {
		return wrap("create deposit session", err)
	}
	return nil
}

// create validates and inserts s in tx, returning raw errors.
func (r *DepositSessions) create(ctx context.Context, tx *ScopedTx, s DepositSession) error {
	email, err := NormalizeEmail(s.Email)
	if err != nil {
		return err
	}
	created := r.db.orNow(s.CreatedAt)
	switch {
	case !id.Valid(id.DepositSession, s.ID):
		return invalid("malformed deposit session id")
	case !validTokenHash(s.TokenHash):
		return invalid("token hash must hold %d bytes", TokenHashSize)
	case !validDepositorKind(s.Kind):
		return invalid("unknown depositor kind")
	case (s.Kind == DepositorExternal) != (s.InvitationID != ""):
		return invalid("an external session needs an invitation, an internal one none")
	case s.InvitationID != "" && !id.Valid(id.Invitation, s.InvitationID):
		return invalid("malformed invitation id")
	case (s.Kind == DepositorReply) != (s.ReplyToTransferID != "") ||
		(s.Kind == DepositorReply) != (s.RecipientLinkID != ""):
		return invalid("a reply session needs its source transfer and recipient link, another kind none")
	case s.ReplyToTransferID != "" && !id.Valid(id.Transfer, s.ReplyToTransferID):
		return invalid("malformed source transfer id")
	case s.RecipientLinkID != "" && !id.Valid(id.RecipientLink, s.RecipientLinkID):
		return invalid("malformed recipient link id")
	case !s.ExpiresAt.After(created):
		return invalid("session must expire after its creation")
	case !s.EndedAt.IsZero():
		return invalid("a new session cannot be ended")
	}
	if s.Kind == DepositorReply {
		var n int
		if err := tx.QueryRow(ctx, qSessionReplyLink, s.RecipientLinkID, s.ReplyToTransferID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
	}
	_, err = tx.Exec(ctx, qSessionInsert, s.ID, s.TokenHash, email, string(s.Kind), nullText(s.InvitationID),
		toMillis(created), toMillis(s.ExpiresAt), nullText(s.ReplyToTransferID), nullText(s.RecipientLinkID))
	return err
}

// CountLiveReplyTx returns the number of reply sessions opened through the
// recipient link linkID in the tenant tx is bound to that are neither ended
// nor expired at now: the bound on the reply sessions of a link (threat
// model P33). Like [Challenges.CountSinceTx], it first takes the tenant
// lock, so that a count followed by [DepositSessions.CreateTx] in the same
// transaction is atomic against concurrent openings in the tenant. A link
// of another tenant counts nothing. After an error, the caller must abort
// the transaction.
func (r *DepositSessions) CountLiveReplyTx(ctx context.Context, tx *ScopedTx, linkID string, now time.Time) (int, error) {
	return countTx(ctx, tx, qSessionCountLiveReply, linkID, now, "count live reply sessions")
}

// GetByTokenHash returns the session of tenant tid whose cookie token
// hashes to hash, provided it is neither ended nor expired at now. It
// returns ErrNotFound otherwise, including for a session of another tenant
// (the lookup runs in the tenant scope, under row-level security on
// PostgreSQL), and ErrInvalid for a hash of the wrong size.
func (r *DepositSessions) GetByTokenHash(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (DepositSession, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return DepositSession{}, err
	}
	if !validTokenHash(hash) {
		return DepositSession{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	var s DepositSession
	err = sc.ReadTx(ctx, func(tx *ScopedTx) error {
		var (
			kind             string
			inv, reply, link sql.NullString
			created, expires int64
		)
		err := tx.QueryRow(ctx, qSessionGet, hash, toMillis(now)).Scan(&s.ID, &s.TokenHash, &s.Email, &kind,
			&inv, &created, &expires, &reply, &link)
		s.Kind, s.InvitationID = DepositorKind(kind), inv.String
		s.ReplyToTransferID, s.RecipientLinkID = reply.String, link.String
		s.CreatedAt, s.ExpiresAt = fromMillis(created), fromMillis(expires)
		return err
	})
	if err != nil {
		return DepositSession{}, wrap("get deposit session", err)
	}
	return s, nil
}

// End ends the session of tenant tid whose cookie token hashes to hash, at
// now. It returns ErrNotFound when no such session is active at now
// (unknown, already ended, expired or of another tenant) and ErrInvalid for
// a hash of the wrong size.
func (r *DepositSessions) End(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if !validTokenHash(hash) {
		return invalid("token hash must hold %d bytes", TokenHashSize)
	}
	err = sc.Tx(ctx, func(tx *ScopedTx) error {
		ms := toMillis(now)
		res, err := tx.Exec(ctx, qSessionEnd, ms, hash, ms)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("end deposit session", err)
	}
	return nil
}
