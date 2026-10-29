package store

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MaxChallengeAttempts is the number of wrong codes a verification
// challenge tolerates (spec 7): the challenge is dead when none remain.
const MaxChallengeAttempts = 2

// challengeColumns is the column list read by the challenge queries.
const challengeColumns = `id, email, code_mac, attempts_remaining, invitation_id, client_ip, created_at, expires_at, ` +
	`consumed_at, purpose, recipient_link_id, recipient_intent`

// Statements of the Challenges repository.
var (
	qChallengeInsert = tenantQuery(
		`INSERT INTO verification_challenges (tenant_id, id, email, code_mac, attempts_remaining, invitation_id,
		client_ip, created_at, expires_at, purpose, recipient_link_id, recipient_intent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qChallengeGet = tenantQuery(
		`SELECT ` + challengeColumns + ` FROM verification_challenges WHERE tenant_id = ? AND id = ?`)
	// qChallengeCountEmail counts the deposit codes of an address: the
	// recipient codes have their own budget, per link (D22).
	qChallengeCountEmail = tenantQuery(
		`SELECT count(*) FROM verification_challenges
		WHERE tenant_id = ? AND email = ? AND created_at >= ? AND purpose = 'deposit'`)
	// qChallengeCountLink counts the recipient codes of a link
	// (verification_challenges_link_idx).
	qChallengeCountLink = tenantQuery(
		`SELECT count(*) FROM verification_challenges
		WHERE tenant_id = ? AND recipient_link_id = ? AND created_at >= ?`)
	// qChallengeLatestLink reads the newest recipient code of a link
	// (verification_challenges_link_idx), the only one a code is checked
	// against.
	qChallengeLatestLink = tenantQuery(
		`SELECT ` + challengeColumns + ` FROM verification_challenges
		WHERE tenant_id = ? AND recipient_link_id = ? AND purpose = 'recipient'
		ORDER BY created_at DESC, id DESC LIMIT 1`)
	qChallengeCountIP = tenantQuery(
		`SELECT count(*) FROM verification_challenges WHERE tenant_id = ? AND client_ip = ? AND created_at >= ?`)
	qChallengeDelete = tenantQuery(
		`DELETE FROM verification_challenges WHERE tenant_id = ? AND id = ?`)
	// qChallengeDecrement spends one attempt of a challenge that is still
	// open; the condition makes it atomic against concurrent attempts.
	qChallengeDecrement = tenantQuery(
		`UPDATE verification_challenges SET attempts_remaining = attempts_remaining - 1
		WHERE tenant_id = ? AND id = ? AND attempts_remaining > 0 AND consumed_at IS NULL AND expires_at > ?
		RETURNING attempts_remaining`)
	// qChallengeConsume closes a challenge that is still open, at most once.
	qChallengeConsume = tenantQuery(
		`UPDATE verification_challenges SET consumed_at = ?
		WHERE tenant_id = ? AND id = ? AND attempts_remaining > 0 AND consumed_at IS NULL AND expires_at > ?`)
)

// ChallengePurpose is what a verification code proves (D21).
type ChallengePurpose string

// Challenge purposes.
const (
	// ChallengeDeposit verifies a depositor's address (spec 7), the zero
	// value at creation.
	ChallengeDeposit ChallengePurpose = "deposit"
	// ChallengeRecipient verifies the recipient of a recipient link (spec
	// 10): the code is sent to the address of the link only.
	ChallengeRecipient ChallengePurpose = "recipient"
)

// RecipientIntent is what a recipient verifies their address for
// (OpenAPI RecipientVerificationStart.purpose).
type RecipientIntent string

// Recipient intents.
const (
	// IntentDownload verifies the recipient before a download.
	IntentDownload RecipientIntent = "download"
	// IntentReply verifies the recipient before a reply to the transfer.
	IntentReply RecipientIntent = "reply"
)

// Challenge is a verification code sent by mail to an address (spec 7). The
// code itself is never stored: CodeMAC is computed by the caller (HMAC with
// a key derived from the master key, over the challenge ID and the code).
type Challenge struct {
	// ID is the challenge identifier, "vch_" + 22 to 43 base62 characters
	// (id.NewToken with at least 16 bytes). The caller assigns it; it is
	// unguessable and appears in the confirmation URL.
	ID string
	// Email is the address the code was sent to, normalized by the store.
	Email string
	// CodeMAC is the MAC of the code (1 to MaxMACBytes bytes).
	CodeMAC []byte
	// AttemptsRemaining is the number of wrong codes still tolerated, 1 to
	// MaxChallengeAttempts at creation.
	AttemptsRemaining int
	// InvitationID is the invitation the depositor presented ("inv_" +
	// ULID), or "" for an internal depositor. It must belong to the same
	// tenant; deleting the invitation deletes the challenge.
	InvitationID string
	// ClientIP is the IP address the challenge was requested from, counted
	// by the per-IP rate limit. IPv4-mapped addresses are stored as IPv4.
	ClientIP netip.Addr
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero. The rate limits count challenges by creation time.
	CreatedAt time.Time
	// ExpiresAt is the end of validity (15 minutes after creation), after
	// CreatedAt.
	ExpiresAt time.Time
	// ConsumedAt is when the right code was entered, zero while unused.
	ConsumedAt time.Time
	// Purpose is what the code proves: ChallengeDeposit (the zero value at
	// creation) or ChallengeRecipient.
	Purpose ChallengePurpose
	// RecipientLinkID is the recipient link ("rcl_" + ULID, same tenant) of
	// a ChallengeRecipient code, "" for a deposit code. Email must then be
	// the address of the recipient of the link; deleting the link deletes
	// the challenge.
	RecipientLinkID string
	// RecipientIntent is what a ChallengeRecipient code is for, "" for a
	// deposit code.
	RecipientIntent RecipientIntent
}

// Open reports whether the challenge still accepts a code at now: not
// consumed, not expired and with attempts remaining. [Challenges.Get]
// returns challenges in any state, so that callers can tell an expired or
// exhausted challenge from an unknown one; DecrementAttempt and ConsumeTx
// check the same conditions atomically.
func (c Challenge) Open(now time.Time) bool {
	return c.ConsumedAt.IsZero() && c.AttemptsRemaining > 0 && now.Before(c.ExpiresAt)
}

// Challenges is the tenant-scoped repository of verification challenges.
// Obtain it with [DB.Challenges].
//
// Retention: the rate limits count the challenges created during the last
// hour, consumed, expired or not. A challenge row must therefore be kept at
// least until CreatedAt + 1 hour (the RateWindow of the deposit service),
// even once it is expired or used: the cleanup job purges only the rows
// whose created_at is older than now - 1 hour.
type Challenges struct {
	db *DB
}

// Challenges returns the verification challenge repository.
func (db *DB) Challenges() *Challenges { return &Challenges{db: db} }

// validChallengeID reports whether s has the shape of a challenge ID.
func validChallengeID(s string) bool {
	return id.TokenValid(id.ChallengeTokenPrefix, s, id.MinTokenBodyLen, id.MaxTokenBodyLen)
}

// Create stores c for tenant tid in its own transaction (see
// [Challenges.CreateTx]).
func (r *Challenges) Create(ctx context.Context, tid tenant.ID, c Challenge) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return r.create(ctx, tx, c) }); err != nil {
		return wrap("create challenge", err)
	}
	return nil
}

// CreateTx stores c for the tenant tx is bound to, inside tx. It returns
// ErrInvalid for a malformed field (a recipient code needs a link and an
// intent, is sent to the address of the link and has no invitation; a
// deposit code has neither link nor intent), ErrNotFound when the tenant,
// the invitation or the recipient link does not exist (or belongs to
// another tenant) and ErrConflict when the ID is already used. After an
// error, the caller must abort the transaction.
func (r *Challenges) CreateTx(ctx context.Context, tx *ScopedTx, c Challenge) error {
	if err := r.create(ctx, tx, c); err != nil {
		return wrap("create challenge", err)
	}
	return nil
}

// create validates and inserts c in tx, returning raw errors.
func (r *Challenges) create(ctx context.Context, tx *ScopedTx, c Challenge) error {
	email, err := NormalizeEmail(c.Email)
	if err != nil {
		return err
	}
	ip, err := ipText(c.ClientIP)
	if err != nil {
		return err
	}
	created := r.db.orNow(c.CreatedAt)
	switch {
	case !validChallengeID(c.ID):
		return invalid("malformed challenge id")
	case len(c.CodeMAC) == 0 || len(c.CodeMAC) > MaxMACBytes:
		return invalid("code mac must hold 1 to %d bytes", MaxMACBytes)
	case c.AttemptsRemaining < 1 || c.AttemptsRemaining > MaxChallengeAttempts:
		return invalid("attempts must be between 1 and %d", MaxChallengeAttempts)
	case c.InvitationID != "" && !id.Valid(id.Invitation, c.InvitationID):
		return invalid("malformed invitation id")
	case !c.ExpiresAt.After(created):
		return invalid("challenge must expire after its creation")
	case !c.ConsumedAt.IsZero():
		return invalid("a new challenge cannot be consumed")
	}
	if c.Purpose == "" {
		c.Purpose = ChallengeDeposit
	}
	if err := checkChallengePurpose(ctx, tx, c, email); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, qChallengeInsert, c.ID, email, c.CodeMAC, c.AttemptsRemaining,
		nullText(c.InvitationID), ip, toMillis(created), toMillis(c.ExpiresAt), string(c.Purpose),
		nullText(c.RecipientLinkID), nullText(string(c.RecipientIntent)))
	return err
}

// checkChallengePurpose validates the purpose fields of c, whose address is
// email (normalized): a recipient code is sent to the address of its link,
// read in tx.
func checkChallengePurpose(ctx context.Context, tx *ScopedTx, c Challenge, email string) error {
	switch c.Purpose {
	case ChallengeDeposit:
		if c.RecipientLinkID != "" || c.RecipientIntent != "" {
			return invalid("a deposit code has no recipient link")
		}
		return nil
	case ChallengeRecipient:
	default:
		return invalid("unknown challenge purpose")
	}
	switch {
	case c.InvitationID != "":
		return invalid("a recipient code has no invitation")
	case c.RecipientIntent != IntentDownload && c.RecipientIntent != IntentReply:
		return invalid("unknown recipient intent")
	case !validLinkID(c.RecipientLinkID):
		return invalid("malformed recipient link id")
	}
	l, err := scanLink(tx.QueryRow(ctx, qLinkGet, c.RecipientLinkID))
	if err != nil {
		return err
	}
	if l.Email != email {
		return invalid("a recipient code goes to the address of its link")
	}
	return nil
}

// Get returns the challenge chID of tenant tid in whatever state it is
// (see [Challenge.Open]), or ErrNotFound when it does not exist or belongs
// to another tenant.
func (r *Challenges) Get(ctx context.Context, tid tenant.ID, chID string) (Challenge, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return Challenge{}, err
	}
	var c Challenge
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		c, err = scanChallenge(tx.QueryRow(ctx, qChallengeGet, chID))
		return err
	})
	if err != nil {
		return Challenge{}, wrap("get challenge", err)
	}
	return c, nil
}

// LatestByLink returns the newest recipient challenge of the recipient link
// linkID of tenant tid (by creation time, then ID), in whatever state it is:
// a new code replaces the previous ones, so it is the only one a code is
// checked against. It returns ErrNotFound when the link has no recipient
// challenge (including a link of another tenant) and ErrInvalid for a
// malformed link ID.
func (r *Challenges) LatestByLink(ctx context.Context, tid tenant.ID, linkID string) (Challenge, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return Challenge{}, err
	}
	var c Challenge
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		c, err = r.LatestByLinkTx(ctx, tx, linkID)
		return err
	})
	if err != nil {
		return Challenge{}, err
	}
	return c, nil
}

// LatestByLinkTx is [Challenges.LatestByLink] inside tx, for the tenant tx
// is bound to. After an error, the caller must abort the transaction.
func (r *Challenges) LatestByLinkTx(ctx context.Context, tx *ScopedTx, linkID string) (Challenge, error) {
	if !validLinkID(linkID) {
		return Challenge{}, wrap("latest challenge", invalid("malformed recipient link id"))
	}
	c, err := scanChallenge(tx.QueryRow(ctx, qChallengeLatestLink, linkID))
	if err != nil {
		return Challenge{}, wrap("latest challenge", err)
	}
	return c, nil
}

// scanChallenge reads one row of challengeColumns.
func scanChallenge(row interface{ Scan(...any) error }) (Challenge, error) {
	var (
		c                 Challenge
		inv, link, intent sql.NullString
		ip, purpose       string
		created, expires  int64
		consumed          sql.NullInt64
	)
	if err := row.Scan(&c.ID, &c.Email, &c.CodeMAC, &c.AttemptsRemaining,
		&inv, &ip, &created, &expires, &consumed, &purpose, &link, &intent); err != nil {
		return Challenge{}, err
	}
	c.InvitationID, c.Purpose = inv.String, ChallengePurpose(purpose)
	c.RecipientLinkID, c.RecipientIntent = link.String, RecipientIntent(intent.String)
	c.ClientIP = parseIP(ip)
	c.CreatedAt, c.ExpiresAt = fromMillis(created), fromMillis(expires)
	c.ConsumedAt = nullMillis(consumed)
	return c, nil
}

// CountSince returns the number of deposit challenges created for the
// address email of tenant tid at or after since, consumed or not: the
// per-address rate limit (5 codes per sliding hour, spec 7). The recipient
// codes are not counted: they have their own budget per link
// ([Challenges.CountByLinkSince]). It is a plain read: a caller
// enforcing the limit counts with [Challenges.CountSinceTx] in the
// transaction that inserts the challenge.
func (r *Challenges) CountSince(ctx context.Context, tid tenant.ID, email string, since time.Time) (int, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	return r.count(ctx, tid, qChallengeCountEmail, email, since)
}

// CountByIPSince returns the number of challenges of tenant tid requested
// from ip at or after since, whatever their purpose: the per-IP rate limit
// (20 codes per sliding hour and per tenant, spec 7, shared by the deposit
// and the recipient codes). See [Challenges.CountByIPSinceTx] to
// enforce it.
func (r *Challenges) CountByIPSince(ctx context.Context, tid tenant.ID, ip netip.Addr, since time.Time) (int, error) {
	text, err := ipText(ip)
	if err != nil {
		return 0, err
	}
	return r.count(ctx, tid, qChallengeCountIP, text, since)
}

// CountSinceTx is [Challenges.CountSince] inside tx, for a write
// transaction that counts then inserts a challenge ([Challenges.CreateTx]):
// it first takes the tenant lock, so that concurrent transactions of the
// tenant doing the same count and insert run one after the other and can
// never exceed a limit together (on SQLite, write transactions are already
// serialized). After an error, the caller must abort the transaction.
func (r *Challenges) CountSinceTx(ctx context.Context, tx *ScopedTx, email string, since time.Time) (int, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	return countTx(ctx, tx, qChallengeCountEmail, email, since, "count challenges")
}

// CountByIPSinceTx is [Challenges.CountByIPSince] inside tx, after the
// tenant lock (see [Challenges.CountSinceTx]). The count is per tenant: the
// same IP has its own allowance in every tenant. After an error, the caller
// must abort the transaction.
func (r *Challenges) CountByIPSinceTx(ctx context.Context, tx *ScopedTx, ip netip.Addr, since time.Time) (int, error) {
	text, err := ipText(ip)
	if err != nil {
		return 0, err
	}
	return countTx(ctx, tx, qChallengeCountIP, text, since, "count challenges")
}

// CountByLinkSince returns the number of recipient challenges of tenant
// tid created for the recipient link linkID at or after since, consumed or
// not: the per-(address, link) rate limit of the recipient codes (5 per
// sliding hour, D22; a link fixes its address). See
// [Challenges.CountByLinkSinceTx] to enforce it. It returns ErrInvalid for
// a malformed link ID.
func (r *Challenges) CountByLinkSince(ctx context.Context, tid tenant.ID, linkID string, since time.Time) (int, error) {
	if !validLinkID(linkID) {
		return 0, invalid("malformed recipient link id")
	}
	return r.count(ctx, tid, qChallengeCountLink, linkID, since)
}

// CountByLinkSinceTx is [Challenges.CountByLinkSince] inside tx, after the
// tenant lock (see [Challenges.CountSinceTx]). After an error, the caller
// must abort the transaction.
func (r *Challenges) CountByLinkSinceTx(ctx context.Context, tx *ScopedTx, linkID string, since time.Time) (int, error) {
	if !validLinkID(linkID) {
		return 0, wrap("count challenges", invalid("malformed recipient link id"))
	}
	return countTx(ctx, tx, qChallengeCountLink, linkID, since, "count challenges")
}

// countTx takes the tenant lock, then runs the count q for key and since in
// tx.
func countTx(ctx context.Context, tx *ScopedTx, q TenantQuery, key string, since time.Time, what string) (int, error) {
	if err := tx.lock(ctx); err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRow(ctx, q, key, toMillis(since)).Scan(&n); err != nil {
		return 0, wrap(what, err)
	}
	return n, nil
}

// Delete removes the challenge chID of tenant tid, whatever its state. The
// deposit service uses it when the mail carrying the code could not be
// queued, so that a code nobody received neither stays usable nor counts
// against the rate limits. It returns ErrNotFound when the challenge does
// not exist or belongs to another tenant.
func (r *Challenges) Delete(ctx context.Context, tid tenant.ID, chID string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		res, err := tx.Exec(ctx, qChallengeDelete, chID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("delete challenge", err)
	}
	return nil
}

// count runs one of the rate-limit counts.
func (r *Challenges) count(ctx context.Context, tid tenant.ID, q TenantQuery, key string, since time.Time) (int, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	var n int
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		return tx.QueryRow(ctx, q, key, toMillis(since)).Scan(&n)
	})
	if err != nil {
		return 0, wrap("count challenges", err)
	}
	return n, nil
}

// DecrementAttempt spends one attempt of the challenge chID of tenant tid
// after a wrong code and returns the attempts remaining; 0 means the
// challenge is now dead. The update is atomic and only applies to a
// challenge open at now (see [Challenge.Open]): otherwise, or when the
// challenge does not exist or belongs to another tenant, it returns
// ErrNotFound.
func (r *Challenges) DecrementAttempt(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	var remaining int
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		return tx.QueryRow(ctx, qChallengeDecrement, chID, toMillis(now)).Scan(&remaining)
	})
	if err != nil {
		return 0, wrap("decrement challenge attempts", err)
	}
	return remaining, nil
}

// ConsumeTx marks the challenge chID of the tenant tx is bound to as
// consumed at now, inside tx, after the right code was entered, so that the
// verified address and the deposit session are recorded in the same
// transaction. It only applies to a challenge open at now (see
// [Challenge.Open]) and succeeds at most once: otherwise, or when the
// challenge does not exist or belongs to another tenant, it returns
// ErrNotFound. After an error, the caller must abort the transaction.
func (r *Challenges) ConsumeTx(ctx context.Context, tx *ScopedTx, chID string, now time.Time) error {
	ms := toMillis(now)
	res, err := tx.Exec(ctx, qChallengeConsume, ms, chID, ms)
	if err == nil {
		err = expectOne(res)
	}
	if err != nil {
		return wrap("consume challenge", err)
	}
	return nil
}
