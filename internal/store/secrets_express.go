package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Express secrets (since 2.3, CLAUDE.md section 22.2): rows of the secrets
// table with express set, created without authentication (creator kind
// anonymous) or with an API token allowed for them, text only, link
// delivery, created active. The data model is
// docs/architecture/data-model-v2.3.md; the recipient side is the one of
// the 2.1 secrets ([Secrets.StatusByToken], [Secrets.Reveal]) behind the
// read gate of [ExpressGate].

// Limits of the express secrets.
const (
	// ExpressTokenWindow is the sliding window of the per-token limit
	// (tenant.ExpressSettings.PerHourPerToken).
	ExpressTokenWindow = time.Hour
	// ExpressPurgeBatchSize is the number of secrets
	// [Secrets.PurgeAnonymousExpress] ends per write transaction, so that
	// the SQLite writer is never held long.
	ExpressPurgeBatchSize = 500
)

// Errors of the express secrets.
var (
	// ErrExpressDisabled reports an anonymous creation while the anonymous
	// mode of the tenant is off (tenant.ExpressSettings.Enabled). It wraps
	// ErrSecretPolicy.
	ErrExpressDisabled = fmt.Errorf("%w: anonymous express secrets are disabled", ErrSecretPolicy)
	// ErrExpressLimit reports an anonymous creation while the tenant holds
	// tenant.ExpressSettings.MaxPending live express secrets or more. It
	// wraps ErrLimitReached.
	ErrExpressLimit = fmt.Errorf("%w: too many live express secrets", ErrLimitReached)
	// ErrExpressTokenRate is matched by an [*ExpressTokenRateError]. It
	// wraps ErrLimitReached.
	ErrExpressTokenRate = fmt.Errorf("%w: too many express secrets created by the token", ErrLimitReached)
	// ErrExpressTokenNotAllowed reports a creation with an API token that is
	// not (or no longer) allowed for the express secrets
	// (APIToken.ExpressAllowed). It wraps ErrSecretPolicy.
	ErrExpressTokenNotAllowed = fmt.Errorf("%w: the token is not allowed for express secrets", ErrSecretPolicy)
	// ErrExpressTokenUnusable reports a creation with an API token that is
	// unknown to the tenant, revoked or expired, read in the creation
	// transaction (the token was authenticated before it, so it changed in
	// between). It wraps ErrNotFound.
	ErrExpressTokenUnusable = fmt.Errorf("%w: the api token is unknown, revoked or expired", ErrNotFound)
	// ErrExpressClosed reports a recipient operation on an express secret
	// closed by the instance kill switch or by its tenant ([ExpressGate]).
	// Nothing is read beyond the gate, counted nor written.
	ErrExpressClosed = errors.New("store: express secrets closed")
	// ErrTenantInSetup reports a creation on a tenant still being
	// configured (tenant.SetupStateSetup).
	ErrTenantInSetup = errors.New("store: tenant in setup")
)

// ExpressTokenRateError reports an API token that created
// tenant.ExpressSettings.PerHourPerToken express secrets or more in the
// last ExpressTokenWindow. It matches ErrExpressTokenRate (and so
// ErrLimitReached).
type ExpressTokenRateError struct {
	// RetryAfter is the time until the oldest counted creation leaves the
	// window (always positive).
	RetryAfter time.Duration
}

// Error implements error.
func (e *ExpressTokenRateError) Error() string {
	return fmt.Sprintf("store: too many express secrets created by the token (retry after %s)", e.RetryAfter)
}

// Unwrap returns ErrExpressTokenRate.
func (e *ExpressTokenRateError) Unwrap() error { return ErrExpressTokenRate }

// ExpressGate is the instance state the recipient operations of the
// secrets apply to the express secrets ([Secrets.StatusByToken],
// [Secrets.Reveal]; threat model T-389, decision P90). An express secret
// is closed while KillSwitch is on, and an anonymous one also while the
// anonymous mode of its tenant is off (read in the same transaction as the
// secret). A closed secret is answered ErrExpressClosed once its token is
// found in the tenant (an unknown token stays ErrNotFound first), whatever
// its state, and nothing is consumed: the link works again once the
// service reopens before its expiry. The zero value closes nothing but the
// anonymous secrets of the tenants whose anonymous mode is off. The 2.1
// secrets are never affected.
type ExpressGate struct {
	// KillSwitch is the instance switch TT_EXPRESS_SECRETS_DISABLED: every
	// express secret is closed, those created with an API token included.
	KillSwitch bool
}

// CreateExpressSecret is the input of [Secrets.CreateExpress].
type CreateExpressSecret struct {
	// APITokenID is the API token creating the secret ("tok_" + ULID),
	// already authenticated and allowed for the express secrets by the
	// caller; "" for an anonymous creation.
	APITokenID string
	// Verifier is SHA-256(proof) and KeyVerifier SHA-256(keyProof), 32
	// bytes each (e2e-format.md 3.3.4 and 3.3.9).
	Verifier    []byte
	KeyVerifier []byte
	// SealedText is the sealed text string from the client,
	// MinSecretSealedTextLen to MaxSecretSealedTextLen base64url
	// characters.
	SealedText string
	// Duration is 1h, 1d or 7d ([tenant.SecretDuration.ExpressDuration]),
	// whatever the tenant offers to the 2.1 secrets.
	Duration tenant.SecretDuration
	// Now is the creation time; zero means the store clock.
	Now time.Time
}

// Reasons of the reviewed queries of the express secrets.
const (
	// reasonExpressSettings is the review of qSecretExpressSettings: the
	// tenant slot filters secrets, and the join reads the tenants row of
	// the same tenant only (n.id = s.tenant_id); on PostgreSQL the tenants
	// policy also restricts a tenant scope to its own row.
	reasonExpressSettings = "express secret creation: check the express settings of the same tenant row only"
	// reasonExpressGate is the review of qSecretExpressGate, joined the
	// same way.
	reasonExpressGate = "express secret read gate: read the anonymous switch of the same tenant row only"
)

// Statements of the express secrets.
var (
	qSecretExpressInsert = tenantQuery(
		`INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, api_token_id, delivery, verifier,
		key_verifier, text_sealed, text_key_id, duration_code, created_at, activated_at, expires_at, express)
		VALUES (?, ?, ?, 'active', ?, ?, 'link', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	// qSecretExpressSettings reads, after the insertion, the status, the
	// setup state and the express settings of the tenant of the new
	// secret.
	qSecretExpressSettings = reviewedTenantQuery(
		`SELECT n.status, n.setup_state, n.express_enabled, n.express_per_hour_token, n.express_max_pending
		FROM secrets s JOIN tenants n ON n.id = s.tenant_id WHERE s.tenant_id = ? AND s.id = ?`,
		reasonExpressSettings)
	// qSecretExpressGate reads what the read gate checks, by token hash.
	qSecretExpressGate = reviewedTenantQuery(
		`SELECT s.express, s.creator_kind, n.express_enabled
		FROM secrets s JOIN tenants n ON n.id = s.tenant_id WHERE s.tenant_id = ? AND s.token_hash = ?`,
		reasonExpressGate)
	// The live express secrets of the tenant (the cap counts the new one
	// too), through secrets_express_live_idx.
	qSecretCountExpressLive = tenantQuery(
		`SELECT count(*) FROM secrets WHERE tenant_id = ? AND express AND state = 'active' AND expires_at > ?`)
	// The express secrets of a token in the window (the new one included)
	// and the oldest of them, through secrets_token_created_idx.
	qSecretCountExpressByToken = tenantQuery(
		`SELECT count(*), min(created_at) FROM secrets WHERE tenant_id = ? AND api_token_id = ? AND express
		AND created_at > ?`)
	// The live anonymous express secrets of the tenant, a batch at a time,
	// through secrets_express_live_idx.
	qSecretExpressPurgeList = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND express AND creator_kind = 'anonymous'
		AND state = 'active' ORDER BY id LIMIT ?`)
)

// checkCreateExpress checks the input of CreateExpress, independent of the
// database.
func checkCreateExpress(c CreateExpressSecret) error {
	switch {
	case len(c.Verifier) != secretVerifierLen || len(c.KeyVerifier) != secretVerifierLen:
		return invalid("verifiers must be %d bytes", secretVerifierLen)
	case len(c.SealedText) < MinSecretSealedTextLen || !isBase64URL(c.SealedText, MaxSecretSealedTextLen):
		return invalid("malformed sealed text")
	case !c.Duration.ExpressDuration():
		return invalid("unknown express duration")
	}
	return nil
}

// CreateExpress stores a new express secret of tenant tid, in one
// transaction under the tenant lock (data-model-v2.3.md 2.3): for a token
// creator, the token must be a usable token of the tenant allowed for the
// express secrets; a new text data key (SecretKeys.NewDEKTx) encrypting
// the sealed text at rest as for [Secrets.Create]; the row, active at
// once (activated at its creation, expiring Duration later), link
// delivery, no address, passphrase, file nor receipt; then, read in the
// same transaction, the tenant (active, out of its setup), and:
//
//   - anonymous creation: the anonymous mode of the tenant must be on, and
//     the live express secrets of the tenant (active and not expired,
//     anonymous and token ones together) must stay within MaxPending, the
//     new one included;
//   - token creation: the express secrets the token created in the last
//     ExpressTokenWindow, the new one included, must stay within
//     PerHourPerToken. Neither the anonymous mode nor the cap applies.
//
// The 2.1 creator limits do not apply, and the express secrets are not
// counted by them. It returns the secret (SenderEmail "", Express true)
// with its token, shown once. Errors: ErrInvalid for a malformed input;
// ErrNotFound for a tenant that does not exist or is being deleted;
// ErrExpressTokenUnusable (which
// wraps ErrNotFound) for an unknown, revoked or expired token;
// ErrExpressTokenNotAllowed;
// ErrTenantInSetup; ErrExpressDisabled; ErrExpressLimit; an
// [*ExpressTokenRateError]. Nothing is stored after an error.
func (r *Secrets) CreateExpress(ctx context.Context, tid tenant.ID, c CreateExpressSecret) (CreatedSecret, error) {
	if r.keys == nil {
		return CreatedSecret{}, errSecretNoKeys
	}
	if err := checkCreateExpress(c); err != nil {
		return CreatedSecret{}, err
	}
	secID, err := r.db.newID(id.Secret)
	if err != nil {
		return CreatedSecret{}, wrap("create express secret", err)
	}
	token, err := r.newToken()
	if err != nil {
		return CreatedSecret{}, wrap("create express secret", err)
	}
	now := r.db.orNow(c.Now).UTC().Truncate(time.Millisecond)
	out, err := writeScopedValue(ctx, r.db, tid, "create express secret", func(tx *ScopedTx) (Secret, error) {
		return r.createExpressTx(ctx, tx, secID, id.HashToken(token), c, now)
	})
	if err != nil {
		return CreatedSecret{}, err
	}
	return CreatedSecret{Secret: out, Token: token}, nil
}

// createExpressTx implements CreateExpress inside tx.
func (r *Secrets) createExpressTx(ctx context.Context, tx *ScopedTx, secID string, tokenHash []byte,
	c CreateExpressSecret, now time.Time,
) (Secret, error) {
	if err := tx.lock(ctx); err != nil {
		return Secret{}, err
	}
	kind := SecretCreatorAnonymous
	if c.APITokenID != "" {
		kind = SecretCreatorAPIToken
		if err := checkExpressToken(ctx, tx, c.APITokenID, now); err != nil {
			return Secret{}, err
		}
	}
	wkID, dek, err := r.keys.NewDEKTx(ctx, tx)
	if err != nil {
		return Secret{}, err
	}
	sealed, err := sealSecretText(dek, tx.Tenant(), secID, c.SealedText)
	clear(dek)
	if err != nil {
		return Secret{}, err
	}
	_, err = tx.Exec(ctx, qSecretExpressInsert, secID, tokenHash, string(kind), nullText(c.APITokenID),
		c.Verifier, c.KeyVerifier, sealed, wkID, string(c.Duration), toMillis(now), toMillis(now),
		toMillis(now.Add(c.Duration.Duration())), true)
	if err != nil {
		return Secret{}, err
	}
	if err := checkExpressSettings(ctx, tx, secID, c.APITokenID, now); err != nil {
		return Secret{}, err
	}
	row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
	return row.Secret, err
}

// checkExpressToken verifies, inside tx, that tokID is a token of the
// tenant tx is bound to (ErrExpressTokenUnusable otherwise), usable at now
// (ErrExpressTokenUnusable) and allowed for the express secrets
// (ErrExpressTokenNotAllowed).
func checkExpressToken(ctx context.Context, tx *ScopedTx, tokID string, now time.Time) error {
	tok, err := scanAPIToken(tx.QueryRow(ctx, qAPITokenGet, tokID))
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrExpressTokenUnusable
	case err != nil:
		return err
	case !tok.Usable(now):
		return ErrExpressTokenUnusable
	}
	if !tok.ExpressAllowed {
		return ErrExpressTokenNotAllowed
	}
	return nil
}

// checkExpressSettings checks the new express secret secID against the
// status, the setup state and the express settings of its tenant and the
// limits, read in the creation transaction; tokID is the creating token,
// "" for an anonymous creation. The counts include the new secret.
func checkExpressSettings(ctx context.Context, tx *ScopedTx, secID, tokID string, now time.Time) error {
	var (
		status, setup        string
		enabled              bool
		perToken, maxPending int
	)
	err := tx.QueryRow(ctx, qSecretExpressSettings, secID).Scan(&status, &setup, &enabled, &perToken, &maxPending)
	if err != nil {
		return err
	}
	switch {
	case tenant.Status(status) != tenant.StatusActive:
		return ErrNotFound
	case tenant.SetupState(setup) != tenant.SetupStateActive:
		return ErrTenantInSetup
	case tokID == "" && !enabled:
		return ErrExpressDisabled
	}
	if tokID == "" {
		var live int
		if err := tx.QueryRow(ctx, qSecretCountExpressLive, toMillis(now)).Scan(&live); err != nil {
			return err
		}
		if live > maxPending {
			return ErrExpressLimit
		}
		return nil
	}
	var (
		recent int
		oldest sql.NullInt64
	)
	err = tx.QueryRow(ctx, qSecretCountExpressByToken, tokID, toMillis(now.Add(-ExpressTokenWindow))).Scan(&recent, &oldest)
	if err != nil {
		return err
	}
	if recent > perToken {
		// The oldest counted row is in the window, so strictly after
		// now - ExpressTokenWindow: the wait is positive.
		return &ExpressTokenRateError{RetryAfter: fromMillis(oldest.Int64).Add(ExpressTokenWindow).Sub(now)}
	}
	return nil
}

// checkExpressGate reads, inside tx, the secret of token hash hash and the
// anonymous switch of its tenant, and returns ErrExpressClosed when gate
// or the tenant closes it, ErrNotFound for an unknown token, nil
// otherwise (a 2.1 secret is never closed).
func checkExpressGate(ctx context.Context, tx *ScopedTx, hash []byte, gate ExpressGate) error {
	var (
		express, enabled bool
		kind             string
	)
	if err := tx.QueryRow(ctx, qSecretExpressGate, hash).Scan(&express, &kind, &enabled); err != nil {
		return err
	}
	if express && (gate.KillSwitch || (SecretCreatorKind(kind) == SecretCreatorAnonymous && !enabled)) {
		return ErrExpressClosed
	}
	return nil
}

// LookupByToken returns the secret of tenant tid whose link carries token,
// in any state (pending and tombstones included) and as stored (no expiry
// applied), without content: the lookup of an administrator from a link
// (lookupTenantSecret, threat model T-408). The token is only hashed. It
// returns ErrNotFound for a malformed or unknown token and a token of
// another tenant. Nothing is written.
func (r *Secrets) LookupByToken(ctx context.Context, tid tenant.ID, token string) (Secret, error) {
	if !id.SecretTokenValid(token) {
		return Secret{}, fmt.Errorf("store: lookup secret: %w", ErrNotFound)
	}
	return readScoped(ctx, r.db, tid, "lookup secret", func(tx *ScopedTx) (Secret, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGetByHash, id.HashToken(token)), tid)
		return row.Secret, err
	})
}

// PurgeAnonymousExpress ends every live (active) anonymous express secret
// of tenant tid exactly as [Secrets.DeleteByAdmin] does: each becomes a
// deleted tombstone (end reason deleted_by_admin, content cleared), then
// its text key is destroyed (cryptographic erasure), in batches of
// ExpressPurgeBatchSize per write transaction (purgeExpressSecrets, threat
// model T-392). The express secrets created with an API token, the 2.1
// secrets and the tombstones are not touched; an express secret has no
// file. A listed secret that a concurrent reveal, expiry or deletion ended
// before its update is skipped, its key left to that operation, rather
// than failing the batch. It returns how many secrets it ended, also after
// an error (the batches already committed stay ended: calling again
// finishes the work). The caller scrubs the database.
func (r *Secrets) PurgeAnonymousExpress(ctx context.Context, tid tenant.ID, now time.Time) (int, error) {
	if r.keys == nil {
		return 0, errSecretNoKeys
	}
	at := toMillis(now)
	total := 0
	for {
		var listed, ended int
		err := writeScoped(ctx, r.db, tid, "purge express secrets", func(tx *ScopedTx) error {
			listed, ended = 0, 0
			rows, err := r.queryRows(ctx, tx, qSecretExpressPurgeList, r.expressPurgeBatch)
			if err != nil {
				return err
			}
			if r.expressPurgeHook != nil {
				if err := r.expressPurgeHook(ctx, tx, rows); err != nil {
					return err
				}
			}
			for _, row := range rows {
				n, err := execCount(ctx, tx, qSecretMarkDeleted, at, string(SecretEndDeletedByAdmin), row.ID)
				if err != nil {
					return err
				}
				if n == 0 {
					// Ended since the list by a concurrent reveal, expiry or
					// deletion (the list takes no row lock and PostgreSQL
					// reads at READ COMMITTED), which destroyed its key.
					continue
				}
				if err := r.destroyKeys(ctx, tx, row.keyIDs()); err != nil {
					return err
				}
				ended++
			}
			listed = len(rows)
			return nil
		})
		if err != nil {
			return total, err
		}
		total += ended
		if listed < r.expressPurgeBatch {
			return total, nil
		}
	}
}
