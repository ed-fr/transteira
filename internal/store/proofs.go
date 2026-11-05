package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonProofKeys is the reason of the proof signing key queries.
const reasonProofKeys = "proof signing keys of the instance (system table, no tenant; public keys published by /proof-keys)"

// Limits of a transfer proof (migration 0028).
const (
	// ProofSignatureSize is the size of an Ed25519 signature.
	ProofSignatureSize = 64
	// ProofPublicKeySize is the size of a raw Ed25519 public key.
	ProofPublicKeySize = 32
	// MinProofStatementBytes and MaxProofStatementBytes bound the
	// canonical JSON statement of a proof.
	MinProofStatementBytes = 2
	MaxProofStatementBytes = 4 << 20
)

// proofLookupBatch bounds the per-recipient delivery proofs one step of
// [TransferProofs.GetRecipientDelivery] reads at once.
const proofLookupBatch = 10

// proofEraseBatch bounds the candidate statements one step of
// [TransferProofs.DeleteByAddressTx] reads at once (each may hold up to
// MaxProofStatementBytes bytes).
const proofEraseBatch = 50

// ProofKind is the fact a transfer proof attests.
type ProofKind string

// Proof kinds.
const (
	// ProofDeposit attests the deposit of a transfer, written at its
	// finalization after the antivirus verdict.
	ProofDeposit ProofKind = "deposit"
	// ProofDelivery attests a first download: of the transfer (no
	// recipient link), or of one recipient link.
	ProofDelivery ProofKind = "delivery"
)

// proofKeyColumns is the column list read by the proof key queries.
const proofKeyColumns = `id, public_key, private_key_secret_id, created_at, retired_at`

// proofColumns is the column list read by the proof queries (tenant_id
// excepted: a tenant query cannot read it).
const proofColumns = `id, transfer_id, kind, recipient_link_id, statement, signature, key_id, created_at, expires_at`

// Statements of the ProofKeys repository.
var (
	qProofKeyInsert = systemQuery(
		`INSERT INTO proof_signing_keys (`+proofKeyColumns+`) VALUES (?, ?, ?, ?, NULL)`,
		reasonProofKeys)
	qProofKeyActive = systemQuery(
		`SELECT `+proofKeyColumns+` FROM proof_signing_keys WHERE retired_at IS NULL`,
		reasonProofKeys)
	qProofKeyGet = systemQuery(
		`SELECT `+proofKeyColumns+` FROM proof_signing_keys WHERE id = ?`,
		reasonProofKeys)
	qProofKeyList = systemQuery(
		`SELECT `+proofKeyColumns+` FROM proof_signing_keys ORDER BY created_at DESC, id DESC`,
		reasonProofKeys)
	qProofKeyRetire = systemQuery(
		`UPDATE proof_signing_keys SET retired_at = ? WHERE id = ? AND retired_at IS NULL`,
		reasonProofKeys)
)

// Statements of the TransferProofs repository. The erasure prefilter
// exists in one form per engine (instr on SQLite, strpos on PostgreSQL):
// see proofCandidates.
var (
	qProofInsert = tenantQuery(
		`INSERT INTO transfer_proofs (id, tenant_id, transfer_id, kind, recipient_link_id, statement, signature,
		key_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qProofGetOverall = tenantQuery(
		`SELECT ` + proofColumns + ` FROM transfer_proofs
		WHERE tenant_id = ? AND transfer_id = ? AND kind = ? AND recipient_link_id IS NULL`)
	qProofGetRecipient = tenantQuery(
		`SELECT ` + proofColumns + ` FROM transfer_proofs
		WHERE tenant_id = ? AND transfer_id = ? AND kind = ? AND recipient_link_id = ?`)
	qProofPurgeList = tenantQuery(
		`SELECT id FROM transfer_proofs WHERE tenant_id = ? AND expires_at <= ? ORDER BY expires_at, id LIMIT ?`)
	qProofPurge = tenantQuery(
		`DELETE FROM transfer_proofs WHERE tenant_id = ? AND id = ? AND expires_at <= ?`)
	qProofCandidatesSQLite = tenantQuery(
		`SELECT id, statement FROM transfer_proofs
		WHERE tenant_id = ? AND instr(lower(statement), ?) > 0 AND id > ? ORDER BY id LIMIT ?`)
	qProofCandidatesPostgres = tenantQuery(
		`SELECT id, statement FROM transfer_proofs
		WHERE tenant_id = ? AND strpos(lower(statement), ?) > 0 AND id > ? ORDER BY id LIMIT ?`)
	qProofDelete = tenantQuery(
		`DELETE FROM transfer_proofs WHERE tenant_id = ? AND id = ?`)
	qProofRecipientDeliveries = tenantQuery(
		`SELECT ` + proofColumns + ` FROM transfer_proofs
		WHERE tenant_id = ? AND transfer_id = ? AND kind = 'delivery' AND recipient_link_id IS NOT NULL AND id > ?
		ORDER BY id LIMIT ?`)
)

// ProofKey is a proof signing key of the instance (Ed25519). Its public
// key is kept for ever, so that old proofs stay verifiable; its private
// key is a system secret of purpose SecretPurposeProofSigning, sealed by
// the master key and rewrapped by its rotation, destroyed when the key is
// retired.
type ProofKey struct {
	// ID is the key identifier ("psk_" + ULID), the "kid" written in every
	// statement the key signs. The caller assigns it.
	ID string
	// PublicKey is the raw Ed25519 public key (ProofPublicKeySize bytes).
	PublicKey []byte
	// PrivateKeySecretID is the system secret holding the sealed private
	// key, "" once the key is retired (cryptographic erasure).
	PrivateKeySecretID string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// RetiredAt is the retirement time, zero while the key is active.
	RetiredAt time.Time
}

// Active reports whether the key is the active signing key.
func (k ProofKey) Active() bool { return k.RetiredAt.IsZero() }

// ProofKeys is the repository of the proof signing keys. Instance table:
// its operations are system-scoped, and at most one key is active (a
// database constraint). Obtain it with [DB.ProofKeys]. Key rows are never
// deleted: the proofs reference them and GET /proof-keys publishes them.
type ProofKeys struct {
	db *DB
}

// ProofKeys returns the proof signing key repository.
func (db *DB) ProofKeys() *ProofKeys { return &ProofKeys{db: db} }

// scanProofKey reads one row of proofKeyColumns.
func scanProofKey(sc interface{ Scan(...any) error }) (ProofKey, error) {
	var (
		k       ProofKey
		secret  sql.NullString
		created int64
		retired sql.NullInt64
	)
	if err := sc.Scan(&k.ID, &k.PublicKey, &secret, &created, &retired); err != nil {
		return ProofKey{}, err
	}
	k.PrivateKeySecretID, k.CreatedAt, k.RetiredAt = secret.String, fromMillis(created), nullMillis(retired)
	return k, nil
}

// Active returns the active signing key, or ErrNotFound when there is none
// (the caller then creates one, [ProofKeys.CreateTx]).
func (r *ProofKeys) Active(ctx context.Context) (ProofKey, error) {
	var k ProofKey
	err := r.db.systemScope(reasonProofKeys).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		k, err = scanProofKey(tx.QueryRow(ctx, qProofKeyActive))
		return err
	})
	if err != nil {
		return ProofKey{}, wrap("get active proof key", err)
	}
	return k, nil
}

// ActiveTx is Active inside tx.
func (r *ProofKeys) ActiveTx(ctx context.Context, tx *SystemTx) (ProofKey, error) {
	k, err := scanProofKey(tx.QueryRow(ctx, qProofKeyActive))
	if err != nil {
		return ProofKey{}, wrap("get active proof key", err)
	}
	return k, nil
}

// Get returns the key keyID, active or retired, or ErrNotFound.
func (r *ProofKeys) Get(ctx context.Context, keyID string) (ProofKey, error) {
	var k ProofKey
	err := r.db.systemScope(reasonProofKeys).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		k, err = scanProofKey(tx.QueryRow(ctx, qProofKeyGet, keyID))
		return err
	})
	if err != nil {
		return ProofKey{}, wrap("get proof key", err)
	}
	return k, nil
}

// List returns every key, active and retired, most recent first. It holds
// public data only (the public keys, OpenAPI listProofKeys).
func (r *ProofKeys) List(ctx context.Context) ([]ProofKey, error) {
	var out []ProofKey
	err := r.db.systemScope(reasonProofKeys).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qProofKeyList)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (ProofKey, error) { return scanProofKey(r) })
		return err
	})
	if err != nil {
		return nil, wrap("list proof keys", err)
	}
	return out, nil
}

// CreateTx stores, inside tx, the system secret secret (the sealed private
// key, purpose SecretPurposeProofSigning) then the active key k referencing
// it. k.PrivateKeySecretID is set to secret.ID when empty, and must equal
// it otherwise; k.RetiredAt must be zero. It returns ErrInvalid for a
// malformed field, ErrConflict when an active key already exists (or the
// ID or public key is already used) and ErrKeyRetired when the secret is
// sealed under a retired master key. After an error, the caller must abort
// the transaction.
func (r *ProofKeys) CreateTx(ctx context.Context, tx *SystemTx, k ProofKey, secret SystemSecret) error {
	if err := r.create(ctx, tx, k, secret); err != nil {
		return wrap("create proof key", err)
	}
	return nil
}

// create implements CreateTx, returning raw errors.
func (r *ProofKeys) create(ctx context.Context, tx *SystemTx, k ProofKey, secret SystemSecret) error {
	if k.PrivateKeySecretID == "" {
		k.PrivateKeySecretID = secret.ID
	}
	switch {
	case !id.Valid(id.ProofKey, k.ID):
		return invalid("malformed proof key id")
	case len(k.PublicKey) != ProofPublicKeySize:
		return invalid("proof public key must hold %d bytes", ProofPublicKeySize)
	case k.PrivateKeySecretID != secret.ID:
		return invalid("proof key must reference its private key secret")
	case !k.RetiredAt.IsZero():
		return invalid("a new proof key is active")
	case secret.Purpose != SecretPurposeProofSigning:
		return invalid("proof private key needs the proof-signing purpose")
	}
	if err := validateSystemSecret(secret); err != nil {
		return err
	}
	// The partial unique index is the guarantee; checking first avoids
	// inserting the secret for nothing.
	if _, err := scanProofKey(tx.QueryRow(ctx, qProofKeyActive)); err == nil {
		return ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	created := toMillis(r.db.orNow(secret.CreatedAt))
	if _, err := tx.Exec(ctx, qSystemSecretInsert, secret.ID, secret.Purpose, secret.KeyID, secret.Blob, created); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, qProofKeyInsert, k.ID, k.PublicKey, k.PrivateKeySecretID, toMillis(r.db.orNow(k.CreatedAt)))
	return err
}

// RetireActiveTx retires, inside tx, the active key at now (the creation
// time when now is earlier) and destroys its private key: the system
// secret row is deleted, which clears PrivateKeySecretID (cryptographic
// erasure, threat T-300). The public key stays published. It returns the
// retired key, or ErrNotFound when no key is active (a retired key cannot
// be retired again). Callers run [DB.ScrubDeleted] once tx is committed.
func (r *ProofKeys) RetireActiveTx(ctx context.Context, tx *SystemTx, now time.Time) (ProofKey, error) {
	k, err := r.retireActive(ctx, tx, now)
	if err != nil {
		return ProofKey{}, wrap("retire proof key", err)
	}
	return k, nil
}

// retireActive implements RetireActiveTx, returning raw errors.
func (r *ProofKeys) retireActive(ctx context.Context, tx *SystemTx, now time.Time) (ProofKey, error) {
	k, err := scanProofKey(tx.QueryRow(ctx, qProofKeyActive))
	if err != nil {
		return ProofKey{}, err
	}
	at := fromMillis(toMillis(r.db.orNow(now)))
	if at.Before(k.CreatedAt) {
		at = k.CreatedAt
	}
	res, err := tx.Exec(ctx, qProofKeyRetire, toMillis(at), k.ID)
	if err != nil {
		return ProofKey{}, err
	}
	if err := expectOne(res); err != nil {
		return ProofKey{}, err
	}
	// The key is retired: its secret may now be deleted (ON DELETE SET
	// NULL clears the reference).
	if err := deleteSecrets(ctx, tx, k.PrivateKeySecretID); err != nil {
		return ProofKey{}, err
	}
	k.RetiredAt, k.PrivateKeySecretID = at, ""
	return k, nil
}

// TransferProof is a signed, immutable statement of a transfer: its
// deposit, or a first download (of the transfer, or of one recipient
// link). It outlives the transfer: it is kept until ExpiresAt (12 months
// after creation), unless the data-subject erasure or the deletion of the
// tenant removes it first.
type TransferProof struct {
	// ID is the identifier ("prf_" + ULID), assigned by the store when
	// empty.
	ID string
	// TransferID is the transfer the statement is about (not a foreign
	// key: the proof outlives the transfer).
	TransferID string
	// Kind is ProofDeposit or ProofDelivery.
	Kind ProofKind
	// RecipientLinkID is the recipient link of a per-recipient delivery,
	// "" otherwise (always "" for a deposit).
	RecipientLinkID string
	// Statement is the canonical JSON (RFC 8785) of the signed statement,
	// MinProofStatementBytes to MaxProofStatementBytes bytes.
	Statement []byte
	// Signature is the Ed25519 signature of Statement by KeyID.
	Signature []byte
	// KeyID is the proof signing key that signed Statement.
	KeyID string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// ExpiresAt is the end of the retention, after CreatedAt.
	ExpiresAt time.Time
}

// TransferProofs is the tenant-scoped repository of the transfer proofs.
// Proofs are inserted once and never updated (the database refuses any
// update, in every scope); one row exists per fact. Obtain it with
// [DB.TransferProofs].
type TransferProofs struct {
	db *DB
}

// TransferProofs returns the transfer proof repository.
func (db *DB) TransferProofs() *TransferProofs { return &TransferProofs{db: db} }

// scanProof reads one row of proofColumns.
func scanProof(sc interface{ Scan(...any) error }) (TransferProof, error) {
	var (
		p                TransferProof
		kind, statement  string
		recipient        sql.NullString
		created, expires int64
	)
	if err := sc.Scan(&p.ID, &p.TransferID, &kind, &recipient, &statement, &p.Signature, &p.KeyID,
		&created, &expires); err != nil {
		return TransferProof{}, err
	}
	p.Kind, p.RecipientLinkID, p.Statement = ProofKind(kind), recipient.String, []byte(statement)
	p.CreatedAt, p.ExpiresAt = fromMillis(created), fromMillis(expires)
	return p, nil
}

// validProofKind reports whether k is a known proof kind.
func validProofKind(k ProofKind) bool { return k == ProofDeposit || k == ProofDelivery }

// InsertTx stores the proof p inside tx, in the tenant tx is bound to. It
// returns ErrInvalid for a malformed field (unknown kind, recipient link on
// a deposit, statement that is not JSON of MinProofStatementBytes to
// MaxProofStatementBytes bytes, signature of another size than
// ProofSignatureSize, ExpiresAt not after CreatedAt), ErrConflict when the
// fact already has a proof (one deposit and one overall delivery per
// transfer, one delivery per recipient link) and ErrNotFound when KeyID
// names no signing key. After an error, the caller must abort the
// transaction.
func (r *TransferProofs) InsertTx(ctx context.Context, tx *ScopedTx, p TransferProof) error {
	if err := r.insert(ctx, tx, p); err != nil {
		return wrap("insert transfer proof", err)
	}
	return nil
}

// insert implements InsertTx, returning raw errors.
func (r *TransferProofs) insert(ctx context.Context, tx *ScopedTx, p TransferProof) error {
	if p.ID == "" {
		newID, err := r.db.newID(id.TransferProof)
		if err != nil {
			return err
		}
		p.ID = newID
	}
	created := fromMillis(toMillis(r.db.orNow(p.CreatedAt)))
	switch {
	case !id.Valid(id.TransferProof, p.ID):
		return invalid("malformed proof id")
	case !id.Valid(id.Transfer, p.TransferID):
		return invalid("malformed transfer id")
	case !validProofKind(p.Kind):
		return invalid("unknown proof kind")
	case p.RecipientLinkID != "" && p.Kind != ProofDelivery:
		return invalid("only a delivery proof names a recipient link")
	case p.RecipientLinkID != "" && !id.Valid(id.RecipientLink, p.RecipientLinkID):
		return invalid("malformed recipient link id")
	case len(p.Statement) < MinProofStatementBytes || len(p.Statement) > MaxProofStatementBytes:
		return invalid("proof statement must hold %d to %d bytes", MinProofStatementBytes, MaxProofStatementBytes)
	case !json.Valid(p.Statement):
		return invalid("proof statement must be json")
	case len(p.Signature) != ProofSignatureSize:
		return invalid("proof signature must hold %d bytes", ProofSignatureSize)
	case !id.Valid(id.ProofKey, p.KeyID):
		return invalid("malformed proof key id")
	case toMillis(p.ExpiresAt) <= toMillis(created):
		return invalid("proof must expire after its creation")
	}
	_, err := tx.Exec(ctx, qProofInsert, p.ID, p.TransferID, string(p.Kind), nullText(p.RecipientLinkID),
		string(p.Statement), p.Signature, p.KeyID, toMillis(created), toMillis(p.ExpiresAt))
	return err
}

// Get returns the proof of kind kind of the transfer transferID of tenant
// tid: the overall one when recipientLinkID is "", the one of that
// recipient link otherwise. It returns ErrNotFound when it does not exist
// or belongs to another tenant.
func (r *TransferProofs) Get(ctx context.Context, tid tenant.ID, transferID string, kind ProofKind, recipientLinkID string) (TransferProof, error) {
	return readScoped(ctx, r.db, tid, "get transfer proof", func(tx *ScopedTx) (TransferProof, error) {
		return getProof(ctx, tx, transferID, kind, recipientLinkID)
	})
}

// GetTx is Get inside tx, in the tenant tx is bound to.
func (r *TransferProofs) GetTx(ctx context.Context, tx *ScopedTx, transferID string, kind ProofKind, recipientLinkID string) (TransferProof, error) {
	p, err := getProof(ctx, tx, transferID, kind, recipientLinkID)
	if err != nil {
		return TransferProof{}, wrap("get transfer proof", err)
	}
	return p, nil
}

// getProof implements GetTx, returning raw errors.
func getProof(ctx context.Context, tx *ScopedTx, transferID string, kind ProofKind, recipientLinkID string) (TransferProof, error) {
	if recipientLinkID == "" {
		return scanProof(tx.QueryRow(ctx, qProofGetOverall, transferID, string(kind)))
	}
	return scanProof(tx.QueryRow(ctx, qProofGetRecipient, transferID, string(kind), recipientLinkID))
}

// GetRecipientDelivery returns the per-recipient delivery proof of the
// transfer transferID of tenant tid whose statement attests the first
// download of the address email (the email of its single recipientDownloads
// entry, compared in normalized form). It does not use the recipient links,
// which are deleted with the transfer while the proof outlives it: the rows
// of the transfer are read in small batches and their statements parsed. It
// returns ErrInvalid for a malformed address and ErrNotFound when no such
// proof exists or the transfer belongs to another tenant.
func (r *TransferProofs) GetRecipientDelivery(ctx context.Context, tid tenant.ID, transferID, email string) (TransferProof, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return TransferProof{}, err
	}
	return readScoped(ctx, r.db, tid, "get recipient delivery proof", func(tx *ScopedTx) (TransferProof, error) {
		return recipientDelivery(ctx, tx, transferID, email)
	})
}

// recipientDelivery implements GetRecipientDelivery inside tx for a
// normalized address, returning raw errors.
func recipientDelivery(ctx context.Context, tx *ScopedTx, transferID, email string) (TransferProof, error) {
	after := ""
	for {
		rows, err := tx.Query(ctx, qProofRecipientDeliveries, transferID, after, proofLookupBatch)
		if err != nil {
			return TransferProof{}, err
		}
		batch, err := collect(rows, func(r *sql.Rows) (TransferProof, error) { return scanProof(r) })
		if err != nil {
			return TransferProof{}, err
		}
		for _, p := range batch {
			if deliveryRecipient(p.Statement, email) {
				return p, nil
			}
		}
		if len(batch) < proofLookupBatch {
			return TransferProof{}, ErrNotFound
		}
		after = batch[len(batch)-1].ID
	}
}

// deliveryRecipient reports whether the JSON statement of a per-recipient
// delivery names the normalized address email in its single
// recipientDownloads entry.
func deliveryRecipient(statement []byte, email string) bool {
	var fields struct {
		RecipientDownloads []struct {
			Email string `json:"email"`
		} `json:"recipientDownloads"`
	}
	if json.Unmarshal(statement, &fields) != nil || len(fields.RecipientDownloads) != 1 {
		return false
	}
	return sameAddress(fields.RecipientDownloads[0].Email, email)
}

// Purge deletes the proofs of tenant tid that expire at or before now (12
// months after their creation), oldest first, in batches of
// PurgeBatchSize, and returns how many it deleted. A proof is purged
// whether or not its transfer still exists.
func (r *TransferProofs) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	ms := toMillis(now)
	return r.db.purge(ctx, tid, "purge transfer proofs", false, func(ctx context.Context, tx *ScopedTx, _ string, size int) (int64, string, bool, error) {
		// Every listed row is eligible and is gone after the batch (an
		// immutable proof never becomes ineligible), so the next batch
		// needs no cursor.
		ids, err := listIDs(ctx, tx, qProofPurgeList, ms, size)
		if err != nil {
			return 0, "", false, err
		}
		var deleted int64
		for _, prfID := range ids {
			n, err := execCount(ctx, tx, qProofPurge, prfID, ms)
			if err != nil {
				return 0, "", false, err
			}
			deleted += n
		}
		return deleted, "", len(ids) == size, nil
	})
}

// DeleteByAddressTx deletes, inside tx, every proof of the tenant tx is
// bound to whose statement names the address email (normalized) as its
// sender, one of its recipients or in a recipient download, and returns how
// many it deleted (GDPR erasure, data model section 2.3). A text prefilter
// selects the candidate statements; each is then parsed, so that a proof
// naming the address only inside another address or a file name is kept.
// It returns ErrInvalid for a malformed address. After an error, the
// caller must abort the transaction. Callers run [DB.ScrubDeleted] once
// tx is committed.
func (r *TransferProofs) DeleteByAddressTx(ctx context.Context, tx *ScopedTx, email string) (int, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	n, err := r.deleteByAddress(ctx, tx, email)
	if err != nil {
		return 0, wrap("delete transfer proofs by address", err)
	}
	return n, nil
}

// proofCandidates returns the prefilter statement of the engine.
func (r *TransferProofs) proofCandidates() TenantQuery {
	if r.db.dialect.name == config.DriverPostgres {
		return qProofCandidatesPostgres
	}
	return qProofCandidatesSQLite
}

// deleteByAddress implements DeleteByAddressTx for a normalized address.
func (r *TransferProofs) deleteByAddress(ctx context.Context, tx *ScopedTx, email string) (int, error) {
	deleted := 0
	err := r.forEachNamed(ctx, tx, email, func(id string) error {
		n, err := execCount(ctx, tx, qProofDelete, id)
		deleted += int(n)
		return err
	})
	return deleted, err
}

// CountByAddress returns how many proofs of tenant tid have a statement
// naming the address email (normalized) as its sender, one of its
// recipients or in a recipient download: the proofs
// [TransferProofs.DeleteByAddressTx] would delete, with the same matching.
// It returns ErrInvalid for a malformed address.
func (r *TransferProofs) CountByAddress(ctx context.Context, tid tenant.ID, email string) (int, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	return readScoped(ctx, r.db, tid, "count transfer proofs by address", func(tx *ScopedTx) (int, error) {
		n := 0
		err := r.forEachNamed(ctx, tx, email, func(string) error {
			n++
			return nil
		})
		return n, err
	})
}

// forEachNamed calls visit with the ID of every proof of the tenant of tx
// whose statement names the normalized address email, by batches: the
// prefilter selects the candidates, statementNames decides.
func (r *TransferProofs) forEachNamed(ctx context.Context, tx *ScopedTx, email string, visit func(id string) error) error {
	q, needle := r.proofCandidates(), proofNeedle(email)
	after := ""
	for {
		// Read the whole batch first: the connection cannot run the
		// visits (deletions) while a result set is open.
		rows, err := tx.Query(ctx, q, needle, after, proofEraseBatch)
		if err != nil {
			return err
		}
		type candidate struct{ id, statement string }
		batch, err := collect(rows, func(r *sql.Rows) (candidate, error) {
			var c candidate
			err := r.Scan(&c.id, &c.statement)
			return c, err
		})
		if err != nil {
			return err
		}
		for _, c := range batch {
			if !statementNames(c.statement, email) {
				continue
			}
			if err := visit(c.id); err != nil {
				return err
			}
		}
		if len(batch) < proofEraseBatch {
			return nil
		}
		after = batch[len(batch)-1].id
	}
}

// proofNeedle returns the text the erasure prefilter looks for in the
// lower-cased statements: the normalized address itself when every
// character of it appears unescaped in any JSON encoding, and its "@domain"
// part otherwise (the domain is ASCII letters, digits, dots and hyphens).
// The prefilter only has to select a superset of the statements naming the
// address: statementNames decides.
func proofNeedle(email string) string {
	for _, c := range email {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_+@", c) {
			continue
		}
		return email[strings.LastIndexByte(email, '@'):]
	}
	return email
}

// statementNames reports whether the JSON statement names the normalized
// address email as its senderEmail, one of its recipients or the email of
// one of its recipientDownloads. Each field is decoded on its own, so that
// a field of an unexpected shape does not hide the others.
func statementNames(statement, email string) bool {
	var fields struct {
		SenderEmail        json.RawMessage `json:"senderEmail"`
		Recipients         json.RawMessage `json:"recipients"`
		RecipientDownloads json.RawMessage `json:"recipientDownloads"`
	}
	if json.Unmarshal([]byte(statement), &fields) != nil {
		return false
	}
	var addrs []string
	var sender string
	if json.Unmarshal(fields.SenderEmail, &sender) == nil {
		addrs = append(addrs, sender)
	}
	var rcpts []string
	if json.Unmarshal(fields.Recipients, &rcpts) == nil {
		addrs = append(addrs, rcpts...)
	}
	var downloads []struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(fields.RecipientDownloads, &downloads) == nil {
		for _, d := range downloads {
			addrs = append(addrs, d.Email)
		}
	}
	for _, a := range addrs {
		if sameAddress(a, email) {
			return true
		}
	}
	return false
}

// sameAddress reports whether the address a of a statement is the
// normalized address email, comparing normalized forms (a lower-cased
// trimmed form when a does not normalize).
func sameAddress(a, email string) bool {
	if n, err := NormalizeEmail(a); err == nil {
		return n == email
	}
	return strings.ToLower(strings.TrimSpace(a)) == email
}
