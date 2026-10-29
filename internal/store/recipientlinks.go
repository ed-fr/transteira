package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonRecipientLinkEmail is the review of the recipient link reads joined
// with their recipient address: the tenant slot filters recipient_links,
// and the join reads the transfer_recipients row of the same tenant,
// transfer and position only (r.tenant_id = l.tenant_id); on PostgreSQL
// the transfer_recipients policy also restricts it to the tenant.
const reasonRecipientLinkEmail = "recipient links: read the address of the recipient of the same tenant, transfer and position"

// reasonReminderSweep is the reason of the system query listing the
// transfers due for their expiry reminder across tenants.
const reasonReminderSweep = "expiry reminder"

// ReminderLead is how long before the expiry of a per-recipient transfer
// its recipients who did not download yet get the expiry reminder (spec
// 12.2: the day before).
const ReminderLead = 24 * time.Hour

// ReminderSweepLimit is the largest page of [RecipientLinks.DueReminders].
const ReminderSweepLimit = maxSweepPage

// ArchiveItem is the item of a [RecipientDownload] of the ZIP archive of
// the whole transfer, stored in place of a file ID.
const ArchiveItem = "archive"

// linkColumns is the column list read by the recipient link queries, the
// address coming from the joined transfer_recipients row r.
const linkColumns = `l.id, l.transfer_id, l.position, r.email, l.token_hash, l.token_key_id, l.verified_at, ` +
	`l.first_downloaded_at, l.last_downloaded_at, l.completed_at, l.download_count, l.reminder_sent_at, l.created_at`

// linkFrom is the join of a recipient link with its recipient address.
const linkFrom = ` FROM recipient_links l JOIN transfer_recipients r
		ON r.tenant_id = l.tenant_id AND r.transfer_id = l.transfer_id AND r.position = l.position`

// Statements of the RecipientLinks repository. The reads joined with the
// recipient address are reviewed; the reminder sweep is the only system
// query.
var (
	qLinkInsert = tenantQuery(
		`INSERT INTO recipient_links (tenant_id, id, transfer_id, position, token_hash, token_key_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	qLinkGetByToken = reviewedTenantQuery(
		`SELECT `+linkColumns+linkFrom+` WHERE l.tenant_id = ? AND l.token_hash = ?`,
		reasonRecipientLinkEmail)
	qLinkGet = reviewedTenantQuery(
		`SELECT `+linkColumns+linkFrom+` WHERE l.tenant_id = ? AND l.id = ?`,
		reasonRecipientLinkEmail)
	qLinkListByTransfer = reviewedTenantQuery(
		`SELECT `+linkColumns+linkFrom+` WHERE l.tenant_id = ? AND l.transfer_id = ? ORDER BY l.position`,
		reasonRecipientLinkEmail)
	// qLinkTransfers lists the links of a tenant with their transfer, for
	// the reconciliation of its directory (the range state files).
	qLinkTransfers = tenantQuery(
		`SELECT id, transfer_id FROM recipient_links WHERE tenant_id = ? LIMIT ?`)
	qLinkCount = tenantQuery(
		`SELECT count(*) FROM recipient_links WHERE tenant_id = ? AND id = ?`)
	qLinkKeyIDs = tenantQuery(
		`SELECT token_key_id FROM recipient_links
		WHERE tenant_id = ? AND transfer_id = ? AND token_key_id IS NOT NULL ORDER BY position`)
	qLinkSetVerified = tenantQuery(
		`UPDATE recipient_links SET verified_at = ? WHERE tenant_id = ? AND id = ?`)
	// qLinkClaim counts a download start through a link.
	qLinkClaim = tenantQuery(
		`UPDATE recipient_links SET download_count = download_count + 1,
		first_downloaded_at = COALESCE(first_downloaded_at, ?), last_downloaded_at = ?
		WHERE tenant_id = ? AND id = ?`)
	// qLinkComplete records the first complete download through a link
	// already claimed, at most once.
	qLinkComplete = tenantQuery(
		`UPDATE recipient_links SET completed_at = ?
		WHERE tenant_id = ? AND id = ? AND completed_at IS NULL AND first_downloaded_at IS NOT NULL`)
	qLinkCountIncomplete = tenantQuery(
		`SELECT count(*) FROM recipient_links WHERE tenant_id = ? AND transfer_id = ? AND completed_at IS NULL`)
	qLinkReminderSent = tenantQuery(
		`UPDATE recipient_links SET reminder_sent_at = ? WHERE tenant_id = ? AND id = ? AND reminder_sent_at IS NULL`)
	qLinkReminderReset = tenantQuery(
		`UPDATE recipient_links SET reminder_sent_at = NULL WHERE tenant_id = ? AND transfer_id = ? AND id = ?`)

	// The validator refuses ON CONFLICT: a tracking row is an UPDATE, then
	// an INSERT when none existed. The claim updates the link row first,
	// which serializes the claims of one link on PostgreSQL (row lock) as
	// SQLite serializes every write transaction.
	qDownloadBump = tenantQuery(
		`UPDATE recipient_downloads SET count = count + 1, last_at = ?
		WHERE tenant_id = ? AND recipient_link_id = ? AND item = ?`)
	qDownloadInsert = tenantQuery(
		`INSERT INTO recipient_downloads (tenant_id, recipient_link_id, item, first_at, last_at) VALUES (?, ?, ?, ?, ?)`)
	qDownloadComplete = tenantQuery(
		`UPDATE recipient_downloads SET completed_at = ?
		WHERE tenant_id = ? AND recipient_link_id = ? AND item = ? AND completed_at IS NULL`)
	qDownloadCount = tenantQuery(
		`SELECT count(*) FROM recipient_downloads WHERE tenant_id = ? AND recipient_link_id = ? AND item = ?`)
	qDownloadList = tenantQuery(
		`SELECT item, first_at, last_at, count, completed_at FROM recipient_downloads
		WHERE tenant_id = ? AND recipient_link_id = ? ORDER BY first_at, item`)

	qTransferMarkReminder = tenantQuery(
		`UPDATE transfers SET expiry_reminder_at = ? WHERE tenant_id = ? AND id = ? AND expiry_reminder_at IS NULL`)
	qTransferResetReminder = tenantQuery(
		`UPDATE transfers SET expiry_reminder_at = NULL
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND expires_at > ?`)
	// qTransferDueReminders returns identifiers and the expiry only,
	// earliest expiry first, one page after a keyset cursor
	// (transfers_reminder_idx).
	qTransferDueReminders = systemQuery(
		`SELECT tenant_id, id, expires_at FROM transfers
		WHERE status = 'available' AND link_mode = 'per_recipient' AND expiry_reminder_at IS NULL
		AND expires_at <= ? AND expires_at > ?
		AND (expires_at, tenant_id, id) > (?, ?, ?)
		ORDER BY expires_at, tenant_id, id LIMIT ?`,
		reasonReminderSweep)
)

// RecipientLink is the own download link of one recipient of a
// LinkModePerRecipient transfer (spec 10). The link itself is a "dl_" token
// given to that recipient only: the store keeps its SHA-256 and a sealed
// copy, never shown to the sender, an administrator or an API token (D1).
type RecipientLink struct {
	// ID is the identifier ("rcl_" + ULID), assigned by the store.
	ID string
	// TransferID is the transfer of the link.
	TransferID string
	// Position is the position of the recipient in the transfer.
	Position int
	// Email is the normalized address of the recipient, read from the
	// recipients of the transfer.
	Email string
	// TokenHash is the SHA-256 (TokenHashSize bytes) of the "dl_" token.
	TokenHash []byte
	// TokenKeyID is the wrapped key ("wk_" + ULID, purpose
	// KeyPurposeSecret) holding the raw token sealed by the key vault, used
	// only to mail the link again to its own recipient. It reads "" once
	// the key was destroyed (cryptographic erasure).
	TokenKeyID string
	// VerifiedAt is the last successful recipient verification by code
	// (display only: the proof is the verification cookie), zero when
	// never.
	VerifiedAt time.Time
	// FirstDownloadedAt and LastDownloadedAt are the first and the last
	// download start through the link, zero before the first.
	FirstDownloadedAt, LastDownloadedAt time.Time
	// CompletedAt is the first complete download through the link (D2),
	// zero before.
	CompletedAt time.Time
	// DownloadCount counts the download starts through the link.
	DownloadCount int64
	// ReminderSentAt is when the expiry reminder of the current expiry was
	// sent to the recipient, zero when not.
	ReminderSentAt time.Time
	// CreatedAt is when the link was created (the transfer became
	// available).
	CreatedAt time.Time
}

// LinkToken is a new recipient link, as generated by the caller: the
// SHA-256 of its "dl_" token and the wrapped key sealing the raw token.
type LinkToken struct {
	// Hash is the SHA-256 (TokenHashSize bytes) of the "dl_" token.
	Hash []byte
	// KeyID is the wrapped key ("wk_" + ULID, purpose KeyPurposeSecret,
	// same tenant) sealing the raw token, created in the same transaction.
	KeyID string
}

// LinkCompletion is the outcome of [RecipientLinks.CompleteTx].
type LinkCompletion struct {
	// First reports that this call recorded the completion of the link
	// (false when it was already complete).
	First bool
	// AllComplete reports that every link of the transfer is now complete.
	AllComplete bool
}

// RecipientDownload is the tracking of one item downloaded through a
// recipient link (OpenAPI RecipientTracking.downloads).
type RecipientDownload struct {
	// FileID is the downloaded file ("fil_" + ULID), "" for the ZIP archive.
	FileID string
	// FirstAt and LastAt are the first and the last download start of the
	// item.
	FirstAt, LastAt time.Time
	// Count counts the download starts of the item (resumed ranges
	// excluded), at least 1.
	Count int64
	// CompletedAt is when the item was fully served for the first time,
	// zero before.
	CompletedAt time.Time
}

// RecipientTracking is the tracking of one recipient of a per-recipient
// transfer (OpenAPI RecipientTracking): who verified, and what they
// downloaded, through their own link.
type RecipientTracking struct {
	// LinkID is the link of the recipient ("rcl_" + ULID).
	LinkID string
	// Position is the position of the recipient in the transfer.
	Position int
	// Email is the address of the recipient.
	Email string
	// VerifiedAt is the last verification by code, zero when never.
	VerifiedAt time.Time
	// FirstDownloadedAt and LastDownloadedAt are the first and the last
	// download start, zero before the first.
	FirstDownloadedAt, LastDownloadedAt time.Time
	// CompletedAt is the first complete download, zero before.
	CompletedAt time.Time
	// Downloads is the tracking of each downloaded item, in the order of
	// their first download.
	Downloads []RecipientDownload
}

// RecipientLinks is the tenant-scoped repository of the per-recipient
// links of the transfers and of their download tracking. Obtain it with
// [DB.RecipientLinks].
//
// Cryptographic erasure (T-110): the sealed token of a link must be
// destroyed ([RecipientLinks.DestroyKeysTx]) before its transfer ends or is
// deleted, and before its recipient is removed; the store refuses those
// operations with [ErrKeysRemain] otherwise.
type RecipientLinks struct {
	db *DB
}

// RecipientLinks returns the recipient link repository.
func (db *DB) RecipientLinks() *RecipientLinks { return &RecipientLinks{db: db} }

// checkLinkTokens validates the shape of new link tokens: 1 to
// MaxTransferRecipients of them.
func checkLinkTokens(tokens []LinkToken) error {
	if len(tokens) == 0 || len(tokens) > MaxTransferRecipients {
		return invalid("a transfer needs 1 to %d recipient links", MaxTransferRecipients)
	}
	for _, t := range tokens {
		if !validTokenHash(t.Hash) {
			return invalid("token hash must hold %d bytes", TokenHashSize)
		}
		if !id.Valid(id.WrappedKey, t.KeyID) {
			return invalid("malformed token key id")
		}
	}
	return nil
}

// CreateTx creates, inside tx, the own link of each recipient of the
// LinkModePerRecipient transfer trfID of the tenant tx is bound to at now:
// tokens[i] is the link of the recipient at position i, and there must be
// exactly one per recipient. It returns the links created, in position
// order. [Transfers.MarkAvailableLinksTx] calls it when the transfer
// becomes available.
//
// It returns ErrInvalid for a malformed token, a wrong number of tokens, a
// key that is not a secret or a shared transfer, ErrNotFound when the
// transfer or a key does not exist (or belongs to another tenant), and
// ErrConflict when the transfer already has links or a token hash or a key
// is already used. After an error, the caller must abort the transaction.
func (r *RecipientLinks) CreateTx(ctx context.Context, tx *ScopedTx, trfID string, tokens []LinkToken, now time.Time) ([]RecipientLink, error) {
	links, err := func() ([]RecipientLink, error) {
		if err := checkLinkTokens(tokens); err != nil {
			return nil, err
		}
		t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
		if err != nil {
			return nil, err
		}
		if t.LinkMode != LinkModePerRecipient {
			return nil, invalid("the transfer has shared links")
		}
		return createLinks(ctx, tx, trfID, tokens, now)
	}()
	if err != nil {
		return nil, wrap("create recipient links", err)
	}
	return links, nil
}

// createLinks inserts the links of tokens (already validated) for the
// recipients of trfID in tx, returning raw errors.
func createLinks(ctx context.Context, tx *ScopedTx, trfID string, tokens []LinkToken, now time.Time) ([]RecipientLink, error) {
	var n int
	if err := tx.QueryRow(ctx, qRecipientCount, trfID).Scan(&n); err != nil {
		return nil, err
	}
	if n != len(tokens) {
		return nil, invalid("the transfer has %d recipients, %d links given", n, len(tokens))
	}
	for _, t := range tokens {
		if err := checkKey(ctx, tx, t.KeyID, KeyPurposeSecret, "token key is not a secret"); err != nil {
			return nil, err
		}
	}
	ms := toMillis(now)
	for i, t := range tokens {
		if _, err := tx.Exec(ctx, qLinkInsert, id.New(id.RecipientLink), trfID, i, t.Hash, t.KeyID, ms); err != nil {
			return nil, err
		}
	}
	return listLinks(ctx, tx, trfID)
}

// scanLink reads one row of linkColumns.
func scanLink(row interface{ Scan(...any) error }) (RecipientLink, error) {
	var (
		l                                   RecipientLink
		key                                 sql.NullString
		verified, first, last, done, remind sql.NullInt64
		created                             int64
	)
	err := row.Scan(&l.ID, &l.TransferID, &l.Position, &l.Email, &l.TokenHash, &key, &verified, &first, &last,
		&done, &l.DownloadCount, &remind, &created)
	if err != nil {
		return RecipientLink{}, err
	}
	l.TokenKeyID, l.VerifiedAt = key.String, nullMillis(verified)
	l.FirstDownloadedAt, l.LastDownloadedAt, l.CompletedAt = nullMillis(first), nullMillis(last), nullMillis(done)
	l.ReminderSentAt, l.CreatedAt = nullMillis(remind), fromMillis(created)
	return l, nil
}

// listLinks returns the links of trfID in tx, in position order.
func listLinks(ctx context.Context, tx *ScopedTx, trfID string) ([]RecipientLink, error) {
	rows, err := tx.Query(ctx, qLinkListByTransfer, trfID)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (RecipientLink, error) { return scanLink(r) })
}

// validLinkID reports whether s has the shape of a recipient link ID.
func validLinkID(s string) bool { return id.Valid(id.RecipientLink, s) }

// GetByTokenHash returns the recipient link of tenant tid whose token has
// the SHA-256 hash, with its recipient address and its transfer, in
// whatever state the transfer is. It returns ErrNotFound when there is
// none, including for a link of another tenant, and ErrInvalid for a hash
// of the wrong size. The store applies no download rule (see
// [Transfers.GetByDownloadTokenHash]): the caller reads the transfer and
// checks it.
func (r *RecipientLinks) GetByTokenHash(ctx context.Context, tid tenant.ID, hash []byte) (RecipientLink, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return RecipientLink{}, err
	}
	if !validTokenHash(hash) {
		return RecipientLink{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return readScoped(ctx, r.db, tid, "get recipient link by token", func(tx *ScopedTx) (RecipientLink, error) {
		return scanLink(tx.QueryRow(ctx, qLinkGetByToken, hash))
	})
}

// GetTx returns the recipient link linkID of the tenant tx is bound to,
// inside tx. It returns ErrInvalid for a malformed ID and ErrNotFound when
// the link does not exist or belongs to another tenant. After an error, the
// caller must abort the transaction.
func (r *RecipientLinks) GetTx(ctx context.Context, tx *ScopedTx, linkID string) (RecipientLink, error) {
	if !validLinkID(linkID) {
		return RecipientLink{}, wrap("get recipient link", invalid("malformed recipient link id"))
	}
	l, err := scanLink(tx.QueryRow(ctx, qLinkGet, linkID))
	if err != nil {
		return RecipientLink{}, wrap("get recipient link", err)
	}
	return l, nil
}

// ListByTransfer returns the links of the transfer trfID of tenant tid, in
// position order, with their recipient address, sealed token key (to mail
// a link again to its own recipient) and tracking fields: none for a
// shared transfer, or a transfer that does not exist or belongs to another
// tenant.
func (r *RecipientLinks) ListByTransfer(ctx context.Context, tid tenant.ID, trfID string) ([]RecipientLink, error) {
	return readScoped(ctx, r.db, tid, "list recipient links", func(tx *ScopedTx) ([]RecipientLink, error) {
		return listLinks(ctx, tx, trfID)
	})
}

// ListByTransferTx is [RecipientLinks.ListByTransfer] inside tx. After an
// error, the caller must abort the transaction.
func (r *RecipientLinks) ListByTransferTx(ctx context.Context, tx *ScopedTx, trfID string) ([]RecipientLink, error) {
	links, err := listLinks(ctx, tx, trfID)
	if err != nil {
		return nil, wrap("list recipient links", err)
	}
	return links, nil
}

// TransfersByLink returns the transfer of every recipient link of tenant
// tid, keyed by link ID, whatever the state of the transfer: the
// reconciliation of the tenant directory keeps the range state files of
// the links of the available transfers (each link has its own). It reads
// at most MaxReconcileRows links and returns [ErrTooManyRows] beyond.
func (r *RecipientLinks) TransfersByLink(ctx context.Context, tid tenant.ID) (map[string]string, error) {
	return readScoped(ctx, r.db, tid, "list recipient links", func(tx *ScopedTx) (map[string]string, error) {
		rows, err := tx.Query(ctx, qLinkTransfers, r.db.reconcileRows+1)
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		_, err = collect(rows, func(r *sql.Rows) (struct{}, error) {
			var linkID, trfID string
			err := r.Scan(&linkID, &trfID)
			out[linkID] = trfID
			return struct{}{}, err
		})
		if err != nil {
			return nil, err
		}
		if len(out) > r.db.reconcileRows {
			return nil, ErrTooManyRows
		}
		return out, nil
	})
}

// MarkVerifiedTx records, inside tx, that the recipient of the link linkID
// of the tenant tx is bound to verified their address by code at now (the
// last verification wins). It returns ErrInvalid for a malformed ID and
// ErrNotFound when the link does not exist or belongs to another tenant.
// After an error, the caller must abort the transaction.
func (r *RecipientLinks) MarkVerifiedTx(ctx context.Context, tx *ScopedTx, linkID string, now time.Time) error {
	err := execLink(ctx, tx, qLinkSetVerified, linkID, toMillis(now))
	if err != nil {
		return wrap("mark recipient verified", err)
	}
	return nil
}

// execLink runs the single-row update q (its arguments, then the link ID)
// on the link linkID, returning ErrNotFound when no row matched.
func execLink(ctx context.Context, tx *ScopedTx, q TenantQuery, linkID string, args ...any) error {
	if !validLinkID(linkID) {
		return invalid("malformed recipient link id")
	}
	res, err := tx.Exec(ctx, q, append(args, linkID)...)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// downloadItem maps a file ID ("" for the archive) to its tracking item.
func downloadItem(fileID string) (string, error) {
	if fileID == "" {
		return ArchiveItem, nil
	}
	if !id.Valid(id.File, fileID) {
		return "", invalid("malformed file id")
	}
	return fileID, nil
}

// ClaimTx records, inside tx, a download start (never a HEAD request or a
// resumed range) through the link linkID of the tenant tx is bound to at
// now: of the file fileID, or of the archive when fileID is "". It counts
// the start on the link (DownloadCount, FirstDownloadedAt,
// LastDownloadedAt) and in the tracking of the item. The caller checks
// beforehand that the file belongs to the transfer of the link, and counts
// the start on the transfer in the same transaction
// ([Transfers.ClaimDownloadTx] or [Transfers.IncrementDownloadsTx]).
//
// It returns ErrInvalid for a malformed ID and ErrNotFound when the link
// does not exist or belongs to another tenant. After an error, the caller
// must abort the transaction.
func (r *RecipientLinks) ClaimTx(ctx context.Context, tx *ScopedTx, linkID, fileID string, now time.Time) error {
	if err := claimLink(ctx, tx, linkID, fileID, now); err != nil {
		return wrap("claim recipient download", err)
	}
	return nil
}

// claimLink implements ClaimTx, returning raw errors.
func claimLink(ctx context.Context, tx *ScopedTx, linkID, fileID string, now time.Time) error {
	item, err := downloadItem(fileID)
	if err != nil {
		return err
	}
	ms := toMillis(now)
	if err := execLink(ctx, tx, qLinkClaim, linkID, ms, ms); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, qDownloadBump, ms, linkID, item)
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		_, err = tx.Exec(ctx, qDownloadInsert, linkID, item, ms, ms)
	}
	return err
}

// CompleteItemTx records, inside tx, that the file fileID (the archive
// when "") was fully served through the link linkID of the tenant tx is
// bound to for the first time at now. The update is conditional: it
// returns true for the call that recorded it, and false, without error,
// when it was already recorded. It returns ErrInvalid for a malformed ID
// and ErrNotFound when the item was never claimed through the link
// ([RecipientLinks.ClaimTx]), or the link does not exist or belongs to
// another tenant. After an error, the caller must abort the transaction.
func (r *RecipientLinks) CompleteItemTx(ctx context.Context, tx *ScopedTx, linkID, fileID string, now time.Time) (bool, error) {
	first, err := completeItem(ctx, tx, linkID, fileID, now)
	if err != nil {
		return false, wrap("complete recipient download", err)
	}
	return first, nil
}

// completeItem implements CompleteItemTx, returning raw errors.
func completeItem(ctx context.Context, tx *ScopedTx, linkID, fileID string, now time.Time) (bool, error) {
	item, err := downloadItem(fileID)
	if err != nil {
		return false, err
	}
	if !validLinkID(linkID) {
		return false, invalid("malformed recipient link id")
	}
	res, err := tx.Exec(ctx, qDownloadComplete, toMillis(now), linkID, item)
	if err == nil {
		err = expectOne(res)
	}
	if !errors.Is(err, ErrNotFound) {
		return err == nil, err
	}
	var n int
	if err := tx.QueryRow(ctx, qDownloadCount, linkID, item).Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		return false, ErrNotFound
	}
	return false, nil
}

// CompleteTx records, inside tx, the first complete download through the
// link linkID of the tenant tx is bound to at now (D2): every byte of
// every deliverable file, or the whole archive, was served through it. The
// update is conditional, so that exactly one call records it (First). It
// also reports whether every link of the transfer is now complete
// (AllComplete). In the same transaction, the caller then calls
// [Transfers.MarkFirstDownloadTx], which records the first download of the
// transfer and, for a transfer deleted after its first download, makes it
// due for deletion once every link is complete.
//
// It returns ErrInvalid for a malformed ID, ErrNotFound when the link does
// not exist or belongs to another tenant, and ErrConflict when no download
// was ever claimed through it ([RecipientLinks.ClaimTx]). After an error,
// the caller must abort the transaction.
func (r *RecipientLinks) CompleteTx(ctx context.Context, tx *ScopedTx, linkID string, now time.Time) (LinkCompletion, error) {
	c, err := completeLink(ctx, tx, linkID, now)
	if err != nil {
		return LinkCompletion{}, wrap("complete recipient link", err)
	}
	return c, nil
}

// completeLink implements CompleteTx, returning raw errors.
func completeLink(ctx context.Context, tx *ScopedTx, linkID string, now time.Time) (LinkCompletion, error) {
	if !validLinkID(linkID) {
		return LinkCompletion{}, invalid("malformed recipient link id")
	}
	l, err := scanLink(tx.QueryRow(ctx, qLinkGet, linkID))
	if err != nil {
		return LinkCompletion{}, err
	}
	if l.FirstDownloadedAt.IsZero() {
		return LinkCompletion{}, ErrConflict
	}
	var c LinkCompletion
	res, err := tx.Exec(ctx, qLinkComplete, toMillis(now), linkID)
	if err == nil {
		err = expectOne(res)
	}
	switch {
	case err == nil:
		c.First = true
	case !errors.Is(err, ErrNotFound):
		return LinkCompletion{}, err
	}
	var n int
	if err := tx.QueryRow(ctx, qLinkCountIncomplete, l.TransferID).Scan(&n); err != nil {
		return LinkCompletion{}, err
	}
	c.AllComplete = n == 0
	return c, nil
}

// DestroyKeysTx destroys, inside tx, the sealed token of every link of the
// transfer trfID of the tenant tx is bound to (cryptographic erasure, spec
// 16.1), and returns how many it destroyed: none for a shared transfer, a
// transfer whose link keys are already destroyed, or a transfer that does
// not exist or belongs to another tenant. The links stay usable to resolve
// their token (the "gone" answer) but can no longer be mailed again. Every
// path that ends or deletes a per-recipient transfer calls it first, in
// the transaction that ends it ([Transfers.MarkExpiredTx],
// [Transfers.MarkDeletedTx], [Transfers.SetStatusTx], [Transfers.DeleteTx]
// refuse with ErrKeysRemain otherwise); callers call [DB.ScrubDeleted] once
// the transaction is committed. After an error, the caller must abort the
// transaction.
func (r *RecipientLinks) DestroyKeysTx(ctx context.Context, tx *ScopedTx, trfID string) (int, error) {
	n, err := destroyLinkKeys(ctx, tx, trfID)
	if err != nil {
		return 0, wrap("destroy recipient link keys", err)
	}
	return n, nil
}

// destroyLinkKeys implements DestroyKeysTx, returning raw errors.
func destroyLinkKeys(ctx context.Context, tx *ScopedTx, trfID string) (int, error) {
	keys, err := listIDs(ctx, tx, qLinkKeyIDs, trfID)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if err := deleteWrappedKey(ctx, tx, k); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

// DestroyRecipientKeyTx destroys, inside tx, the sealed token of the link
// of the recipient email (normalized) of the transfer trfID of the tenant
// tx is bound to, and reports whether there was one to destroy: false when
// the address is not a recipient, has no link (shared transfer) or its key
// is already destroyed. The data-subject erasure calls it before
// [Transfers.RemoveRecipientTx], in the same transaction, which refuses
// with ErrKeysRemain otherwise. It returns ErrInvalid for a malformed
// address. After an error, the caller must abort the transaction.
func (r *RecipientLinks) DestroyRecipientKeyTx(ctx context.Context, tx *ScopedTx, trfID, email string) (bool, error) {
	done, err := func() (bool, error) {
		email, err := NormalizeEmail(email)
		if err != nil {
			return false, err
		}
		links, err := listLinks(ctx, tx, trfID)
		if err != nil {
			return false, err
		}
		for _, l := range links {
			if l.Email == email && l.TokenKeyID != "" {
				return true, deleteWrappedKey(ctx, tx, l.TokenKeyID)
			}
		}
		return false, nil
	}()
	if err != nil {
		return false, wrap("destroy recipient link key", err)
	}
	return done, nil
}

// TrackingByTransfer returns the tracking of each recipient of the
// per-recipient transfer trfID of tenant tid, in position order (spec 10:
// who verified, and what they downloaded through their own link): none
// for a shared transfer, or a transfer that does not exist or belongs to
// another tenant. It never returns the link tokens.
func (r *RecipientLinks) TrackingByTransfer(ctx context.Context, tid tenant.ID, trfID string) ([]RecipientTracking, error) {
	return readScoped(ctx, r.db, tid, "read recipient tracking", func(tx *ScopedTx) ([]RecipientTracking, error) {
		return tracking(ctx, tx, trfID)
	})
}

// TrackingByTransferTx is [RecipientLinks.TrackingByTransfer] inside tx.
// After an error, the caller must abort the transaction.
func (r *RecipientLinks) TrackingByTransferTx(ctx context.Context, tx *ScopedTx, trfID string) ([]RecipientTracking, error) {
	out, err := tracking(ctx, tx, trfID)
	if err != nil {
		return nil, wrap("read recipient tracking", err)
	}
	return out, nil
}

// tracking implements TrackingByTransfer inside tx, returning raw errors.
func tracking(ctx context.Context, tx *ScopedTx, trfID string) ([]RecipientTracking, error) {
	links, err := listLinks(ctx, tx, trfID)
	if err != nil {
		return nil, err
	}
	out := make([]RecipientTracking, len(links))
	for i, l := range links {
		rows, err := tx.Query(ctx, qDownloadList, l.ID)
		if err != nil {
			return nil, err
		}
		ds, err := collect(rows, func(r *sql.Rows) (RecipientDownload, error) {
			var (
				d           RecipientDownload
				item        string
				first, last int64
				done        sql.NullInt64
			)
			err := r.Scan(&item, &first, &last, &d.Count, &done)
			if item != ArchiveItem {
				d.FileID = item
			}
			d.FirstAt, d.LastAt, d.CompletedAt = fromMillis(first), fromMillis(last), nullMillis(done)
			return d, err
		})
		if err != nil {
			return nil, err
		}
		out[i] = RecipientTracking{
			LinkID: l.ID, Position: l.Position, Email: l.Email, VerifiedAt: l.VerifiedAt,
			FirstDownloadedAt: l.FirstDownloadedAt, LastDownloadedAt: l.LastDownloadedAt, CompletedAt: l.CompletedAt,
			Downloads: ds,
		}
	}
	return out, nil
}

// DueReminders returns one page of the per-recipient transfers of every
// tenant due for their expiry reminder at now: available, expiring after
// now and at most ReminderLead after it, and whose reminder pass was not
// done yet (ExpiryReminderAt zero). They come earliest expiry first (then
// by tenant and transfer), the SortKey of each being its ExpiresAt, after
// page.After and at most page.Limit of them (1 to ReminderSweepLimit). It
// is the only cross-tenant read of the reminder (reason "expiry
// reminder") and returns identifiers only: the caller handles each
// transfer in a transaction scoped to its tenant
// ([RecipientLinks.ReminderTargetsTx], [RecipientLinks.MarkReminderSentTx],
// [Transfers.MarkExpiryReminderTx]). It returns ErrInvalid for a page limit
// out of range.
func (r *RecipientLinks) DueReminders(ctx context.Context, now time.Time, page SweepPage) ([]TenantTransfer, error) {
	return r.db.sweepPage(ctx, reasonReminderSweep, "sweep due reminders", qTransferDueReminders,
		page, toMillis(now.Add(ReminderLead)), toMillis(now))
}

// ReminderTargetsTx returns, inside tx, the links of the transfer trfID of
// the tenant tx is bound to whose recipient gets the expiry reminder: no
// download started through the link and no reminder sent for the current
// expiry, in position order. The caller also skips the recipients blocked
// or erased since. After an error, the caller must abort the transaction.
func (r *RecipientLinks) ReminderTargetsTx(ctx context.Context, tx *ScopedTx, trfID string) ([]RecipientLink, error) {
	links, err := listLinks(ctx, tx, trfID)
	if err != nil {
		return nil, wrap("list reminder targets", err)
	}
	out := links[:0]
	for _, l := range links {
		if l.FirstDownloadedAt.IsZero() && l.ReminderSentAt.IsZero() {
			out = append(out, l)
		}
	}
	return out, nil
}

// MarkReminderSentTx records, inside tx, that the expiry reminder was sent
// at at through each link of linkIDs of the tenant tx is bound to. It
// returns ErrInvalid for a malformed ID, ErrNotFound when a link does not
// exist or belongs to another tenant, and ErrConflict when its reminder
// was already sent. After an error, the caller must abort the transaction.
func (r *RecipientLinks) MarkReminderSentTx(ctx context.Context, tx *ScopedTx, linkIDs []string, at time.Time) error {
	for _, linkID := range linkIDs {
		err := execLink(ctx, tx, qLinkReminderSent, linkID, toMillis(at))
		if errors.Is(err, ErrNotFound) {
			err = probe(ctx, tx, qLinkCount, linkID, ErrConflict)
		}
		if err != nil {
			return wrap("mark reminder sent", err)
		}
	}
	return nil
}

// ResetReminderSent clears, in one transaction, the reminder mark of the
// links linkIDs of the transfer trfID of tenant tid, when their reminder
// mail could not be queued, and with them the reminder pass of the
// transfer while it is still available and not expired at now, so that
// the next reminder sweep lists it again and mails these links only
// ([RecipientLinks.ReminderTargetsTx] skips the links still marked). It
// does nothing without links. It returns ErrInvalid for a malformed link
// ID and ErrNotFound when a link does not exist, belongs to another
// transfer or to another tenant; nothing is reset then.
func (r *RecipientLinks) ResetReminderSent(ctx context.Context, tid tenant.ID, trfID string, linkIDs []string, now time.Time) error {
	if len(linkIDs) == 0 {
		return nil
	}
	return writeScoped(ctx, r.db, tid, "reset reminder", func(tx *ScopedTx) error {
		for _, linkID := range linkIDs {
			if err := execLink(ctx, tx, qLinkReminderReset, linkID, trfID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, qTransferResetReminder, trfID, toMillis(now))
		return err
	})
}

// MarkExpiryReminderTx records, inside tx, that the expiry reminder pass of
// the transfer trfID of the tenant tx is bound to was done at at, so that
// the reminder sweep ([RecipientLinks.DueReminders]) no longer lists it.
// It returns ErrNotFound when the transfer does not exist or belongs to
// another tenant, and ErrConflict when the pass was already recorded.
// After an error, the caller must abort the transaction.
func (r *Transfers) MarkExpiryReminderTx(ctx context.Context, tx *ScopedTx, trfID string, at time.Time) error {
	res, err := tx.Exec(ctx, qTransferMarkReminder, toMillis(at), trfID)
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		err = probe(ctx, tx, qTransferCount, trfID, ErrConflict)
	}
	if err != nil {
		return wrap("mark expiry reminder", err)
	}
	return nil
}
