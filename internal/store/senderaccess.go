package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// AccessRateWindow is the sliding window of the rate limits of the "my
// transfers" access link requests (5 per address and 20 per IP, spec 8.7,
// D12): [SenderAccess.RecordRequestTx] counts the requests created at or
// after now - AccessRateWindow. The purge keeps them at least as long.
const AccessRateWindow = time.Hour

// AccessRequestsPerIP is the number of access link requests one client
// (IPv4 address or IPv6 /64) may make per AccessRateWindow in a tenant
// (spec 8.7, D12). [SenderAccess.RecordRequestTx] no longer records the
// requests of a client that reached it: they are refused (429) by the
// caller and must not cost a write each (a flood would otherwise grow the
// table and hold the write lock of the tenant).
const AccessRequestsPerIP = 20

// AddressMACSize is the size of the address MAC of an access link request:
// an HMAC-SHA256 (crypto.MACPurposeAccessRate) of the normalized address,
// computed by the caller. The store never sees the address of a request.
const AddressMACSize = 32

// SenderSessionEndedRetention is how long an ended "my transfers" session
// is kept after its end before the purge deletes it (data model 5.1).
const SenderSessionEndedRetention = time.Hour

// senderLinkColumns and senderSessionColumns are the column lists read by
// the access link and session queries.
const (
	senderLinkColumns    = `id, email, created_at, expires_at, consumed_at`
	senderSessionColumns = `id, email, created_at, expires_at`
)

// Statements of the SenderAccess repository. All of them are single-table
// tenant queries (data model 3.1: no system query).
var (
	qAccessRequestInsert = tenantQuery(
		`INSERT INTO access_link_requests (tenant_id, id, address_mac, client_ip, created_at) VALUES (?, ?, ?, ?, ?)`)
	qAccessRequestCountMAC = tenantQuery(
		`SELECT count(*) FROM access_link_requests WHERE tenant_id = ? AND address_mac = ? AND created_at >= ?`)
	qAccessRequestCountIP = tenantQuery(
		`SELECT count(*) FROM access_link_requests WHERE tenant_id = ? AND client_ip = ? AND created_at >= ?`)
	qAccessRequestDeleteByMAC = tenantQuery(
		`DELETE FROM access_link_requests WHERE tenant_id = ? AND address_mac = ?`)

	qSenderLinkInsert = tenantQuery(
		`INSERT INTO sender_access_links (tenant_id, id, token_hash, email, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`)
	// qSenderLinkConsume consumes a link at most once, while it is valid.
	qSenderLinkConsume = tenantQuery(
		`UPDATE sender_access_links SET consumed_at = ?
		WHERE tenant_id = ? AND token_hash = ? AND consumed_at IS NULL AND expires_at > ?
		RETURNING ` + senderLinkColumns)
	qSenderLinkDeleteByEmail = tenantQuery(
		`DELETE FROM sender_access_links WHERE tenant_id = ? AND email = ?`)

	qSenderSessionInsert = tenantQuery(
		`INSERT INTO sender_sessions (tenant_id, id, token_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`)
	// qSenderSessionGet only returns a session that is neither ended nor
	// expired.
	qSenderSessionGet = tenantQuery(
		`SELECT ` + senderSessionColumns + ` FROM sender_sessions
		WHERE tenant_id = ? AND token_hash = ? AND ended_at IS NULL AND expires_at > ?`)
	qSenderSessionEnd = tenantQuery(
		`UPDATE sender_sessions SET ended_at = ?
		WHERE tenant_id = ? AND token_hash = ? AND ended_at IS NULL AND expires_at > ?`)
	qSenderSessionDeleteByEmail = tenantQuery(
		`DELETE FROM sender_sessions WHERE tenant_id = ? AND email = ?`)

	// Purges (data model 5.1): each lists a bounded batch of candidates,
	// then deletes each by primary key with its condition checked again.
	qAccessRequestPurgeList = tenantQuery(
		`SELECT id FROM access_link_requests WHERE tenant_id = ? AND created_at < ? AND id > ? ORDER BY id LIMIT ?`)
	qAccessRequestPurge = tenantQuery(
		`DELETE FROM access_link_requests WHERE tenant_id = ? AND id = ? AND created_at < ?`)
	qSenderLinkPurgeList = tenantQuery(
		`SELECT id FROM sender_access_links
		WHERE tenant_id = ? AND expires_at <= ? AND COALESCE(consumed_at, 0) <= ? AND id > ?
		ORDER BY id LIMIT ?`)
	qSenderLinkPurge = tenantQuery(
		`DELETE FROM sender_access_links
		WHERE tenant_id = ? AND id = ? AND expires_at <= ? AND COALESCE(consumed_at, 0) <= ?`)
	qSenderSessionPurgeList = tenantQuery(
		`SELECT id FROM sender_sessions
		WHERE tenant_id = ? AND (expires_at <= ? OR ended_at <= ?) AND id > ?
		ORDER BY id LIMIT ?`)
	qSenderSessionPurge = tenantQuery(
		`DELETE FROM sender_sessions WHERE tenant_id = ? AND id = ? AND (expires_at <= ? OR ended_at <= ?)`)
)

// AccessRequestCounts are the requests of access links counted by
// [SenderAccess.RecordRequestTx] in the AccessRateWindow before the
// request, excluding the request itself.
type AccessRequestCounts struct {
	// ByAddress counts the requests for the same address (same address
	// MAC), known or unknown.
	ByAddress int
	// ByIP counts the requests from the same client (IPv4 address or
	// IPv6 /64), whatever the address. When it reaches
	// AccessRequestsPerIP, the request was not recorded.
	ByIP int
}

// SenderAccessLink is a one-time "my transfers" access link (spec 8.7),
// mailed to a verified address. Only the SHA-256 of its "mta_" token is
// stored, never the token itself.
type SenderAccessLink struct {
	// ID is the identifier ("sal_" + ULID), assigned by the store.
	ID string
	// Email is the normalized address the link opens "my transfers" for.
	Email string
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// ExpiresAt is the end of the validity of the link, after CreatedAt.
	ExpiresAt time.Time
	// ConsumedAt is when the link opened a session, zero before.
	ConsumedAt time.Time
}

// SenderSession is a "my transfers" session, opened by an access link and
// carried by a cookie. Only the SHA-256 of the cookie token is stored. A
// session is bound to its tenant and to its normalized address: every
// "my transfers" query is scoped to both.
type SenderSession struct {
	// ID is the internal identifier ("mts_" + ULID), assigned by the
	// store. It never leaves the server.
	ID string
	// Email is the normalized address of the sender.
	Email string
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// ExpiresAt is the absolute end of the session, after CreatedAt.
	ExpiresAt time.Time
}

// SenderAccess is the tenant-scoped repository of "my transfers" (spec
// 8.7): the rate limit of the access link requests, the one-time access
// links and the sessions. Obtain it with [DB.SenderAccess]. Every lookup
// runs in the scope of one tenant (under row-level security on
// PostgreSQL): a token of another tenant reads exactly as an unknown one.
type SenderAccess struct {
	db *DB
}

// SenderAccess returns the "my transfers" access repository.
func (db *DB) SenderAccess() *SenderAccess { return &SenderAccess{db: db} }

// checkMAC validates the shape of an address MAC.
func checkMAC(mac []byte) error {
	if len(mac) != AddressMACSize {
		return invalid("address mac must hold %d bytes", AddressMACSize)
	}
	return nil
}

// RecordRequestTx records, inside tx, a request of an access link at now
// for the address whose MAC (crypto.MACPurposeAccessRate over the
// normalized address) is mac, from the client IP ip, and returns the
// requests counted in the AccessRateWindow before it, for the same address
// MAC and for the same client (excluding this one). A client is an IPv4
// address or an IPv6 /64, like the HTTP rate limits key their clients: the
// row keeps the client key in client_ip. It takes the tenant lock first, so
// that concurrent requests of the tenant count and insert one after the
// other. A request whose client already reached AccessRequestsPerIP is
// counted but not recorded: the caller refuses it (429), and it costs
// neither a row nor the budget of the address. The caller decides on the
// other limit (5 per address: the request is dropped silently, but still
// recorded). Known and unknown addresses go through exactly the same reads
// and writes (D12): the store never looks the address up.
//
// It returns ErrInvalid for a MAC of the wrong size or an invalid IP.
// After an error, the caller must abort the transaction.
func (r *SenderAccess) RecordRequestTx(ctx context.Context, tx *ScopedTx, mac []byte, ip netip.Addr, now time.Time) (AccessRequestCounts, error) {
	c, err := recordRequest(ctx, tx, mac, ip, now)
	if err != nil {
		return AccessRequestCounts{}, wrap("record access link request", err)
	}
	return c, nil
}

// RecordRequest is [SenderAccess.RecordRequestTx] for tenant tid in its
// own transaction, always committed: the request is counted whatever the
// caller decides.
func (r *SenderAccess) RecordRequest(ctx context.Context, tid tenant.ID, mac []byte, ip netip.Addr, now time.Time) (AccessRequestCounts, error) {
	var c AccessRequestCounts
	err := writeScoped(ctx, r.db, tid, "record access link request", func(tx *ScopedTx) error {
		var err error
		c, err = recordRequest(ctx, tx, mac, ip, now)
		return err
	})
	return c, err
}

// recordRequest implements RecordRequestTx, returning raw errors.
func recordRequest(ctx context.Context, tx *ScopedTx, mac []byte, ip netip.Addr, now time.Time) (AccessRequestCounts, error) {
	if err := checkMAC(mac); err != nil {
		return AccessRequestCounts{}, err
	}
	text, err := accessClientKey(ip)
	if err != nil {
		return AccessRequestCounts{}, err
	}
	if err := tx.lock(ctx); err != nil {
		return AccessRequestCounts{}, err
	}
	since := toMillis(now.Add(-AccessRateWindow))
	var c AccessRequestCounts
	if err := tx.QueryRow(ctx, qAccessRequestCountMAC, mac, since).Scan(&c.ByAddress); err != nil {
		return AccessRequestCounts{}, err
	}
	if err := tx.QueryRow(ctx, qAccessRequestCountIP, text, since).Scan(&c.ByIP); err != nil {
		return AccessRequestCounts{}, err
	}
	if c.ByIP >= AccessRequestsPerIP {
		return c, nil // refused by the caller: nothing recorded
	}
	if _, err := tx.Exec(ctx, qAccessRequestInsert, id.New(id.AccessLinkRequest), mac, text, toMillis(now)); err != nil {
		return AccessRequestCounts{}, err
	}
	return c, nil
}

// accessClientKey returns the client key of ip stored in
// access_link_requests.client_ip: the address for IPv4 (IPv4-mapped IPv6
// addresses included), its /64 prefix for IPv6, since one IPv6 client
// usually holds a whole /64. It returns ErrInvalid for an invalid IP.
func accessClientKey(ip netip.Addr) (string, error) {
	text, err := ipText(ip)
	if err != nil || ip.Unmap().Is4() {
		return text, err
	}
	p, _ := ip.WithZone("").Prefix(64) // cannot fail: 64 bits fit an IPv6 address
	return p.String(), nil
}

// checkValidity validates the token hash and the validity window of a new
// link or session.
func checkValidity(hash []byte, now, expiresAt time.Time) error {
	switch {
	case !validTokenHash(hash):
		return invalid("token hash must hold %d bytes", TokenHashSize)
	case !expiresAt.After(now):
		return invalid("must expire after its creation")
	}
	return nil
}

// CreateLinkTx creates, inside tx, a one-time access link of the tenant tx
// is bound to for the address email (normalized by the store), valid from
// now to expiresAt, whose "mta_" token hashes (SHA-256) to hash, and
// returns it. The caller only creates links for verified addresses. It
// returns ErrInvalid for a malformed address, a hash of the wrong size or
// an expiry not after now, and ErrConflict when the hash is already used.
// After an error, the caller must abort the transaction.
func (r *SenderAccess) CreateLinkTx(ctx context.Context, tx *ScopedTx, hash []byte, email string, now, expiresAt time.Time) (SenderAccessLink, error) {
	l, err := createLink(ctx, tx, hash, email, now, expiresAt)
	if err != nil {
		return SenderAccessLink{}, wrap("create access link", err)
	}
	return l, nil
}

// CreateLink is [SenderAccess.CreateLinkTx] for tenant tid in its own
// transaction.
func (r *SenderAccess) CreateLink(ctx context.Context, tid tenant.ID, hash []byte, email string, now, expiresAt time.Time) (SenderAccessLink, error) {
	var l SenderAccessLink
	err := writeScoped(ctx, r.db, tid, "create access link", func(tx *ScopedTx) error {
		var err error
		l, err = createLink(ctx, tx, hash, email, now, expiresAt)
		return err
	})
	return l, err
}

// createLink implements CreateLinkTx, returning raw errors.
func createLink(ctx context.Context, tx *ScopedTx, hash []byte, email string, now, expiresAt time.Time) (SenderAccessLink, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return SenderAccessLink{}, err
	}
	if err := checkValidity(hash, now, expiresAt); err != nil {
		return SenderAccessLink{}, err
	}
	l := SenderAccessLink{ID: id.New(id.SenderAccessLink), Email: email, CreatedAt: now, ExpiresAt: expiresAt}
	_, err = tx.Exec(ctx, qSenderLinkInsert, l.ID, hash, email, toMillis(now), toMillis(expiresAt))
	if err != nil {
		return SenderAccessLink{}, err
	}
	return l, nil
}

// ConsumeLinkTx consumes, inside tx, the access link of the tenant tx is
// bound to whose token hashes to hash, at now, and returns it with its
// address: a single conditional update, so that exactly one call consumes
// a link. It returns ErrNotFound, identically, when the link is unknown,
// expired, already consumed or belongs to another tenant, and ErrInvalid
// for a hash of the wrong size. The caller opens the session
// ([SenderAccess.CreateSessionTx]) in the same transaction. After an
// error, the caller must abort the transaction.
func (r *SenderAccess) ConsumeLinkTx(ctx context.Context, tx *ScopedTx, hash []byte, now time.Time) (SenderAccessLink, error) {
	l, err := consumeLink(ctx, tx, hash, now)
	if err != nil {
		return SenderAccessLink{}, wrap("consume access link", err)
	}
	return l, nil
}

// consumeLink implements ConsumeLinkTx, returning raw errors.
func consumeLink(ctx context.Context, tx *ScopedTx, hash []byte, now time.Time) (SenderAccessLink, error) {
	if !validTokenHash(hash) {
		return SenderAccessLink{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	ms := toMillis(now)
	var (
		l                         SenderAccessLink
		created, expires, consume int64
	)
	err := tx.QueryRow(ctx, qSenderLinkConsume, ms, hash, ms).Scan(&l.ID, &l.Email, &created, &expires, &consume)
	if err != nil {
		return SenderAccessLink{}, err
	}
	l.CreatedAt, l.ExpiresAt, l.ConsumedAt = fromMillis(created), fromMillis(expires), fromMillis(consume)
	return l, nil
}

// CreateSessionTx opens, inside tx, a "my transfers" session of the tenant
// tx is bound to for the address email (normalized by the store), valid
// from now to expiresAt, whose cookie token hashes (SHA-256) to hash, and
// returns it. It returns ErrInvalid for a malformed address, a hash of the
// wrong size or an expiry not after now, and ErrConflict when the hash is
// already used. After an error, the caller must abort the transaction.
func (r *SenderAccess) CreateSessionTx(ctx context.Context, tx *ScopedTx, hash []byte, email string, now, expiresAt time.Time) (SenderSession, error) {
	s, err := createSenderSession(ctx, tx, hash, email, now, expiresAt)
	if err != nil {
		return SenderSession{}, wrap("create sender session", err)
	}
	return s, nil
}

// createSenderSession implements CreateSessionTx, returning raw errors.
func createSenderSession(ctx context.Context, tx *ScopedTx, hash []byte, email string, now, expiresAt time.Time) (SenderSession, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return SenderSession{}, err
	}
	if err := checkValidity(hash, now, expiresAt); err != nil {
		return SenderSession{}, err
	}
	s := SenderSession{ID: id.New(id.SenderSession), Email: email, CreatedAt: now, ExpiresAt: expiresAt}
	if _, err := tx.Exec(ctx, qSenderSessionInsert, s.ID, hash, email, toMillis(now), toMillis(expiresAt)); err != nil {
		return SenderSession{}, err
	}
	return s, nil
}

// GetSession returns the session of tenant tid whose cookie token hashes
// to hash, provided it is neither ended nor expired at now. It returns
// ErrNotFound otherwise, including for a session of another tenant, and
// ErrInvalid for a hash of the wrong size.
func (r *SenderAccess) GetSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (SenderSession, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return SenderSession{}, err
	}
	if !validTokenHash(hash) {
		return SenderSession{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return readScoped(ctx, r.db, tid, "get sender session", func(tx *ScopedTx) (SenderSession, error) {
		var (
			s                SenderSession
			created, expires int64
		)
		err := tx.QueryRow(ctx, qSenderSessionGet, hash, toMillis(now)).Scan(&s.ID, &s.Email, &created, &expires)
		s.CreatedAt, s.ExpiresAt = fromMillis(created), fromMillis(expires)
		return s, err
	})
}

// EndSession ends the session of tenant tid whose cookie token hashes to
// hash, at now. It returns ErrNotFound when no such session is active at
// now (unknown, already ended, expired or of another tenant) and
// ErrInvalid for a hash of the wrong size.
func (r *SenderAccess) EndSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error {
	if _, err := r.db.Scoped(tid); err != nil {
		return err
	}
	if !validTokenHash(hash) {
		return invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return writeScoped(ctx, r.db, tid, "end sender session", func(tx *ScopedTx) error {
		ms := toMillis(now)
		res, err := tx.Exec(ctx, qSenderSessionEnd, ms, hash, ms)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
}

// DeleteByEmailTx deletes, inside tx, every access link and every session
// of the tenant tx is bound to of the address email (normalized), in every
// state, and returns how many it deleted, links and sessions together
// (GDPR erasure, data model 5.2): an open session ends at once, its cookie
// no longer resolving, and a pending link no longer opens one. It returns
// ErrInvalid for a malformed address. After an error, the caller must
// abort the transaction.
func (r *SenderAccess) DeleteByEmailTx(ctx context.Context, tx *ScopedTx, email string) (int64, error) {
	links, err := deleteByEmail(ctx, tx, "delete access links by address", qSenderLinkDeleteByEmail, email)
	if err != nil {
		return 0, err
	}
	sessions, err := deleteByEmail(ctx, tx, "delete sender sessions by address", qSenderSessionDeleteByEmail, email)
	if err != nil {
		return 0, err
	}
	return links + sessions, nil
}

// DeleteRequestsByMACTx deletes, inside tx, every access link request of
// the tenant tx is bound to counted for the address whose MAC
// (crypto.MACPurposeAccessRate) is mac, and returns how many it deleted
// (GDPR erasure, data model 5.2). The per-address rate limit of the
// address restarts from zero. It returns ErrInvalid for a MAC of the wrong
// size. After an error, the caller must abort the transaction.
func (r *SenderAccess) DeleteRequestsByMACTx(ctx context.Context, tx *ScopedTx, mac []byte) (int64, error) {
	if err := checkMAC(mac); err != nil {
		return 0, err
	}
	n, err := execCount(ctx, tx, qAccessRequestDeleteByMAC, mac)
	if err != nil {
		return 0, wrap("delete access link requests by address", err)
	}
	return n, nil
}

// Purge deletes, for tenant tid at now (data model 5.1), the access link
// requests created more than AccessRateWindow ago, the access links
// expired (and consumed, if they were) at or before now, and the sessions
// expired at or before now or ended at or before now -
// SenderSessionEndedRetention, in batches of PurgeBatchSize, and returns
// how many rows it deleted in all.
func (r *SenderAccess) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	ms := toMillis(now)
	created, ended := toMillis(now.Add(-AccessRateWindow)), toMillis(now.Add(-SenderSessionEndedRetention))
	purges := []struct {
		op   string
		list TenantQuery
		args []any
		del  TenantQuery
	}{
		{"purge access link requests", qAccessRequestPurgeList, []any{created}, qAccessRequestPurge},
		{"purge access links", qSenderLinkPurgeList, []any{ms, ms}, qSenderLinkPurge},
		{"purge sender sessions", qSenderSessionPurgeList, []any{ms, ended}, qSenderSessionPurge},
	}
	var total int64
	for _, p := range purges {
		n, err := r.db.purge(ctx, tid, p.op, false, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
			return deleteEach(ctx, tx, p.list, p.args, after, size, p.del,
				func(k string) []any { return append([]any{k}, p.args...) })
		})
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
