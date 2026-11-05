package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"net/netip"
	"regexp"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonSecurityEvents is the reason of the system queries of the security
// events: they are written in the system scope (most of them happen before
// or outside any tenant scope), listed instance-wide for the super admin
// and purged after 12 months.
const reasonSecurityEvents = "security log copy: batched writes of every tenant's and tenant-less events, instance-wide listing and purge"

// Limits of the security event fields (migration 0026).
const (
	// MaxSecurityEventTypeLen bounds the event type.
	MaxSecurityEventTypeLen = 64
	// MaxSecurityEventReasonLen bounds the reason.
	MaxSecurityEventReasonLen = 64
	// MaxSecurityEventDetailsBytes bounds the JSON details of an event.
	MaxSecurityEventDetailsBytes = 2048
	// MaxSecurityEventBatch bounds the number of events of one
	// [SecurityEvents.Save].
	MaxSecurityEventBatch = 1000
)

// securityTokenPattern is the form of a security event type and reason:
// the closed tokens of the security log (internal/securitylog).
var securityTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidSecurityEventType reports whether s has the form of a security event
// type (OpenAPI SecurityEventType: ^[a-z][a-z0-9_]*$, at most 64 bytes).
func ValidSecurityEventType(s string) bool {
	return len(s) <= MaxSecurityEventTypeLen && securityTokenPattern.MatchString(s)
}

// SecurityEvent is a security log line kept in the database (spec 16.3,
// V2): one row for one or several identical events coalesced in a window.
// It never holds an e-mail address nor free text: the type and the reason
// are closed tokens, the IP comes from a netip.Addr and the details only
// hold bounded token fields. The table is append-only for the
// administrators: only the writer of the copy updates the occurrences of
// its own rows, and only the cleanup task deletes.
type SecurityEvent struct {
	// ID is the identifier ("sev_" + ULID), assigned by the store.
	ID string
	// At is the time of the first occurrence; the store's clock is used
	// when it is zero.
	At time.Time
	// LastSeenAt is the time of the last occurrence (At when zero).
	LastSeenAt time.Time
	// TenantID is the tenant of the event, "" for an event bound to no
	// tenant (unknown FQDN, admin host, provisioning, monitoring).
	TenantID tenant.ID
	// Type is the security event type ("verification_code_invalid"...).
	Type string
	// Reason is the reason field of the line, "" when it has none.
	Reason string
	// IP is the real client IP, the zero Addr when unknown.
	IP netip.Addr
	// Details is an optional JSON object of at most
	// MaxSecurityEventDetailsBytes bytes (the scope, purpose and host
	// fields), never holding an "@".
	Details json.RawMessage
	// Occurrences is the number of coalesced events (1 when 0).
	Occurrences int
}

// securityEventColumns is the column list read by the queries, tenant_id
// excepted (a tenant query cannot read it).
const securityEventColumns = `id, at, event_type, reason, ip, details, occurrences, last_seen_at`

// Statements of the SecurityEvents repository. The list filters are
// optional: an empty type matches every row, since and until bound at in
// Unix milliseconds (decision 9: the first occurrence), and the keyset
// cursor is (at, id), newest first.
var (
	qSecurityEventInsert = systemQuery(
		`INSERT INTO security_events (id, at, tenant_id, event_type, reason, ip, details, occurrences, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonSecurityEvents)
	qSecurityEventUpdate = systemQuery(
		`UPDATE security_events SET occurrences = ?, last_seen_at = ? WHERE id = ?`,
		reasonSecurityEvents)
	qSecurityEventListAll = systemQuery(
		`SELECT tenant_id, `+securityEventColumns+` FROM security_events
		WHERE at >= ? AND at <= ? AND (? = '' OR event_type = ?) AND (at, id) < (?, ?)
		ORDER BY at DESC, id DESC LIMIT ?`,
		reasonSecurityEvents)
	// qSecurityEventListTenant never returns a row without tenant: the
	// tenant slot is an equality, which NULL never satisfies (T-283).
	qSecurityEventListTenant = tenantQuery(
		`SELECT ` + securityEventColumns + ` FROM security_events
		WHERE tenant_id = ? AND at >= ? AND at <= ? AND (? = '' OR event_type = ?)
		AND (at, id) < (?, ?) ORDER BY at DESC, id DESC LIMIT ?`)
	qSecurityEventPurge = systemQuery(
		`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events WHERE at < ? ORDER BY at, id LIMIT ?)`,
		reasonSecurityEvents)
)

// SecurityEvents is the repository of the security events kept in the
// database. Obtain it with [DB.SecurityEvents].
//
// The events are written in batches in the system scope
// ([SecurityEvents.Save]). A tenant's listing runs in that tenant's scope
// (row-level security on PostgreSQL: policy security_events_tenant_select)
// and never returns an event without tenant; the instance-wide listing is
// a system query, for the super admin only.
type SecurityEvents struct {
	db *DB
}

// SecurityEvents returns the security events repository.
func (db *DB) SecurityEvents() *SecurityEvents { return &SecurityEvents{db: db} }

// normalizeSecurityEvent validates ev and fills its times and occurrences.
func (r *SecurityEvents) normalizeSecurityEvent(ev *SecurityEvent) error {
	switch {
	case ev.TenantID != "" && ev.TenantID.Validate() != nil:
		return invalid("malformed tenant id")
	case !ValidSecurityEventType(ev.Type):
		return invalid("malformed security event type")
	case ev.Reason != "" && (len(ev.Reason) > MaxSecurityEventReasonLen || !securityTokenPattern.MatchString(ev.Reason)):
		return invalid("malformed security event reason")
	case len(ev.Details) > MaxSecurityEventDetailsBytes:
		return invalid("security event details exceed %d bytes", MaxSecurityEventDetailsBytes)
	case len(ev.Details) > 0 && (!json.Valid(ev.Details) || !bytes.HasPrefix(bytes.TrimSpace(ev.Details), []byte("{"))):
		return invalid("security event details must be a json object")
	case bytes.IndexByte(ev.Details, '@') >= 0 || bytes.Contains(bytes.ToLower(ev.Details), []byte(`@`)):
		// Never an e-mail address (T-285), not even escaped in JSON.
		return invalid("security event details must not hold an address")
	case ev.Occurrences < 0:
		return invalid("negative occurrences")
	}
	ev.At = fromMillis(toMillis(r.db.orNow(ev.At)))
	if ev.LastSeenAt.IsZero() {
		ev.LastSeenAt = ev.At
	}
	ev.LastSeenAt = fromMillis(toMillis(ev.LastSeenAt))
	if ev.LastSeenAt.Before(ev.At) {
		return invalid("last seen before the first occurrence")
	}
	if ev.Occurrences == 0 {
		ev.Occurrences = 1
	}
	if ev.IP.IsValid() {
		ev.IP = ev.IP.Unmap().WithZone("")
	}
	return nil
}

// Save writes batch in one system transaction and returns it with the
// identifiers and times the store filled. An event without ID is inserted
// (its ID is assigned); an event with an ID updates the occurrences and the
// last time of that row, which a purge may have deleted meanwhile (the
// update is then a no-op). Nothing is written when an event is malformed
// (ErrInvalid) or when the batch holds more than MaxSecurityEventBatch
// events.
func (r *SecurityEvents) Save(ctx context.Context, batch []SecurityEvent) ([]SecurityEvent, error) {
	if len(batch) > MaxSecurityEventBatch {
		return nil, invalid("more than %d security events in a batch", MaxSecurityEventBatch)
	}
	out := make([]SecurityEvent, len(batch))
	copy(out, batch)
	for i := range out {
		ev := &out[i]
		if ev.ID != "" && !id.Valid(id.SecurityEvent, ev.ID) {
			return nil, invalid("malformed security event id")
		}
		if err := r.normalizeSecurityEvent(ev); err != nil {
			return nil, err
		}
		if ev.ID == "" {
			newID, err := r.db.newAuditID(id.SecurityEvent)
			if err != nil {
				return nil, err
			}
			ev.ID = newID
		}
	}
	if len(out) == 0 {
		return out, nil
	}
	err := r.db.systemScope(reasonSecurityEvents).Tx(ctx, func(tx *SystemTx) error {
		for i := range out {
			ev := &out[i]
			if batch[i].ID != "" {
				if _, err := tx.Exec(ctx, qSecurityEventUpdate, ev.Occurrences, toMillis(ev.LastSeenAt), ev.ID); err != nil {
					return err
				}
				continue
			}
			var ip, details any
			if ev.IP.IsValid() {
				ip, _ = ipText(ev.IP)
			}
			if len(ev.Details) > 0 {
				details = string(ev.Details)
			}
			if _, err := tx.Exec(ctx, qSecurityEventInsert, ev.ID, toMillis(ev.At), nullText(string(ev.TenantID)),
				ev.Type, nullText(ev.Reason), ip, details, ev.Occurrences, toMillis(ev.LastSeenAt)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrap("save security events", err)
	}
	return out, nil
}

// SecurityEventFilter selects a page of security events, newest first.
type SecurityEventFilter struct {
	// TenantID restricts the listing to one tenant, through the tenant
	// scope (row-level security on PostgreSQL): the events without tenant
	// are then excluded. "" lists every event, of every tenant and without
	// tenant, in the system scope, for the super admin only: the caller
	// must set it for any other administrator.
	TenantID tenant.ID
	// Type keeps the events of this type only ("" for all).
	Type string
	// Since and Until bound the time of the first occurrence, both
	// inclusive (zero: no bound).
	Since time.Time
	Until time.Time
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// scanSecurityEvent reads one row of securityEventColumns, after the
// scanned prefix.
func scanSecurityEvent(sc interface{ Scan(...any) error }, prefix ...any) (SecurityEvent, error) {
	var (
		ev                 SecurityEvent
		at, last           int64
		reason, ip, detail sql.NullString
	)
	dest := append(append(make([]any, 0, len(prefix)+8), prefix...),
		&ev.ID, &at, &ev.Type, &reason, &ip, &detail, &ev.Occurrences, &last)
	if err := sc.Scan(dest...); err != nil {
		return SecurityEvent{}, err
	}
	ev.At, ev.LastSeenAt, ev.Reason, ev.IP = fromMillis(at), fromMillis(last), reason.String, parseIP(ip.String)
	if detail.Valid {
		ev.Details = json.RawMessage(detail.String)
	}
	return ev, nil
}

// List returns a page of security events matching f, newest first. With
// f.TenantID set, the query runs in that tenant's scope and binds the
// tenant itself; otherwise it runs in the system scope over the whole log.
// It returns ErrInvalid for a malformed tenant, type, cursor or bounds.
func (r *SecurityEvents) List(ctx context.Context, f SecurityEventFilter) (Page[SecurityEvent], error) {
	atCursor, idCursor, err := parseTimeCursor(f.Cursor, id.SecurityEvent)
	if err != nil {
		return Page[SecurityEvent]{}, err
	}
	if f.Type != "" && !ValidSecurityEventType(f.Type) {
		return Page[SecurityEvent]{}, invalid("malformed security event type")
	}
	since, until := int64(0), int64(math.MaxInt64)
	if !f.Since.IsZero() {
		since = toMillis(f.Since)
	}
	if !f.Until.IsZero() {
		until = toMillis(f.Until)
	}
	if since > until {
		return Page[SecurityEvent]{}, invalid("the period ends before it starts")
	}
	limit := pageLimit(f.Limit)
	args := []any{since, until, f.Type, f.Type, atCursor, idCursor, limit + 1}
	var items []SecurityEvent
	if f.TenantID != "" {
		s, err := r.db.Scoped(f.TenantID)
		if err != nil {
			return Page[SecurityEvent]{}, err
		}
		err = s.ReadTx(ctx, func(tx *ScopedTx) error {
			rows, err := tx.Query(ctx, qSecurityEventListTenant, args...)
			if err != nil {
				return err
			}
			items, err = collect(rows, func(rs *sql.Rows) (SecurityEvent, error) {
				ev, err := scanSecurityEvent(rs)
				ev.TenantID = f.TenantID
				return ev, err
			})
			return err
		})
		if err != nil {
			return Page[SecurityEvent]{}, wrap("list security events", err)
		}
	} else {
		err = r.db.systemScope(reasonSecurityEvents).ReadTx(ctx, func(tx *SystemTx) error {
			rows, err := tx.Query(ctx, qSecurityEventListAll, args...)
			if err != nil {
				return err
			}
			items, err = collect(rows, func(rs *sql.Rows) (SecurityEvent, error) {
				var tid sql.NullString
				ev, err := scanSecurityEvent(rs, &tid)
				ev.TenantID = tenant.ID(tid.String)
				return ev, err
			})
			return err
		})
		if err != nil {
			return Page[SecurityEvent]{}, wrap("list security events", err)
		}
	}
	return paginate(items, limit, func(ev SecurityEvent) string { return timeCursor(ev.At, ev.ID) }), nil
}

// Purge deletes the security events whose first occurrence happened
// strictly before before (now minus the 12-month retention, computed by
// the cleanup task), in batches of PurgeBatchSize, and returns how many it
// deleted.
func (r *SecurityEvents) Purge(ctx context.Context, before time.Time) (int64, error) {
	return r.db.purgeSystem(ctx, reasonSecurityEvents, "purge security events", "", qSecurityEventPurge, toMillis(before))
}
