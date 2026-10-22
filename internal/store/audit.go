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

// reasonAudit is the reason of the audit system queries.
const reasonAudit = "audit log: global events, and instance-wide listing and purge"

// reasonAuditPseudonymise is the reason of the GDPR pseudonymisation of
// the audit log.
const reasonAuditPseudonymise = "GDPR erasure: replace one data subject's address in the actor column of one tenant's events"

// AuditActorKind is the kind of actor of an audit event (OpenAPI
// AuditEvent.actor.kind, an extensible enumeration).
type AuditActorKind string

// Audit actor kinds.
const (
	// ActorAdmin is an administrator (Actor: its username).
	ActorAdmin AuditActorKind = "admin"
	// ActorDepositor is a depositor (Actor: its mail address).
	ActorDepositor AuditActorKind = "depositor"
	// ActorRecipient is a recipient (Actor: its mail address).
	ActorRecipient AuditActorKind = "recipient"
	// ActorAPIToken is an API token (Actor: its record ID).
	ActorAPIToken AuditActorKind = "api_token"
	// ActorSystem is TransTeira itself (cleanup task, local command...).
	ActorSystem AuditActorKind = "system"
)

// valid reports whether k is a known actor kind.
func (k AuditActorKind) valid() bool {
	switch k {
	case ActorAdmin, ActorDepositor, ActorRecipient, ActorAPIToken, ActorSystem:
		return true
	}
	return false
}

// Limits of the audit event fields.
const (
	// MaxAuditDetailsBytes bounds the JSON details of an event.
	MaxAuditDetailsBytes = 4096
	// MaxAuditActorLen bounds the actor, in characters (a mail address).
	MaxAuditActorLen = 320
	// MaxAuditObjectIDLen bounds the object identifier, in characters.
	MaxAuditObjectIDLen = 320
)

// Syntax of the audit actions ("admin.login") and object kinds ("admin").
var (
	auditActionPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`)
	auditObjectKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// maxAuditActionLen bounds an action.
const maxAuditActionLen = 64

// AuditEvent is an entry of the audit log (spec 21.1). The log is
// append-only: the store offers no update.
type AuditEvent struct {
	// ID is the identifier ("aud_" + ULID), assigned by the store.
	ID string
	// At is when the event happened; the store's clock is used when it is
	// zero.
	At time.Time
	// TenantID is the tenant of the event, "" for a global event (setup,
	// administrator management, maintenance, key rotation).
	TenantID tenant.ID
	// ActorKind and Actor identify who acted.
	ActorKind AuditActorKind
	Actor     string
	// IP is the client IP (the zero Addr when not applicable).
	IP netip.Addr
	// Action is the action ("admin.login", "transfer.deleted"...).
	Action string
	// ObjectKind and ObjectID identify the object of the action.
	ObjectKind string
	ObjectID   string
	// Details is an optional JSON object of at most MaxAuditDetailsBytes
	// bytes. It must never hold a secret.
	Details json.RawMessage
}

// auditColumns is the column list read by the audit queries, tenant_id
// excepted (a tenant query cannot read it).
const auditColumns = `id, at, actor_kind, actor, ip, action, object_kind, object_id, details`

// Statements of the AuditEvents repository. The list filters are optional:
// an empty action or actor matches every row, since and until are bounds
// in Unix milliseconds, and the keyset cursor is (at, id), newest first.
var (
	qAuditInsert = systemQuery(
		`INSERT INTO audit_events (id, at, tenant_id, actor_kind, actor, ip, action, object_kind, object_id, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonAudit)
	qAuditInsertTenant = tenantQuery(
		`INSERT INTO audit_events (id, at, tenant_id, actor_kind, actor, ip, action, object_kind, object_id, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qAuditListAll = systemQuery(
		`SELECT tenant_id, `+auditColumns+` FROM audit_events
		WHERE at >= ? AND at <= ? AND (? = '' OR action = ?) AND (? = '' OR actor = ?) AND (at, id) < (?, ?)
		ORDER BY at DESC, id DESC LIMIT ?`,
		reasonAudit)
	qAuditListTenant = tenantQuery(
		`SELECT ` + auditColumns + ` FROM audit_events
		WHERE tenant_id = ? AND at >= ? AND at <= ? AND (? = '' OR action = ?) AND (? = '' OR actor = ?)
		AND (at, id) < (?, ?) ORDER BY at DESC, id DESC LIMIT ?`)
	// qAuditCountActor counts the events of a data subject (GDPR search):
	// the actor column only holds an address for these kinds.
	qAuditCountActor = tenantQuery(
		`SELECT count(*) FROM audit_events WHERE tenant_id = ? AND actor = ? AND actor_kind IN ('depositor', 'recipient')`)
	// qAuditPseudonymise is the only update of the audit log: the system
	// scope alone may run it, the tenant scope staying append-only.
	qAuditPseudonymise = systemQuery(
		`UPDATE audit_events SET actor = ?
		WHERE tenant_id = ? AND actor = ? AND actor_kind IN ('depositor', 'recipient')`,
		reasonAuditPseudonymise)
	qAuditPurge = systemQuery(
		`DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE at < ? ORDER BY at, id LIMIT ?)`,
		reasonAudit)
)

// AuditEvents is the repository of the audit log. Obtain it with
// [DB.AuditEvents].
//
// Global events are appended in the system scope ([AuditEvents.Append],
// [AuditEvents.AppendTx]); tenant events may also be appended inside a
// tenant-scoped transaction ([AuditEvents.AppendScopedTx]), atomically
// with the action they record. On PostgreSQL, a tenant-scoped transaction
// only sees and writes its own tenant's events (row-level security).
type AuditEvents struct {
	db *DB
}

// AuditEvents returns the audit log repository.
func (db *DB) AuditEvents() *AuditEvents { return &AuditEvents{db: db} }

// normalizeAudit validates ev, fills its ID and time, and returns the
// arguments of the insert (tenant_id included, at index 2).
func (r *AuditEvents) normalizeAudit(ev *AuditEvent) ([]any, error) {
	switch {
	case ev.TenantID != "" && ev.TenantID.Validate() != nil:
		return nil, invalid("malformed tenant id")
	case !ev.ActorKind.valid():
		return nil, invalid("unknown audit actor kind")
	case ev.Actor == "" || !validText(ev.Actor, MaxAuditActorLen, true):
		return nil, invalid("audit actor must be a single line of 1 to %d characters", MaxAuditActorLen)
	case len(ev.Action) > maxAuditActionLen || !auditActionPattern.MatchString(ev.Action):
		return nil, invalid("malformed audit action")
	case !auditObjectKindPattern.MatchString(ev.ObjectKind):
		return nil, invalid("malformed audit object kind")
	case ev.ObjectID == "" || !validText(ev.ObjectID, MaxAuditObjectIDLen, true):
		return nil, invalid("audit object id must be a single line of 1 to %d characters", MaxAuditObjectIDLen)
	case len(ev.Details) > MaxAuditDetailsBytes:
		return nil, invalid("audit details exceed %d bytes", MaxAuditDetailsBytes)
	case len(ev.Details) > 0 && (!json.Valid(ev.Details) || !bytes.HasPrefix(bytes.TrimSpace(ev.Details), []byte("{"))):
		return nil, invalid("audit details must be a json object")
	}
	newID, err := r.db.newID(id.Audit)
	if err != nil {
		return nil, err
	}
	ev.ID = newID
	ev.At = fromMillis(toMillis(r.db.orNow(ev.At)))
	var ip, details any
	if ev.IP.IsValid() {
		ip, _ = ipText(ev.IP)
		ev.IP = ev.IP.Unmap().WithZone("")
	}
	if len(ev.Details) > 0 {
		details = string(ev.Details)
	}
	return []any{
		ev.ID, toMillis(ev.At), nullText(string(ev.TenantID)), string(ev.ActorKind), ev.Actor, ip,
		ev.Action, ev.ObjectKind, ev.ObjectID, details,
	}, nil
}

// Append records ev in its own system transaction and returns the stored
// event (see [AuditEvents.AppendTx]).
func (r *AuditEvents) Append(ctx context.Context, ev AuditEvent) (AuditEvent, error) {
	var out AuditEvent
	err := r.db.systemScope(reasonAudit).Tx(ctx, func(tx *SystemTx) error {
		var err error
		out, err = r.appendSystem(ctx, tx, ev)
		return err
	})
	if err != nil {
		return AuditEvent{}, wrap("append audit event", err)
	}
	return out, nil
}

// AppendTx records ev inside the system transaction tx (for example with
// the administrator operation it records) and returns the stored event,
// whose ID and time the store fills. ev.TenantID may be "" (global event)
// or any tenant. It returns ErrInvalid for a malformed field.
func (r *AuditEvents) AppendTx(ctx context.Context, tx *SystemTx, ev AuditEvent) (AuditEvent, error) {
	out, err := r.appendSystem(ctx, tx, ev)
	if err != nil {
		return AuditEvent{}, wrap("append audit event", err)
	}
	return out, nil
}

// appendSystem implements AppendTx, returning raw errors.
func (r *AuditEvents) appendSystem(ctx context.Context, tx *SystemTx, ev AuditEvent) (AuditEvent, error) {
	args, err := r.normalizeAudit(&ev)
	if err != nil {
		return AuditEvent{}, err
	}
	if _, err := tx.Exec(ctx, qAuditInsert, args...); err != nil {
		return AuditEvent{}, err
	}
	return ev, nil
}

// AppendScopedTx records ev for the tenant tx is bound to, inside tx, and
// returns the stored event. ev.TenantID must be "" (it is then set to the
// tenant of tx) or that tenant; another tenant yields ErrInvalid.
func (r *AuditEvents) AppendScopedTx(ctx context.Context, tx *ScopedTx, ev AuditEvent) (AuditEvent, error) {
	out, err := r.appendScoped(ctx, tx, ev)
	if err != nil {
		return AuditEvent{}, wrap("append audit event", err)
	}
	return out, nil
}

// appendScoped implements AppendScopedTx, returning raw errors.
func (r *AuditEvents) appendScoped(ctx context.Context, tx *ScopedTx, ev AuditEvent) (AuditEvent, error) {
	if ev.TenantID != "" && ev.TenantID != tx.Tenant() {
		return AuditEvent{}, invalid("audit event of another tenant")
	}
	ev.TenantID = tx.Tenant()
	args, err := r.normalizeAudit(&ev)
	if err != nil {
		return AuditEvent{}, err
	}
	// The executor binds the tenant itself, at index 2.
	args = append(args[:2], args[3:]...)
	if _, err := tx.Exec(ctx, qAuditInsertTenant, args...); err != nil {
		return AuditEvent{}, err
	}
	return ev, nil
}

// AppendScoped records ev for tenant tid in its own tenant-scoped
// transaction and returns the stored event (see
// [AuditEvents.AppendScopedTx]): the events a tenant operation records
// after its own transaction committed. It returns ErrInvalid for a
// malformed tenant or field, or an event of another tenant.
func (r *AuditEvents) AppendScoped(ctx context.Context, tid tenant.ID, ev AuditEvent) (AuditEvent, error) {
	var out AuditEvent
	err := writeScoped(ctx, r.db, tid, "append audit event", func(tx *ScopedTx) error {
		var err error
		out, err = r.appendScoped(ctx, tx, ev)
		return err
	})
	if err != nil {
		return AuditEvent{}, err
	}
	return out, nil
}

// CountActor returns the number of audit events of tenant tid whose actor
// is the address email (normalized), as a depositor or a recipient (GDPR
// search). It returns ErrInvalid for a malformed tenant or address.
func (r *AuditEvents) CountActor(ctx context.Context, tid tenant.ID, email string) (int, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return 0, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	return readScoped(ctx, r.db, tid, "count audit events by actor", func(tx *ScopedTx) (int, error) {
		var n int
		err := tx.QueryRow(ctx, qAuditCountActor, email).Scan(&n)
		return n, err
	})
}

// PseudonymiseActor replaces the address email (normalized) by pseudonym
// in the actor column of the events of tenant tid where it acted as a
// depositor or a recipient, and returns how many events it changed (GDPR
// erasure). Nothing else changes: the other columns, the other tenants'
// events and the events of other actor kinds stay as they are. It is the
// only update of the audit log, a system query (reason "GDPR erasure:
// replace one data subject's address in the actor column of one tenant's
// events"): the tenant scope stays append-only. It returns ErrInvalid for
// a malformed tenant or address, or a pseudonym [IsPseudonym] rejects.
func (r *AuditEvents) PseudonymiseActor(ctx context.Context, tid tenant.ID, email, pseudonym string) (int64, error) {
	if err := tid.Validate(); err != nil {
		return 0, invalid("malformed tenant id")
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	if !IsPseudonym(pseudonym) {
		return 0, invalid("malformed pseudonym")
	}
	var n int64
	err = r.db.systemScope(reasonAuditPseudonymise).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qAuditPseudonymise, pseudonym, string(tid), email)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, wrap("pseudonymise audit actor", err)
	}
	return n, nil
}

// AuditFilter selects a page of audit events, newest first.
type AuditFilter struct {
	// TenantID restricts the listing to one tenant, through the tenant
	// scope (row-level security on PostgreSQL): the global events (without
	// tenant) are then excluded. "" lists every event, global and of every
	// tenant, in the system scope, for the super admin only: the caller
	// must set it for any other administrator.
	TenantID tenant.ID
	// Action keeps the events of this action only ("" for all).
	Action string
	// Actor keeps the events of this actor only ("" for all).
	Actor string
	// Since and Until bound the event time, both inclusive (zero: no
	// bound).
	Since time.Time
	Until time.Time
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// auditCursor returns the cursor of the page after ev.
func auditCursor(ev AuditEvent) string {
	return timeCursor(ev.At, ev.ID)
}

// parseAuditCursor reads a cursor; "" starts from the newest event.
func parseAuditCursor(c string) (int64, string, error) {
	return parseTimeCursor(c, id.Audit)
}

// scanAudit reads one row of auditColumns, after the scanned prefix.
func scanAudit(sc interface{ Scan(...any) error }, prefix ...any) (AuditEvent, error) {
	var (
		ev         AuditEvent
		at         int64
		kind       string
		ip, detail sql.NullString
	)
	dest := append(append(make([]any, 0, len(prefix)+9), prefix...),
		&ev.ID, &at, &kind, &ev.Actor, &ip, &ev.Action, &ev.ObjectKind, &ev.ObjectID, &detail)
	if err := sc.Scan(dest...); err != nil {
		return AuditEvent{}, err
	}
	ev.At, ev.ActorKind, ev.IP = fromMillis(at), AuditActorKind(kind), parseIP(ip.String)
	if detail.Valid {
		ev.Details = json.RawMessage(detail.String)
	}
	return ev, nil
}

// List returns a page of audit events matching f, newest first. With
// f.TenantID set, the query runs in that tenant's scope and binds the
// tenant itself; otherwise it runs in the system scope over the whole log.
// It returns ErrInvalid for a malformed tenant, cursor or bounds.
func (r *AuditEvents) List(ctx context.Context, f AuditFilter) (Page[AuditEvent], error) {
	atCursor, idCursor, err := parseAuditCursor(f.Cursor)
	if err != nil {
		return Page[AuditEvent]{}, err
	}
	since, until := int64(0), int64(math.MaxInt64)
	if !f.Since.IsZero() {
		since = toMillis(f.Since)
	}
	if !f.Until.IsZero() {
		until = toMillis(f.Until)
	}
	if since > until {
		return Page[AuditEvent]{}, invalid("the period ends before it starts")
	}
	limit := pageLimit(f.Limit)
	args := []any{since, until, f.Action, f.Action, f.Actor, f.Actor, atCursor, idCursor, limit + 1}
	var items []AuditEvent
	if f.TenantID != "" {
		s, err := r.db.Scoped(f.TenantID)
		if err != nil {
			return Page[AuditEvent]{}, err
		}
		err = s.ReadTx(ctx, func(tx *ScopedTx) error {
			rows, err := tx.Query(ctx, qAuditListTenant, args...)
			if err != nil {
				return err
			}
			items, err = collect(rows, func(rs *sql.Rows) (AuditEvent, error) {
				ev, err := scanAudit(rs)
				ev.TenantID = f.TenantID
				return ev, err
			})
			return err
		})
		if err != nil {
			return Page[AuditEvent]{}, wrap("list audit events", err)
		}
	} else {
		err = r.db.systemScope(reasonAudit).ReadTx(ctx, func(tx *SystemTx) error {
			rows, err := tx.Query(ctx, qAuditListAll, args...)
			if err != nil {
				return err
			}
			items, err = collect(rows, func(rs *sql.Rows) (AuditEvent, error) {
				var tid sql.NullString
				ev, err := scanAudit(rs, &tid)
				ev.TenantID = tenant.ID(tid.String)
				return ev, err
			})
			return err
		})
		if err != nil {
			return Page[AuditEvent]{}, wrap("list audit events", err)
		}
	}
	return paginate(items, limit, auditCursor), nil
}

// Purge deletes the audit events that happened strictly before before
// (now minus the 12-month retention of spec 20, computed by the cleanup
// task), in batches of PurgeBatchSize, and returns how many it deleted.
func (r *AuditEvents) Purge(ctx context.Context, before time.Time) (int64, error) {
	return r.db.purgeSystem(ctx, reasonAudit, "purge audit events", "", qAuditPurge, toMillis(before))
}
