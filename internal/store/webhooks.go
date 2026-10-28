package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// WebhookKind is the format of a webhook (OpenAPI WebhookKind).
type WebhookKind string

// Webhook kinds.
const (
	// WebhookTeams posts a Microsoft Teams card.
	WebhookTeams WebhookKind = "teams"
	// WebhookSlack posts a Slack message.
	WebhookSlack WebhookKind = "slack"
	// WebhookGeneric posts a signed JSON document; it is the only kind with
	// a signing secret.
	WebhookGeneric WebhookKind = "generic"
)

// Limits of a webhook record (migration 0018).
const (
	// MaxWebhooks is the maximum number of webhooks of a tenant, and of
	// the instance-wide webhooks.
	MaxWebhooks = 20
	// MaxWebhookNameLen bounds the name of a webhook, in characters.
	MaxWebhookNameLen = 100
	// MaxWebhookURLHintLen bounds the displayed scheme and host of the
	// URL, in characters.
	MaxWebhookURLHintLen = 300
	// maxWebhookCreatedByLen bounds the admin username recorded as the
	// creator.
	maxWebhookCreatedByLen = 64
	// maxWebhookErrorLen bounds the error category of the last delivery.
	maxWebhookErrorLen = 300
)

// Values of the last_status column.
const (
	webhookStatusSuccess = "success"
	webhookStatusFailure = "failure"
)

// reasonSystemWebhooks is the reason of the instance-wide webhook queries.
const reasonSystemWebhooks = "instance-wide webhooks, which belong to no tenant"

// systemWebhooksLock is the name of the lock serializing the creations of
// instance-wide webhooks on PostgreSQL, so that two concurrent creations
// cannot both pass the MaxWebhooks count. It cannot collide with a tenant
// ID ("ten_" + ULID).
const systemWebhooksLock tenant.ID = "system_webhooks"

// webhookColumns is the column list read by the tenant webhook queries;
// systemWebhookColumns is the same list for the instance-wide webhooks,
// whose sealed URL and secret are system secrets.
const (
	webhookColumns = `id, name, kind, url_key_id, url_hint, secret_key_id, events, enabled, created_at, created_by, ` +
		`updated_at, last_delivery_at, last_status, last_http_status, last_duration_ms, last_error, ` +
		`consecutive_failures, circuit_open_until`
	systemWebhookColumns = `id, name, kind, url_secret_id, url_hint, hmac_secret_id, events, enabled, created_at, ` +
		`created_by, updated_at, last_delivery_at, last_status, last_http_status, last_duration_ms, last_error, ` +
		`consecutive_failures, circuit_open_until`
)

// Statements of the Webhooks repository.
var (
	qWebhookInsert = tenantQuery(
		`INSERT INTO webhooks (tenant_id, id, name, kind, url_key_id, url_hint, secret_key_id, events, enabled,
		created_at, created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qWebhookCount = tenantQuery(
		`SELECT count(*) FROM webhooks WHERE tenant_id = ?`)
	qWebhookExists = tenantQuery(
		`SELECT count(*) FROM webhooks WHERE tenant_id = ? AND id = ?`)
	qWebhookGet = tenantQuery(
		`SELECT ` + webhookColumns + ` FROM webhooks WHERE tenant_id = ? AND id = ?`)
	qWebhookList = tenantQuery(
		`SELECT ` + webhookColumns + ` FROM webhooks WHERE tenant_id = ? ORDER BY created_at, id`)
	// qWebhookUpdate only changes the version of the webhook it was
	// computed from (its updated_at): a concurrent change wins.
	qWebhookUpdate = tenantQuery(
		`UPDATE webhooks SET name = ?, url_key_id = ?, url_hint = ?, secret_key_id = ?, events = ?, enabled = ?,
		updated_at = ? WHERE tenant_id = ? AND id = ? AND updated_at = ?`)
	qWebhookCloseBreaker = tenantQuery(
		`UPDATE webhooks SET consecutive_failures = 0, circuit_open_until = NULL WHERE tenant_id = ? AND id = ?`)
	// qWebhookRecord only records a delivery computed from the current
	// version of the webhook (its updated_at), which it leaves unchanged.
	qWebhookRecord = tenantQuery(
		`UPDATE webhooks SET last_delivery_at = ?, last_status = ?, last_http_status = ?, last_duration_ms = ?,
		last_error = ?, consecutive_failures = ?, circuit_open_until = ? WHERE tenant_id = ? AND id = ? AND updated_at = ?`)
	// qWebhookDelete only deletes a webhook whose sealed URL and secret are
	// destroyed already (D23).
	qWebhookDelete = tenantQuery(
		`DELETE FROM webhooks WHERE tenant_id = ? AND id = ? AND url_key_id IS NULL AND secret_key_id IS NULL`)
)

// Statements of the SystemWebhooks repository.
var (
	qSystemWebhookInsert = systemQuery(
		`INSERT INTO system_webhooks (id, name, kind, url_secret_id, url_hint, hmac_secret_id, events, enabled,
		created_at, created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, reasonSystemWebhooks)
	qSystemWebhookCount = systemQuery(
		`SELECT count(*) FROM system_webhooks`, reasonSystemWebhooks)
	qSystemWebhookExists = systemQuery(
		`SELECT count(*) FROM system_webhooks WHERE id = ?`, reasonSystemWebhooks)
	qSystemWebhookGet = systemQuery(
		`SELECT `+systemWebhookColumns+` FROM system_webhooks WHERE id = ?`, reasonSystemWebhooks)
	qSystemWebhookList = systemQuery(
		`SELECT `+systemWebhookColumns+` FROM system_webhooks ORDER BY created_at, id`, reasonSystemWebhooks)
	// qSystemWebhookUpdate only changes the version of the webhook it was
	// computed from (its updated_at): a concurrent change wins.
	qSystemWebhookUpdate = systemQuery(
		`UPDATE system_webhooks SET name = ?, url_secret_id = ?, url_hint = ?, hmac_secret_id = ?, events = ?,
		enabled = ?, updated_at = ? WHERE id = ? AND updated_at = ?`, reasonSystemWebhooks)
	qSystemWebhookCloseBreaker = systemQuery(
		`UPDATE system_webhooks SET consecutive_failures = 0, circuit_open_until = NULL WHERE id = ?`,
		reasonSystemWebhooks)
	qSystemWebhookRecord = systemQuery(
		`UPDATE system_webhooks SET last_delivery_at = ?, last_status = ?, last_http_status = ?, last_duration_ms = ?,
		last_error = ?, consecutive_failures = ?, circuit_open_until = ? WHERE id = ? AND updated_at = ?`,
		reasonSystemWebhooks)
	qSystemWebhookDelete = systemQuery(
		`DELETE FROM system_webhooks WHERE id = ? AND url_secret_id IS NULL AND hmac_secret_id IS NULL`,
		reasonSystemWebhooks)
)

// Webhook is an alert webhook of a tenant or of the instance (spec 12.4).
// Its URL and signing secret are never held here: URLKeyID and SecretKeyID
// reference them sealed by the master key vault (wrapped keys of purpose
// KeyPurposeSecret for a tenant webhook, system secrets of purpose
// SecretPurposeWebhook for an instance-wide one).
type Webhook struct {
	// ID is the identifier ("whk_" + ULID), assigned by the caller.
	ID string
	// Name is the label chosen by the admin (1 to MaxWebhookNameLen
	// characters on one line).
	Name string
	// Kind is the format of the deliveries.
	Kind WebhookKind
	// URLKeyID references the sealed URL. It is required at creation and
	// reads "" once the key is destroyed.
	URLKeyID string
	// URLHint is the scheme and host of the URL, for display (1 to
	// MaxWebhookURLHintLen characters on one line).
	URLHint string
	// SecretKeyID references the sealed signing secret: required for the
	// generic kind at creation, "" for the other kinds.
	SecretKeyID string
	// Events are the subscribed event types: at least one, distinct, all
	// tenant types ([events.IsTenant]) for a tenant webhook and all system
	// types ([events.IsSystem]) for an instance-wide one.
	Events []events.Type
	// Enabled tells whether the webhook receives deliveries.
	Enabled bool
	// CreatedBy is the username of the admin who created the webhook.
	CreatedBy string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// UpdatedAt is the time of the last change by an admin. It is also the
	// version of the webhook: every change moves it forward (by one
	// millisecond at least), and a delivery is recorded only against the
	// version it was computed from ([WebhookDeliveryState.Version]).
	UpdatedAt time.Time
	// LastDelivery is the outcome of the last delivery attempt; its At is
	// zero when there was none.
	LastDelivery WebhookDelivery
	// ConsecutiveFailures is the number of failed deliveries in a row.
	ConsecutiveFailures int
	// CircuitOpenUntil is the end of the suspension by the circuit
	// breaker, zero when it is closed.
	CircuitOpenUntil time.Time
}

// HasSecret reports whether the webhook has a signing secret.
func (w Webhook) HasSecret() bool { return w.SecretKeyID != "" }

// Subscribed reports whether the webhook is enabled and subscribed to t.
func (w Webhook) Subscribed(t events.Type) bool { return w.Enabled && slices.Contains(w.Events, t) }

// WebhookDelivery is the outcome of a delivery attempt.
type WebhookDelivery struct {
	// At is when the attempt ended.
	At time.Time
	// Success is true when the receiver answered 2xx in time.
	Success bool
	// HTTPStatus is the status answered (100 to 599), 0 when none.
	HTTPStatus int
	// Duration is the duration of the attempt, stored in milliseconds.
	Duration time.Duration
	// ErrorCategory is the coarse cause of a failure ("" on success): at
	// most 300 characters on one line, never an address nor a URL.
	ErrorCategory string
}

// WebhookDeliveryState is the state recorded after a delivery: its last
// attempt and the new circuit breaker state.
type WebhookDeliveryState struct {
	// Version is the UpdatedAt of the webhook the state was computed from
	// (required): once an admin has changed the webhook (for example
	// re-enabled it, closing its circuit), the state is not recorded.
	Version time.Time
	// Last is the last attempt.
	Last WebhookDelivery
	// ConsecutiveFailures is the new number of failed deliveries in a row.
	ConsecutiveFailures int
	// CircuitOpenUntil is the new end of the suspension, zero when closed.
	CircuitOpenUntil time.Time
}

// WebhookChange is a change of a webhook: the zero value of a field keeps
// its current value.
type WebhookChange struct {
	// Name is the new name, "" to keep it.
	Name string
	// URLKeyID references a new sealed URL, "" to keep it; URLHint is then
	// required. The replaced key is left to the caller to destroy.
	URLKeyID string
	// URLHint is the hint of the new URL.
	URLHint string
	// SecretKeyID references a new signing secret (generic kind only), ""
	// to keep it. The replaced key is left to the caller to destroy.
	SecretKeyID string
	// Events replace the subscribed events, nil to keep them.
	Events []events.Type
	// Enabled enables or disables the webhook, nil to keep it. Setting it
	// to true also closes the circuit breaker.
	Enabled *bool
	// UpdatedAt is the time of the change; the store's clock is used when
	// it is zero.
	UpdatedAt time.Time
	// Version, when not zero, is the version (UpdatedAt) of the webhook the
	// change was computed from: it applies only while the webhook keeps
	// it, so that a change computed from a stale read (keys destroyed
	// since) is refused with ErrConflict. When zero, the change applies to
	// the version read by the update itself.
	Version time.Time
}

// Webhooks is the tenant-scoped repository of webhooks. Obtain it with
// [DB.Webhooks].
type Webhooks struct {
	db *DB
}

// Webhooks returns the tenant webhook repository.
func (db *DB) Webhooks() *Webhooks { return &Webhooks{db: db} }

// SystemWebhooks is the repository of the instance-wide webhooks. Its
// operations are system-scoped. Obtain it with [DB.SystemWebhooks].
type SystemWebhooks struct {
	db *DB
}

// SystemWebhooks returns the instance-wide webhook repository.
func (db *DB) SystemWebhooks() *SystemWebhooks { return &SystemWebhooks{db: db} }

// webhookEventsDoc validates a list of subscribed events, each of which
// must satisfy allowed, and returns its JSON text.
func webhookEventsDoc(list []events.Type, allowed func(events.Type) bool) (string, error) {
	if len(list) == 0 {
		return "", invalid("a webhook needs at least one event")
	}
	seen := make(map[events.Type]bool, len(list))
	for _, t := range list {
		if !allowed(t) {
			return "", invalid("event type not allowed for this webhook")
		}
		if seen[t] {
			return "", invalid("duplicate event type")
		}
		seen[t] = true
	}
	doc, _ := json.Marshal(list) // a []events.Type always marshals
	return string(doc), nil
}

// validWebhookName reports whether s is an acceptable webhook name.
func validWebhookName(s string) bool { return s != "" && validText(s, MaxWebhookNameLen, true) }

// validWebhookHint reports whether s is an acceptable URL hint.
func validWebhookHint(s string) bool { return s != "" && validText(s, MaxWebhookURLHintLen, true) }

// normalizeWebhook validates a new webhook w whose keys have prefix
// keyPrefix and events satisfy allowed, and returns it with its timestamps
// set, together with its events as JSON text.
func (db *DB) normalizeWebhook(w Webhook, keyPrefix id.Prefix, allowed func(events.Type) bool) (Webhook, string, error) {
	switch {
	case !id.Valid(id.Webhook, w.ID):
		return Webhook{}, "", invalid("malformed webhook id")
	case !validWebhookName(w.Name):
		return Webhook{}, "", invalid("name must be 1 to %d characters on one line", MaxWebhookNameLen)
	case w.Kind != WebhookTeams && w.Kind != WebhookSlack && w.Kind != WebhookGeneric:
		return Webhook{}, "", invalid("unknown webhook kind")
	case !id.Valid(keyPrefix, w.URLKeyID):
		return Webhook{}, "", invalid("malformed url key id")
	case !validWebhookHint(w.URLHint):
		return Webhook{}, "", invalid("url hint must be 1 to %d characters on one line", MaxWebhookURLHintLen)
	case (w.Kind == WebhookGeneric) != (w.SecretKeyID != ""):
		return Webhook{}, "", invalid("a generic webhook, and only it, has a signing secret")
	case w.SecretKeyID != "" && !id.Valid(keyPrefix, w.SecretKeyID):
		return Webhook{}, "", invalid("malformed secret key id")
	case w.CreatedBy == "" || !validText(w.CreatedBy, maxWebhookCreatedByLen, true):
		return Webhook{}, "", invalid("creator must be 1 to %d characters on one line", maxWebhookCreatedByLen)
	case !w.LastDelivery.At.IsZero() || w.ConsecutiveFailures != 0 || !w.CircuitOpenUntil.IsZero():
		return Webhook{}, "", invalid("a new webhook has no delivery")
	}
	doc, err := webhookEventsDoc(w.Events, allowed)
	if err != nil {
		return Webhook{}, "", err
	}
	w.CreatedAt = fromMillis(toMillis(db.orNow(w.CreatedAt)))
	w.UpdatedAt = w.CreatedAt
	return w, doc, nil
}

// applyWebhookChange validates c against the current webhook cur (keys
// with prefix keyPrefix, events satisfying allowed) and returns the
// changed webhook with its events as JSON text, and whether the circuit
// breaker must be closed.
func (db *DB) applyWebhookChange(cur Webhook, c WebhookChange, keyPrefix id.Prefix, allowed func(events.Type) bool) (Webhook, string, bool, error) {
	switch {
	case c.Name != "" && !validWebhookName(c.Name):
		return Webhook{}, "", false, invalid("name must be 1 to %d characters on one line", MaxWebhookNameLen)
	case c.URLKeyID != "" && !id.Valid(keyPrefix, c.URLKeyID):
		return Webhook{}, "", false, invalid("malformed url key id")
	case c.URLKeyID != "" && !validWebhookHint(c.URLHint):
		return Webhook{}, "", false, invalid("url hint must be 1 to %d characters on one line", MaxWebhookURLHintLen)
	case c.SecretKeyID != "" && cur.Kind != WebhookGeneric:
		return Webhook{}, "", false, invalid("only a generic webhook has a signing secret")
	case c.SecretKeyID != "" && !id.Valid(keyPrefix, c.SecretKeyID):
		return Webhook{}, "", false, invalid("malformed secret key id")
	}
	if c.Name != "" {
		cur.Name = c.Name
	}
	if c.URLKeyID != "" {
		cur.URLKeyID, cur.URLHint = c.URLKeyID, c.URLHint
	}
	if c.SecretKeyID != "" {
		cur.SecretKeyID = c.SecretKeyID
	}
	if c.Events != nil {
		cur.Events = c.Events
	}
	doc, err := webhookEventsDoc(cur.Events, allowed)
	if err != nil {
		return Webhook{}, "", false, err
	}
	closeBreaker := c.Enabled != nil && *c.Enabled
	if c.Enabled != nil {
		cur.Enabled = *c.Enabled
	}
	if closeBreaker {
		cur.ConsecutiveFailures, cur.CircuitOpenUntil = 0, time.Time{}
	}
	// The version always moves forward, even with a clock that stands still
	// or goes back, so that a delivery in flight cannot overwrite the
	// change.
	at := toMillis(db.orNow(c.UpdatedAt))
	if prev := toMillis(cur.UpdatedAt); at <= prev {
		at = prev + 1
	}
	cur.UpdatedAt = fromMillis(at)
	return cur, doc, closeBreaker, nil
}

// expectedVersion returns the version, in milliseconds, that the update of
// cur by c requires: c.Version when set, the version read otherwise. On
// PostgreSQL, the row is read without a lock at READ COMMITTED: the
// version guard of the update statement is what keeps two concurrent
// changes from both applying.
func expectedVersion(cur Webhook, c WebhookChange) int64 {
	if !c.Version.IsZero() {
		return toMillis(c.Version)
	}
	return toMillis(cur.UpdatedAt)
}

// expectVersion maps an update that changed no row, because the webhook
// changed or was deleted since it was read, to ErrConflict.
func expectVersion(res sql.Result) error {
	err := expectOne(res)
	if errors.Is(err, ErrNotFound) {
		err = ErrConflict
	}
	return err
}

// deliveryArgs validates s and returns the arguments of the record
// statements before the row identification, and the version.
func deliveryArgs(s WebhookDeliveryState) ([]any, int64, error) {
	d := s.Last
	switch {
	case s.Version.IsZero():
		return nil, 0, invalid("a delivery needs the version of the webhook")
	case d.At.IsZero():
		return nil, 0, invalid("a delivery needs a time")
	case d.HTTPStatus != 0 && (d.HTTPStatus < 100 || d.HTTPStatus > 599):
		return nil, 0, invalid("http status must be between 100 and 599")
	case d.Duration < 0 || s.ConsecutiveFailures < 0:
		return nil, 0, invalid("duration and failure count cannot be negative")
	case !validText(d.ErrorCategory, maxWebhookErrorLen, true):
		return nil, 0, invalid("error category must be text of at most %d characters", maxWebhookErrorLen)
	}
	status := webhookStatusFailure
	if d.Success {
		status = webhookStatusSuccess
	}
	var httpStatus any
	if d.HTTPStatus != 0 {
		httpStatus = d.HTTPStatus
	}
	return []any{
		toMillis(d.At), status, httpStatus, d.Duration.Milliseconds(), nullText(d.ErrorCategory),
		s.ConsecutiveFailures, nullTime(s.CircuitOpenUntil),
	}, toMillis(s.Version), nil
}

// scanWebhook reads one row of webhookColumns or systemWebhookColumns.
func scanWebhook(row interface{ Scan(...any) error }) (Webhook, error) {
	var (
		w                                  Webhook
		kind, doc                          string
		urlKey, secretKey, status, lastErr sql.NullString
		created, updated                   int64
		lastAt, httpStatus, durMs, circuit sql.NullInt64
	)
	err := row.Scan(&w.ID, &w.Name, &kind, &urlKey, &w.URLHint, &secretKey, &doc, &w.Enabled, &created,
		&w.CreatedBy, &updated, &lastAt, &status, &httpStatus, &durMs, &lastErr, &w.ConsecutiveFailures, &circuit)
	if err != nil {
		return Webhook{}, err
	}
	if err := json.Unmarshal([]byte(doc), &w.Events); err != nil {
		return Webhook{}, err
	}
	w.Kind, w.URLKeyID, w.SecretKeyID = WebhookKind(kind), urlKey.String, secretKey.String
	w.CreatedAt, w.UpdatedAt, w.CircuitOpenUntil = fromMillis(created), fromMillis(updated), nullMillis(circuit)
	w.LastDelivery = WebhookDelivery{
		At: nullMillis(lastAt), Success: status.String == webhookStatusSuccess, HTTPStatus: int(httpStatus.Int64),
		Duration: time.Duration(durMs.Int64) * time.Millisecond, ErrorCategory: lastErr.String,
	}
	return w, nil
}

// subscribed returns the webhooks of list subscribed to t.
func subscribed(list []Webhook, t events.Type) []Webhook {
	out := make([]Webhook, 0, len(list))
	for _, w := range list {
		if w.Subscribed(t) {
			out = append(out, w)
		}
	}
	return out
}

// checkWebhookKey verifies, inside tx, that wkID is a secret of the tenant
// tx is bound to: the foreign key only proves that the key exists.
func checkWebhookKey(ctx context.Context, tx *ScopedTx, wkID string) error {
	if wkID == "" {
		return nil
	}
	k, err := scanWrappedKey(tx.QueryRow(ctx, qWrappedKeyGet, wkID))
	if err != nil {
		return err
	}
	if k.Purpose != KeyPurposeSecret {
		return invalid("webhook key is not a secret")
	}
	return nil
}

// CreateTx stores the new webhook w for the tenant tx is bound to, inside
// tx (which also seals its URL and secret), and returns it as stored. It
// returns ErrInvalid for a malformed field or an event type that is not a
// tenant type, ErrLimitReached when the tenant has MaxWebhooks webhooks
// already, ErrNotFound when the tenant does not exist or a key is not a
// wrapped key of this tenant, and ErrConflict when the identifier or a
// key is already used. After an error, the caller must abort tx.
func (r *Webhooks) CreateTx(ctx context.Context, tx *ScopedTx, w Webhook) (Webhook, error) {
	w, doc, err := r.db.normalizeWebhook(w, id.WrappedKey, events.IsTenant)
	if err != nil {
		return Webhook{}, err
	}
	if err := r.create(ctx, tx, w, doc); err != nil {
		return Webhook{}, wrap("create webhook", err)
	}
	return w, nil
}

// create checks the limit and the keys, then inserts w, returning raw
// errors.
func (r *Webhooks) create(ctx context.Context, tx *ScopedTx, w Webhook, doc string) error {
	if err := tx.lock(ctx); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, qWebhookCount).Scan(&n); err != nil {
		return err
	}
	if n >= MaxWebhooks {
		return ErrLimitReached
	}
	for _, k := range []string{w.URLKeyID, w.SecretKeyID} {
		if err := checkWebhookKey(ctx, tx, k); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, qWebhookInsert, w.ID, w.Name, string(w.Kind), w.URLKeyID, w.URLHint,
		nullText(w.SecretKeyID), doc, w.Enabled, toMillis(w.CreatedAt), w.CreatedBy, toMillis(w.UpdatedAt))
	return err
}

// Get returns the webhook whkID of tenant tid, or ErrNotFound when it does
// not exist or belongs to another tenant.
func (r *Webhooks) Get(ctx context.Context, tid tenant.ID, whkID string) (Webhook, error) {
	return readScoped(ctx, r.db, tid, "get webhook", func(tx *ScopedTx) (Webhook, error) {
		return scanWebhook(tx.QueryRow(ctx, qWebhookGet, whkID))
	})
}

// GetTx is Get inside tx, for the tenant tx is bound to.
func (r *Webhooks) GetTx(ctx context.Context, tx *ScopedTx, whkID string) (Webhook, error) {
	w, err := scanWebhook(tx.QueryRow(ctx, qWebhookGet, whkID))
	if err != nil {
		return Webhook{}, wrap("get webhook", err)
	}
	return w, nil
}

// List returns every webhook of tenant tid, oldest first.
func (r *Webhooks) List(ctx context.Context, tid tenant.ID) ([]Webhook, error) {
	return readScoped(ctx, r.db, tid, "list webhooks", func(tx *ScopedTx) ([]Webhook, error) {
		rows, err := tx.Query(ctx, qWebhookList)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (Webhook, error) { return scanWebhook(r) })
	})
}

// ListSubscribed returns the enabled webhooks of tenant tid subscribed to
// t, oldest first. It reads under the tenant scope only (threat model
// T-179): a webhook of another tenant is never returned.
func (r *Webhooks) ListSubscribed(ctx context.Context, tid tenant.ID, t events.Type) ([]Webhook, error) {
	list, err := r.List(ctx, tid)
	if err != nil {
		return nil, err
	}
	return subscribed(list, t), nil
}

// UpdateTx applies c to the webhook whkID of the tenant tx is bound to,
// inside tx, and returns it as changed. The keys it replaces are left to
// the caller to destroy in the same transaction (D23). It returns
// ErrInvalid for a malformed field, an event type that is not a tenant
// type or a secret for a kind other than generic, ErrNotFound when the
// webhook does not exist (or belongs to another tenant) or a new key is
// not a wrapped key of this tenant, and ErrConflict when a new key is
// already used or the webhook is no longer at the version the change was
// computed from (c.Version, or the version read, changed concurrently).
// After an error, the caller must abort tx.
func (r *Webhooks) UpdateTx(ctx context.Context, tx *ScopedTx, whkID string, c WebhookChange) (Webhook, error) {
	w, err := r.update(ctx, tx, whkID, c)
	if err != nil {
		return Webhook{}, wrap("update webhook", err)
	}
	return w, nil
}

// update implements UpdateTx, returning raw errors.
func (r *Webhooks) update(ctx context.Context, tx *ScopedTx, whkID string, c WebhookChange) (Webhook, error) {
	cur, err := scanWebhook(tx.QueryRow(ctx, qWebhookGet, whkID))
	if err != nil {
		return Webhook{}, err
	}
	w, doc, closeBreaker, err := r.db.applyWebhookChange(cur, c, id.WrappedKey, events.IsTenant)
	if err != nil {
		return Webhook{}, err
	}
	for _, k := range []string{c.URLKeyID, c.SecretKeyID} {
		if err := checkWebhookKey(ctx, tx, k); err != nil {
			return Webhook{}, err
		}
	}
	res, err := tx.Exec(ctx, qWebhookUpdate, w.Name, nullText(w.URLKeyID), w.URLHint, nullText(w.SecretKeyID), doc,
		w.Enabled, toMillis(w.UpdatedAt), whkID, expectedVersion(cur, c))
	if err != nil {
		return Webhook{}, err
	}
	if err := expectVersion(res); err != nil {
		return Webhook{}, err
	}
	if closeBreaker {
		if _, err := tx.Exec(ctx, qWebhookCloseBreaker, whkID); err != nil {
			return Webhook{}, err
		}
	}
	return w, nil
}

// DeleteTx deletes the webhook whkID of the tenant tx is bound to, inside
// tx. Its sealed URL and secret must be destroyed first, in the same
// transaction (D23): while one of them exists, nothing is deleted and
// ErrKeysRemain is returned. It returns ErrNotFound when the webhook does
// not exist or belongs to another tenant.
func (r *Webhooks) DeleteTx(ctx context.Context, tx *ScopedTx, whkID string) error {
	if err := deleteWebhook(ctx, tx, whkID); err != nil {
		return wrap("delete webhook", err)
	}
	return nil
}

// deleteWebhook implements DeleteTx, returning raw errors.
func deleteWebhook(ctx context.Context, tx *ScopedTx, whkID string) error {
	res, err := tx.Exec(ctx, qWebhookDelete, whkID)
	if err != nil {
		return err
	}
	if err := expectOne(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	return probe(ctx, tx, qWebhookExists, whkID, ErrKeysRemain)
}

// RecordDelivery records s as the delivery state of the webhook whkID of
// tenant tid, provided the webhook is still at version s.Version; it never
// changes that version. A webhook deleted or changed in the meantime (or
// of another tenant) changes nothing and is not an error. It returns
// ErrInvalid for a malformed state.
func (r *Webhooks) RecordDelivery(ctx context.Context, tid tenant.ID, whkID string, s WebhookDeliveryState) error {
	args, version, err := deliveryArgs(s)
	if err != nil {
		return err
	}
	return writeScoped(ctx, r.db, tid, "record webhook delivery", func(tx *ScopedTx) error {
		_, err := tx.Exec(ctx, qWebhookRecord, append(args, whkID, version)...)
		return err
	})
}

// checkSystemWebhookKey verifies, inside tx, that ssID is a system secret
// of purpose SecretPurposeWebhook.
func checkSystemWebhookKey(ctx context.Context, tx *SystemTx, ssID string) error {
	if ssID == "" {
		return nil
	}
	s, err := scanSystemSecret(tx.QueryRow(ctx, qSystemSecretGet, ssID))
	if err != nil {
		return err
	}
	if s.Purpose != SecretPurposeWebhook {
		return invalid("webhook key is not a webhook secret")
	}
	return nil
}

// CreateTx stores the new instance-wide webhook w inside tx (which also
// stores its sealed URL and secret, system secrets of purpose
// SecretPurposeWebhook) and returns it as stored. It returns ErrInvalid for
// a malformed field, an event type that is not a system type or a key that
// is not a webhook secret, ErrLimitReached when the instance has
// MaxWebhooks instance-wide webhooks already, ErrNotFound when a key does
// not exist and ErrConflict when the identifier or a key is already used.
// After an error, the caller must abort tx.
func (r *SystemWebhooks) CreateTx(ctx context.Context, tx *SystemTx, w Webhook) (Webhook, error) {
	w, doc, err := r.db.normalizeWebhook(w, id.SystemSecret, events.IsSystem)
	if err != nil {
		return Webhook{}, err
	}
	if err := r.create(ctx, tx, w, doc); err != nil {
		return Webhook{}, wrap("create system webhook", err)
	}
	return w, nil
}

// create checks the limit and the keys, then inserts w, returning raw
// errors.
func (r *SystemWebhooks) create(ctx context.Context, tx *SystemTx, w Webhook, doc string) error {
	if err := tx.lockTenant(ctx, systemWebhooksLock); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, qSystemWebhookCount).Scan(&n); err != nil {
		return err
	}
	if n >= MaxWebhooks {
		return ErrLimitReached
	}
	for _, k := range []string{w.URLKeyID, w.SecretKeyID} {
		if err := checkSystemWebhookKey(ctx, tx, k); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, qSystemWebhookInsert, w.ID, w.Name, string(w.Kind), w.URLKeyID, w.URLHint,
		nullText(w.SecretKeyID), doc, w.Enabled, toMillis(w.CreatedAt), w.CreatedBy, toMillis(w.UpdatedAt))
	return err
}

// Get returns the instance-wide webhook whkID, or ErrNotFound.
func (r *SystemWebhooks) Get(ctx context.Context, whkID string) (Webhook, error) {
	var w Webhook
	err := r.db.systemScope(reasonSystemWebhooks).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		w, err = scanWebhook(tx.QueryRow(ctx, qSystemWebhookGet, whkID))
		return err
	})
	if err != nil {
		return Webhook{}, wrap("get system webhook", err)
	}
	return w, nil
}

// GetTx is Get inside tx.
func (r *SystemWebhooks) GetTx(ctx context.Context, tx *SystemTx, whkID string) (Webhook, error) {
	w, err := scanWebhook(tx.QueryRow(ctx, qSystemWebhookGet, whkID))
	if err != nil {
		return Webhook{}, wrap("get system webhook", err)
	}
	return w, nil
}

// List returns every instance-wide webhook, oldest first.
func (r *SystemWebhooks) List(ctx context.Context) ([]Webhook, error) {
	var list []Webhook
	err := r.db.systemScope(reasonSystemWebhooks).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qSystemWebhookList)
		if err != nil {
			return err
		}
		list, err = collect(rows, func(r *sql.Rows) (Webhook, error) { return scanWebhook(r) })
		return err
	})
	if err != nil {
		return nil, wrap("list system webhooks", err)
	}
	return list, nil
}

// ListSubscribed returns the enabled instance-wide webhooks subscribed to
// t, oldest first.
func (r *SystemWebhooks) ListSubscribed(ctx context.Context, t events.Type) ([]Webhook, error) {
	list, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	return subscribed(list, t), nil
}

// UpdateTx applies c to the instance-wide webhook whkID inside tx and
// returns it as changed. The secrets it replaces are left to the caller to
// destroy in the same transaction ([SystemSecrets.DeleteTx], D23). It
// returns ErrInvalid for a malformed field, an event type that is not a
// system type, a secret for a kind other than generic or a new key that is
// not a webhook secret, ErrNotFound when the webhook or a new key does not
// exist, and ErrConflict when a new key is already used or the webhook is
// no longer at the version the change was computed from (c.Version, or
// the version read, changed concurrently). After an error, the caller must
// abort tx.
func (r *SystemWebhooks) UpdateTx(ctx context.Context, tx *SystemTx, whkID string, c WebhookChange) (Webhook, error) {
	w, err := r.update(ctx, tx, whkID, c)
	if err != nil {
		return Webhook{}, wrap("update system webhook", err)
	}
	return w, nil
}

// update implements UpdateTx, returning raw errors.
func (r *SystemWebhooks) update(ctx context.Context, tx *SystemTx, whkID string, c WebhookChange) (Webhook, error) {
	cur, err := scanWebhook(tx.QueryRow(ctx, qSystemWebhookGet, whkID))
	if err != nil {
		return Webhook{}, err
	}
	w, doc, closeBreaker, err := r.db.applyWebhookChange(cur, c, id.SystemSecret, events.IsSystem)
	if err != nil {
		return Webhook{}, err
	}
	for _, k := range []string{c.URLKeyID, c.SecretKeyID} {
		if err := checkSystemWebhookKey(ctx, tx, k); err != nil {
			return Webhook{}, err
		}
	}
	res, err := tx.Exec(ctx, qSystemWebhookUpdate, w.Name, nullText(w.URLKeyID), w.URLHint, nullText(w.SecretKeyID),
		doc, w.Enabled, toMillis(w.UpdatedAt), whkID, expectedVersion(cur, c))
	if err != nil {
		return Webhook{}, err
	}
	if err := expectVersion(res); err != nil {
		return Webhook{}, err
	}
	if closeBreaker {
		if _, err := tx.Exec(ctx, qSystemWebhookCloseBreaker, whkID); err != nil {
			return Webhook{}, err
		}
	}
	return w, nil
}

// DeleteTx deletes the instance-wide webhook whkID inside tx. Its sealed
// URL and secret must be destroyed first, in the same transaction
// ([SystemSecrets.DeleteTx], D23): while one of them exists, nothing is
// deleted and ErrKeysRemain is returned. It returns ErrNotFound when the
// webhook does not exist.
func (r *SystemWebhooks) DeleteTx(ctx context.Context, tx *SystemTx, whkID string) error {
	if err := deleteSystemWebhook(ctx, tx, whkID); err != nil {
		return wrap("delete system webhook", err)
	}
	return nil
}

// deleteSystemWebhook implements DeleteTx, returning raw errors.
func deleteSystemWebhook(ctx context.Context, tx *SystemTx, whkID string) error {
	res, err := tx.Exec(ctx, qSystemWebhookDelete, whkID)
	if err != nil {
		return err
	}
	if err := expectOne(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, qSystemWebhookExists, whkID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return ErrKeysRemain
}

// RecordDelivery records s as the delivery state of the instance-wide
// webhook whkID, provided the webhook is still at version s.Version; it
// never changes that version. A webhook deleted or changed in the meantime
// changes nothing and is not an error. It returns ErrInvalid for a
// malformed state.
func (r *SystemWebhooks) RecordDelivery(ctx context.Context, whkID string, s WebhookDeliveryState) error {
	args, version, err := deliveryArgs(s)
	if err != nil {
		return err
	}
	err = r.db.systemScope(reasonSystemWebhooks).Tx(ctx, func(tx *SystemTx) error {
		_, err := tx.Exec(ctx, qSystemWebhookRecord, append(args, whkID, version)...)
		return err
	})
	if err != nil {
		return wrap("record system webhook delivery", err)
	}
	return nil
}
