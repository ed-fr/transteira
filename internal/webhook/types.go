// Package webhook delivers the alert events of the bus to the webhooks
// configured by the administrators (CLAUDE.md section 12.4): Microsoft
// Teams, Slack and a generic JSON receiver signed with HMAC-SHA256.
//
// The package owns the delivery: the outbound network guard (T-181, P30),
// the payload formats with their minimisation (T-182, P31), the signature
// (T-183), the bounded retries and the per-webhook circuit breaker (T-185).
// The configuration of the webhooks (storage, sealing of the URL and the
// secret, administration API) lives in internal/webhookadmin, which
// implements [Store] for the dispatcher.
package webhook

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/events"
)

// Kind is the format of a webhook (OpenAPI WebhookKind).
type Kind string

// Kinds.
const (
	// KindTeams posts a Microsoft Teams card.
	KindTeams Kind = "teams"
	// KindSlack posts a Slack message.
	KindSlack Kind = "slack"
	// KindGeneric posts the WebhookEvent JSON, signed with HMAC-SHA256.
	KindGeneric Kind = "generic"
)

// ErrorCategory is the coarse cause of a failed delivery (OpenAPI
// WebhookErrorCategory). It never reveals more than the category: no
// address, no error text of the receiver (T-181).
type ErrorCategory string

// Error categories.
const (
	// CategoryNone is the category of a successful delivery.
	CategoryNone ErrorCategory = ""
	// CategoryDNS: the host could not be resolved.
	CategoryDNS ErrorCategory = "dns"
	// CategoryRefusedNetwork: the host resolves to a denied network.
	CategoryRefusedNetwork ErrorCategory = "refused_network"
	// CategoryConnect: the connection failed.
	CategoryConnect ErrorCategory = "connect"
	// CategoryTLS: the TLS handshake or the certificate check failed.
	CategoryTLS ErrorCategory = "tls"
	// CategoryTimeout: the receiver did not answer in time.
	CategoryTimeout ErrorCategory = "timeout"
	// CategoryHTTPStatus: the receiver answered with a non-2xx status.
	CategoryHTTPStatus ErrorCategory = "http_status"
)

// Delivery rules (OpenAPI Webhook description).
const (
	// MaxAttempts is the number of attempts of a delivery.
	MaxAttempts = 5
	// RequestTimeout bounds one attempt.
	RequestTimeout = 10 * time.Second
	// BreakerThreshold is the number of consecutive failed deliveries that
	// opens the circuit breaker of a webhook.
	BreakerThreshold = 5
	// BreakerCooldown is how long an open circuit suspends the deliveries.
	BreakerCooldown = 15 * time.Minute
	// MaxPerOwner is the maximum number of webhooks of a tenant, and of the
	// instance for the system webhooks.
	MaxPerOwner = 20
)

// Errors of the URL validation.
var (
	// ErrURLInvalid: the URL is malformed, too long, carries user
	// information or uses a scheme other than https (or http when plain
	// http is allowed towards no network). It is decided on the syntax
	// alone, before any resolution.
	ErrURLInvalid = errors.New("webhook: invalid url")
	// ErrURLNotAllowed: the host does not resolve, resolves to a denied
	// network, or plain http is not allowed towards it (field code
	// url-not-allowed): one answer for the three, so that the validation
	// reveals nothing of the internal DNS.
	ErrURLNotAllowed = errors.New("webhook: url not allowed")
)

// Ref names a subscribed webhook for the routing of an event, with the
// breaker state that lets the routing skip it: it holds neither the URL
// nor the secret, which are unsealed by [Store.Target] right before each
// attempt only, so that an unsealed secret lives in memory for one attempt
// at most.
type Ref struct {
	// ID is the identifier of the webhook ("whk_" + ULID).
	ID string
	// TenantID is its tenant, "" for a system webhook.
	TenantID string
	// CircuitOpenUntil is the end of the suspension, zero when the circuit
	// is closed.
	CircuitOpenUntil time.Time
}

// Target is a webhook ready to be called: its URL and secret are already
// unsealed. A Target must never be logged, and is kept for one attempt
// only.
type Target struct {
	// ID is the identifier of the webhook ("whk_" + ULID).
	ID string
	// TenantID is its tenant, "" for a system webhook.
	TenantID string
	// TenantName is the display name of the tenant, "" for a system webhook.
	TenantName string
	// Kind is its format.
	Kind Kind
	// URL is the unsealed URL.
	URL string
	// Secret is the unsealed HMAC secret of a generic webhook, nil otherwise.
	Secret []byte
	// IncludeAddresses is the webhookIncludeAddresses setting of the tenant
	// (always false for a system webhook).
	IncludeAddresses bool
	// Events are the subscribed event types.
	Events []events.Type
	// Version identifies the configuration the target was read from (the
	// time of the last change by an admin): a delivery is recorded only
	// while the webhook keeps this version.
	Version time.Time
	// ConsecutiveFailures is the number of failed deliveries in a row.
	ConsecutiveFailures int
	// CircuitOpenUntil is the end of the suspension, zero when the circuit
	// is closed.
	CircuitOpenUntil time.Time
}

// Subscribed reports whether t subscribes to the event type et.
func (t Target) Subscribed(et events.Type) bool { return slices.Contains(t.Events, et) }

// Result is the outcome of one attempt (or of a test).
type Result struct {
	// Success is true when the receiver answered 2xx in time.
	Success bool
	// HTTPStatus is the status answered, 0 when there was none.
	HTTPStatus int
	// Duration is the duration of the attempt.
	Duration time.Duration
	// Category is the cause of a failure, [CategoryNone] on success.
	Category ErrorCategory
}

// Delivery is the state recorded after a delivery (all its attempts): the
// result of the last attempt and the new breaker state.
type Delivery struct {
	// Version is the Version of the target the breaker state was computed
	// from: the delivery is not recorded once the webhook has changed
	// since (re-enabled, re-addressed...), so that the change wins.
	Version time.Time
	// At is when the last attempt ended.
	At time.Time
	// Result is the result of the last attempt.
	Result Result
	// ConsecutiveFailures is the new number of failed deliveries in a row
	// (0 after a success).
	ConsecutiveFailures int
	// CircuitOpenUntil is the new end of the suspension, zero when closed.
	CircuitOpenUntil time.Time
}

// Store gives the dispatcher the webhooks to call and records their
// deliveries. internal/webhookadmin implements it; every call for a tenant
// runs under that tenant's scoped executor (T-179).
type Store interface {
	// Subscribers returns the references of the enabled webhooks of
	// tenantID ("" for the system webhooks) subscribed to t. It unseals
	// nothing.
	Subscribers(ctx context.Context, tenantID string, t events.Type) ([]Ref, error)
	// Target re-reads the webhook id of tenantID ("" for a system webhook),
	// unsealed, before an attempt. ok is false when the webhook is gone or
	// disabled, or the tenant is missing or being deleted.
	Target(ctx context.Context, tenantID, id string) (t Target, ok bool, err error)
	// RecordDelivery records the state of a delivery to the webhook id of
	// tenantID ("" for a system webhook) while the webhook keeps the
	// version d.Version. A webhook deleted or changed in the meantime is
	// not an error: nothing is recorded.
	RecordDelivery(ctx context.Context, tenantID, id string, d Delivery) error
}
