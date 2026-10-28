package webhookadmin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
	"github.com/ed-fr/transteira/internal/webhook"
)

// Limits of the tests (OpenAPI testTenantWebhook).
const (
	// TestLimit is the number of tests allowed per administrator and
	// tenant (per administrator for the instance-wide webhooks) in
	// TestWindow.
	TestLimit = 10
	// TestWindow is the period of TestLimit.
	TestWindow = time.Hour
)

// Limits of the URL changes (OpenAPI createTenantWebhook and
// updateTenantWebhook): every URL checked resolves its host, so the checks
// are limited, keeping the validation from serving as an oracle on the
// internal DNS (T-181).
const (
	// URLChangeLimit is the number of creations and URL changes allowed
	// per administrator and tenant (per administrator for the
	// instance-wide webhooks) in URLChangeWindow.
	URLChangeLimit = 30
	// URLChangeWindow is the period of URLChangeLimit.
	URLChangeWindow = time.Hour
)

// SecretBytes is the size of the random part of a signing secret, written
// as 2*SecretBytes lowercase hexadecimal characters.
const SecretBytes = 32

// URLValidator checks the URL of a webhook against the network guard
// (*webhook.Client).
type URLValidator interface {
	// ValidateURL returns the hint of raw (its scheme and host), or an
	// error matching webhook.ErrURLInvalid or webhook.ErrURLNotAllowed.
	ValidateURL(ctx context.Context, raw string) (hint string, err error)
}

// Tester sends the test event of a webhook (*webhook.Client).
type Tester interface {
	// SendTest delivers a webhook.test event to t once, synchronously.
	SendTest(ctx context.Context, t webhook.Target, now time.Time) webhook.Result
}

// Compile-time checks that the webhook client fits.
var (
	_ URLValidator = (*webhook.Client)(nil)
	_ Tester       = (*webhook.Client)(nil)
)

// Options configures a [Service].
type Options struct {
	// Validator checks the URLs (required).
	Validator URLValidator
	// Tester sends the test events (required).
	Tester Tester
	// Audit is the shared audit writer of the application; nil means a
	// writer of its own over the database, publishing nothing.
	Audit *audit.Writer
	// Logger receives the audit and scrub failures; nil means
	// slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// CreateInput is the input of a creation (OpenAPI WebhookCreate).
type CreateInput struct {
	Name   string
	Kind   store.WebhookKind
	URL    string
	Events []events.Type
	// Enabled is nil for the default, true.
	Enabled *bool
}

// UpdateInput is a merge patch of a webhook (OpenAPI WebhookUpdate): a nil
// field is left unchanged.
type UpdateInput struct {
	Name *string
	URL  *string
	// Events replace the subscribed events, nil to keep them; a non-nil
	// empty list is refused.
	Events  []events.Type
	Enabled *bool
	// RotateSecret replaces the signing secret (generic kind only).
	RotateSecret bool
}

// Result is a webhook after a creation or an update, with its signing
// secret when one was generated (OpenAPI WebhookWithSecret).
type Result struct {
	Webhook store.Webhook
	// Secret is the new signing secret (64 lowercase hexadecimal
	// characters, the HMAC key as is), "" when none was generated.
	Secret string
}

// Service manages the webhooks and implements [webhook.Store]. It is safe
// for concurrent use.
type Service struct {
	validator URLValidator
	tester    Tester
	vault     Vault
	logger    *slog.Logger
	now       func() time.Time
	tests     *ratelimit.Window
	urls      *ratelimit.Window

	// getTenant reads a tenant.
	getTenant func(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	// tenantOwner returns the owner of the webhooks of a tenant.
	tenantOwner func(tid tenant.ID) owner
	// systemOwner is the owner of the instance-wide webhooks.
	systemOwner owner
}

// Compile-time check that the service is the store of the dispatcher.
var _ webhook.Store = (*Service)(nil)

// Errors of [New].
var (
	errMissingDB  = errors.New("webhookadmin: a database is required")
	errMissingDep = errors.New("webhookadmin: a vault, an url validator and a tester are required")
)

// New returns the service over db, sealing with vault (a
// *masterkey.Vault).
func New(db *store.DB, vault Vault, opts Options) (*Service, error) {
	if db == nil {
		return nil, errMissingDB
	}
	if vault == nil || opts.Validator == nil || opts.Tester == nil {
		return nil, errMissingDep
	}
	writer := audit.OrNew(opts.Audit, db)
	s := &Service{
		validator: opts.Validator, tester: opts.Tester, vault: vault, logger: opts.Logger, now: opts.Now,
		getTenant: db.Tenants().Get,
		tenantOwner: func(tid tenant.ID) owner {
			return &tenantOwner{db: db, vault: vault, writer: writer, tid: tid}
		},
		systemOwner: &systemOwner{db: db, vault: vault, writer: writer, reason: reasonSystemWebhooks},
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.tests = ratelimit.NewWindow(TestLimit, TestWindow, ratelimit.WithClock(s.now))
	s.urls = ratelimit.NewWindow(URLChangeLimit, URLChangeWindow, ratelimit.WithClock(s.now))
	return s, nil
}

// activeTenant returns tenant tid when it exists and is active; a missing
// tenant, and a tenant being deleted, are ErrNotFound.
func (s *Service) activeTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	t, err := s.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("webhookadmin: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return nil, ErrNotFound
	}
	return t, nil
}

// readable checks that p may read tenant tid, which must be active.
func (s *Service) readable(ctx context.Context, p adminauth.Principal, tid tenant.ID) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	if err := adminauth.RequireTenantAccess(p.Admin, tid); err != nil {
		return err
	}
	_, err := s.activeTenant(ctx, tid)
	return err
}

// writable checks that p may change tenant tid, which must be active, and
// returns it.
func (s *Service) writable(ctx context.Context, p adminauth.Principal, tid tenant.ID) (*tenant.Tenant, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, err
	}
	if err := adminauth.RequireTenantWrite(p.Admin, tid); err != nil {
		return nil, err
	}
	return s.activeTenant(ctx, tid)
}

// superAdmin checks that p is an authenticated super admin.
func superAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// newSecret returns a new signing secret: SecretBytes from crypto/rand
// (whose Read never fails) as lowercase hexadecimal text.
func newSecret() []byte {
	b := make([]byte, SecretBytes)
	_, _ = rand.Read(b)
	return []byte(hex.EncodeToString(b))
}

// validName reports whether name is 1 to store.MaxWebhookNameLen
// characters of valid UTF-8 on one line, without control or bidi
// characters.
func validName(name string) bool {
	return name != "" && utf8.ValidString(name) && utf8.RuneCountInString(name) <= store.MaxWebhookNameLen &&
		!strings.ContainsFunc(name, func(r rune) bool {
			return textsafe.IsControl(r) || textsafe.IsBidiControl(r) || textsafe.IsLineSeparator(r)
		})
}

// checkEvents validates a list of subscribed events: at least one,
// distinct, each allowed.
func checkEvents(list []events.Type, allowed func(events.Type) bool) error {
	if len(list) == 0 {
		return invalid(FieldEvents, CodeRequired)
	}
	seen := make(map[events.Type]bool, len(list))
	for i, t := range list {
		if !allowed(t) || seen[t] {
			return invalid(fmt.Sprintf("%s/%d", FieldEvents, i), CodeInvalidFormat)
		}
		seen[t] = true
	}
	return nil
}

// checkURL validates raw with the network guard and returns its hint,
// once the URL rate limit of key allows it (*RateLimitError). A host that
// does not resolve answers like a denied one (CodeURLNotAllowed).
func (s *Service) checkURL(ctx context.Context, raw, key string) (string, error) {
	if ok, retry := s.urls.Allow(key); !ok {
		return "", &RateLimitError{RetryAfter: max(retry, time.Second)}
	}
	hint, err := s.validator.ValidateURL(ctx, raw)
	switch {
	case errors.Is(err, webhook.ErrURLNotAllowed):
		return "", invalid(FieldURL, CodeURLNotAllowed)
	case err != nil, hint == "", utf8.RuneCountInString(hint) > store.MaxWebhookURLHintLen:
		return "", invalid(FieldURL, CodeInvalidFormat)
	}
	return hint, nil
}

// hostOf returns the host of a URL hint ("https://host" -> "host").
func hostOf(hint string) string {
	if i := strings.Index(hint, "://"); i >= 0 {
		return hint[i+len("://"):]
	}
	return hint
}

// eventNames returns list as strings, for the audit.
func eventNames(list []events.Type) []string {
	out := make([]string, len(list))
	for i, t := range list {
		out[i] = string(t)
	}
	return out
}

// record writes the audit event of action on webhook whkID of o by p. The
// change is committed already: a failure is logged, never returned, and a
// canceled request does not prevent the write.
func (s *Service) record(ctx context.Context, p adminauth.Principal, ip netip.Addr, o owner, action audit.Action,
	whkID string, details map[string]any,
) {
	ev := audit.Event{
		ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: audit.ObjectWebhook, ObjectID: whkID, Details: details,
	}
	if err := o.audit(context.WithoutCancel(ctx), ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", string(o.tenant())), slog.String("error", err.Error()))
	}
}

// scrub purges the destroyed keys from the database files; a failure is
// logged, never returned: the keys are destroyed already.
func (s *Service) scrub(ctx context.Context) {
	if err := s.vault.Scrub(context.WithoutCancel(ctx)); err != nil {
		s.logger.WarnContext(ctx, "webhook key scrub failed", slog.String("error", err.Error()))
	}
}
