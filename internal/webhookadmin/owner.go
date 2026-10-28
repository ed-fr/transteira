package webhookadmin

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Vault seals, opens and destroys the URLs and secrets of the webhooks
// (*masterkey.Vault).
type Vault interface {
	// SealTx wraps plaintext for purpose p inside tx, for the tenant tx is
	// bound to, and returns its wrapped key ID.
	SealTx(ctx context.Context, tx *store.ScopedTx, p crypto.Purpose, plaintext []byte) (string, error)
	// Open unwraps the wrapped key wkID of tenant tid.
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
	// DestroyTx deletes the wrapped key wkID inside tx.
	DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error
	// WrapSystem wraps plaintext as a system secret, without storing it.
	WrapSystem(p crypto.Purpose, plaintext []byte) (store.SystemSecret, error)
	// OpenSystem unwraps the system secret secretID.
	OpenSystem(ctx context.Context, p crypto.Purpose, secretID string) ([]byte, error)
	// Scrub purges the destroyed keys from the database files.
	Scrub(ctx context.Context) error
}

// Compile-time check that the master key vault fits.
var _ Vault = (*masterkey.Vault)(nil)

// reasonSystemWebhooks is the reason of the system transactions of the
// instance-wide webhooks.
const reasonSystemWebhooks = "system webhooks"

// change is a validated change of a webhook.
type change struct {
	name    string
	url     []byte
	hint    string
	events  []events.Type
	enabled *bool
	// secret is the new signing secret of a rotation, nil otherwise.
	secret []byte
	at     time.Time
}

// storeChange returns the store change of c, without the new keys.
func (c change) storeChange() store.WebhookChange {
	return store.WebhookChange{Name: c.name, URLHint: c.hint, Events: c.events, Enabled: c.enabled, UpdatedAt: c.at}
}

// replacedKeys returns the keys of cur that the change ch replaces.
func replacedKeys(cur store.Webhook, ch store.WebhookChange) []string {
	var out []string
	if ch.URLKeyID != "" && cur.URLKeyID != "" {
		out = append(out, cur.URLKeyID)
	}
	if ch.SecretKeyID != "" && cur.SecretKeyID != "" {
		out = append(out, cur.SecretKeyID)
	}
	return out
}

// owner is the set of webhooks of one tenant, or the instance-wide
// webhooks, with the storage of their sealed URLs and secrets. Every
// operation of a tenant owner runs in that tenant's scope (T-179).
type owner interface {
	// tenant returns the tenant, "" for the instance.
	tenant() tenant.ID
	// allowed reports whether the webhooks may subscribe to t.
	allowed(t events.Type) bool
	list(ctx context.Context) ([]store.Webhook, error)
	subscribed(ctx context.Context, t events.Type) ([]store.Webhook, error)
	get(ctx context.Context, whkID string) (store.Webhook, error)
	// create seals url and secret (nil for none) and stores w with them.
	create(ctx context.Context, w store.Webhook, url, secret []byte) (store.Webhook, error)
	// update applies c, sealing its new URL and secret and destroying the
	// keys they replace, and returns the webhook before and after. It fails
	// with store.ErrConflict when the webhook changed concurrently.
	update(ctx context.Context, whkID string, c change) (before, after store.Webhook, err error)
	// remove destroys the keys of the webhook, deletes it and returns it.
	remove(ctx context.Context, whkID string) (store.Webhook, error)
	// open unseals the key keyID (URL or secret).
	open(ctx context.Context, keyID string) ([]byte, error)
	record(ctx context.Context, whkID string, s store.WebhookDeliveryState) error
	audit(ctx context.Context, ev audit.Event) error
}

// tenantOwner is the owner of the webhooks of tenant tid.
type tenantOwner struct {
	db     *store.DB
	vault  Vault
	writer *audit.Writer
	tid    tenant.ID
}

func (o *tenantOwner) tenant() tenant.ID          { return o.tid }
func (o *tenantOwner) allowed(t events.Type) bool { return events.IsTenant(t) }

func (o *tenantOwner) list(ctx context.Context) ([]store.Webhook, error) {
	return o.db.Webhooks().List(ctx, o.tid)
}

func (o *tenantOwner) subscribed(ctx context.Context, t events.Type) ([]store.Webhook, error) {
	return o.db.Webhooks().ListSubscribed(ctx, o.tid, t)
}

func (o *tenantOwner) get(ctx context.Context, whkID string) (store.Webhook, error) {
	return o.db.Webhooks().Get(ctx, o.tid, whkID)
}

// tx runs fn in a write transaction of the tenant.
func (o *tenantOwner) tx(ctx context.Context, fn func(tx *store.ScopedTx) error) error {
	sc, err := o.db.Scoped(o.tid)
	if err != nil {
		return err
	}
	return sc.Tx(ctx, fn)
}

// seal seals plaintext inside tx.
func (o *tenantOwner) seal(ctx context.Context, tx *store.ScopedTx, plaintext []byte) (string, error) {
	return o.vault.SealTx(ctx, tx, crypto.PurposeSecret, plaintext)
}

func (o *tenantOwner) create(ctx context.Context, w store.Webhook, url, secret []byte) (store.Webhook, error) {
	var created store.Webhook
	err := o.tx(ctx, func(tx *store.ScopedTx) error {
		var err error
		if w.URLKeyID, err = o.seal(ctx, tx, url); err != nil {
			return err
		}
		if secret != nil {
			if w.SecretKeyID, err = o.seal(ctx, tx, secret); err != nil {
				return err
			}
		}
		created, err = o.db.Webhooks().CreateTx(ctx, tx, w)
		return err
	})
	return created, err
}

func (o *tenantOwner) update(ctx context.Context, whkID string, c change) (store.Webhook, store.Webhook, error) {
	var before, after store.Webhook
	err := o.tx(ctx, func(tx *store.ScopedTx) error {
		var err error
		if before, err = o.db.Webhooks().GetTx(ctx, tx, whkID); err != nil {
			return err
		}
		if c.secret != nil && before.Kind != store.WebhookGeneric {
			return errNotGeneric
		}
		ch := c.storeChange()
		// The change applies to the version read here only: a concurrent
		// change, which may have destroyed the keys of before, wins.
		ch.Version = before.UpdatedAt
		if c.url != nil {
			if ch.URLKeyID, err = o.seal(ctx, tx, c.url); err != nil {
				return err
			}
		}
		if c.secret != nil {
			if ch.SecretKeyID, err = o.seal(ctx, tx, c.secret); err != nil {
				return err
			}
		}
		after, err = o.db.Webhooks().UpdateTx(ctx, tx, whkID, ch)
		for _, k := range replacedKeys(before, ch) {
			if err == nil {
				err = o.vault.DestroyTx(ctx, tx, k)
			}
		}
		return err
	})
	return before, after, err
}

func (o *tenantOwner) remove(ctx context.Context, whkID string) (store.Webhook, error) {
	var removed store.Webhook
	err := o.tx(ctx, func(tx *store.ScopedTx) error {
		var err error
		if removed, err = o.db.Webhooks().GetTx(ctx, tx, whkID); err != nil {
			return err
		}
		for _, k := range []string{removed.URLKeyID, removed.SecretKeyID} {
			if k != "" && err == nil {
				err = o.vault.DestroyTx(ctx, tx, k)
			}
		}
		if err == nil {
			err = o.db.Webhooks().DeleteTx(ctx, tx, whkID)
		}
		return err
	})
	return removed, err
}

func (o *tenantOwner) open(ctx context.Context, keyID string) ([]byte, error) {
	return o.vault.Open(ctx, o.tid, crypto.PurposeSecret, keyID)
}

func (o *tenantOwner) record(ctx context.Context, whkID string, s store.WebhookDeliveryState) error {
	return o.db.Webhooks().RecordDelivery(ctx, o.tid, whkID, s)
}

func (o *tenantOwner) audit(ctx context.Context, ev audit.Event) error {
	return o.writer.RecordScoped(ctx, o.tid, ev)
}

// systemOwner is the owner of the instance-wide webhooks.
type systemOwner struct {
	db     *store.DB
	vault  Vault
	writer *audit.Writer
	// reason is the reason of the system transactions.
	reason string
}

func (o *systemOwner) tenant() tenant.ID          { return "" }
func (o *systemOwner) allowed(t events.Type) bool { return events.IsSystem(t) }

func (o *systemOwner) list(ctx context.Context) ([]store.Webhook, error) {
	return o.db.SystemWebhooks().List(ctx)
}

func (o *systemOwner) subscribed(ctx context.Context, t events.Type) ([]store.Webhook, error) {
	return o.db.SystemWebhooks().ListSubscribed(ctx, t)
}

func (o *systemOwner) get(ctx context.Context, whkID string) (store.Webhook, error) {
	return o.db.SystemWebhooks().Get(ctx, whkID)
}

// tx runs fn in a system write transaction.
func (o *systemOwner) tx(ctx context.Context, fn func(tx *store.SystemTx) error) error {
	sys, err := o.db.System(o.reason)
	if err != nil {
		return err
	}
	return sys.Tx(ctx, fn)
}

// seal seals plaintext as a system secret stored inside tx.
func (o *systemOwner) seal(ctx context.Context, tx *store.SystemTx, plaintext []byte) (string, error) {
	sec, err := o.vault.WrapSystem(crypto.PurposeWebhook, plaintext)
	if err != nil {
		return "", err
	}
	return sec.ID, o.db.SystemSecrets().CreateTx(ctx, tx, sec)
}

func (o *systemOwner) create(ctx context.Context, w store.Webhook, url, secret []byte) (store.Webhook, error) {
	var created store.Webhook
	err := o.tx(ctx, func(tx *store.SystemTx) error {
		var err error
		if w.URLKeyID, err = o.seal(ctx, tx, url); err != nil {
			return err
		}
		if secret != nil {
			if w.SecretKeyID, err = o.seal(ctx, tx, secret); err != nil {
				return err
			}
		}
		created, err = o.db.SystemWebhooks().CreateTx(ctx, tx, w)
		return err
	})
	return created, err
}

func (o *systemOwner) update(ctx context.Context, whkID string, c change) (store.Webhook, store.Webhook, error) {
	var before, after store.Webhook
	err := o.tx(ctx, func(tx *store.SystemTx) error {
		var err error
		if before, err = o.db.SystemWebhooks().GetTx(ctx, tx, whkID); err != nil {
			return err
		}
		if c.secret != nil && before.Kind != store.WebhookGeneric {
			return errNotGeneric
		}
		ch := c.storeChange()
		// The change applies to the version read here only: a concurrent
		// change, which may have destroyed the keys of before, wins.
		ch.Version = before.UpdatedAt
		if c.url != nil {
			if ch.URLKeyID, err = o.seal(ctx, tx, c.url); err != nil {
				return err
			}
		}
		if c.secret != nil {
			if ch.SecretKeyID, err = o.seal(ctx, tx, c.secret); err != nil {
				return err
			}
		}
		after, err = o.db.SystemWebhooks().UpdateTx(ctx, tx, whkID, ch)
		for _, k := range replacedKeys(before, ch) {
			if err == nil {
				err = o.db.SystemSecrets().DeleteTx(ctx, tx, k)
			}
		}
		return err
	})
	return before, after, err
}

func (o *systemOwner) remove(ctx context.Context, whkID string) (store.Webhook, error) {
	var removed store.Webhook
	err := o.tx(ctx, func(tx *store.SystemTx) error {
		var err error
		if removed, err = o.db.SystemWebhooks().GetTx(ctx, tx, whkID); err != nil {
			return err
		}
		for _, k := range []string{removed.URLKeyID, removed.SecretKeyID} {
			if k != "" && err == nil {
				err = o.db.SystemSecrets().DeleteTx(ctx, tx, k)
			}
		}
		if err == nil {
			err = o.db.SystemWebhooks().DeleteTx(ctx, tx, whkID)
		}
		return err
	})
	return removed, err
}

func (o *systemOwner) open(ctx context.Context, keyID string) ([]byte, error) {
	return o.vault.OpenSystem(ctx, crypto.PurposeWebhook, keyID)
}

func (o *systemOwner) record(ctx context.Context, whkID string, s store.WebhookDeliveryState) error {
	return o.db.SystemWebhooks().RecordDelivery(ctx, whkID, s)
}

func (o *systemOwner) audit(ctx context.Context, ev audit.Event) error {
	return o.writer.Record(ctx, ev)
}
