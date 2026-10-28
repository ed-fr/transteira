// Package webhookadmin manages the alert webhooks of the tenants and of the
// instance (CLAUDE.md section 12.4, threats T-179 and T-181 to T-186): the
// administrators list, create, change, test and delete them, and the
// dispatcher of internal/webhook reads the webhooks to call through
// [Service.Subscribers], reads each one again before every attempt through
// [Service.Target] and records their deliveries through
// [Service.RecordDelivery] ([webhook.Store]). It writes no HTTP: the
// handlers of package api/admin map its results and errors.
//
// # Access (threats T-63, T-186)
//
// Every administration method takes the [adminauth.Principal] of the
// caller and checks it before anything else, request body included: an
// authenticated session, then [adminauth.RequireTenantAccess] for the
// reads of a tenant, [adminauth.RequireTenantWrite] for its changes and
// tests, and [adminauth.RequireSuperAdmin] for the instance-wide webhooks.
// A tenant the caller is not attached to, a tenant being deleted and a
// webhook of another tenant (or an instance-wide webhook under a tenant,
// and the reverse) are answered like a missing one ([ErrNotFound]).
//
// # Sealed URL and secret (threats T-183, T-184, decision D23)
//
// The URL of a webhook (Teams and Slack URLs embed a secret) is checked by
// the network guard of internal/webhook, then sealed with the master key:
// a wrapped key of purpose crypto.PurposeSecret for a tenant webhook, a
// system secret of purpose crypto.PurposeWebhook for an instance-wide one.
// Only its scheme and host are kept in clear, for display. A generic
// webhook gets a signing secret: 32 bytes from crypto/rand written as 64
// lowercase hexadecimal characters. That text is returned once, at the
// creation and after a rotation, sealed like the URL, and its ASCII bytes
// are the HMAC-SHA256 key of the deliveries ([webhook.Target].Secret): a
// receiver uses the secret exactly as shown, without decoding it. A new
// URL or secret replaces the previous one in the same transaction, which
// destroys the previous key material; a deletion destroys the keys before
// the webhook.
//
// # Audit
//
// The changes and the tests are audited (webhook.created, webhook.updated,
// webhook.deleted, webhook.tested), in the tenant of the webhook or
// without tenant for an instance-wide one, with the kind, the events, the
// host of the URL and the names of the changed fields only: never the URL
// nor the secret.
//
// # Errors
//
// The errors map to the problem codes of the API: [ErrInvalid] (an
// *[InvalidError] naming the field and its code, 400 validation-failed),
// [ErrUnauthenticated] (401), [ErrForbidden] (403, an instance-wide webhook
// for a delegated admin), [ErrNotFound] (404), [ErrLimitReached] and
// [ErrConflict] (409 state-conflict) and [ErrRateLimited] (a *[RateLimitError], 429: too many
// tests, or too many creations and URL changes, each of which resolves a
// host: [TestLimit], [URLChangeLimit]). Any
// other error is an internal failure whose message never holds a URL or a
// secret.
package webhookadmin
