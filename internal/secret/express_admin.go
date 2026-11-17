package secret

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MaxLookupLinkLen bounds the pasted link of a lookup, in bytes (OpenAPI
// SecretLookup.link).
const MaxLookupLinkLen = 2048

// linkPath is the path of a secret link before its token
// (https://<fqdn>/s/<token>#k=<key>, e2e-format.md 3.3.1).
const linkPath = "/s/"

// AdminActor is the administrator of a lookup or a purge, for the audit.
// The caller checks first that it may act on the tenant (a delegated admin
// of the tenant or the super admin; an auditor may look up but not purge).
type AdminActor struct {
	// Username is the username of the administrator.
	Username string
	// IP is the client IP of the request.
	IP netip.Addr
}

// Lookup returns the secret of tenant t a pasted link leads to
// (lookupTenantSecret, since 2.3, threat model T-408), in any state and as
// stored, without content: link is a full link
// https://<fqdn>/s/<token>#k=<key> (the host is ignored, the query and the
// fragment are dropped unread) or a bare "tts_" token, surrounding spaces
// ignored. A link without an extractable token is a *ValidationError on
// FieldLink (CodeRequired, CodeTooLong beyond MaxLookupLinkLen bytes, or
// CodeInvalidFormat); a token of no secret of the tenant is ErrNotFound.
// The token is only hashed by the store: the link, its token and its
// fragment are never stored, logged nor audited. A secret found is
// audited as secret.looked_up (object its "sec_" identifier, actor the
// administrator). Nothing else is written.
func (s *Service) Lookup(ctx context.Context, t *tenant.Tenant, actor AdminActor, link string) (store.Secret, error) {
	token, err := tokenOfLink(link)
	if err != nil {
		return store.Secret{}, err
	}
	sec, err := s.repo.LookupByToken(ctx, t.ID, token)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Secret{}, ErrNotFound
	case err != nil:
		return store.Secret{}, fmt.Errorf("secret: lookup: %w", err)
	}
	s.record(ctx, t, audit.Event{
		ActorKind: store.ActorAdmin, Actor: actor.Username, IP: actor.IP, Action: audit.ActionSecretLookedUp, ObjectID: sec.ID,
	})
	return sec, nil
}

// tokenOfLink extracts the "tts_" token of a pasted link or bare token
// (see [Service.Lookup]), or returns the *ValidationError on FieldLink. It
// never returns a part of link in an error.
func tokenOfLink(link string) (string, error) {
	fail := func(code string) error {
		return &ValidationError{Fields: []FieldError{{Pointer: FieldLink, Code: code}}}
	}
	switch {
	case strings.TrimSpace(link) == "":
		return "", fail(CodeRequired)
	case len(link) > MaxLookupLinkLen:
		return "", fail(CodeTooLong)
	}
	// The fragment holds the key: it is cut first and never read.
	link, _, _ = strings.Cut(link, "#")
	link, _, _ = strings.Cut(link, "?")
	link = strings.TrimSpace(link)
	if id.SecretTokenValid(link) {
		return link, nil
	}
	// A link: [scheme://]host/s/<token>[/], or the path alone.
	i := strings.LastIndex(link, linkPath)
	if i < 0 {
		return "", fail(CodeInvalidFormat)
	}
	host, token := link[:i], strings.TrimSuffix(link[i+len(linkPath):], "/")
	if _, rest, ok := strings.Cut(host, "://"); ok {
		host = rest
	}
	if strings.Contains(host, "/") || !id.SecretTokenValid(token) {
		return "", fail(CodeInvalidFormat)
	}
	return token, nil
}

// PurgeExpress ends every live (active) anonymous express secret of tenant
// t at once (purgeExpressSecrets, since 2.3, threat model T-392 and
// T-408), as an administrator deletion: each becomes a deleted tombstone
// and its key is destroyed (cryptographic erasure), then the database is
// scrubbed. The express secrets created with an API token, the 2.1 secrets
// and the tombstones are kept. The purge is not interrupted by the
// cancellation of ctx. It returns how many secrets it ended, audited once
// as secret.express_purged (object the tenant, details.count, actor the
// administrator) instead of one secret.deleted per secret, also after a
// failure midway (the batches already ended stay ended, and the error is
// returned with their count: calling again finishes the work).
func (s *Service) PurgeExpress(ctx context.Context, t *tenant.Tenant, actor AdminActor) (int, error) {
	n, err := s.repo.PurgeAnonymousExpress(context.WithoutCancel(ctx), t.ID, s.now())
	if n > 0 {
		s.erased(ctx, t, "")
	}
	if n > 0 || err == nil {
		s.record(ctx, t, audit.Event{
			ActorKind: store.ActorAdmin, Actor: actor.Username, IP: actor.IP, Action: audit.ActionSecretExpressPurged,
			ObjectKind: audit.ObjectTenant, ObjectID: t.ID.String(), Details: map[string]any{"count": n},
		})
	}
	if err != nil {
		return n, fmt.Errorf("secret: purge express secrets: %w", err)
	}
	return n, nil
}
