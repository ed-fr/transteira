package httpisolation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/provisioning"
	"github.com/ed-fr/transteira/internal/store"
)

// Provisioning API (since API 1.2, threats T-267 to T-276): the
// provisioning tokens of the super admin and the provisioning operations
// of the service providers, both on the admin host only.

const (
	// unknownProvisioningToken is a well-formed provisioning token
	// identifier that the harness never creates.
	unknownProvisioningToken = "prv_01JABCT1V2W3X4Y5Z6A7B8C9D0"
	// unknownTenant is a well-formed tenant identifier of no tenant.
	unknownTenant = "ten_01JAB00000000000000ENT1TYC"
	// harnessSuffix is the FQDN suffix of the harness token.
	harnessSuffix = ".provisioned.localhost"
)

// provisioningTokenBody is a valid body of createProvisioningToken, so
// that a refusal of the delegated admin is the role check and nothing
// else.
const provisioningTokenBody = `{"name":"MSP","allowedCidrs":["198.51.100.0/24"],"allowedFqdnSuffixes":["` + harnessSuffix +
	`"],"maxStorageQuotaBytes":1073741824,"maxTenants":1,"code":"123456"}`

// provisioningTokenOperation is the isolation case of the provisioning
// token operations, instance-wide and reserved to the super admin: served
// on the admin host only; 403 forbidden for tenant A's delegated admin
// even with a valid body; then served to the super admin without data of
// any tenant (a creation without code is refused before any TOTP attempt,
// the revocation of an unknown token is a 404).
func provisioningTokenOperation(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	path := strings.ReplaceAll(op.template, "{tokenId}", unknownProvisioningToken)
	body := ""
	if op.verb == http.MethodPost {
		body = provisioningTokenBody
	}
	deleg := h.adminCall(t, h.session(t), op.verb, path, body)
	wantCode(t, op, hostAdmin, deleg, http.StatusForbidden, "forbidden")
	h.noDataOfB(t, op, "the answer to a delegated admin", deleg)
	noLeak(t, h, op, hostAdmin, deleg)

	super := h.superSession(t)
	var resp response
	switch op.id {
	case "createProvisioningToken":
		resp = h.adminCall(t, super, op.verb, path, strings.Replace(provisioningTokenBody, `,"code":"123456"`, "", 1))
		wantCode(t, op, hostAdmin, resp, http.StatusBadRequest, "validation-failed")
	case "revokeProvisioningToken":
		resp = h.adminCall(t, super, op.verb, path, "")
		wantCode(t, op, hostAdmin, resp, http.StatusNotFound, "not-found")
	default: // listProvisioningTokens
		resp = h.adminCall(t, super, op.verb, path, "")
		wantOK(t, op, "super admin", resp)
	}
	h.noDataOfB(t, op, "the answer to the super admin", resp)
	noLeak(t, h, op, hostAdmin, resp)
}

// provisioningSecret returns the secret of the provisioning token of the
// harness, created in the store on first use, usable from every client IP
// of the harness (198.51.0.0/16).
func (h *harness) provisioningSecret(t *testing.T) string {
	t.Helper()
	h.sessMu.Lock()
	defer h.sessMu.Unlock()
	if h.provisioning != "" {
		return h.provisioning
	}
	gen, err := provisioning.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ProvisioningTokens().Create(ctx, store.ProvisioningToken{
		ID: id.New(id.ProvisioningToken), Name: "Harness MSP", Prefix: gen.Prefix, TokenHash: gen.Hash,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.0.0/16")}, AllowedFQDNSuffixes: []string{harnessSuffix},
		MaxStorageQuotaBytes: 1 << 30, MaxTenants: 2, CreatedBy: "adm_01JABCS1T2V3W4X5Y6Z7A8B9C0",
	}, nil); err != nil {
		t.Fatal(err)
	}
	h.provisioning = gen.Secret
	return h.provisioning
}

// bearer returns the headers of a provisioning request with secret.
func bearer(secret string, withJSON bool) http.Header {
	hdr := http.Header{"Authorization": {"Bearer " + secret}}
	if withJSON {
		hdr.Set("Content-Type", "application/json")
	}
	return hdr
}

// provisionedTenantOperation is the isolation case of the provisioning
// operations: served on the admin host only, even with a valid
// provisioning token (404 under both tenant hosts); never opened by an
// admin session (401); then, with a token that created no tenant, the
// tenants A and B are never listed nor read (404, exactly like an unknown
// one), and a creation outside the suffixes of the token is refused.
func provisionedTenantOperation(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	secret := h.provisioningSecret(t)
	path := func(tid string) string {
		return "http://" + h.addr + op.base + strings.ReplaceAll(op.template, "{tenantId}", tid)
	}
	for _, host := range []string{hostA, hostB} {
		resp := h.do(t, op.verb, path(string(h.tenantA.ID)), host, strings.NewReader("{}"), bearer(secret, true))
		wantCode(t, op, host, resp, http.StatusNotFound, "not-found")
		noLeak(t, h, op, host, resp)
	}
	sess := h.session(t).header(true)
	resp := h.do(t, op.verb, path(string(h.tenantA.ID)), hostAdmin, strings.NewReader("{}"), sess)
	wantCode(t, op, hostAdmin, resp, http.StatusUnauthorized, "unauthenticated")

	switch op.id {
	case "getProvisionedTenant":
		missing := h.do(t, op.verb, path(unknownTenant), hostAdmin, nil, bearer(secret, false))
		wantCode(t, op, hostAdmin, missing, http.StatusNotFound, "not-found")
		for _, tid := range []string{string(h.tenantA.ID), string(h.tenantB.ID)} {
			resp = h.do(t, op.verb, path(tid), hostAdmin, nil, bearer(secret, false))
			h.sameAsMissing(t, op, resp, missing)
		}
	case "provisionTenant":
		// Tenant A's FQDN is outside the suffixes of the token.
		body, _ := json.Marshal(map[string]any{
			"name": "Entity P", "fqdn": h.tenantA.FQDN, "defaultLanguage": "en", "storageQuotaBytes": 1 << 20,
			"delegatedAdmin": map[string]any{"username": "admin.entity-p", "email": "it@entity-p.example.com", "language": "en"},
		})
		resp = h.do(t, op.verb, path(""), hostAdmin, strings.NewReader(string(body)), bearer(secret, true))
		wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "provisioning-scope-exceeded")
	default: // listProvisionedTenants
		resp = h.do(t, op.verb, path(""), hostAdmin, nil, bearer(secret, false))
		if b := wantOK(t, op, "provisioning token", resp); string(b) != `{"items":[]}`+"\n" && string(b) != `{"items":[]}` {
			t.Errorf("%s: %s, want no tenant", op, b)
		}
	}
	h.noDataOfB(t, op, "the answer to a provisioning token", resp)
	noLeak(t, h, op, hostAdmin, resp)
}
