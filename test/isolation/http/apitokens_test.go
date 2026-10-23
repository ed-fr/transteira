package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
)

// tokenNameB is the name of the API tokens created for tenant B by the
// token cases.
const tokenNameB = "Tenant B export token"

// apiTokenView is the part of the OpenAPI ApiToken the token cases read.
type apiTokenView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Prefix       string   `json:"prefix"`
	AllowedCidrs []string `json:"allowedCidrs"`
	RevokedAt    *string  `json:"revokedAt"`
	Token        string   `json:"token"`
}

// adminAPIToken is the isolation case of an API token operation: served on
// the admin host only, tenant B's ID answered like an unknown tenant
// (adminTenantOp), then the checks of the operation on a token of B
// created by the super admin (tokenChecks).
func adminAPIToken(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	check, ok := tokenChecks[op.id]
	if !ok {
		t.Fatalf("%s has no entry in tokenChecks", op)
	}
	check(t, h, op, h.session(t), h.tokenOfB(t, op))
}

// tokenChecks are the per-operation checks of adminAPIToken, run with the
// session of tenant A's delegated admin and a fresh token of tenant B.
var tokenChecks = map[string]func(t *testing.T, h *harness, op operation, sess adminSession, tokB apiTokenView){
	"listApiTokens":  checkListTokens,
	"createApiToken": checkCreateToken,
	"updateApiToken": checkUpdateToken,
	"revokeApiToken": checkRevokeToken,
}

// tokenOfB creates, as the super admin, an API token of tenant B and
// returns it with its secret.
func (h *harness) tokenOfB(t *testing.T, op operation) apiTokenView {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPost, tenantPath(h.tenantB.ID, "/api-tokens"),
		`{"name":"`+tokenNameB+`","allowedCidrs":["198.51.100.0/24"]}`)
	var tok apiTokenView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tok) != nil || tok.ID == "" || tok.Token == "" {
		t.Fatalf("%s: create a token of tenant B (super admin): %d %s", op, resp.status, resp.body)
	}
	return tok
}

// tokensOf lists the tokens of tenant tid with the session sess.
func (h *harness) tokensOf(t *testing.T, op operation, sess adminSession, tid string) []apiTokenView {
	t.Helper()
	resp := h.adminCall(t, sess, http.MethodGet, "/admin/tenants/"+tid+"/api-tokens", "")
	var list []apiTokenView
	if json.Unmarshal(wantOK(t, op, "the token list of "+tid, resp), &list) != nil {
		t.Fatalf("%s: token list of %s: %s", op, tid, resp.body)
	}
	return list
}

// tokenOfBIntact asserts that tenant B's token tokB is still listed for B
// unchanged: same name and ranges, not revoked.
func (h *harness) tokenOfBIntact(t *testing.T, op operation, tokB apiTokenView) {
	t.Helper()
	for _, tok := range h.tokensOf(t, op, h.superSession(t), string(h.tenantB.ID)) {
		if tok.ID != tokB.ID {
			continue
		}
		if tok.Name != tokenNameB || strings.Join(tok.AllowedCidrs, ",") != "198.51.100.0/24" || tok.RevokedAt != nil {
			t.Errorf("%s: tenant B's token was changed: %+v", op, tok)
		}
		return
	}
	t.Errorf("%s: tenant B's token %s is gone", op, tokB.ID)
}

// noTokenOfB asserts that resp holds nothing of tenant B's token tokB.
func (h *harness) noTokenOfB(t *testing.T, op operation, what string, resp response, tokB apiTokenView) {
	t.Helper()
	h.noDataOfB(t, op, what, resp, tokB.ID, tokB.Token, tokenNameB, "198.51.100.0/24")
}

// checkListTokens: A's list never holds B's token.
func checkListTokens(t *testing.T, h *harness, op operation, sess adminSession, tokB apiTokenView) {
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/api-tokens"), "")
	wantOK(t, op, "tenant A's list", resp)
	h.noTokenOfB(t, op, "tenant A's list", resp, tokB)
}

// checkCreateToken: an invalid body for B answers like an unknown tenant
// (the access is checked first); A's token, created under A's path, is
// listed for A only, never for B.
func checkCreateToken(t *testing.T, h *harness, op operation, sess adminSession, tokB apiTokenView) {
	for _, bad := range []string{`{}`, `null`, `{"name":"x","allowedCidrs":["not a range"]}`} {
		h.invalidInputOfB(t, op, sess, http.MethodPost, "/api-tokens", bad)
	}
	resp := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/api-tokens"),
		`{"name":"Tenant A token","allowedCidrs":["192.0.2.0/24"]}`)
	var tokA apiTokenView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tokA) != nil || tokA.ID == "" || tokA.Token == "" {
		t.Fatalf("%s: tenant A's own token: %d %s, want 201", op, resp.status, resp.body)
	}
	if resp.header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s: the answer holding the secret has Cache-Control %q, want no-store", op, resp.header.Get("Cache-Control"))
	}
	h.noTokenOfB(t, op, "tenant A's new token", resp, tokB)
	for _, tok := range h.tokensOf(t, op, h.superSession(t), string(h.tenantB.ID)) {
		if tok.ID == tokA.ID {
			t.Errorf("%s: tenant A's token %s is listed for tenant B", op, tokA.ID)
		}
	}
	h.tokenOfBIntact(t, op, tokB)
}

// checkUpdateToken: B's token under A's path answers like a missing token
// and stays unchanged.
func checkUpdateToken(t *testing.T, h *harness, op operation, sess adminSession, tokB apiTokenView) {
	body := `{"name":"Renamed by A","allowedCidrs":["0.0.0.0/0"]}`
	foreign := h.adminCall(t, sess, http.MethodPatch, tenantPath(h.tenantA.ID, "/api-tokens/"+tokB.ID), body)
	missing := h.adminCall(t, sess, http.MethodPatch, tenantPath(h.tenantA.ID, "/api-tokens/"+id.New(id.APIToken)), body)
	h.sameAsMissing(t, op, foreign, missing, tokB.ID, tokB.Token, tokenNameB)
	h.tokenOfBIntact(t, op, tokB)
}

// checkRevokeToken: B's token under A's path answers like a missing token
// and stays valid.
func checkRevokeToken(t *testing.T, h *harness, op operation, sess adminSession, tokB apiTokenView) {
	foreign := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/api-tokens/"+tokB.ID), "")
	missing := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/api-tokens/"+id.New(id.APIToken)), "")
	h.sameAsMissing(t, op, foreign, missing, tokB.ID, tokB.Token, tokenNameB)
	h.tokenOfBIntact(t, op, tokB)
}
