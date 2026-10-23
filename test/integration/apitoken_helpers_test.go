package integration_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Helpers of the API token tests (CLAUDE.md sections 4.1 and 16.4;
// api/openapi.yaml security scheme apiToken, "Admin operations" API token
// operations and the deposit operations accepting a token; threat model
// T-68 to T-73).

const (
	// scriptIP is the client IP of the script holding the token, outside
	// the internal ranges of tenant A: the token ranges replace them.
	scriptIP = "198.51.100.77"
	// scriptNet is the single-address range of the tokens of the script.
	scriptNet = "198.51.100.77/32"
	// strangerIP is a client IP outside every token range.
	strangerIP = "203.0.113.99"
	// pathDocs is the interactive API documentation.
	pathDocs = "/api/docs"
	// docsCSP is the exact Content-Security-Policy of the documentation
	// (httpserver.DocsCSP, threat model entry of the documentation page).
	docsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; " +
		"img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	// Audit actions of the API tokens.
	actTokenCreated = "api_token.created"
	actTokenUsed    = "api_token.used"
	actTokenRevoked = "api_token.revoked"
	// tokenFailureLimit is httpserver.APITokenFailureLimit: the invalid
	// tokens one client IP may present before being locked out.
	tokenFailureLimit = 10
)

// secretRE is the format of an API token secret: tt_ and 43 base62
// characters.
var secretRE = regexp.MustCompile(`^tt_[0-9A-Za-z]{43}$`)

// apiTokenMembers are the members of the ApiToken schema; ApiTokenCreated
// adds token.
var (
	apiTokenMembers = []string{
		"id", "name", "prefix", "allowedCidrs", "allowedSenders", "createdBy", "createdAt", "lastUsedAt", "expiresAt", "revokedAt",
	}
	apiTokenRequired = []string{"id", "name", "prefix", "allowedCidrs", "allowedSenders", "createdBy", "createdAt"}
)

// apiTokenJSON is the ApiToken schema.
type apiTokenJSON struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Prefix       string   `json:"prefix"`
	AllowedCidrs []string `json:"allowedCidrs"`
	// AllowedSenders is never null: [] without restriction.
	AllowedSenders []string   `json:"allowedSenders"`
	CreatedBy      string     `json:"createdBy"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
	ExpiresAt      *time.Time `json:"expiresAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
}

// tokensPath returns the admin path of the API tokens of tenant tid.
func tokensPath(tid string) string { return tenantPath(tid, "/api-tokens") }

// createToken creates an API token of tenant tid through the admin API and
// returns it with its secret, checking the ApiTokenCreated answer: the
// members of the schema, the secret format and its visible prefix. The
// secret is recorded as one that must never be logged.
func (c *adminClient) createToken(t *testing.T, tid, name string, cidrs []string, expires *time.Time) (apiTokenJSON, string) {
	t.Helper()
	tok, secret := c.createTokenFor(t, tid, name, cidrs, expires, nil)
	if tok.AllowedSenders == nil || len(tok.AllowedSenders) != 0 {
		t.Errorf("created token allowedSenders = %#v, want []", tok.AllowedSenders)
	}
	return tok, secret
}

// createTokenFor is createToken with allowed senders (none when nil).
func (c *adminClient) createTokenFor(t *testing.T, tid, name string, cidrs []string, expires *time.Time, senders []string) (apiTokenJSON, string) {
	t.Helper()
	body := map[string]any{"name": name, "allowedCidrs": cidrs}
	if expires != nil {
		body["expiresAt"] = expires.UTC().Format(time.RFC3339)
	}
	if senders != nil {
		body["allowedSenders"] = senders
	}
	resp := mustStatus(t, "createApiToken", c.call(t, http.MethodPost, tokensPath(tid), body), http.StatusCreated)
	if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("createApiToken Cache-Control = %q, want no-store", cc)
	}
	var members map[string]json.RawMessage
	mustJSON(t, resp.body, &members)
	checkMembers(t, "ApiTokenCreated", members, append(slices.Clone(apiTokenMembers), "token"), append(slices.Clone(apiTokenRequired), "token"))
	var created struct {
		apiTokenJSON
		Token string `json:"token"`
	}
	mustJSON(t, resp.body, &created)
	if !secretRE.MatchString(created.Token) {
		t.Fatalf("token secret %q, want tt_ and 43 base62 characters", created.Token)
	}
	tok := created.apiTokenJSON
	if !id.Valid(id.APIToken, tok.ID) {
		t.Errorf("token id %q, want a tok_ identifier", tok.ID)
	}
	if tok.Prefix != created.Token[:7] {
		t.Errorf("token prefix %q, want the first 7 characters of the secret", tok.Prefix)
	}
	if tok.Name != name || !slices.Equal(tok.AllowedCidrs, cidrs) || tok.LastUsedAt != nil || tok.RevokedAt != nil {
		t.Errorf("created token = %+v, want %q from %v, never used nor revoked", tok, name, cidrs)
	}
	if (tok.ExpiresAt == nil) != (expires == nil) || (expires != nil && !tok.ExpiresAt.Equal(expires.UTC().Truncate(time.Second))) {
		t.Errorf("created token expiresAt = %v, want %v", tok.ExpiresAt, expires)
	}
	c.a.secret(created.Token)
	return tok, created.Token
}

// updateToken sends updateApiToken for the token tokID of tenant tid with
// the merge patch body.
func (c *adminClient) updateToken(t *testing.T, tid, tokID string, body any) response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return c.send(t, http.MethodPatch, tokensPath(tid)+"/"+tokID, string(raw),
		http.Header{hdrCSRF: {c.csrf}, "Content-Type": {mergePatch}})
}

// listTokens sends listApiTokens and decodes the 200 answer, checking that
// no item carries a secret.
func (c *adminClient) listTokens(t *testing.T, tid string) []apiTokenJSON {
	t.Helper()
	resp := mustStatus(t, "listApiTokens", c.call(t, http.MethodGet, tokensPath(tid), nil), http.StatusOK)
	var items []map[string]json.RawMessage
	mustJSON(t, resp.body, &items)
	for _, it := range items {
		checkMembers(t, "ApiToken", it, apiTokenMembers, apiTokenRequired)
	}
	if secretInBody(string(resp.body)) {
		t.Errorf("listApiTokens holds a secret: %s", resp.body)
	}
	var out []apiTokenJSON
	mustJSON(t, resp.body, &out)
	return out
}

// tokenIn returns the token tokID of list.
func tokenIn(t *testing.T, list []apiTokenJSON, tokID string) apiTokenJSON {
	t.Helper()
	for _, tok := range list {
		if tok.ID == tokID {
			return tok
		}
	}
	t.Fatalf("token %s not listed in %+v", tokID, list)
	return apiTokenJSON{}
}

// anySecretRE finds anything shaped like a token secret.
var anySecretRE = regexp.MustCompile(`tt_[0-9A-Za-z]{40,}`)

// secretInBody reports whether s holds something shaped like a secret.
func secretInBody(s string) bool { return anySecretRE.MatchString(s) }

// revokeToken sends revokeApiToken and expects 204.
func (c *adminClient) revokeToken(t *testing.T, tid, tokID string) {
	t.Helper()
	mustStatus(t, "revokeApiToken", c.call(t, http.MethodDelete, tokensPath(tid)+"/"+tokID, nil), http.StatusNoContent)
}

// newUnknownSecret returns a well-formed secret that no tenant knows,
// generated at runtime.
func newUnknownSecret(t *testing.T) string {
	t.Helper()
	s, err := id.NewToken("tt", 32)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// scriptClient returns a script of tenant A presenting the token secret
// from ip, without any cookie.
func (d *depositEnv) scriptClient(secret, ip string) *depositor {
	return &depositor{d: d, host: hostA, ip: ip, bearer: secret}
}

// tokenTransferCreate is the TransferCreate schema with the senderEmail
// member of the API token requests.
type tokenTransferCreate struct {
	SenderEmail string `json:"senderEmail,omitempty"`
	transferCreate
}

// tokenCreate sends createTransfer with senderEmail ("" omits it) and an
// optional Idempotency-Key, without CSRF token: a script holds no session.
func (c *depositor) tokenCreate(t *testing.T, senderEmail string, body transferCreate, key string) response {
	t.Helper()
	b, err := json.Marshal(tokenTransferCreate{SenderEmail: senderEmail, transferCreate: body})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	if key != "" {
		h.Set(hdrIdempotency, key)
	}
	return c.send(t, http.MethodPost, pathTransfers, string(b), h)
}

// mustTokenCreate is tokenCreate expecting 201 without any cookie.
func (c *depositor) mustTokenCreate(t *testing.T, senderEmail string, body transferCreate) senderTransferJSON {
	t.Helper()
	resp := c.tokenCreate(t, senderEmail, body, "")
	if resp.status != http.StatusCreated {
		t.Fatalf("createTransfer with a token: %d %s", resp.status, resp.body)
	}
	expectNoCookie(t, "createTransfer with a token", resp)
	return parseTransfer(t, resp.body)
}

// tokenFinalize and tokenCancel send finalizeTransfer and cancelTransfer
// without CSRF token.
func (c *depositor) tokenFinalize(t *testing.T, trfID string) response {
	t.Helper()
	return c.send(t, http.MethodPost, pathTransfers+"/"+trfID+"/finalize", "", nil)
}

func (c *depositor) tokenCancel(t *testing.T, trfID string) response {
	t.Helper()
	return c.send(t, http.MethodDelete, pathTransfers+"/"+trfID, "", nil)
}

// expectNoCookie fails when resp sets a cookie: the token path never does.
func expectNoCookie(t *testing.T, what string, resp response) {
	t.Helper()
	if sc := resp.header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("%s sets cookies %q, want none on the token path", what, sc)
	}
}

// expectFieldCode fails unless the transfer Problem lists the field with
// the code.
func expectFieldCode(t *testing.T, p transferProblem, field, code string) {
	t.Helper()
	for _, e := range p.Errors {
		if e.Field == field && e.Code == code {
			return
		}
	}
	t.Errorf("problem errors = %+v, want %s %s", p.Errors, field, code)
}

// tokenLogLines returns the security log lines of event from ip on host.
func tokenLogLines(t *testing.T, s *server, event, ip, host string) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range eventsOf(t, s.securityLines(t), event) {
		if l.ip == ip && l.tenant == host {
			out = append(out, l)
		}
	}
	return out
}

// startOpsWith is startOps with extra server options.
func startOpsWith(t *testing.T, e storetest.Engine, o serverOptions) *opsEnv {
	t.Helper()
	o, av := withScanner(t, o)
	a := startAdmin(t, e, o, true)
	return &opsEnv{adminEnv: a, av: av, sa: a.bootstrapUnique(t, adminIP(10)), tid: string(a.tenantA.ID)}
}

// adminTransferAPI is the subset of AdminTransferDetail about the origin of
// a transfer.
type adminTransferAPI struct {
	Origin      string  `json:"origin"`
	APITokenID  *string `json:"apiTokenId"`
	SenderEmail string  `json:"senderEmail"`
	SenderIP    *string `json:"senderIp"`
}
