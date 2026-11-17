package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Contract and wiring tests of the express secrets (since 2.3, CLAUDE.md
// section 22.2): every answer of createExpressSecret, of the recipient
// operations on an express secret, of reportSecretAbuse, of the secret
// settings with their express members, of lookupTenantSecret and of
// purgeExpressSecrets is validated against api/openapi.yaml, and the
// instance kill switch is read from the configuration.

const (
	pathExpress      = "/api/v1/express-secrets"
	pathSecretLinks  = "/api/v1/secret-links/"
	opCreateExpress  = "createExpressSecret"
	opSecretLinkStat = "getSecretLink"
	opRevealSecret   = "revealSecret"
	opReportSecret   = "reportSecretAbuse"
	// expressClientIP and badBodyIP are anonymous creators outside every
	// internal range; badBodyIP spends its own hourly budget on refusals.
	expressClientIP = "203.0.113.41"
	badBodyIP       = "203.0.113.42"
)

// sealedExpress is an express secret sealed as a browser would.
type sealedExpress struct {
	text, verifier, keyVerifier, keyProof, proof string
	ID                                           string `json:"id"`
	Token                                        string `json:"token"`
}

// sealExpress seals text with a new key, without passphrase.
func sealExpress(t *testing.T, text string) sealedExpress {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	root, err := tte2.DeriveSecretKey(key, "", tte2.PassphraseDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := tte2.SealSecret(root, text)
	if err != nil {
		t.Fatal(err)
	}
	keyProof, _ := tte2.SecretKeyProof(key)
	proof, _ := tte2.SecretProof(root)
	return sealedExpress{
		text: sealed, keyProof: tte2.EncodeProof(keyProof), proof: tte2.EncodeProof(proof),
		verifier: tte2.EncodeProof(tte2.SecretVerifier(proof)), keyVerifier: tte2.EncodeProof(tte2.SecretVerifier(keyProof)),
	}
}

// body returns the creation body of s with extra raw members.
func (s sealedExpress) body(extra string) []byte {
	return []byte(`{` + extra + `"encryptedText":"` + s.text + `","verifier":"` + s.verifier + `","keyVerifier":"` + s.keyVerifier +
		`","expiresIn":"1d"}`)
}

// expressCall sends a public express request under host A from ip, with
// the extra headers given as pairs.
func expressCall(t *testing.T, s *server, method, path, ip string, body []byte, hdr ...string) response {
	t.Helper()
	h := http.Header{"X-Forwarded-For": {ip}}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return s.do(t, request{method: method, path: path, host: hostA, body: body, headers: h})
}

// createExpress creates s under host A, anonymous unless a bearer is
// given, checks the 201 against the contract and returns s with its
// identifiers.
func createExpress(t *testing.T, s *server, ip string, sealed sealedExpress, bearer ...string) sealedExpress {
	t.Helper()
	var hdr []string
	if len(bearer) > 0 {
		hdr = []string{"Authorization", "Bearer " + bearer[0]}
	}
	resp := mustStatus(t, opCreateExpress, expressCall(t, s, http.MethodPost, pathExpress, ip, sealed.body(""), hdr...), http.StatusCreated)
	expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
	if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("createExpressSecret Cache-Control = %q", cc)
	}
	mustJSON(t, resp.body, &sealed)
	return sealed
}

// setExpressSettings replaces the secret settings of tenant tid with the
// defaults of a new tenant and the given express members.
func setExpressSettings(t *testing.T, c *adminClient, tid string, express map[string]any) response {
	t.Helper()
	body := map[string]any{
		"enabled": true, "durations": []string{"1h", "1d", "7d"}, "fileAllowed": true, "fileMaxBytes": 10 << 20, "emailAllowed": true,
	}
	for k, v := range express {
		body[k] = v
	}
	resp := c.call(t, http.MethodPut, tenantPath(tid, "/secret-settings"), body)
	expectContract(t, "updateSecretSettings", http.MethodPut, tenantPath(tid, "/secret-settings"), resp)
	return resp
}

func TestExpressSecretsContract(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		s := o.server
		settings := tenantPath(o.tid, "/secret-settings")
		get := mustStatus(t, "getSecretSettings", o.sa.call(t, http.MethodGet, settings, nil), http.StatusOK)
		expectContract(t, "getSecretSettings", http.MethodGet, settings, get)
		if !strings.Contains(string(get.body), `"expressEnabled":false`) || !strings.Contains(string(get.body), `"expressMaxPending":1000`) {
			t.Errorf("default settings: %s", get.body)
		}

		// Off by default: refused, with the security event.
		resp := expressCall(t, s, http.MethodPost, pathExpress, expressClientIP, sealExpress(t, "closed").body(""))
		expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)

		// The settings: null and out-of-range members refused.
		for _, bad := range []map[string]any{{"expressEnabled": nil}, {"expressPerHourPerIp": 0}, {"expressMaxPending": 100001}} {
			resp := setExpressSettings(t, o.sa, o.tid, bad)
			expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
		}
		mustStatus(t, "open", setExpressSettings(t, o.sa, o.tid, map[string]any{"expressEnabled": true, "expressPerHourPerIp": 2}), http.StatusOK)
		tenantResp := s.get(t, hostA, "/api/v1/tenant")
		expectContract(t, "getPublicTenant", http.MethodGet, "/api/v1/tenant", tenantResp)
		if !strings.Contains(string(tenantResp.body), `"expressSecrets":{"durations":["1h","1d","7d"],"enabled":true,"maxChars":10000}`) {
			t.Errorf("public features: %s", tenantResp.body)
		}

		// Anonymous creation, status, reveal, report after reading.
		first := createExpress(t, s, expressClientIP, sealExpress(t, "first express secret"))
		link := pathSecretLinks + first.Token
		status := mustStatus(t, opSecretLinkStat, expressCall(t, s, http.MethodGet, link, expressClientIP, nil), http.StatusOK)
		expectContract(t, opSecretLinkStat, http.MethodGet, link, status)
		if !strings.Contains(string(status.body), `"express":true`) || !strings.Contains(string(status.body), `"anonymous":true`) {
			t.Errorf("status: %s", status.body)
		}
		reveal := []byte(`{"keyProof":"` + first.keyProof + `","proof":"` + first.proof + `"}`)
		resp = mustStatus(t, opRevealSecret, expressCall(t, s, http.MethodPost, link+"/reveal", expressClientIP, reveal), http.StatusOK)
		expectContract(t, opRevealSecret, http.MethodPost, link+"/reveal", resp)
		gone := expressCall(t, s, http.MethodGet, link, expressClientIP, nil)
		expectProblem(t, gone, http.StatusGone, "secret-gone")
		expectContract(t, opSecretLinkStat, http.MethodGet, link, gone)
		report := []byte(`{"category":"phishing","message":"Asks for a bank password."}`)
		resp = mustStatus(t, opReportSecret, expressCall(t, s, http.MethodPost, link+"/abuse-reports", expressClientIP, report), http.StatusAccepted)
		expectContract(t, opReportSecret, http.MethodPost, link+"/abuse-reports", resp)
		unknown := pathSecretLinks + "tts_" + strings.Repeat("Q", 43)
		resp = expressCall(t, s, http.MethodPost, unknown+"/abuse-reports", expressClientIP, report)
		expectProblem(t, resp, http.StatusNotFound, "not-found")
		expectContract(t, opReportSecret, http.MethodPost, unknown+"/abuse-reports", resp)
		resp = expressCall(t, s, http.MethodPost, link+"/abuse-reports", expressClientIP, []byte(`{"category":"nope"}`))
		expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
		expectContract(t, opReportSecret, http.MethodPost, link+"/abuse-reports", resp)

		// Malformed bodies, each on its own client (a refused body still
		// counts in the hourly limit of its client): every one is 400.
		for name, c := range map[string]struct {
			ip   string
			body []byte
		}{
			"extra member": {badBodyIP, sealExpress(t, "x").body(`"passphrase":{"kdf":"pbkdf2-sha256"},`)},
			"malformed":    {"203.0.113.51", []byte(`{`)},
			"duration":     {"203.0.113.52", []byte(`{"encryptedText":"AQ","verifier":"x","keyVerifier":"y","expiresIn":"30d"}`)},
		} {
			resp := expressCall(t, s, http.MethodPost, pathExpress, c.ip, c.body)
			expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
			expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
			if name == "extra member" && !strings.Contains(string(resp.body), `"/passphrase"`) {
				t.Errorf("extra member: %s", resp.body)
			}
		}
		// Cross-site, without token.
		resp = expressCall(t, s, http.MethodPost, pathExpress, expressClientIP, sealExpress(t, "x").body(""),
			"Origin", "https://evil.example.net")
		expectProblem(t, resp, http.StatusForbidden, "csrf-invalid")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)

		// The per-client limit (2 per hour here): the second creation
		// passes, the third is refused with Retry-After.
		second := createExpress(t, s, expressClientIP, sealExpress(t, "second"))
		resp = expressCall(t, s, http.MethodPost, pathExpress, expressClientIP, sealExpress(t, "third").body(""))
		expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		if resp.header.Get("Retry-After") == "" {
			t.Error("rate-limited without Retry-After")
		}

		// API tokens: invalid, without the opt-in, with it.
		resp = expressCall(t, s, http.MethodPost, pathExpress, scriptIP, sealExpress(t, "x").body(""), "Authorization", "Bearer tt_"+strings.Repeat("x", 43))
		expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		_, plain := o.sa.createToken(t, o.tid, "No express", []string{scriptNet}, nil)
		resp = expressCall(t, s, http.MethodPost, pathExpress, scriptIP, sealExpress(t, "x").body(""), "Authorization", "Bearer "+plain)
		expectProblem(t, resp, http.StatusForbidden, "express-token-not-allowed")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		tokResp := mustStatus(t, "createApiToken", o.sa.call(t, http.MethodPost, tokensPath(o.tid), map[string]any{
			"name": "Service desk", "allowedCidrs": []string{scriptNet}, "expressAllowed": true,
		}), http.StatusCreated)
		expectContract(t, "createApiToken", http.MethodPost, tokensPath(o.tid), tokResp)
		var tok struct {
			Token          string `json:"token"`
			ExpressAllowed bool   `json:"expressAllowed"`
		}
		mustJSON(t, tokResp.body, &tok)
		if !tok.ExpressAllowed {
			t.Errorf("token: %s", tokResp.body)
		}
		o.secret(tok.Token, plain)
		resp = expressCall(t, s, http.MethodPost, pathExpress, strangerIP, sealExpress(t, "x").body(""), "Authorization", "Bearer "+tok.Token)
		expectProblem(t, resp, http.StatusForbidden, "ip-not-allowed")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		byToken := createExpress(t, s, scriptIP, sealExpress(t, "by token"), tok.Token)

		// The tenant cap refuses the anonymous creations only.
		mustStatus(t, "cap", setExpressSettings(t, o.sa, o.tid, map[string]any{"expressMaxPending": 1}), http.StatusOK)
		resp = expressCall(t, s, http.MethodPost, pathExpress, "203.0.113.43", sealExpress(t, "capped").body(""))
		expectProblem(t, resp, http.StatusTooManyRequests, "express-secret-limit-reached")
		expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		if resp.header.Get("Retry-After") != "" {
			t.Error("express-secret-limit-reached with Retry-After")
		}
		createExpress(t, s, scriptIP, sealExpress(t, "by token over the cap"), tok.Token)

		// The administration: lookup by link (fragment ignored), purge of
		// the live anonymous secrets.
		lookup := tenantPath(o.tid, "/secrets/lookup")
		resp = mustStatus(t, "lookupTenantSecret", o.sa.call(t, http.MethodPost, lookup, map[string]any{
			"link": "https://" + hostA + "/s/" + second.Token + "#k=ew7WSQ3aQqhKCGs_K2QR3lal5iX7Jr66egxAI_Wmhuk",
		}), http.StatusOK)
		expectContract(t, "lookupTenantSecret", http.MethodPost, lookup, resp)
		if !strings.Contains(string(resp.body), second.ID) || strings.Contains(string(resp.body), second.Token) {
			t.Errorf("lookup: %s", resp.body)
		}
		for _, link := range []string{"https://" + hostA + "/s/nothing", "tts_" + strings.Repeat("R", 43)} {
			resp := o.sa.call(t, http.MethodPost, lookup, map[string]any{"link": link})
			if resp.status != http.StatusBadRequest && resp.status != http.StatusNotFound {
				t.Errorf("lookup %q: %d %s", link, resp.status, resp.body)
			}
			expectContract(t, "lookupTenantSecret", http.MethodPost, lookup, resp)
		}
		list := mustStatus(t, "listTenantSecrets", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/secrets"), nil), http.StatusOK)
		expectContract(t, "listTenantSecrets", http.MethodGet, tenantPath(o.tid, "/secrets"), list)
		purge := tenantPath(o.tid, "/express-secrets/purge")
		resp = mustStatus(t, "purgeExpressSecrets", o.sa.call(t, http.MethodPost, purge, nil), http.StatusOK)
		expectContract(t, "purgeExpressSecrets", http.MethodPost, purge, resp)
		if string(resp.body) != "{\"deleted\":1}\n" {
			t.Errorf("purge: %s", resp.body)
		}
		gone = expressCall(t, s, http.MethodGet, pathSecretLinks+second.Token, expressClientIP, nil)
		expectProblem(t, gone, http.StatusGone, "secret-gone")
		// The token's secret survives the purge.
		mustStatus(t, "token secret", expressCall(t, s, http.MethodGet, pathSecretLinks+byToken.Token, scriptIP, nil), http.StatusOK)

		// The read block: the anonymous mode off closes the anonymous
		// secrets only, and nothing is consumed.
		mustStatus(t, "uncap", setExpressSettings(t, o.sa, o.tid, map[string]any{"expressMaxPending": 1000}), http.StatusOK)
		third := createExpress(t, s, "203.0.113.44", sealExpress(t, "third anonymous"))
		mustStatus(t, "close", setExpressSettings(t, o.sa, o.tid, map[string]any{"expressEnabled": false}), http.StatusOK)
		thirdLink := pathSecretLinks + third.Token
		resp = expressCall(t, s, http.MethodGet, thirdLink, expressClientIP, nil)
		expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
		expectContract(t, opSecretLinkStat, http.MethodGet, thirdLink, resp)
		resp = expressCall(t, s, http.MethodPost, thirdLink+"/reveal", expressClientIP,
			[]byte(`{"keyProof":"`+third.keyProof+`","proof":"`+third.proof+`"}`))
		expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
		expectContract(t, opRevealSecret, http.MethodPost, thirdLink+"/reveal", resp)
		mustStatus(t, "token secret readable", expressCall(t, s, http.MethodGet, pathSecretLinks+byToken.Token, scriptIP, nil), http.StatusOK)
		mustStatus(t, "reopen", setExpressSettings(t, o.sa, o.tid, map[string]any{"expressEnabled": true}), http.StatusOK)
		mustStatus(t, "readable again", expressCall(t, s, http.MethodGet, thirdLink, expressClientIP, nil), http.StatusOK)
		o.secret(first.Token, second.Token, byToken.Token, third.Token, first.keyProof, first.proof, first.verifier, first.text)
		o.expectNoSecrets(t, o.auditRows(t))
	})
}

// TestExpressKillSwitch: TT_EXPRESS_SECRETS_DISABLED=true closes the
// creation (anonymous and by token) and the reading of every express
// secret, and the public configuration says so, whatever the tenant
// setting; the reports and the administration stay open.
func TestExpressKillSwitch(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		mustStatus(t, "open", setExpressSettings(t, o.sa, o.tid, map[string]any{"expressEnabled": true}), http.StatusOK)
		tokResp := mustStatus(t, "createApiToken", o.sa.call(t, http.MethodPost, tokensPath(o.tid), map[string]any{
			"name": "Vault", "allowedCidrs": []string{scriptNet}, "expressAllowed": true,
		}), http.StatusCreated)
		var tok struct {
			Token string `json:"token"`
		}
		mustJSON(t, tokResp.body, &tok)
		anonymous := createExpress(t, o.server, expressClientIP, sealExpress(t, "before the switch"))
		byToken := createExpress(t, o.server, scriptIP, sealExpress(t, "by token before the switch"), tok.Token)

		if err := o.stop(); err != nil {
			t.Fatalf("stop: %v", err)
		}
		o.cfg.ExpressSecretsDisabled = true
		o.server = o.restart(t)
		s := o.server

		for _, c := range []struct{ ip, bearer string }{{expressClientIP, ""}, {scriptIP, tok.Token}} {
			hdr := []string{}
			if c.bearer != "" {
				hdr = append(hdr, "Authorization", "Bearer "+c.bearer)
			}
			resp := expressCall(t, s, http.MethodPost, pathExpress, c.ip, sealExpress(t, "after").body(""), hdr...)
			expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
			expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		}
		for _, sec := range []sealedExpress{anonymous, byToken} {
			link := pathSecretLinks + sec.Token
			resp := expressCall(t, s, http.MethodGet, link, expressClientIP, nil)
			expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
			expectContract(t, opSecretLinkStat, http.MethodGet, link, resp)
			reveal := []byte(`{"keyProof":"` + sec.keyProof + `","proof":"` + sec.proof + `"}`)
			resp = expressCall(t, s, http.MethodPost, link+"/reveal", expressClientIP, reveal)
			expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
			expectContract(t, opRevealSecret, http.MethodPost, link+"/reveal", resp)
		}
		// The read block writes no security event and counts no failure;
		// an unknown token is still 404 first (no oracle, T-400).
		for _, l := range parseLines(t, s.securityLines(t)) {
			if l.ip == expressClientIP && l.event != "express_refused" {
				t.Errorf("the read block wrote %q", l.raw)
			}
		}
		unknown := pathSecretLinks + "tts_" + strings.Repeat("Q", 43)
		expectProblem(t, expressCall(t, s, http.MethodGet, unknown, badBodyIP, nil), http.StatusNotFound, "not-found")
		expectProblem(t, expressCall(t, s, http.MethodPost, unknown+"/reveal", badBodyIP,
			[]byte(`{"keyProof":"`+anonymous.keyProof+`","proof":"`+anonymous.proof+`"}`)), http.StatusNotFound, "not-found")
		var pub struct {
			Features struct {
				ExpressSecrets struct {
					Enabled bool `json:"enabled"`
				} `json:"expressSecrets"`
			} `json:"features"`
		}
		tenantResp := s.get(t, hostA, "/api/v1/tenant")
		mustJSON(t, tenantResp.body, &pub)
		if pub.Features.ExpressSecrets.Enabled {
			t.Errorf("public features under the kill switch: %s", tenantResp.body)
		}
		// The setting is kept as stored.
		get := mustStatus(t, "getSecretSettings", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/secret-settings"), nil), http.StatusOK)
		if !strings.Contains(string(get.body), `"expressEnabled":true`) {
			t.Errorf("stored setting: %s", get.body)
		}
		// Reporting and the administration stay open.
		report := []byte(`{"category":"illegal_content"}`)
		mustStatus(t, opReportSecret, expressCall(t, s, http.MethodPost, pathSecretLinks+anonymous.Token+"/abuse-reports", expressClientIP, report),
			http.StatusAccepted)
		resp := mustStatus(t, "lookupTenantSecret", o.sa.call(t, http.MethodPost, tenantPath(o.tid, "/secrets/lookup"),
			map[string]any{"link": anonymous.Token}), http.StatusOK)
		var found struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}
		mustJSON(t, resp.body, &found)
		if found.ID != anonymous.ID || found.State != "active" {
			t.Errorf("lookup under the kill switch: %s", resp.body)
		}
		if lines := strings.Join(s.securityLines(t), "\n"); !strings.Contains(lines, "express_refused") {
			t.Errorf("no express_refused event: %s", lines)
		}

		// Reopened before their expiry, the secrets were never consumed:
		// both read once.
		if err := o.stop(); err != nil {
			t.Fatalf("stop: %v", err)
		}
		o.cfg.ExpressSecretsDisabled = false
		o.server = o.restart(t)
		for _, sec := range []sealedExpress{anonymous, byToken} {
			link := pathSecretLinks + sec.Token
			mustStatus(t, "status after reopening", expressCall(t, o.server, http.MethodGet, link, expressClientIP, nil), http.StatusOK)
			reveal := []byte(`{"keyProof":"` + sec.keyProof + `","proof":"` + sec.proof + `"}`)
			mustStatus(t, "reveal after reopening", expressCall(t, o.server, http.MethodPost, link+"/reveal", expressClientIP, reveal),
				http.StatusOK)
		}
	})
}
