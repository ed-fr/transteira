package integration_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end flows of the express secrets (since 2.3, CLAUDE.md section
// 22.2): the integration cases of the threat model row T-389 to T-408
// (docs/security/threat-model.md, section 9), on SQLite and PostgreSQL,
// with tenant A's mails captured by Mailpit, a local webhook receiver and
// the shipped fail2ban and CrowdSec rules applied to the security log
// lines the server really wrote (express_rules_test.go). The contract of
// every answer is checked by express_test.go.

const (
	// pastedKey is the key of the fragment of a link pasted in the lookup:
	// it must never be stored, logged nor audited.
	pastedKey = "Xq3vB9zL0sKp7RmT2wYc5NhJ8dFgA1eU4iO6tPaSbQk" // gitleaks:allow (fake fragment key of a test link)
	// expressPerIPDefault and expressPerTokenDefault are the default
	// hourly limits of a tenant (expressPerHourPerIp, expressPerHourPerToken).
	expressPerIPDefault    = 10
	expressPerTokenDefault = 100
	// secretLinkFailures is the number of failures (unknown tokens, wrong
	// proofs) after which a client is locked out of the secret links.
	secretLinkFailures = 10
	// reportsPerSecret and reportsPerIP are the limits of the abuse
	// reports: per secret and day, per client IP and hour.
	reportsPerSecret = 3
	reportsPerIP     = 5
	// tokenNet is the range of the API tokens of the express tests.
	tokenNet = "198.51.100.0/24"
	// reportBody is a valid abuse report.
	reportBody = `{"category":"phishing","message":"Asks for a bank password."}`
)

// expressOn sends a public express request under host from ip, with the
// extra headers given as pairs.
func expressOn(t *testing.T, s *server, host, method, path, ip string, body []byte, hdr ...string) response {
	t.Helper()
	h := http.Header{hdrXFF: {ip}}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return s.do(t, request{method: method, path: path, host: host, body: body, headers: h})
}

// createExpressOn creates sealed under host from ip, with the API token
// bearer unless it is "", and returns it with its identifiers.
func createExpressOn(t *testing.T, s *server, host, ip string, sealed sealedExpress, bearer string) sealedExpress {
	t.Helper()
	var hdr []string
	if bearer != "" {
		hdr = []string{"Authorization", "Bearer " + bearer}
	}
	resp := expressOn(t, s, host, http.MethodPost, pathExpress, ip, sealed.body(""), hdr...)
	mustStatus(t, "createExpressSecret from "+ip, resp, http.StatusCreated)
	mustJSON(t, resp.body, &sealed)
	if !strings.HasPrefix(sealed.ID, "sec_") || !strings.HasPrefix(sealed.Token, "tts_") {
		t.Fatalf("created express secret %s", resp.body)
	}
	return sealed
}

// link returns the API path of the link of s.
func (s sealedExpress) link() string { return pathSecretLinks + s.Token }

// revealBody returns the reveal body of s.
func (s sealedExpress) revealBody() []byte {
	return []byte(`{"keyProof":"` + s.keyProof + `","proof":"` + s.proof + `"}`)
}

// material returns every secret value of s: none may be logged nor
// audited.
func (s sealedExpress) material() []string {
	return []string{s.text, s.verifier, s.keyVerifier, s.keyProof, s.proof, s.Token}
}

// expressStatus is the SecretStatus schema of an express secret.
type expressStatus struct {
	State     string `json:"state"`
	Express   bool   `json:"express"`
	Anonymous bool   `json:"anonymous"`
}

// statusOf reads the status of s under host from ip and expects it active,
// express, anonymous as given.
func statusOf(t *testing.T, s *server, host, ip string, sec sealedExpress, anonymous bool) {
	t.Helper()
	resp := mustStatus(t, "getSecretLink "+sec.ID, expressOn(t, s, host, http.MethodGet, sec.link(), ip, nil), http.StatusOK)
	var st expressStatus
	mustJSON(t, resp.body, &st)
	if st.State != "active" || !st.Express || st.Anonymous != anonymous {
		t.Errorf("status of %s = %s, want active, express, anonymous %v", sec.ID, resp.body, anonymous)
	}
}

// expectSecretGone asserts a 410 secret-gone answer with reason.
func expectSecretGone(t *testing.T, what string, resp response, reason string) {
	t.Helper()
	expectProblem(t, resp, http.StatusGone, "secret-gone")
	var p struct {
		Reason string `json:"reason"`
	}
	mustJSON(t, resp.body, &p)
	if p.Reason != reason {
		t.Errorf("%s: reason %q, want %q (%s)", what, p.Reason, reason, resp.body)
	}
}

// expressTokenOf creates, as the super admin, an API token of tenant tid
// usable from cidrs, with the express opt-in when allowed, records its
// secret and returns its identifier and secret.
func (o *opsEnv) expressTokenOf(t *testing.T, tid, name string, cidrs []string, allowed bool) (id, secret string) {
	t.Helper()
	resp := mustStatus(t, "createApiToken "+name, o.sa.call(t, http.MethodPost, tokensPath(tid), map[string]any{
		"name": name, "allowedCidrs": cidrs, "expressAllowed": allowed,
	}), http.StatusCreated)
	var tok struct {
		ID             string `json:"id"`
		Token          string `json:"token"`
		ExpressAllowed bool   `json:"expressAllowed"`
	}
	mustJSON(t, resp.body, &tok)
	if tok.ExpressAllowed != allowed || tok.Token == "" {
		t.Fatalf("token %s: %s", name, resp.body)
	}
	o.secret(tok.Token)
	return tok.ID, tok.Token
}

// openExpress turns the anonymous express mode of tenant tid on, with the
// express members given.
func (o *opsEnv) openExpress(t *testing.T, tid string, members map[string]any) {
	t.Helper()
	body := map[string]any{"expressEnabled": true}
	for k, v := range members {
		body[k] = v
	}
	mustStatus(t, "open the express secrets of "+tid, setExpressSettings(t, o.sa, tid, body), http.StatusOK)
}

// securityLinesOf returns the security log lines of event from ip under
// host whose fields are exactly fields ("" for any).
func securityLinesOf(t *testing.T, s *server, event, ip, host, fields string) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range eventsOf(t, s.securityLines(t), event) {
		if l.ip == ip && l.tenant == host && (fields == "" || strings.TrimSpace(l.fields) == fields) {
			out = append(out, l)
		}
	}
	return out
}

// auditOf returns the rows of action about object ("" for any).
func auditOf(rows []auditRow, action, object string) []auditRow {
	var out []auditRow
	for _, r := range rows {
		if r.action == action && (object == "" || r.objectID == object) {
			out = append(out, r)
		}
	}
	return out
}

// TestExpressAnonymousFlow: an anonymous express secret, created while
// the 2.1 module is off (P89), is active with express and anonymous set,
// is revealed once (a second reveal and the status then answer 410 read),
// and leaves secret.created (actor anonymous, the client IP, express and
// creatorKind, no address) and secret.revealed in the audit, without any
// secret material in the audit or the logs. A ciphertext beyond the 2.1
// bound is 400; a cross-site (Sec-Fetch-Site) or non-JSON creation is
// refused through the whole chain (T-389, T-395, T-398, T-402, T-404).
func TestExpressAnonymousFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		s := o.server
		o.openExpress(t, o.tid, map[string]any{"enabled": false})
		const creatorIP, readerIP = "203.0.113.61", "198.51.100.62"

		sec := createExpressOn(t, s, hostA, creatorIP, sealExpress(t, "anonymous express flow"), "")
		o.secret(sec.material()...)
		statusOf(t, s, hostA, readerIP, sec, true)
		resp := mustStatus(t, "revealSecret", expressOn(t, s, hostA, http.MethodPost, sec.link()+"/reveal", readerIP, sec.revealBody()),
			http.StatusOK)
		var rev struct {
			EncryptedText string `json:"encryptedText"`
		}
		mustJSON(t, resp.body, &rev)
		if rev.EncryptedText != sec.text || strings.Contains(string(resp.body), "encryptedMetadata") {
			t.Errorf("reveal = %s", resp.body)
		}
		expectSecretGone(t, "second reveal", expressOn(t, s, hostA, http.MethodPost, sec.link()+"/reveal", readerIP, sec.revealBody()), "read")
		expectSecretGone(t, "status after the reveal", expressOn(t, s, hostA, http.MethodGet, sec.link(), readerIP, nil), "read")

		rows := o.tenantAudit(t, o.tid)
		created := auditOf(rows, "secret.created", sec.ID)
		if len(created) != 1 || created[0].actorKind != "anonymous" || created[0].actor != "-" || created[0].ip != creatorIP ||
			!strings.Contains(created[0].details, `"express":true`) || !strings.Contains(created[0].details, `"creatorKind":"anonymous"`) ||
			strings.Contains(created[0].details, "@") {
			t.Errorf("secret.created = %+v", created)
		}
		if revealed := auditOf(rows, "secret.revealed", sec.ID); len(revealed) != 1 || revealed[0].ip != readerIP {
			t.Errorf("secret.revealed = %+v", revealed)
		}
		if used := auditOf(rows, "api_token.used", ""); len(used) != 0 {
			t.Errorf("api_token.used after an anonymous creation: %+v", used)
		}

		// Beyond the bound of the 2.1 ciphertext (53 372 characters).
		big := sealExpress(t, "x")
		big.text = "A" + strings.Repeat("Q", 53372)
		resp = expressOn(t, s, hostA, http.MethodPost, pathExpress, "203.0.113.63", big.body(""))
		expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
		if !strings.Contains(string(resp.body), `"/encryptedText"`) {
			t.Errorf("oversized ciphertext: %s", resp.body)
		}
		// Cross-site and non-JSON, without token.
		ok := sealExpress(t, "refused").body("")
		expectProblem(t, expressOn(t, s, hostA, http.MethodPost, pathExpress, "203.0.113.64", ok, "Sec-Fetch-Site", "cross-site"),
			http.StatusForbidden, "csrf-invalid")
		expectProblem(t, expressOn(t, s, hostA, http.MethodPost, pathExpress, "203.0.113.64", ok, "Content-Type", "text/plain"),
			http.StatusUnsupportedMediaType, "unsupported-media-type")
		// The refusals before the service write no express event.
		for _, ev := range []string{"express_refused", "rate_limited"} {
			if lines := securityLinesOf(t, s, ev, "203.0.113.64", hostA, ""); len(lines) != 0 {
				t.Errorf("%s lines after refusals before the service: %v", ev, lines)
			}
		}
		o.expectNoSecrets(t, o.tenantAudit(t, o.tid))
	})
}

// TestExpressAnonymousLimits: the 11th anonymous creation in the hour from
// an IPv4 address, then from another address of the same IPv6 /64, is
// 429 rate-limited with Retry-After and writes one rate_limited line of
// scope express_ip (throttled), counted by the shipped fail2ban and
// CrowdSec rules; another /64 is another client. The limit and the cap are
// the tenant's: B still accepts the client A refuses, and A's full cap
// refuses A's anonymous creations only (429 express-secret-limit-reached,
// express_refused reason=limit, ignored by the rules) (T-390 to T-392,
// T-394, T-405).
func TestExpressAnonymousLimits(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		s := o.server
		o.openExpress(t, o.tid, nil)
		o.openExpress(t, string(o.tenantB.ID), nil)
		rules := loadBanRules(t)

		const v4 = "203.0.113.70"
		v6 := make([]string, 0, expressPerIPDefault)
		for i := 1; i <= expressPerIPDefault; i++ {
			v6 = append(v6, "2001:db8:5:6::"+strconv.FormatInt(int64(i), 16))
		}
		for _, c := range []struct {
			name    string
			senders []string
			last    string
		}{
			{"IPv4", []string{v4}, v4},
			{"IPv6 /64", v6, "2001:db8:5:6:ffff:ffff:ffff:fffe"},
		} {
			for i := range expressPerIPDefault {
				createExpressOn(t, s, hostA, c.senders[i%len(c.senders)], sealExpress(t, c.name), "")
			}
			for range 2 {
				resp := expressOn(t, s, hostA, http.MethodPost, pathExpress, c.last, sealExpress(t, "over").body(""))
				expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
				if ra, err := strconv.Atoi(resp.header.Get(hdrRetryAfter)); err != nil || ra < 1 || ra > 3600 {
					t.Errorf("%s: Retry-After %q", c.name, resp.header.Get(hdrRetryAfter))
				}
			}
			lines := securityLinesOf(t, s, "rate_limited", c.last, hostA, `scope="express_ip"`)
			if len(lines) != 1 {
				t.Fatalf("%s: %d rate_limited express_ip lines from %s, want 1 (throttled): %v", c.name, len(lines), c.last, s.securityLines(t))
			}
			if f2b, cs := rules.fail2ban(lines[0].raw), rules.crowdsec(lines[0].raw); f2b != c.last || cs != c.last {
				t.Errorf("%s: fail2ban counts %q, CrowdSec %q, want %s: %q", c.name, f2b, cs, c.last, lines[0].raw)
			}
			// The same client is a new one for tenant B.
			createExpressOn(t, s, hostB, c.last, sealExpress(t, "under B"), "")
		}
		// Another /64 of the same /48 is another client.
		createExpressOn(t, s, hostA, "2001:db8:5:7::1", sealExpress(t, "other /64"), "")

		// A's cap (21 live express secrets) refuses A's anonymous
		// creations only; B is not affected.
		o.openExpress(t, o.tid, map[string]any{"expressMaxPending": 2*expressPerIPDefault + 1})
		const fresh = "203.0.113.71"
		for range 2 {
			resp := expressOn(t, s, hostA, http.MethodPost, pathExpress, fresh, sealExpress(t, "capped").body(""))
			expectProblem(t, resp, http.StatusTooManyRequests, "express-secret-limit-reached")
			if resp.header.Get(hdrRetryAfter) != "" {
				t.Errorf("express-secret-limit-reached with Retry-After %q", resp.header.Get(hdrRetryAfter))
			}
		}
		createExpressOn(t, s, hostB, fresh, sealExpress(t, "B below its cap"), "")
		refused := securityLinesOf(t, s, "express_refused", fresh, hostA, `reason="limit"`)
		if len(refused) != 1 {
			t.Fatalf("%d express_refused limit lines from %s, want 1 (throttled)", len(refused), fresh)
		}
		if f2b, cs := rules.fail2ban(refused[0].raw), rules.crowdsec(refused[0].raw); f2b != "" || cs != "" {
			t.Errorf("express_refused limit counted: fail2ban %q, CrowdSec %q", f2b, cs)
		}
		if lines := securityLinesOf(t, s, "rate_limited", fresh, hostA, ""); len(lines) != 0 {
			t.Errorf("the cap wrote rate_limited lines: %v", lines)
		}
	})
}

// TestExpressTokens: an API token needs the express opt-in (403
// express-token-not-allowed, express_refused reason=token) and its
// allowedCidrs (403 ip-not-allowed, deposit_refused reason=ip). With them
// it creates while the anonymous mode is off (403 express-secrets-disabled
// for an anonymous call): creatorKind api_token, api_token.used and
// secret.created audited with the token as actor, the secret readable
// since the anonymous mode only closes the anonymous secrets. The 101st
// creation of the hour is 429 rate-limited, scope express_token; the
// shipped rules ignore express_token and express_refused (T-389, T-393,
// T-405, P87, P91).
func TestExpressTokens(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		s := o.server
		rules := loadBanRules(t)
		ips := []string{"198.51.100.81", "198.51.100.82", "198.51.100.83"}
		_, plain := o.expressTokenOf(t, o.tid, "Deposit script", []string{tokenNet}, false)
		tokID, tok := o.expressTokenOf(t, o.tid, "Password vault", []string{tokenNet}, true)

		// Without the opt-in, outside the ranges, anonymous while closed.
		for range 2 {
			resp := expressOn(t, s, hostA, http.MethodPost, pathExpress, ips[0], sealExpress(t, "x").body(""), "Authorization", "Bearer "+plain)
			expectProblem(t, resp, http.StatusForbidden, "express-token-not-allowed")
		}
		resp := expressOn(t, s, hostA, http.MethodPost, pathExpress, strangerIP, sealExpress(t, "x").body(""), "Authorization", "Bearer "+tok)
		expectProblem(t, resp, http.StatusForbidden, "ip-not-allowed")
		resp = expressOn(t, s, hostA, http.MethodPost, pathExpress, "203.0.113.84", sealExpress(t, "x").body(""))
		expectProblem(t, resp, http.StatusForbidden, "express-secrets-disabled")
		for _, c := range []struct{ event, ip, fields string }{
			{"express_refused", ips[0], `reason="token"`},
			{"express_refused", "203.0.113.84", `reason="disabled"`},
		} {
			lines := securityLinesOf(t, s, c.event, c.ip, hostA, c.fields)
			if len(lines) != 1 {
				t.Fatalf("%d %s %s lines from %s, want 1", len(lines), c.event, c.fields, c.ip)
			}
			if f2b, cs := rules.fail2ban(lines[0].raw), rules.crowdsec(lines[0].raw); f2b != "" || cs != "" {
				t.Errorf("%s counted: fail2ban %q, CrowdSec %q", lines[0].raw, f2b, cs)
			}
		}
		if lines := securityLinesOf(t, s, "deposit_refused", strangerIP, hostA, ""); len(lines) != 1 ||
			!strings.Contains(lines[0].fields, `reason="ip"`) {
			t.Errorf("deposit_refused lines from %s: %v", strangerIP, lines)
		}

		// With the opt-in, the anonymous mode off: 100 creations in the
		// hour (spread over three addresses of the token's range, below the
		// global limit of a client), then 429.
		first := createExpressOn(t, s, hostA, ips[0], sealExpress(t, "by token"), tok)
		o.secret(first.material()...)
		statusOf(t, s, hostA, "203.0.113.85", first, false)
		for i := 1; i < expressPerTokenDefault; i++ {
			createExpressOn(t, s, hostA, ips[i%len(ips)], sealExpress(t, "by token"), tok)
		}
		for range 2 {
			resp = expressOn(t, s, hostA, http.MethodPost, pathExpress, ips[1], sealExpress(t, "101st").body(""), "Authorization", "Bearer "+tok)
			expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
			if resp.header.Get(hdrRetryAfter) == "" {
				t.Error("express_token refusal without Retry-After")
			}
		}
		limited := securityLinesOf(t, s, "rate_limited", ips[1], hostA, `scope="express_token"`)
		if len(limited) != 1 {
			t.Fatalf("%d rate_limited express_token lines, want 1 (throttled per token)", len(limited))
		}
		if f2b, cs := rules.fail2ban(limited[0].raw), rules.crowdsec(limited[0].raw); f2b != "" || cs != "" {
			t.Errorf("express_token counted: fail2ban %q, CrowdSec %q", f2b, cs)
		}
		// The token's secret is readable while the anonymous mode is off.
		mustStatus(t, "reveal a token secret", expressOn(t, s, hostA, http.MethodPost, first.link()+"/reveal", "203.0.113.85",
			first.revealBody()), http.StatusOK)

		rows := o.tenantAudit(t, o.tid)
		created := auditOf(rows, "secret.created", first.ID)
		if len(created) != 1 || created[0].actorKind != "api_token" || created[0].actor != tokID || created[0].ip != ips[0] ||
			!strings.Contains(created[0].details, `"express":true`) || !strings.Contains(created[0].details, `"creatorKind":"api_token"`) {
			t.Errorf("secret.created by token = %+v", created)
		}
		used := 0
		for _, r := range auditOf(rows, "api_token.used", "") {
			if r.actorKind == "api_token" && r.actor == tokID {
				used++
			}
		}
		if used < expressPerTokenDefault {
			t.Errorf("%d api_token.used rows of the express token, want at least %d", used, expressPerTokenDefault)
		}
		if n := len(auditOf(rows, "secret.created", "")); n != expressPerTokenDefault {
			t.Errorf("%d secret.created rows, want %d (refusals create nothing)", n, expressPerTokenDefault)
		}
		o.expectNoSecrets(t, rows)
	})
}

// TestExpressReadLimiters: the 2.1 limiters of the secret links apply to
// the express secrets. A wrong key proof is 403 secret-proof-invalid,
// never counted on the secret (no attemptsRemaining, the secret stays
// active) but counted for the client, which 10 failures lock out of the
// secret links (429 rate-limited, scope secret_link), right proofs
// included, while another client still reads the secret. Concurrent
// reveals: exactly one wins, the others get 410 read (T-353, T-400).
func TestExpressReadLimiters(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		s := o.server
		o.openExpress(t, o.tid, nil)
		const attacker = "203.0.113.90"
		sec := createExpressOn(t, s, hostA, "203.0.113.91", sealExpress(t, "guarded"), "")
		wrong := []byte(`{"keyProof":"` + strings.Repeat("0", 64) + `","proof":"` + sec.proof + `"}`)
		for i := range secretLinkFailures {
			resp := expressOn(t, s, hostA, http.MethodPost, sec.link()+"/reveal", attacker, wrong)
			expectProblem(t, resp, http.StatusForbidden, "secret-proof-invalid")
			if strings.Contains(string(resp.body), "attemptsRemaining") {
				t.Errorf("wrong key proof %d counted on the secret: %s", i+1, resp.body)
			}
		}
		resp := expressOn(t, s, hostA, http.MethodPost, sec.link()+"/reveal", attacker, sec.revealBody())
		expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
		if lines := securityLinesOf(t, s, "rate_limited", attacker, hostA, `scope="secret_link"`); len(lines) == 0 {
			t.Error("no rate_limited secret_link line for the locked-out client")
		}
		if lines := securityLinesOf(t, s, "secret_proof_invalid", attacker, hostA, ""); len(lines) == 0 ||
			!strings.Contains(lines[0].fields, `reason="key"`) {
			t.Errorf("secret_proof_invalid lines: %v", lines)
		}
		statusOf(t, s, hostA, "203.0.113.92", sec, true)

		// Concurrent reveals with the right proofs.
		const readers = 5
		var wg sync.WaitGroup
		codes := make([]int, readers)
		for i := range readers {
			wg.Go(func() {
				resp, err := s.tryDo(t, request{
					method: http.MethodPost, path: sec.link() + "/reveal", host: hostA, body: sec.revealBody(),
					headers: http.Header{hdrXFF: {"203.0.113." + strconv.Itoa(100+i)}},
				})
				if err != nil {
					t.Errorf("reveal %d: %v", i, err)
					return
				}
				codes[i] = resp.status
			})
		}
		wg.Wait()
		won := 0
		for i, c := range codes {
			switch c {
			case http.StatusOK:
				won++
			case http.StatusGone:
			default:
				t.Errorf("concurrent reveal %d: %d", i, c)
			}
		}
		if won != 1 {
			t.Errorf("%d concurrent reveals won, want exactly 1 (%v)", won, codes)
		}
		expectSecretGone(t, "status after the race", expressOn(t, s, hostA, http.MethodGet, sec.link(), "203.0.113.92", nil), "read")
	})
}

// TestExpressAbuseReport: the reader reports an express secret while it is
// active and after reading it (202). The report names the sec_ ID only
// (admin list, audit abuse.reported with details.secretId); the delegated
// admin gets the abuse-report mail through Mailpit and the tenant webhook
// the signed abuse.reported event, neither holding the token, the link,
// the key proofs nor the text. A 2.1 secret is 404 without security event,
// a deleted express secret 410; 3 reports per secret and day, 5 per client
// IP and hour; a cross-site or non-JSON report is refused (T-395, T-396,
// T-402, T-407).
func TestExpressAbuseReport(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOpsWith(t, e, serverOptions{env: map[string]string{
			config.EnvWebhookAllowNetworks:     "127.0.0.0/8",
			config.EnvWebhookAllowHTTPNetworks: "127.0.0.0/8",
		}})
		s := o.server
		o.secret(webhookURLToken)
		da := o.sa.createDelegatedOf(t, "delegate-express", o.tid, domainA, adminIP(21))
		rcv := newWebhookReceiver(t)
		hook := da.mustCreateWebhook(t, o.tid, map[string]any{
			"name": "Abuse channel", "kind": "generic", "url": rcv.url(), "events": []string{"abuse.reported"},
		})
		o.openExpress(t, o.tid, nil)
		report := func(sec sealedExpress, ip string, hdr ...string) response {
			t.Helper()
			return expressOn(t, s, hostA, http.MethodPost, sec.link()+"/abuse-reports", ip, []byte(reportBody), hdr...)
		}
		const r1, r2, r3 = "203.0.113.120", "203.0.113.121", "203.0.113.122"

		sec := createExpressOn(t, s, hostA, "203.0.113.110", sealExpress(t, "https://bank.example.net/login"), "")
		o.secret(sec.material()...)
		mustStatus(t, "report while active", report(sec, r1), http.StatusAccepted)
		mustStatus(t, "reveal", expressOn(t, s, hostA, http.MethodPost, sec.link()+"/reveal", r1, sec.revealBody()), http.StatusOK)
		mustStatus(t, "report after reading", report(sec, r1), http.StatusAccepted)
		mustStatus(t, "third report", report(sec, r2), http.StatusAccepted)
		expectProblem(t, report(sec, r3), http.StatusTooManyRequests, "rate-limited")
		perSecret := securityLinesOf(t, s, "rate_limited", r3, hostA, `transfer="`+sec.ID[:14]+`" scope="abuse_report_link"`)
		if len(perSecret) != 1 {
			t.Errorf("abuse_report_link lines from %s: %d, want 1: %v", r3, len(perSecret), s.securityLines(t))
		}

		// 5 reports per client IP and hour: r1 has 2, 3 more on other
		// secrets, then the 6th is refused.
		others := make([]sealedExpress, 4)
		for i := range others {
			others[i] = createExpressOn(t, s, hostA, "203.0.113.111", sealExpress(t, "other"), "")
			o.secret(others[i].material()...)
		}
		for _, sec := range others[:reportsPerIP-2] {
			mustStatus(t, "report from "+r1, report(sec, r1), http.StatusAccepted)
		}
		expectProblem(t, report(others[3], r1), http.StatusTooManyRequests, "rate-limited")
		if lines := securityLinesOf(t, s, "rate_limited", r1, hostA, `scope="abuse_report_ip"`); len(lines) != 1 {
			t.Errorf("abuse_report_ip lines from %s: %v", r1, lines)
		}

		// A 2.1 secret: 404 without security event; an unknown token: 404
		// and secret_invalid; a deleted express secret: 410.
		_, v21Token := o.expressTokenOf(t, o.tid, "Secrets script", []string{tokenNet}, false)
		v21 := sealExpress(t, "a 2.1 secret")
		resp := expressOn(t, s, hostA, http.MethodPost, "/api/v1/secrets", "198.51.100.86",
			[]byte(`{"senderEmail":"`+uniqueEmail(t, "it", domainA)+`","encryptedText":"`+v21.text+`","verifier":"`+v21.verifier+
				`","keyVerifier":"`+v21.keyVerifier+`","expiresIn":"1d","delivery":"link"}`), "Authorization", "Bearer "+v21Token)
		mustStatus(t, "createSecret", resp, http.StatusCreated)
		mustJSON(t, resp.body, &v21)
		o.secret(v21.material()...)
		const r4, r5 = "203.0.113.123", "203.0.113.124"
		expectProblem(t, report(v21, r4), http.StatusNotFound, "not-found")
		if lines := securityLinesOf(t, s, "secret_invalid", r4, hostA, ""); len(lines) != 0 {
			t.Errorf("a report on a 2.1 secret wrote secret_invalid: %v", lines)
		}
		unknown := sealedExpress{Token: "tts_" + strings.Repeat("Q", 43)}
		expectProblem(t, report(unknown, r5), http.StatusNotFound, "not-found")
		if lines := securityLinesOf(t, s, "secret_invalid", r5, hostA, ""); len(lines) != 1 {
			t.Errorf("secret_invalid lines of an unknown token: %v", lines)
		}
		mustStatus(t, "deleteTenantSecret", da.call(t, http.MethodDelete, tenantPath(o.tid, "/secrets/"+others[3].ID), nil), http.StatusNoContent)
		expectSecretGone(t, "report on a deleted secret", report(others[3], r4), "deleted")

		// Cross-site and non-JSON reports.
		expectProblem(t, report(others[3], "203.0.113.125", "Origin", "https://evil.example.net"), http.StatusForbidden, "csrf-invalid")
		expectProblem(t, report(others[3], "203.0.113.125", "Sec-Fetch-Site", "cross-site"), http.StatusForbidden, "csrf-invalid")
		expectProblem(t, report(others[3], "203.0.113.125", "Content-Type", "text/plain"), http.StatusUnsupportedMediaType,
			"unsupported-media-type")

		// The administration: the reports name the secret only.
		list := mustStatus(t, "listAbuseReports", da.call(t, http.MethodGet, tenantPath(o.tid, "/abuse-reports"), nil), http.StatusOK)
		expectContract(t, "listAbuseReports", http.MethodGet, tenantPath(o.tid, "/abuse-reports"), list)
		var reports struct {
			Items []map[string]any `json:"items"`
		}
		mustJSON(t, list.body, &reports)
		onSec := 0
		for _, r := range reports.Items {
			if r["secretId"] == sec.ID {
				onSec++
				if r["transferId"] != nil || r["senderEmail"] != nil {
					t.Errorf("report on a secret = %v", r)
				}
			}
		}
		if onSec != reportsPerSecret || len(reports.Items) != reportsPerSecret+reportsPerIP-2 {
			t.Errorf("%d reports on %s, %d in all: %s", onSec, sec.ID, len(reports.Items), list.body)
		}
		rows := o.tenantAudit(t, o.tid)
		if n := len(auditOf(rows, "abuse.reported", "")); n != len(reports.Items) {
			t.Errorf("%d abuse.reported rows, want %d", n, len(reports.Items))
		}
		for _, r := range auditOf(rows, "abuse.reported", "") {
			if !strings.Contains(r.details, `"secretId":"sec_`) {
				t.Errorf("abuse.reported details %s, want the secretId", r.details)
			}
		}

		// The mail to the delegated admin names the sec_ ID only.
		var mail mpMessage
		eventually(t, "the abuse report mail of "+sec.ID, func() bool {
			for _, m := range o.mp.messagesTo(t, da.acct.email) {
				o.mp.get(t, "/api/v1/message/"+m.ID, &mail)
				if strings.Contains(mail.Text, sec.ID) {
					return true
				}
			}
			return false
		})
		// The webhook: signed abuse.reported events of tenant A, with the
		// link to the reports, nothing of the secret.
		var events []receivedRequest
		eventually(t, "the abuse.reported webhook deliveries", func() bool {
			rcv.mu.Lock()
			defer rcv.mu.Unlock()
			events = append(events[:0], rcv.got...)
			return len(events) >= 1
		})
		for _, ev := range events {
			if ev.header.Get("X-TransTeira-Event") != "abuse.reported" {
				t.Errorf("webhook event %v", ev.header)
				continue
			}
			verifySignature(t, ev, hook.Secret)
			var members map[string]json.RawMessage
			mustJSON(t, ev.body, &members)
			checkMembers(t, "WebhookEvent", members, []string{"id", "type", "severity", "occurredAt", "tenant", "counts", "adminUrl"},
				[]string{"id", "type", "severity", "occurredAt", "counts"})
			var p struct {
				Tenant struct {
					ID string `json:"id"`
				} `json:"tenant"`
				AdminURL string `json:"adminUrl"`
			}
			mustJSON(t, ev.body, &p)
			if p.Tenant.ID != o.tid || !strings.HasSuffix(p.AdminURL, "/admin/tenants/"+o.tid+"/abuse-reports") {
				t.Errorf("webhook payload %s", ev.body)
			}
		}
		texts := map[string]string{"mail text": mail.Text, "mail HTML": mail.HTML}
		for i, ev := range events {
			texts["webhook "+strconv.Itoa(i)] = string(ev.body)
		}
		for where, text := range texts {
			for _, v := range append(sec.material(), sec.link(), "bank.example.net") {
				if strings.Contains(text, v) {
					t.Errorf("%s holds %.16s...", where, v)
				}
			}
		}
		o.expectNoSecrets(t, rows)
	})
}

// TestExpressLookupAndPurge: the delegated admin and the auditor of A find
// an express secret from its full pasted link, fragment ignored, or its
// bare token (metadata only, audited as secret.looked_up with the sec_ ID,
// the link and the token never stored, logged nor audited); an unknown
// token is 404 without audit. The purge, refused to the auditor (403
// read-only-role), ends the live anonymous express secrets only (deleted,
// keys destroyed, no orphan key), audited once as secret.express_purged
// with the count; the token secret and the read one are untouched
// (T-392, T-402, T-408, P86).
func TestExpressLookupAndPurge(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		s := o.server
		o.secret(pastedKey)
		da := o.sa.createDelegatedOf(t, "delegate-lookup", o.tid, domainA, adminIP(22))
		aud := o.sa.createAuditorOf(t, "auditor-lookup", o.tid, adminIP(23))
		o.openExpress(t, o.tid, nil)
		_, tok := o.expressTokenOf(t, o.tid, "Vault", []string{tokenNet}, true)
		const creator, reader = "203.0.113.130", "203.0.113.131"
		live1 := createExpressOn(t, s, hostA, creator, sealExpress(t, "live one"), "")
		live2 := createExpressOn(t, s, hostA, creator, sealExpress(t, "live two"), "")
		read := createExpressOn(t, s, hostA, creator, sealExpress(t, "read one"), "")
		byTok := createExpressOn(t, s, hostA, "198.51.100.87", sealExpress(t, "by token"), tok)
		for _, sec := range []sealedExpress{live1, live2, read, byTok} {
			o.secret(sec.material()...)
		}
		mustStatus(t, "reveal", expressOn(t, s, hostA, http.MethodPost, read.link()+"/reveal", reader, read.revealBody()), http.StatusOK)

		lookup := tenantPath(o.tid, "/secrets/lookup")
		find := func(c *adminClient, link string, want int) map[string]any {
			t.Helper()
			resp := c.call(t, http.MethodPost, lookup, map[string]any{"link": link})
			mustStatus(t, "lookupTenantSecret "+link[:20], resp, want)
			expectContract(t, "lookupTenantSecret", http.MethodPost, lookup, resp)
			var out map[string]any
			mustJSON(t, resp.body, &out)
			return out
		}
		for _, c := range []struct {
			who                   *adminClient
			link, id, state, kind string
		}{
			{da, "https://" + hostA + "/s/" + live1.Token + "#k=" + pastedKey, live1.ID, "active", "anonymous"},
			{aud, read.Token, read.ID, "read", "anonymous"},
			{da, "https://" + hostA + "/s/" + byTok.Token + "?utm=x#k=" + pastedKey, byTok.ID, "active", "api_token"},
		} {
			got := find(c.who, c.link, http.StatusOK)
			if got["id"] != c.id || got["state"] != c.state || got["express"] != true || got["creatorKind"] != c.kind ||
				got["senderEmail"] != nil {
				t.Errorf("lookup of %s = %v", c.id, got)
			}
		}
		find(da, "https://"+hostA+"/s/tts_"+strings.Repeat("R", 43)+"#k="+pastedKey, http.StatusNotFound)
		rows := o.tenantAudit(t, o.tid)
		looked := auditOf(rows, "secret.looked_up", "")
		want := map[string]string{live1.ID: "delegate-lookup", read.ID: "auditor-lookup", byTok.ID: "delegate-lookup"}
		if len(looked) != len(want) {
			t.Errorf("secret.looked_up rows = %+v, want %d", looked, len(want))
		}
		for _, r := range looked {
			if who, ok := want[r.objectID]; !ok || r.actor != who || r.actorKind != "admin" {
				t.Errorf("secret.looked_up = %+v", r)
			}
		}

		// The purge: refused to the auditor, then the live anonymous ones.
		purge := tenantPath(o.tid, "/express-secrets/purge")
		resp := aud.call(t, http.MethodPost, purge, nil)
		expectProblem(t, resp, http.StatusForbidden, "read-only-role")
		expectContract(t, "purgeExpressSecrets", http.MethodPost, purge, resp)
		statusOf(t, s, hostA, reader, live1, true)
		resp = mustStatus(t, "purgeExpressSecrets", da.call(t, http.MethodPost, purge, nil), http.StatusOK)
		var out struct {
			Deleted int `json:"deleted"`
		}
		mustJSON(t, resp.body, &out)
		if out.Deleted != 2 {
			t.Errorf("purge deleted %d, want 2", out.Deleted)
		}
		for _, sec := range []sealedExpress{live1, live2} {
			expectSecretGone(t, "purged "+sec.ID, expressOn(t, s, hostA, http.MethodGet, sec.link(), reader, nil), "deleted")
		}
		expectSecretGone(t, "read secret after the purge", expressOn(t, s, hostA, http.MethodGet, read.link(), reader, nil), "read")
		statusOf(t, s, hostA, reader, byTok, false)

		// Cryptographic erasure: the purged rows hold neither text nor key,
		// and no data key is left unreferenced.
		for _, row := range sysQuery(t, e, `SELECT id, state, text_key_id, text_sealed FROM secrets WHERE id IN ('`+
			live1.ID+`', '`+live2.ID+`')`) {
			if row[1] != "deleted" || row[2] != "" || row[3] != "" {
				t.Errorf("purged row %v", row)
			}
		}
		orphans := sysQuery(t, e, `SELECT count(*) FROM wrapped_keys w WHERE purpose = 'dek'
			AND NOT EXISTS (SELECT 1 FROM secrets s WHERE s.text_key_id = w.id OR s.file_key_id = w.id)
			AND NOT EXISTS (SELECT 1 FROM transfer_files tf WHERE tf.dek_key_id = w.id)`)
		if orphans[0][0] != "0" {
			t.Errorf("%s unreferenced data keys after the purge", orphans[0][0])
		}
		rows = o.tenantAudit(t, o.tid)
		purged := auditOf(rows, "secret.express_purged", "")
		if len(purged) != 1 || purged[0].actor != "delegate-lookup" || !strings.Contains(purged[0].details, `"count":2`) {
			t.Errorf("secret.express_purged = %+v", purged)
		}
		for _, sec := range []sealedExpress{live1, live2} {
			if del := auditOf(rows, "secret.deleted", sec.ID); len(del) != 0 {
				t.Errorf("per-secret secret.deleted of the purge: %+v", del)
			}
		}
		// A second purge has nothing left to end.
		resp = mustStatus(t, "second purge", da.call(t, http.MethodPost, purge, nil), http.StatusOK)
		mustJSON(t, resp.body, &out)
		if out.Deleted != 0 {
			t.Errorf("second purge deleted %d", out.Deleted)
		}
		o.expectNoSecrets(t, rows)
	})
}

// TestExpressMaintenanceAndSetup: the maintenance mode refuses the
// creation (503 maintenance with Retry-After, anonymous and by token) and
// leaves the status, the reveal and the reports open; a tenant in the
// setup state refuses it with 503 tenant-in-setup, before the token is
// looked at (T-389).
func TestExpressMaintenanceAndSetup(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		flag := new(maintenanceFlag)
		o := startOpsWith(t, e, serverOptions{flag: flag})
		s := o.server
		o.openExpress(t, o.tid, nil)
		_, tok := o.expressTokenOf(t, o.tid, "Vault", []string{tokenNet}, true)
		const ip = "203.0.113.140"
		sec := createExpressOn(t, s, hostA, ip, sealExpress(t, "before maintenance"), "")

		flag.Store(true)
		for _, hdr := range [][]string{nil, {"Authorization", "Bearer " + tok}} {
			from := ip
			if hdr != nil {
				from = "198.51.100.88"
			}
			p := expectProblem(t, expressOn(t, s, hostA, http.MethodPost, pathExpress, from, sealExpress(t, "x").body(""), hdr...),
				http.StatusServiceUnavailable, "maintenance")
			if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 300 {
				t.Errorf("maintenance retryAfterSeconds = %v", p.RetryAfterSeconds)
			}
		}
		statusOf(t, s, hostA, ip, sec, true)
		mustStatus(t, "report in maintenance", expressOn(t, s, hostA, http.MethodPost, sec.link()+"/abuse-reports", ip, []byte(reportBody)),
			http.StatusAccepted)
		mustStatus(t, "reveal in maintenance", expressOn(t, s, hostA, http.MethodPost, sec.link()+"/reveal", ip, sec.revealBody()),
			http.StatusOK)
		flag.Store(false)
		createExpressOn(t, s, hostA, ip, sealExpress(t, "after maintenance"), "")

		const host = "transfer.entity-express-setup.localhost"
		mustStatus(t, "createTenant in setup", o.sa.call(t, http.MethodPost, pathTenants, map[string]any{
			"name": "Entity Express Setup", "fqdn": host, "defaultLanguage": "en", "storageQuotaBytes": 1 << 30, "setupState": "setup",
		}), http.StatusCreated)
		for _, hdr := range [][]string{nil, {"Authorization", "Bearer " + tok}, {"Authorization", "Bearer tt_" + strings.Repeat("x", 43)}} {
			resp := expressOn(t, s, host, http.MethodPost, pathExpress, "198.51.100.88", sealExpress(t, "x").body(""), hdr...)
			expectProblem(t, resp, http.StatusServiceUnavailable, "tenant-in-setup")
			expectContract(t, opCreateExpress, http.MethodPost, pathExpress, resp)
		}
	})
}

// TestExpressUntrustedForwardedFor: an X-Forwarded-For header from a peer
// that is not a trusted proxy is ignored, so every anonymous creation
// counts on the TCP peer whatever address it claims: a client can neither
// dodge the per-IP limit nor charge a third party, and the security log
// names the peer (T-394).
func TestExpressUntrustedForwardedFor(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOpsWith(t, e, serverOptions{trustedProxies: "192.0.2.254"})
		s := o.server
		o.openExpress(t, o.tid, nil)
		for i := range expressPerIPDefault {
			createExpressOn(t, s, hostA, "203.0.113."+strconv.Itoa(150+i), sealExpress(t, "claimed"), "")
		}
		expectProblem(t, expressOn(t, s, hostA, http.MethodPost, pathExpress, "203.0.113.170", sealExpress(t, "x").body("")),
			http.StatusTooManyRequests, "rate-limited")
		lines := eventsOf(t, s.securityLines(t), "rate_limited")
		if len(lines) != 1 || lines[0].ip != "127.0.0.1" || strings.TrimSpace(lines[0].fields) != `scope="express_ip"` {
			t.Errorf("rate_limited lines = %v, want one express_ip line naming the peer 127.0.0.1", lines)
		}
		rows := o.tenantAudit(t, o.tid)
		for _, r := range auditOf(rows, "secret.created", "") {
			if r.ip != "127.0.0.1" {
				t.Errorf("secret.created from the claimed address %s", r.ip)
			}
		}
	})
}

// TestExpressConfigImport: the export carries the express settings as
// stored, and an import, even of a document saying expressEnabled true,
// always creates the tenant with the anonymous mode off and the exported
// limits; a limit out of range is 422 import-invalid (T-403, P92).
func TestExpressConfigImport(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.openExpress(t, o.tid, map[string]any{"expressPerHourPerIp": 7, "expressPerHourPerToken": 70, "expressMaxPending": 700})
		exp := mustStatus(t, "exportTenantConfig", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/export"), nil), http.StatusOK)
		var doc map[string]any
		mustJSON(t, exp.body, &doc)
		ss, _ := doc["secretSettings"].(map[string]any)
		if ss["expressEnabled"] != true || ss["expressPerHourPerIp"] != float64(7) || ss["expressPerHourPerToken"] != float64(70) ||
			ss["expressMaxPending"] != float64(700) {
			t.Fatalf("exported secret settings = %v", ss)
		}
		resp := mustStatus(t, "importTenant", o.sa.call(t, http.MethodPost, pathImport,
			importBody("Entity Express Imported", "transfer.entity-express.localhost", string(exp.body))), http.StatusCreated)
		var created struct {
			ID string `json:"id"`
		}
		mustJSON(t, resp.body, &created)
		got := mustStatus(t, "getSecretSettings", o.sa.call(t, http.MethodGet, tenantPath(created.ID, "/secret-settings"), nil), http.StatusOK)
		var settings map[string]any
		mustJSON(t, got.body, &settings)
		if settings["expressEnabled"] != false || settings["expressPerHourPerIp"] != float64(7) ||
			settings["expressPerHourPerToken"] != float64(70) || settings["expressMaxPending"] != float64(700) {
			t.Errorf("imported settings = %s", got.body)
		}
		ss["expressMaxPending"] = 0
		resp = o.sa.call(t, http.MethodPost, pathImport, importBody("Entity Express Bad", "transfer.entity-express-bad.localhost", mustMarshal(doc)))
		expectProblem(t, resp, http.StatusUnprocessableEntity, "import-invalid")
		expectContract(t, "importTenant", http.MethodPost, pathImport, resp)
		var fp fieldProblem
		mustJSON(t, resp.body, &fp)
		if len(fp.Errors) == 0 || fp.Errors[0].Field != "/config/secretSettings/expressMaxPending" {
			t.Errorf("out-of-range import errors = %+v", fp.Errors)
		}
	})
}
