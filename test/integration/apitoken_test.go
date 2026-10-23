package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the API tokens (CLAUDE.md sections 4.1, 16.2, 16.3
// and 16.4; api/openapi.yaml security scheme apiToken; threat model T-68 to
// T-73): a real server, the fake clamd of antivirustest, Mailpit, on
// SQLite and PostgreSQL.

// TestAPITokenDeposit: an admin creates a token (the secret is shown once,
// never listed); a script holding only the token deposits a multi-MB file
// in tus chunks, survives a cut connection by resuming from the offset
// reported by HEAD, finalizes, and the recipient gets the mail and
// downloads the file whose SHA-256 matches. The audit log records
// api_token.created, a single api_token.used with the sender address as
// actor (a depositor, found by the GDPR search on that address) and the
// transfer events with the token as actor; the admin view shows the api
// origin and the token;
// lastUsedAt is set; the secret appears nowhere else.
func TestAPITokenDeposit(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		before := time.Now().Add(-time.Second)
		tok, secret := o.sa.createToken(t, o.tid, "Nightly export", []string{scriptNet}, nil)
		if tok.CreatedBy != superName || tok.ExpiresAt != nil || tok.CreatedAt.Before(before) {
			t.Errorf("created token = %+v, want created by %s now, without expiry", tok, superName)
		}
		listed := tokenIn(t, o.sa.listTokens(t, o.tid), tok.ID)
		if listed.Prefix != tok.Prefix || listed.LastUsedAt != nil {
			t.Errorf("listed token = %+v, want prefix %s and no use yet", listed, tok.Prefix)
		}

		script := o.scriptClient(secret, scriptIP)
		sender := uniqueEmail(t, "erp", domainA)
		r := uniqueEmail(t, "rcpt", "example.net")
		const (
			size  = 6<<20 + 12345
			chunk = 1 << 20
			seed  = 41
		)
		content := seededBytes(t, seed, size)
		tr := script.mustTokenCreate(t, sender, transferCreate{
			Recipients: []string{r}, ExpiryDays: 7, Files: []fileDecl{{Name: "export.csv", Size: size}},
		})
		if tr.SenderEmail != sender || !slices.Equal(tr.Recipients, []string{r}) || tr.Status != "uploading" {
			t.Errorf("token transfer = %+v, want uploading from %s to %s", tr, sender, r)
		}
		url := tr.Files[0].UploadURL

		// Two chunks, then a connection cut in the middle of the third
		// (half-close): the server keeps every byte received.
		script.mustPatch(t, url, 0, content[:chunk])
		script.mustPatch(t, url, chunk, content[chunk:2*chunk])
		const sent = chunk/2 + 7
		conn := script.rawPatch(t, url, 2*chunk, size-2*chunk)
		if _, err := conn.Write(content[2*chunk : 2*chunk+sent]); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		expectTusError(t, "cut PATCH", readRawResponse(t, conn), http.StatusBadRequest)
		off, length := script.offsetOf(t, url)
		if off != 2*chunk+sent || length != size {
			t.Fatalf("offset after the cut = %d/%d, want %d/%d", off, length, 2*chunk+sent, size)
		}
		// An abrupt reset: the offset reported afterwards is between the
		// previous one and the bytes sent.
		const sent2 = 300_000
		conn = script.rawPatch(t, url, off, size-off)
		if _, err := conn.Write(content[off : off+sent2]); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetLinger(0)
		_ = conn.Close()
		script.waitUnlocked(t, tr.ID)
		off2, _ := script.offsetOf(t, url)
		if off2 < off || off2 > off+sent2 {
			t.Fatalf("offset after the reset = %d, want in [%d, %d]", off2, off, off+sent2)
		}
		// Resume to the end, chunk by chunk.
		for off = off2; off < size; {
			n := min(int64(chunk), size-off)
			script.mustPatch(t, url, off, content[off:off+n])
			off += n
		}
		if resp := script.tokenFinalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize with the token: %d %s", resp.status, resp.body)
		}
		got := script.waitStatus(t, tr.ID, "available", waitTimeout)
		if got.Files[0].Sha256 != sha256Hex(content) || got.Files[0].ScanStatus != "clean" {
			t.Errorf("available file = %+v, want sha256 %s and clean", got.Files[0], sha256Hex(content))
		}
		dl := tokenOf(t, hostA, got.DownloadURL)

		// The recipient mail, then the download.
		o.waitMailSent(t, r)
		msg := o.mp.find(t, r, func(mpMessage) bool { return true })
		if !strings.Contains(msg.Text, got.DownloadURL) || !strings.Contains(msg.Text, sha256Hex(content)) {
			t.Errorf("recipient mail lacks the link or the SHA-256:\n%s", msg.Text)
		}
		rec := o.newRecipient(1)
		resp := rec.get(t, filePath(dl, tr.Files[0].ID), nil)
		expectFile(t, "download", resp, "export.csv", content)
		if sha256Hex(resp.body) != sha256Hex(content) {
			t.Errorf("downloaded SHA-256 %s, want %s", sha256Hex(resp.body), sha256Hex(content))
		}

		// Audit trail.
		events := o.sa.tenantEvents(t, o.tid, "")
		for act, want := range map[string]int{actTokenCreated: 1, actTokenUsed: 1, actTransferCreated: 1, actTransferFinalized: 1} {
			got := ofAction(events, act)
			if len(got) != want {
				t.Errorf("%d %s events, want %d; actions: %v", len(got), act, want, eventActions(events))
				continue
			}
			ev := got[0]
			switch act {
			case actTokenCreated:
				expectEvent(t, ev, o.tid, "admin", superName, adminIP(10), "api_token", tok.ID)
			case actTokenUsed:
				expectEvent(t, ev, o.tid, "depositor", sender, scriptIP, "api_token", tok.ID)
				if ev.Details["transferId"] != tr.ID {
					t.Errorf("%s details = %v, want transferId %s", act, ev.Details, tr.ID)
				}
			default:
				expectEvent(t, ev, o.tid, "api_token", tok.ID, scriptIP, "transfer", tr.ID)
				if act == actTransferCreated && ev.Details["origin"] != "api" {
					t.Errorf("%s details = %v, want origin api", act, ev.Details)
				}
			}
			expectNoAddressIn(t, ev)
		}

		// The GDPR search on the sender address finds api_token.used.
		if sum := o.sa.searchSubject(t, o.tid, sender); sum.AuditEvents != 1 || sum.TransfersAsSender != 1 {
			t.Errorf("data subject summary of the sender = %+v, want 1 audit event and 1 transfer", sum)
		}

		// The transfer as the administration sees it.
		raw := mustStatus(t, "getTenantTransfer", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers/"+tr.ID), nil), http.StatusOK)
		var adm adminTransferAPI
		mustJSON(t, raw.body, &adm)
		if adm.Origin != "api" || adm.APITokenID == nil || *adm.APITokenID != tok.ID || adm.SenderEmail != sender ||
			adm.SenderIP == nil || *adm.SenderIP != scriptIP {
			t.Errorf("admin transfer = %s, want origin api, apiTokenId %s, sender %s from %s", raw.body, tok.ID, sender, scriptIP)
		}
		listed = tokenIn(t, o.sa.listTokens(t, o.tid), tok.ID)
		if listed.LastUsedAt == nil || listed.LastUsedAt.Before(tok.CreatedAt.Truncate(time.Second)) || listed.LastUsedAt.After(time.Now()) {
			t.Errorf("lastUsedAt = %v, want set after the creation %v", listed.LastUsedAt, tok.CreatedAt)
		}

		// The secret only ever appeared in the 201 of the creation.
		for what, body := range map[string][]byte{"admin transfer": raw.body, "sender transfer": mustBody(t, script.getTransfer(t, tr.ID))} {
			if strings.Contains(string(body), secret) {
				t.Errorf("%s holds the token secret", what)
			}
		}
		o.expectNoSecrets(t, o.tenantAudit(t, o.tid))
	})
}

// mustBody returns the body of a 200 answer.
func mustBody(t *testing.T, resp response) []byte {
	t.Helper()
	return mustStatus(t, "request", resp, http.StatusOK).body
}

// TestAPITokenInvalid: a revoked, expired, unknown or malformed token gets
// 401 invalid-credentials (bodyless on the tus operations) whatever the
// client IP, and an api_token_invalid line without the token; after
// tokenFailureLimit failures, the IP is locked out (429, a valid token
// included) with a rate_limited line of scope api_token.
func TestAPITokenInvalid(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		_, validSecret := o.sa.createToken(t, o.tid, "Valid", []string{"0.0.0.0/0", "::/0"}, nil)
		tr := o.scriptClient(validSecret, scriptIP).mustTokenCreate(t, uniqueEmail(t, "erp", domainA), oneFile("held.bin", 10))
		upload := tr.Files[0].UploadURL

		revoked, revokedSecret := o.sa.createToken(t, o.tid, "Revoked", []string{"0.0.0.0/0", "::/0"}, nil)
		o.sa.revokeToken(t, o.tid, revoked.ID)
		if got := tokenIn(t, o.sa.listTokens(t, o.tid), revoked.ID); got.RevokedAt == nil {
			t.Errorf("revoked token = %+v, want revokedAt set", got)
		}
		in := time.Now().Add(time.Hour)
		expired, expiredSecret := o.sa.createToken(t, o.tid, "Expired", []string{"0.0.0.0/0", "::/0"}, &in)
		// No clock is injectable into the running server: age the token in
		// the database, as if its expiry had passed.
		execSystem(t, e, "UPDATE api_tokens SET expires_at = "+millis(-time.Minute)+" WHERE id = '"+expired.ID+"'")
		unknown := newUnknownSecret(t)
		o.secret(unknown)

		cases := []struct {
			name   string
			header []string // Authorization values
		}{
			{"revoked", []string{"Bearer " + revokedSecret}},
			{"expired", []string{"Bearer " + expiredSecret}},
			{"unknown", []string{"Bearer " + unknown}},
			{"lowercase scheme, unknown", []string{"bearer " + unknown}},
			{"malformed", []string{"Bearer not-a-token"}},
			{"truncated", []string{"Bearer " + validSecret[:20]}},
			{"empty", []string{"Bearer"}},
			{"two headers", []string{"Bearer " + validSecret, "Bearer " + validSecret}},
		}
		for i, c := range cases {
			ip := "198.51.100." + strconv.Itoa(100+i)
			cl := &depositor{d: o.depositEnv, host: hostA, ip: ip}
			auth := http.Header{"Authorization": c.header}
			expectProblem(t, cl.send(t, http.MethodPost, pathTransfers, `{"senderEmail":"x@`+domainA+`","expiryDays":1,"recipients":["r@example.net"],"files":[{"name":"a","size":1}]}`, auth),
				http.StatusUnauthorized, "invalid-credentials")
			expectProblem(t, cl.send(t, http.MethodGet, pathTransfers+"/"+tr.ID, "", auth), http.StatusUnauthorized, "invalid-credentials")
			for _, m := range []string{http.MethodHead, http.MethodPatch, http.MethodDelete} {
				var (
					body io.Reader
					n    int64
				)
				if m == http.MethodPatch {
					body, n = strings.NewReader("x"), 1
				}
				resp := cl.tusRequest(t, m, upload, func(h http.Header) {
					h["Authorization"] = c.header
					if m == http.MethodPatch {
						h.Set(hdrUploadOffset, "0")
					}
				}, body, n)
				expectTusError(t, c.name+" "+m, resp, http.StatusUnauthorized)
				if got := resp.header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
					t.Errorf("%s %s: WWW-Authenticate %q, want a Bearer challenge", c.name, m, got)
				}
			}
			if n := len(tokenLogLines(t, o.server, "api_token_invalid", ip, hostA)); n != 5 {
				t.Errorf("%s: %d api_token_invalid lines from %s, want 5", c.name, n, ip)
			}
		}
		// Another scheme is not a token: the deposit session path answers
		// unauthenticated, without api_token_invalid line.
		basic := &depositor{d: o.depositEnv, host: hostA, ip: "198.51.100.99"}
		expectProblem(t, basic.send(t, http.MethodGet, pathTransfers+"/"+tr.ID, "", http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}}),
			http.StatusUnauthorized, "unauthenticated")
		if n := len(tokenLogLines(t, o.server, "api_token_invalid", basic.ip, hostA)); n != 0 {
			t.Errorf("%d api_token_invalid lines for a Basic header, want 0", n)
		}
		// The held transfer is intact.
		if got := o.scriptClient(validSecret, scriptIP).mustGet(t, tr.ID); got.Status != "uploading" {
			t.Errorf("held transfer status %q, want uploading", got.Status)
		}

		// A flood from one IP: locked out after tokenFailureLimit failures.
		const floodIP = "198.51.100.250"
		flood := o.scriptClient(unknown, floodIP)
		for range tokenFailureLimit {
			expectProblem(t, flood.getTransfer(t, tr.ID), http.StatusUnauthorized, "invalid-credentials")
		}
		p := expectProblem(t, flood.getTransfer(t, tr.ID), http.StatusTooManyRequests, "rate-limited")
		if ra := headerInt(t, flood.getTransfer(t, tr.ID), hdrRetryAfter); ra <= 0 || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds <= 0 {
			t.Errorf("Retry-After = %d, retryAfterSeconds = %v, want positive", ra, p.RetryAfterSeconds)
		}
		// The valid token still passes from the locked-out IP (shared
		// egress), while invalid ones keep getting 429, bodyless on tus.
		lockedValid := o.scriptClient(validSecret, floodIP)
		if got := lockedValid.mustGet(t, tr.ID); got.ID != tr.ID {
			t.Errorf("valid token from the locked-out IP got %+v", got)
		}
		expectProblem(t, flood.getTransfer(t, tr.ID), http.StatusTooManyRequests, "rate-limited")
		expectTusError(t, "HEAD from a locked-out IP", o.scriptClient(unknown, floodIP).head(t, upload), http.StatusTooManyRequests)
		if n := len(tokenLogLines(t, o.server, "api_token_invalid", floodIP, hostA)); n != tokenFailureLimit {
			t.Errorf("%d api_token_invalid lines from the flood, want %d (none once locked out)", n, tokenFailureLimit)
		}
		limited := tokenLogLines(t, o.server, "rate_limited", floodIP, hostA)
		if len(limited) != 1 || limited[0].fields != ` scope="api_token"` {
			t.Errorf("rate_limited lines from the flood = %+v, want one of scope api_token (throttled)", limited)
		}
		// Another IP is not affected.
		if got := o.scriptClient(validSecret, scriptIP).mustGet(t, tr.ID); got.ID != tr.ID {
			t.Errorf("valid token from another IP got %+v", got)
		}
		noSecretInLogs(t, o.server, validSecret, revokedSecret, expiredSecret, unknown)
		o.expectNoSecrets(t, o.tenantAudit(t, o.tid))
	})
}

// TestAPITokenIPNotAllowed: a valid token used from outside its allowed
// ranges gets 403 ip-not-allowed (bodyless on tus), a deposit_refused line
// of reason ip, no failure count and no recorded use.
func TestAPITokenIPNotAllowed(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		tok, secret := o.sa.createToken(t, o.tid, "Restricted", []string{scriptNet}, nil)
		// More refusals than the failure limit: they are not failures.
		stranger := o.scriptClient(secret, strangerIP)
		for range tokenFailureLimit + 2 {
			expectProblem(t, stranger.tokenCreate(t, uniqueEmail(t, "erp", domainA), oneFile("a.bin", 1), ""), http.StatusForbidden, "ip-not-allowed")
		}
		expectProblem(t, stranger.getTransfer(t, "trf_01JABCJ5M6N7P8Q9R0S1T2V3V4"), http.StatusForbidden, "ip-not-allowed")
		expectTusError(t, "HEAD from outside the token ranges", stranger.head(t, pathUploads+"/upl_01JABCJ5M6N7P8Q9R0S1T2V3V4"), http.StatusForbidden)
		refused := tokenLogLines(t, o.server, "deposit_refused", strangerIP, hostA)
		if len(refused) != tokenFailureLimit+4 {
			t.Errorf("%d deposit_refused lines from %s, want %d", len(refused), strangerIP, tokenFailureLimit+4)
		}
		for _, l := range refused {
			if l.fields != ` reason="ip"` {
				t.Errorf("deposit_refused line %q, want reason ip", l.raw)
			}
		}
		if n := len(tokenLogLines(t, o.server, "api_token_invalid", strangerIP, hostA)); n != 0 {
			t.Errorf("%d api_token_invalid lines for a valid token, want 0", n)
		}
		if got := tokenIn(t, o.sa.listTokens(t, o.tid), tok.ID); got.LastUsedAt != nil {
			t.Errorf("lastUsedAt = %v after refused uses, want none", got.LastUsedAt)
		}
		// Not a failure of the token: the IP is not locked out, and the
		// token works from its range.
		o.scriptClient(secret, scriptIP).mustTokenCreate(t, uniqueEmail(t, "erp", domainA), oneFile("ok.bin", 1))
		noSecretInLogs(t, o.server, secret)
	})
}

// TestAPITokenSenderEmail: with a token, senderEmail is required, must be
// a plain address of an internal domain of the tenant and not blocklisted;
// with a deposit session it is refused.
func TestAPITokenSenderEmail(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		_, secret := o.sa.createToken(t, o.tid, "Sender checks", []string{scriptNet}, nil)
		script := o.scriptClient(secret, scriptIP)
		body := oneFile("a.bin", 1)

		p := expectTransferProblem(t, script.tokenCreate(t, "", body, ""), http.StatusBadRequest, "validation-failed")
		expectFieldCode(t, p, "/senderEmail", "required")
		addr := uniqueEmail(t, "erp", domainA)
		p = expectTransferProblem(t, script.tokenCreate(t, "ERP <"+addr+">", body, ""), http.StatusBadRequest, "validation-failed")
		expectFieldCode(t, p, "/senderEmail", "invalid-email")
		p = expectTransferProblem(t, script.tokenCreate(t, "not-an-address", body, ""), http.StatusBadRequest, "validation-failed")
		expectFieldCode(t, p, "/senderEmail", "invalid-email")
		noRcpt := body
		noRcpt.Recipients = nil
		p = expectTransferProblem(t, script.tokenCreate(t, addr, noRcpt, ""), http.StatusBadRequest, "validation-failed")
		expectFieldCode(t, p, "/recipients", "required")

		before := len(reasons(t, o.server))
		expectProblem(t, script.tokenCreate(t, uniqueEmail(t, "erp", externalDomain), body, ""), http.StatusForbidden, "deposit-not-allowed")
		blocked := uniqueEmail(t, "blocked", domainA)
		o.block(t, store.BlockEmail, blocked)
		expectProblem(t, script.tokenCreate(t, blocked, body, ""), http.StatusForbidden, "deposit-not-allowed")
		if got := reasons(t, o.server)[before:]; !slices.Equal(got, []string{"domain", "blocklist"}) {
			t.Errorf("deposit_refused reasons = %v, want [domain blocklist]", got)
		}
		// The domain check is case-insensitive and the address normalized.
		tr := script.mustTokenCreate(t, strings.ToUpper(addr), body)
		if tr.SenderEmail != addr {
			t.Errorf("sender %q, want the normalized %q", tr.SenderEmail, addr)
		}

		// A deposit session may not name a sender.
		alice, aliceEmail := internalSession(t, o.depositEnv, "alice")
		b := `{"senderEmail":"` + aliceEmail + `","expiryDays":1,"recipients":["r@example.net"],"files":[{"name":"a.bin","size":1}]}`
		p = expectTransferProblem(t, alice.send(t, http.MethodPost, pathTransfers, b, alice.withCSRF()), http.StatusBadRequest, "validation-failed")
		expectFieldCode(t, p, "/senderEmail", "not-allowed")
		// No token audit event for the refused creations.
		if used := o.sa.tenantEvents(t, o.tid, actTokenUsed); len(used) != 1 {
			t.Errorf("%d api_token.used events, want 1 (the accepted creation)", len(used))
		}
	})
}

// TestAPITokenAllowedSenders: a token restricted to allowed senders refuses
// any other internal address (403 deposit-not-allowed, security log reason
// domain) and accepts an allowed address or an address of an allowed
// domain (201); a subdomain is not covered, the internal domains still
// apply, the restriction is re-checked on finalize, and an empty list
// lifts it. The admin audit records the number of senders, never them.
func TestAPITokenAllowedSenders(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		allowed := uniqueEmail(t, "erp", domainA)
		tok, secret := o.sa.createTokenFor(t, o.tid, "Restricted", []string{scriptNet}, nil,
			[]string{" " + strings.ToUpper(allowed) + " "})
		if !slices.Equal(tok.AllowedSenders, []string{allowed}) {
			t.Fatalf("created allowedSenders = %v, want [%s]", tok.AllowedSenders, allowed)
		}
		script := o.scriptClient(secret, scriptIP)
		body := oneFile("a.bin", 1)

		before := len(reasons(t, o.server))
		other := uniqueEmail(t, "other", domainA)
		expectProblem(t, script.tokenCreate(t, other, body, ""), http.StatusForbidden, "deposit-not-allowed")
		// Match by address (normalized).
		byAddress := script.mustTokenCreate(t, strings.ToUpper(allowed), body)
		if byAddress.SenderEmail != allowed {
			t.Errorf("sender %q, want %q", byAddress.SenderEmail, allowed)
		}

		// Match by domain: the internal domain itself, not a subdomain, and
		// an allowed domain outside the internal domains stays refused.
		resp := mustStatus(t, "updateApiToken", o.sa.updateToken(t, o.tid, tok.ID,
			map[string]any{"allowedSenders": []string{strings.ToUpper(domainA), externalDomain}}), http.StatusOK)
		var upd apiTokenJSON
		mustJSON(t, resp.body, &upd)
		if !slices.Equal(upd.AllowedSenders, []string{domainA, externalDomain}) {
			t.Errorf("updated allowedSenders = %v", upd.AllowedSenders)
		}
		byDomain := script.mustTokenCreate(t, other, body)
		if byDomain.SenderEmail != other {
			t.Errorf("sender %q, want %q", byDomain.SenderEmail, other)
		}
		expectProblem(t, script.tokenCreate(t, uniqueEmail(t, "x", externalDomain), body, ""), http.StatusForbidden, "deposit-not-allowed")
		mustStatus(t, "updateApiToken", o.sa.updateToken(t, o.tid, tok.ID,
			map[string]any{"allowedSenders": []string{"sub." + domainA}}), http.StatusOK)
		expectProblem(t, script.tokenCreate(t, other, body, ""), http.StatusForbidden, "deposit-not-allowed")

		// Finalize reads the current list: the address is no longer allowed.
		script.mustPatch(t, byDomain.Files[0].UploadURL, 0, []byte("x"))
		expectProblem(t, script.tokenFinalize(t, byDomain.ID), http.StatusForbidden, "deposit-not-allowed")
		if got := reasons(t, o.server)[before:]; !slices.Equal(got, []string{"domain", "domain", "domain", "domain"}) {
			t.Errorf("deposit_refused reasons = %v, want four domain", got)
		}
		// An empty list lifts the restriction.
		resp = mustStatus(t, "updateApiToken", o.sa.updateToken(t, o.tid, tok.ID,
			map[string]any{"allowedSenders": []string{}}), http.StatusOK)
		mustJSON(t, resp.body, &upd)
		if upd.AllowedSenders == nil || len(upd.AllowedSenders) != 0 {
			t.Errorf("cleared allowedSenders = %#v, want []", upd.AllowedSenders)
		}
		if r := script.tokenFinalize(t, byDomain.ID); r.status != http.StatusAccepted {
			t.Errorf("finalize without restriction: %d %s", r.status, r.body)
		}

		// Malformed lists, null and unknown members are refused.
		for what, c := range map[string]struct {
			body  any
			field string
		}{
			"bad entry":  {map[string]any{"allowedSenders": []string{domainA, "not a domain"}}, "/allowedSenders/1"},
			"duplicate":  {map[string]any{"allowedSenders": []string{domainA, strings.ToUpper(domainA)}}, "/allowedSenders/1"},
			"null":       {map[string]any{"allowedSenders": nil}, "/allowedSenders"},
			"unknown":    {map[string]any{"name": "x", "senders": []string{}}, "/senders"},
			"wrong type": {map[string]any{"allowedSenders": domainA}, "/allowedSenders"},
		} {
			r := o.sa.updateToken(t, o.tid, tok.ID, c.body)
			p := expectTransferProblem(t, r, http.StatusBadRequest, "validation-failed")
			if len(p.Errors) != 1 || p.Errors[0].Field != c.field {
				t.Errorf("%s: errors %+v, want %s", what, p.Errors, c.field)
			}
		}

		// The admin audit holds the number of senders, never an address.
		created := ofAction(o.sa.tenantEvents(t, o.tid, actTokenCreated), actTokenCreated)
		updated := o.sa.tenantEvents(t, o.tid, "api_token.updated")
		if len(created) != 1 || created[0].Details["senderCount"] != float64(1) || len(updated) != 3 {
			t.Errorf("token audit: created %+v, %d updated", created, len(updated))
		}
		for _, ev := range append(created, updated...) {
			expectNoAddressIn(t, ev)
			if raw, _ := json.Marshal(ev.Details); strings.Contains(string(raw), domainA) {
				t.Errorf("%s details hold a sender: %s", ev.Action, raw)
			}
		}
	})
}

// TestAPITokenOwnership: a transfer created by a token is reachable by that
// token only: not by a deposit session of the same address, nor by another
// token; the token reaches no session transfer. A token is unknown on the
// host of another tenant (401) and the admin host never accepts it.
func TestAPITokenOwnership(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		_, secret1 := o.sa.createToken(t, o.tid, "First", []string{scriptNet}, nil)
		_, secret2 := o.sa.createToken(t, o.tid, "Second", []string{scriptNet}, nil)
		alice, aliceEmail := internalSession(t, o.depositEnv, "alice")
		tok1 := o.scriptClient(secret1, scriptIP)
		tok2 := o.scriptClient(secret2, scriptIP)
		tokTr := tok1.mustTokenCreate(t, aliceEmail, oneFile("token.bin", 1000))
		sessTr := alice.mustCreate(t, oneFile("session.bin", 1000))

		// expectUnreachable asserts that c reaches none of the operations of
		// the transfer tr.
		expectUnreachable := func(who string, c *depositor, tr senderTransferJSON, session bool) {
			t.Helper()
			finalize, cancel := c.tokenFinalize, c.tokenCancel
			if session {
				finalize, cancel = c.finalize, c.cancelTransfer
			}
			expectProblem(t, c.getTransfer(t, tr.ID), http.StatusNotFound, "not-found")
			expectProblem(t, finalize(t, tr.ID), http.StatusNotFound, "not-found")
			expectProblem(t, cancel(t, tr.ID), http.StatusNotFound, "not-found")
			up := tr.Files[0].UploadURL
			expectTusError(t, who+" HEAD", c.head(t, up), http.StatusNotFound)
			expectTusError(t, who+" PATCH", c.patch(t, up, 0, []byte("x")), http.StatusNotFound)
			expectTusError(t, who+" DELETE", c.terminate(t, up), http.StatusNotFound)
		}
		expectUnreachable("session of the same address", alice, tokTr, true)
		expectUnreachable("token on a session transfer", tok1, sessTr, false)
		expectUnreachable("another token", tok2, tokTr, false)
		// A request carrying both a token and the session cookie takes the
		// token path only.
		both := &depositor{d: o.depositEnv, host: hostA, ip: scriptIP, bearer: secret2, cookie: alice.cookie, csrf: alice.csrf}
		expectProblem(t, both.getTransfer(t, sessTr.ID), http.StatusNotFound, "not-found")
		// Both transfers are intact for their owners.
		if got := tok1.mustGet(t, tokTr.ID); got.Status != "uploading" || got.Files[0].UploadOffset == nil || *got.Files[0].UploadOffset != 0 {
			t.Errorf("token transfer = %+v, want uploading at offset 0", got)
		}
		if got := alice.mustGet(t, sessTr.ID); got.Status != "uploading" {
			t.Errorf("session transfer status %q, want uploading", got.Status)
		}

		// The token of A on the host of B.
		onB := &depositor{d: o.depositEnv, host: hostB, ip: scriptIP, bearer: secret1}
		expectProblem(t, onB.tokenCreate(t, uniqueEmail(t, "erp", domainB), oneFile("b.bin", 1), ""), http.StatusUnauthorized, "invalid-credentials")
		expectProblem(t, onB.getTransfer(t, tokTr.ID), http.StatusUnauthorized, "invalid-credentials")
		if n := len(tokenLogLines(t, o.server, "api_token_invalid", scriptIP, hostB)); n != 2 {
			t.Errorf("%d api_token_invalid lines on %s, want 2", n, hostB)
		}

		// The admin host: no deposit route, no admin access by token.
		bearer := http.Header{"Authorization": {"Bearer " + secret1}, hdrXFF: {scriptIP}}
		resp := o.do(t, request{
			method: http.MethodPost, path: pathTransfers, host: adminHost, headers: bearer,
			body: []byte(`{"senderEmail":"` + aliceEmail + `","expiryDays":1,"recipients":["r@example.net"],"files":[{"name":"a","size":1}]}`),
		})
		expectProblem(t, resp, http.StatusNotFound, "not-found")
		expectProblem(t, o.do(t, request{path: pathTransfers + "/" + tokTr.ID, host: adminHost, headers: bearer}), http.StatusNotFound, "not-found")
		for _, path := range []string{pathAdminMe, tokensPath(o.tid), tenantPath(o.tid, "/transfers/"+tokTr.ID)} {
			expectProblem(t, o.do(t, request{path: path, host: adminHost, headers: bearer}), http.StatusUnauthorized, "unauthenticated")
		}
		noSecretInLogs(t, o.server, secret1, secret2)
	})
}

// TestAPITokenOpenCapAndIdempotency: the cap on unfinished transfers
// (TT_MAX_OPEN_TRANSFERS) is counted per token, apart from the deposit
// session of the same address and from the other tokens; an
// Idempotency-Key is scoped to its token, apart from the session using the
// same key with the same address.
func TestAPITokenOpenCapAndIdempotency(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOpsWith(t, e, serverOptions{env: map[string]string{config.EnvMaxOpenTransfers: "2"}})
		_, secret1 := o.sa.createToken(t, o.tid, "Capped", []string{scriptNet}, nil)
		_, secret2 := o.sa.createToken(t, o.tid, "Other", []string{scriptNet}, nil)
		alice, aliceEmail := internalSession(t, o.depositEnv, "alice")
		tok1 := o.scriptClient(secret1, scriptIP)
		tok2 := o.scriptClient(secret2, scriptIP)

		first := tok1.mustTokenCreate(t, aliceEmail, oneFile("one.bin", 10))
		tok1.mustTokenCreate(t, uniqueEmail(t, "other", domainA), oneFile("two.bin", 10))
		resp := tok1.tokenCreate(t, aliceEmail, oneFile("three.bin", 10), "")
		p := expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
		if resp.header.Get(hdrRetryAfter) != "3600" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
			t.Errorf("Retry-After = %q, retryAfterSeconds = %v, want 3600", resp.header.Get(hdrRetryAfter), p.RetryAfterSeconds)
		}
		limited := tokenLogLines(t, o.server, "rate_limited", scriptIP, hostA)
		if len(limited) != 1 || limited[0].fields != ` scope="open_transfers"` {
			t.Errorf("rate_limited lines = %+v, want one of scope open_transfers", limited)
		}
		// The session of the same address and another token are not capped
		// by the token's transfers.
		alice.mustCreate(t, oneFile("session.bin", 10))
		tok2.mustTokenCreate(t, aliceEmail, oneFile("other-token.bin", 10))
		// Canceling frees a slot of the token.
		if resp := tok1.tokenCancel(t, first.ID); resp.status != http.StatusNoContent {
			t.Fatalf("cancel with the token: %d %s", resp.status, resp.body)
		}
		tok1.mustTokenCreate(t, aliceEmail, oneFile("after-cancel.bin", 10))

		// Idempotency keys, with fresh tokens and a fresh session.
		_, secret3 := o.sa.createToken(t, o.tid, "Idempotent", []string{scriptNet}, nil)
		_, secret4 := o.sa.createToken(t, o.tid, "Idempotent too", []string{scriptNet}, nil)
		tok3 := o.scriptClient(secret3, scriptIP)
		tok4 := o.scriptClient(secret4, scriptIP)
		bob, bobEmail := internalSession(t, o.depositEnv, "bob")
		const key = "nightly-2026-10-23" // gitleaks:allow (idempotency key, not a secret)
		body := oneFile("export.csv", 100)
		sess := bob.createTransfer(t, body, key)
		if sess.status != http.StatusCreated {
			t.Fatalf("session create with the key: %d %s", sess.status, sess.body)
		}
		sessTr := parseTransfer(t, sess.body)
		create := func(c *depositor) senderTransferJSON {
			t.Helper()
			resp := c.tokenCreate(t, bobEmail, body, key)
			if resp.status != http.StatusCreated {
				t.Fatalf("token create with the key: %d %s", resp.status, resp.body)
			}
			return parseTransfer(t, resp.body)
		}
		t3 := create(tok3)
		if t3.ID == sessTr.ID {
			t.Error("the token replaying the session's key got the session's transfer")
		}
		if again := create(tok3); again.ID != t3.ID {
			t.Errorf("token replay = %s, want %s", again.ID, t3.ID)
		}
		if t4 := create(tok4); t4.ID == t3.ID || t4.ID == sessTr.ID {
			t.Errorf("another token with the key got %s, want a new transfer", t4.ID)
		}
		if again := parseTransfer(t, bob.createTransfer(t, body, key).body); again.ID != sessTr.ID {
			t.Errorf("session replay = %s, want %s", again.ID, sessTr.ID)
		}
		// Same key, different body, same token: 409.
		other := body
		other.Message = "changed"
		expectProblem(t, tok3.tokenCreate(t, bobEmail, other, key), http.StatusConflict, "state-conflict")
		noSecretInLogs(t, o.server, secret1, secret2, secret3, secret4)
	})
}

// assetRE finds the src and href attributes of an HTML page.
var assetRE = regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*"([^"]*)"`)

// TestAPIDocs: the interactive API documentation is served on the admin
// host to an authenticated admin session only, with its own exact CSP and
// same-origin assets; it is absent from the tenant hosts unless
// TT_API_DOCS_PUBLIC is set, which never opens it on the admin host nor on
// an unknown host (421).
func TestAPIDocs(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		anon := a.client(nil, adminIP(1))
		for _, p := range []string{pathDocs, pathDocs + "/scalar.js", pathDocs + "/init.js"} {
			expectProblem(t, anon.send(t, http.MethodGet, p, nil, nil), http.StatusUnauthorized, "unauthenticated")
		}
		sa := a.bootstrap(t, adminIP(2))
		page := mustStatus(t, "docs page", sa.send(t, http.MethodGet, pathDocs, nil, nil), http.StatusOK)
		expectDocsFile(t, "docs page", page, "text/html; charset=utf-8", "no-store")
		expectSameOriginAssets(t, page.body)
		for _, js := range []string{"scalar.js", "init.js"} {
			resp := mustStatus(t, js, sa.send(t, http.MethodGet, pathDocs+"/"+js, nil, nil), http.StatusOK)
			expectDocsFile(t, js, resp, "text/javascript; charset=utf-8", "no-store")
		}
		missing := sa.send(t, http.MethodGet, pathDocs+"/missing.js", nil, nil)
		expectProblem(t, missing, http.StatusNotFound, "not-found")
		if csp := missing.header.Get("Content-Security-Policy"); csp != securityHeaders["Content-Security-Policy"] {
			t.Errorf("unknown asset CSP = %q, want the default policy", csp)
		}
		// Not served on the tenant hosts by default.
		for _, p := range []string{pathDocs, pathDocs + "/scalar.js"} {
			expectProblem(t, a.get(t, hostA, p), http.StatusNotFound, "not-found")
		}

		// TT_API_DOCS_PUBLIC: served on the tenant hosts, revalidated, and
		// still reserved to admin sessions on the admin host.
		// The same database, restarted with the variable set.
		if err := a.stop(); err != nil {
			t.Fatalf("stop: %v", err)
		}
		cfg := *a.cfg
		cfg.APIDocsPublic = true
		pub := launchServer(t, &cfg, a.tenantA, a.tenantB, serverOptions{})
		for _, host := range []string{hostA, hostB} {
			page := pub.get(t, host, pathDocs)
			mustStatus(t, "public docs on "+host, page, http.StatusOK)
			expectDocsFile(t, "public docs on "+host, page, "text/html; charset=utf-8", "no-cache")
			expectSameOriginAssets(t, page.body)
			js := pub.get(t, host, pathDocs+"/scalar.js")
			mustStatus(t, "public scalar.js on "+host, js, http.StatusOK)
			expectDocsFile(t, "public scalar.js", js, "text/javascript; charset=utf-8", "no-cache")
		}
		expectProblem(t, pub.get(t, adminHost, pathDocs), http.StatusUnauthorized, "unauthenticated")
		// An unknown host never gets it: 421 and an unknown_fqdn line.
		expectProblem(t, pub.get(t, "docs.unknown.example.net", pathDocs), http.StatusMisdirectedRequest, "unknown-tenant")
		if n := len(withHost(eventsOf(t, pub.securityLines(t), "unknown_fqdn"), `"docs.unknown.example.net"`)); n != 1 {
			t.Errorf("%d unknown_fqdn lines for the docs on an unknown host, want 1", n)
		}
		// The admin session still gets it on the admin host, never cached.
		sa.a = &adminEnv{depositEnv: &depositEnv{server: pub}}
		page = mustStatus(t, "docs page on the admin host", sa.send(t, http.MethodGet, pathDocs, nil, nil), http.StatusOK)
		expectDocsFile(t, "docs page on the admin host", page, "text/html; charset=utf-8", "no-store")
	})
}

// expectDocsFile checks a documentation file: its content type, the exact
// documentation CSP, the other security headers, the cache policy and a
// non-empty body.
func expectDocsFile(t *testing.T, what string, resp response, contentType, cacheControl string) {
	t.Helper()
	if ct := resp.header.Get("Content-Type"); ct != contentType {
		t.Errorf("%s Content-Type = %q, want %q", what, ct, contentType)
	}
	if csp := resp.header.Values("Content-Security-Policy"); len(csp) != 1 || csp[0] != docsCSP {
		t.Errorf("%s CSP = %q, want exactly %q", what, csp, docsCSP)
	}
	for k, want := range securityHeaders {
		if k == "Content-Security-Policy" {
			continue
		}
		if got := resp.header.Get(k); got != want {
			t.Errorf("%s %s = %q, want %q", what, k, got, want)
		}
	}
	if cc := resp.header.Get("Cache-Control"); cc != cacheControl {
		t.Errorf("%s Cache-Control = %q, want %q", what, cc, cacheControl)
	}
	if resp.header.Get("ETag") == "" || len(resp.body) == 0 {
		t.Errorf("%s: ETag %q, %d bytes, want an ETag and a body", what, resp.header.Get("ETag"), len(resp.body))
	}
}

// expectSameOriginAssets fails when the page references anything but
// same-origin absolute paths (or data: URIs): no CDN, no other origin.
func expectSameOriginAssets(t *testing.T, page []byte) {
	t.Helper()
	refs := assetRE.FindAllStringSubmatch(string(page), -1)
	if len(refs) == 0 {
		t.Fatal("the documentation page references no asset")
	}
	scripts := 0
	for _, m := range refs {
		ref := m[1]
		switch {
		case strings.HasPrefix(ref, "data:"):
		case strings.HasPrefix(ref, "/") && !strings.HasPrefix(ref, "//"):
			if strings.HasPrefix(ref, pathDocs+"/") {
				scripts++
			}
		default:
			t.Errorf("the documentation page references %q, want a same-origin path", ref)
		}
	}
	if scripts == 0 {
		t.Error("the documentation page loads no script from " + pathDocs + "/")
	}
	if strings.Contains(strings.ToLower(string(page)), "<script>") {
		t.Error("the documentation page holds an inline script")
	}
}
