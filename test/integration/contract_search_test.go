package integration_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// Contract and wiring tests of the transfer search of the administration
// (since 2.3, CLAUDE.md section 13.2, threat model T-411 to T-414): every
// answer of searchTransfers, success and errors alike, is validated
// against api/openapi.yaml, with Cache-Control: no-store; the CSRF token is
// required; the 31st search of an administrator within the minute is 429
// with Retry-After, never written to the security log (P94); no search is
// audited (P95).

// pathSearch is the path of searchTransfers.
const pathSearch = "/api/v1/admin/transfers/search"

// searchProblem is a validation-failed Problem with its field errors.
type searchProblem struct {
	Code   string `json:"code"`
	Errors []struct {
		Field string `json:"field"`
		Code  string `json:"code"`
	} `json:"errors"`
}

func TestContractSearchTransfers(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "search", "customer.example.net")
		tr := alice.mustCreate(t, transferCreate{
			Recipients: []string{rcpt}, ExpiryDays: 1, Files: []fileDecl{{Name: "plans.pdf", Size: 4}},
		})
		deleg := o.sa.createDelegatedOf(t, "search.deleg", o.tid, domainA, adminIP(20))
		auditor := o.sa.createAuditorOf(t, "search.audit", o.tid, adminIP(21))
		flood := o.sa.createDelegatedOf(t, "search.flood", o.tid, domainA, adminIP(22))
		audited := len(o.sa.tenantEvents(t, o.tid, ""))

		search := func(c *adminClient, body any) response {
			t.Helper()
			resp := c.call(t, http.MethodPost, pathSearch, body)
			expectContract(t, "searchTransfers", http.MethodPost, pathSearch, resp)
			if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("searchTransfers %d: Cache-Control %q, want no-store", resp.status, cc)
			}
			return resp
		}

		// 200: an address (recipient in any case, sender), an identifier,
		// for a delegated admin, the super admin and, by identifier, the
		// auditor; no match.
		for _, q := range []string{strings.ToUpper(rcpt), " " + sender + " ", strings.ToLower(tr.ID)} {
			for _, c := range []*adminClient{deleg, o.sa} {
				resp := mustStatus(t, "search "+q, search(c, map[string]any{"q": q, "limit": 5}), http.StatusOK)
				if !strings.Contains(string(resp.body), `"id":"`+tr.ID+`"`) || !strings.Contains(string(resp.body), `"tenantId":"`+o.tid+`"`) {
					t.Errorf("search %q: %s", q, resp.body)
				}
			}
		}
		resp := mustStatus(t, "auditor identifier", search(auditor, map[string]any{"q": tr.ID}), http.StatusOK)
		if !strings.Contains(string(resp.body), tr.ID) || strings.Contains(string(resp.body), `"kind":"email"`) {
			t.Errorf("auditor identifier: %s", resp.body)
		}
		resp = mustStatus(t, "no match", search(deleg, map[string]any{"q": id.New(id.Transfer)}), http.StatusOK)
		if string(resp.body) != `{"items":[],"kind":"transfer_id","tenants":[],"truncated":false}`+"\n" {
			t.Errorf("no match: %s", resp.body)
		}

		// 400: the query, the limit and the body.
		for body, want := range map[string]string{
			`{"q":" \u00a0 "}`:                   "/q invalid-format",
			`{}`:                                 "/q invalid-format",
			`{"q":"trf_01JCQ3V8K2M4N6P8R0S2T4"}`: "/q invalid-format",
			`{"q":"` + rcpt[:4] + `"}`:           "/q invalid-format",
			`{"q":"` + strings.Repeat("a", tenantops.MaxSearchQueryLen+1) + `"}`: "/q invalid-format",
			`{"q":"Carol <` + rcpt + `>"}`:                                       "/q invalid-email",
			`{"q":"` + rcpt + `","limit":0}`:                                     "/limit invalid-format",
			`{"q":"` + rcpt + `","limit":51}`:                                    "/limit invalid-format",
			`{"q":"` + rcpt + `","limit":null}`:                                  "/limit invalid-format",
			`{"q":"` + rcpt + `","tenantId":"` + o.tid + `"}`:                    "/tenantId invalid-format",
			`[]`: "",
		} {
			resp := search(deleg, body)
			expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
			var p searchProblem
			mustJSON(t, resp.body, &p)
			got := ""
			if len(p.Errors) == 1 {
				got = p.Errors[0].Field + " " + p.Errors[0].Code
			}
			if want != "" && got != want {
				t.Errorf("%.60s: errors %s, want %s", body, resp.body, want)
			}
		}

		// 401 without a session, 403 without the CSRF token, and an address
		// refused to the auditor, even invalid.
		anon := o.client(nil, adminIP(23))
		expectProblem(t, search(anon, map[string]any{"q": rcpt}), http.StatusUnauthorized, "unauthenticated")
		noCSRF := deleg.send(t, http.MethodPost, pathSearch, map[string]any{"q": rcpt}, nil)
		expectContract(t, "searchTransfers", http.MethodPost, pathSearch, noCSRF)
		expectProblem(t, noCSRF, http.StatusForbidden, "csrf-invalid")
		for _, q := range []string{rcpt, "not an address @"} {
			expectProblem(t, search(auditor, map[string]any{"q": q}), http.StatusForbidden, "read-only-role")
		}

		// 429: the 31st search of an administrator within the minute, the
		// others unaffected; never a security log line.
		for i := range tenantops.SearchRateLimit {
			mustStatus(t, "search "+strconv.Itoa(i+1), search(flood, map[string]any{"q": rcpt}), http.StatusOK)
		}
		limited := search(flood, map[string]any{"q": rcpt})
		p := expectProblem(t, limited, http.StatusTooManyRequests, "rate-limited")
		retry, err := strconv.Atoi(limited.header.Get("Retry-After"))
		if err != nil || retry < 1 || retry > 60 || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != retry {
			t.Errorf("429: Retry-After %q, retryAfterSeconds %v", limited.header.Get("Retry-After"), p.RetryAfterSeconds)
		}
		mustStatus(t, "another administrator", search(deleg, map[string]any{"q": rcpt}), http.StatusOK)
		for _, l := range eventsOf(t, o.securityLines(t), "rate_limited") {
			if l.ip == adminIP(22) {
				t.Errorf("the search limit is in the security log: %s", l.raw)
			}
		}
		if strings.Contains(strings.Join(o.securityLines(t), "\n"), rcpt) {
			t.Error("a searched address is in the security log")
		}

		// Nothing audited.
		if events := o.sa.tenantEvents(t, o.tid, ""); len(events) != audited {
			raw, _ := json.Marshal(eventActions(events))
			t.Errorf("searches audited: %d events, want %d: %s", len(events), audited, raw)
		}
	})
}
