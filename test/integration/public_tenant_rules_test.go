package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Public rules of an entity (plan step 12, threat model T-233 and T-235): the public tenant
// resource that feeds the personalised help never carries the internal ranges, the internal
// domains, the abuse thresholds, the recipient domain lists or the blocklist, and the rules
// served under the host of an entity are those of that entity.

// TestPublicTenantRulesIsolationAndLeaks configures tenant C with every internal setting set to a
// distinctive sentinel, then checks the raw JSON of GET /tenant: no sentinel under C's host (T-233),
// and C's limits, levels and features appear under no other host (T-235).
func TestPublicTenantRulesIsolationAndLeaks(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o, _ := withScanner(t, serverOptions{})
		a := startAdmin(t, e, o, true)
		sa := a.bootstrap(t, adminIP(1))
		c := sa.createTenantC(t)

		const (
			levelKey    = "c-only-sentinel-level"
			levelLabel  = "Sentinel label of C"
			cidr        = "100.64.77.0/24"
			intDomain   = "internal-sentinel.example.org"
			allowedDom  = "allowed-sentinel.example.net"
			deniedDom   = "denied-sentinel.example.com"
			blockedMail = "blocked-sentinel@example.org"
			blockedDom  = "blocked-sentinel.example.net"
			blockedHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
			maxTransfer = int64(123456789)
		)
		mustStatus(t, "limit of C", sa.mergePatch(t, tenantPath(c.ID, ""), `{"maxTransferBytes":`+strconv.FormatInt(maxTransfer, 10)+`}`), http.StatusOK)
		mustStatus(t, "network of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/network"),
			map[string][]string{"internalCidrs": {cidr}, "internalDomains": {intDomain}}), http.StatusOK)
		mustStatus(t, "levels of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/confidentiality-levels"),
			map[string]any{"items": []map[string]any{{
				"key": levelKey, "labels": map[string]string{"en": levelLabel, "fr": levelLabel}, "isDefault": true,
				"rules": map[string]any{
					"requireRecipientVerification": false, "requirePassword": true, "allowedExpiryDays": []int{7},
					"internalRecipientsOnly": false, "forceDeleteAfterFirstDownload": false, "maxDownloads": 3,
				},
			}}}), http.StatusOK)
		mustStatus(t, "recipient rules of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/recipient-rules"),
			map[string][]string{"allowedDomains": {allowedDom}, "deniedDomains": {deniedDom}}), http.StatusOK)
		resp := mustStatus(t, "getAbuseThresholds", sa.call(t, http.MethodGet, tenantPath(c.ID, "/abuse-thresholds"), nil), http.StatusOK)
		var thresholds map[string]any
		mustJSON(t, resp.body, &thresholds)
		thresholds["maxDailyTransfersPerSender"] = 987654
		thresholds["officeHours"] = map[string]any{"start": "07:13", "end": "19:47", "weekdays": []int{1, 2, 3}}
		mustStatus(t, "abuse thresholds of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/abuse-thresholds"), thresholds), http.StatusOK)
		for _, entry := range []map[string]string{
			{"kind": "email", "value": blockedMail}, {"kind": "domain", "value": blockedDom}, {"kind": "sha256", "value": blockedHash},
		} {
			mustStatus(t, "blocklist of C", sa.call(t, http.MethodPost, tenantPath(c.ID, "/blocklist"), entry), http.StatusCreated)
		}

		// T-233: the raw public resource of C holds none of the internal settings.
		raw := mustStatus(t, "GET /tenant under C", a.get(t, hostC, pathPublicTenant), http.StatusOK).body
		for _, secret := range []string{
			cidr, "100.64.77", intDomain, allowedDom, deniedDom, blockedMail, blockedDom, blockedHash,
			"987654", "07:13", "19:47", "internalCidrs", "internalDomains", "allowedDomains", "deniedDomains",
			"blocklist", "officeHours", "maxDailyTransfers",
		} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("public tenant of C leaks %q: %s", secret, raw)
			}
		}
		// The rules meant for the help are there, and the restriction is only an on/off.
		var c1 struct {
			Limits struct {
				MaxTransferBytes int64 `json:"maxTransferBytes"`
			} `json:"limits"`
			Levels []struct {
				Key   string `json:"key"`
				Label string `json:"label"`
			} `json:"confidentialityLevels"`
			Features map[string]any `json:"features"`
		}
		if err := json.Unmarshal(raw, &c1); err != nil {
			t.Fatal(err)
		}
		if c1.Limits.MaxTransferBytes != maxTransfer || len(c1.Levels) != 1 || c1.Levels[0].Key != levelKey ||
			c1.Levels[0].Label != levelLabel || c1.Features["recipientRestrictions"] != true {
			t.Errorf("public tenant of C = %s", raw)
		}

		// T-235: the rules of C under the host of A are those of A.
		rawA := mustStatus(t, "GET /tenant under A", a.get(t, hostA, pathPublicTenant), http.StatusOK).body
		for _, mine := range []string{levelKey, levelLabel, strconv.FormatInt(maxTransfer, 10)} {
			if strings.Contains(string(rawA), mine) {
				t.Errorf("public tenant of A shows %q of tenant C: %s", mine, rawA)
			}
		}
		var a1 struct {
			Limits struct {
				MaxTransferBytes int64 `json:"maxTransferBytes"`
			} `json:"limits"`
			Features map[string]any `json:"features"`
		}
		if err := json.Unmarshal(rawA, &a1); err != nil {
			t.Fatal(err)
		}
		if a1.Limits.MaxTransferBytes == maxTransfer || a1.Features["recipientRestrictions"] == true {
			t.Errorf("public tenant of A takes the rules of C: %s", rawA)
		}
		// Neither a spoofed header nor a query changes the tenant that answers.
		spoof := mustStatus(t, "GET /tenant under A with a forged tenant", a.do(t, request{
			host: hostA, path: pathPublicTenant + "?tenant=" + c.ID,
			headers: http.Header{"X-Forwarded-Host": {hostC}, "X-Tenant-Id": {c.ID}},
		}), http.StatusOK).body
		if strings.Contains(string(spoof), levelKey) {
			t.Errorf("forged tenant selectors reach the rules of C: %s", spoof)
		}
	})
}
