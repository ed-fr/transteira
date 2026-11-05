package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Client IPs of the security events seeded for the security event cases,
// one per owner: tenant A, tenant B and no tenant.
const (
	secIPA    = "203.0.113.101"
	secIPB    = "203.0.113.102"
	secIPNone = "203.0.113.103"
)

// securityEventItem is the part of an OpenAPI SecurityEvent the cases read.
type securityEventItem struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	IP       string  `json:"ip"`
	TenantID *string `json:"tenantId"`
}

// seedSecurityEvents writes one security event of A, one of B and one
// without tenant, each from its own IP, straight to the database (the
// recorder of the server is covered by the end-to-end check).
func (h *harness) seedSecurityEvents(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	at := time.Now().Add(-time.Minute)
	_, err = db.SecurityEvents().Save(ctx, []store.SecurityEvent{
		{At: at, TenantID: h.tenantA.ID, Type: "deposit_refused", Reason: "ip", IP: netip.MustParseAddr(secIPA)},
		{At: at, TenantID: h.tenantB.ID, Type: "deposit_refused", Reason: "ip", IP: netip.MustParseAddr(secIPB)},
		{At: at, Type: "unknown_fqdn", IP: netip.MustParseAddr(secIPNone), Details: json.RawMessage(`{"host":"evil.localhost"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// securityEvents decodes a SecurityEventList answer.
func securityEvents(t *testing.T, op operation, what string, resp response) []securityEventItem {
	t.Helper()
	var page struct {
		Items []securityEventItem `json:"items"`
	}
	if err := json.Unmarshal(wantOK(t, op, what, resp), &page); err != nil {
		t.Fatalf("%s: %s: %v", op, what, err)
	}
	return page.Items
}

// onlyTenant asserts that every event of items belongs to tid (never to
// another tenant, never without tenant) and returns the IPs listed.
func onlyTenant(t *testing.T, op operation, what string, items []securityEventItem, tid tenant.ID) map[string]bool {
	t.Helper()
	ips := map[string]bool{}
	for _, ev := range items {
		if ev.TenantID == nil || *ev.TenantID != string(tid) {
			t.Errorf("%s: %s lists event %s of tenant %v", op, what, ev.ID, ev.TenantID)
		}
		ips[ev.IP] = true
	}
	return ips
}

// tenantSecurityEvents is the case of listTenantSecurityEvents (threat
// model T-283): served on the admin host only, tenant B's ID answers the
// delegated admin of A exactly like an unknown tenant, and A's listing
// holds A's events only, never B's nor those without tenant, whatever the
// filter; the events a request under A's Host raises reach A's listing.
func tenantSecurityEvents(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	h.seedSecurityEvents(t)
	sess := h.session(t)
	for _, query := range []string{"?limit=200", "?limit=200&type=deposit_refused", "?limit=200&type=unknown_fqdn"} {
		resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/security-events"+query), "")
		ips := onlyTenant(t, op, "tenant A's security events "+query, securityEvents(t, op, "tenant A's security events", resp), h.tenantA.ID)
		if ips[secIPB] || ips[secIPNone] {
			t.Errorf("%s: tenant A's security events %s list events of B or without tenant: %s", op, query, resp.body)
		}
		if query != "?limit=200&type=unknown_fqdn" && !ips[secIPA] {
			t.Errorf("%s: tenant A's security events %s miss A's event: %s", op, query, resp.body)
		}
		h.noDataOfB(t, op, "tenant A's security events", resp, string(h.tenantB.ID), secIPB)
	}
	// The super admin reads B's events under B's ID, never A's.
	resp := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/security-events?limit=200"), "")
	if ips := onlyTenant(t, op, "tenant B's security events", securityEvents(t, op, "tenant B's security events", resp), h.tenantB.ID); !ips[secIPB] || ips[secIPA] {
		t.Errorf("%s: tenant B's security events: %s", op, resp.body)
	}
	// A malformed filter is a validation error, not a leak.
	resp = h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/security-events?type=Bad-Type"), "")
	wantCode(t, op, hostAdmin, resp, http.StatusBadRequest, "validation-failed")

	// End to end: an invalid API token under A's Host is recorded for A
	// (asynchronously, within a few flush intervals).
	start := time.Now().Add(-time.Second)
	hdr := http.Header{"Authorization": {"Bearer ttk_isolationInvalidToken0000"}}
	if r := h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1/transfers/"+id.New(id.Transfer), hostA, nil, hdr); r.status != http.StatusUnauthorized {
		t.Fatalf("%s: invalid token under %s: %d %s", op, hostA, r.status, r.body)
	}
	q := url.Values{"type": {"api_token_invalid"}, "from": {start.UTC().Format(time.RFC3339)}, "limit": {"200"}}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/security-events?"+q.Encode()), "")
		if items := securityEvents(t, op, "tenant A's api_token_invalid events", resp); len(items) > 0 {
			onlyTenant(t, op, "tenant A's api_token_invalid events", items, h.tenantA.ID)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the invalid token under %s never reached A's security events", op, hostA)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// globalSecurityEvents is the case of listGlobalSecurityEvents: reserved
// to the super admin (403 forbidden for A's delegated admin, with or
// without a filter on B), it lists the events of every tenant and those
// without tenant, and with tenantId only those of that tenant.
func globalSecurityEvents(t *testing.T, h *harness, op operation) {
	t.Helper()
	superAdminOperation(t, h, op)
	h.seedSecurityEvents(t)
	super := h.superSession(t)
	path := "/" + strings.TrimPrefix(op.template, "/")
	resp := h.adminCall(t, super, http.MethodGet, path+"?limit=200&type=deposit_refused", "")
	ips := map[string]bool{}
	for _, ev := range securityEvents(t, op, "the instance's security events", resp) {
		ips[ev.IP] = true
	}
	if !ips[secIPA] || !ips[secIPB] {
		t.Errorf("%s: the instance's security events miss A's or B's: %s", op, resp.body)
	}
	resp = h.adminCall(t, super, http.MethodGet, path+"?limit=200&type=unknown_fqdn", "")
	found := false
	for _, ev := range securityEvents(t, op, "the instance's unknown_fqdn events", resp) {
		found = found || (ev.IP == secIPNone && ev.TenantID == nil)
	}
	if !found {
		t.Errorf("%s: the instance's security events miss the event without tenant: %s", op, resp.body)
	}
	q := url.Values{"tenantId": {string(h.tenantA.ID)}, "limit": {"200"}}
	resp = h.adminCall(t, super, http.MethodGet, path+"?"+q.Encode(), "")
	if ips := onlyTenant(t, op, "the instance's events of A", securityEvents(t, op, "the instance's events of A", resp), h.tenantA.ID); !ips[secIPA] || ips[secIPB] || ips[secIPNone] {
		t.Errorf("%s: the instance's events filtered on A: %s", op, resp.body)
	}
	resp = h.adminCall(t, super, http.MethodGet, path+"?tenantId=bogus", "")
	wantCode(t, op, hostAdmin, resp, http.StatusBadRequest, "validation-failed")
}
