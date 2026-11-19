package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
)

// The transfer search across the tenants of an administrator (since 2.3,
// threat model T-409 to T-412): the delegated admin of A never finds a
// transfer of B, by address or by identifier, and gets for B's identifier
// exactly the answer of a random identifier (no existence oracle); the
// same address in A and B is found in both by the super admin only; the
// auditor of A searches by identifier only, within A.

// Fictitious recipients of the search case (CLAUDE.md section 25).
const (
	// searchShared receives a transfer in A and one in B.
	searchShared = "grace@customer.example.net"
	// searchOnlyB receives a transfer in B only.
	searchOnlyB = "heidi@customer.example.net"
	// searchUnknown receives nothing.
	searchUnknown = "ivy@customer.example.net"
)

// searchPath is the path of searchTransfers below /api/v1.
const searchPath = "/admin/transfers/search"

// searchAnswer is the TransferSearchResult of an answer.
type searchAnswer struct {
	Kind  string `json:"kind"`
	Items []struct {
		TenantID   string `json:"tenantId"`
		TenantName string `json:"tenantName"`
		Transfer   struct {
			ID string `json:"id"`
		} `json:"transfer"`
	} `json:"items"`
	Truncated bool `json:"truncated"`
	Tenants   []struct {
		TenantID string `json:"tenantId"`
		More     bool   `json:"more"`
	} `json:"tenants"`
}

// searchAs sends a search of q by sess and returns the answer, decoded
// when it is a 200.
func (h *harness) searchAs(t *testing.T, sess adminSession, q string) (response, searchAnswer) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"q": q})
	resp := h.adminCall(t, sess, http.MethodPost, searchPath, string(body))
	var out searchAnswer
	if resp.status == http.StatusOK {
		if err := json.Unmarshal(resp.body, &out); err != nil {
			t.Fatalf("search %q: %s", q, resp.body)
		}
	}
	return resp, out
}

// transferIDs returns the identifiers of the transfers of a, in order, and
// of its tenants.
func (a searchAnswer) transferIDs() (transfers, tenants []string) {
	for _, it := range a.Items {
		transfers = append(transfers, it.Transfer.ID)
	}
	for _, tn := range a.Tenants {
		tenants = append(tenants, tn.TenantID)
	}
	return transfers, tenants
}

// emptySearch is the answer of a search without match, by identifier.
const emptySearch = `{"items":[],"kind":"transfer_id","tenants":[],"truncated":false}`

// searchAcrossTenants is the isolation case of searchTransfers.
func searchAcrossTenants(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	trA := h.newTransfer(t, h.colleague(t), searchShared)
	trB := h.newTransfer(t, h.other(t), searchShared)
	onlyB := h.newTransfer(t, h.other(t), searchOnlyB)
	a, b := string(h.tenantA.ID), string(h.tenantB.ID)
	deleg, super, auditor := h.session(t), h.superSession(t), h.auditorSession(t)
	leaks := []string{trB.ID, onlyB.ID, searchOnlyB}
	random := id.New(id.Transfer)

	// The delegated admin of A: B's identifier, in any case, answers
	// exactly like a random one; B's address like an unknown one; the
	// shared address finds A's transfer only.
	for _, sess := range []adminSession{deleg, auditor} {
		want, _ := h.searchAs(t, sess, random)
		if want.status != http.StatusOK || string(want.body) != emptySearch+"\n" {
			t.Fatalf("%s: random identifier: %d %s", op, want.status, want.body)
		}
		for _, q := range []string{trB.ID, strings.ToLower(onlyB.ID)} {
			got, _ := h.searchAs(t, sess, q)
			if got.status != want.status || string(got.body) != string(want.body) {
				t.Errorf("%s: identifier of B: %d %s, want the answer of a random identifier %s", op, got.status, got.body, want.body)
			}
			h.noDataOfB(t, op, "identifier of B", got, leaks...)
		}
		resp, ans := h.searchAs(t, sess, strings.ToLower(trA.ID))
		if ids, tenants := ans.transferIDs(); resp.status != http.StatusOK || !slices.Equal(ids, []string{trA.ID}) ||
			!slices.Equal(tenants, []string{a}) || ans.Kind != "transfer_id" {
			t.Errorf("%s: identifier of A: %d %s", op, resp.status, resp.body)
		}
		h.noDataOfB(t, op, "identifier of A", resp, leaks...)
	}
	unknown, _ := h.searchAs(t, deleg, searchUnknown)
	if unknown.status != http.StatusOK || string(unknown.body) != strings.Replace(emptySearch, "transfer_id", "email", 1)+"\n" {
		t.Fatalf("%s: unknown address: %d %s", op, unknown.status, unknown.body)
	}
	got, _ := h.searchAs(t, deleg, strings.ToUpper(searchOnlyB))
	if got.status != unknown.status || string(got.body) != string(unknown.body) {
		t.Errorf("%s: address of B: %d %s, want the answer of an unknown address %s", op, got.status, got.body, unknown.body)
	}
	h.noDataOfB(t, op, "address of B", got, leaks...)
	resp, ans := h.searchAs(t, deleg, searchShared)
	if ids, tenants := ans.transferIDs(); resp.status != http.StatusOK || !slices.Equal(ids, []string{trA.ID}) ||
		!slices.Equal(tenants, []string{a}) || ans.Kind != "email" || ans.Items[0].TenantName != nameA {
		t.Errorf("%s: shared address by the admin of A: %d %s", op, resp.status, resp.body)
	}
	h.noDataOfB(t, op, "shared address", resp, leaks...)

	// The super admin finds the shared address in A and B.
	resp, ans = h.searchAs(t, super, searchShared)
	ids, tenants := ans.transferIDs()
	slices.Sort(ids)
	want := []string{trA.ID, trB.ID}
	slices.Sort(want)
	if resp.status != http.StatusOK || !slices.Equal(ids, want) || !slices.Equal(tenants, []string{a, b}) {
		t.Errorf("%s: shared address by the super admin: %d %s", op, resp.status, resp.body)
	}

	// The auditor of A: an address is refused before it is checked.
	for _, q := range []string{searchShared, searchOnlyB, "not an address @"} {
		resp, _ := h.searchAs(t, auditor, q)
		wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "read-only-role")
		h.noDataOfB(t, op, "auditor address", resp, leaks...)
	}

	// The CSRF token is required (P93), and an unknown member refused.
	hdr := deleg.header(true)
	hdr.Del("X-CSRF-Token")
	resp = h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1"+searchPath, hostAdmin, strings.NewReader(`{"q":"`+searchShared+`"}`), hdr)
	wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "csrf-invalid")
	resp = h.adminCall(t, deleg, http.MethodPost, searchPath, `{"q":"`+trB.ID+`","tenantId":"`+b+`"}`)
	wantCode(t, op, hostAdmin, resp, http.StatusBadRequest, "validation-failed")
	if !strings.Contains(string(resp.body), `"field":"/tenantId"`) || resp.header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s: unknown member: %s %v", op, resp.body, resp.header)
	}
	h.noDataOfB(t, op, "unknown member", resp, leaks...)
}
