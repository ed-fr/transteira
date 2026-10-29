package httpisolation_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// meCookie is the name of the "my transfers" session cookie.
const meCookie = "__Host-tt_me"

// meLink stores, directly in the database, email as a verified address of
// tenant tid (a link opens a session only for a verified address) and a
// "my transfers" access link of email in tid, valid 15 minutes, and
// returns its token.
func (h *harness) meLink(t *testing.T, tid tenant.ID, email string) string {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	token, err := id.NewToken(id.AccessLinkTokenPrefix, id.AccessLinkTokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Truncate(time.Millisecond)
	sc, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		_, err := db.VerifiedAddresses().UpsertTx(ctx, tx, store.VerifiedAddress{
			Email: email, FirstVerifiedAt: now, FirstVerifiedIP: netip.MustParseAddr("192.0.2.1"), LastUsedAt: now,
		})
		return err
	})
	if err != nil {
		t.Fatalf("verify address: %v", err)
	}
	if _, err := db.SenderAccess().CreateLink(ctx, tid, hash[:], email, now, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("create access link: %v", err)
	}
	return token
}

// meClient is one "my transfers" session under one host, with its CSRF
// token.
type meClient struct {
	host, token, csrf string
}

// headers returns the cookie and CSRF headers of c.
func (c meClient) headers() []string {
	return []string{"Cookie", meCookie + "=" + c.token, "X-CSRF-Token", c.csrf}
}

// meStartOp is the startMyTransfersSession operation.
func meStartOp() operation {
	return operation{id: "startMyTransfersSession", verb: http.MethodPost, template: "/me/sessions", base: "/api/v1"}
}

// meSession opens, through the API under host, a session of email in
// tenant tid from a fresh access link.
func (h *harness) meSession(t *testing.T, host string, tid tenant.ID, email string) meClient {
	t.Helper()
	resp := h.call(t, meStartOp(), host, nil, `{"token":"`+h.meLink(t, tid, email)+`"}`)
	var s struct {
		Email     string `json:"email"`
		CSRFToken string `json:"csrfToken"`
	}
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &s) != nil || s.Email != email || s.CSRFToken == "" {
		t.Fatalf("my transfers session under %s: %d %s", host, resp.status, resp.body)
	}
	for _, c := range (&http.Response{Header: resp.header}).Cookies() {
		if c.Name == meCookie {
			return meClient{host: host, token: c.Value, csrf: s.CSRFToken}
		}
	}
	t.Fatalf("my transfers session under %s set no cookie: %v", host, resp.header)
	return meClient{}
}

// meSenders are the sessions of the "my transfers" cases: owner is the
// sender of A's transfers (insiderA under A), colleague another sender of
// A, and sameAddressB the same address as owner in tenant B.
type meSenders struct {
	owner, colleague, sameAddressB meClient
}

func (h *harness) meSenders(t *testing.T) meSenders {
	t.Helper()
	return meSenders{
		owner:        h.meSession(t, hostA, h.tenantA.ID, insiderA),
		colleague:    h.meSession(t, hostA, h.tenantA.ID, colleagueA),
		sameAddressB: h.meSession(t, hostB, h.tenantB.ID, insiderA),
	}
}

// meRefused asserts resp is the expected refusal and carries no data of
// tenant A; the only cookie it may set is the expiry of the "my transfers"
// cookie (401 for a cookie that resolves to no session).
func meRefused(t *testing.T, h *harness, op operation, host string, resp response, status int, code string) {
	t.Helper()
	wantCode(t, op, host, resp, status, code)
	noLeak(t, h, op, host, resp)
	if strings.Contains(string(resp.body), insiderA) && host == hostB {
		t.Errorf("%s under %s leaks %q", op, host, insiderA)
	}
	for _, sc := range resp.header.Values("Set-Cookie") {
		if !strings.HasPrefix(sc, meCookie+"=;") || !strings.Contains(sc, "Max-Age=0") {
			t.Errorf("%s under %s sets a cookie: %q", op, host, sc)
		}
	}
}

// meRefusedForOthers asserts that, for a transfer of A's owner, the other
// sender of A (under A) and the same address in B (under B) both get 404,
// and that the owner's cookie under B is unauthenticated (401).
func meRefusedForOthers(t *testing.T, h *harness, op operation, s meSenders, params map[string]string, body string) {
	t.Helper()
	meRefused(t, h, op, hostA, h.call(t, op, hostA, params, body, s.colleague.headers()...), http.StatusNotFound, "not-found")
	meRefused(t, h, op, hostB, h.call(t, op, hostB, params, body, s.sameAddressB.headers()...), http.StatusNotFound, "not-found")
	meRefused(t, h, op, hostB, h.call(t, op, hostB, params, body, s.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
}

// requestLinkEverywhere: the answer under A and under B for A's sender is
// the same (neither tenant has SMTP settings in the harness: 503
// mail-unavailable, whatever the address), without data of A.
func requestLinkEverywhere(t *testing.T, h *harness, op operation) {
	t.Helper()
	body := `{"email":"` + insiderA + `"}`
	for _, host := range []string{hostA, hostB} {
		meRefused(t, h, op, host, h.call(t, op, host, nil, body), http.StatusServiceUnavailable, "mail-unavailable")
	}
	meRefused(t, h, op, hostA, h.call(t, op, hostA, nil, `{"email":"nobody@entity-a.localhost"}`), http.StatusServiceUnavailable, "mail-unavailable")
}

// startWithForeignLink: A's access link is unknown under B (410, no
// cookie, not consumed) and opens a session under A.
func startWithForeignLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	body := `{"token":"` + h.meLink(t, h.tenantA.ID, insiderA) + `"}`
	meRefused(t, h, op, hostB, h.call(t, op, hostB, nil, body), http.StatusGone, "access-link-invalid")
	if resp := h.call(t, op, hostA, nil, body); resp.status != http.StatusCreated || !strings.Contains(string(resp.body), insiderA) {
		t.Fatalf("%s under %s: %d %s", op, hostA, resp.status, resp.body)
	}
	// Used once.
	meRefused(t, h, op, hostA, h.call(t, op, hostA, nil, body), http.StatusGone, "access-link-invalid")
}

// currentWithForeignMeSession: A's session cookie is unknown under B; B's
// session of the same address is unknown under A.
func currentWithForeignMeSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.meSenders(t)
	if resp := h.call(t, op, hostA, nil, "", s.owner.headers()...); resp.status != http.StatusOK || !strings.Contains(string(resp.body), insiderA) {
		t.Fatalf("%s under %s: %d %s", op, hostA, resp.status, resp.body)
	}
	meRefused(t, h, op, hostB, h.call(t, op, hostB, nil, "", s.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
	meRefused(t, h, op, hostA, h.call(t, op, hostA, nil, "", s.sameAddressB.headers()...), http.StatusUnauthorized, "unauthenticated")
}

// endWithForeignMeSession: A's session cannot be ended under B (401) and
// still works under A, where it ends.
func endWithForeignMeSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.meSenders(t)
	meRefused(t, h, op, hostB, h.call(t, op, hostB, nil, "", s.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
	current := operation{id: "getCurrentMyTransfersSession", verb: http.MethodGet, template: "/me/sessions/current", base: "/api/v1"}
	if resp := h.call(t, current, hostA, nil, "", s.owner.headers()...); resp.status != http.StatusOK {
		t.Fatalf("session of A after the attempt under B: %d %s", resp.status, resp.body)
	}
	if resp := h.call(t, op, hostA, nil, "", s.owner.headers()...); resp.status != http.StatusNoContent {
		t.Fatalf("%s under %s: %d %s", op, hostA, resp.status, resp.body)
	}
	meRefused(t, h, current, hostA, h.call(t, current, hostA, nil, "", s.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
}

// listMyForeignTransfers: A's transfer is listed for its sender under A
// only.
func listMyForeignTransfers(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID, _ := h.availableTransfer(t, "")
	s := h.meSenders(t)
	if resp := h.call(t, op, hostA, nil, "", s.owner.headers()...); resp.status != http.StatusOK || !strings.Contains(string(resp.body), trfID) {
		t.Fatalf("%s for the owner: %d %s", op, resp.status, resp.body)
	}
	for _, c := range []meClient{s.colleague, s.sameAddressB} {
		resp := h.call(t, op, c.host, nil, "", c.headers()...)
		if resp.status != http.StatusOK || strings.Contains(string(resp.body), trfID) {
			t.Errorf("%s under %s for another sender: %d %s", op, c.host, resp.status, resp.body)
		}
		noLeak(t, h, op, c.host, resp)
	}
	meRefused(t, h, op, hostB, h.call(t, op, hostB, nil, "", s.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
}

// getMyForeignTransfer: only the sender of A reads its transfer, under A.
func getMyForeignTransfer(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID, token := h.availableTransfer(t, "")
	s := h.meSenders(t)
	params := map[string]string{"transferId": trfID}
	resp := h.call(t, op, hostA, params, "", s.owner.headers()...)
	if resp.status != http.StatusOK || !strings.Contains(string(resp.body), trfID) || strings.Contains(string(resp.body), token) {
		t.Fatalf("%s for the owner: %d %s", op, resp.status, resp.body)
	}
	meRefusedForOthers(t, h, op, s, params, "")
}

// deleteMyForeignTransfer: neither another sender of A nor the same
// address in B deletes A's transfer; its sender does.
func deleteMyForeignTransfer(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID, _ := h.availableTransfer(t, "")
	s := h.meSenders(t)
	params := map[string]string{"transferId": trfID}
	meRefusedForOthers(t, h, op, s, params, "")
	get := operation{id: "getMyTransfer", verb: http.MethodGet, template: "/me/transfers/{transferId}", base: "/api/v1"}
	if resp := h.call(t, get, hostA, params, "", s.owner.headers()...); resp.status != http.StatusOK {
		t.Fatalf("transfer of A after the attempts: %d %s", resp.status, resp.body)
	}
	if resp := h.call(t, op, hostA, params, "", s.owner.headers()...); resp.status != http.StatusNoContent {
		t.Fatalf("%s by the owner: %d %s", op, resp.status, resp.body)
	}
	wantCode(t, get, hostA, h.call(t, get, hostA, params, "", s.owner.headers()...), http.StatusNotFound, "not-found")
}

// extendMyForeignTransfer: neither another sender of A nor the same
// address in B extends A's transfer; its sender does.
func extendMyForeignTransfer(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID, _ := h.availableTransfer(t, "")
	s := h.meSenders(t)
	params := map[string]string{"transferId": trfID}
	body := `{"expiryDays":30}`
	meRefusedForOthers(t, h, op, s, params, body)
	resp := h.call(t, op, hostA, params, body, s.owner.headers()...)
	var d struct {
		ID             string `json:"id"`
		ExtensionCount int    `json:"extensionCount"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &d) != nil || d.ID != trfID || d.ExtensionCount != 1 {
		t.Fatalf("%s by the owner: %d %s", op, resp.status, resp.body)
	}
}
