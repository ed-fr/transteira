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

// Fictitious depositors of the transfer cases (CLAUDE.md section 25).
const (
	colleagueA = "carol@entity-a.localhost"
	insiderB   = "dave@entity-b.localhost"
	// clientRange covers every X-Forwarded-For address the harness sends.
	clientRange = "198.51.0.0/16"
)

// transferFixtures are the sessions of the transfer cases: tenant A's owner
// session is depositFixtures.sessionToken; colleague is another internal
// sender of A, and otherTenant an internal sender of B.
type transferFixtures struct {
	colleague   string
	otherTenant string
}

// seedTransfers makes the harness clients internal users of both tenants
// (their client range and mail domain) and opens the sessions of the
// colleague of A and of the sender of B.
func seedTransfers(t *testing.T, db *store.DB, a, b tenant.ID) transferFixtures {
	t.Helper()
	ctx := context.Background()
	for tid, domain := range map[tenant.ID]string{a: "entity-a.localhost", b: "entity-b.localhost"} {
		if _, err := db.NetworkRules().Replace(ctx, tid, []netip.Prefix{netip.MustParsePrefix(clientRange)}, []string{domain}); err != nil {
			t.Fatalf("network rules: %v", err)
		}
	}
	session := func(tid tenant.ID, email string) string {
		tok, err := id.NewToken("ds", 32)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(tok))
		now := time.Now().UTC().Truncate(time.Millisecond)
		if err := db.DepositSessions().Create(ctx, tid, store.DepositSession{
			ID: id.New(id.DepositSession), TokenHash: h[:], Email: email, Kind: store.DepositorInternal,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return tok
	}
	return transferFixtures{colleague: session(a, colleagueA), otherTenant: session(b, insiderB)}
}

// client is one deposit session under one host, with its CSRF token.
type client struct {
	host, token, csrf string
}

// clientOf reads the CSRF token of the session token under host.
func (h *harness) clientOf(t *testing.T, host, token string) client {
	t.Helper()
	resp := h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1/deposit-sessions/current", host, nil,
		http.Header{"Cookie": {"__Host-tt_deposit=" + token}})
	var s struct {
		CSRFToken string `json:"csrfToken"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &s) != nil || s.CSRFToken == "" {
		t.Fatalf("session under %s: %d %s", host, resp.status, resp.body)
	}
	return client{host: host, token: token, csrf: s.CSRFToken}
}

// owner, colleague and other are the three senders of the cases.
func (h *harness) owner(t *testing.T) client {
	return h.clientOf(t, hostA, h.fixtures.sessionToken)
}

func (h *harness) colleague(t *testing.T) client {
	return h.clientOf(t, hostA, h.transfers.colleague)
}

func (h *harness) other(t *testing.T) client {
	return h.clientOf(t, hostB, h.transfers.otherTenant)
}

// headers returns the cookie and CSRF headers of c, plus extra pairs.
func (c client) headers(extra ...string) []string {
	return append([]string{"Cookie", "__Host-tt_deposit=" + c.token, "X-CSRF-Token", c.csrf}, extra...)
}

// createdTransfer is a transfer of tenant A created by its owner.
type createdTransfer struct {
	ID    string
	Files []struct {
		UploadURL string `json:"uploadUrl"`
	} `json:"files"`
}

// uploadID returns the identifier of the first upload.
func (c createdTransfer) uploadID() string {
	return strings.TrimPrefix(c.Files[0].UploadURL, "/api/v1/uploads/")
}

// createTransferA creates, as tenant A's owner, a transfer of one 4-byte
// file and returns it.
func (h *harness) createTransferA(t *testing.T) createdTransfer {
	t.Helper()
	o := h.owner(t)
	header := http.Header{}
	for kv := o.headers("Content-Type", "application/json"); len(kv) > 1; kv = kv[2:] {
		header.Set(kv[0], kv[1])
	}
	body := `{"recipients":["erin@customer.example.net"],"expiryDays":1,"files":[{"name":"plans.pdf","size":4}]}`
	resp := h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/transfers", hostA, strings.NewReader(body), header)
	var tr createdTransfer
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tr) != nil || len(tr.Files) != 1 {
		t.Fatalf("create transfer under %s: %d %s", hostA, resp.status, resp.body)
	}
	if loc := resp.header.Get("Location"); loc != "/api/v1/transfers/"+tr.ID {
		t.Errorf("Location = %q", loc)
	}
	return tr
}

// refusedEverywhere asserts that the colleague of A (under A) and the
// sender of B (under B) both get 404 for a resource of A's owner, and that
// neither answer leaks data of A.
func refusedEverywhere(t *testing.T, h *harness, op operation, params map[string]string, body string, extra ...string) {
	t.Helper()
	code := "not-found"
	if strings.Contains(op.template, "/uploads/") {
		code = "" // tus errors have no body
	}
	c := h.colleague(t)
	resp := h.call(t, op, hostA, params, body, c.headers(extra...)...)
	wantCode(t, op, hostA, resp, http.StatusNotFound, code)
	if strings.Contains(string(resp.body), insiderA) {
		t.Errorf("%s for another sender of A leaks the owner's address", op)
	}
	o := h.other(t)
	refusedUnderB(t, h, op, h.call(t, op, hostB, params, body, o.headers(extra...)...), http.StatusNotFound, code)
}

// createWithForeignSession: tenant A's session creates under A and is
// unauthenticated under B.
func createWithForeignSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	h.createTransferA(t)
	o := h.owner(t)
	body := `{"recipients":["erin@customer.example.net"],"expiryDays":1,"files":[{"name":"a","size":1}]}`
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, body, o.headers()...), http.StatusUnauthorized, "unauthenticated")
}

// getForeignTransfer: only the owner of A reads the transfer.
func getForeignTransfer(t *testing.T, h *harness, op operation) {
	t.Helper()
	tr := h.createTransferA(t)
	params := map[string]string{"transferId": tr.ID}
	o := h.owner(t)
	if resp := h.call(t, op, hostA, params, "", o.headers()...); resp.status != http.StatusOK || !strings.Contains(string(resp.body), tr.ID) {
		t.Fatalf("%s for its owner: %d %s", op, resp.status, resp.body)
	}
	refusedEverywhere(t, h, op, params, "")
}

// cancelForeignTransfer: neither another sender of A nor a sender of B can
// cancel it; its owner can.
func cancelForeignTransfer(t *testing.T, h *harness, op operation) {
	t.Helper()
	tr := h.createTransferA(t)
	params := map[string]string{"transferId": tr.ID}
	refusedEverywhere(t, h, op, params, "")
	o := h.owner(t)
	if resp := h.call(t, op, hostA, params, "", o.headers()...); resp.status != http.StatusNoContent {
		t.Fatalf("%s by its owner: %d %s", op, resp.status, resp.body)
	}
}

// finalizeForeignTransfer: only the owner reaches the transfer (whose
// file is not uploaded: 409 upload-incomplete).
func finalizeForeignTransfer(t *testing.T, h *harness, op operation) {
	t.Helper()
	tr := h.createTransferA(t)
	params := map[string]string{"transferId": tr.ID}
	refusedEverywhere(t, h, op, params, "")
	o := h.owner(t)
	wantCode(t, op, hostA, h.call(t, op, hostA, params, "", o.headers()...), http.StatusConflict, "upload-incomplete")
}

// tusCapabilities: the same capabilities under both tenants (their limits
// are equal), no session needed, no tenant data.
func tusCapabilities(t *testing.T, h *harness, op operation) {
	t.Helper()
	for _, host := range []string{hostA, hostB} {
		resp := h.call(t, op, host, nil, "")
		if resp.status != http.StatusNoContent || resp.header.Get("Tus-Max-Size") != "1073741824" ||
			resp.header.Get("Tus-Version") != "1.0.0" {
			t.Fatalf("%s under %s: %d %v", op, host, resp.status, resp.header)
		}
		noLeak(t, h, op, host, resp)
	}
}

// headForeignUpload: only the owner reads the offset.
func headForeignUpload(t *testing.T, h *harness, op operation) {
	t.Helper()
	tr := h.createTransferA(t)
	params := map[string]string{"uploadId": tr.uploadID()}
	o := h.owner(t)
	if resp := h.call(t, op, hostA, params, "", o.headers("Tus-Resumable", "1.0.0")...); resp.status != http.StatusOK ||
		resp.header.Get("Upload-Offset") != "0" || resp.header.Get("Upload-Length") != "4" {
		t.Fatalf("%s for its owner: %d %v", op, resp.status, resp.header)
	}
	refusedEverywhere(t, h, op, params, "", "Tus-Resumable", "1.0.0")
}

// patchForeignUpload: only the owner reaches the upload (a wrong offset:
// 409); the others get 404 and write nothing.
func patchForeignUpload(t *testing.T, h *harness, op operation) {
	t.Helper()
	tr := h.createTransferA(t)
	params := map[string]string{"uploadId": tr.uploadID()}
	tus := []string{"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", "application/offset+octet-stream"}
	refusedEverywhere(t, h, op, params, "data", tus...)
	o := h.owner(t)
	wrong := append(o.headers(tus...), "Upload-Offset", "2")
	if resp := h.call(t, op, hostA, params, "da", wrong...); resp.status != http.StatusConflict {
		t.Fatalf("%s by its owner at a wrong offset: %d", op, resp.status)
	}
	if resp := h.call(t, op, hostA, params, "data", o.headers(tus...)...); resp.status != http.StatusNoContent ||
		resp.header.Get("Upload-Offset") != "4" {
		t.Fatalf("%s by its owner: %d %v", op, resp.status, resp.header)
	}
}

// terminateForeignUpload: only the owner terminates the upload.
func terminateForeignUpload(t *testing.T, h *harness, op operation) {
	t.Helper()
	tr := h.createTransferA(t)
	params := map[string]string{"uploadId": tr.uploadID()}
	refusedEverywhere(t, h, op, params, "", "Tus-Resumable", "1.0.0")
	o := h.owner(t)
	if resp := h.call(t, op, hostA, params, "", o.headers("Tus-Resumable", "1.0.0")...); resp.status != http.StatusNoContent {
		t.Fatalf("%s by its owner: %d", op, resp.status)
	}
}
