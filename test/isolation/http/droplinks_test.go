package httpisolation_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Fictitious values of the drop link cases (CLAUDE.md section 25): the
// recipients are in the internal domains of each tenant (seedTransfers).
const (
	dropLabelA     = "Tenant A supplier invoices"
	dropLabelB     = "Tenant B supplier invoices"
	dropRecipientA = "accounting@entity-a.localhost"
	dropRecipientB = "accounting@entity-b.localhost"
	dropDepositor  = "supplier@partner.example.org"
)

// dropLinkView is the part of the OpenAPI DropLink and DropLinkCreated the
// drop link cases read.
type dropLinkView struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Recipients []string `json:"recipients"`
	Enabled    bool     `json:"enabled"`
	RevokedAt  *string  `json:"revokedAt"`
	Token      string   `json:"token"`
	URL        string   `json:"url"`
}

// dropLinkOf creates, as the super admin, a drop link of tenant tid for
// recipient and returns it with its token.
func (h *harness) dropLinkOf(t *testing.T, op operation, tid tenant.ID, label, recipient string) dropLinkView {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPost, tenantPath(tid, "/drop-links"),
		`{"label":"`+label+`","recipients":["`+recipient+`"],"validityDays":7}`)
	var l dropLinkView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &l) != nil || l.ID == "" || l.Token == "" {
		t.Fatalf("%s: create a drop link of %s (super admin): %d %s", op, tid, resp.status, resp.body)
	}
	return l
}

// dropLinkOfB creates a drop link of tenant B.
func (h *harness) dropLinkOfB(t *testing.T, op operation) dropLinkView {
	t.Helper()
	return h.dropLinkOf(t, op, h.tenantB.ID, dropLabelB, dropRecipientB)
}

// dropLinksOf lists the drop links of tenant tid with the session sess.
func (h *harness) dropLinksOf(t *testing.T, op operation, sess adminSession, tid string) []dropLinkView {
	t.Helper()
	resp := h.adminCall(t, sess, http.MethodGet, "/admin/tenants/"+tid+"/drop-links", "")
	var list struct {
		Items []dropLinkView `json:"items"`
	}
	if json.Unmarshal(wantOK(t, op, "the drop link list of "+tid, resp), &list) != nil {
		t.Fatalf("%s: drop link list of %s: %s", op, tid, resp.body)
	}
	return list.Items
}

// publicDropLinkOp is the getPublicDropLink operation.
func publicDropLinkOp() operation {
	return operation{id: "getPublicDropLink", verb: http.MethodGet, template: "/drop-links/{dropToken}", base: "/api/v1"}
}

// dropLinkOfBIntact asserts that tenant B's link l is still listed for B
// unchanged (same label and recipient, enabled, not revoked, never its
// token) and that its token still opens it under B's host only.
func (h *harness) dropLinkOfBIntact(t *testing.T, op operation, l dropLinkView) {
	t.Helper()
	found := false
	for _, got := range h.dropLinksOf(t, op, h.superSession(t), string(h.tenantB.ID)) {
		if got.ID != l.ID {
			continue
		}
		found = true
		if got.Label != dropLabelB || strings.Join(got.Recipients, ",") != dropRecipientB || !got.Enabled ||
			got.RevokedAt != nil || got.Token != "" {
			t.Errorf("%s: tenant B's drop link was changed (or its token listed): %+v", op, got)
		}
	}
	if !found {
		t.Errorf("%s: tenant B's drop link %s is gone", op, l.ID)
	}
	pub := publicDropLinkOp()
	params := map[string]string{"dropToken": l.Token}
	if resp := h.call(t, pub, hostB, params, ""); resp.status != http.StatusOK || !strings.Contains(string(resp.body), dropLabelB) {
		t.Errorf("%s: tenant B's token after the call: %d %s, want 200", op, resp.status, resp.body)
	}
}

// noDropLinkOfB asserts that resp holds nothing of tenant B's link l.
func (h *harness) noDropLinkOfB(t *testing.T, op operation, what string, resp response, l dropLinkView) {
	t.Helper()
	h.noDataOfB(t, op, what, resp, l.ID, l.Token, dropLabelB, dropRecipientB)
}

// adminDropLink is the isolation case of a drop link operation: served on
// the admin host only, tenant B's ID answered like an unknown tenant
// (adminTenantOp), then the checks of the operation on a link of B created
// by the super admin (dropLinkChecks).
func adminDropLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	check, ok := dropLinkChecks[op.id]
	if !ok {
		t.Fatalf("%s has no entry in dropLinkChecks", op)
	}
	l := h.dropLinkOfB(t, op)
	check(t, h, op, h.session(t), l)
	h.dropLinkOfBIntact(t, op, l)
}

// dropLinkChecks are the per-operation checks of adminDropLink, run with
// the session of tenant A's delegated admin and a fresh link of tenant B.
var dropLinkChecks = map[string]func(t *testing.T, h *harness, op operation, sess adminSession, l dropLinkView){
	"listDropLinks":  checkListDropLinks,
	"createDropLink": checkCreateDropLink,
	"getDropLink":    checkForeignDropLink(http.MethodGet, "", ""),
	"updateDropLink": checkForeignDropLink(http.MethodPatch, "",
		`{"label":"Renamed by A","recipients":["`+dropRecipientA+`"],"enabled":false}`),
	"deleteDropLink": checkForeignDropLink(http.MethodDelete, "", ""),
	"rotateDropLink": checkForeignDropLink(http.MethodPost, "/rotate", ""),
}

// checkListDropLinks: A's list never holds B's link.
func checkListDropLinks(t *testing.T, h *harness, op operation, sess adminSession, l dropLinkView) {
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/drop-links"), "")
	wantOK(t, op, "tenant A's list", resp)
	h.noDropLinkOfB(t, op, "tenant A's list", resp, l)
}

// checkCreateDropLink: an invalid body for B (a recipient outside B's
// domains included) answers like an unknown tenant (the access is checked
// first); A's link, created under A's path, is listed for A only, never
// for B, and its token is unknown under B's host.
func checkCreateDropLink(t *testing.T, h *harness, op operation, sess adminSession, l dropLinkView) {
	for _, bad := range []string{
		`{}`, `null`,
		`{"label":"x","recipients":["someone@outside.example.net"],"validityDays":7}`,
		`{"label":"x","recipients":["` + dropRecipientB + `"],"validityDays":7,"confidentialityLevel":"no-such-level"}`,
	} {
		h.invalidInputOfB(t, op, sess, http.MethodPost, "/drop-links", bad)
	}
	// A's admin cannot create a link of A addressed to B's internal
	// recipients: they are outside A's internal domains.
	resp := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/drop-links"),
		`{"label":"To B","recipients":["`+dropRecipientB+`"],"validityDays":7}`)
	wantCode(t, op, hostAdmin, resp, http.StatusBadRequest, "validation-failed")

	resp = h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/drop-links"),
		`{"label":"`+dropLabelA+`","recipients":["`+dropRecipientA+`"],"validityDays":7}`)
	var own dropLinkView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &own) != nil || own.ID == "" || own.Token == "" {
		t.Fatalf("%s: tenant A's own link: %d %s, want 201", op, resp.status, resp.body)
	}
	if resp.header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s: the answer holding the token has Cache-Control %q, want no-store", op, resp.header.Get("Cache-Control"))
	}
	if !strings.HasPrefix(own.URL, "https://"+hostA+"/drop/") {
		t.Errorf("%s: URL of A's link %q, want under %s", op, own.URL, hostA)
	}
	h.noDropLinkOfB(t, op, "tenant A's new link", resp, l)
	for _, got := range h.dropLinksOf(t, op, h.superSession(t), string(h.tenantB.ID)) {
		if got.ID == own.ID {
			t.Errorf("%s: tenant A's link %s is listed for tenant B", op, own.ID)
		}
	}
	pub := publicDropLinkOp()
	wantCode(t, pub, hostB, h.call(t, pub, hostB, map[string]string{"dropToken": own.Token}, ""),
		http.StatusNotFound, "drop-link-invalid")
}

// checkForeignDropLink returns the check of an operation on one link
// (method, path suffix, body): B's link under A's path answers exactly
// like a missing link; adminDropLink then checks it is unchanged.
func checkForeignDropLink(method, suffix, body string) func(t *testing.T, h *harness, op operation, sess adminSession, l dropLinkView) {
	return func(t *testing.T, h *harness, op operation, sess adminSession, l dropLinkView) {
		foreign := h.adminCall(t, sess, method, tenantPath(h.tenantA.ID, "/drop-links/"+l.ID+suffix), body)
		missing := h.adminCall(t, sess, method, tenantPath(h.tenantA.ID, "/drop-links/"+id.New(id.DropLink)+suffix), body)
		h.sameAsMissing(t, op, foreign, missing, l.ID, l.Token, dropLabelB, dropRecipientB)
		// Under B's own path, A's admin is refused like for an unknown tenant.
		foreignTenant := h.adminCall(t, sess, method, tenantPath(h.tenantB.ID, "/drop-links/"+l.ID+suffix), body)
		missingTenant := h.adminCall(t, sess, method, tenantPath(tenant.ID(id.New(id.Tenant)), "/drop-links/"+l.ID+suffix), body)
		h.sameAsMissing(t, op, foreignTenant, missingTenant, l.ID, l.Token, dropLabelB, dropRecipientB)
	}
}

// publicForeignDropLink is the isolation case of getPublicDropLink: A's
// token opens A's link under A only; under B it gets exactly the answer of
// an unknown token (404 drop-link-invalid), and B's token under A as well.
func publicForeignDropLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	a := h.dropLinkOf(t, op, h.tenantA.ID, dropLabelA, dropRecipientA)
	b := h.dropLinkOfB(t, op)
	unknown, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	own := h.call(t, op, hostA, map[string]string{"dropToken": a.Token}, "")
	if own.status != http.StatusOK || !strings.Contains(string(own.body), dropLabelA) {
		t.Fatalf("%s under %s: %d %s, want A's link", op, hostA, own.status, own.body)
	}
	if strings.Contains(string(own.body), dropRecipientA) {
		t.Errorf("%s: the public answer reveals the recipients: %s", op, own.body)
	}
	for _, c := range []struct {
		host, token, foreignLabel string
	}{
		{hostB, a.Token, dropLabelA},
		{hostA, b.Token, dropLabelB},
	} {
		foreign := h.call(t, op, c.host, map[string]string{"dropToken": c.token}, "")
		missing := h.call(t, op, c.host, map[string]string{"dropToken": unknown}, "")
		wantCode(t, op, c.host, foreign, http.StatusNotFound, "drop-link-invalid")
		if missing.status != foreign.status || string(withoutInstance(t, missing)) != string(withoutInstance(t, foreign)) {
			t.Errorf("%s under %s: a foreign token answers %s, an unknown one %s: they must be identical",
				op, c.host, foreign.body, missing.body)
		}
		noLeak(t, h, op, c.host, foreign)
		for _, s := range []string{c.foreignLabel, dropRecipientA, dropRecipientB} {
			if strings.Contains(string(foreign.body), s) {
				t.Errorf("%s under %s leaks %q", op, c.host, s)
			}
		}
		if sc := foreign.header.Get("Set-Cookie"); sc != "" {
			t.Errorf("%s under %s sets a cookie: %q", op, c.host, sc)
		}
	}
}

// startWithForeignInvitationOrDropLink extends startWithForeignInvitation
// to the drop links (since 2.0): A's drop token starts a code under A (503
// mail-unavailable, A has no SMTP settings), and under B it gets exactly
// the answer of an unknown token (404 drop-link-invalid), as does B's
// token under A.
func startWithForeignInvitationOrDropLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	startWithForeignInvitation(t, h, op)
	a := h.dropLinkOf(t, op, h.tenantA.ID, dropLabelA, dropRecipientA)
	b := h.dropLinkOfB(t, op)
	unknown, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	body := func(token string) string {
		return `{"email":"` + dropDepositor + `","dropLinkToken":"` + token + `"}`
	}
	wantCode(t, op, hostA, h.call(t, op, hostA, nil, body(a.Token)), http.StatusServiceUnavailable, "mail-unavailable")
	for _, c := range []struct{ host, token string }{{hostB, a.Token}, {hostA, b.Token}} {
		foreign := h.call(t, op, c.host, nil, body(c.token))
		missing := h.call(t, op, c.host, nil, body(unknown))
		wantCode(t, op, c.host, foreign, http.StatusNotFound, "drop-link-invalid")
		if string(withoutInstance(t, missing)) != string(withoutInstance(t, foreign)) {
			t.Errorf("%s under %s: a foreign drop token answers %s, an unknown one %s", op, c.host, foreign.body, missing.body)
		}
		noLeak(t, h, op, c.host, foreign)
		if sc := foreign.header.Get("Set-Cookie"); sc != "" {
			t.Errorf("%s under %s sets a cookie: %q", op, c.host, sc)
		}
	}
}

// dropLinkSession opens, directly in the database, a drop link deposit
// session of tenant tid bound to the link linkID (as a confirmed code
// would) and returns its client under host.
func (h *harness) dropLinkSession(t *testing.T, host string, tid tenant.ID, linkID string) client {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	tok, err := id.NewToken("ds", 32)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(tok))
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := db.DepositSessions().Create(ctx, tid, store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: hash[:], Email: dropDepositor, Kind: store.DepositorDropLink,
		DropLinkID: linkID, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create drop link session: %v", err)
	}
	return h.clientOf(t, host, tok)
}

// createWithForeignSessionOrDropLink extends createWithForeignSession to
// the drop links (since 2.0): no deposit session of A can be bound to a
// link of B (the composite foreign key refuses it), a drop link session of
// A is unknown under B, and its transfer is addressed to the recipients of
// A's link only, never to those of B's link.
func createWithForeignSessionOrDropLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	createWithForeignSession(t, h, op)
	a := h.dropLinkOf(t, op, h.tenantA.ID, dropLabelA, dropRecipientA)
	b := h.dropLinkOfB(t, op)

	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	err = db.DepositSessions().Create(ctx, h.tenantA.ID, store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: id.HashToken("ds_forged_isolation"), Email: dropDepositor,
		Kind: store.DepositorDropLink, DropLinkID: b.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	_ = db.Close()
	if err == nil {
		t.Fatalf("%s: a deposit session of A bound to B's drop link was stored", op)
	}

	sess := h.dropLinkSession(t, hostA, h.tenantA.ID, a.ID)
	files := `,"expiryDays":7,"files":[{"name":"invoice.pdf","size":4}]}`
	// Under B's host, A's drop link session is unknown.
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, `{"recipients":["`+dropRecipientB+`"]`+files, sess.headers()...), http.StatusUnauthorized, "unauthenticated")
	// Under A, B's recipients are not those of A's link: refused.
	resp := h.call(t, op, hostA, nil, `{"recipients":["`+dropRecipientB+`"]`+files, sess.headers()...)
	if resp.status < 400 || resp.status >= 500 {
		t.Fatalf("%s: drop link session of A addressing B's recipient: %d %s, want a 4xx refusal", op, resp.status, resp.body)
	}
	h.noDropLinkOfB(t, op, "the refusal", resp, b)
	// Without recipients, the transfer goes to A's link recipients, which
	// the answer never shows (T-311): it names A's link instead.
	resp = h.call(t, op, hostA, nil, `{"expiryDays":7,"files":[{"name":"invoice.pdf","size":4}]}`, sess.headers()...)
	if resp.status != http.StatusCreated || strings.Contains(string(resp.body), dropRecipientA) ||
		!strings.Contains(string(resp.body), `"dropLinkLabel":"`+dropLabelA+`"`) {
		t.Fatalf("%s: drop link session of A: %d %s, want 201 naming %q without recipient", op, resp.status, resp.body, dropLabelA)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.body, &created); err != nil {
		t.Fatal(err)
	}
	if db, err = store.Open(ctx, h.engine.Config()); err != nil {
		t.Fatal(err)
	}
	stored, err := db.Transfers().Get(ctx, h.tenantA.ID, created.ID)
	_ = db.Close()
	if err != nil || len(stored.Recipients) != 1 || stored.Recipients[0] != dropRecipientA {
		t.Fatalf("%s: stored recipients = %v, %v; want %s", op, stored.Recipients, err, dropRecipientA)
	}
	h.noDropLinkOfB(t, op, "A's drop link transfer", resp, b)
	h.dropLinkOfBIntact(t, op, b)
}

// linkOnlyTransferA makes tenant A allow link-only transfers (as the super
// admin), creates a link-only transfer of A's owner and makes it available
// directly in the database, as the antivirus would. It returns the
// transfer and its download token.
func (h *harness) linkOnlyTransferA(t *testing.T) (trfID, token string) {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPatch, tenantPath(h.tenantA.ID, ""), `{"linkOnlyAllowed":true}`)
	if resp.status != http.StatusOK {
		t.Fatalf("allow link-only transfers on A: %d %s", resp.status, resp.body)
	}
	o := h.owner(t)
	header := http.Header{}
	for kv := o.headers("Content-Type", "application/json"); len(kv) > 1; kv = kv[2:] {
		header.Set(kv[0], kv[1])
	}
	resp = h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/transfers", hostA,
		strings.NewReader(`{"linkOnly":true,"expiryDays":1,"files":[{"name":"empty.txt","size":0}]}`), header)
	var tr struct {
		ID    string `json:"id"`
		Files []struct {
			ID string `json:"id"`
		} `json:"files"`
	}
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tr) != nil || len(tr.Files) != 1 {
		t.Fatalf("create link-only transfer: %d %s", resp.status, resp.body)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	token, err = id.NewDownloadToken()
	if err != nil {
		t.Fatal(err)
	}
	s, err := db.Scoped(h.tenantA.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if err := db.Transfers().FinalizeTx(ctx, tx, tr.ID, now); err != nil {
			return err
		}
		if err := db.TransferFiles().SetScanResultTx(ctx, tx, tr.Files[0].ID, store.ScanClean, "", now); err != nil {
			return err
		}
		if err := db.Transfers().SetLinkOnlyTokenTx(ctx, tx, tr.ID, id.HashToken(token)); err != nil {
			return err
		}
		return db.Transfers().MarkLinkOnlyAvailableTx(ctx, tx, tr.ID, now)
	})
	if err != nil {
		t.Fatalf("make the link-only transfer available: %v", err)
	}
	return tr.ID, token
}

// reissueMyForeignTransferLink: neither another sender of A nor the same
// address in B (nor A's sender cookie under B) reissues the link of A's
// link-only transfer, whose link keeps working; its sender does, under A,
// and the previous link is dead.
func reissueMyForeignTransferLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID, token := h.linkOnlyTransferA(t)
	s := h.meSenders(t)
	params := map[string]string{"transferId": trfID}
	meRefusedForOthers(t, h, op, s, params, "")
	get := operation{id: "getDownload", verb: http.MethodGet, template: "/downloads/{linkToken}", base: "/api/v1"}
	if resp := h.call(t, get, hostA, map[string]string{"linkToken": token}, ""); resp.status != http.StatusOK {
		t.Fatalf("link of A's transfer after the attempts: %d %s, want 200", resp.status, resp.body)
	}
	resp := h.call(t, op, hostA, params, "", s.owner.headers()...)
	var out struct {
		DownloadURL string `json:"downloadUrl"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &out) != nil ||
		!strings.HasPrefix(out.DownloadURL, "https://"+hostA+"/d/") {
		t.Fatalf("%s by the owner: %d %s", op, resp.status, resp.body)
	}
	fresh := out.DownloadURL[strings.LastIndex(out.DownloadURL, "/")+1:]
	wantCode(t, get, hostA, h.call(t, get, hostA, map[string]string{"linkToken": token}, ""), http.StatusNotFound, "not-found")
	if resp := h.call(t, get, hostA, map[string]string{"linkToken": fresh}, ""); resp.status != http.StatusOK {
		t.Errorf("new link under %s: %d %s, want 200", hostA, resp.status, resp.body)
	}
	foreign := h.call(t, get, hostB, map[string]string{"linkToken": fresh}, "")
	wantCode(t, get, hostB, foreign, http.StatusNotFound, "not-found")
	noLeak(t, h, get, hostB, foreign)
}
