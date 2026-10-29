package httpisolation_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Fictitious data of the tenant operation cases (CLAUDE.md section 25).
const (
	// invitedB is invited by tenant B's sender.
	invitedB = "frank@partner-b.example.org"
	// blockedA and blockedB are blocked domains of tenant A and B.
	blockedA = "blocked-a.example.net"
	blockedB = "blocked-b.example.net"
	// auditActorB is the actor of the audit event seeded for tenant B.
	auditActorB = "admin.entity-b"
	// superUser is the super admin of the harness.
	superUser = "root.isolation"
)

// opsFixtures are the resources of the tenant operation cases, created
// directly in the database.
type opsFixtures struct {
	// invitationA is a pending invitation of tenant A, which the
	// revokeInvitation case revokes (the deposit fixture invitation stays
	// untouched for the deposit cases).
	invitationA string
	// invitationB is a pending invitation of tenant B for invitedB.
	invitationB string
	// entryA and entryB block blockedA in A and blockedB in B.
	entryA, entryB string
	// auditB is an audit event of tenant B, by auditActorB.
	auditB string
	// reportA and reportB are open abuse reports of tenants A and B (the
	// latter with the message reportMarkerB).
	reportA, reportB string
	// superToken is the cookie token of an authenticated session of the
	// super admin.
	superToken string
}

// seedOperations creates the fixtures of the tenant operation cases, and a
// super admin with an authenticated session (opened in the database, as a
// login with TOTP would).
func seedOperations(t *testing.T, db *store.DB, a, b tenant.ID) opsFixtures {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("seed operations: %v", err)
		}
	}
	hash := func(tok string) []byte {
		h := sha256.Sum256([]byte(tok))
		return h[:]
	}
	newToken := func(prefix string) string {
		tok, err := id.NewToken(prefix, 32)
		must(err)
		return tok
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	f := opsFixtures{invitationA: id.New(id.Invitation), invitationB: id.New(id.Invitation)}
	must(db.Invitations().Create(ctx, a, store.Invitation{
		ID: f.invitationA, TokenHash: hash(newToken("inv")), Email: "judy@partner.example.org", InvitedBy: insiderA, CreatedAt: now,
	}))
	must(db.Invitations().Create(ctx, b, store.Invitation{
		ID: f.invitationB, TokenHash: hash(newToken("inv")), Email: invitedB, InvitedBy: insiderB, CreatedAt: now,
	}))
	ea, err := db.Blocklist().Create(ctx, a, store.BlocklistEntry{Kind: store.BlockDomain, Value: blockedA, CreatedBy: "deleg.entity-a"})
	must(err)
	eb, err := db.Blocklist().Create(ctx, b, store.BlocklistEntry{Kind: store.BlockDomain, Value: blockedB, CreatedBy: auditActorB})
	must(err)
	f.entryA, f.entryB = ea.ID, eb.ID
	ev, err := db.AuditEvents().Append(ctx, store.AuditEvent{
		TenantID: b, ActorKind: store.ActorAdmin, Actor: auditActorB,
		Action: "blocklist.updated", ObjectKind: "blocklist", ObjectID: eb.ID,
	})
	must(err)
	f.auditB = ev.ID
	f.reportA, f.reportB = seedAbuseReport(t, db, a, "report of A"), seedAbuseReport(t, db, b, reportMarkerB)

	pw, err := crypto.NewPasswordHasher(1).HashPassword(ctx, []byte("a-long-passphrase-for-the-root"))
	must(err)
	sa, err := db.Admins().Create(ctx, store.Admin{
		Username: superUser, Email: "root@example.com", Role: store.RoleSuperAdmin, PasswordHash: pw,
	})
	must(err)
	f.superToken = newToken("as")
	must(db.AdminSessions().Create(ctx, store.AdminSession{
		ID: id.New(id.AdminSession), TokenHash: hash(f.superToken), AdminID: sa.ID,
		State: store.SessionAuthenticated, CreatedAt: now, ExpiresAt: now.Add(12 * time.Hour),
	}))
	return f
}

// superSession returns the session of the super admin, with the CSRF token
// read from getAdminMe on first use.
func (h *harness) superSession(t *testing.T) adminSession {
	t.Helper()
	h.sessMu.Lock()
	defer h.sessMu.Unlock()
	if h.super == nil {
		s := adminSession{cookie: h.ops.superToken}
		resp := h.adminCall(t, s, http.MethodGet, "/admin/me", "")
		var me struct {
			Role      string `json:"role"`
			CsrfToken string `json:"csrfToken"`
		}
		if resp.status != http.StatusOK || json.Unmarshal(resp.body, &me) != nil || me.Role != "super_admin" || me.CsrfToken == "" {
			t.Fatalf("super admin me: %d %s", resp.status, resp.body)
		}
		s.csrf = me.CsrfToken
		h.super = &s
	}
	return *h.super
}

// adminCall sends a request of the session sess on the admin host to
// /api/v1 + path, with an optional JSON body.
func (h *harness) adminCall(t *testing.T, sess adminSession, method, path, body string) response {
	t.Helper()
	hdr := sess.header(body != "")
	if body == "" {
		return h.do(t, method, "http://"+h.addr+"/api/v1"+path, hostAdmin, nil, hdr)
	}
	return h.do(t, method, "http://"+h.addr+"/api/v1"+path, hostAdmin, strings.NewReader(body), hdr)
}

// tenantPath returns the path of an operation of tenant tid.
func tenantPath(tid tenant.ID, rest string) string {
	return "/admin/tenants/" + string(tid) + rest
}

// newTransfer creates, as the sender c under its host, a transfer of one
// 4-byte file to recipient and returns it. The cases use tenant A's
// colleague and tenant B's sender: the open transfers they leave never
// count against the limit of tenant A's owner, whom the download cases
// need.
func (h *harness) newTransfer(t *testing.T, c client, recipient string) createdTransfer {
	t.Helper()
	header := http.Header{}
	for kv := c.headers("Content-Type", "application/json"); len(kv) > 1; kv = kv[2:] {
		header.Set(kv[0], kv[1])
	}
	body := `{"recipients":["` + recipient + `"],"expiryDays":1,"files":[{"name":"report.pdf","size":4}]}`
	resp := h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/transfers", c.host, strings.NewReader(body), header)
	var tr createdTransfer
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tr) != nil || tr.ID == "" {
		t.Fatalf("create transfer under %s: %d %s", c.host, resp.status, resp.body)
	}
	return tr
}

// transferOfB asserts that tenant B's sender still reads its transfer trID
// under B's host, not deleted, with recipient among its recipients.
func (h *harness) transferOfB(t *testing.T, op operation, trID, recipient string) {
	t.Helper()
	o := h.other(t)
	header := http.Header{}
	for kv := o.headers(); len(kv) > 1; kv = kv[2:] {
		header.Set(kv[0], kv[1])
	}
	resp := h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1/transfers/"+trID, hostB, nil, header)
	var tr struct {
		Status     string   `json:"status"`
		Recipients []string `json:"recipients"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &tr) != nil {
		t.Fatalf("%s: tenant B's transfer %s after the call: %d %s, want it intact", op, trID, resp.status, resp.body)
	}
	if tr.Status == "deleted" || !strings.Contains(string(resp.body), recipient) {
		t.Errorf("%s: tenant B's transfer %s was changed: %s", op, trID, resp.body)
	}
}

// leaksB lists the data of tenant B that no answer to tenant A's
// delegated admin may hold, extra values (such as B's transfer IDs)
// included.
func (h *harness) leaksB(extra ...string) []string {
	return append([]string{
		nameB, hostB, string(h.tenantB.ID), legalMarkerB, colorB, insiderB, invitedB, blockedB, auditActorB, reportMarkerB,
		h.ops.invitationB, h.ops.entryB, h.ops.auditB,
	}, extra...)
}

// noDataOfB asserts that resp holds none of h.leaksB(extra...).
func (h *harness) noDataOfB(t *testing.T, op operation, what string, resp response, extra ...string) {
	t.Helper()
	for _, s := range h.leaksB(extra...) {
		if s != "" && strings.Contains(string(resp.body), s) {
			t.Errorf("%s: %s leaks %q of tenant B: %s", op, what, s, resp.body)
		}
	}
}

// wantOK asserts a 200 answer and returns its body for decoding.
func wantOK(t *testing.T, op operation, what string, resp response) []byte {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("%s: %s: %d %s, want 200", op, what, resp.status, resp.body)
	}
	return resp.body
}

// sameAsMissing asserts that foreign, the answer for an object of tenant B
// addressed under tenant A's path, is a 404 not-found identical (but for
// its instance) to missing, the answer for an object that does not exist,
// and holds no data of B.
func (h *harness) sameAsMissing(t *testing.T, op operation, foreign, missing response, extra ...string) {
	t.Helper()
	if foreign.status != http.StatusNotFound || problemCode(foreign) != "not-found" {
		t.Fatalf("%s: tenant B's object under tenant A's path: %d %s, want 404 not-found", op, foreign.status, foreign.body)
	}
	if missing.status != foreign.status || string(withoutInstance(t, missing)) != string(withoutInstance(t, foreign)) {
		t.Errorf("%s: tenant B's object answers %d %s, a missing object %d %s: they must be identical",
			op, foreign.status, foreign.body, missing.status, missing.body)
	}
	h.noDataOfB(t, op, "the answer for tenant B's object", foreign, extra...)
}

// invalidInputOfB asserts that the delegated admin of tenant A sending an
// invalid input (query or body) for tenant B gets exactly the answer of an
// unknown tenant (404 not-found), not a validation error: the access is
// checked before the input.
func (h *harness) invalidInputOfB(t *testing.T, op operation, sess adminSession, method, rest, body string) {
	t.Helper()
	foreign := h.adminCall(t, sess, method, tenantPath(h.tenantB.ID, rest), body)
	missing := h.adminCall(t, sess, method, tenantPath(tenant.ID(id.New(id.Tenant)), rest), body)
	h.sameAsMissing(t, op, foreign, missing)
}

// adminOperation is the isolation case of an operation of a tenant
// (tenantops, stats, datasubject): served on the admin host only, tenant
// B's ID answered like an unknown tenant (adminTenantOp), then the checks
// of the operation on the objects of B (opsChecks).
func adminOperation(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	check, ok := opsChecks[op.id]
	if !ok {
		t.Fatalf("%s has no entry in opsChecks", op)
	}
	check(t, h, op, h.session(t))
}

// opsChecks are the per-operation checks of adminOperation, run with the
// session of tenant A's delegated admin.
var opsChecks = map[string]func(t *testing.T, h *harness, op operation, sess adminSession){
	"listTenantTransfers":        checkListTransfers,
	"getTenantTransfer":          checkGetTransfer,
	"deleteTenantTransfer":       checkDeleteTransfer,
	"resendTransferNotification": checkResend,
	"listTenantInvitations":      checkListInvitations,
	"revokeInvitation":           checkRevokeInvitation,
	"listBlocklist":              checkListBlocklist,
	"createBlocklistEntry":       checkCreateBlocklistEntry,
	"deleteBlocklistEntry":       checkDeleteBlocklistEntry,
	"listTenantAuditEvents":      checkTenantAudit,
	"getTenantStats":             checkTenantStats,
	"searchDataSubject":          checkSearchDataSubject,
	"eraseDataSubject":           checkEraseDataSubject,
	"listAbuseReports":           checkListAbuseReports,
	"getAbuseReport":             checkGetAbuseReport,
	"updateAbuseReport":          checkUpdateAbuseReport,
}

// checkListTransfers: A's list holds A's transfer, never B's, even
// filtered on B's sender.
func checkListTransfers(t *testing.T, h *harness, op operation, sess adminSession) {
	trA := h.newTransfer(t, h.colleague(t), "ivan@customer.example.net")
	trB := h.newTransfer(t, h.other(t), "ivan@customer.example.net")
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/transfers?limit=200"), "")
	if body := wantOK(t, op, "tenant A's list", resp); !strings.Contains(string(body), trA.ID) {
		t.Errorf("%s: tenant A's list misses its transfer %s: %s", op, trA.ID, body)
	}
	h.noDataOfB(t, op, "tenant A's list", resp, trB.ID)
	q := url.Values{"email": {insiderB}}
	resp = h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/transfers?"+q.Encode()), "")
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(wantOK(t, op, "tenant A's list filtered on B's sender", resp), &page) != nil || len(page.Items) != 0 {
		t.Errorf("%s: tenant A's list filtered on B's sender: %s, want no item", op, resp.body)
	}
	h.noDataOfB(t, op, "tenant A's filtered list", resp, trB.ID)
}

// checkGetTransfer: A's transfer is read under A's path, B's answers like
// a missing transfer.
func checkGetTransfer(t *testing.T, h *harness, op operation, sess adminSession) {
	trA := h.newTransfer(t, h.colleague(t), "ivan@customer.example.net")
	trB := h.newTransfer(t, h.other(t), "ivan@customer.example.net")
	own := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/transfers/"+trA.ID), "")
	if body := wantOK(t, op, "tenant A's transfer", own); !strings.Contains(string(body), trA.ID) {
		t.Errorf("%s: tenant A's transfer: %s", op, body)
	}
	foreign := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/transfers/"+trB.ID), "")
	missing := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/transfers/"+id.New(id.Transfer)), "")
	h.sameAsMissing(t, op, foreign, missing, trB.ID)
}

// checkDeleteTransfer: B's transfer under A's path answers like a missing
// transfer and stays intact; A's own transfer is deleted.
func checkDeleteTransfer(t *testing.T, h *harness, op operation, sess adminSession) {
	trA := h.newTransfer(t, h.colleague(t), "ivan@customer.example.net")
	trB := h.newTransfer(t, h.other(t), "ivan@customer.example.net")
	body := `{"reason":"isolation check"}`
	foreign := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/transfers/"+trB.ID), body)
	missing := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/transfers/"+id.New(id.Transfer)), body)
	h.sameAsMissing(t, op, foreign, missing, trB.ID)
	h.transferOfB(t, op, trB.ID, "ivan@customer.example.net")
	if own := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/transfers/"+trA.ID), body); own.status != http.StatusNoContent {
		t.Errorf("%s: tenant A's own transfer: %d %s, want 204", op, own.status, own.body)
	}
}

// checkResend: B's transfer under A's path answers like a missing
// transfer; A's own transfer is reached (not available yet: 409).
func checkResend(t *testing.T, h *harness, op operation, sess adminSession) {
	trA := h.newTransfer(t, h.colleague(t), "ivan@customer.example.net")
	trB := h.newTransfer(t, h.other(t), "ivan@customer.example.net")
	foreign := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/transfers/"+trB.ID+"/resend"), "{}")
	missing := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/transfers/"+id.New(id.Transfer)+"/resend"), "{}")
	h.sameAsMissing(t, op, foreign, missing, trB.ID)
	own := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/transfers/"+trA.ID+"/resend"), "{}")
	wantCode(t, op, hostAdmin, own, http.StatusConflict, "state-conflict")
}

// checkListInvitations: A's list holds A's invitations, never B's.
func checkListInvitations(t *testing.T, h *harness, op operation, sess adminSession) {
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/invitations?limit=200"), "")
	if body := wantOK(t, op, "tenant A's list", resp); !strings.Contains(string(body), invitedA) {
		t.Errorf("%s: tenant A's list misses its invitation: %s", op, body)
	}
	h.noDataOfB(t, op, "tenant A's list", resp)
}

// checkRevokeInvitation: B's invitation under A's path answers like a
// missing invitation and stays pending; A's own invitation is revoked.
func checkRevokeInvitation(t *testing.T, h *harness, op operation, sess adminSession) {
	foreign := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/invitations/"+h.ops.invitationB), "")
	missing := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/invitations/"+id.New(id.Invitation)), "")
	h.sameAsMissing(t, op, foreign, missing)
	var page struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	resp := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/invitations?limit=200"), "")
	if json.Unmarshal(wantOK(t, op, "tenant B's list (super admin)", resp), &page) != nil {
		t.Fatalf("%s: tenant B's list: %s", op, resp.body)
	}
	found := false
	for _, it := range page.Items {
		if it.ID == h.ops.invitationB {
			found = true
			if it.Status != "pending" {
				t.Errorf("%s: tenant B's invitation is %q after the call under A's path, want pending", op, it.Status)
			}
		}
	}
	if !found {
		t.Errorf("%s: tenant B's invitation is gone: %s", op, resp.body)
	}
	if own := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/invitations/"+h.ops.invitationA), ""); own.status != http.StatusNoContent {
		t.Errorf("%s: tenant A's own invitation: %d %s, want 204", op, own.status, own.body)
	}
}

// checkListBlocklist: A's list holds A's entry, never B's.
func checkListBlocklist(t *testing.T, h *harness, op operation, sess adminSession) {
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/blocklist?limit=200"), "")
	if body := wantOK(t, op, "tenant A's list", resp); !strings.Contains(string(body), h.ops.entryA) {
		t.Errorf("%s: tenant A's list misses its entry: %s", op, body)
	}
	h.noDataOfB(t, op, "tenant A's list", resp)
}

// checkCreateBlocklistEntry: A blocks the value B already blocks without
// conflict (B's entry is neither revealed nor reused), then a duplicate
// within A conflicts; the entry is removed afterwards.
func checkCreateBlocklistEntry(t *testing.T, h *harness, op operation, sess adminSession) {
	for _, bad := range []string{`{}`, `null`, `{"kind":"domain","value":"not a domain"}`} {
		h.invalidInputOfB(t, op, sess, http.MethodPost, "/blocklist", bad)
	}
	body := `{"kind":"domain","value":"` + blockedB + `"}`
	resp := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/blocklist"), body)
	var e struct {
		ID string `json:"id"`
	}
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &e) != nil || e.ID == "" || e.ID == h.ops.entryB {
		t.Fatalf("%s: tenant A blocking the value of B's entry: %d %s, want 201 with a new entry", op, resp.status, resp.body)
	}
	if strings.Contains(string(resp.body), auditActorB) {
		t.Errorf("%s: the new entry of A shows B's creator: %s", op, resp.body)
	}
	wantCode(t, op, hostAdmin, h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/blocklist"), body),
		http.StatusConflict, "already-exists")
	if del := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/blocklist/"+e.ID), ""); del.status != http.StatusNoContent {
		t.Errorf("%s: removing the entry of A: %d %s", op, del.status, del.body)
	}
	h.blocklistOfB(t, op)
}

// checkDeleteBlocklistEntry: B's entry under A's path answers like a
// missing entry and stays in B's blocklist.
func checkDeleteBlocklistEntry(t *testing.T, h *harness, op operation, sess adminSession) {
	foreign := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/blocklist/"+h.ops.entryB), "")
	missing := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/blocklist/"+id.New(id.Blocklist)), "")
	h.sameAsMissing(t, op, foreign, missing)
	h.blocklistOfB(t, op)
}

// blocklistOfB asserts, as the super admin, that B's blocklist still holds
// B's entry.
func (h *harness) blocklistOfB(t *testing.T, op operation) {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/blocklist?limit=200"), "")
	if body := wantOK(t, op, "tenant B's blocklist (super admin)", resp); !strings.Contains(string(body), h.ops.entryB) {
		t.Errorf("%s: tenant B's entry is gone: %s", op, body)
	}
}

// checkTenantAudit: A's audit log never holds B's event, even filtered on
// B's actor, while B's log (read by the super admin) does.
func checkTenantAudit(t *testing.T, h *harness, op operation, sess adminSession) {
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/audit-events?limit=200"), "")
	wantOK(t, op, "tenant A's audit log", resp)
	// blockedB is left out: the createBlocklistEntry case blocks it in A
	// too, which A's own log records.
	for _, s := range []string{
		nameB, hostB, string(h.tenantB.ID), insiderB, invitedB, auditActorB, h.ops.invitationB, h.ops.entryB, h.ops.auditB,
	} {
		if strings.Contains(string(resp.body), s) {
			t.Errorf("%s: tenant A's audit log leaks %q of tenant B: %s", op, s, resp.body)
		}
	}
	q := url.Values{"actor": {auditActorB}}
	resp = h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/audit-events?"+q.Encode()), "")
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(wantOK(t, op, "tenant A's audit log filtered on B's actor", resp), &page) != nil || len(page.Items) != 0 {
		t.Errorf("%s: tenant A's audit log filtered on B's actor: %s, want no item", op, resp.body)
	}
	resp = h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/audit-events?limit=200"), "")
	if body := wantOK(t, op, "tenant B's audit log (super admin)", resp); !strings.Contains(string(body), h.ops.auditB) {
		t.Errorf("%s: tenant B's audit log misses its event: %s", op, body)
	}
}

// checkTenantStats: A's statistics carry nothing of B.
func checkTenantStats(t *testing.T, h *harness, op operation, sess adminSession) {
	h.invalidInputOfB(t, op, sess, http.MethodGet, "/stats?period=1y", "")
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/stats?period=7d"), "")
	var st struct {
		Period            string `json:"period"`
		StorageQuotaBytes int64  `json:"storageQuotaBytes"`
	}
	if json.Unmarshal(wantOK(t, op, "tenant A's statistics", resp), &st) != nil || st.Period != "7d" || st.StorageQuotaBytes != h.tenantA.StorageQuotaBytes {
		t.Errorf("%s: tenant A's statistics: %s", op, resp.body)
	}
	h.noDataOfB(t, op, "tenant A's statistics", resp)
}

// subjectSummary is the answer of searchDataSubject.
type subjectSummary struct {
	Email                string `json:"email"`
	VerifiedAddress      bool   `json:"verifiedAddress"`
	TransfersAsSender    int    `json:"transfersAsSender"`
	TransfersAsRecipient int    `json:"transfersAsRecipient"`
	Invitations          int    `json:"invitations"`
	AuditEvents          int    `json:"auditEvents"`
	SecurityEvents       int    `json:"securityEvents"`
}

// search runs searchDataSubject for addr in tenant tid with sess.
func (h *harness) search(t *testing.T, op operation, sess adminSession, tid tenant.ID, addr string) subjectSummary {
	t.Helper()
	resp := h.adminCall(t, sess, http.MethodPost, tenantPath(tid, "/data-subjects/search"), `{"email":"`+addr+`"}`)
	var s subjectSummary
	if json.Unmarshal(wantOK(t, op, "search in "+string(tid), resp), &s) != nil {
		t.Fatalf("%s: search in %s: %s", op, tid, resp.body)
	}
	return s
}

// checkSearchDataSubject: an address that is a recipient in both tenants
// is counted once in A (its transfer of A only), once in B; B's sender is
// not known at all in A.
func checkSearchDataSubject(t *testing.T, h *harness, op operation, sess adminSession) {
	for _, bad := range []string{`{}`, `{"email":"not an address"}`, `{"email":"Grace <grace@shared.example.net>"}`} {
		h.invalidInputOfB(t, op, sess, http.MethodPost, "/data-subjects/search", bad)
	}
	const shared = "grace@shared.example.net"
	h.newTransfer(t, h.colleague(t), shared)
	h.newTransfer(t, h.other(t), shared)
	if got := h.search(t, op, sess, h.tenantA.ID, shared); got.TransfersAsRecipient != 1 || got.TransfersAsSender != 0 || got.Invitations != 0 {
		t.Errorf("%s: %s in tenant A = %+v, want its single transfer of A", op, shared, got)
	}
	if got := h.search(t, op, h.superSession(t), h.tenantB.ID, shared); got.TransfersAsRecipient != 1 {
		t.Errorf("%s: %s in tenant B (super admin) = %+v, want its single transfer of B", op, shared, got)
	}
	if got := h.search(t, op, sess, h.tenantA.ID, insiderB); got != (subjectSummary{Email: insiderB}) {
		t.Errorf("%s: tenant B's sender in tenant A = %+v, want nothing", op, got)
	}
	if got := h.search(t, op, h.superSession(t), h.tenantB.ID, insiderB); got.TransfersAsSender == 0 {
		t.Errorf("%s: tenant B's sender in tenant B (super admin) = %+v, want its transfers", op, got)
	}
}

// checkEraseDataSubject: erasing in A an address known in both tenants
// leaves B's transfer, B's sender session and B's invitation untouched.
func checkEraseDataSubject(t *testing.T, h *harness, op operation, sess adminSession) {
	for _, bad := range []string{`null`, `{"email":"not an address"}`} {
		h.invalidInputOfB(t, op, sess, http.MethodPost, "/data-subjects/erase", bad)
	}
	const shared = "heidi@shared.example.net"
	h.newTransfer(t, h.colleague(t), shared)
	trB := h.newTransfer(t, h.other(t), shared)
	for _, addr := range []string{shared, insiderB} {
		resp := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/data-subjects/erase"), `{"email":"`+addr+`"}`)
		wantOK(t, op, "erasure in tenant A", resp)
		h.noDataOfB(t, op, "erasure in tenant A", resp, trB.ID)
	}
	if got := h.search(t, op, sess, h.tenantA.ID, shared); got.TransfersAsRecipient != 0 {
		t.Errorf("%s: %s in tenant A after its erasure = %+v, want nothing", op, shared, got)
	}
	if got := h.search(t, op, h.superSession(t), h.tenantB.ID, shared); got.TransfersAsRecipient != 1 {
		t.Errorf("%s: %s in tenant B after the erasure in A = %+v, want its transfer of B", op, shared, got)
	}
	// B's sender still has its session (other reads it) and its transfers.
	h.transferOfB(t, op, trB.ID, shared)
	if got := h.search(t, op, h.superSession(t), h.tenantB.ID, insiderB); got.TransfersAsSender == 0 {
		t.Errorf("%s: tenant B's sender in tenant B after the erasure in A = %+v, want its transfers", op, got)
	}
}

// superAdminOperation is the isolation case of an instance-wide
// operation: served on the admin host only, 403 forbidden for tenant A's
// delegated admin, without data of any tenant; served to the super admin.
func superAdminOperation(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	path := strings.TrimPrefix(op.template, "/")
	deleg := h.adminCall(t, h.session(t), op.verb, "/"+path, "")
	wantCode(t, op, hostAdmin, deleg, http.StatusForbidden, "forbidden")
	h.noDataOfB(t, op, "the answer to a delegated admin", deleg)
	noLeak(t, h, op, hostAdmin, deleg)
	// The same refusal with a filter on tenant B.
	q := url.Values{"tenantId": {string(h.tenantB.ID)}}
	filtered := h.adminCall(t, h.session(t), op.verb, "/"+path+"?"+q.Encode(), "")
	if filtered.status != http.StatusForbidden || string(withoutInstance(t, filtered)) != string(withoutInstance(t, deleg)) {
		t.Errorf("%s filtered on tenant B: %d %s, want the same 403", op, filtered.status, filtered.body)
	}
	super := h.superSession(t)
	all := h.adminCall(t, super, op.verb, "/"+path+"?limit=200", "")
	wantOK(t, op, "super admin", all)
	switch op.id {
	case "getGlobalStats":
		for _, tid := range []tenant.ID{h.tenantA.ID, h.tenantB.ID} {
			if !strings.Contains(string(all.body), string(tid)) {
				t.Errorf("%s: the super admin's dashboard misses tenant %s: %s", op, tid, all.body)
			}
		}
	case "listGlobalAuditEvents":
		if !strings.Contains(string(all.body), h.ops.auditB) {
			t.Errorf("%s: the instance audit log misses B's event: %s", op, all.body)
		}
		qa := url.Values{"tenantId": {string(h.tenantA.ID)}, "limit": {"200"}}
		onlyA := h.adminCall(t, super, op.verb, "/"+path+"?"+qa.Encode(), "")
		wantOK(t, op, "super admin filtered on tenant A", onlyA)
		if strings.Contains(string(onlyA.body), h.ops.auditB) || strings.Contains(string(onlyA.body), string(h.tenantB.ID)) {
			t.Errorf("%s filtered on tenant A holds events of B: %s", op, onlyA.body)
		}
	}
}
