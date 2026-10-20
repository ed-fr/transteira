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

// Fictitious depositors of tenant A (CLAUDE.md section 25).
const (
	insiderA = "alice@entity-a.localhost"
	invitedA = "bob@partner.example.org"
)

// depositFixtures are deposit resources of tenant A, created directly in
// the database: an internal deposit session, an active invitation for
// invitedA and an open verification challenge bound to that invitation.
type depositFixtures struct {
	sessionToken    string
	invitationToken string
	challengeID     string
}

// seedDeposit creates the deposit fixtures of tenant tid.
func seedDeposit(t *testing.T, db *store.DB, tid tenant.ID) depositFixtures {
	t.Helper()
	ctx := context.Background()
	newToken := func(prefix string, n int) string {
		tok, err := id.NewToken(prefix, n)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	hash := func(tok string) []byte {
		h := sha256.Sum256([]byte(tok))
		return h[:]
	}
	f := depositFixtures{
		sessionToken:    newToken("ds", 32),
		invitationToken: newToken("inv", 32),
		challengeID:     newToken("vch", 16),
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := db.DepositSessions().Create(ctx, tid, store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: hash(f.sessionToken), Email: insiderA,
		Kind: store.DepositorInternal, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	invID := id.New(id.Invitation)
	if err := db.Invitations().Create(ctx, tid, store.Invitation{
		ID: invID, TokenHash: hash(f.invitationToken), Email: invitedA, InvitedBy: insiderA, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if err := db.Challenges().Create(ctx, tid, store.Challenge{
		ID: f.challengeID, Email: invitedA, CodeMAC: []byte("not the mac of any code"), AttemptsRemaining: 2,
		InvitationID: invID, ClientIP: netip.MustParseAddr("198.51.100.1"), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	return f
}

// call sends a request for op (path parameters given by params) under
// host, with an optional JSON body and extra headers given as pairs.
func (h *harness) call(t *testing.T, op operation, host string, params map[string]string, body string, hdr ...string) response {
	t.Helper()
	path := op.template
	for k, v := range params {
		path = strings.ReplaceAll(path, "{"+k+"}", v)
	}
	header := http.Header{}
	var reader *strings.Reader
	if body != "" {
		header.Set("Content-Type", "application/json")
		reader = strings.NewReader(body)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		header.Set(hdr[i], hdr[i+1])
	}
	target := "http://" + h.addr + op.base + path
	if reader == nil {
		return h.do(t, op.verb, target, host, nil, header)
	}
	return h.do(t, op.verb, target, host, reader, header)
}

// wantCode asserts resp is a Problem with status and code.
func wantCode(t *testing.T, op operation, host string, resp response, status int, code string) {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(resp.body, &p)
	if resp.status != status || p.Code != code {
		t.Fatalf("%s under %s: %d %s, want %d %s", op, host, resp.status, resp.body, status, code)
	}
}

// refusedUnderB asserts the answer under tenant B is the expected refusal
// and carries no data of tenant A (the depositors' addresses included).
func refusedUnderB(t *testing.T, h *harness, op operation, resp response, status int, code string) {
	t.Helper()
	wantCode(t, op, hostB, resp, status, code)
	noLeak(t, h, op, hostB, resp)
	for _, s := range []string{insiderA, invitedA} {
		if strings.Contains(string(resp.body), s) {
			t.Errorf("%s under %s leaks %q", op, hostB, s)
		}
	}
	if sc := resp.header.Get("Set-Cookie"); sc != "" {
		t.Errorf("%s under %s sets a cookie: %q", op, hostB, sc)
	}
}

func (h *harness) cookie() []string {
	return []string{"Cookie", "__Host-tt_deposit=" + h.fixtures.sessionToken}
}

// startWithForeignInvitation: tenant A's invitation token lets its invited
// address start a session under A (which then needs a code, and fails with
// 503 mail-unavailable since A has no SMTP settings), but is unknown under
// B: 403 deposit-not-allowed.
func startWithForeignInvitation(t *testing.T, h *harness, op operation) {
	t.Helper()
	body := `{"email":"` + invitedA + `","invitationToken":"` + h.fixtures.invitationToken + `"}`
	wantCode(t, op, hostA, h.call(t, op, hostA, nil, body), http.StatusServiceUnavailable, "mail-unavailable")
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, body), http.StatusForbidden, "deposit-not-allowed")
}

// confirmForeignChallenge: tenant A's challenge is found under A (a wrong
// code spends an attempt: 422) and unknown under B (404).
func confirmForeignChallenge(t *testing.T, h *harness, op operation) {
	t.Helper()
	params := map[string]string{"challengeId": h.fixtures.challengeID}
	refusedUnderB(t, h, op, h.call(t, op, hostB, params, `{"code":"000000"}`), http.StatusNotFound, "not-found")
	wantCode(t, op, hostA, h.call(t, op, hostA, params, `{"code":"000000"}`), http.StatusUnprocessableEntity, "verification-code-invalid")
}

// currentWithForeignSession: tenant A's session cookie is served under A
// and unauthenticated under B.
func currentWithForeignSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	a := h.call(t, op, hostA, nil, "", h.cookie()...)
	if a.status != http.StatusOK || !strings.Contains(string(a.body), insiderA) {
		t.Fatalf("%s under %s: %d %s, want the session", op, hostA, a.status, a.body)
	}
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, "", h.cookie()...), http.StatusUnauthorized, "unauthenticated")
}

// endWithForeignSession: tenant A's session cookie is recognized under A
// (refused for its missing CSRF token, so the session survives for the
// other cases) and unauthenticated under B.
func endWithForeignSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	wantCode(t, op, hostA, h.call(t, op, hostA, nil, "", h.cookie()...), http.StatusForbidden, "csrf-invalid")
	hdr := append(h.cookie(), "X-CSRF-Token", "csrf_forged")
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, "", hdr...), http.StatusUnauthorized, "unauthenticated")
}

// inviteWithForeignSession: same as endWithForeignSession for invitations.
func inviteWithForeignSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	body := `{"email":"carol@partner.example.org"}`
	wantCode(t, op, hostA, h.call(t, op, hostA, nil, body, h.cookie()...), http.StatusForbidden, "csrf-invalid")
	hdr := append(h.cookie(), "X-CSRF-Token", "csrf_forged")
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, body, hdr...), http.StatusUnauthorized, "unauthenticated")
}

// getForeignInvitation: tenant A's invitation token is shown under A and
// unknown under B.
func getForeignInvitation(t *testing.T, h *harness, op operation) {
	t.Helper()
	params := map[string]string{"invitationToken": h.fixtures.invitationToken}
	a := h.call(t, op, hostA, params, "")
	if a.status != http.StatusOK || !strings.Contains(string(a.body), invitedA) {
		t.Fatalf("%s under %s: %d %s, want the invitation", op, hostA, a.status, a.body)
	}
	refusedUnderB(t, h, op, h.call(t, op, hostB, params, ""), http.StatusNotFound, "not-found")
}
