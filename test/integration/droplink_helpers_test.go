package integration_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
)

// Helpers of the permanent drop link and link-only tests (CLAUDE.md
// sections 8.2, 22; api/openapi.yaml "Drop links", getPublicDropLink,
// reissueMyTransferLink; threat model T-3xx of the drop link).

const (
	pathDropLinks      = "/api/v1/drop-links/"
	opGetPublicDrop    = "getPublicDropLink"
	opCreateDropLink   = "createDropLink"
	opStartDepositSess = "startDepositSession"
)

// dropLinkJSON is the DropLink and DropLinkCreated schemas.
type dropLinkJSON struct {
	ID                   string   `json:"id"`
	Label                string   `json:"label"`
	Recipients           []string `json:"recipients"`
	ValidityDays         int      `json:"validityDays"`
	ConfidentialityLevel *string  `json:"confidentialityLevel"`
	Enabled              bool     `json:"enabled"`
	RevokedAt            *string  `json:"revokedAt"`
	Token                string   `json:"token"`
	URL                  string   `json:"url"`
}

// dropLinksPath is the admin path of the drop links of the tenant tid.
func dropLinksPath(tid string, sub ...string) string {
	return tenantPath(tid, "/drop-links") + strings.Join(sub, "")
}

// createDropLink creates a drop link of tenant A to recipients, checks the
// contract and the token shape, and returns it.
func (o *opsEnv) createDropLink(t *testing.T, label string, level string, recipients ...string) dropLinkJSON {
	t.Helper()
	body := map[string]any{"label": label, "recipients": recipients, "validityDays": 7}
	if level != "" {
		body["confidentialityLevel"] = level
	}
	path := dropLinksPath(o.tid)
	resp := mustStatus(t, opCreateDropLink, o.sa.call(t, http.MethodPost, path, body), http.StatusCreated)
	expectContract(t, opCreateDropLink, http.MethodPost, path, resp)
	var l dropLinkJSON
	mustJSON(t, resp.body, &l)
	if !id.DropTokenValid(l.Token) || l.URL != id.DropURL(hostA, l.Token) {
		t.Fatalf("created link = %s, want a ttd_ token and its /drop/ url", resp.body)
	}
	o.secret(l.Token)
	return l
}

// patchDropLink sends updateDropLink.
func (o *opsEnv) patchDropLink(t *testing.T, linkID, body string) response {
	t.Helper()
	return o.sa.mergePatch(t, dropLinksPath(o.tid, "/", linkID), body)
}

// landing sends getPublicDropLink as an external client.
func (o *opsEnv) landing(t *testing.T, token string) response {
	t.Helper()
	return o.do(t, request{host: hostA, path: pathDropLinks + token, headers: http.Header{hdrXFF: {outside}}})
}

// dropSession runs the code flow of an external depositor through the drop
// link token: the address has received n-1 code mails before. The code is
// always asked, never a recognition cookie.
func (o *opsEnv) dropSession(t *testing.T, token, email string, n int) (*depositor, sessionJSON) {
	t.Helper()
	c := &depositor{d: o.depositEnv, host: hostA, ip: outside}
	ch := expectChallenge(t, c.startDrop(t, email, token), email)
	code := o.waitCode(t, email, n)
	resp := c.confirm(t, ch.ChallengeID, code)
	expectContract(t, "confirmVerificationChallenge", http.MethodPost, "/api/v1/verification-challenges/"+ch.ChallengeID+"/confirm", resp)
	s, cookie, known := expectSessionWithKnown(t, resp, email)
	if known != "" {
		t.Errorf("a drop link session set the recognition cookie %q", known)
	}
	if s.Kind != "drop_link" || s.DropLink == nil || s.CanInvite {
		t.Errorf("session = %s, want a drop_link session that cannot invite", resp.body)
	}
	c.cookie, c.csrf = cookie, s.CSRFToken
	return c, s
}

// startDrop sends startDepositSession with a dropLinkToken.
func (c *depositor) startDrop(t *testing.T, email, token string) response {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"email": email, "dropLinkToken": token})
	resp := c.send(t, http.MethodPost, pathSessions, string(b), nil)
	expectContract(t, opStartDepositSess, http.MethodPost, pathSessions, resp)
	return resp
}
