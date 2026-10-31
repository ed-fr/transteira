package integration_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// mailedLinkRE finds an activation link in a mail body.
var mailedLinkRE = regexp.MustCompile(`https://` + regexp.QuoteMeta(adminHost) + `/admin/activate#(act_[0-9A-Za-z]{43})`)

// TestAdminInvitationByMail covers the V1.2 delivery of an activation link
// by mail through the system SMTP (threat model T-254 to T-257): the link
// reaches the administrator by mail only, never in the API answer; TOTP is
// then mandatory; a new invitation revokes the previous link.
func TestAdminInvitationByMail(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		mp := mailpitEnv(t)
		a := startAdmin(t, e, serverOptions{env: systemSMTPEnv(mp)}, false)
		sa := a.bootstrap(t, adminIP(10))
		email := uniqueEmail(t, "invited", domainA)
		resp := sa.call(t, http.MethodPost, pathAdmins, map[string]any{
			"username": "invited.one", "email": email, "role": "delegated_admin", "requireTotp": false,
			"tenantIds": []string{string(a.tenantA.ID)}, "invitation": map[string]any{"delivery": "mail", "language": "fr"},
		})
		if resp.status != http.StatusCreated {
			t.Fatalf("createAdmin: %d %s", resp.status, resp.body)
		}
		if strings.Contains(string(resp.body), "activationUrl") || strings.Contains(string(resp.body), "act_") {
			t.Errorf("the answer carries the link: %s", resp.body)
		}
		var created struct {
			ID                 string `json:"id"`
			RequireTOTP        bool   `json:"requireTotp"`
			InvitationDelivery string `json:"invitationDelivery"`
		}
		mustJSON(t, resp.body, &created)
		if created.InvitationDelivery != "mail" || !created.RequireTOTP {
			t.Errorf("created = %+v, want mail delivery and TOTP forced", created)
		}
		msg := mp.find(t, email, func(mpMessage) bool { return true })
		m := mailedLinkRE.FindStringSubmatch(msg.Text + msg.HTML)
		if m == nil {
			t.Fatalf("no activation link in the mail:\n%s", msg.Text)
		}
		first := m[1]
		a.secret(first)

		// A new invitation revokes the link of the first mail.
		resp = sa.call(t, http.MethodPost, pathAdmins+"/"+created.ID+"/invite", map[string]any{"delivery": "mail", "language": "en"})
		if resp.status != http.StatusOK || strings.Contains(string(resp.body), "act_") {
			t.Fatalf("inviteAdmin: %d %s", resp.status, resp.body)
		}
		// The second mail is the English one (the summaries carry no body).
		msg = mp.find(t, email, func(msg mpMessage) bool { return msg.Subject == "Your TransTeira administrator account" })
		m = mailedLinkRE.FindStringSubmatch(msg.Text + msg.HTML)
		if m == nil || m[1] == first {
			t.Fatalf("no new activation link in the second mail:\n%s", msg.Text)
		}
		second := m[1]
		a.secret(second)
		acct := &adminAccount{username: "invited.one", email: email, password: "invited password one"}
		a.secret(acct.password)
		d := a.client(acct, adminIP(20))
		expectProblem(t, d.activate(t, first), http.StatusNotFound, "not-found")
		if resp := d.activate(t, second); resp.status != http.StatusOK || d.state != stateEnrollRequired {
			t.Fatalf("activate: %d %s, want state %s", resp.status, resp.body, stateEnrollRequired)
		}

		// Activated: nothing more to invite.
		expectProblem(t, sa.call(t, http.MethodPost, pathAdmins+"/"+created.ID+"/invite", map[string]any{"delivery": "copy"}),
			http.StatusConflict, "admin-already-active")
		// An activated super admin is refused first for being active; the
		// refusal of a mailed link to a super admin account not yet
		// activated is covered by the adminauth tests.
		expectProblem(t, sa.call(t, http.MethodPost, pathAdmins+"/"+sa.acct.id+"/invite", map[string]any{"delivery": "mail"}),
			http.StatusConflict, "admin-already-active")
		a.expectLogsClean(t, nil)
	})
}

// TestAdminInvitationWithoutSystemSMTP: the mail delivery is refused with a
// 503 and creates nothing.
func TestAdminInvitationWithoutSystemSMTP(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(10))
		resp := sa.call(t, http.MethodPost, pathAdmins, map[string]any{
			"username": "invited.two", "email": uniqueEmail(t, "invited", domainA), "role": "delegated_admin",
			"tenantIds": []string{string(a.tenantA.ID)}, "invitation": map[string]any{"delivery": "mail"},
		})
		expectProblem(t, resp, http.StatusServiceUnavailable, "system-smtp-unavailable")
		resp = sa.call(t, http.MethodGet, pathAdmins, nil)
		if strings.Contains(string(resp.body), "invited.two") {
			t.Errorf("the account was created despite the refusal: %s", resp.body)
		}
	})
}
