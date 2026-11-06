package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Integration tests of the link-only transfers (CLAUDE.md section 8.2;
// api/openapi.yaml createTransfer linkOnly, finalizeTransfer,
// reissueMyTransferLink; threat model T-3xx).

// pathMeTransfers is the base of the "My transfers" operations.
const pathMeTransfers = "/api/v1/me/transfers/"

// setLinkOnly allows or forbids the link-only transfers of tenant A, as
// the super admin would.
func (o *opsEnv) setLinkOnly(t *testing.T, on bool) {
	t.Helper()
	body := `{"linkOnlyAllowed":false}`
	if on {
		body = `{"linkOnlyAllowed":true}`
	}
	mustStatus(t, "updateTenant linkOnlyAllowed", o.sa.mergePatch(t, tenantPath(o.tid, ""), body), http.StatusOK)
}

// linkOnlyCreate is a link-only request of one file.
func linkOnlyCreate(recipients ...string) transferCreate {
	return transferCreate{Recipients: recipients, ExpiryDays: 7, LinkOnly: true, Files: []fileDecl{{Name: "a.txt", Size: 5}}}
}

// downloadURLOf decodes downloadUrl of a SenderTransfer body.
func downloadURLOf(t *testing.T, resp response) string {
	t.Helper()
	var v struct {
		DownloadURL string `json:"downloadUrl"`
	}
	mustJSON(t, resp.body, &v)
	return v.DownloadURL
}

// TestLinkOnlyFlow: a link-only transfer returns its link once, in the
// answer of the finalization, mails nobody but the sender (whose
// confirmation has no link), downloads once the scan ended, never shows the
// link again, and a reissue through "My transfers" kills the old link.
func TestLinkOnlyFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.setLinkOnly(t, true)
		alice, aliceMail := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "carol", "example.net")
		content := []byte("hello")

		tr := alice.mustCreate(t, linkOnlyCreate(rcpt))
		alice.upload(t, tr.Files[0].UploadURL, content)
		if tr.DownloadURL != "" {
			t.Errorf("createTransfer carries a download link")
		}
		fin := mustStatus(t, "finalizeTransfer", alice.finalize(t, tr.ID), http.StatusAccepted)
		expectContract(t, "finalizeTransfer", http.MethodPost, pathTransfers+"/"+tr.ID+"/finalize", fin)
		link := downloadURLOf(t, fin)
		token := tokenOf(t, hostA, link)
		o.secret(token)

		// The link is returned once.
		expectTransferProblem(t, alice.finalize(t, tr.ID), http.StatusConflict, "state-conflict")
		eventually(t, "available", func() bool { return alice.mustGet(t, tr.ID).Status == "available" })
		got := alice.getTransfer(t, tr.ID)
		mustStatus(t, "getTransfer", got, http.StatusOK)
		expectNoLink(t, "getTransfer of a link-only transfer", got.body)

		// The sender is told, without link; the recipient is not mailed.
		o.mp.find(t, aliceMail, func(m mpMessage) bool { return strings.Contains(m.Subject, "Your files have been sent") })
		o.mailBarrier(t, alice)
		for _, m := range o.mp.messagesTo(t, aliceMail) {
			if c := o.mp.content(t, m.ID); strings.Contains(c, token) || strings.Contains(c, id.DownloadPath+"dl_") {
				t.Errorf("mail %q to the sender carries the link", m.Subject)
			}
		}
		if n := len(o.mp.messagesTo(t, rcpt)); n != 0 {
			t.Errorf("the recipient of a link-only transfer got %d mails", n)
		}

		// The link downloads.
		rc := o.newRecipient(1)
		page := rc.mustPage(t, token)
		if len(page.Files) != 1 {
			t.Fatalf("page = %+v", page)
		}
		expectFile(t, "link-only download", rc.get(t, filePath(token, page.Files[0].ID), nil), "a.txt", content)

		// Reissue: a new link, the old one is dead.
		me := o.meSessionOf(t, aliceMail)
		path := pathMeTransfers + tr.ID + "/link"
		resp := mustStatus(t, "reissueMyTransferLink", o.do(t, request{method: http.MethodPost, host: hostA, path: path, headers: me}), http.StatusOK)
		expectContract(t, "reissueMyTransferLink", http.MethodPost, path, resp)
		fresh := tokenOf(t, hostA, downloadURLOf(t, resp))
		o.secret(fresh)
		if fresh == token {
			t.Fatal("the reissued link is the old one")
		}
		expectProblem(t, rc.page(t, token), http.StatusNotFound, "not-found")
		if rc.page(t, fresh).status != http.StatusOK {
			t.Errorf("the reissued link does not open")
		}
		expectTransferProblem(t, alice.finalize(t, tr.ID), http.StatusConflict, "state-conflict")

		// A transfer with per-recipient links cannot be reissued.
		plain, _ := alice.availableTransfer(t, transferCreate{Recipients: []string{rcpt}}, uploadedFile{"b.txt", []byte("b")})
		conflict := o.do(t, request{method: http.MethodPost, host: hostA, path: pathMeTransfers + plain.ID + "/link", headers: me})
		expectProblem(t, conflict, http.StatusConflict, "state-conflict")
		expectContract(t, "reissueMyTransferLink", http.MethodPost, pathMeTransfers+plain.ID+"/link", conflict)

		// The admin cannot mail the link: there is none.
		resend := o.sa.call(t, http.MethodPost, tenantPath(o.tid, "/transfers/"+tr.ID+"/resend"), nil)
		expectProblem(t, resend, http.StatusConflict, "state-conflict")
		noSecretInLogs(t, o.server, token, fresh)
	})
}

// TestLinkOnlyRefusals: a link-only request is forbidden by the tenant, by
// the level and by the kind of depositor, and conflicts with the recipient
// verification.
func TestLinkOnlyRefusals(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, _ := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "carol", "example.net")
		forbidden := func(_ string, c *depositor, req transferCreate) {
			t.Helper()
			resp := c.createTransfer(t, req, "")
			expectTransferProblem(t, resp, http.StatusForbidden, "link-only-forbidden")
			expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)
		}

		// The tenant default: not allowed.
		forbidden("tenant default", alice, linkOnlyCreate(rcpt))

		// Conflict with the recipient verification.
		o.setLinkOnly(t, true)
		both := linkOnlyCreate(rcpt)
		both.RecipientVerification = true
		resp := alice.createTransfer(t, both, "")
		expectTransferProblem(t, resp, http.StatusBadRequest, "link-only-conflict")
		expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)

		// An invited external and a drop link depositor.
		guest := uniqueEmail(t, "guest", externalDomain)
		_, token := alice.inviteAndLink(t, guest)
		o.secret(token)
		xe := o.invitedSession(t, guest, token, 1)
		forbidden("invited external", xe, linkOnlyCreate())
		dl := o.createDropLink(t, "Link only", "", uniqueEmail(t, "accounting", domainA))
		dropper, _ := o.dropSession(t, dl.Token, uniqueEmail(t, "supplier", externalDomain), 1)
		forbidden("drop link", dropper, linkOnlyCreate())

		// The level forbids it.
		levels := `{"items":[{"key":"open","labels":{"en":"Open","fr":"Ouvert"},"isDefault":true,"rules":{"requireRecipientVerification":false,"requirePassword":false,"allowedExpiryDays":[1,7,30],"internalRecipientsOnly":false,"forceDeleteAfterFirstDownload":false,"maxDownloads":null,"linkOnlyAllowed":false}}]}`
		mustStatus(t, "levels", o.sa.send(t, http.MethodPut, tenantPath(o.tid, "/confidentiality-levels"), levels, http.Header{hdrCSRF: {o.sa.csrf}}), http.StatusOK)
		forbidden("level", alice, linkOnlyCreate(rcpt))
	})
}

// TestDropLinkLevelDeletion: removing a confidentiality level used by an
// enabled drop link is refused with 409, and allowed once the link is
// disabled or revoked.
func TestDropLinkLevelDeletion(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		const rules = `"rules":{"requireRecipientVerification":false,"requirePassword":false,"allowedExpiryDays":[1,7,30],"internalRecipientsOnly":false,"forceDeleteAfterFirstDownload":false,"maxDownloads":null}`
		open := `{"key":"open","labels":{"en":"Open","fr":"Ouvert"},"isDefault":true,` + rules + `}`
		extra := `{"key":"extra","labels":{"en":"Extra","fr":"Extra"},"isDefault":false,` + rules + `}`
		put := func(items ...string) response {
			return o.sa.send(t, http.MethodPut, tenantPath(o.tid, "/confidentiality-levels"),
				`{"items":[`+strings.Join(items, ",")+`]}`, http.Header{hdrCSRF: {o.sa.csrf}})
		}
		mustStatus(t, "levels", put(open, extra), http.StatusOK)
		link := o.createDropLink(t, "Extra", "extra", uniqueEmail(t, "accounting", domainA))

		resp := put(open)
		expectProblem(t, resp, http.StatusConflict, "state-conflict")
		expectContract(t, "updateConfidentialityLevels", http.MethodPut, tenantPath(o.tid, "/confidentiality-levels"), resp)

		mustStatus(t, "disable", o.patchDropLink(t, link.ID, `{"enabled":false}`), http.StatusOK)
		mustStatus(t, "levels without extra", put(open), http.StatusOK)
	})
}
