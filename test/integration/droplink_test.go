package integration_test

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Integration tests of the permanent drop links (CLAUDE.md sections 6.3,
// 8.1, 22; api/openapi.yaml getPublicDropLink, startDepositSession with
// dropLinkToken, createTransfer; threat model T-3xx).

// mailWithLink waits for a mail to addr that carries a download link and
// returns the link token.
func (o *opsEnv) mailWithLink(t *testing.T, addr string) string {
	t.Helper()
	m := o.mp.find(t, addr, func(m mpMessage) bool {
		return !strings.Contains(m.Subject, "code") && strings.Contains(o.mp.content(t, m.ID), id.DownloadPath+"dl_")
	})
	loc := strings.Index(o.mp.content(t, m.ID), id.DownloadPath+"dl_")
	rest := o.mp.content(t, m.ID)[loc+len(id.DownloadPath):]
	end := strings.IndexAny(rest, "\"'<> \r\n\\&=")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

// TestDropLinkFlow: a third party identifies itself with a code at every
// use of the link, two sessions in a row each send one transfer to the
// recipients of the link, which are mailed but never shown to the
// depositor; a second transfer in a session, a request that differs from
// the link and any recipient list (even the link's own: no oracle, T-311)
// are refused.
func TestDropLinkFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		r1, r2 := uniqueEmail(t, "accounting", domainA), uniqueEmail(t, "billing", domainA)
		link := o.createDropLink(t, "Supplier invoices", "", r1, r2)
		guest := uniqueEmail(t, "supplier", externalDomain)

		// Landing page: label and duration, never the recipients.
		page := mustStatus(t, opGetPublicDrop, o.landing(t, link.Token), http.StatusOK)
		expectContract(t, opGetPublicDrop, http.MethodGet, pathDropLinks+link.Token, page)
		if body := string(page.body); !strings.Contains(body, "Supplier invoices") || strings.Contains(body, r1) || strings.Contains(body, r2) {
			t.Errorf("landing page = %s, want the label and no recipient", body)
		}

		c, sess := o.dropSession(t, link.Token, guest, 1)
		if sess.DropLink.Label != "Supplier invoices" || sess.DropLink.ValidityDays != 7 {
			t.Errorf("session link = %+v", sess.DropLink)
		}
		file := uploadedFile{"invoice.txt", []byte("invoice one")}

		// What differs from the link is refused.
		wrongDays := transferCreate{ExpiryDays: 1, Files: []fileDecl{{Name: "a.txt", Size: 1}}}
		expectTransferProblem(t, c.createTransfer(t, wrongDays, ""), http.StatusBadRequest, "validation-failed")
		for _, rcpts := range [][]string{{uniqueEmail(t, "elsewhere", "example.net")}, {r1, r2}, {r1}} {
			resp := c.createTransfer(t, transferCreate{Recipients: rcpts, ExpiryDays: 7, Files: []fileDecl{{Name: "a.txt", Size: 1}}}, "")
			expectTransferProblem(t, resp, http.StatusBadRequest, "validation-failed")
			if !strings.Contains(string(resp.body), `"/recipients"`) || strings.Contains(string(resp.body), "/recipients/") {
				t.Errorf("recipients %v: %s", rcpts, resp.body)
			}
		}

		tr, _ := c.availableDrop(t, transferCreate{ExpiryDays: 7}, file)
		if tr.SenderEmail != guest || len(tr.Recipients) != 0 || tr.DropLinkLabel != "Supplier invoices" {
			t.Errorf("transfer = %+v, want no recipient and the link label", tr)
		}
		for _, r := range []string{r1, r2} {
			o.secret(o.mailWithLink(t, r))
		}

		// One transfer per session.
		again := transferCreate{ExpiryDays: 7, Files: []fileDecl{{Name: "b.txt", Size: 1}}}
		expectTransferProblem(t, c.createTransfer(t, again, ""), http.StatusForbidden, "deposit-not-allowed")

		// The code is asked again: a second session in a row, with the
		// same address, needs a second code.
		c2, _ := o.dropSession(t, link.Token, guest, 2)
		tr2, _ := c2.availableDrop(t, transferCreate{ExpiryDays: 7}, uploadedFile{"invoice2.txt", []byte("invoice two")})
		if tr2.ID == tr.ID {
			t.Errorf("both sessions made transfer %s", tr.ID)
		}

		// The admin sees the origin.
		at := o.sa.adminTransfer(t, o.tid, tr.ID)
		if at.Origin != "drop_link" || at.SenderEmail != guest {
			t.Errorf("admin view = %+v, want origin drop_link", at)
		}
		noSecretInLogs(t, o.server, link.Token)
	})
}

// TestDropLinkRefusals: the blocklist stops a blocked address after the
// link was found, and an unknown, malformed, disabled, revoked or rotated
// token answers the same 404 drop-link-invalid with a drop_link_invalid
// line of the security log, whatever the entry point.
func TestDropLinkRefusals(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		rcpt := uniqueEmail(t, "accounting", domainA)
		link := o.createDropLink(t, "Refusals", "", rcpt)
		guest := uniqueEmail(t, "supplier", externalDomain)

		// Blocklist.
		blocked := uniqueEmail(t, "blocked", externalDomain)
		o.block(t, store.BlockEmail, blocked)
		c := &depositor{d: o.depositEnv, host: hostA, ip: outside}
		expectProblem(t, c.startDrop(t, blocked, link.Token), http.StatusForbidden, "deposit-not-allowed")
		if got := reasons(t, o.server); !slices.Contains(got, "blocklist") {
			t.Errorf("deposit_refused reasons = %v, want blocklist", got)
		}
		if n := len(o.mp.messagesTo(t, blocked)); n != 0 {
			t.Errorf("a blocked address got %d mails", n)
		}

		// Unknown and malformed tokens.
		unknown, err := id.NewDropToken()
		if err != nil {
			t.Fatal(err)
		}
		invalid := 0
		check := func(what, token string) {
			t.Helper()
			expectProblem(t, o.landing(t, token), http.StatusNotFound, "drop-link-invalid")
			expectProblem(t, c.startDrop(t, guest, token), http.StatusNotFound, "drop-link-invalid")
			invalid += 2
			if lines := eventsOf(t, o.securityLines(t), "drop_link_invalid"); len(lines) != invalid {
				t.Errorf("%s: %d drop_link_invalid lines, want %d", what, len(lines), invalid)
			}
		}
		check("unknown", unknown)
		check("malformed", "ttd_short")
		check("other prefix", "dl_"+link.Token[4:])

		// Disabled, then enabled again.
		mustStatus(t, "disable", o.patchDropLink(t, link.ID, `{"enabled":false}`), http.StatusOK)
		check("disabled", link.Token)
		mustStatus(t, "enable", o.patchDropLink(t, link.ID, `{"enabled":true}`), http.StatusOK)
		mustStatus(t, "landing", o.landing(t, link.Token), http.StatusOK)

		// A session opened before the link was disabled cannot send.
		c1, _ := o.dropSession(t, link.Token, guest, 1)
		mustStatus(t, "disable", o.patchDropLink(t, link.ID, `{"enabled":false}`), http.StatusOK)
		resp := c1.createTransfer(t, transferCreate{ExpiryDays: 7, Files: []fileDecl{{Name: "a.txt", Size: 1}}}, "")
		if resp.status != http.StatusNotFound && resp.status != http.StatusForbidden && resp.status != http.StatusUnauthorized {
			t.Errorf("createTransfer through a disabled link: %d %s", resp.status, resp.body)
		}
		mustStatus(t, "enable", o.patchDropLink(t, link.ID, `{"enabled":true}`), http.StatusOK)

		// Rotated: the old token is dead, the new one works.
		rot := dropLinksPath(o.tid, "/", link.ID, "/rotate")
		rresp := mustStatus(t, "rotateDropLink", o.sa.call(t, http.MethodPost, rot, nil), http.StatusOK)
		expectContract(t, "rotateDropLink", http.MethodPost, rot, rresp)
		var rotated dropLinkJSON
		mustJSON(t, rresp.body, &rotated)
		if rotated.Token == link.Token || !id.DropTokenValid(rotated.Token) {
			t.Fatalf("rotated link = %s", rresp.body)
		}
		o.secret(rotated.Token)
		check("rotated", link.Token)
		mustStatus(t, "landing of the new token", o.landing(t, rotated.Token), http.StatusOK)

		// Revoked: final.
		del := dropLinksPath(o.tid, "/", link.ID)
		dresp := mustStatus(t, "deleteDropLink", o.sa.call(t, http.MethodDelete, del, nil), http.StatusNoContent)
		expectContract(t, "deleteDropLink", http.MethodDelete, del, dresp)
		check("revoked", rotated.Token)
		got := mustStatus(t, "getDropLink", o.sa.call(t, http.MethodGet, del, nil), http.StatusOK)
		expectContract(t, "getDropLink", http.MethodGet, del, got)
		if !strings.Contains(string(got.body), `"revokedAt":"`) {
			t.Errorf("revoked link = %s", got.body)
		}

		// Format of the line, and no token in the logs.
		for _, l := range eventsOf(t, o.securityLines(t), "drop_link_invalid") {
			if l.ip != outside || l.tenant != hostA {
				t.Errorf("line %q, want ip=%s tenant=%s", l.raw, outside, hostA)
			}
		}
		noSecretInLogs(t, o.server, link.Token, rotated.Token)
	})
}

// TestDropLinkContract validates the answers of the other administration
// operations against the specification.
func TestDropLinkContract(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		rcpt := uniqueEmail(t, "accounting", domainA)
		link := o.createDropLink(t, "Contract", "", rcpt)
		list := dropLinksPath(o.tid)
		expectContract(t, "listDropLinks", http.MethodGet, list, mustStatus(t, "list", o.sa.call(t, http.MethodGet, list, nil), http.StatusOK))
		one := dropLinksPath(o.tid, "/", link.ID)
		expectContract(t, "updateDropLink", http.MethodPatch, one, mustStatus(t, "update", o.patchDropLink(t, link.ID, `{"label":"Renamed","validityDays":30}`), http.StatusOK))
		for what, body := range map[string]string{"unknown member": `{"x":1}`, "null label": `{"label":null}`, "empty recipients": `{"recipients":[]}`, "external recipient": `{"recipients":["a@example.net"]}`} {
			resp := o.patchDropLink(t, link.ID, body)
			if resp.status != http.StatusBadRequest {
				t.Errorf("%s: status %d, want 400: %s", what, resp.status, resp.body)
			}
			expectContract(t, "updateDropLink", http.MethodPatch, one, resp)
		}
		expectContract(t, "getDropLink", http.MethodGet, dropLinksPath(o.tid, "/drl_unknown"), o.sa.call(t, http.MethodGet, dropLinksPath(o.tid, "/drl_unknown"), nil))
		bad := o.sa.call(t, http.MethodPost, list, map[string]any{"label": "", "recipients": []string{}, "validityDays": 9})
		expectContract(t, opCreateDropLink, http.MethodPost, list, bad)
		expectContract(t, opGetPublicDrop, http.MethodGet, pathDropLinks+"ttd_short", o.landing(t, "ttd_short"))
	})
}

// availableDrop creates, uploads, finalizes the transfer of a drop link
// session and waits until it is available, without reading recipient links
// (the recipient mails carry them).
func (c *depositor) availableDrop(t *testing.T, req transferCreate, files ...uploadedFile) (senderTransferJSON, string) {
	t.Helper()
	req.noRecipients = true
	got := c.finalizedTransfer(t, req, files...)
	var cur senderTransferJSON
	eventually(t, "transfer "+got.ID+" available", func() bool {
		cur = c.mustGet(t, got.ID)
		return cur.Status == "available"
	})
	return cur, ""
}

// TestDropLinkErasureAndPurge: the search counts the drop links listing the
// address and the erase report counts those updated and disabled; erasing an address removes it from the
// recipients of the drop links (a link left without recipient is
// disabled), and the purge deletes a link revoked for more than 12
// months, never a younger one nor a link of another tenant.
func TestDropLinkErasureAndPurge(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOpsWith(t, e, serverOptions{lifecycle: cleanupEvery})
		subject, other := uniqueEmail(t, "subject", domainA), uniqueEmail(t, "other", domainA)
		shared := o.createDropLink(t, "Shared", "", subject, other)
		sole := o.createDropLink(t, "Sole", "", subject)
		untouched := o.createDropLink(t, "Untouched", "", other)

		if sum := o.sa.searchSubject(t, o.tid, subject); sum.DropLinks != 2 {
			t.Errorf("search dropLinks = %d, want 2", sum.DropLinks)
		}
		erase := mustStatus(t, "eraseDataSubject", o.sa.eraseSubject(t, o.tid, subject), http.StatusOK)
		expectContract(t, "eraseDataSubject", http.MethodPost, tenantPath(o.tid, "/data-subjects/erase"), erase)
		var rep opsEraseReport
		mustJSON(t, erase.body, &rep)
		if rep.DropLinksUpdated != 2 || rep.DropLinksDisabled != 1 {
			t.Errorf("erase report = %+v, want 2 drop links updated, 1 disabled", rep)
		}
		view := func(l dropLinkJSON) dropLinkJSON {
			var got dropLinkJSON
			mustJSON(t, mustStatus(t, "getDropLink", o.sa.call(t, http.MethodGet, dropLinksPath(o.tid, "/", l.ID), nil), http.StatusOK).body, &got)
			return got
		}
		if got := view(shared); !slices.Equal(got.Recipients, []string{other}) || !got.Enabled {
			t.Errorf("shared link = %+v, want only %s, enabled", got, other)
		}
		if got := view(sole); got.Enabled {
			t.Errorf("sole link = %+v, want disabled", got)
		}
		if got := view(untouched); !got.Enabled || !slices.Equal(got.Recipients, []string{other}) {
			t.Errorf("untouched link = %+v", got)
		}
		if n := countSystem(t, o.e, `SELECT count(*) FROM drop_links WHERE CAST(recipients AS TEXT) LIKE '%`+subject+`%'`); n != 0 {
			t.Errorf("%d recipient rows still hold the address", n)
		}

		// Purge: only the old revoked link goes.
		old, young := o.createDropLink(t, "Old", "", other), o.createDropLink(t, "Young", "", other)
		for _, l := range []dropLinkJSON{old, young} {
			mustStatus(t, "revoke", o.sa.call(t, http.MethodDelete, dropLinksPath(o.tid, "/", l.ID), nil), http.StatusNoContent)
		}
		ms := func(d time.Duration) string { return strconv.FormatInt(time.Now().Add(d).UnixMilli(), 10) }
		execSystem(t, o.e,
			"UPDATE drop_links SET revoked_at = "+ms(-13*30*24*time.Hour)+" WHERE id = '"+old.ID+"'",
			"UPDATE drop_links SET revoked_at = "+ms(-11*30*24*time.Hour)+" WHERE id = '"+young.ID+"'")
		eventually(t, "old revoked link purged", func() bool {
			return countSystem(t, o.e, `SELECT count(*) FROM drop_links WHERE id = '`+old.ID+`'`) == 0
		})
		for _, id := range []string{young.ID, untouched.ID, shared.ID, sole.ID} {
			if countSystem(t, o.e, `SELECT count(*) FROM drop_links WHERE id = '`+id+`'`) != 1 {
				t.Errorf("link %s was purged", id)
			}
		}
	})
}
