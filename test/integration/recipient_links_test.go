package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// trackingJSON is the RecipientTracking schema.
type trackingJSON struct {
	Email             string  `json:"email"`
	VerifiedAt        *string `json:"verifiedAt"`
	FirstDownloadedAt *string `json:"firstDownloadedAt"`
	LastDownloadedAt  *string `json:"lastDownloadedAt"`
	Downloads         []struct {
		FileID *string `json:"fileId"`
		Count  int     `json:"count"`
	} `json:"downloads"`
}

// trackingOf decodes the recipientTracking member of a transfer body.
func trackingOf(t *testing.T, body []byte) []trackingJSON {
	t.Helper()
	var v struct {
		RecipientTracking []trackingJSON `json:"recipientTracking"`
	}
	mustJSON(t, body, &v)
	return v.RecipientTracking
}

// TestRecipientLinksFlow: every transfer created since 1.1 gives each
// recipient their own link (P27): three recipients get three distinct
// links, each mailed to its recipient only and each working; no link
// reaches the sender view, the admin view or the API, which show the
// tracking of each recipient instead; erasing one recipient (data-subject
// erasure) destroys the key of their link, which stops resolving, while
// the other links keep working.
func TestRecipientLinksFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		r1, r2, r3 := uniqueEmail(t, "link-one", "example.net"), uniqueEmail(t, "link-two", "example.org"), uniqueEmail(t, "link-three", "example.com")
		content := []byte("per-recipient content")
		tr, _ := alice.availableTransfer(t, transferCreate{Recipients: []string{r1, r2, r3}}, uploadedFile{"links.txt", content})

		links := o.recipientLinks(t, hostA, tr.ID)
		tokens := map[string]string{}
		seen := map[string]bool{}
		for _, r := range []string{r1, r2, r3} {
			if links[r] == "" || seen[links[r]] {
				t.Fatalf("link of %s missing or shared: %v", r, links[r] == "")
			}
			seen[links[r]] = true
			tokens[r] = tokenOf(t, hostA, links[r])
			o.secret(tokens[r])
		}

		// Each recipient mail carries its own link and no other.
		for _, r := range []string{r1, r2, r3} {
			o.waitMailSent(t, r)
			msg := o.mp.find(t, r, func(mpMessage) bool { return true })
			raw := o.mp.content(t, msg.ID)
			for other, tok := range tokens {
				if strings.Contains(raw, tok) != (other == r) {
					t.Errorf("mail to %s: token of %s present = %v", r, other, other != r)
				}
			}
		}
		// No mail to the sender carries a link.
		for _, m := range o.mp.messagesTo(t, sender) {
			expectNoLink(t, "mail "+m.Subject+" to the sender", []byte(o.mp.content(t, m.ID)))
		}

		// The sender view: no link, the tracking of each recipient.
		resp := alice.getTransfer(t, tr.ID)
		if resp.status != http.StatusOK {
			t.Fatalf("getTransfer: %d %s", resp.status, resp.body)
		}
		expectNoLink(t, "the sender view", resp.body)
		parseTransfer(t, resp.body)
		if tr := trackingOf(t, resp.body); len(tr) != 3 || tr[0].Email != r1 || tr[1].Email != r2 || tr[2].Email != r3 ||
			tr[0].FirstDownloadedAt != nil || tr[0].VerifiedAt != nil {
			t.Errorf("sender tracking = %+v", tr)
		}
		// The admin view: no link, the same tracking.
		admin := mustStatus(t, "getTenantTransfer", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers/"+tr.ID), nil), http.StatusOK)
		expectNoLink(t, "the admin view", admin.body)
		if tr := trackingOf(t, admin.body); len(tr) != 3 || tr[1].Email != r2 {
			t.Errorf("admin tracking = %+v", tr)
		}
		var flags struct {
			RecipientVerification *bool `json:"recipientVerification"`
		}
		mustJSON(t, admin.body, &flags)
		if flags.RecipientVerification == nil || *flags.RecipientVerification {
			t.Errorf("admin recipientVerification = %v, want false", flags.RecipientVerification)
		}
		list := mustStatus(t, "listTenantTransfers", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers"), nil), http.StatusOK)
		expectNoLink(t, "the admin list", list.body)

		// Each link works on the tenant of the transfer only.
		for i, r := range []string{r1, r2, r3} {
			o.newRecipient(i+1).mustPage(t, tokens[r])
		}
		other := o.newRecipient(9)
		other.host = hostB
		if got := other.page(t, tokens[r1]); got.status != http.StatusNotFound {
			t.Errorf("link of A under the FQDN of B: %d, want 404", got.status)
		}

		// The data-subject erasure of r2 destroys the key of their link.
		ls, err := o.db.RecipientLinks().ListByTransfer(context.Background(), o.tenantA.ID, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		var keyR2 string
		for _, l := range ls {
			if l.Email == r2 {
				keyR2 = l.TokenKeyID
			}
		}
		if keyR2 == "" {
			t.Fatal("no key for the link of r2")
		}
		erase := mustStatus(t, "eraseDataSubject", o.sa.eraseSubject(t, o.tid, r2), http.StatusOK)
		var rep opsEraseReport
		mustJSON(t, erase.body, &rep)
		if rep.RecipientEntriesRemoved != 1 || rep.TransfersDeleted != 0 {
			t.Errorf("erase report = %+v", rep)
		}
		if _, err := o.vault(t).Open(context.Background(), o.tenantA.ID, crypto.PurposeSecret, keyR2); err == nil {
			t.Error("the sealed token of the erased recipient can still be opened")
		}
		if after := o.recipientLinks(t, hostA, tr.ID); after[r2] != "" || after[r1] != links[r1] || after[r3] != links[r3] {
			t.Errorf("links after the erasure: r2 present %v, others kept %v", after[r2] != "",
				after[r1] == links[r1] && after[r3] == links[r3])
		}
		if got := o.newRecipient(4).page(t, tokens[r2]); got.status != http.StatusNotFound {
			t.Errorf("link of the erased recipient: %d, want 404", got.status)
		}
		o.newRecipient(5).mustPage(t, tokens[r1])
		if tr := trackingOf(t, alice.getTransfer(t, tr.ID).body); len(tr) != 2 {
			t.Errorf("tracking after the erasure = %+v", tr)
		}
		noSecretInLogs(t, o.server, tokens[r1], tokens[r2], tokens[r3])
		o.expectNoSecrets(t, o.tenantAudit(t, o.tid))
	})
}

// TestRecipientVerificationOption: the option is offered by the public
// configuration, recorded on the transfer, and the seeded confidential
// level (which requires it) is refused without it (422) and accepted with
// it.
func TestRecipientVerificationOption(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		cfg := mustStatus(t, "GET /tenant", d.get(t, hostA, pathPublicTenant), http.StatusOK)
		var pub struct {
			Features struct {
				RecipientVerification bool `json:"recipientVerification"`
			} `json:"features"`
		}
		mustJSON(t, cfg.body, &pub)
		if !pub.Features.RecipientVerification {
			t.Errorf("features = %s, want recipientVerification offered", cfg.body)
		}

		alice, _ := internalSession(t, d, "alice")
		pw := transferPassword
		req := oneFile("secret.pdf", 10)
		req.Recipients, req.Password, req.ConfidentialityLevel = []string{uniqueEmail(t, "colleague", domainA)}, &pw, "confidential"
		p := expectTransferProblem(t, alice.createTransfer(t, req, ""), http.StatusUnprocessableEntity, "confidentiality-rule-violated")
		expectFieldCode(t, p, "/recipientVerification", "required")

		req.RecipientVerification = true
		resp := alice.createTransfer(t, req, "")
		if resp.status != http.StatusCreated {
			t.Fatalf("confidential with verification: %d %s", resp.status, resp.body)
		}
		var got struct {
			RecipientVerification bool   `json:"recipientVerification"`
			DownloadURL           string `json:"downloadUrl"`
			Level                 struct {
				Key string `json:"key"`
			} `json:"confidentialityLevel"`
		}
		if err := json.Unmarshal(resp.body, &got); err != nil {
			t.Fatal(err)
		}
		if !got.RecipientVerification || got.Level.Key != "confidential" || got.DownloadURL != "" {
			t.Errorf("created = %s", resp.body)
		}
		// Without level, the option is accepted on its own.
		plain := oneFile("plain.txt", 10)
		plain.RecipientVerification = true
		if resp := alice.createTransfer(t, plain, ""); resp.status != http.StatusCreated ||
			!strings.Contains(string(resp.body), `"recipientVerification":true`) {
			t.Errorf("plain with verification: %d %s", resp.status, resp.body)
		}
	})
}
