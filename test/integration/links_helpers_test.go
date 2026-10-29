package integration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
)

// recipientLinks returns the download URL of each recipient of the
// transfer trfID of the tenant served on host, by address, unsealed from
// the store with the master key of the server: the API never returns them
// (P27, T-199), and only the recipient mails carry them. A link whose key
// was destroyed (its recipient erased) is absent.
func (d *depositEnv) recipientLinks(t *testing.T, host, trfID string) map[string]string {
	t.Helper()
	ctx := context.Background()
	tn, err := d.db.Tenants().TenantByFQDN(ctx, host)
	if err != nil {
		t.Fatalf("tenant of %s: %v", host, err)
	}
	links, err := d.db.RecipientLinks().ListByTransfer(ctx, tn.ID, trfID)
	if err != nil {
		t.Fatalf("recipient links of %s: %v", trfID, err)
	}
	out := make(map[string]string, len(links))
	for _, l := range links {
		if l.TokenKeyID == "" {
			continue
		}
		raw, err := d.vault(t).Open(ctx, tn.ID, crypto.PurposeSecret, l.TokenKeyID)
		if err != nil {
			t.Fatalf("open the link token of %s: %v", l.ID, err)
		}
		out[l.Email] = id.DownloadURL(host, string(raw))
	}
	return out
}

// recipientLink returns the download URL of the recipient email of the
// transfer trfID of the tenant served on host (see recipientLinks).
func (d *depositEnv) recipientLink(t *testing.T, host, trfID, email string) string {
	t.Helper()
	norm, err := store.NormalizeEmail(email)
	if err != nil {
		t.Fatalf("recipient %q: %v", email, err)
	}
	link := d.recipientLinks(t, host, trfID)[norm]
	if link == "" {
		t.Fatalf("transfer %s has no link for %s", trfID, email)
	}
	return link
}

// withFirstLink checks that the sender view got of an available transfer
// carries no download link, as for every transfer created since 1.1 (P27),
// then returns it with DownloadURL set to the own link of its first
// recipient, read from the store: the tests written for the single shared
// link of 1.0 then follow that recipient.
func (c *depositor) withFirstLink(t *testing.T, got senderTransferJSON) senderTransferJSON {
	t.Helper()
	if got.DownloadURL != "" {
		t.Fatalf("the sender view of %s carries a download link", got.ID)
	}
	if len(got.Recipients) == 0 {
		t.Fatalf("transfer %s without recipient", got.ID)
	}
	got.DownloadURL = c.d.recipientLink(t, c.host, got.ID, got.Recipients[0])
	return got
}

// expectNoLink fails when body, a response or a mail given to anyone but
// a recipient, carries a download link or a link token.
func expectNoLink(t *testing.T, what string, body []byte) {
	t.Helper()
	if s := string(body); strings.Contains(s, id.DownloadPath+"dl_") || strings.Contains(s, "dl_") ||
		strings.Contains(s, `"downloadUrl"`) {
		t.Errorf("%s carries a download link or token: %s", what, s)
	}
}
