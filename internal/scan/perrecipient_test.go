package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// recipientLinkURLs returns the download URL of each link of the transfer
// trfID of tn, by recipient, unsealed from the database.
func (ev *env) recipientLinkURLs(tn *tenant.Tenant, trfID string) map[string]string {
	ev.t.Helper()
	ctx := context.Background()
	links, err := ev.db.RecipientLinks().ListByTransfer(ctx, tn.ID, trfID)
	if err != nil {
		ev.t.Fatal(err)
	}
	out := make(map[string]string, len(links))
	for _, l := range links {
		if l.TokenKeyID == "" {
			continue
		}
		raw, err := ev.vault.Open(ctx, tn.ID, crypto.PurposeSecret, l.TokenKeyID)
		if err != nil {
			ev.t.Fatal(err)
		}
		if sum := sha256.Sum256(raw); !id.DownloadTokenValid(string(raw)) || !bytes.Equal(sum[:], l.TokenHash) {
			ev.t.Fatalf("sealed token of %s does not match its hash", l.ID)
		}
		out[l.Email] = id.DownloadURL(tn.FQDN, string(raw))
	}
	return out
}

// checkNoLinkToSender fails when a mail to the sender carries a download
// link: the sender never sees a recipient link (P27, T-199).
func checkNoLinkToSender(t *testing.T, jobs []mail.Job) {
	t.Helper()
	for _, j := range jobs {
		if slices.Contains(j.Message.To, alice) && (strings.Contains(j.Message.Text, "/d/dl_") || strings.Contains(j.Message.HTML, "/d/dl_")) {
			t.Errorf("mail %s to the sender carries a download link", j.Template)
		}
	}
}

// TestPerRecipientLinks makes a transfer with one link per recipient
// available: one distinct token per recipient, sealed and hashed in the
// links (no transfer-level token), and each recipient mailed their own link
// only.
func TestPerRecipientLinks(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.perRecipient(ev.a, clean(100))
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		if d.LinkMode != store.LinkModePerRecipient || len(d.DownloadTokenHash) != 0 || d.DownloadTokenKeyID != "" {
			t.Fatalf("transfer-level link: %q %x %q", d.LinkMode, d.DownloadTokenHash, d.DownloadTokenKeyID)
		}
		links := ev.recipientLinkURLs(ev.a, trfID)
		if len(links) != 2 || links[dave] == "" || links[erin] == "" || links[dave] == links[erin] {
			t.Fatalf("links %d, distinct %v", len(links), links[dave] != links[erin])
		}
		ev.waitIdle()
		jobs := ev.queue.snapshot()
		notif := byTemplate(jobs, mail.TemplateTransferNotification)
		if len(notif) != 2 {
			t.Fatalf("templates %v", templates(jobs))
		}
		for _, j := range notif {
			if len(j.Message.To) != 1 || len(j.Message.Inline) != 1 {
				t.Fatalf("recipient mail to %v with %d inline parts", j.Message.To, len(j.Message.Inline))
			}
			to := j.Message.To[0]
			other := dave
			if to == dave {
				other = erin
			}
			if !strings.Contains(j.Message.Text, links[to]) || strings.Contains(j.Message.Text, links[other]) {
				t.Errorf("mail to %s does not carry its own link only", to)
			}
		}
		if len(byTemplate(jobs, mail.TemplateTransferConfirmation)) > 1 {
			t.Errorf("templates %v", templates(jobs))
		}
		checkNoLinkToSender(t, jobs)
	})
}

// TestPerRecipientDeferred sends the mails deferred by an edit hold to the
// remaining recipients of a transfer with one link per recipient, each with
// their own link unsealed from the database; a recipient removed meanwhile
// (link key destroyed) gets nothing.
func TestPerRecipientDeferred(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.perRecipient(ev.a, clean(10))
		got := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
		ev.start()
		release := <-got
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.settle(0)
		links := ev.recipientLinkURLs(ev.a, trfID)
		second := ev.holdFor(ev.a, trfID, lifecycle.HoldForEdit)
		ev.removeRecipient(ev.a, trfID, erin)
		release()
		ev.settle(0)
		second()
		ev.waitUntil("recipient mail", func() bool {
			return len(byTemplate(ev.queue.snapshot(), mail.TemplateTransferNotification)) == 1
		})
		ev.waitIdle()
		jobs := ev.queue.snapshot()
		notif := byTemplate(jobs, mail.TemplateTransferNotification)
		if len(notif) != 1 || !slices.Equal(notif[0].Message.To, []string{dave}) || !strings.Contains(notif[0].Message.Text, links[dave]) {
			t.Fatalf("recipient mails %v", templates(jobs))
		}
		checkNoLinkToSender(t, jobs)
	})
}

// TestPerRecipientDeferredSkipsErasedLink sends nothing through a link
// whose sealed token is destroyed while the link stays (a tenant being
// erased), and still mails the other recipients.
func TestPerRecipientDeferredSkipsErasedLink(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	trfID := ev.perRecipient(ev.a, clean(10))
	got := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
	ev.start()
	release := <-got
	ev.waitStatus(ev.a, trfID, store.TransferAvailable)
	ev.settle(0)
	links := ev.recipientLinkURLs(ev.a, trfID)
	second := ev.holdFor(ev.a, trfID, lifecycle.HoldForEdit)
	s, err := ev.db.Scoped(ev.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		_, err := ev.db.RecipientLinks().DestroyRecipientKeyTx(context.Background(), tx, trfID, erin)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	release()
	ev.settle(0)
	second()
	ev.waitUntil("recipient mail", func() bool {
		return len(byTemplate(ev.queue.snapshot(), mail.TemplateTransferNotification)) == 1
	})
	ev.waitIdle()
	notif := byTemplate(ev.queue.snapshot(), mail.TemplateTransferNotification)
	if len(notif) != 1 || !slices.Equal(notif[0].Message.To, []string{dave}) || !strings.Contains(notif[0].Message.Text, links[dave]) {
		t.Fatalf("recipient mails %v", templates(ev.queue.snapshot()))
	}
}

// TestPerRecipientDeferredFailures logs, without mail, a deferred send
// whose links cannot be listed or unsealed.
func TestPerRecipientDeferredFailures(t *testing.T) {
	for _, fault := range []string{"recipientLinks", "openSecret"} {
		t.Run(fault, func(t *testing.T) {
			ev := newEnv(t, storetest.SQLite(t), Options{})
			trfID := ev.perRecipient(ev.a, clean(10))
			got := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
			ev.start()
			release := <-got
			ev.waitStatus(ev.a, trfID, store.TransferAvailable)
			ev.settle(0)
			ev.f.set(fault, 1, nil)
			release()
			ev.settle(0)
			if ev.logs.count("deferred notification mails not sent: recipient links not opened") != 1 {
				t.Fatalf("logs:\n%s", ev.logs.all())
			}
		})
	}
}

// TestRecipientLinksPairing pairs the links with their tokens by hash and
// skips a link without a matching token.
func TestRecipientLinksPairing(t *testing.T) {
	tn := &tenant.Tenant{FQDN: hostA}
	tokA, tokB := "dl_"+strings.Repeat("a", 43), "dl_"+strings.Repeat("b", 43)
	ha, hb := sha256.Sum256([]byte(tokA)), sha256.Sum256([]byte(tokB))
	links := []store.RecipientLink{
		{Email: dave, TokenHash: hb[:]},
		{Email: erin, TokenHash: ha[:]},
		{Email: alice, TokenHash: []byte{1}},
		{Email: alice, TokenHash: make([]byte, sha256.Size)},
	}
	got := recipientLinks(tn, links, []string{tokA, tokB})
	if len(got) != 2 || got[0].Email != dave || got[0].Link != id.DownloadURL(hostA, tokB) ||
		got[1].Email != erin || got[1].Link != id.DownloadURL(hostA, tokA) {
		t.Errorf("links %+v", got)
	}
}
