package scan

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// linkOnly creates a scanning link-only transfer of tn without recipient,
// whose token hash is set at the finalization as the transfer service
// does, and returns its identifier with that hash.
func (ev *env) linkOnly(tn *tenant.Tenant, contents ...[]byte) (string, []byte) {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	tok, err := id.NewDownloadToken()
	if err != nil {
		ev.t.Fatal(err)
	}
	hash := id.HashToken(tok)
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		var files []store.TransferFile
		for i, c := range contents {
			f, err := ev.storeFile(ctx, tx, tn, c)
			if err != nil {
				return err
			}
			f.Name = fmt.Sprintf("file-%d.bin", i)
			files = append(files, f)
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7,
			LinkMode: store.LinkModeShared, LinkOnly: true,
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, nil, files); err != nil {
			return err
		}
		if err := ev.db.Transfers().FinalizeTx(ctx, tx, trfID, time.Now()); err != nil {
			return err
		}
		return ev.db.Transfers().SetLinkOnlyTokenTx(ctx, tx, trfID, hash)
	})
	if err != nil {
		ev.t.Fatalf("link-only transfer: %v", err)
	}
	return trfID, hash
}

// checkLinkOnlyMails checks the mails of an available link-only transfer:
// the sender confirmation only, without any download link.
func checkLinkOnlyMails(t *testing.T, jobs []mail.Job) {
	t.Helper()
	if len(byTemplate(jobs, mail.TemplateTransferNotification)) != 0 {
		t.Errorf("a recipient is mailed: %v", templates(jobs))
	}
	conf := byTemplate(jobs, mail.TemplateTransferConfirmation)
	if len(conf) != 1 {
		t.Fatalf("confirmations: %v", templates(jobs))
	}
	if bytes.Contains([]byte(conf[0].Message.Text), []byte("/d/dl_")) {
		t.Error("the confirmation carries a download link")
	}
}

// TestLinkOnlyAvailable makes a link-only transfer available: the token
// hash drawn at the finalization is kept, nothing is sealed, no recipient
// is mailed and the sender confirmation has no link.
func TestLinkOnlyAvailable(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID, hash := ev.linkOnly(ev.a, clean(100))
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		if !bytes.Equal(d.DownloadTokenHash, hash) || d.DownloadTokenKeyID != "" {
			t.Fatalf("token: %x sealed %q", d.DownloadTokenHash, d.DownloadTokenKeyID)
		}
		ev.waitIdle()
		checkLinkOnlyMails(t, ev.queue.snapshot())
	})
}

// TestLinkOnlyDeferred sends the confirmation deferred by an edit hold of
// a link-only transfer, without opening any sealed token (there is none)
// and without mailing the recipients.
func TestLinkOnlyDeferred(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID, _ := ev.linkOnly(ev.a, clean(10))
		got := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
		ev.start()
		release := <-got
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.settle(0)
		release()
		ev.waitUntil("confirmation", func() bool {
			return len(byTemplate(ev.queue.snapshot(), mail.TemplateTransferConfirmation)) == 1
		})
		ev.waitIdle()
		checkLinkOnlyMails(t, ev.queue.snapshot())
		if n := ev.logs.count("deferred notification mails not sent: download token not opened"); n != 0 {
			t.Errorf("token open attempted %d times", n)
		}
	})
}

// TestDropLinkConfirmation checks that the sender confirmation of a drop
// link deposit names the link and never its recipients (T-311), and still
// names none when the link cannot be read.
func TestDropLinkConfirmation(t *testing.T) {
	for _, fault := range []error{nil, errFault, store.ErrNotFound} {
		ev := newEnv(t, storetest.SQLite(t), Options{})
		ctx := context.Background()
		tok, err := id.NewDropToken()
		if err != nil {
			t.Fatal(err)
		}
		l, err := ev.db.DropLinks().Create(ctx, ev.a.ID, store.DropLink{
			ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: "Supplier invoices",
			Recipients: []string{dave}, ValidityDays: 7, Enabled: true, CreatedBy: "adm_1",
		})
		if err != nil {
			t.Fatal(err)
		}
		s, err := ev.db.Scoped(ev.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		trfID := id.New(id.Transfer)
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			f, err := ev.storeFile(ctx, tx, ev.a, clean(100))
			if err != nil {
				return err
			}
			f.Name = "invoice.pdf"
			tr := store.Transfer{
				ID: trfID, SenderEmail: erin, SenderKind: store.DepositorDropLink, DropLinkID: l.ID, ExpiryDays: 7,
				LinkMode: store.LinkModePerRecipient,
			}
			if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{dave}, []store.TransferFile{f}); err != nil {
				return err
			}
			return ev.db.Transfers().FinalizeTx(ctx, tx, trfID, time.Now())
		})
		if err != nil {
			t.Fatal(err)
		}
		if fault != nil {
			ev.f.set("dropLink", 1, fault)
		}
		ev.start()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitIdle()
		conf := byTemplate(ev.queue.snapshot(), mail.TemplateTransferConfirmation)
		if len(conf) != 1 {
			t.Fatalf("%v: %d confirmations", fault, len(conf))
		}
		text := []byte(conf[0].Message.Text)
		if bytes.Contains(text, []byte(dave)) || bytes.Contains(text, []byte("Supplier invoices")) != (fault == nil) {
			t.Errorf("%v: confirmation:\n%s", fault, text)
		}
	}
}
