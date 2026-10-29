package tenantops

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestGetTransferTracking returns the tracking of each recipient of a
// transfer with one link per recipient, never a link; an empty tracking
// before the links exist, and none for a shared transfer.
func TestGetTransferTracking(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seedLinks(ev.a, store.TransferAvailable, carol, dave)
		d, err := ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, trf.id)
		mustNoErr(t, "get", err)
		if len(d.RecipientTracking) != 2 || d.RecipientTracking[0].Email != carol || d.RecipientTracking[1].Email != dave ||
			!d.RecipientTracking[0].FirstDownloadedAt.IsZero() {
			t.Fatalf("tracking = %+v", d.RecipientTracking)
		}
		scanning := ev.seedLinks(ev.a, store.TransferScanning, carol)
		d, err = ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, scanning.id)
		mustNoErr(t, "get scanning", err)
		if d.RecipientTracking == nil || len(d.RecipientTracking) != 0 {
			t.Errorf("scanning tracking = %#v, want empty", d.RecipientTracking)
		}
		shared := ev.seed(ev.a, store.TransferAvailable, carol)
		d, err = ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, shared.id)
		mustNoErr(t, "get shared", err)
		if d.RecipientTracking != nil {
			t.Errorf("shared tracking = %+v", d.RecipientTracking)
		}
		// Tenant B never sees the transfer of A, nor its tracking.
		_, err = ev.svc.GetTransfer(ctx, ev.adminB, ev.a.ID, trf.id)
		wantErr(t, "admin of B", err, ErrNotFound)
		_, err = ev.svc.GetTransfer(ctx, ev.super, ev.b.ID, trf.id)
		wantErr(t, "under B", err, ErrNotFound)
		ev.faults("tracking")
		_, err = ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, trf.id)
		wantErr(t, "tracking failure", err, errBoom)
	})
}

// TestResendRecipientLinks mails each recipient of a transfer with one link
// per recipient their own existing link again, all of them or a subset,
// never another link; the tokens are neither rotated nor logged nor
// audited.
func TestResendRecipientLinks(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seedLinks(ev.a, store.TransferAvailable, carol, dave)
		links := map[string]string{
			carol: id.DownloadURL(hostA, trf.tokens[carol]), dave: id.DownloadURL(hostA, trf.tokens[dave]),
		}
		if links[carol] == links[dave] {
			t.Fatal("the recipients share a link")
		}
		mustNoErr(t, "resend all", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP))
		if len(ev.mailer.jobs) != 2 {
			t.Fatalf("jobs = %d, want 2", len(ev.mailer.jobs))
		}
		for _, j := range ev.mailer.jobs {
			if len(j.Message.To) != 1 {
				t.Fatalf("job to %v", j.Message.To)
			}
			to := j.Message.To[0]
			for addr, link := range links {
				if strings.Contains(j.Message.Text, link) != (addr == to) {
					t.Errorf("mail to %s: link of %s present = %v", to, addr, addr != to)
				}
			}
		}
		if len(ev.notifier.links) != 0 || len(ev.notifier.perLinks) != 1 {
			t.Errorf("notifier calls: shared %d, per recipient %d", len(ev.notifier.links), len(ev.notifier.perLinks))
		}
		evs := ev.auditEvents(ev.a.ID, "transfer.notification_resent")
		if len(evs) != 1 || ev.details(evs[0])["recipientCount"] != float64(2) {
			t.Fatalf("audit = %+v", evs)
		}

		// A subset gets their own link only.
		ev.mailer.jobs = nil
		mustNoErr(t, "resend subset", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, []string{dave}, clientIP))
		if len(ev.mailer.jobs) != 1 || !slices.Equal(ev.mailer.jobs[0].Message.To, []string{dave}) ||
			!strings.Contains(ev.mailer.jobs[0].Message.Text, links[dave]) || strings.Contains(ev.mailer.jobs[0].Message.Text, links[carol]) {
			t.Fatalf("subset jobs = %+v", ev.mailer.jobs)
		}

		// Never a token in the logs, the queue attributes or the audit log.
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{})
		mustNoErr(t, "audit", err)
		for _, tok := range trf.tokens {
			for _, a := range ev.mailer.attrs {
				if strings.Contains(a.Value.String(), tok) {
					t.Error("a token reached the queue attributes")
				}
			}
			for _, a := range page.Items {
				if strings.Contains(string(a.Details), tok) {
					t.Error("a token reached the audit log")
				}
			}
			if strings.Contains(ev.logs.String(), tok) {
				t.Error("a token reached the logs")
			}
		}
		// The tokens are never rotated.
		ls, err := ev.db.RecipientLinks().ListByTransfer(ctx, ev.a.ID, trf.id)
		mustNoErr(t, "links", err)
		for _, l := range ls {
			raw, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, l.TokenKeyID)
			if err != nil || string(raw) != trf.tokens[l.Email] {
				t.Errorf("the token of %s changed: %v", l.Email, err)
			}
		}
	})
}

// TestResendRecipientLinksEdges covers an erased recipient link, and the
// failures of the links, the tokens and the mails.
func TestResendRecipientLinksEdges(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seedLinks(ev.a, store.TransferAvailable, carol, dave)
		// The link key of carol is destroyed (her erasure is under way):
		// she gets nothing, dave gets his link.
		sc, err := ev.db.Scoped(ev.a.ID)
		mustNoErr(t, "scope", err)
		mustNoErr(t, "destroy", sc.Tx(ctx, func(tx *store.ScopedTx) error {
			_, err := ev.db.RecipientLinks().DestroyRecipientKeyTx(ctx, tx, trf.id, carol)
			return err
		}))
		mustNoErr(t, "resend", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP))
		if len(ev.mailer.jobs) != 1 || !slices.Equal(ev.mailer.jobs[0].Message.To, []string{dave}) {
			t.Fatalf("jobs = %+v", ev.mailer.jobs)
		}
		wantErr(t, "only carol", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, []string{carol}, clientIP), ErrNotAvailable)

		ev.faults("recipientLinks")
		wantErr(t, "links failure", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP), errBoom)
		ev.faults("openSecret")
		wantErr(t, "token failure", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP), errBoom)
		ev.faults()
		ev.notifier.err = errBoom
		wantErr(t, "build failure", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP), errBoom)
		ev.notifier.err = nil

		// Tenant B has no SMTP settings; a scanning transfer is not
		// available.
		trfB := ev.seedLinks(ev.b, store.TransferAvailable, carol)
		wantErr(t, "no smtp", ev.svc.ResendNotification(ctx, ev.adminB, ev.b.ID, trfB.id, nil, clientIP), ErrMailUnavailable)
		scanning := ev.seedLinks(ev.a, store.TransferScanning, carol)
		wantErr(t, "scanning", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, scanning.id, nil, clientIP), ErrNotAvailable)
		// The transfer of A is unknown under B.
		wantErr(t, "under B", ev.svc.ResendNotification(ctx, ev.super, ev.b.ID, trf.id, nil, clientIP), ErrNotFound)
	})
}
