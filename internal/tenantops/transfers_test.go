package tenantops

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestNewRequiresDependencies refuses a service without its dependencies.
func TestNewRequiresDependencies(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		full := Options{Vault: ev.vault, Eraser: ev.eraser, Notifier: ev.notifier, Mailer: ev.mailer}
		for name, o := range map[string]Options{
			"vault":    {Eraser: ev.eraser, Notifier: ev.notifier, Mailer: ev.mailer},
			"eraser":   {Vault: ev.vault, Notifier: ev.notifier, Mailer: ev.mailer},
			"notifier": {Vault: ev.vault, Eraser: ev.eraser, Mailer: ev.mailer},
			"mailer":   {Vault: ev.vault, Eraser: ev.eraser, Notifier: ev.notifier},
		} {
			if _, err := New(ev.db, o); err == nil {
				t.Errorf("New without %s succeeded", name)
			}
		}
		if _, err := New(nil, full); err == nil {
			t.Error("New without a database succeeded")
		}
		svc, err := New(ev.db, full)
		mustNoErr(t, "New", err)
		if svc.logger == nil || svc.now == nil || svc.busyRetries != DefaultBusyRetries ||
			svc.busyDelay != DefaultBusyDelay || svc.busyRetryAfter != DefaultBusyRetryAfter {
			t.Errorf("defaults not applied: %+v", svc)
		}
		full.BusyRetries = -1
		svc, err = New(ev.db, full)
		mustNoErr(t, "New", err)
		if svc.busyRetries != 0 {
			t.Errorf("busyRetries = %d, want 0", svc.busyRetries)
		}
	})
}

// TestListTransfers lists the transfers of a tenant with their metadata,
// filters and pages, never those of another tenant.
func TestListTransfers(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		uploading := ev.seed(ev.a, store.TransferUploading, dave)
		ev.clock.Advance(time.Minute)
		scanning := ev.seed(ev.a, store.TransferScanning, dave)
		ev.clock.Advance(time.Minute)
		available := ev.seed(ev.a, store.TransferAvailable, carol, dave)
		ev.clock.Advance(time.Minute)
		expired := ev.seed(ev.a, store.TransferExpired, dave)
		ev.seed(ev.b, store.TransferAvailable, carol)

		page, err := ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, TransferFilter{})
		mustNoErr(t, "list", err)
		var ids []string
		for _, tr := range page.Items {
			ids = append(ids, tr.ID)
		}
		if want := []string{expired.id, available.id, scanning.id, uploading.id}; !slices.Equal(ids, want) || page.NextCursor != "" {
			t.Fatalf("listed %v (next %q), want %v", ids, page.NextCursor, want)
		}
		got := page.Items[1]
		if got.Status != store.TransferAvailable || got.Origin != OriginInternal || got.SenderEmail != alice ||
			!slices.Equal(got.Recipients, []string{carol, dave}) || got.FileCount != 2 || got.TotalBytes != 2000 ||
			got.PasswordProtected || got.DeleteAfterFirstDownload || !got.CreatedAt.Equal(testStart.Add(2*time.Minute)) ||
			!got.ExpiresAt.Equal(testStart.Add(2*time.Minute+7*24*time.Hour)) || !got.FirstDownloadedAt.IsZero() ||
			got.DownloadCount != 0 || got.InvitationID != "" {
			t.Errorf("available transfer = %+v", got)
		}
		// The expiry written at finalization is provisional: not shown.
		if !page.Items[2].ExpiresAt.IsZero() {
			t.Errorf("scanning transfer expiry = %v, want none", page.Items[2].ExpiresAt)
		}

		page, err = ev.svc.ListTransfers(ctx, ev.super, ev.a.ID, TransferFilter{Status: "available"})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != available.id {
			t.Errorf("status filter = %+v, %v", page.Items, err)
		}
		page, err = ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, TransferFilter{Email: " Carol@Customer.Example.NET "})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != available.id {
			t.Errorf("email filter = %+v, %v", page.Items, err)
		}
		page, err = ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, TransferFilter{CreatedAfter: testStart.Add(90 * time.Second)})
		if err != nil || len(page.Items) != 2 {
			t.Errorf("createdAfter filter = %+v, %v", page.Items, err)
		}
		page, err = ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, TransferFilter{Limit: 3})
		if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
			t.Fatalf("first page = %+v, %v", page, err)
		}
		page, err = ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, TransferFilter{Limit: 3, Cursor: page.NextCursor})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != uploading.id || page.NextCursor != "" {
			t.Errorf("second page = %+v, %v", page, err)
		}

		for _, c := range []struct {
			f     TransferFilter
			field string
		}{
			{TransferFilter{Status: "lost"}, FieldStatus},
			{TransferFilter{Email: "not an address"}, FieldEmail},
			// Accepted by the loose store normalization, refused by the
			// strict address syntax.
			{TransferFilter{Email: "a,b@entity-a.example.com"}, FieldEmail},
			{TransferFilter{Email: "a<b@entity-a.example.com"}, FieldEmail},
			{TransferFilter{Limit: -1}, FieldLimit},
			{TransferFilter{Limit: store.MaxPageSize + 1}, FieldLimit},
			{TransferFilter{Cursor: "garbage"}, FieldCursor},
		} {
			_, err := ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, c.f)
			wantInvalid(t, "filter "+c.field, err, c.field)
			if got := notAnAddress(err); got != (c.field == FieldEmail) {
				t.Errorf("filter %s: NotAnAddress = %v", c.field, got)
			}
		}
		ev.faults("listTransfers")
		_, err = ev.svc.ListTransfers(ctx, ev.adminA, ev.a.ID, TransferFilter{})
		wantErr(t, "list failure", err, errBoom)
	})
}

// TestGetTransfer returns the metadata of a transfer with its files.
func TestGetTransfer(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seed(ev.a, store.TransferAvailable, carol)
		d, err := ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, trf.id)
		mustNoErr(t, "get", err)
		if d.ID != trf.id || d.FileCount != 2 || len(d.Files) != 2 || d.SenderIP != netip.MustParseAddr("10.10.4.21") ||
			!slices.Equal(d.Recipients, []string{carol}) {
			t.Fatalf("detail = %+v", d)
		}
		f := d.Files[0]
		if !id.Valid(id.File, f.ID) || f.Name != "plans-0.pdf" || f.Size != 1000 || f.MediaType != "application/pdf" ||
			len(f.SHA256) != 64 || f.ScanStatus != store.ScanClean {
			t.Errorf("file = %+v", f)
		}
		_, err = ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, "not-an-id")
		wantErr(t, "malformed id", err, ErrNotFound)
		_, err = ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, missingTrf)
		wantErr(t, "missing", err, ErrNotFound)
		ev.faults("getTransfer")
		_, err = ev.svc.GetTransfer(ctx, ev.adminA, ev.a.ID, trf.id)
		wantErr(t, "get failure", err, errBoom)
	})
}

// TestDeleteTransfer erases a transfer through the eraser and audits the
// redacted reason; an ended transfer is a silent no-op.
func TestDeleteTransfer(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seed(ev.a, store.TransferAvailable, carol)
		reason := "Sent to the wrong recipient: carol@customer.example.net, at the sender's request."
		mustNoErr(t, "delete", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, trf.id, reason, clientIP))
		d, err := ev.db.Transfers().Get(ctx, ev.a.ID, trf.id)
		if err != nil || d.Status != store.TransferDeleted {
			t.Fatalf("transfer after delete = %v, %v", d.Status, err)
		}
		c := ev.eraser.calls[0]
		if c.tid != ev.a.ID || c.trfID != trf.id || c.mode != lifecycle.MarkDeleted || c.cancellable {
			t.Errorf("eraser call = %+v", c)
		}
		evs := ev.auditEvents(ev.a.ID, audit.ActionTransferDeleted)
		if len(evs) != 1 {
			t.Fatalf("audit events = %d", len(evs))
		}
		got := evs[0]
		if got.Actor != "alice.admin" || got.ActorKind != store.ActorAdmin || got.IP != clientIP ||
			got.ObjectKind != audit.ObjectTransfer || got.ObjectID != trf.id {
			t.Errorf("audit event = %+v", got)
		}
		if r := ev.details(got)["reason"]; r != "Sent to the wrong recipient: [address], at the sender's request." {
			t.Errorf("recorded reason = %q", r)
		}

		// Deleting again, or deleting an expired transfer, does nothing.
		mustNoErr(t, "delete again", ev.svc.DeleteTransfer(ctx, ev.super, ev.a.ID, trf.id, "again", clientIP))
		exp := ev.seed(ev.a, store.TransferExpired, carol)
		mustNoErr(t, "delete expired", ev.svc.DeleteTransfer(ctx, ev.super, ev.a.ID, exp.id, "", clientIP))
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionTransferDeleted)); n != 1 {
			t.Errorf("audit events after no-ops = %d, want 1", n)
		}

		// Without reason, no details.
		ev.clock.Advance(time.Second)
		scanning := ev.seed(ev.a, store.TransferScanning, carol)
		mustNoErr(t, "delete scanning", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, scanning.id, "", clientIP))
		if evs := ev.auditEvents(ev.a.ID, audit.ActionTransferDeleted); len(evs) != 2 || len(evs[0].Details) != 0 {
			t.Errorf("audit without reason = %+v", evs)
		}

		calls := ev.eraser.count()
		wantErr(t, "malformed id", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, "trf_bad", "", clientIP), ErrNotFound)
		if ev.eraser.count() != calls {
			t.Error("the eraser was called for a malformed id")
		}
		wantErr(t, "missing", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, missingTrf, "", clientIP), ErrNotFound)
		wantInvalid(t, "long reason", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, missingTrf,
			strings.Repeat("é", MaxReasonLen+1), clientIP), FieldReason)
		wantInvalid(t, "invalid utf-8", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, missingTrf, "\xff", clientIP), FieldReason)
		mustNoErr(t, "max reason", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID,
			ev.seed(ev.a, store.TransferAvailable, carol).id, strings.Repeat("é", MaxReasonLen), clientIP))

		ev.eraser.err = errBoom
		wantErr(t, "eraser failure", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, missingTrf, "", clientIP), errBoom)
	})
}

// TestDeleteReasonCap cuts a reason that the redaction lengthens.
func TestDeleteReasonCap(t *testing.T) {
	reason := strings.Repeat("a@b.c ", 80)
	got := redactReason(reason)
	if utf8.RuneCountInString(got) != MaxReasonLen || strings.Contains(got, "@") || !strings.HasPrefix(got, "[address] ") {
		t.Errorf("redactReason = %q", got)
	}
	if got := redactReason("plain"); got != "plain" {
		t.Errorf("redactReason(plain) = %q", got)
	}
}

// TestDeleteBusy retries while an upload holds the transfer, then refuses
// with a Retry-After delay.
func TestDeleteBusy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seed(ev.a, store.TransferAvailable, carol)
		ev.eraser.busy = 2
		mustNoErr(t, "delete after retries", ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, trf.id, "", clientIP))
		if n := ev.eraser.count(); n != 3 {
			t.Errorf("eraser calls = %d, want 3", n)
		}

		other := ev.seed(ev.a, store.TransferAvailable, carol)
		ev.eraser.calls, ev.eraser.busy = nil, 100
		err := ev.svc.DeleteTransfer(ctx, ev.adminA, ev.a.ID, other.id, "", clientIP)
		var be *BusyError
		if !errors.As(err, &be) || be.RetryAfter != DefaultBusyRetryAfter || !errors.Is(err, ErrBusy) ||
			!errors.Is(err, ErrStateConflict) || be.Error() == "" {
			t.Fatalf("busy delete = %v", err)
		}
		if n := ev.eraser.count(); n != 1+DefaultBusyRetries {
			t.Errorf("eraser calls = %d, want %d", n, 1+DefaultBusyRetries)
		}
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionTransferDeleted)); n != 1 {
			t.Errorf("audit events = %d, want 1", n)
		}

		// A canceled request stops waiting.
		cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		ev.eraser.calls, ev.svc.busyDelay = nil, time.Hour
		wantErr(t, "canceled", ev.svc.DeleteTransfer(cctx, ev.adminA, ev.a.ID, other.id, "", clientIP), context.DeadlineExceeded)
		if n := ev.eraser.count(); n != 1 {
			t.Errorf("eraser calls when canceled = %d, want 1", n)
		}
	})
}

// TestDeleteNoRetry refuses at once when retries are disabled.
func TestDeleteNoRetry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, func(o *Options) { o.BusyRetries, o.BusyRetryAfter = -1, 3*time.Second })
		ev.eraser.busy = 1
		err := ev.svc.DeleteTransfer(context.Background(), ev.adminA, ev.a.ID, missingTrf, "", clientIP)
		var be *BusyError
		if !errors.As(err, &be) || be.RetryAfter != 3*time.Second || ev.eraser.count() != 1 {
			t.Fatalf("busy delete = %v after %d calls", err, ev.eraser.count())
		}
	})
}

// TestAuditFailureIsLogged keeps a committed change when its audit event
// cannot be written, and logs the failure without address.
func TestAuditFailureIsLogged(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		trf := ev.seed(ev.a, store.TransferAvailable, carol)
		ev.faults("audit")
		mustNoErr(t, "delete", ev.svc.DeleteTransfer(context.Background(), ev.adminA, ev.a.ID, trf.id,
			"for carol@customer.example.net", clientIP))
		logs := ev.logs.String()
		if !strings.Contains(logs, "audit write failed") || !strings.Contains(logs, string(audit.ActionTransferDeleted)) ||
			strings.Contains(logs, "@") {
			t.Errorf("logs = %q", logs)
		}
	})
}

// TestResendNotification queues the notification again with the existing
// link, to all or some recipients, without ever exposing the link.
func TestResendNotification(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seed(ev.a, store.TransferAvailable, carol, dave)

		mustNoErr(t, "resend all", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP))
		if len(ev.mailer.jobs) != 2 {
			t.Fatalf("jobs = %d, want 2", len(ev.mailer.jobs))
		}
		link := id.DownloadURL(hostA, trf.token)
		for _, j := range ev.mailer.jobs {
			if !strings.Contains(j.Message.Text, link) || j.TenantID != string(ev.a.ID) {
				t.Errorf("job %v does not carry the existing link", j.Message.To)
			}
		}
		if ev.notifier.links[0] != link {
			t.Errorf("link = %q, want %q", ev.notifier.links[0], link)
		}
		evs := ev.auditEvents(ev.a.ID, audit.ActionTransferNotificationResent)
		if len(evs) != 1 || evs[0].ObjectID != trf.id || evs[0].Actor != "alice.admin" || evs[0].IP != clientIP {
			t.Fatalf("audit = %+v", evs)
		}
		if n := ev.details(evs[0])["recipientCount"]; n != float64(2) {
			t.Errorf("recipientCount = %v", n)
		}

		// A subset, normalized and without duplicates.
		ev.clock.Advance(time.Second)
		ev.mailer.jobs = nil
		mustNoErr(t, "resend subset", ev.svc.ResendNotification(ctx, ev.super, ev.a.ID, trf.id,
			[]string{" Carol@Customer.Example.NET ", carol}, clientIP))
		if len(ev.mailer.jobs) != 1 || !slices.Equal(ev.mailer.jobs[0].Message.To, []string{carol}) {
			t.Fatalf("subset jobs = %+v", ev.mailer.jobs)
		}
		if v := ev.notifier.views[1]; !slices.Equal(v.Recipients, []string{carol}) {
			t.Errorf("view recipients = %v", v.Recipients)
		}
		evs = ev.auditEvents(ev.a.ID, audit.ActionTransferNotificationResent)
		if n := ev.details(evs[0])["recipientCount"]; len(evs) != 2 || n != float64(1) {
			t.Errorf("subset audit = %d events, count %v", len(evs), n)
		}

		err := ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, []string{"mallory@example.net"}, clientIP)
		wantInvalid(t, "not a recipient", err, FieldRecipients+"/0")
		if notAnAddress(err) {
			t.Error("not a recipient reported as not an address")
		}
		// Malformed addresses, display-name forms included, are not
		// addresses (field code invalid-email).
		for _, bad := range []string{"nope", "Carol <" + carol + ">", "<" + carol + ">", `"carol"@customer.example.net`} {
			err := ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, []string{carol, bad}, clientIP)
			wantInvalid(t, "malformed "+bad, err, FieldRecipients+"/1")
			if !notAnAddress(err) {
				t.Errorf("malformed %q not reported as not an address", bad)
			}
		}

		// Neither the token nor the link reaches the logs, the log
		// attributes of the queue or the audit log.
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{})
		mustNoErr(t, "audit", err)
		for _, a := range ev.mailer.attrs {
			if strings.Contains(a.Value.String(), trf.token) {
				t.Error("the token reached the queue attributes")
			}
		}
		for _, a := range page.Items {
			if strings.Contains(string(a.Details), trf.token) {
				t.Error("the token reached the audit log")
			}
		}
		if strings.Contains(ev.logs.String(), trf.token) {
			t.Error("the token reached the logs")
		}
		// The token is never rotated.
		d, err := ev.db.Transfers().Get(ctx, ev.a.ID, trf.id)
		mustNoErr(t, "get", err)
		token, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, d.DownloadTokenKeyID)
		if err != nil || string(token) != trf.token {
			t.Errorf("the token changed: %v", err)
		}
	})
}

// TestResendStates refuses a transfer that is not available, a tenant
// without SMTP settings, and failures of the token and the mails.
func TestResendStates(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		for _, st := range []store.TransferStatus{store.TransferScanning, store.TransferExpired, store.TransferDeleted} {
			trf := ev.seed(ev.a, st, carol)
			err := ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP)
			wantErr(t, "resend "+string(st), err, ErrNotAvailable)
			wantErr(t, "resend "+string(st), err, ErrStateConflict)
		}
		wantErr(t, "missing", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, missingTrf, nil, clientIP), ErrNotFound)

		// Tenant B has no SMTP settings: nothing queued, nothing counted.
		trfB := ev.seed(ev.b, store.TransferAvailable, carol)
		for range DefaultResendLimit + 1 {
			wantErr(t, "no smtp", ev.svc.ResendNotification(ctx, ev.adminB, ev.b.ID, trfB.id, nil, clientIP), ErrMailUnavailable)
		}
		if ev.mailer.count() != 0 || len(ev.auditEvents(ev.b.ID, audit.ActionTransferNotificationResent)) != 0 {
			t.Error("a resend without SMTP queued or audited something")
		}

		trf := ev.seed(ev.a, store.TransferAvailable, carol)
		ev.notifier.err = errBoom
		wantErr(t, "build failure", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP), errBoom)
		ev.notifier.err = notify.ErrNoSMTP
		wantErr(t, "no smtp", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP), ErrMailUnavailable)
		ev.notifier.err = nil
		ev.faults("openSecret")
		wantErr(t, "token failure", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP), errBoom)
		if ev.mailer.count() != 0 {
			t.Error("a failed resend queued a mail")
		}
		// The failed resends were refunded: the whole quota is left.
		ev.faults()
		for range DefaultResendLimit {
			mustNoErr(t, "resend after failures", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP))
		}
	})
}

// TestResendRateLimit allows DefaultResendLimit resends per transfer and
// hour.
func TestResendRateLimit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trf := ev.seed(ev.a, store.TransferAvailable, carol)
		other := ev.seed(ev.a, store.TransferAvailable, carol)
		for range DefaultResendLimit {
			mustNoErr(t, "resend", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP))
			ev.clock.Advance(time.Minute)
		}
		err := ev.svc.ResendNotification(ctx, ev.super, ev.a.ID, trf.id, nil, clientIP)
		var rl *RateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter < time.Second ||
			rl.RetryAfter > time.Hour || rl.Error() == "" {
			t.Fatalf("sixth resend = %v", err)
		}
		if n := ev.mailer.count(); n != DefaultResendLimit {
			t.Errorf("jobs = %d, want %d", n, DefaultResendLimit)
		}
		// The limit is checked before the download token is unsealed.
		ev.faults("openSecret")
		if err := ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("rate-limited resend reached the token: %v", err)
		}
		ev.faults()
		// The limit is per transfer, and the window slides.
		mustNoErr(t, "other transfer", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, other.id, nil, clientIP))
		ev.clock.Advance(time.Hour)
		mustNoErr(t, "after the window", ev.svc.ResendNotification(ctx, ev.adminA, ev.a.ID, trf.id, nil, clientIP))
	})
}

// notAnAddress reports whether err is an *InvalidError flagged NotAnAddress.
func notAnAddress(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie) && ie.NotAnAddress
}

// TestTransferOrigin maps the sender of a stored transfer to its origin,
// and exposes the API token of a token transfer.
func TestTransferOrigin(t *testing.T) {
	t.Parallel()
	tokID := id.New(id.APIToken)
	for _, c := range []struct {
		tr    store.Transfer
		want  Origin
		token string
	}{
		{store.Transfer{SenderKind: store.DepositorInternal}, OriginInternal, ""},
		{store.Transfer{SenderKind: store.DepositorExternal, InvitationID: id.New(id.Invitation)}, OriginExternal, ""},
		{store.Transfer{SenderKind: store.DepositorInternal, APITokenID: tokID}, OriginAPI, tokID},
	} {
		got := transferOf(c.tr, nil, 0)
		if got.Origin != c.want || got.APITokenID != c.token {
			t.Errorf("transferOf(%+v) = origin %q token %q, want %q %q", c.tr, got.Origin, got.APITokenID, c.want, c.token)
		}
	}
}
