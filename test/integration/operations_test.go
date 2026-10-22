package integration_test

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the tenant operations of the administration
// (CLAUDE.md sections 5, 6.5, 8.5, 9, 15.2, 16.1, 20 and 21;
// api/openapi.yaml "Admin operations", getGlobalStats and
// listGlobalAuditEvents): a real server, the fake clamd of antivirustest,
// Mailpit, on SQLite and PostgreSQL.

// TestOperationsFullFlow: a deposit verified by code, scanned and
// downloaded leaves its audit trail (address.verified, transfer.created,
// transfer.finalized, transfer.downloaded), the sender IP and the download
// count on the transfer; once the usage counters are flushed (by the
// shutdown of the server), the tenant and global statistics count it, with
// zero-filled series.
func TestOperationsFullFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		r := uniqueEmail(t, "rcpt", "example.net")
		content := seededBytes(t, 11, 50_000)
		tr, token := alice.availableTransfer(t, transferCreate{Recipients: []string{r}}, uploadedFile{"report.pdf", content})
		fileID := tr.Files[0].ID
		rec := o.newRecipient(1)
		expectFile(t, "download", rec.get(t, filePath(token, fileID), nil), "report.pdf", content)
		// A resumed range is served, but it is not a new download start.
		expectPartial(t, "resumed range", rec.getRange(t, filePath(token, fileID), "bytes=5-"), "report.pdf", content, 5, len(content)-1)

		// Audit trail.
		events := o.sa.tenantEvents(t, o.tid, "")
		for _, ev := range events {
			if ev.TenantID == nil || *ev.TenantID != o.tid {
				t.Errorf("tenant audit list holds %s of tenant %v", ev.Action, ev.TenantID)
			}
		}
		for _, act := range []string{actAddressVerified, actTransferCreated, actTransferFinalized, actTransferDownloaded} {
			got := ofAction(events, act)
			if len(got) != 1 {
				t.Errorf("%d %s events, want 1; actions: %v", len(got), act, eventActions(events))
				continue
			}
			ev := got[0]
			switch act {
			case actAddressVerified:
				expectEvent(t, ev, o.tid, "depositor", sender, insideA, "", "")
			case actTransferCreated, actTransferFinalized:
				expectEvent(t, ev, o.tid, "depositor", sender, insideA, "transfer", tr.ID)
				if detailNumber(ev, "fileCount") != 1 || detailNumber(ev, "totalBytes") != float64(len(content)) {
					t.Errorf("%s details = %v, want fileCount 1 and totalBytes %d", act, ev.Details, len(content))
				}
			case actTransferDownloaded:
				expectEvent(t, ev, o.tid, "recipient", "link", recipientNet+"1", "transfer", tr.ID)
				if ev.Details["file"] != fileID {
					t.Errorf("%s details = %v, want file %s", act, ev.Details, fileID)
				}
			}
			expectNoAddressIn(t, ev)
		}

		// The transfer as the administration sees it.
		got := o.sa.adminTransfer(t, o.tid, tr.ID)
		if got.SenderIP == nil || *got.SenderIP != insideA {
			t.Errorf("senderIp = %v, want %s", got.SenderIP, insideA)
		}
		if got.DownloadCount != 1 || got.FirstDownloadedAt == nil || got.Status != "available" || got.Origin != "internal" ||
			got.SenderEmail != sender || !slices.Equal(got.Recipients, []string{r}) || got.FileCount != 1 ||
			got.TotalBytes != int64(len(content)) || got.ExpiresAt == nil {
			t.Errorf("admin transfer = %+v, want available, 1 download, first download set, sender %s to %s", got, sender, r)
		}
		if len(got.Files) != 1 || got.Files[0].ID != fileID || got.Files[0].Sha256 != sha256Hex(content) || got.Files[0].ScanStatus != "clean" {
			t.Errorf("admin transfer files = %+v", got.Files)
		}
		if strings.Contains(strings.Join(got.Recipients, " "), token) {
			t.Error("the admin transfer holds the download token")
		}
		list := o.sa.listTransfers(t, o.tid, url.Values{"email": {strings.ToUpper(r)}})
		if len(list.Items) != 1 || list.Items[0].ID != tr.ID || list.Items[0].DownloadCount != 1 {
			t.Errorf("transfers of the recipient = %+v, want the transfer with 1 download", list.Items)
		}
		if l := o.sa.listTransfers(t, o.tid, url.Values{"email": {uniqueEmail(t, "nobody", "example.net")}}); len(l.Items) != 0 {
			t.Errorf("transfers of an unknown address = %+v, want none", l.Items)
		}

		// The usage counters are flushed at shutdown (no test hook shortens
		// the 30-second flush interval of the running server).
		o.restartServer(t)
		size := int64(len(content))
		for _, p := range []struct {
			period  string
			n       int
			monthly bool
		}{{"7d", 7, false}, {"30d", 30, false}, {"12m", 12, true}} {
			st := o.sa.tenantStats(t, o.tid, p.period)
			if st.Period != p.period || st.TransferCount != 1 || st.BytesUploaded != size || st.DownloadCount != 1 ||
				st.BytesDownloaded != 2*size-5 || st.VirusDetections != 0 || st.StorageUsedBytes != size ||
				st.StorageQuotaBytes != 1<<40 || !near(st.StorageUsedRatio, float64(size)/(1<<40)) {
				t.Errorf("stats %s = %+v, want 1 transfer of %d bytes, 1 download of %d bytes served, %d bytes used",
					p.period, st, size, 2*size-5, size)
			}
			expectSeries(t, "series "+p.period, st.Series, p.n, p.monthly, *tr.FinalizedAt, 1, size)
		}
		expectProblem(t, o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/stats?period=1y"), nil), http.StatusBadRequest, "validation-failed")

		// Global statistics (item 11): the disk of the data directory and
		// one row per active tenant.
		resp := mustStatus(t, "getGlobalStats", o.sa.call(t, http.MethodGet, pathGlobalStats+"?period=7d", nil), http.StatusOK)
		var gs opsGlobalStats
		mustJSON(t, resp.body, &gs)
		if gs.Period != "7d" || gs.Disk.TotalBytes <= 0 || gs.Disk.UsedBytes <= 0 || gs.Disk.UsedBytes > gs.Disk.TotalBytes ||
			gs.Disk.UsedRatio <= 0 || gs.Disk.UsedRatio > 1 || !near(gs.Disk.AlertThreshold, 0.85) {
			t.Errorf("global disk = %+v, want positive sizes and the 0.85 threshold", gs.Disk)
		}
		if !near(gs.Disk.UsedRatio, float64(gs.Disk.UsedBytes)/float64(gs.Disk.TotalBytes)) {
			t.Errorf("usedRatio %v, want usedBytes/totalBytes", gs.Disk.UsedRatio)
		}
		rows := map[string]int{}
		for _, row := range gs.Tenants {
			rows[row.TenantID]++
			switch row.TenantID {
			case o.tid:
				if row.Name != nameA || row.TransferCount != 1 || row.BytesUploaded != size || row.StorageUsedBytes != size ||
					row.StorageQuotaBytes != 1<<40 {
					t.Errorf("global row of A = %+v", row)
				}
			case string(o.tenantB.ID):
				if row.Name != nameB || row.TransferCount != 0 || row.BytesUploaded != 0 || row.StorageUsedBytes != 0 {
					t.Errorf("global row of B = %+v", row)
				}
			}
		}
		if len(gs.Tenants) != 2 || rows[o.tid] != 1 || rows[string(o.tenantB.ID)] != 1 {
			t.Errorf("global tenant rows = %+v, want exactly one for A and one for B", gs.Tenants)
		}
		noSecretInLogs(t, o.server, token, sender, r)
		o.expectNoSecrets(t, nil)
	})
}

// eventActions returns the action of every event, in order.
func eventActions(events []opsAuditEvent) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.Action
	}
	return out
}

// TestOperationsDeleteAvailable: the admin deletion of an available
// transfer crypto-erases it (keys then files), its link answers 410, the
// quota is freed, and transfer.deleted records the reason with its
// addresses redacted; deleting it again is a no-op without audit.
func TestOperationsDeleteAvailable(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		r := uniqueEmail(t, "rcpt", "example.net")
		content := []byte("content deleted by the administration")
		tr, token := alice.availableTransfer(t, transferCreate{Recipients: []string{r}}, uploadedFile{"wrong.txt", content})
		files := o.files(t, tr.ID)
		if used := o.usedBytes(t, o.tenantA.ID); used != int64(len(content)) {
			t.Fatalf("quota used before the deletion = %d, want %d", used, len(content))
		}

		reason := "Sent to " + r + " by mistake, asked by " + strings.ToUpper(sender) + "."
		mustStatus(t, "deleteTenantTransfer", o.sa.deleteTransfer(t, o.tid, tr.ID, reason), http.StatusNoContent)
		rec := o.newRecipient(2)
		expectGone(t, "page after the deletion", rec.page(t, token))
		expectGone(t, "file after the deletion", rec.get(t, filePath(token, tr.Files[0].ID), nil))
		if used := o.usedBytes(t, o.tenantA.ID); used != 0 {
			t.Errorf("quota used after the deletion = %d, want 0", used)
		}
		if got := o.sa.adminTransfer(t, o.tid, tr.ID); got.Status != "deleted" {
			t.Errorf("status after the deletion = %q, want deleted", got.Status)
		}
		for _, f := range files {
			o.expectKeyDestroyed(t, f.DEKKeyID)
			expectNoFileOnDisk(t, "encrypted file "+f.ID, o.encPath(f.StorageName))
		}
		deleted := o.sa.tenantEvents(t, o.tid, actTransferDeleted)
		if len(deleted) != 1 {
			t.Fatalf("%d transfer.deleted events, want 1", len(deleted))
		}
		expectEvent(t, deleted[0], o.tid, "admin", superName, adminIP(10), "transfer", tr.ID)
		if want := "Sent to [address] by mistake, asked by [address]."; deleted[0].Details["reason"] != want {
			t.Errorf("reason = %v, want %q", deleted[0].Details["reason"], want)
		}
		expectNoAddressIn(t, deleted[0])

		// Already ended: no-op, no audit.
		mustStatus(t, "delete again", o.sa.deleteTransfer(t, o.tid, tr.ID, ""), http.StatusNoContent)
		if n := len(o.sa.tenantEvents(t, o.tid, actTransferDeleted)); n != 1 {
			t.Errorf("%d transfer.deleted events after the second deletion, want 1", n)
		}
		expectProblem(t, o.sa.deleteTransfer(t, o.tid, id.New(id.Transfer), ""), http.StatusNotFound, "not-found")
		long := strings.Repeat("x", 501)
		expectFieldError(t, o.sa.deleteTransfer(t, o.tid, tr.ID, long), "/reason")
		noSecretInLogs(t, o.server, token, r, sender)
		o.expectNoSecrets(t, nil)
	})
}

// TestOperationsDeleteScanning: deleting a transfer while clamd analyzes
// it withdraws it from the antivirus: the transfer ends deleted, never
// available, and no mail reaches any recipient (nor the sender).
func TestOperationsDeleteScanning(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		r1, r2 := uniqueEmail(t, "rcpt-one", "example.net"), uniqueEmail(t, "rcpt-two", "example.org")
		tr := alice.deposit(t, transferCreate{Recipients: []string{r1, r2}}, uploadedFile{"held.txt", []byte("analyzed when deleted")})
		o.av.SetMode(antivirustest.ModeHang)
		alice.mustFinalize(t, tr.ID)
		o.waitFileScanning(t, tr.ID, tr.Files[0].ID)
		files := o.files(t, tr.ID)

		start := time.Now()
		mustStatus(t, "delete a scanning transfer", o.sa.deleteTransfer(t, o.tid, tr.ID, ""), http.StatusNoContent)
		t.Logf("%s: scanning transfer deleted in %s", e.Name, time.Since(start).Round(time.Millisecond))
		o.av.SetMode(antivirustest.ModeScan)
		if got := o.sa.adminTransfer(t, o.tid, tr.ID); got.Status != "deleted" {
			t.Fatalf("status after the deletion = %q, want deleted", got.Status)
		}
		for _, f := range files {
			o.expectKeyDestroyed(t, f.DEKKeyID)
		}
		// Every mail queued before the barrier has been handled.
		o.mailBarrier(t, alice)
		for _, r := range []string{r1, r2} {
			if msgs := o.mp.messagesTo(t, r); len(msgs) != 0 {
				t.Errorf("%d mails to the recipient %s of a transfer deleted while scanned, want none", len(msgs), r)
			}
		}
		if subj := o.mp.subjects(t, sender); len(subj) != 1 {
			t.Errorf("sender mails %q, want the code mail only", subj)
		}
		if got := o.sa.adminTransfer(t, o.tid, tr.ID); got.Status != "deleted" {
			t.Errorf("status after the barrier = %q, want deleted", got.Status)
		}
		if n := len(o.sa.tenantEvents(t, o.tid, actTransferDeleted)); n != 1 {
			t.Errorf("%d transfer.deleted events, want 1", n)
		}
	})
}

// TestOperationsDeleteUploading: while a tus PATCH of the transfer is in
// progress, the deletion is refused with 409 and Retry-After; once the
// PATCH has ended, it succeeds.
func TestOperationsDeleteUploading(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, _ := internalSession(t, o.depositEnv, "alice")
		data := seededBytes(t, 21, 256<<10)
		tr := alice.mustCreate(t, transferCreate{
			Recipients: []string{uniqueEmail(t, "rcpt", "example.net")}, ExpiryDays: 1,
			Files: []fileDecl{{Name: "in-progress.bin", Size: int64(len(data))}},
		})
		finish := alice.holdPatch(t, tr.ID, tr.Files[0].UploadURL, data)

		start := time.Now()
		expectRetryAfter(t, "delete during the PATCH", o.sa.deleteTransfer(t, o.tid, tr.ID, ""), 5)
		t.Logf("%s: deletion refused after %s", e.Name, time.Since(start).Round(time.Millisecond))
		if got := o.sa.adminTransfer(t, o.tid, tr.ID); got.Status != "uploading" {
			t.Errorf("status after the refused deletion = %q, want uploading", got.Status)
		}
		resp := finish()
		if resp.status != http.StatusNoContent || resp.header.Get(hdrUploadOffset) != strconv.Itoa(len(data)) {
			t.Fatalf("PATCH after the refused deletion: %d %v %s", resp.status, resp.header, resp.body)
		}
		files := o.files(t, tr.ID)
		mustStatus(t, "delete after the PATCH", o.sa.deleteTransfer(t, o.tid, tr.ID, ""), http.StatusNoContent)
		if got := o.sa.adminTransfer(t, o.tid, tr.ID); got.Status != "deleted" {
			t.Errorf("status after the deletion = %q, want deleted", got.Status)
		}
		for _, f := range files {
			o.expectKeyDestroyed(t, f.DEKKeyID)
			expectNoFileOnDisk(t, "encrypted file "+f.ID, o.encPath(f.StorageName))
		}
		if n := len(o.sa.tenantEvents(t, o.tid, actTransferDeleted)); n != 1 {
			t.Errorf("%d transfer.deleted events, want 1 (the refused deletion is not audited)", n)
		}
	})
}

// TestOperationsResend: the notification is resent to a subset of the
// original recipients with the existing link, which keeps working; an
// address that is not a recipient is refused (400), a transfer that is
// not available too (409), and the sixth resend of the hour is 429. The
// link never appears in a response, a log or the audit log.
func TestOperationsResend(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		r1, r2, r3 := uniqueEmail(t, "rcpt-one", "example.net"), uniqueEmail(t, "rcpt-two", "example.org"), uniqueEmail(t, "rcpt-three", "example.com")
		tr, token := alice.availableTransfer(t, transferCreate{Recipients: []string{r1, r2, r3}}, uploadedFile{"notice.txt", []byte("resent content")})
		o.secret(token)
		for _, r := range []string{r1, r2, r3} {
			o.waitMailSent(t, r)
		}

		resp := mustStatus(t, "resend to r2", o.sa.resend(t, o.tid, tr.ID, []string{strings.ToUpper(r2)}), http.StatusAccepted)
		if strings.Contains(string(resp.body), token) || strings.Contains(string(resp.body), "/d/") {
			t.Errorf("resend answer holds the link: %s", resp.body)
		}
		eventually(t, "second notification to r2", func() bool { return len(o.mp.messagesTo(t, r2)) >= 2 })
		for _, msg := range o.mp.messagesTo(t, r2) {
			if !strings.Contains(o.mp.detail(t, msg.ID).text(), tr.DownloadURL) {
				t.Errorf("notification %q to r2 lacks the existing link", msg.Subject)
			}
		}
		o.newRecipient(3).mustPage(t, token)
		o.mailBarrier(t, alice)
		for r, want := range map[string]int{r1: 1, r2: 2, r3: 1} {
			if n := len(o.mp.messagesTo(t, r)); n != want {
				t.Errorf("%d mails to %s, want %d", n, r, want)
			}
		}

		expectFieldError(t, o.sa.resend(t, o.tid, tr.ID, []string{uniqueEmail(t, "stranger", "example.org")}), "/recipients/0")
		// A malformed address, a display-name form included, is refused
		// with the pointer of its field (invalid-email); it does not count
		// against the resend limit.
		expectEmailError(t, o.sa.resend(t, o.tid, tr.ID, []string{r1, "not an address"}), "/recipients/1")
		expectEmailError(t, o.sa.resend(t, o.tid, tr.ID, []string{"Recipient <" + r1 + ">"}), "/recipients/0")
		up := alice.mustCreate(t, transferCreate{Recipients: []string{r1}, ExpiryDays: 1, Files: []fileDecl{{Name: "pending.bin", Size: 10}}})
		expectProblem(t, o.sa.resend(t, o.tid, up.ID, nil), http.StatusConflict, "state-conflict")
		expectProblem(t, o.sa.resend(t, o.tid, id.New(id.Transfer), nil), http.StatusNotFound, "not-found")

		// 5 resends per hour and transfer: 4 more, then 429.
		for i := range 4 {
			mustStatus(t, "resend "+strconv.Itoa(i+2), o.sa.resend(t, o.tid, tr.ID, []string{r3}), http.StatusAccepted)
		}
		limited := o.sa.resend(t, o.tid, tr.ID, []string{r3})
		expectProblem(t, limited, http.StatusTooManyRequests, "rate-limited")
		if ra, err := strconv.Atoi(limited.header.Get(hdrRetryAfter)); err != nil || ra < 1 || ra > 3600 {
			t.Errorf("Retry-After = %q, want 1 to 3600 seconds", limited.header.Get(hdrRetryAfter))
		}

		resent := o.sa.tenantEvents(t, o.tid, actTransferResent)
		if len(resent) != 5 {
			t.Errorf("%d transfer.notification_resent events, want 5", len(resent))
		}
		for _, ev := range resent {
			expectEvent(t, ev, o.tid, "admin", superName, adminIP(10), "transfer", tr.ID)
			if detailNumber(ev, "recipientCount") != 1 || len(ev.Details) != 1 {
				t.Errorf("resend details = %v, want recipientCount 1 only", ev.Details)
			}
		}
		noSecretInLogs(t, o.server, token, r1, r2, r3, sender)
		o.expectNoSecrets(t, o.tenantAudit(t, o.tid))
	})
}

// TestOperationsInvitations: the invitations are listed with their status
// and issuer; revoking a used invitation stops its link (410) and its
// session, and is audited once; revoking it again is a no-op.
func TestOperationsInvitations(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, inviter := internalSession(t, o.depositEnv, "inviter")
		g1, g2 := uniqueEmail(t, "guest-one", externalDomain), uniqueEmail(t, "guest-two", externalDomain)
		inv1, _ := alice.inviteAndLink(t, g1)
		inv2, token2 := alice.inviteAndLink(t, g2)
		o.secret(token2)
		guest := o.invitedSession(t, g2, token2, 1)

		ids := func(l opsInvitationList) []string {
			var out []string
			for _, inv := range l.Items {
				out = append(out, inv.ID)
			}
			return out
		}
		all := o.sa.invitations(t, o.tid, nil)
		if !slices.Equal(ids(all), []string{inv2, inv1}) {
			t.Errorf("invitations = %v, want [%s %s] (most recent first)", ids(all), inv2, inv1)
		}
		for _, inv := range all.Items {
			if inv.InvitedBy != inviter {
				t.Errorf("invitation %s invitedBy %q, want %s", inv.ID, inv.InvitedBy, inviter)
			}
		}
		for status, want := range map[string][]string{"pending": {inv1}, "used": {inv2}, "revoked": nil, "expired": nil} {
			if got := ids(o.sa.invitations(t, o.tid, url.Values{"status": {status}})); !slices.Equal(got, want) {
				t.Errorf("invitations %s = %v, want %v", status, got, want)
			}
		}
		expectFieldError(t, o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/invitations?status=lost"), nil), "status")

		mustStatus(t, "revoke the used invitation", o.sa.revokeInvitation(t, o.tid, inv2), http.StatusNoContent)
		expectProblem(t, o.get(t, hostA, pathInvitations+"/"+token2), http.StatusGone, "invitation-gone")
		expectProblem(t, guest.current(t), http.StatusUnauthorized, "unauthenticated")
		if got := ids(o.sa.invitations(t, o.tid, url.Values{"status": {"revoked"}})); !slices.Equal(got, []string{inv2}) {
			t.Errorf("revoked invitations = %v, want [%s]", got, inv2)
		}
		revoked := o.sa.tenantEvents(t, o.tid, actInvitationRevoked)
		if len(revoked) != 1 {
			t.Fatalf("%d invitation.revoked events, want 1", len(revoked))
		}
		expectEvent(t, revoked[0], o.tid, "admin", superName, adminIP(10), "invitation", inv2)

		mustStatus(t, "revoke again", o.sa.revokeInvitation(t, o.tid, inv2), http.StatusNoContent)
		if n := len(o.sa.tenantEvents(t, o.tid, actInvitationRevoked)); n != 1 {
			t.Errorf("%d invitation.revoked events after the second revocation, want 1", n)
		}
		expectProblem(t, o.sa.revokeInvitation(t, o.tid, id.New(id.Invitation)), http.StatusNotFound, "not-found")
		events := o.sa.tenantEvents(t, o.tid, "")
		if len(ofAction(events, actInvitationCreated)) != 2 || len(ofAction(events, actInvitationUsed)) != 1 {
			t.Errorf("audit actions = %v, want 2 invitation.created and 1 invitation.used", eventActions(events))
		}
		noSecretInLogs(t, o.server, token2)
	})
}

// TestOperationsBlocklist: an entry is stored trimmed and in lower case,
// a duplicate is refused (409), the blocked address cannot deposit until
// the entry is removed, and blocklist.updated never records an address.
func TestOperationsBlocklist(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		path := tenantPath(o.tid, "/blocklist")
		blocked := uniqueEmail(t, "mallory", domainA)
		resp := mustStatus(t, "create the email entry", o.sa.call(t, http.MethodPost, path, map[string]string{
			"kind": "email", "value": "  " + strings.ToUpper(blocked) + " ", "comment": "Phishing attempts",
		}), http.StatusCreated)
		var entry opsBlockEntry
		mustJSON(t, resp.body, &entry)
		if !strings.HasPrefix(entry.ID, "blk_") || entry.Kind != "email" || entry.Value != blocked || entry.CreatedBy != superName ||
			entry.Comment == nil || *entry.Comment != "Phishing attempts" {
			t.Errorf("email entry = %+v, want %s stored in lower case", entry, blocked)
		}
		expectProblem(t, o.sa.call(t, http.MethodPost, path, map[string]string{"kind": "email", "value": blocked}),
			http.StatusConflict, "already-exists")
		resp = mustStatus(t, "create the domain entry", o.sa.call(t, http.MethodPost, path, map[string]string{
			"kind": "domain", "value": "Spam-Ops.Example.NET",
		}), http.StatusCreated)
		var domain opsBlockEntry
		mustJSON(t, resp.body, &domain)
		if domain.Value != "spam-ops.example.net" || domain.Kind != "domain" {
			t.Errorf("domain entry = %+v", domain)
		}
		expectFieldError(t, o.sa.call(t, http.MethodPost, path, map[string]string{"kind": "domain", "value": "a@b.example.net"}), "/value")

		resp = mustStatus(t, "listBlocklist", o.sa.call(t, http.MethodGet, path+"?kind=domain", nil), http.StatusOK)
		var list opsBlockList
		mustJSON(t, resp.body, &list)
		if len(list.Items) != 1 || list.Items[0].ID != domain.ID {
			t.Errorf("domain entries = %+v, want the domain entry only", list.Items)
		}

		expectProblem(t, o.newDepositor().start(t, blocked, ""), http.StatusForbidden, "deposit-not-allowed")
		if got := reasons(t, o.server); !slices.Equal(got, []string{"blocklist"}) {
			t.Errorf("deposit_refused reasons = %v, want [blocklist]", got)
		}
		mustStatus(t, "delete the email entry", o.sa.call(t, http.MethodDelete, path+"/"+entry.ID, nil), http.StatusNoContent)
		expectProblem(t, o.sa.call(t, http.MethodDelete, path+"/"+entry.ID, nil), http.StatusNotFound, "not-found")
		expectChallenge(t, o.newDepositor().start(t, blocked, ""), blocked)

		updated := o.sa.tenantEvents(t, o.tid, actBlocklistUpdated)
		if len(updated) != 3 {
			t.Fatalf("%d blocklist.updated events, want 3", len(updated))
		}
		ops := map[string]int{}
		for _, ev := range updated {
			expectEvent(t, ev, o.tid, "admin", superName, adminIP(10), "", "")
			expectNoAddressIn(t, ev)
			op, _ := ev.Details["op"].(string)
			ops[op+" "+ev.Details["kind"].(string)]++
			if ev.Details["entryId"] != ev.Object.ID {
				t.Errorf("blocklist.updated entryId %v, object %s", ev.Details["entryId"], ev.Object.ID)
			}
			_, hasValue := ev.Details["value"]
			switch ev.Details["kind"] {
			case "email":
				if hasValue {
					t.Errorf("blocklist.updated of an email entry holds the value: %v", ev.Details)
				}
			case "domain":
				if ev.Details["value"] != "spam-ops.example.net" {
					t.Errorf("blocklist.updated of the domain entry = %v, want its value", ev.Details)
				}
			}
		}
		if want := map[string]int{"created email": 1, "deleted email": 1, "created domain": 1}; !maps.Equal(ops, want) {
			t.Errorf("blocklist.updated operations = %v, want %v", ops, want)
		}
		noSecretInLogs(t, o.server, blocked)
	})
}

// TestOperationsAudit: the tenant audit list filters by action, actor and
// period and pages with its cursor; the global list includes the events
// without tenant, and only those of a tenant with tenantId; a delegated
// admin gets 403 on the global audit log and the global statistics.
func TestOperationsAudit(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		da := o.sa.createDelegatedOf(t, "delegate-ops", o.tid, domainA, adminIP(20))
		alice, aliceEmail := internalSession(t, o.depositEnv, "alice")
		bob, bobEmail := internalSession(t, o.depositEnv, "bob")
		for i := range 3 {
			alice.mustCreate(t, oneFileTo(t, "alice-"+strconv.Itoa(i)+".bin", 10))
		}
		bob.mustCreate(t, oneFileTo(t, "bob.bin", 10))
		openTenantB(t, o.depositEnv) // events of tenant B, never listed for A

		base := tenantPath(o.tid, "/audit-events")
		full := o.sa.auditAll(t, base, nil)
		if len(full) < 6 {
			t.Fatalf("tenant A has %d audit events, want at least 6", len(full))
		}
		for i, ev := range full {
			if ev.TenantID == nil || *ev.TenantID != o.tid {
				t.Errorf("tenant list holds an event of %v", ev.TenantID)
			}
			if i > 0 && ev.OccurredAt.After(full[i-1].OccurredAt) {
				t.Errorf("event %d is more recent than event %d", i, i-1)
			}
		}
		filter := func(keep func(opsAuditEvent) bool) []string {
			var out []string
			for _, ev := range full {
				if keep(ev) {
					out = append(out, ev.ID)
				}
			}
			return out
		}
		check := func(what string, q url.Values, want []string) {
			t.Helper()
			if got := eventIDs(o.sa.auditAll(t, base, q)); !slices.Equal(got, want) {
				t.Errorf("%s: %v, want %v", what, got, want)
			}
		}
		created := filter(func(ev opsAuditEvent) bool { return ev.Action == actTransferCreated })
		if len(created) != 4 {
			t.Errorf("%d transfer.created events, want 4", len(created))
		}
		check("action", url.Values{"action": {actTransferCreated}}, created)
		check("actor", url.Values{"actor": {strings.ToUpper(aliceEmail)}}, filter(func(ev opsAuditEvent) bool { return ev.Actor.ID == aliceEmail }))
		check("action and actor", url.Values{"action": {actTransferCreated}, "actor": {bobEmail}},
			filter(func(ev opsAuditEvent) bool { return ev.Action == actTransferCreated && ev.Actor.ID == bobEmail }))
		check("unknown action", url.Values{"action": {"transfer.never_recorded"}}, nil)
		from, to := full[len(full)-2].OccurredAt, full[1].OccurredAt
		check("period", url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}},
			filter(func(ev opsAuditEvent) bool { return !ev.OccurredAt.Before(from) && !ev.OccurredAt.After(to) }))
		expectFieldError(t, o.sa.call(t, http.MethodGet, base+"?action=Not+An+Action", nil), "action")
		expectFieldError(t, o.sa.call(t, http.MethodGet, base+"?"+url.Values{
			"from": {to.Format(time.RFC3339Nano)}, "to": {from.Format(time.RFC3339Nano)},
		}.Encode(), nil), "to")
		expectFieldError(t, o.sa.call(t, http.MethodGet, base+"?limit=201", nil), "limit")

		// Cursor pagination by 2.
		var paged []string
		q := url.Values{"limit": {"2"}}
		pages := 0
		for {
			page := o.sa.auditPage(t, base+"?"+q.Encode())
			pages++
			if len(page.Items) > 2 {
				t.Fatalf("page of %d items, want at most 2", len(page.Items))
			}
			paged = append(paged, eventIDs(page.Items)...)
			if page.NextCursor == nil {
				break
			}
			if pages > len(full) {
				t.Fatal("the cursor never ends")
			}
			q.Set("cursor", *page.NextCursor)
		}
		if !slices.Equal(paged, eventIDs(full)) || pages != (len(full)+1)/2 {
			t.Errorf("paged events = %v in %d pages, want %v in %d pages", paged, pages, eventIDs(full), (len(full)+1)/2)
		}
		expectFieldError(t, o.sa.call(t, http.MethodGet, base+"?cursor=not-a-cursor", nil), "cursor")

		// Global audit log.
		global := o.sa.auditAll(t, pathGlobalAudit, nil)
		perTenant := map[string]int{}
		for _, ev := range global {
			key := "null"
			if ev.TenantID != nil {
				key = *ev.TenantID
			}
			perTenant[key]++
		}
		if perTenant["null"] == 0 || perTenant[o.tid] != len(full) || perTenant[string(o.tenantB.ID)] == 0 {
			t.Errorf("global audit events per tenant = %v, want events without tenant, %d of A and some of B", perTenant, len(full))
		}
		if got := eventIDs(o.sa.auditAll(t, pathGlobalAudit, url.Values{"tenantId": {o.tid}})); !slices.Equal(got, eventIDs(full)) {
			t.Errorf("global audit of A = %v, want the tenant list %v", got, eventIDs(full))
		}
		if setup := ofAction(global, "setup.completed"); len(setup) != 1 || setup[0].TenantID != nil {
			t.Errorf("setup.completed in the global list = %+v, want one event without tenant", setup)
		}

		// The delegated admin reads its tenant, never the global views.
		if got := eventIDs(da.auditAll(t, base, nil)); !slices.Equal(got, eventIDs(full)) {
			t.Errorf("delegated audit of A = %v, want %v", got, eventIDs(full))
		}
		expectProblem(t, da.call(t, http.MethodGet, tenantPath(string(o.tenantB.ID), "/audit-events"), nil), http.StatusNotFound, "not-found")
		expectProblem(t, da.call(t, http.MethodGet, pathGlobalAudit, nil), http.StatusForbidden, "forbidden")
		expectProblem(t, da.call(t, http.MethodGet, pathGlobalStats, nil), http.StatusForbidden, "forbidden")
		o.expectNoSecrets(t, nil)
	})
}

// oneFileTo is oneFile with a recipient unique to the test.
func oneFileTo(t *testing.T, name string, size int64) transferCreate {
	t.Helper()
	req := oneFile(name, size)
	req.Recipients = []string{uniqueEmail(t, "rcpt", "example.net")}
	return req
}

// TestOperationsQuota: crossing 80 % of the quota mails one warning to
// each delegated admin through the tenant SMTP; a creation still under
// 100 % mails nothing more; a creation refused at 95 % or more mails one
// "quota reached" alert; once the storage falls under 75 % and the sweep
// ran, the next crossing mails again. A tenant without delegated admin
// alerts the super admins.
func TestOperationsQuota(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		d1 := o.sa.createDelegatedOf(t, "delegate-q1", o.tid, domainA, adminIP(21))
		d2 := o.sa.createDelegatedOf(t, "delegate-q2", o.tid, domainA, adminIP(22))
		alice, _ := internalSession(t, o.depositEnv, "alice")
		bob := openTenantB(t, o.depositEnv)
		const quota = 1000
		o.setLimits(t, quota, quota)
		o.setLimitsOf(t, o.tenantB.ID, quota, quota)
		create := func(c *depositor, size int64) response {
			t.Helper()
			return c.createTransfer(t, oneFileTo(t, "quota.bin", size), "")
		}
		admins := []string{d1.acct.email, d2.acct.email}

		// 80 %: one warning to each delegated admin.
		t1 := parseTransfer(t, mustStatus(t, "transfer of 80 %", create(alice, 800), http.StatusCreated).body)
		for _, addr := range admins {
			o.mp.waitQuotaMails(t, addr, nameA, 1, 0)
		}
		// 95 %: no new alert; a refused creation then raises "reached".
		t2 := parseTransfer(t, mustStatus(t, "transfer of 95 %", create(alice, 150), http.StatusCreated).body)
		expectProblem(t, create(alice, 100), http.StatusInsufficientStorage, "quota-exceeded")
		for _, addr := range admins {
			o.mp.waitQuotaMails(t, addr, nameA, 1, 1)
			// The alerts are queued in order: the reached one is the last.
			if w, r := o.mp.quotaMails(t, addr, nameA); w != 1 || r != 1 {
				t.Errorf("quota mails to %s: %d warnings, %d reached, want 1 and 1", addr, w, r)
			}
		}
		msg := o.mp.waitSubject(t, d1.acct.email, quotaSubjectPrefix+nameA+" "+quotaReachedWord)
		if msg.From.Address != "noreply@"+domainA {
			t.Errorf("quota alert from %q, want the tenant sender noreply@%s", msg.From.Address, domainA)
		}
		if n := quotaLevel(t, e, o.tid); n != 100 {
			t.Errorf("quota level = %d, want 100", n)
		}
		events := o.sa.tenantEvents(t, o.tid, "")
		for act, want := range map[string]int{actQuotaWarning: 1, actQuotaReached: 1} {
			got := ofAction(events, act)
			if len(got) != want {
				t.Errorf("%d %s events, want %d", len(got), act, want)
			}
			for _, ev := range got {
				expectEvent(t, ev, o.tid, "system", "quota", "", "tenant", o.tid)
			}
		}

		// Under 75 %, the sweep re-arms the alert (the start-up sweep of a
		// restarted server: no test hook shortens the 15-minute interval).
		for _, trf := range []string{t1.ID, t2.ID} {
			mustStatus(t, "delete "+trf, o.sa.deleteTransfer(t, o.tid, trf, ""), http.StatusNoContent)
		}
		if n := quotaLevel(t, e, o.tid); n != 100 {
			t.Errorf("quota level before the sweep = %d, want 100 (a deletion alone does not re-arm)", n)
		}
		o.restartServer(t)
		eventually(t, "quota level re-armed by the sweep", func() bool { return quotaLevel(t, e, o.tid) == 0 })
		mustStatus(t, "transfer of 85 %", create(alice, 850), http.StatusCreated)
		for _, addr := range admins {
			o.mp.waitQuotaMails(t, addr, nameA, 2, 1)
		}
		eventually(t, "quota level 80", func() bool { return quotaLevel(t, e, o.tid) == 80 })

		// Tenant B has no delegated admin: the super admin is alerted,
		// through the SMTP settings of B.
		mustStatus(t, "transfer of 80 % in B", create(bob, 800), http.StatusCreated)
		o.mp.waitQuotaMails(t, o.sa.acct.email, nameB, 1, 0)
		fallback := o.mp.waitSubject(t, o.sa.acct.email, quotaSubjectPrefix+nameB)
		if fallback.From.Address != "noreply@"+domainB {
			t.Errorf("fallback alert from %q, want noreply@%s", fallback.From.Address, domainB)
		}
		for _, addr := range admins {
			if w, r := o.mp.quotaMails(t, addr, nameB); w+r != 0 {
				t.Errorf("the delegated admin %s of A got %d alerts about B", addr, w+r)
			}
		}
		if w, r := o.mp.quotaMails(t, o.sa.acct.email, nameA); w+r != 0 {
			t.Errorf("the super admin got %d alerts about A, which has delegated admins", w+r)
		}
		o.expectNoSecrets(t, nil)
	})
}

// TestOperationsGDPR: the erasure of an address that is, in tenant A, an
// internal sender, an external sender through an invitation, a recipient
// among several, the sole recipient of a transfer, a recipient of an ended
// transfer, an inviter, an invitee, a verified address with a pending
// challenge and open sessions, and an audit actor: the search counts it
// all, the erasure reports it, a new search finds nothing, its audit
// events share one pseudonym, data_subject.erased holds no address, its
// sessions are refused. The same address in tenant B is untouched.
func TestOperationsGDPR(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		subject := uniqueEmail(t, "subject", domainA)
		tidB := string(o.tenantB.ID)

		// Tenant B: the same address, internal there too, sender and
		// recipient.
		bob := openTenantB(t, o.depositEnv)
		o.setRules(t, false, []string{internalNetB}, domainB, domainA)
		xb := &depositor{d: o.depositEnv, host: hostB, ip: insideB}
		xb.openSessionNth(t, subject, "", 1)
		tb, tokenB := xb.availableTransfer(t, transferCreate{Recipients: []string{uniqueEmail(t, "rcpt-b", "example.net")}},
			uploadedFile{"b.txt", []byte("content of B")})
		bob.availableTransfer(t, transferCreate{Recipients: []string{subject}}, uploadedFile{"to-subject.txt", []byte("for the subject in B")})

		// Tenant A.
		x := o.newDepositor()
		x.openSessionNth(t, subject, "", 2)
		alice, aliceEmail := internalSession(t, o.depositEnv, "alice")
		invX, tokenX := alice.inviteAndLink(t, subject)
		xe := o.invitedSession(t, subject, tokenX, 3)
		guest := uniqueEmail(t, "guest", externalDomain)
		invG, tokenG := x.inviteAndLink(t, guest)
		o.secret(tokenX, tokenG)

		file := func(name string) uploadedFile { return uploadedFile{name, []byte("content of " + name)} }
		t1, token1 := x.availableTransfer(t, transferCreate{Recipients: []string{uniqueEmail(t, "rcpt", "example.net")}}, file("sent.txt"))
		t2, token2 := xe.availableTransfer(t, transferCreate{}, file("external.txt"))
		r1, r2 := uniqueEmail(t, "rcpt-one", "example.net"), uniqueEmail(t, "rcpt-two", "example.org")
		t3, token3 := alice.availableTransfer(t, transferCreate{Recipients: []string{subject, r1}}, file("several.txt"))
		t4, token4 := alice.availableTransfer(t, transferCreate{Recipients: []string{subject}}, file("sole.txt"))
		t5, _ := alice.availableTransfer(t, transferCreate{Recipients: []string{subject, r2}}, file("ended.txt"))
		mustStatus(t, "end t5", o.sa.deleteTransfer(t, o.tid, t5.ID, ""), http.StatusNoContent)
		expectChallenge(t, o.newDepositor().start(t, subject, ""), subject) // pending challenge
		if t2.SenderEmail != subject || !slices.Equal(t2.Recipients, []string{aliceEmail}) {
			t.Fatalf("external transfer = %s to %v, want %s to %s", t2.SenderEmail, t2.Recipients, subject, aliceEmail)
		}
		erasedFiles := map[string][]string{}
		for _, trf := range []senderTransferJSON{t1, t2, t4} {
			for _, f := range o.files(t, trf.ID) {
				erasedFiles[trf.ID] = append(erasedFiles[trf.ID], f.DEKKeyID, o.encPath(f.StorageName))
			}
		}

		// Snapshots of B.
		rowsB := tenantRows(t, e, tidB)
		delete(rowsB, "tenant_daily_stats") // flushed in the background
		subjectB := rowsWith(t, e, tidB, subject)
		if subjectB["transfers.sender_email"] != 1 || subjectB["transfer_recipients.email"] != 1 ||
			subjectB["verified_addresses.email"] != 1 || subjectB["audit_events.actor"] == 0 {
			t.Fatalf("data of the subject in B = %v", subjectB)
		}
		searchB := o.sa.searchSubject(t, tidB, subject)

		// Search in A.
		eventsA := countSystem(t, e, `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '`+o.tid+`' AND actor = '`+subject+`'`)
		sum := o.sa.searchSubject(t, o.tid, strings.ToUpper(subject))
		want := opsSubjectSummary{
			Email: subject, VerifiedAddress: true, TransfersAsSender: 2, TransfersAsRecipient: 3, Invitations: 2,
			AuditEvents: eventsA, SecurityEvents: 0,
		}
		if sum != want || eventsA < 8 {
			t.Errorf("search = %+v, want %+v (with at least 8 audit events)", sum, want)
		}

		// Erasure.
		resp := mustStatus(t, "eraseDataSubject", o.sa.eraseSubject(t, o.tid, subject), http.StatusOK)
		var rep opsEraseReport
		mustJSON(t, resp.body, &rep)
		wantRep := opsEraseReport{
			TransfersDeleted: 3, RecipientEntriesRemoved: 2, VerifiedAddressDeleted: true,
			InvitationsDeleted: 1, LogEntriesPseudonymised: eventsA,
		}
		if rep != wantRep {
			t.Errorf("erase report = %+v, want %+v", rep, wantRep)
		}
		if after := o.sa.searchSubject(t, o.tid, subject); after != (opsSubjectSummary{Email: subject}) {
			t.Errorf("search after the erasure = %+v, want zeros", after)
		}
		for k, n := range rowsWith(t, e, o.tid, subject) {
			if n != 0 {
				t.Errorf("tenant A: %d rows of %s still hold the address", n, k)
			}
		}

		// Audit: one pseudonym for every event of the subject.
		pseudonyms := sysQuery(t, e, `SELECT actor, COUNT(*) FROM audit_events WHERE tenant_id = '`+o.tid+
			`' AND actor LIKE 'erased-%' GROUP BY actor`)
		if len(pseudonyms) != 1 || !pseudonymRE.MatchString(pseudonyms[0][0]) || pseudonyms[0][1] != strconv.Itoa(eventsA) {
			t.Fatalf("pseudonymised actors = %v, want one erased-<16 hex> on %d events", pseudonyms, eventsA)
		}
		pseudonym := pseudonyms[0][0]
		erased := o.sa.tenantEvents(t, o.tid, actSubjectErased)
		if len(erased) != 1 {
			t.Fatalf("%d data_subject.erased events, want 1", len(erased))
		}
		expectEvent(t, erased[0], o.tid, "admin", superName, adminIP(10), "data_subject", pseudonym)
		expectNoAddressIn(t, erased[0])
		if detailNumber(erased[0], "transfersDeleted") != 3 || erased[0].Details["complete"] != true {
			t.Errorf("data_subject.erased details = %v", erased[0].Details)
		}
		for _, ev := range o.sa.tenantEvents(t, o.tid, actSubjectSearched) {
			expectNoAddressIn(t, ev)
			if ev.Object.ID == pseudonym || !pseudonymRE.MatchString(ev.Object.ID) {
				t.Errorf("data_subject.searched object %q, want another pseudonym than the erasure's", ev.Object.ID)
			}
		}

		// Sessions, invitations, transfers.
		expectProblem(t, x.current(t), http.StatusUnauthorized, "unauthenticated")
		expectProblem(t, xe.current(t), http.StatusUnauthorized, "unauthenticated")
		invs := o.sa.invitations(t, o.tid, nil)
		var issued *opsInvitation
		for i, inv := range invs.Items {
			if inv.ID == invX {
				t.Errorf("the invitation of the subject %s is still listed", invX)
			}
			if inv.ID == invG {
				issued = &invs.Items[i]
			}
		}
		if issued == nil || issued.InvitedBy != pseudonym || issued.Status != "revoked" {
			t.Errorf("invitation issued by the subject = %+v, want revoked and issued by %s", issued, pseudonym)
		}
		expectProblem(t, o.get(t, hostA, pathInvitations+"/"+tokenG), http.StatusGone, "invitation-gone")
		rec := o.newRecipient(4)
		for _, c := range []struct{ trf, token string }{{t1.ID, token1}, {t2.ID, token2}, {t4.ID, token4}} {
			expectProblem(t, o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers/"+c.trf), nil), http.StatusNotFound, "not-found")
			expectProblem(t, rec.page(t, c.token), http.StatusNotFound, "not-found")
		}
		for trf, keys := range erasedFiles {
			for i := 0; i+1 < len(keys); i += 2 {
				o.expectKeyDestroyed(t, keys[i])
				expectNoFileOnDisk(t, "file of "+trf, keys[i+1])
			}
		}
		if got := o.sa.adminTransfer(t, o.tid, t3.ID); got.Status != "available" || !slices.Equal(got.Recipients, []string{r1}) {
			t.Errorf("transfer with several recipients = %s to %v, want available to [%s]", got.Status, got.Recipients, r1)
		}
		rec.mustPage(t, token3)
		resp = o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers/"+t5.ID), nil)
		if resp.status == http.StatusOK {
			var got opsTransfer
			mustJSON(t, resp.body, &got)
			if got.Status != "deleted" || !slices.Equal(got.Recipients, []string{r2}) {
				t.Errorf("ended transfer = %s to %v, want deleted to [%s]", got.Status, got.Recipients, r2)
			}
		} else {
			expectProblem(t, resp, http.StatusNotFound, "not-found")
		}

		// Tenant B is untouched.
		gotRowsB := tenantRows(t, e, tidB)
		delete(gotRowsB, "tenant_daily_stats")
		if !maps.Equal(gotRowsB, rowsB) {
			t.Errorf("rows of B after the erasure in A = %v, want %v", gotRowsB, rowsB)
		}
		if got := rowsWith(t, e, tidB, subject); !maps.Equal(got, subjectB) {
			t.Errorf("data of the subject in B after the erasure in A = %v, want %v", got, subjectB)
		}
		if got := o.sa.searchSubject(t, tidB, subject); got != searchB {
			t.Errorf("search in B after the erasure in A = %+v, want %+v", got, searchB)
		}
		if n := countSystem(t, e, `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '`+tidB+`' AND actor LIKE 'erased-%'`); n != 0 {
			t.Errorf("%d pseudonymised audit events in B, want none", n)
		}
		if st := xb.current(t).status; st != http.StatusOK {
			t.Errorf("session of the subject in B: %d, want 200", st)
		}
		expectIntactB(t, o.depositEnv, tb.ID)
		(&recipient{d: o.depositEnv, host: hostB, ip: recipientNet + "5"}).mustPage(t, tokenB)

		noSecretInLogs(t, o.server, subject)
		o.expectNoSecrets(t, nil)
		t.Logf("%s: %d audit events pseudonymised as %s; B tables %v", e.Name, eventsA, pseudonym, sortedKeys(rowsB))
	})
}

// TestOperationsGDPRUploadInProgress: while an upload of a transfer of the
// address is in progress, the erasure stops with 409 and Retry-After
// (what was erased stays erased); repeated once the upload has ended, it
// completes.
func TestOperationsGDPRUploadInProgress(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		y, subject := internalSession(t, o.depositEnv, "subject")
		data := seededBytes(t, 22, 256<<10)
		tr := y.mustCreate(t, transferCreate{
			Recipients: []string{uniqueEmail(t, "rcpt", "example.net")}, ExpiryDays: 1,
			Files: []fileDecl{{Name: "uploading.bin", Size: int64(len(data))}},
		})
		files := o.files(t, tr.ID)
		finish := y.holdPatch(t, tr.ID, tr.Files[0].UploadURL, data)

		expectRetryAfter(t, "erase during the PATCH", o.sa.eraseSubject(t, o.tid, subject), 5)
		resp := finish()
		t.Logf("%s: PATCH after the interrupted erasure: %d", e.Name, resp.status)
		done := mustStatus(t, "erase after the PATCH", o.sa.eraseSubject(t, o.tid, subject), http.StatusOK)
		var rep opsEraseReport
		mustJSON(t, done.body, &rep)
		if rep.TransfersDeleted != 1 {
			t.Errorf("report of the completed erasure = %+v, want the transfer deleted", rep)
		}
		if after := o.sa.searchSubject(t, o.tid, subject); after != (opsSubjectSummary{Email: subject}) {
			t.Errorf("search after the erasure = %+v, want zeros", after)
		}
		expectProblem(t, o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers/"+tr.ID), nil), http.StatusNotFound, "not-found")
		for _, f := range files {
			o.expectKeyDestroyed(t, f.DEKKeyID)
			expectNoFileOnDisk(t, "encrypted file "+f.ID, o.encPath(f.StorageName))
		}
		erased := o.sa.tenantEvents(t, o.tid, actSubjectErased)
		if len(erased) != 2 || erased[0].Details["complete"] != true || erased[1].Details["complete"] != false {
			var details []map[string]any
			for _, ev := range erased {
				details = append(details, ev.Details)
			}
			t.Errorf("data_subject.erased details = %v, want the incomplete erasure then the complete one", details)
		}
		for k, n := range rowsWith(t, e, o.tid, subject) {
			if n != 0 {
				t.Errorf("%d rows of %s still hold the address", n, k)
			}
		}
		noSecretInLogs(t, o.server, subject)
	})
}

// TestOperationsMalformedEmail: a malformed address in a data subject
// search or erasure, or in the email filter of the transfers, is refused
// with the pointer (or parameter name) of its field and the code
// invalid-email; display-name forms are never rewritten into an address.
// A missing address is reported as required.
func TestOperationsMalformedEmail(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		search, erase := tenantPath(o.tid, "/data-subjects/search"), tenantPath(o.tid, "/data-subjects/erase")
		for _, bad := range []string{"not an address", "Carol <carol@customer.example.net>", "carol@customer.example.net, dave@example.org"} {
			expectEmailError(t, o.sa.call(t, http.MethodPost, search, map[string]string{"email": bad}), "/email")
			expectEmailError(t, o.sa.eraseSubject(t, o.tid, bad), "/email")
			q := url.Values{"email": {bad}}
			expectEmailError(t, o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers?"+q.Encode()), nil), "email")
		}
		for _, path := range []string{search, erase} {
			p := expectFieldError(t, o.sa.call(t, http.MethodPost, path, map[string]string{}), "/email")
			if len(p.Errors) != 1 || p.Errors[0].Code != "required" {
				t.Errorf("%s without address: %+v, want required", path, p.Errors)
			}
		}
	})
}

// expectEmailError asserts a 400 validation-failed naming field with the
// code invalid-email.
func expectEmailError(t *testing.T, resp response, field string) {
	t.Helper()
	p := expectFieldError(t, resp, field)
	if !slices.ContainsFunc(p.Errors, func(e fieldErr) bool { return e.Field == field && e.Code == "invalid-email" }) {
		t.Errorf("errors = %s, want invalid-email on %s", resp.body, field)
	}
}
