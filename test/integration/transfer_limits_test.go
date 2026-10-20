package integration_test

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// externalSession invites a new external address from inviter and opens
// its session through the invitation link and the code mail.
func externalSession(t *testing.T, d *depositEnv, inviter *depositor) *depositor {
	t.Helper()
	guestEmail := uniqueEmail(t, "guest", externalDomain)
	if resp := inviter.invite(t, `{"email":"`+guestEmail+`"}`, inviter.withCSRF()); resp.status != http.StatusCreated {
		t.Fatalf("createInvitation: %d %s", resp.status, resp.body)
	}
	d.waitMailSent(t, guestEmail)
	m := invitationLinkRE.FindStringSubmatch(d.mp.only(t, guestEmail).Text)
	if m == nil {
		t.Fatal("no invitation link")
	}
	guest := &depositor{d: d, host: hostA, ip: outside}
	ch := expectChallenge(t, guest.start(t, guestEmail, m[1]), guestEmail)
	msg := d.mp.find(t, guestEmail, func(m mpMessage) bool { return strings.Contains(strings.ToLower(m.Subject), "code") })
	code := codeRE.FindStringSubmatch(msg.Text)
	if code == nil {
		t.Fatalf("no code in %s", msg.Text)
	}
	s, cookie := expectSession(t, guest.confirm(t, ch.ChallengeID, code[1]), guestEmail)
	guest.cookie, guest.csrf = cookie, s.CSRFToken
	return guest
}

// TestTransferOpenCap covers the per-sender cap on unfinished transfers: an
// invited external depositor may have 3 open (uploading) transfers; the 4th
// gets 429 rate-limited with Retry-After, and finalizing or canceling one
// frees a slot.
func TestTransferOpenCap(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		inviter, _ := internalSession(t, d, "inviter")
		guest := externalSession(t, d, inviter)

		// Empty files are complete at creation: the transfers can be
		// finalized at once.
		var open []string
		for i := range 3 {
			open = append(open, guest.mustCreate(t, oneFile(fmt.Sprintf("empty-%d.txt", i), 0)).ID)
		}
		expectCapped := func(what string) {
			t.Helper()
			resp := guest.createTransfer(t, oneFile("one-too-many.txt", 0), "")
			p := expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
			if resp.header.Get(hdrRetryAfter) != "3600" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
				t.Errorf("%s: Retry-After = %q, retryAfterSeconds = %v, want 3600", what, resp.header.Get(hdrRetryAfter), p.RetryAfterSeconds)
			}
		}
		expectCapped("4th open transfer")

		// Finalizing frees a slot.
		if resp := guest.finalize(t, open[0]); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		open = append(open[1:], guest.mustCreate(t, oneFile("after-finalize.txt", 0)).ID)
		expectCapped("after the slot freed by the finalization was used")

		// Canceling frees a slot.
		if resp := guest.cancelTransfer(t, open[0]); resp.status != http.StatusNoContent {
			t.Fatalf("cancel: %d %s", resp.status, resp.body)
		}
		guest.mustCreate(t, oneFile("after-cancel.txt", 0))
		expectCapped("after the slot freed by the cancellation was used")

		// The cap is per sender: the inviter still creates.
		inviter.mustCreate(t, oneFile("inviter.txt", 0))
	})
}

// TestTransferIdempotencyMismatch covers an Idempotency-Key replayed with a
// different body: 409 state-conflict, and no second transfer.
func TestTransferIdempotencyMismatch(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		const key = "mismatch-key-0001" // gitleaks:allow (an Idempotency-Key, not a secret)
		first := alice.createTransfer(t, oneFile("report.csv", 10), key)
		if first.status != http.StatusCreated {
			t.Fatalf("create: %d %s", first.status, first.body)
		}
		other := oneFile("report.csv", 10)
		other.Message = "changed"
		expectProblem(t, alice.createTransfer(t, other, key), http.StatusConflict, "state-conflict")
		// The same body still replays the transfer.
		replay := alice.createTransfer(t, oneFile("report.csv", 10), key)
		if replay.status != http.StatusCreated || parseTransfer(t, replay.body).ID != parseTransfer(t, first.body).ID {
			t.Errorf("replay: %d %s", replay.status, replay.body)
		}
	})
}

// TestUploadActivityAcrossFiles covers the expiry of the uploads of a
// transfer, counted from the latest activity of any of its files: a second
// file that starts after the creation time plus the upload TTL is still
// accepted while the first one was active recently, and both expire once
// every file has been idle for the TTL.
func TestUploadActivityAcrossFiles(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{env: map[string]string{config.EnvUploadTTL: "1h"}}, true)
		alice, _ := internalSession(t, d, "alice")
		req := oneFile("first.bin", 1000)
		req.Files = append(req.Files, fileDecl{Name: "second.bin", Size: 1000})
		tr := alice.mustCreate(t, req)
		first, second := tr.Files[0].UploadURL, tr.Files[1].UploadURL

		// Recent activity on the first file, then the creation moved more
		// than the TTL into the past.
		alice.mustPatch(t, first, 0, make([]byte, 300))
		execSystem(t, e, fmt.Sprintf(`UPDATE transfers SET created_at = created_at - %d WHERE id = '%s'`,
			(61*time.Minute).Milliseconds(), tr.ID))

		// The second file starts now: accepted thanks to the first one.
		h := alice.head(t, second)
		if h.status != http.StatusOK {
			t.Fatalf("HEAD of the second file: %d", h.status)
		}
		exp, err := http.ParseTime(h.header.Get(hdrUploadExpires))
		if err != nil || exp.Before(time.Now().Add(59*time.Minute)) {
			t.Errorf("Upload-Expires of the second file = %q, want about one hour ahead", h.header.Get(hdrUploadExpires))
		}
		alice.mustPatch(t, second, 0, make([]byte, 200))

		// Every file idle for the TTL: both expire.
		past := time.Now().Add(-61 * time.Minute)
		for _, f := range tr.Files {
			row := d.fileRow(t, tr.ID, f.ID)
			if err := os.Chtimes(d.ckptPath(row.StorageName), past, past); err != nil {
				t.Fatal(err)
			}
		}
		expectTusError(t, "HEAD of the first file", alice.head(t, first), http.StatusGone)
		expectTusError(t, "PATCH of the second file", alice.patch(t, second, 200, make([]byte, 10)), http.StatusGone)
	})
}
