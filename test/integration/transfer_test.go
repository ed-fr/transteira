package integration_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the transfers (CLAUDE.md sections 8, 9, 15.2, 16.1
// and 20; api/openapi.yaml createTransfer, getTransfer, cancelTransfer,
// finalizeTransfer) against a real server, on both engines, with deposit
// sessions opened through Mailpit.

// plaintextMarker is a known plaintext that must never appear in an
// encrypted file on disk.
const plaintextMarker = "TRANSTEIRA-CLEAR-TEXT-MARKER;"

// TestTransferFullFlow covers the nominal flow: an internal session creates
// a transfer of three files (empty, small, 20 MiB) with a password, uploads
// them with tus in irregular chunks, finalizes it, and the files on disk
// decrypt to the originals while never containing the plaintext.
func TestTransferFullFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, aliceEmail := internalSession(t, d, "alice")

		small := bytes.Repeat([]byte(plaintextMarker), 4096/len(plaintextMarker)+1)[:4096+13]
		big := seededBytes(t, 1, 20<<20)
		contents := [][]byte{{}, small, big}
		password := "correct horse battery staple"
		rcpt1, rcpt2 := uniqueEmail(t, "Carol", "customer.example.net"), uniqueEmail(t, "dave", "customer.example.net")
		req := transferCreate{
			Recipients: []string{rcpt1, rcpt2}, Message: "Here are the plans.", ExpiryDays: 7,
			Password: &password, Language: "en",
			Files: []fileDecl{
				{Name: "empty.txt", Size: 0, MediaType: "text/plain"},
				{Name: "notes été.txt", Size: int64(len(small)), MediaType: "text/plain"},
				{Name: "site-survey.bin", Size: int64(len(big))},
			},
		}
		const idemKey = "full-flow-retry-1"
		before := time.Now()
		resp := alice.createTransfer(t, req, idemKey)
		if resp.status != http.StatusCreated {
			t.Fatalf("createTransfer: %d %s", resp.status, resp.body)
		}
		if ct := resp.header.Get("Content-Type"); ct != contentJSON {
			t.Errorf("Content-Type = %q", ct)
		}
		tr := parseTransfer(t, resp.body)
		if loc := resp.header.Get("Location"); loc != pathTransfers+"/"+tr.ID {
			t.Errorf("Location = %q, want %s/%s", loc, pathTransfers, tr.ID)
		}
		total := int64(len(small) + len(big))
		if tr.Status != "uploading" || tr.SenderEmail != aliceEmail || !slices.Equal(tr.Recipients, []string{strings.ToLower(rcpt1), rcpt2}) ||
			tr.Message != "Here are the plans." || tr.ExpiryDays != 7 || !tr.PasswordProtected || tr.DeleteAfterFirstDownload ||
			tr.TotalBytes != total || len(tr.Files) != 3 {
			t.Errorf("created transfer = %s", resp.body)
		}
		if tr.CreatedAt.Before(before.Add(-time.Second)) || tr.CreatedAt.After(time.Now().Add(time.Second)) {
			t.Errorf("createdAt = %s, want now", tr.CreatedAt)
		}
		if tr.UploadExpiresAt == nil || !tr.UploadExpiresAt.Equal(tr.CreatedAt.Add(24*time.Hour)) {
			t.Errorf("uploadExpiresAt = %v, want createdAt + TT_UPLOAD_TTL (24 h)", tr.UploadExpiresAt)
		}
		if tr.ExpiresAt != nil || tr.FinalizedAt != nil || tr.DownloadURL != "" {
			t.Errorf("a new transfer has expiresAt, finalizedAt or downloadUrl: %s", resp.body)
		}
		if strings.Contains(string(resp.body), password) {
			t.Error("the response contains the password")
		}
		for i, f := range tr.Files {
			decl := req.Files[i]
			if f.Name != decl.Name || f.Size != decl.Size || f.MediaType != decl.MediaType || f.ScanStatus != "pending" ||
				!strings.HasPrefix(f.UploadURL, pathUploads+"/upl_") || f.UploadOffset == nil {
				t.Errorf("file %d = %+v, want the declaration %+v, pending, an upl_ uploadUrl and an offset", i, f, decl)
				continue
			}
			if *f.UploadOffset != 0 {
				t.Errorf("file %d uploadOffset = %d, want 0", i, *f.UploadOffset)
			}
		}
		// The empty file is complete at creation: its hash is known and its
		// upload reports 0 of 0, without expiry.
		if tr.Files[0].Sha256 != emptySHA256 || tr.Files[1].Sha256 != "" || tr.Files[2].Sha256 != "" {
			t.Errorf("sha256 at creation = %q, %q, %q; want the empty hash for the empty file only",
				tr.Files[0].Sha256, tr.Files[1].Sha256, tr.Files[2].Sha256)
		}
		emptyHead := alice.head(t, tr.Files[0].UploadURL)
		if emptyHead.status != http.StatusOK || emptyHead.header.Get(hdrUploadOffset) != "0" ||
			emptyHead.header.Get(hdrUploadLength) != "0" || emptyHead.header.Get(hdrUploadExpires) != "" {
			t.Errorf("HEAD of the empty file: %d %v, want 200, offset 0, length 0, no Upload-Expires", emptyHead.status, emptyHead.header)
		}
		// The password is stored as an argon2id hash only.
		stored, err := d.db.Transfers().Get(context.Background(), d.tenantA.ID, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(stored.PasswordHash, "$argon2id$") || strings.Contains(stored.PasswordHash, password) {
			t.Errorf("stored password hash %q, want an argon2id PHC string", stored.PasswordHash)
		}

		// The small file in one PATCH; the big one in irregular chunks
		// with a HEAD (and a getTransfer) between them.
		alice.upload(t, tr.Files[1].UploadURL, small)
		rng := rand.New(rand.NewPCG(7, 11))
		url := tr.Files[2].UploadURL
		var sent int64
		for chunk := 0; sent < int64(len(big)); chunk++ {
			n := min(int64(1+rng.IntN(3<<20)), int64(len(big))-sent)
			alice.mustPatch(t, url, sent, big[sent:sent+n])
			sent += n
			if sent == int64(len(big)) {
				break
			}
			off, length := alice.offsetOf(t, url)
			if off != sent || length != int64(len(big)) {
				t.Fatalf("HEAD after chunk %d = %d/%d, want %d/%d", chunk, off, length, sent, len(big))
			}
			h := alice.head(t, url)
			exp, err := http.ParseTime(h.header.Get(hdrUploadExpires))
			if err != nil || exp.Before(time.Now().Add(23*time.Hour)) {
				t.Errorf("Upload-Expires = %q (%v), want about 24 h ahead", h.header.Get(hdrUploadExpires), err)
			}
			if chunk == 1 {
				mid := alice.mustGet(t, tr.ID)
				if mid.Files[2].UploadOffset == nil || *mid.Files[2].UploadOffset != sent || *mid.Files[1].UploadOffset != int64(len(small)) {
					t.Errorf("getTransfer offsets during the upload = %v, %v; want %d, %d",
						mid.Files[2].UploadOffset, mid.Files[1].UploadOffset, sent, len(small))
				}
			}
		}
		if off, _ := alice.offsetOf(t, url); off != int64(len(big)) {
			t.Fatalf("final HEAD offset %d, want %d", off, len(big))
		}

		resp = alice.finalize(t, tr.ID)
		if resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		fin := parseTransfer(t, resp.body)
		if fin.Status != "scanning" || fin.FinalizedAt == nil || fin.ExpiresAt == nil ||
			!fin.ExpiresAt.Equal(fin.FinalizedAt.AddDate(0, 0, 7)) || fin.UploadExpiresAt != nil {
			t.Errorf("finalized transfer = %s, want scanning, finalizedAt, expiresAt 7 days later, no uploadExpiresAt", resp.body)
		}
		got := alice.mustGet(t, tr.ID)
		for i, f := range got.Files {
			if f.Sha256 != sha256Hex(contents[i]) {
				t.Errorf("file %d sha256 = %s, want %s (hash of the original)", i, f.Sha256, sha256Hex(contents[i]))
			}
			if f.UploadURL != "" || f.UploadOffset != nil {
				t.Errorf("file %d of a finalized transfer still has an uploadUrl", i)
			}
		}

		// On disk: one encrypted file per file, under a random name, which
		// decrypts with its data key to the original and never contains the
		// plaintext; no checkpoint is left.
		rows := d.files(t, tr.ID)
		entries, err := os.ReadDir(d.tenantDir())
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != len(rows) {
			t.Errorf("tenant directory holds %d entries, want %d encrypted files", len(entries), len(rows))
		}
		for i, f := range rows {
			if len(f.StorageName) != 32 || strings.Trim(f.StorageName, "0123456789abcdef") != "" {
				t.Errorf("storage name %q, want 32 random hex characters", f.StorageName)
			}
			if exists(t, d.ckptPath(f.StorageName)) {
				t.Errorf("file %d: checkpoint left after completion", i)
			}
			ct, err := os.ReadFile(d.encPath(f.StorageName))
			if err != nil {
				t.Fatal(err)
			}
			if len(ct) <= len(contents[i]) || bytes.Contains(ct, []byte(plaintextMarker)) {
				t.Errorf("file %d: %d bytes on disk for %d of plaintext, or the plaintext is readable", i, len(ct), len(contents[i]))
			}
			if len(contents[i]) >= 4096 && bytes.Contains(ct, contents[i][1024:1024+256]) {
				t.Errorf("file %d: a plaintext slice is readable on disk", i)
			}
			if f.CiphertextSize != int64(len(ct)) {
				t.Errorf("file %d: ciphertext size %d recorded, %d on disk", i, f.CiphertextSize, len(ct))
			}
			if !bytes.Equal(d.decrypt(t, f), contents[i]) {
				t.Errorf("file %d does not decrypt to the original", i)
			}
		}
		noSecretInLogs(t, d.server, password, alice.cookie, alice.csrf)
	})
}

// TestTransferLimits covers the per-transfer limit (413 transfer-too-large
// with maxTransferBytes) and the storage quota (507 quota-exceeded, a total
// exactly at the quota fits, a cancellation frees the quota): CLAUDE.md
// section 8.5, threat T-124.
func TestTransferLimits(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		two := func(a, b int64) transferCreate {
			req := oneFile("a.bin", a)
			req.Files = append(req.Files, fileDecl{Name: "b.bin", Size: b})
			return req
		}

		d.setLimits(t, 1000, 1<<40)
		p := expectTransferProblem(t, alice.createTransfer(t, two(600, 401), ""), http.StatusRequestEntityTooLarge, "transfer-too-large")
		if p.MaxTransferBytes == nil || *p.MaxTransferBytes != 1000 {
			t.Errorf("maxTransferBytes = %v, want 1000", p.MaxTransferBytes)
		}
		atLimit := alice.mustCreate(t, two(600, 400))
		if atLimit.TotalBytes != 1000 {
			t.Errorf("totalBytes = %d, want 1000", atLimit.TotalBytes)
		}

		// Quota 3000 with 1000 used.
		d.setLimits(t, 1<<30, 3000)
		big := alice.mustCreate(t, oneFile("big.bin", 1500))
		expectProblem(t, alice.createTransfer(t, oneFile("over.bin", 501), ""), http.StatusInsufficientStorage, "quota-exceeded")
		alice.mustCreate(t, oneFile("exact.bin", 500)) // 3000 of 3000: fits
		expectProblem(t, alice.createTransfer(t, oneFile("one.bin", 1), ""), http.StatusInsufficientStorage, "quota-exceeded")
		// A zero-byte transfer still fits a full quota.
		alice.mustCreate(t, oneFile("zero.bin", 0))

		if resp := alice.cancelTransfer(t, big.ID); resp.status != http.StatusNoContent {
			t.Fatalf("cancel: %d %s", resp.status, resp.body)
		}
		alice.mustCreate(t, oneFile("retry.bin", 1500))
		expectProblem(t, alice.createTransfer(t, oneFile("one.bin", 1), ""), http.StatusInsufficientStorage, "quota-exceeded")
	})
}

// TestTransferIdempotency covers the Idempotency-Key of createTransfer:
// a replay returns the same transfer without reserving the quota again, the
// key is scoped to the sender, and a malformed key is refused.
func TestTransferIdempotency(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		bob, _ := internalSession(t, d, "bob")
		d.setLimits(t, 1<<30, 1000)

		const key = "retry-key-0001"
		first := alice.createTransfer(t, oneFile("report.csv", 1000), key)
		if first.status != http.StatusCreated {
			t.Fatalf("first create: %d %s", first.status, first.body)
		}
		tr := parseTransfer(t, first.body)
		// The replay does not count against the (full) quota.
		replay := alice.createTransfer(t, oneFile("report.csv", 1000), key)
		if replay.status != http.StatusCreated {
			t.Fatalf("replay: %d %s", replay.status, replay.body)
		}
		again := parseTransfer(t, replay.body)
		if again.ID != tr.ID || again.Files[0].UploadURL != tr.Files[0].UploadURL ||
			replay.header.Get("Location") != pathTransfers+"/"+tr.ID {
			t.Errorf("replay = %s, want the transfer %s", replay.body, tr.ID)
		}
		// Same key, different body: 409 state-conflict (see also
		// TestTransferIdempotencyMismatch).
		other := oneFile("other.csv", 10)
		other.Message = "changed"
		expectProblem(t, alice.createTransfer(t, other, key), http.StatusConflict, "state-conflict")
		// The key is scoped to its sender: another sender with the same key
		// creates its own transfer (here refused by the full quota).
		expectProblem(t, bob.createTransfer(t, oneFile("report.csv", 1000), key), http.StatusInsufficientStorage, "quota-exceeded")
		d.setLimits(t, 1<<30, 1<<40)
		if b := parseTransfer(t, bob.createTransfer(t, oneFile("report.csv", 1000), key).body); b.ID == tr.ID {
			t.Error("another sender replaying the key got the first sender's transfer")
		}
		// Malformed keys.
		for _, bad := range []string{strings.Repeat("k", 65), "has space"} {
			p := expectTransferProblem(t, alice.createTransfer(t, oneFile("x.bin", 1), bad), http.StatusBadRequest, "validation-failed")
			if len(p.Errors) == 0 || p.Errors[0].Field != hdrIdempotency {
				t.Errorf("key %q: errors = %+v, want the Idempotency-Key field", bad, p.Errors)
			}
		}
	})
}

// TestTransferExternalDepositor covers an invited external depositor
// (CLAUDE.md section 9, threats T-17 and T-21): the recipients are forced
// to the inviter, the upload works, and neither another internal user nor
// the inviter can reach the uploads or the transfer.
func TestTransferExternalDepositor(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		inviter, inviterEmail := internalSession(t, d, "inviter")
		colleague, _ := internalSession(t, d, "colleague")
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

		data := seededBytes(t, 3, 300<<10)
		req := oneFile("scan.pdf", int64(len(data)))
		req.Recipients = []string{"someone-else@customer.example.net", "other@example.org"}
		tr := guest.mustCreate(t, req)
		if tr.SenderEmail != guestEmail || !slices.Equal(tr.Recipients, []string{inviterEmail}) {
			t.Errorf("external transfer sender %s recipients %v, want %s to [%s]", tr.SenderEmail, tr.Recipients, guestEmail, inviterEmail)
		}
		url := tr.Files[0].UploadURL
		guest.mustPatch(t, url, 0, data[:100<<10])

		// Neither the colleague nor the inviter (the recipient) can reach
		// the upload or the transfer: 404, as for an unknown resource.
		for name, other := range map[string]*depositor{"colleague": colleague, "inviter": inviter} {
			expectTusError(t, name+" HEAD", other.head(t, url), http.StatusNotFound)
			expectTusError(t, name+" PATCH", other.patch(t, url, 100<<10, data[100<<10:100<<10+10]), http.StatusNotFound)
			expectTusError(t, name+" DELETE", other.terminate(t, url), http.StatusNotFound)
			expectProblem(t, other.getTransfer(t, tr.ID), http.StatusNotFound, "not-found")
			expectProblem(t, other.cancelTransfer(t, tr.ID), http.StatusNotFound, "not-found")
			expectProblem(t, other.finalize(t, tr.ID), http.StatusNotFound, "not-found")
		}
		if off, _ := guest.offsetOf(t, url); off != 100<<10 {
			t.Errorf("offset after the foreign attempts = %d, want %d", off, 100<<10)
		}
		guest.mustPatch(t, url, 100<<10, data[100<<10:])
		if resp := guest.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("guest finalize: %d %s", resp.status, resp.body)
		}
		f := d.files(t, tr.ID)[0]
		if !bytes.Equal(d.decrypt(t, f), data) || f.SHA256 != sha256Hex(data) {
			t.Error("the external upload does not decrypt to the original")
		}
	})
}

// TestTransferEligibilityRecheck covers the eligibility checked again on
// createTransfer and finalizeTransfer (threat T-25): a session used from
// outside the internal ranges, and a sender blocklisted after the session
// started, get 403 deposit-not-allowed, written to the security log.
func TestTransferEligibilityRecheck(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, aliceEmail := internalSession(t, d, "alice")

		alice.ip = outside
		expectProblem(t, alice.createTransfer(t, oneFile("a.bin", 10), ""), http.StatusForbidden, "deposit-not-allowed")
		alice.ip = insideA

		tr := alice.mustCreate(t, oneFile("a.bin", 10))
		alice.upload(t, tr.Files[0].UploadURL, []byte("0123456789"))
		d.block(t, store.BlockEmail, aliceEmail)
		expectProblem(t, alice.createTransfer(t, oneFile("b.bin", 10), ""), http.StatusForbidden, "deposit-not-allowed")
		expectProblem(t, alice.finalize(t, tr.ID), http.StatusForbidden, "deposit-not-allowed")
		if got := alice.mustGet(t, tr.ID); got.Status != "uploading" {
			t.Errorf("status after the refused finalization = %s, want uploading", got.Status)
		}

		if got := strings.Join(reasons(t, d.server), ","); got != "ip,blocklist,blocklist" {
			t.Errorf("deposit_refused reasons = %s, want ip,blocklist,blocklist", got)
		}
		lines := eventsOf(t, d.securityLines(t), "deposit_refused")
		for i, want := range []string{outside, insideA, insideA} {
			if i < len(lines) && (lines[i].ip != want || lines[i].tenant != hostA) {
				t.Errorf("deposit_refused line %q, want ip=%s tenant=%s", lines[i].raw, want, hostA)
			}
		}
		for _, l := range lines {
			if strings.Contains(l.raw, aliceEmail) {
				t.Errorf("the security log contains the address: %q", l.raw)
			}
		}
	})
}

// TestTransferFinalizeErrors covers the errors of finalizeTransfer:
// incomplete files, checksum mismatch, blocklisted file hash (T-27),
// finalizing twice and a transfer emptied by tus terminations.
func TestTransferFinalizeErrors(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		a, b, c := seededBytes(t, 10, 100), seededBytes(t, 11, 200), seededBytes(t, 12, 300)
		req := oneFile("a.bin", int64(len(a)))
		req.Files[0].ExpectedSha256 = strings.ToUpper(sha256Hex(a)) // either case
		req.Files = append(req.Files,
			fileDecl{Name: "b.bin", Size: int64(len(b)), ExpectedSha256: sha256Hex([]byte("not b"))},
			fileDecl{Name: "c.bin", Size: int64(len(c))})
		tr := alice.mustCreate(t, req)
		alice.upload(t, tr.Files[0].UploadURL, a)
		alice.upload(t, tr.Files[1].UploadURL, b)
		alice.mustPatch(t, tr.Files[2].UploadURL, 0, c[:50])

		p := expectTransferProblem(t, alice.finalize(t, tr.ID), http.StatusConflict, "upload-incomplete")
		if !slices.Equal(p.Files, []string{tr.Files[2].ID}) {
			t.Errorf("upload-incomplete files = %v, want [%s]", p.Files, tr.Files[2].ID)
		}
		alice.mustPatch(t, tr.Files[2].UploadURL, 50, c[50:])
		p = expectTransferProblem(t, alice.finalize(t, tr.ID), http.StatusConflict, "checksum-mismatch")
		if !slices.Equal(p.Files, []string{tr.Files[1].ID}) {
			t.Errorf("checksum-mismatch files = %v, want [%s]", p.Files, tr.Files[1].ID)
		}
		if resp := alice.terminate(t, tr.Files[1].UploadURL); resp.status != http.StatusNoContent {
			t.Fatalf("terminate b: %d", resp.status)
		}

		entry := d.blockEntry(t, store.BlockSHA256, sha256Hex(c))
		expectProblem(t, alice.finalize(t, tr.ID), http.StatusForbidden, "blocked-file")
		if got := alice.mustGet(t, tr.ID); got.Status != "uploading" {
			t.Errorf("status after blocked-file = %s, want uploading", got.Status)
		}
		if got := reasons(t, d.server); !slices.Equal(got, []string{"blocklist"}) {
			t.Errorf("deposit_refused reasons = %v, want [blocklist]", got)
		}
		if err := d.db.Blocklist().Delete(context.Background(), d.tenantA.ID, entry); err != nil {
			t.Fatal(err)
		}

		resp := alice.finalize(t, tr.ID)
		if resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		if fin := parseTransfer(t, resp.body); len(fin.Files) != 2 || fin.TotalBytes != int64(len(a)+len(c)) {
			t.Errorf("finalized transfer = %s, want files a and c", resp.body)
		}
		expectProblem(t, alice.finalize(t, tr.ID), http.StatusConflict, "state-conflict")

		// A transfer whose uploads were all terminated has no file left.
		empty := alice.mustCreate(t, transferCreate{
			Recipients: []string{"r@customer.example.net"}, ExpiryDays: 1,
			Files: []fileDecl{{Name: "x.bin", Size: 5}, {Name: "y.bin", Size: 0}},
		})
		for _, f := range empty.Files {
			if resp := alice.terminate(t, f.UploadURL); resp.status != http.StatusNoContent {
				t.Fatalf("terminate: %d", resp.status)
			}
		}
		if got := alice.mustGet(t, empty.ID); len(got.Files) != 0 || got.TotalBytes != 0 || got.Status != "uploading" {
			t.Errorf("emptied transfer = %+v", got)
		}
		expectProblem(t, alice.finalize(t, empty.ID), http.StatusConflict, "state-conflict")
		if resp := alice.cancelTransfer(t, empty.ID); resp.status != http.StatusNoContent {
			t.Errorf("cancel the emptied transfer: %d %s", resp.status, resp.body)
		}
	})
}

// TestTransferCancelAndTerminate covers the deletions by the sender with
// crypto-erase (CLAUDE.md section 16.1, T-110): canceling a transfer
// removes its files and destroys their keys; terminating an upload removes
// that file and frees its quota; a finalized transfer can no longer be
// canceled nor its uploads touched.
func TestTransferCancelAndTerminate(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")

		// Cancel: a partial file (with a checkpoint), a complete one and an
		// empty one.
		req := oneFile("partial.bin", 1<<20)
		req.Files = append(req.Files, fileDecl{Name: "full.bin", Size: 2048}, fileDecl{Name: "empty.bin", Size: 0})
		tr := alice.mustCreate(t, req)
		alice.mustPatch(t, tr.Files[0].UploadURL, 0, seededBytes(t, 20, 300<<10))
		alice.upload(t, tr.Files[1].UploadURL, seededBytes(t, 21, 2048))
		rows := d.files(t, tr.ID)
		if !exists(t, d.ckptPath(rows[0].StorageName)) {
			t.Fatal("no checkpoint for the partial upload")
		}
		for _, f := range rows {
			if !exists(t, d.encPath(f.StorageName)) {
				t.Fatalf("file %s missing before the cancellation", f.ID)
			}
		}
		if resp := alice.cancelTransfer(t, tr.ID); resp.status != http.StatusNoContent || len(resp.body) != 0 {
			t.Fatalf("cancel: %d %s", resp.status, resp.body)
		}
		for _, f := range rows {
			d.expectKeyDestroyed(t, f.DEKKeyID)
			if exists(t, d.encPath(f.StorageName)) || exists(t, d.ckptPath(f.StorageName)) {
				t.Errorf("file %s left on disk after the cancellation", f.ID)
			}
		}
		if left := d.files(t, tr.ID); len(left) != 0 {
			t.Errorf("%d file rows left after the cancellation", len(left))
		}
		expectProblem(t, alice.getTransfer(t, tr.ID), http.StatusNotFound, "not-found")
		expectProblem(t, alice.cancelTransfer(t, tr.ID), http.StatusNotFound, "not-found")
		for _, f := range tr.Files {
			expectTusError(t, "HEAD after cancel", alice.head(t, f.UploadURL), http.StatusNotFound)
		}
		if entries, err := os.ReadDir(d.tenantDir()); err != nil || len(entries) != 0 {
			t.Errorf("tenant directory after the cancellation: %d entries, %v", len(entries), err)
		}

		// Terminate: the quota is exactly used; terminating one upload
		// frees its declared size.
		d.setLimits(t, 1<<30, 3000)
		two := oneFile("one.bin", 1000)
		two.Files = append(two.Files, fileDecl{Name: "two.bin", Size: 2000})
		tr = alice.mustCreate(t, two)
		expectProblem(t, alice.createTransfer(t, oneFile("more.bin", 1000), ""), http.StatusInsufficientStorage, "quota-exceeded")
		alice.mustPatch(t, tr.Files[0].UploadURL, 0, seededBytes(t, 22, 500))
		victim := d.fileRow(t, tr.ID, tr.Files[0].ID)
		resp := alice.terminate(t, tr.Files[0].UploadURL)
		if resp.status != http.StatusNoContent || len(resp.body) != 0 {
			t.Fatalf("terminate: %d %q", resp.status, resp.body)
		}
		expectTusHeaders(t, "DELETE", resp)
		d.expectKeyDestroyed(t, victim.DEKKeyID)
		if exists(t, d.encPath(victim.StorageName)) || exists(t, d.ckptPath(victim.StorageName)) {
			t.Error("the terminated upload left its files on disk")
		}
		expectTusError(t, "HEAD after terminate", alice.head(t, tr.Files[0].UploadURL), http.StatusNotFound)
		expectTusError(t, "DELETE again", alice.terminate(t, tr.Files[0].UploadURL), http.StatusNotFound)
		if got := alice.mustGet(t, tr.ID); len(got.Files) != 1 || got.Files[0].ID != tr.Files[1].ID || got.TotalBytes != 2000 {
			t.Errorf("transfer after terminate = %+v, want only two.bin, 2000 bytes", got)
		}
		alice.mustCreate(t, oneFile("more.bin", 1000))

		// After finalization the sender can no longer cancel the transfer
		// or touch its uploads; HEAD reports the completed file.
		data := seededBytes(t, 23, 2000)
		alice.upload(t, tr.Files[1].UploadURL, data)
		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		expectProblem(t, alice.cancelTransfer(t, tr.ID), http.StatusConflict, "state-conflict")
		expectTusError(t, "PATCH after finalize", alice.patch(t, tr.Files[1].UploadURL, 2000, nil), http.StatusConflict)
		expectTusError(t, "DELETE after finalize", alice.terminate(t, tr.Files[1].UploadURL), http.StatusConflict)
		if off, length := alice.offsetOf(t, tr.Files[1].UploadURL); off != 2000 || length != 2000 {
			t.Errorf("HEAD after finalize = %d/%d, want 2000/2000", off, length)
		}
		if f := d.fileRow(t, tr.ID, tr.Files[1].ID); !bytes.Equal(d.decrypt(t, f), data) {
			t.Error("the finalized file does not decrypt to the original")
		}
	})
}
