package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Integration tests of the end-to-end encrypted transfers (V2 step 7;
// docs/architecture/e2e-format.md; api/openapi.yaml createTransfer,
// appendUploadChunk, getDownload, downloadFile, downloadArchive; threat
// model 6.53, T-318 to T-327). The browser is played by internal/tte2.

// e2eFiles are the two files of the journey: one of several 64 KiB chunks in
// a folder, one small.
func e2eFiles(t *testing.T) []e2ePlain {
	t.Helper()
	return []e2ePlain{
		{name: "report-q3.pdf", path: "docs/finance", mediaType: "application/pdf", content: seededBytes(t, 7, 3*(64<<10)+777), chunk: 64 << 10},
		{name: "notes-confidential.txt", mediaType: "text/plain", content: []byte("small secret notes")},
	}
}

// uploadWithCuts uploads the ciphertext of the file 0 of s the way a flaky
// client would: slices cut inside the 32-byte header, a connection cut in the
// middle of a request, then the resume from the offset the server reports.
func uploadWithCuts(t *testing.T, c *depositor, trfID, url string, ct []byte) {
	t.Helper()
	n := int64(len(ct))
	if off, length := c.offsetOf(t, url); off != 0 || length != n {
		t.Fatalf("fresh upload: offset %d length %d, want 0 and %d", off, length, n)
	}
	// Two cuts inside the header: the server keeps the validator state of the
	// header prefix in its checkpoint and resumes it.
	c.mustPatch(t, url, 0, ct[:10])
	if off, _ := c.offsetOf(t, url); off != 10 {
		t.Fatalf("offset after 10 bytes = %d", off)
	}
	c.mustPatch(t, url, 10, ct[10:20])
	if off, _ := c.offsetOf(t, url); off != 20 {
		t.Fatalf("offset after 20 bytes = %d", off)
	}
	c.mustPatch(t, url, 20, ct[20:5000])
	// A cut in the middle of a request, past the header.
	conn := c.rawPatch(t, url, 5000, n-5000)
	if _, err := conn.Write(ct[5000:70000]); err != nil {
		t.Fatalf("write the partial body: %v", err)
	}
	_ = conn.Close()
	c.waitUnlocked(t, trfID)
	off, length := c.offsetOf(t, url)
	if off < 5000 || off > 70000 || length != n {
		t.Fatalf("offset after the cut = %d (length %d), want within [5000, 70000] of %d", off, length, n)
	}
	c.mustPatch(t, url, off, ct[off:])
	if off, _ := c.offsetOf(t, url); off != n {
		t.Fatalf("offset after the resume = %d, want %d", off, n)
	}
}

// runE2EJourney runs a whole encrypted transfer, with an optional transfer
// password, and returns the sender session and the transfer.
func runE2EJourney(t *testing.T, o *opsEnv, password string) {
	t.Helper()
	alice, aliceMail := internalSession(t, o.depositEnv, "alice")
	rcpt := uniqueEmail(t, "carol", "example.net")
	const message = "Quarterly figures: the acquisition plan is confidential"
	set := newE2ESet(t, message, e2eFiles(t)...)
	req := set.create(rcpt)
	if password != "" {
		req.Password = &password
	}

	// Creation: the answer carries the generic names, the sealed metadata and
	// the sealed message, and no plaintext message.
	resp := alice.createTransfer(t, req, "")
	if resp.status != http.StatusCreated {
		t.Fatalf("createTransfer: %d %s", resp.status, resp.body)
	}
	expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)
	tr := parseTransfer(t, resp.body)
	if !tr.EndToEndEncrypted || tr.EncryptedMessage != set.sealMsg || tr.Message != "" || len(tr.Files) != 2 {
		t.Fatalf("created transfer = %s", resp.body)
	}
	for i, f := range tr.Files {
		if f.Name != e2eName(i) || f.EncryptedMetadata != set.sealed[i] || f.MediaType != "" || f.Size != int64(len(set.cipher[i])) {
			t.Errorf("created file %d = %+v, want %s sealed %s", i, f, e2eName(i), set.sealed[i])
		}
	}

	// Upload: file 1 cut inside its header, file 0 cut inside its header and
	// in the middle of a request.
	url1 := tr.Files[1].UploadURL
	alice.mustPatch(t, url1, 0, set.cipher[1][:31])
	if off, _ := alice.offsetOf(t, url1); off != 31 {
		t.Fatalf("offset after 31 bytes = %d", off)
	}
	alice.mustPatch(t, url1, 31, set.cipher[1][31:])
	uploadWithCuts(t, alice, tr.ID, tr.Files[0].UploadURL, set.cipher[0])

	// Finalization: no antivirus, the transfer is available.
	finPath := pathTransfers + "/" + tr.ID + "/finalize"
	fin := mustStatus(t, "finalizeTransfer", alice.finalize(t, tr.ID), http.StatusAccepted)
	expectContract(t, "finalizeTransfer", http.MethodPost, finPath, fin)
	got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
	token := tokenOf(t, hostA, got.DownloadURL)
	o.secret(token, set.keyB64)
	view := alice.getTransfer(t, tr.ID)
	expectContract(t, "getTransfer", http.MethodGet, pathTransfers+"/"+tr.ID, view)
	sender := parseTransfer(t, view.body)
	if !sender.EndToEndEncrypted || sender.EncryptedMessage != set.sealMsg {
		t.Errorf("sender view = %s", view.body)
	}
	rows := o.files(t, tr.ID)
	for i, f := range sender.Files {
		if f.ScanStatus != scanE2E || rows[i].ScanStatus != store.ScanNotScannedE2E || rows[i].E2EMetadata != set.sealed[i] {
			t.Errorf("file %d: scan status %q (row %q), metadata %q", i, f.ScanStatus, rows[i].ScanStatus, rows[i].E2EMetadata)
		}
		// Encrypted again at rest by the server, over the ciphertext.
		if at := o.decrypt(t, rows[i]); !slices.Equal(at, set.cipher[i]) {
			t.Errorf("file %d at rest: %d bytes after the server layer, want the %d bytes of the ciphertext", i, len(at), len(set.cipher[i]))
		}
	}
	// The only scan the antivirus ever saw is the EICAR self-test of the
	// instance: never a byte of an encrypted file.
	for _, sc := range o.av.Scans() {
		if !bytes.Equal(sc.Data, antivirustest.EICAR()) {
			t.Errorf("the antivirus scanned %d bytes of an encrypted transfer, want none", len(sc.Data))
		}
	}
	created := false
	for _, r := range o.tenantAudit(t, o.tid) {
		if r.action == actTransferCreated && r.objectID == tr.ID {
			created = strings.Contains(r.details, `"endToEndEncrypted":true`) || strings.Contains(r.details, `"endToEndEncrypted": true`)
		}
	}
	if !created {
		t.Errorf("no transfer.created audit event of %s with endToEndEncrypted true", tr.ID)
	}

	// Mails: the recipient's carries neither the key, the message nor a
	// plaintext name, and tells the files are encrypted end to end.
	notif := o.mp.find(t, rcpt, func(mpMessage) bool { return true })
	expectNoE2ELeak(t, "the recipient mail", notif, set)
	if c := notif.Text + notif.HTML; !strings.Contains(c, "end-to-end encrypted") || !strings.Contains(c, token) {
		t.Errorf("the recipient mail lacks the encryption notice or the link:\n%s", notif.Text)
	}
	conf := o.mp.find(t, aliceMail, func(m mpMessage) bool { return strings.Contains(m.Subject, "Your files have been sent") })
	expectNoE2ELeak(t, "the sender confirmation", conf, set)
	if !strings.Contains(conf.Text+conf.HTML, "end-to-end encrypted") {
		t.Errorf("the sender confirmation lacks the encryption notice:\n%s", conf.Text)
	}
	o.mailBarrier(t, alice)
	for _, m := range o.mp.messagesTo(t, aliceMail) {
		full := o.mp.find(t, aliceMail, func(x mpMessage) bool { return x.ID == m.ID })
		expectNoE2ELeak(t, "the mail "+m.Subject, full, set)
	}

	// The public view.
	rc := o.newRecipient(1)
	if password != "" {
		locked := rc.page(t, token)
		expectContract(t, "getDownload", http.MethodGet, pagePath(token), locked)
		if p := parsePage(t, locked); !p.Locked {
			t.Fatalf("the page of a protected transfer is not locked: %s", locked.body)
		}
		// The archive is refused by the password gate before the E2E rule.
		expectProblem(t, rc.get(t, archivePath(token), nil), http.StatusUnauthorized, "download-locked")
		expectContract(t, "unlockDownload", http.MethodPost, unlockPath(token), rc.unlock(t, token, password, nil))
	}
	pageResp := rc.page(t, token)
	expectContract(t, "getDownload", http.MethodGet, pagePath(token), pageResp)
	page := parsePage(t, pageResp)
	if !page.EndToEndEncrypted || page.EncryptedMessage != set.sealMsg || page.Message != nil || page.ArchiveURL != nil ||
		len(page.Files) != 2 || page.Locked {
		t.Fatalf("public view = %s", pageResp.body)
	}
	if text, err := tte2.OpenMessage(set.key, page.EncryptedMessage); err != nil || text != message {
		t.Errorf("the sealed message opens to %q (%v), want %q", text, err, message)
	}
	for i, f := range page.Files {
		if f.Name != e2eName(i) || f.EncryptedMetadata != set.sealed[i] || f.Sha256 != sha256Hex(set.cipher[i]) ||
			f.ScanStatus != scanE2E || f.Size != int64(len(set.cipher[i])) || f.MediaType != "" {
			t.Errorf("public file %d = %+v", i, f)
		}
	}

	// The ciphertext is served as is, a range too, then decrypted locally.
	for i, f := range page.Files {
		path := filePath(token, f.ID)
		file := rc.get(t, path, nil)
		expectFile(t, "download "+f.Name, file, e2eName(i), set.cipher[i])
		set.decrypt(t, i, file.body, f.EncryptedMetadata)
	}
	expectPartial(t, "range of the big file", rc.getRange(t, filePath(token, page.Files[0].ID), "bytes=40-99"),
		e2eName(0), set.cipher[0], 40, 99)

	// No server archive.
	arch := rc.get(t, archivePath(token), nil)
	expectProblem(t, arch, http.StatusConflict, codeE2EArchiveUnavail)
	expectContract(t, "downloadArchive", http.MethodGet, archivePath(token), arch)

	// The proof of deposit tells the transfer is encrypted, with the generic
	// names and the hashes of the ciphertext.
	keys := o.proofKeys(t, hostA)
	me := o.meSessionOf(t, aliceMail)
	pp := pathMeTransfers + tr.ID + "/proof?kind=deposit"
	prf := o.do(t, request{method: http.MethodGet, path: pp, host: hostA, headers: me})
	expectContract(t, "getMyTransferProof", http.MethodGet, pp, prf)
	st := expectProofPDF(t, "deposit proof", prf, keys)
	if !st.EndToEndEncrypted || len(st.Files) != 2 {
		t.Fatalf("deposit statement = %+v, want an end-to-end encrypted transfer of two files", st)
	}
	for i, f := range st.Files {
		if f.Name != e2eName(i) || f.SHA256 != sha256Hex(set.cipher[i]) || f.Size != int64(len(set.cipher[i])) {
			t.Errorf("statement file %d = %+v", i, f)
		}
	}
	if strings.Contains(string(prf.body), "report-q3") {
		t.Errorf("the proof carries a plaintext name")
	}
	noSecretInLogs(t, o.server, token, set.keyB64, set.sealMsg)
}

// TestE2EFullJourney: an internal sender encrypts two files and a message
// with the reference implementation, uploads them by tus cut inside the
// header and in the middle of a request, and the recipient downloads and
// decrypts them; with and without a transfer password.
func TestE2EFullJourney(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.setE2EPolicy(t, "allowed")
		t.Run("no password", func(t *testing.T) { runE2EJourney(t, o, "") })
		t.Run("with a transfer password", func(t *testing.T) { runE2EJourney(t, o, "correct horse battery staple") })
	})
}

// TestE2EMalformedUploads: the server checks the framing of an encrypted
// upload while streaming. A plaintext declared as ciphertext, or a header
// inconsistent with the declared size, is refused with 400
// e2e-format-invalid before anything is written, the bytes accepted before
// are kept, and a corrected resume succeeds.
func TestE2EMalformedUploads(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.setE2EPolicy(t, "allowed")
		alice, _ := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "carol", "example.net")

		// File 0: 65544 bytes in 128 KiB chunks make 65592 bytes of stream,
		// which is no stream size for 64 KiB chunks (32 + 65552 + 8). File 1:
		// a plaintext declared as the ciphertext of a small file.
		big := e2ePlain{name: "wide.bin", content: seededBytes(t, 3, 65544), chunk: 128 << 10}
		small := e2ePlain{name: "small.txt", content: []byte("a small file in a proper stream")}
		set := newE2ESet(t, "", big, small)
		if n := len(set.cipher[0]); n != 65592 {
			t.Fatalf("test setup: stream of %d bytes, want 65592", n)
		}
		resp := alice.createTransfer(t, set.create(rcpt), "")
		expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)
		tr := parseTransfer(t, resp.body)
		wideURL, smallURL := tr.Files[0].UploadURL, tr.Files[1].UploadURL
		refused := func(what, url string, off int64, data []byte) {
			t.Helper()
			r := alice.patch(t, url, off, data)
			expectTusProblem(t, what, r)
			expectContract(t, "appendUploadChunk", http.MethodPatch, url, r)
			if got, _ := alice.offsetOf(t, url); got != off {
				t.Errorf("%s: offset %d after the refused slice, want %d (nothing of it written)", what, got, off)
			}
		}

		// A plaintext: refused at the first PATCH, offset 0.
		plaintext := []byte(strings.Repeat("this is plain text, not a TTE2 stream. ", 4))[:len(set.cipher[1])]
		refused("plaintext", smallURL, 0, plaintext)
		if r := alice.finalize(t, tr.ID); r.status != http.StatusConflict {
			t.Errorf("finalize with refused uploads: %d %s, want 409", r.status, r.body)
		}

		// A valid header of 64 KiB chunks, inconsistent with the declared size:
		// the four bytes already accepted stay, the slice that carries the
		// chunk size is refused, and the corrected bytes resume.
		var badHeader []byte
		{
			other := encryptFile(t, set.key, 0, e2ePlain{content: []byte("x"), chunk: 64 << 10})
			badHeader = other[:32]
		}
		refused("header with a wrong chunk size at once", wideURL, 0, badHeader)
		alice.mustPatch(t, wideURL, 0, set.cipher[0][:4])
		refused("header with a wrong chunk size after a good prefix", wideURL, 4, badHeader[4:])
		alice.mustPatch(t, wideURL, 4, set.cipher[0][4:])

		// A corrected resume of the plaintext upload. A byte beyond the declared
		// size is discarded with 413 as for any upload (the declared bytes are
		// kept and complete the file).
		if off, _ := alice.offsetOf(t, smallURL); off != 0 {
			t.Fatalf("offset after the refused plaintext = %d", off)
		}
		over := alice.patch(t, smallURL, 0, append(slices.Clone(set.cipher[1]), 0))
		if over.status != http.StatusRequestEntityTooLarge {
			t.Fatalf("a byte beyond the declared size: %d %s, want 413", over.status, over.body)
		}
		if off, length := alice.offsetOf(t, smallURL); off != length || length != int64(len(set.cipher[1])) {
			t.Fatalf("offset after the overflow = %d of %d, want the declared bytes kept", off, length)
		}
		alice.mustPatch(t, smallURL, int64(len(set.cipher[1])), nil) // the empty PATCH that completes it

		alice.mustFinalize(t, tr.ID)
		got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
		token := tokenOf(t, hostA, got.DownloadURL)
		o.secret(token)
		rc := o.newRecipient(1)
		page := rc.mustPage(t, token)
		for i, f := range page.Files {
			file := rc.get(t, filePath(token, f.ID), nil)
			expectFile(t, "download "+f.Name, file, e2eName(i), set.cipher[i])
			set.decrypt(t, i, file.body, f.EncryptedMetadata)
		}
	})
}

// TestE2ECreateValidation: the creation rules of an encrypted transfer are
// enforced with 400 validation-failed.
func TestE2ECreateValidation(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.setE2EPolicy(t, "allowed")
		alice, _ := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "carol", "example.net")
		set := newE2ESet(t, "", e2ePlain{name: "a.txt", content: []byte("aaaa")}, e2ePlain{name: "b.txt", content: []byte("bbbb")})
		cases := map[string]func(r *transferCreate){
			"a missing metadata":      func(r *transferCreate) { r.Files[1].EncryptedMetadata = "" },
			"a plaintext name":        func(r *transferCreate) { r.Files[0].Name = "a.txt" },
			"names out of order":      func(r *transferCreate) { r.Files[0].Name, r.Files[1].Name = r.Files[1].Name, r.Files[0].Name },
			"a media type":            func(r *transferCreate) { r.Files[0].MediaType = "text/plain" },
			"a size below the header": func(r *transferCreate) { r.Files[0].Size = 47 },
			"a plaintext message":     func(r *transferCreate) { r.Message = "hello" },
		}
		for name, mutate := range cases {
			req := set.create(rcpt)
			req.Files = slices.Clone(req.Files)
			mutate(&req)
			resp := alice.createTransfer(t, req, "")
			expectTransferProblem(t, resp, http.StatusBadRequest, "validation-failed")
			expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)
			_ = name
		}
		// Metadata without the encrypted flag is refused as well.
		req := set.create(rcpt)
		req.EndToEndEncrypted = false
		expectTransferProblem(t, alice.createTransfer(t, req, ""), http.StatusBadRequest, "validation-failed")
		// And the valid one is accepted.
		alice.mustCreate(t, set.create(rcpt))
	})
}

// TestE2EPolicyMatrix: the tenant policy and the level policy decide, as
// tenant.EffectiveE2EPolicy, whether an encrypted (403 e2e-forbidden) or a
// plaintext (400 e2e-required) transfer is created, and the public tenant
// announces the effective policy of every level.
func TestE2EPolicyMatrix(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, _ := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "carol", "example.net")
		set := newE2ESet(t, "", e2ePlain{name: "a.txt", content: []byte("matrix")})
		levelRules := []struct {
			key, rule string
			ptr       *tenant.E2EPolicy
		}{
			{"lvlnull", "null", nil},
			{"lvlforbidden", "forbidden", new(tenant.E2EForbidden)},
			{"lvlallowed", "allowed", new(tenant.E2EAllowed)},
			{"lvlrequired", "required", new(tenant.E2ERequired)},
		}
		var items []string
		for i, l := range levelRules {
			items = append(items, levelJSON(l.key, i == 0, l.rule))
		}
		mustStatus(t, "levels", putLevels(t, o.sa, o.tid, items...), http.StatusOK)

		// want[tenant][level] is the effective policy, spelled out.
		want := map[string]map[string]string{
			"forbidden": {"lvlnull": "forbidden", "lvlforbidden": "forbidden", "lvlallowed": "forbidden", "lvlrequired": "forbidden"},
			"allowed":   {"lvlnull": "allowed", "lvlforbidden": "forbidden", "lvlallowed": "allowed", "lvlrequired": "required"},
			"required":  {"lvlnull": "required", "lvlforbidden": "required", "lvlallowed": "required", "lvlrequired": "required"},
		}
		for _, tp := range []string{"forbidden", "allowed", "required"} {
			o.setE2EPolicy(t, tp)
			pub := o.publicTenantRaw(t)
			if pub.Features.E2EPolicy != tp {
				t.Errorf("tenant policy %s: features.e2ePolicy = %q", tp, pub.Features.E2EPolicy)
			}
			for _, l := range levelRules {
				eff := want[tp][l.key]
				if got := tenant.EffectiveE2EPolicy(tenant.E2EPolicy(tp), l.ptr); string(got) != eff {
					t.Fatalf("tenant.EffectiveE2EPolicy(%s, %s) = %s, the matrix says %s", tp, l.rule, got, eff)
				}
				var announced string
				for _, pl := range pub.Levels {
					if pl.Key == l.key {
						announced = pl.E2EPolicy
					}
				}
				if announced != eff {
					t.Errorf("tenant %s level %s: public e2ePolicy %q, want %q", tp, l.key, announced, eff)
				}
				for _, encrypted := range []bool{true, false} {
					var req transferCreate
					if encrypted {
						req = set.create(rcpt)
						req.ConfidentialityLevel = l.key
					} else {
						req = plainRequest(l.key, rcpt)
					}
					resp := alice.createTransfer(t, req, "")
					expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)
					switch {
					case encrypted && eff == "forbidden":
						expectTransferProblem(t, resp, http.StatusForbidden, codeE2EForbidden)
					case !encrypted && eff == "required":
						expectTransferProblem(t, resp, http.StatusBadRequest, codeE2ERequired)
					default:
						if resp.status != http.StatusCreated {
							t.Errorf("tenant %s level %s encrypted=%t: %d %s, want 201", tp, l.key, encrypted, resp.status, resp.body)
							continue
						}
						if got := parseTransfer(t, resp.body); got.EndToEndEncrypted != encrypted {
							t.Errorf("tenant %s level %s: endToEndEncrypted %t, want %t", tp, l.key, got.EndToEndEncrypted, encrypted)
						} else if r := alice.cancelTransfer(t, got.ID); r.status != http.StatusNoContent {
							t.Errorf("cancel %s: %d %s", got.ID, r.status, r.body)
						}
					}
				}
			}
		}
	})
}

// publicTenantE2E is the part of getPublicTenant about the policies.
type publicTenantE2E struct {
	Features struct {
		E2EPolicy string `json:"e2ePolicy"`
	} `json:"features"`
	Levels []struct {
		Key       string `json:"key"`
		E2EPolicy string `json:"e2ePolicy"`
	} `json:"confidentialityLevels"`
}

// publicTenantRaw reads getPublicTenant of tenant A, checks its contract and
// decodes the policies.
func (o *opsEnv) publicTenantRaw(t *testing.T) publicTenantE2E {
	t.Helper()
	resp := mustStatus(t, "getPublicTenant", o.get(t, hostA, pathPublicTenant), http.StatusOK)
	expectContract(t, "getPublicTenant", http.MethodGet, pathPublicTenant, resp)
	var p publicTenantE2E
	mustJSON(t, resp.body, &p)
	return p
}

// TestE2EDepositors: an API token can encrypt, an invited external can, a
// drop link depositor cannot (403 e2e-forbidden, and 400 e2e-required for a
// plaintext deposit under a required policy).
func TestE2EDepositors(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, _ := internalSession(t, o.depositEnv, "alice")
		rcpt := uniqueEmail(t, "carol", "example.net")
		set := newE2ESet(t, "", e2ePlain{name: "a.txt", content: []byte("depositors")})

		// A drop link and its session exist before the policy changes.
		dl := o.createDropLink(t, "Accounting", "", uniqueEmail(t, "accounting", domainA))
		dropper, _ := o.dropSession(t, dl.Token, uniqueEmail(t, "supplier", externalDomain), 1)
		guest := uniqueEmail(t, "guest", externalDomain)
		_, invitation := alice.inviteAndLink(t, guest)
		o.secret(invitation)
		external := o.invitedSession(t, guest, invitation, 1)
		_, secret := o.sa.createToken(t, o.tid, "Script", []string{"0.0.0.0/0", "::/0"}, nil)
		script := o.scriptClient(secret, "198.51.100.77")

		// Forbidden by default.
		forbidden := alice.createTransfer(t, set.create(rcpt), "")
		expectTransferProblem(t, forbidden, http.StatusForbidden, codeE2EForbidden)
		expectContract(t, "createTransfer", http.MethodPost, pathTransfers, forbidden)

		o.setE2EPolicy(t, "allowed")
		tr := script.mustTokenCreate(t, uniqueEmail(t, "erp", domainA), set.create(rcpt))
		if !tr.EndToEndEncrypted {
			t.Errorf("API token transfer = %+v, want an encrypted transfer", tr)
		}
		if r := script.tokenCancel(t, tr.ID); r.status != http.StatusNoContent {
			t.Errorf("cancel the token transfer: %d %s", r.status, r.body)
		}
		ext := external.mustCreate(t, set.create())
		if !ext.EndToEndEncrypted {
			t.Errorf("invited external transfer = %+v, want an encrypted transfer", ext)
		}

		// The drop link depositor cannot encrypt.
		req := set.create()
		req.noRecipients = true
		req.ExpiryDays = dl.ValidityDays
		resp := dropper.createTransfer(t, req, "")
		expectTransferProblem(t, resp, http.StatusForbidden, codeE2EForbidden)
		expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)

		// Under a required policy a plaintext drop deposit is refused: the
		// depositor cannot satisfy it.
		o.setE2EPolicy(t, "required")
		plain := transferCreate{ExpiryDays: dl.ValidityDays, noRecipients: true, Files: []fileDecl{{Name: "a.txt", Size: 5}}}
		resp = dropper.createTransfer(t, plain, "")
		expectTransferProblem(t, resp, http.StatusBadRequest, codeE2ERequired)
		expectContract(t, "createTransfer", http.MethodPost, pathTransfers, resp)
		resp = dropper.createTransfer(t, req, "")
		expectTransferProblem(t, resp, http.StatusForbidden, codeE2EForbidden)
	})
}

// TestE2EPolicyAdministration: the tenant policy is for the super admin only
// (403 for a delegated admin, 404 outside their scope, an audit event for
// the super admin), a delegated admin sets the policy of a level, which can
// only tighten, and the configuration export and import carry the policies.
func TestE2EPolicyAdministration(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		tidB := string(o.tenantB.ID)
		deleg := o.sa.createDelegatedOf(t, "delegate-e2e", o.tid, domainA, adminIP(40))
		body := `{"e2ePolicy":"allowed"}`

		resp := deleg.mergePatch(t, tenantPath(o.tid, ""), body)
		expectProblem(t, resp, http.StatusForbidden, "forbidden")
		expectContract(t, "updateTenant", http.MethodPatch, tenantPath(o.tid, ""), resp)
		resp = deleg.mergePatch(t, tenantPath(tidB, ""), body)
		expectProblem(t, resp, http.StatusNotFound, "not-found")
		expectContract(t, "updateTenant", http.MethodPatch, tenantPath(tidB, ""), resp)
		for _, bad := range []string{`{"e2ePolicy":"sometimes"}`, `{"e2ePolicy":null}`} {
			resp = o.sa.mergePatch(t, tenantPath(o.tid, ""), bad)
			expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
		}
		if got := o.publicTenantRaw(t).Features.E2EPolicy; got != "forbidden" {
			t.Fatalf("policy after the refused changes = %q, want forbidden", got)
		}

		o.setE2EPolicy(t, "allowed")
		var members string
		for _, r := range o.tenantAudit(t, o.tid) {
			if r.action == "tenant.updated" && strings.Contains(r.details, "e2ePolicy") {
				members = r.details
			}
		}
		if members == "" {
			t.Errorf("no tenant.updated audit event naming e2ePolicy: %v", o.tenantAudit(t, o.tid))
		}

		// The delegated admin sets the level policy; it only tightens.
		levels := []string{levelJSON("open", true, ""), levelJSON("sealed", false, "required"), levelJSON("plain", false, "forbidden")}
		lp := tenantPath(o.tid, "/confidentiality-levels")
		resp = putLevels(t, deleg, o.tid, levels...)
		mustStatus(t, "delegated levels", resp, http.StatusOK)
		expectContract(t, "updateConfidentialityLevels", http.MethodPut, lp, resp)
		if r := putLevels(t, deleg, tidB, levels...); r.status != http.StatusNotFound {
			t.Errorf("delegated admin levels of another tenant: %d %s, want 404", r.status, r.body)
		}
		pub := o.publicTenantRaw(t)
		got := map[string]string{}
		for _, l := range pub.Levels {
			got[l.Key] = l.E2EPolicy
		}
		if got["open"] != "allowed" || got["sealed"] != "required" || got["plain"] != "forbidden" {
			t.Errorf("effective level policies = %v", got)
		}
		// Back to forbidden: no level can loosen it.
		o.setE2EPolicy(t, "forbidden")
		for _, l := range o.publicTenantRaw(t).Levels {
			if l.E2EPolicy != "forbidden" {
				t.Errorf("level %s announces %q under a forbidden tenant", l.Key, l.E2EPolicy)
			}
		}
		o.setE2EPolicy(t, "required")

		// Export and import carry the policy of the tenant and of its levels.
		exp := mustStatus(t, "exportTenantConfig", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/export"), nil), http.StatusOK)
		expectContract(t, "exportTenantConfig", http.MethodGet, tenantPath(o.tid, "/export"), exp)
		var doc struct {
			Settings struct {
				E2EPolicy string `json:"e2ePolicy"`
			} `json:"settings"`
			Levels struct {
				Items []struct {
					Key   string `json:"key"`
					Rules struct {
						E2EPolicy *string `json:"e2ePolicy"`
					} `json:"rules"`
				} `json:"items"`
			} `json:"confidentialityLevels"`
		}
		mustJSON(t, exp.body, &doc)
		if doc.Settings.E2EPolicy != "required" {
			t.Errorf("exported e2ePolicy = %q, want required: %s", doc.Settings.E2EPolicy, exp.body)
		}
		exported := map[string]string{}
		for _, l := range doc.Levels.Items {
			if l.Rules.E2EPolicy != nil {
				exported[l.Key] = *l.Rules.E2EPolicy
			}
		}
		if exported["sealed"] != "required" || exported["plain"] != "forbidden" {
			t.Errorf("exported level policies = %v", exported)
		}
		imp := o.sa.send(t, http.MethodPost, pathImport,
			importBody("Entity E2E Imported", "transfer.entity-e2e.localhost", string(exp.body)), http.Header{hdrCSRF: {o.sa.csrf}})
		mustStatus(t, "importTenant", imp, http.StatusCreated)
		expectContract(t, "importTenant", http.MethodPost, pathImport, imp)
		var created struct {
			ID        string `json:"id"`
			E2EPolicy string `json:"e2ePolicy"`
		}
		mustJSON(t, imp.body, &created)
		if created.E2EPolicy != "required" {
			t.Errorf("imported tenant e2ePolicy = %q, want required: %s", created.E2EPolicy, imp.body)
		}
		lvl := mustStatus(t, "imported levels", o.sa.call(t, http.MethodGet, tenantPath(created.ID, "/confidentiality-levels"), nil), http.StatusOK)
		if !strings.Contains(string(lvl.body), `"e2ePolicy":"required"`) || !strings.Contains(string(lvl.body), `"e2ePolicy":"forbidden"`) {
			t.Errorf("imported levels lose their policies: %s", lvl.body)
		}
	})
}

// expectTusProblem asserts the 400 e2e-format-invalid answer of a tus PATCH:
// the one tus error that carries a Problem body (api/openapi.yaml
// appendUploadChunk). The checks after the status are not fatal, so that the
// rest of a flow still runs.
func expectTusProblem(t *testing.T, what string, resp response) {
	t.Helper()
	if resp.status != http.StatusBadRequest {
		t.Fatalf("%s: status %d, want 400; body %q", what, resp.status, resp.body)
	}
	expectTusHeaders(t, what, resp)
	if ct := resp.header.Get("Content-Type"); ct != contentProb {
		t.Errorf("%s: Content-Type %q, want %q", what, ct, contentProb)
	}
	var p problemBody
	if err := json.Unmarshal(resp.body, &p); err != nil {
		t.Errorf("%s: the body is not a Problem: %v; body %q", what, err, resp.body)
		return
	}
	if p.Code != codeE2EFormatInvalid || p.Status != http.StatusBadRequest {
		t.Errorf("%s: problem %q/%d, want %s/400", what, p.Code, p.Status, codeE2EFormatInvalid)
	}
}
