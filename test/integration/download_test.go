package integration_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the recipient side (CLAUDE.md section 10,
// api/openapi.yaml "Downloads", threat model T-47 to T-57, decisions P3,
// P4, P9 and P23): a real server, the fake clamd of antivirustest making the
// transfers available, Mailpit, on SQLite and PostgreSQL.

// TestDownloadFullFlow: the link of the recipient mail opens a page that
// lists the files (no transfer identifier); each file downloads
// byte-identical with the SHA-256 of the page and the forced-download
// headers; the archive reads back with archive/zip, with an exact
// Content-Length, the same names and contents, in store mode.
func TestDownloadFullFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, sender := internalSession(t, d, "alice")
		rcpt := uniqueEmail(t, "rcpt", "example.net")
		files := []uploadedFile{
			{"report.pdf", []byte("%PDF-1.7 quarterly report, page one")},
			{"data.bin", seededBytes(t, 21, 300_000)},
			{"notes.txt", []byte("meeting notes\n")},
		}
		tr, token := alice.availableTransfer(t, transferCreate{Recipients: []string{rcpt}, Message: "Files for the review"}, files...)

		// The link of the recipient mail is the one getTransfer shows.
		msg := d.mp.waitSubject(t, rcpt, wordings["en"].notificationSubject)
		if !strings.Contains(msg.text(), tr.DownloadURL) {
			t.Fatalf("the recipient mail lacks the link %s", tr.DownloadURL)
		}

		r := d.newRecipient(1)
		resp := r.page(t, token)
		p := parsePage(t, resp)
		expectPageFiles(t, p, token, tr, tr.Files)
		if p.PasswordProtected || p.Message == nil || *p.Message != "Files for the review" {
			t.Errorf("page = %+v, want no password and the message", p)
		}
		for _, leak := range []string{tr.ID, rcpt, `"recipients"`, `"scanSignature"`, `"status"`} {
			if bytes.Contains(resp.body, []byte(leak)) {
				t.Errorf("the download page exposes %q: %s", leak, resp.body)
			}
		}

		for i, f := range p.Files {
			got := r.get(t, f.DownloadURL, nil)
			expectFile(t, f.Name, got, f.Name, files[i].content)
			if sha256Hex(got.body) != f.Sha256 {
				t.Errorf("%s: downloaded SHA-256 %s, page shows %s", f.Name, sha256Hex(got.body), f.Sha256)
			}
		}

		arch := r.get(t, *p.ArchiveURL, nil)
		if arch.status != http.StatusOK {
			t.Fatalf("archive: status %d; body %.200s", arch.status, arch.body)
		}
		expectAttachment(t, "archive", arch, "application/zip", "transfer.zip")
		if got := arch.header.Get("Content-Length"); got != strconv.Itoa(len(arch.body)) {
			t.Errorf("archive Content-Length = %q, body has %d bytes", got, len(arch.body))
		}
		zr, err := zip.NewReader(bytes.NewReader(arch.body), int64(len(arch.body)))
		if err != nil {
			t.Fatalf("archive/zip: %v", err)
		}
		if len(zr.File) != len(files) {
			t.Fatalf("archive holds %d entries, want %d", len(zr.File), len(files))
		}
		for i, zf := range zr.File {
			if zf.Name != files[i].name || zf.Method != zip.Store {
				t.Errorf("entry %d = %q (method %d), want %q stored", i, zf.Name, zf.Method, files[i].name)
			}
			if got := readEntry(t, zf); !bytes.Equal(got, files[i].content) {
				t.Errorf("entry %q: %d bytes differ from the uploaded %d", zf.Name, len(got), len(files[i].content))
			}
		}
		expectNoLeak(t, d.server, alice, token, sender, rcpt, string(files[0].content))
	})
}

// readEntry returns the content of a ZIP entry.
func readEntry(t *testing.T, zf *zip.File) []byte {
	t.Helper()
	rc, err := zf.Open()
	if err != nil {
		t.Fatalf("open entry %q: %v", zf.Name, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read entry %q: %v", zf.Name, err)
	}
	return b
}

// TestDownloadHostileNames: names that could fake a path or the display
// are refused at creation; the accepted hostile names (quotes, semicolon,
// non-ASCII, leading dot, characters Windows refuses, duplicates differing
// in case) give a Content-Disposition that parses, with an ASCII fallback
// and a filename* decoding to the original name, and unique, safe archive
// entry names.
func TestDownloadHostileNames(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, _ := internalSession(t, d, "alice")
		for _, bad := range []string{
			"invoice\u202Efdp.exe", // RTL override: displays "invoiceexe.pdf"
			"../../etc/passwd",
			"evil\r\nX-Injected: 1.txt",
			"C:\\temp\\x.txt",
		} {
			p := expectTransferProblem(t, alice.createTransfer(t, oneFile(bad, 3), ""), http.StatusBadRequest, "validation-failed")
			onName := false
			for _, fe := range p.Errors {
				onName = onName || fe.Field == "/files/0/name"
			}
			if !onName {
				t.Errorf("name %q: errors %+v, want one on /files/0/name", bad, p.Errors)
			}
		}

		resume := "r\u00e9sum\u00e9 \"final\";.pdf"
		files := []uploadedFile{
			{resume, []byte("resume content")},
			{".env", []byte("KEY=value\n")},
			{"Report.txt", []byte("upper case report")},
			{"report.TXT", []byte("lower case report")},
			{"q?a*b|c<d>.txt", []byte("windows-hostile name")},
			{"\u65e5\u672c\u8a9e \u30d5\u30a1\u30a4\u30eb.txt", []byte("non-latin name")},
		}
		wantEntries := []string{
			"r\u00e9sum\u00e9 _final_;.pdf", ".env", "Report.txt", "report (2).TXT", "q_a_b_c_d_.txt",
			"\u65e5\u672c\u8a9e \u30d5\u30a1\u30a4\u30eb.txt",
		}
		tr, token := alice.availableTransfer(t, transferCreate{}, files...)
		r := d.newRecipient(2)
		p := r.mustPage(t, token)
		expectPageFiles(t, p, token, tr, tr.Files)
		for i, f := range p.Files {
			if f.Name != files[i].name {
				t.Errorf("page name %q, want the original %q", f.Name, files[i].name)
			}
			got := r.get(t, f.DownloadURL, nil)
			expectFile(t, strconv.Quote(f.Name), got, files[i].name, files[i].content)
		}
		// The exact fallback of the name with quotes, semicolon and accents.
		if cd := r.get(t, p.Files[0].DownloadURL, nil).header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="r_sum_ _final_;.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%22final%22%3B.pdf`) {
			t.Errorf("Content-Disposition = %q", cd)
		}

		arch := r.get(t, archivePath(token), nil)
		if arch.status != http.StatusOK {
			t.Fatalf("archive: status %d", arch.status)
		}
		zr, err := zip.NewReader(bytes.NewReader(arch.body), int64(len(arch.body)))
		if err != nil {
			t.Fatalf("archive/zip: %v", err)
		}
		var names []string
		seen := map[string]bool{}
		for i, zf := range zr.File {
			names = append(names, zf.Name)
			key := strings.ToLower(zf.Name)
			if seen[key] {
				t.Errorf("entry %q repeats another entry case-insensitively", zf.Name)
			}
			seen[key] = true
			if strings.HasPrefix(zf.Name, "/") || strings.ContainsAny(zf.Name, `/\:`) || strings.Contains(zf.Name, "..") {
				t.Errorf("entry %q is not a plain file name", zf.Name)
			}
			if i < len(files) && !bytes.Equal(readEntry(t, zf), files[i].content) {
				t.Errorf("entry %q holds another content", zf.Name)
			}
		}
		if !slices.Equal(names, wantEntries) {
			t.Errorf("archive entries %q, want %q", names, wantEntries)
		}
	})
}

// TestDownloadRange: a single range gets 206 and resumes; several ranges
// get the full file with 200; a range past the end gets 416; an empty file
// downloads; the archive ignores Range.
func TestDownloadRange(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, _ := internalSession(t, d, "alice")
		content := seededBytes(t, 33, 1000)
		tr, token := alice.availableTransfer(t, transferCreate{},
			uploadedFile{"movie.bin", content}, uploadedFile{"empty.txt", nil})
		if tr.Files[1].Sha256 != emptySHA256 || tr.Files[1].ScanStatus != "clean" {
			t.Fatalf("empty file = %+v, want clean with the empty SHA-256", tr.Files[1])
		}
		r := d.newRecipient(3)
		path := filePath(token, tr.Files[0].ID)

		expectPartial(t, "bytes=0-99", r.getRange(t, path, "bytes=0-99"), "movie.bin", content, 0, 99)
		expectPartial(t, "bytes=100-", r.getRange(t, path, "bytes=100-"), "movie.bin", content, 100, 999)
		expectPartial(t, "bytes=-10", r.getRange(t, path, "bytes=-10"), "movie.bin", content, 990, 999)
		expectFile(t, "multi-range", r.getRange(t, path, "bytes=0-9,20-29"), "movie.bin", content)

		over := r.getRange(t, path, "bytes=5000-")
		if over.status != http.StatusRequestedRangeNotSatisfiable {
			t.Errorf("bytes=5000-: status %d, want 416", over.status)
		}
		if got := over.header.Get("Content-Range"); got != "bytes */1000" {
			t.Errorf("416 Content-Range = %q, want bytes */1000", got)
		}
		if bytes.Contains(over.body, content[:16]) {
			t.Error("the 416 response holds file content")
		}

		empty := r.get(t, filePath(token, tr.Files[1].ID), nil)
		expectFile(t, "empty file", empty, "empty.txt", nil)

		arch := r.getRange(t, archivePath(token), "bytes=0-99")
		if arch.status != http.StatusOK || arch.header.Get("Content-Range") != "" {
			t.Errorf("archive with Range: status %d, Content-Range %q; want 200 without range", arch.status, arch.header.Get("Content-Range"))
		}
		if _, err := zip.NewReader(bytes.NewReader(arch.body), int64(len(arch.body))); err != nil {
			t.Errorf("archive with Range is not a whole ZIP: %v", err)
		}
	})
}

// TestDownloadFirstDownload: the first_download mail is sent exactly once,
// to the sender, when the union of the ranges served covers every byte of
// every file, or when the archive was sent to its end; a partial download
// (one range, an archive cut early) never counts.
func TestDownloadFirstDownload(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})

		t.Run("ranges", func(t *testing.T) {
			alice, sender := internalSession(t, d, "alice")
			a, b := seededBytes(t, 41, 1000), seededBytes(t, 42, 500)
			tr, token := alice.availableTransfer(t, transferCreate{}, uploadedFile{"a.bin", a}, uploadedFile{"b.bin", b})
			r := d.newRecipient(4)
			pa, pb := filePath(token, tr.Files[0].ID), filePath(token, tr.Files[1].ID)

			// Every range but the last one: never complete.
			expectPartial(t, "a 0-499", r.getRange(t, pa, "bytes=0-499"), "a.bin", a, 0, 499)
			// The served ranges of a small partial download stay in memory
			// (the download service writes its state in batches).
			expectPartial(t, "a 400-", r.getRange(t, pa, "bytes=400-"), "a.bin", a, 400, 999)
			expectPartial(t, "b 0-249", r.getRange(t, pb, "bytes=0-249"), "b.bin", b, 0, 249)
			if n := firstDownloads(d.server, tr.ID); n != 0 {
				t.Fatalf("%d first downloads recorded before the last range, want 0", n)
			}
			d.mailBarrier(t, alice)
			if n := d.mp.countSubject(t, sender, firstDownloadSubject); n != 0 {
				t.Fatalf("%d first_download mails before the last range, want 0", n)
			}

			// The last missing range completes the union.
			expectPartial(t, "b 250-", r.getRange(t, pb, "bytes=250-"), "b.bin", b, 250, 499)
			msg := d.mp.waitSubject(t, sender, firstDownloadSubject)
			for _, s := range []string{"a.bin", "b.bin"} {
				if !strings.Contains(msg.text(), s) {
					t.Errorf("the first_download mail lacks %q:\n%s", s, msg.text())
				}
			}
			if strings.Contains(d.mp.content(t, msg.ID), token) {
				t.Error("the first_download mail holds the download token")
			}
			if exists(t, statePath(t, d, tr.ID)) {
				t.Error("the served range state is kept after the first download")
			}

			// Later complete downloads send nothing more.
			expectFile(t, "a again", r.get(t, pa, nil), "a.bin", a)
			expectFile(t, "b again", r.get(t, pb, nil), "b.bin", b)
			if resp := r.get(t, archivePath(token), nil); resp.status != http.StatusOK {
				t.Fatalf("archive: status %d", resp.status)
			}
			d.mailBarrier(t, alice)
			if n := d.mp.countSubject(t, sender, firstDownloadSubject); n != 1 {
				t.Errorf("%d first_download mails, want exactly 1", n)
			}
			if n := firstDownloads(d.server, tr.ID); n != 1 {
				t.Errorf("%d first downloads recorded, want 1", n)
			}
			row := d.transferRow(t, tr.ID)
			if row.FirstDownloadedAt.IsZero() || !row.DeleteAfter.IsZero() {
				t.Errorf("row first download %v, delete after %v; want a first download and no deletion", row.FirstDownloadedAt, row.DeleteAfter)
			}
		})

		t.Run("archive", func(t *testing.T) {
			alice, sender := internalSession(t, d, "alice")
			big := seededBytes(t, 43, 24<<20)
			small := []byte("small companion file")
			tr, token := alice.availableTransfer(t, transferCreate{}, uploadedFile{"big.bin", big}, uploadedFile{"small.txt", small})
			r := d.newRecipient(5)

			// An archive cut early does not count.
			r.cutArchive(t, token, tr.ID, 64<<10)
			// One range of one file does not count either.
			expectPartial(t, "small 0-4", r.getRange(t, filePath(token, tr.Files[1].ID), "bytes=0-4"), "small.txt", small, 0, 4)
			d.mailBarrier(t, alice)
			if n := d.mp.countSubject(t, sender, firstDownloadSubject); n != 0 || firstDownloads(d.server, tr.ID) != 0 {
				t.Fatalf("%d first_download mails after a cut archive and one range, want 0", n)
			}

			// The whole archive counts.
			arch := r.get(t, archivePath(token), nil)
			if arch.status != http.StatusOK || arch.header.Get("Content-Length") != strconv.Itoa(len(arch.body)) {
				t.Fatalf("archive: status %d, Content-Length %q for %d bytes", arch.status, arch.header.Get("Content-Length"), len(arch.body))
			}
			d.mp.waitSubject(t, sender, firstDownloadSubject)

			// A second archive sends nothing more.
			if resp := r.get(t, archivePath(token), nil); resp.status != http.StatusOK {
				t.Fatalf("second archive: status %d", resp.status)
			}
			d.mailBarrier(t, alice)
			if n := d.mp.countSubject(t, sender, firstDownloadSubject); n != 1 {
				t.Errorf("%d first_download mails, want exactly 1", n)
			}
			if n := firstDownloads(d.server, tr.ID); n != 1 {
				t.Errorf("%d first downloads recorded, want 1", n)
			}
		})
	})
}

// TestDownloadDeleteAfterFirstDownload: with deleteAfterFirstDownload, the
// first complete download sets the deletion TT_DELETE_AFTER_DOWNLOAD_GRACE
// later, during which a range still resumes; past it the link answers 410,
// and the sweep of the lifecycle erases the transfer: keys of the files and
// of the token destroyed, files and range state removed, status deleted.
//
// The grace keeps its default (15 minutes) and is then moved into the past
// in the database; the sweeper runs every minute and app exposes no option
// to shorten it, so the server is restarted: the sweeper runs a sweep at
// start-up.
func TestDownloadDeleteAfterFirstDownload(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, sender := internalSession(t, d, "alice")
		a, b := seededBytes(t, 51, 2000), []byte("second file")
		tr, token := alice.availableTransfer(t, transferCreate{DeleteAfterFirstDownload: true},
			uploadedFile{"a.bin", a}, uploadedFile{"b.txt", b})
		r := d.newRecipient(6)
		pa, pb := filePath(token, tr.Files[0].ID), filePath(token, tr.Files[1].ID)
		if p := r.mustPage(t, token); p.DeleteAfterFirstDownload == nil || !*p.DeleteAfterFirstDownload {
			t.Errorf("page deleteAfterFirstDownload = %v, want true", p.DeleteAfterFirstDownload)
		}

		expectPartial(t, "a 0-9", r.getRange(t, pa, "bytes=0-9"), "a.bin", a, 0, 9)
		// The served ranges of a small partial download stay in memory (the
		// download service writes its state in batches).
		expectPartial(t, "a 10-", r.getRange(t, pa, "bytes=10-"), "a.bin", a, 10, 1999)
		before := time.Now()
		expectFile(t, "b", r.get(t, pb, nil), "b.txt", b)
		d.mp.waitSubject(t, sender, firstDownloadSubject)

		row := d.transferRow(t, tr.ID)
		if row.FirstDownloadedAt.IsZero() || row.DeleteAfter.Before(before.Add(15*time.Minute-time.Second)) ||
			row.DeleteAfter.After(time.Now().Add(15*time.Minute)) {
			t.Errorf("first download %v, delete after %v: want the deletion 15 minutes after the download", row.FirstDownloadedAt, row.DeleteAfter)
		}
		// During the grace period, an interrupted range still resumes.
		r.mustPage(t, token)
		expectPartial(t, "resume during the grace", r.getRange(t, pa, "bytes=1500-"), "a.bin", a, 1500, 1999)

		// Past the grace period the link is gone, before any sweep.
		execSystem(t, e, "UPDATE transfers SET delete_after = "+strconv.FormatInt(nowMillis(-time.Second), 10)+" WHERE id = '"+tr.ID+"'")
		expectGone(t, "page past the grace", r.page(t, token))
		expectGone(t, "file past the grace", r.get(t, pa, nil))

		files := d.files(t, tr.ID)
		// The sealed token of the link of the (single) recipient.
		links, err := d.db.RecipientLinks().ListByTransfer(context.Background(), d.tenantA.ID, tr.ID)
		if err != nil || len(links) != 1 || row.DownloadTokenKeyID != "" {
			t.Fatalf("links %d (%v), transfer-level key %q: want one link and none", len(links), err, row.DownloadTokenKeyID)
		}
		tokenKey := links[0].TokenKeyID
		if tokenKey == "" {
			t.Fatal("available transfer without a sealed token key")
		}
		for _, f := range files {
			if f.DEKKeyID == "" || !exists(t, d.encPath(f.StorageName)) {
				t.Fatalf("file %s before the sweep = %+v, want a key and a file on disk", f.ID, f)
			}
		}

		if err := d.stop(); err != nil {
			t.Fatalf("stop: %v", err)
		}
		// A complete link tracks no ranges any more, so its state is gone
		// already: one is planted (as left by a failed removal) so that
		// the sweep must remove the state of the recipient link.
		state := statePath(t, d, tr.ID)
		if exists(t, state) {
			t.Fatal("the served range state is kept after the first download")
		}
		if err := os.WriteFile(state, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		d2 := &depositEnv{server: d.restart(t), db: d.db, mp: d.mp}
		alice.d, r.d = d2, d2
		eventually(t, "transfer deleted by the sweep", func() bool {
			return d2.transferRow(t, tr.ID).Status == store.TransferDeleted
		})

		expectGone(t, "page after the sweep", r.page(t, token))
		expectGone(t, "file after the sweep", r.get(t, pa, nil))
		expectGone(t, "archive after the sweep", r.get(t, archivePath(token), nil))
		for _, f := range files {
			d2.expectKeyDestroyed(t, f.DEKKeyID)
			expectNoFileOnDisk(t, "file "+f.ID, d2.encPath(f.StorageName))
		}
		d2.expectKeyDestroyed(t, tokenKey)
		expectNoFileOnDisk(t, "the served range state", state)
		if got := d2.transferRow(t, tr.ID); got.DownloadTokenKeyID != "" {
			t.Errorf("deleted transfer still references the token key %s", got.DownloadTokenKeyID)
		}
		if got := alice.mustGet(t, tr.ID); got.Status != "deleted" || got.DownloadURL != "" {
			t.Errorf("sender view after the sweep: status %q, downloadUrl %q; want deleted without link", got.Status, got.DownloadURL)
		}
		expectNoLeak(t, d2.server, alice, token, sender)
	})
}

// TestDownloadDeletePeriodicSweep: past its grace period, a transfer
// deleted after its first download is erased by a periodic sweep of the
// running server, without restart (sweep interval shortened to 50 ms with
// app.WithLifecycleOptions).
func TestDownloadDeletePeriodicSweep(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{lifecycleInterval: 50 * time.Millisecond})
		bob, _ := internalSession(t, d, "bob")
		content := []byte("swept periodically")
		tr, token := bob.availableTransfer(t, transferCreate{DeleteAfterFirstDownload: true}, uploadedFile{"c.txt", content})
		r := d.newRecipient(7)
		expectFile(t, "c", r.get(t, filePath(token, tr.Files[0].ID), nil), "c.txt", content)
		eventually(t, "first download recorded", func() bool { return !d.transferRow(t, tr.ID).FirstDownloadedAt.IsZero() })
		execSystem(t, e, "UPDATE transfers SET delete_after = "+strconv.FormatInt(nowMillis(-time.Second), 10)+" WHERE id = '"+tr.ID+"'")
		eventually(t, "transfer deleted by a periodic sweep", func() bool {
			return d.transferRow(t, tr.ID).Status == store.TransferDeleted
		})
		expectGone(t, "page after the periodic sweep", r.page(t, token))
	})
}

// transferField is the field of the security log lines about a transfer
// password: the transfer ID truncated to 14 characters ("trf_" and the
// timestamp part of the ULID).
var transferField = regexp.MustCompile(`^ transfer="(trf_[0-9A-Z]{10})"( scope="transfer_password")?$`)

// TestDownloadPassword: a protected transfer shows only the sender, the
// expiry and the flags until unlocked; files and archive answer 401
// download-locked; wrong passwords count down then lock for 15 minutes,
// per transfer (any IP) and per IP (any transfer of the tenant); the right
// password sets the grant cookie, bound to its transfer, which unlocks the
// page, the files and the archive; the unlock refuses cross-site requests
// and non-JSON bodies; the security log records the failures, never a
// password or a token.
func TestDownloadPassword(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, sender := internalSession(t, d, "alice")
		content := []byte("protected content")
		req := transferCreate{Password: new(transferPassword), Message: "secret message"}
		tr1, tok1 := alice.availableTransfer(t, req, uploadedFile{"one.txt", content})
		tr2, tok2 := alice.availableTransfer(t, req, uploadedFile{"two.txt", content})
		tr3, tok3 := alice.availableTransfer(t, req, uploadedFile{"three.txt", content})
		wrong := []string{"wrong horse 1", "wrong horse 2", "wrong horse 3", "wrong horse 4"}

		// Locked page, file and archive.
		anon := d.newRecipient(10)
		resp := anon.page(t, tok1)
		p := parsePage(t, resp)
		if !p.Locked || !p.PasswordProtected || p.SenderEmail != sender || !p.ExpiresAt.Equal(*tr1.ExpiresAt) {
			t.Errorf("locked page = %+v, want locked, protected, the sender and the expiry", p)
		}
		for _, leak := range []string{"secret message", "one.txt", tr1.Files[0].ID} {
			if bytes.Contains(resp.body, []byte(leak)) {
				t.Errorf("the locked page exposes %q", leak)
			}
		}
		expectProblem(t, anon.get(t, filePath(tok1, tr1.Files[0].ID), nil), http.StatusUnauthorized, "download-locked")
		expectProblem(t, anon.get(t, archivePath(tok1), nil), http.StatusUnauthorized, "download-locked")

		// Per transfer: 2, 1 attempts remaining, then the third locks the
		// transfer for every IP.
		ip1 := d.newRecipient(11)
		for i, want := range []int{2, 1} {
			resp := ip1.unlock(t, tok1, wrong[i], nil)
			expectProblem(t, resp, http.StatusUnauthorized, "transfer-password-invalid")
			var ext struct {
				AttemptsRemaining *int `json:"attemptsRemaining"`
			}
			mustJSON(t, resp.body, &ext)
			if ext.AttemptsRemaining == nil || *ext.AttemptsRemaining != want {
				t.Errorf("wrong password %d: attemptsRemaining %v, want %d", i+1, ext.AttemptsRemaining, want)
			}
		}
		expectLocked(t, "third wrong password", ip1.unlock(t, tok1, wrong[2], nil))
		ip2 := d.newRecipient(12)
		expectLocked(t, "right password on a locked transfer", ip2.unlock(t, tok1, transferPassword, nil))
		if ip2.grant != "" {
			t.Error("a locked transfer set a grant cookie")
		}

		// Per IP: two failures on tr2 and one on tr3 lock the IP, although
		// neither transfer reached three failures.
		ip3 := d.newRecipient(13)
		expectProblem(t, ip3.unlock(t, tok2, wrong[0], nil), http.StatusUnauthorized, "transfer-password-invalid")
		expectProblem(t, ip3.unlock(t, tok2, wrong[1], nil), http.StatusUnauthorized, "transfer-password-invalid")
		expectLocked(t, "third failure of the IP on another transfer", ip3.unlock(t, tok3, wrong[3], nil))
		expectLocked(t, "right password from the locked IP", ip3.unlock(t, tok3, transferPassword, nil))

		// Another IP unlocks tr3 with the right password.
		ip4 := d.newRecipient(14)
		ok := ip4.unlock(t, tok3, transferPassword, nil)
		if ok.status != http.StatusNoContent || len(ok.body) != 0 || ip4.grant == "" {
			t.Fatalf("right password: status %d, body %q, grant %q; want 204 with the grant cookie", ok.status, ok.body, ip4.grant)
		}
		p3 := ip4.mustPage(t, tok3)
		expectPageFiles(t, p3, tok3, tr3, tr3.Files)
		if !p3.PasswordProtected || p3.Message == nil || *p3.Message != "secret message" {
			t.Errorf("unlocked page = %+v, want protected with the message", p3)
		}
		expectFile(t, "unlocked file", ip4.get(t, p3.Files[0].DownloadURL, nil), "three.txt", content)
		arch := ip4.get(t, archivePath(tok3), nil)
		if arch.status != http.StatusOK {
			t.Fatalf("unlocked archive: status %d", arch.status)
		}
		expectAttachment(t, "unlocked archive", arch, "application/zip", "transfer.zip")
		// The grant is bound to its transfer: tr2 stays locked.
		if p := ip4.mustPage(t, tok2); !p.Locked {
			t.Error("the grant of tr3 unlocks tr2")
		}
		expectProblem(t, ip4.get(t, filePath(tok2, tr2.Files[0].ID), nil), http.StatusUnauthorized, "download-locked")

		// Cross-site and non-JSON unlocks are refused before any check.
		ip5 := d.newRecipient(15)
		for _, h := range []http.Header{
			{"Origin": {"https://evil.example.com"}},
			{"Origin": {"https://" + hostB}},
			{"Origin": {"http://" + hostA}},
			{"Sec-Fetch-Site": {"cross-site"}},
			{"Sec-Fetch-Site": {"same-site"}},
		} {
			expectProblem(t, ip5.unlock(t, tok2, transferPassword, h), http.StatusForbidden, "csrf-invalid")
		}
		expectProblem(t, ip5.unlock(t, tok2, transferPassword, http.Header{"Content-Type": {"text/plain"}}),
			http.StatusUnsupportedMediaType, "unsupported-media-type")
		if ip5.grant != "" {
			t.Error("a refused unlock set a grant cookie")
		}
		same := ip5.unlock(t, tok2, transferPassword, http.Header{"Origin": {"https://" + hostA}, "Sec-Fetch-Site": {"same-origin"}})
		if same.status != http.StatusNoContent || ip5.grant == "" {
			t.Errorf("same-origin unlock: status %d; want 204 with the grant cookie", same.status)
		}

		// Security log: one transfer_password_invalid per wrong password and
		// one rate_limited per refusal on a lock, with the truncated ID.
		lines := d.securityLines(t)
		type key struct{ ip, trf string }
		invalid, limited := map[key]int{}, map[key]int{}
		for _, l := range eventsOf(t, lines, "transfer_password_invalid") {
			m := transferField.FindStringSubmatch(l.fields)
			if m == nil || m[2] != "" || l.tenant != hostA {
				t.Errorf("transfer_password_invalid line %q, want tenant %s and transfer=<14 characters>", l.raw, hostA)
				continue
			}
			invalid[key{l.ip, m[1]}]++
		}
		for _, l := range eventsOf(t, lines, "rate_limited") {
			if !strings.Contains(l.fields, `scope="transfer_password"`) {
				continue
			}
			m := transferField.FindStringSubmatch(l.fields)
			if m == nil || m[2] == "" || l.tenant != hostA {
				t.Errorf("rate_limited line %q, want tenant %s, transfer=<14 characters> and the scope", l.raw, hostA)
				continue
			}
			limited[key{l.ip, m[1]}]++
		}
		short := func(trf string) string { return trf[:14] }
		wantInvalid := map[key]int{
			{ip1.ip, short(tr1.ID)}: 3,
			{ip3.ip, short(tr2.ID)}: 2,
			{ip3.ip, short(tr3.ID)}: 1,
		}
		wantLimited := map[key]int{
			{ip2.ip, short(tr1.ID)}: 1,
			{ip3.ip, short(tr3.ID)}: 1,
		}
		if !mapsEqual(invalid, wantInvalid) {
			t.Errorf("transfer_password_invalid lines %v, want %v", invalid, wantInvalid)
		}
		if !mapsEqual(limited, wantLimited) {
			t.Errorf("rate_limited transfer_password lines %v, want %v", limited, wantLimited)
		}
		secrets := append([]string{tok1, tok2, tok3, ip4.grant, ip5.grant, sender}, wrong...)
		expectNoLeak(t, d.server, alice, secrets...)
	})
}

// expectLocked asserts a 429 transfer-locked with a Retry-After of at most
// 15 minutes, equal to retryAfterSeconds.
func expectLocked(t *testing.T, label string, resp response) {
	t.Helper()
	if resp.status != http.StatusTooManyRequests {
		t.Fatalf("%s: status %d, want 429; body %s", label, resp.status, resp.body)
	}
	p := expectProblem(t, resp, http.StatusTooManyRequests, "transfer-locked")
	ra, err := strconv.Atoi(resp.header.Get(hdrRetryAfter))
	if err != nil || ra <= 0 || ra > 900 {
		t.Errorf("%s: Retry-After = %q, want 1 to 900 seconds", label, resp.header.Get(hdrRetryAfter))
	}
	if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != ra {
		t.Errorf("%s: retryAfterSeconds %v, want the Retry-After %d", label, p.RetryAfterSeconds, ra)
	}
}

// mapsEqual reports whether two count maps are equal.
func mapsEqual[K comparable](a, b map[K]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestDownloadWithheldFiles: an infected file is neither listed nor in the
// archive, and its identifier answers 404 like an unknown file.
func TestDownloadWithheldFiles(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, _ := internalSession(t, d, "alice")
		clean := []byte("clean spreadsheet")
		tr, token := alice.availableTransfer(t, transferCreate{},
			uploadedFile{"invoice.exe", antivirustest.EICAR()}, uploadedFile{"sheet.csv", clean})
		if tr.Files[0].ScanStatus != "infected" || tr.Files[1].ScanStatus != "clean" {
			t.Fatalf("scan statuses %q/%q, want infected/clean", tr.Files[0].ScanStatus, tr.Files[1].ScanStatus)
		}
		r := d.newRecipient(20)
		resp := r.page(t, token)
		p := parsePage(t, resp)
		expectPageFiles(t, p, token, tr, tr.Files[1:])
		for _, leak := range []string{"invoice.exe", tr.Files[0].ID, antivirustest.EicarSignature, "infected"} {
			if bytes.Contains(resp.body, []byte(leak)) {
				t.Errorf("the page exposes the infected file (%q)", leak)
			}
		}
		unknown := r.get(t, filePath(token, id.New(id.File)), nil)
		expectProblem(t, unknown, http.StatusNotFound, "not-found")
		infected := r.get(t, filePath(token, tr.Files[0].ID), nil)
		expectProblem(t, infected, http.StatusNotFound, "not-found")
		if problemWithoutInstance(t, infected.body) != problemWithoutInstance(t, unknown.body) {
			t.Errorf("the infected file answers %s, an unknown one %s", infected.body, unknown.body)
		}
		expectFile(t, "clean file", r.get(t, p.Files[0].DownloadURL, nil), "sheet.csv", clean)

		arch := r.get(t, archivePath(token), nil)
		zr, err := zip.NewReader(bytes.NewReader(arch.body), int64(len(arch.body)))
		if err != nil {
			t.Fatalf("archive/zip: %v", err)
		}
		if len(zr.File) != 1 || zr.File[0].Name != "sheet.csv" || !bytes.Equal(readEntry(t, zr.File[0]), clean) {
			t.Errorf("archive entries %d, want only sheet.csv", len(zr.File))
		}
		if bytes.Contains(arch.body, antivirustest.EICAR()) {
			t.Error("the archive holds the EICAR content")
		}
	})
}

// TestDownloadGoneVersusNotFound: a malformed or unknown token answers 404;
// a known token whose transfer expired or was rejected answers 410 on
// every download operation (decision P9).
func TestDownloadGoneVersusNotFound(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, _ := internalSession(t, d, "alice")
		r := d.newRecipient(30)
		unknownTok, err := id.NewDownloadToken()
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{unknownTok, "dl_short", "xx_" + unknownTok[3:]} {
			expectProblem(t, r.page(t, tok), http.StatusNotFound, "not-found")
			expectProblem(t, r.get(t, archivePath(tok), nil), http.StatusNotFound, "not-found")
			expectProblem(t, r.get(t, filePath(tok, id.New(id.File)), nil), http.StatusNotFound, "not-found")
			expectProblem(t, r.unlock(t, tok, "any password", nil), http.StatusNotFound, "not-found")
		}

		content := []byte("short-lived content")
		for _, tc := range []struct {
			name string
			stmt func(trfID string) string
		}{
			{"expired", func(trfID string) string {
				return "UPDATE transfers SET expires_at = " + strconv.FormatInt(nowMillis(-time.Minute), 10) + " WHERE id = '" + trfID + "'"
			}},
			// A rejected transfer never gets a token in practice (its files
			// were all refused before the token is issued); the status is
			// forced on an available transfer to check the defense in depth.
			{"rejected", func(trfID string) string {
				return "UPDATE transfers SET status = 'rejected' WHERE id = '" + trfID + "'"
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tr, token := alice.availableTransfer(t, transferCreate{Password: new(transferPassword)}, uploadedFile{"f.txt", content})
				g := d.newRecipient(31)
				if g.unlock(t, token, transferPassword, nil).status != http.StatusNoContent {
					t.Fatal("unlock before the change failed")
				}
				expectFile(t, "before", g.get(t, filePath(token, tr.Files[0].ID), nil), "f.txt", content)
				execSystem(t, e, tc.stmt(tr.ID))
				expectGone(t, "page", g.page(t, token))
				expectGone(t, "file", g.get(t, filePath(token, tr.Files[0].ID), nil))
				expectGone(t, "archive", g.get(t, archivePath(token), nil))
				expectGone(t, "unlock", g.unlock(t, token, transferPassword, nil))
			})
		}
	})
}

// TestDownloadTenantIsolation: after a real flow, the token of tenant A
// under the host of tenant B answers 404 exactly like an unknown token, on
// every download operation, and a file of A is unknown behind a token of
// B.
func TestDownloadTenantIsolation(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		err := d.db.SMTPSettings().Put(context.Background(), d.tenantB.ID, store.SMTPConfig{
			Host: d.mp.host, Port: d.mp.port, Security: store.SMTPSecurityNone,
			FromAddress: "noreply@" + domainB, FromName: nameB,
		})
		if err != nil {
			t.Fatalf("put SMTP settings of B: %v", err)
		}
		alice, senderA := internalSession(t, d, "alice")
		bob := &depositor{d: d, host: hostB, ip: insideB}
		bob.openSession(t, uniqueEmail(t, "bob", domainB), "")
		contentA, contentB := []byte("content of tenant A"), []byte("content of tenant B")
		trA, tokA := alice.availableTransfer(t, transferCreate{}, uploadedFile{"a.txt", contentA})
		trB, tokB := bob.availableTransfer(t, transferCreate{}, uploadedFile{"b.txt", contentB})

		ra := d.newRecipient(40)
		expectFile(t, "A under A", ra.get(t, filePath(tokA, trA.Files[0].ID), nil), "a.txt", contentA)
		rb := &recipient{d: d, host: hostB, ip: recipientNet + "41"}
		expectFile(t, "B under B", rb.get(t, filePath(tokB, trB.Files[0].ID), nil), "b.txt", contentB)

		unknownTok, err := id.NewDownloadToken()
		if err != nil {
			t.Fatal(err)
		}
		baseline := rb.page(t, unknownTok)
		expectProblem(t, baseline, http.StatusNotFound, "not-found")
		for _, c := range []struct {
			label string
			resp  response
		}{
			{"page", rb.page(t, tokA)},
			{"file", rb.get(t, filePath(tokA, trA.Files[0].ID), nil)},
			{"archive", rb.get(t, archivePath(tokA), nil)},
			{"unlock", rb.unlock(t, tokA, transferPassword, nil)},
			{"file of A behind the token of B", rb.get(t, filePath(tokB, trA.Files[0].ID), nil)},
			{"file of B behind the token of A under A", ra.get(t, filePath(tokA, trB.Files[0].ID), nil)},
		} {
			expectProblem(t, c.resp, http.StatusNotFound, "not-found")
			if problemWithoutInstance(t, c.resp.body) != problemWithoutInstance(t, baseline.body) {
				t.Errorf("%s: %s differs from an unknown token", c.label, c.resp.body)
			}
			for _, leak := range []string{senderA, nameA, "a.txt", string(contentA), trA.ID} {
				if bytes.Contains(c.resp.body, []byte(leak)) {
					t.Errorf("%s: the 404 exposes %q", c.label, leak)
				}
			}
		}
		if rb.grant != "" {
			t.Error("an unlock under the other tenant set a grant cookie")
		}
	})
}
