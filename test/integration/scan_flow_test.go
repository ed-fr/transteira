package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	gozxingqr "github.com/makiuchi-d/gozxing/qrcode"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the antivirus worker and of the notification mails
// (CLAUDE.md sections 11 and 12.2, threat model T-41 to T-46, T-81, T-84,
// T-87, T-88, T-110, decision P10): a real server, the fake clamd of
// antivirustest, Mailpit, on SQLite and PostgreSQL.

// Values of the scan flow tests.
const (
	// Log messages of the scan worker (internal/scan).
	msgClamdDown = "antivirus unavailable"
	msgClamdUp   = "antivirus available again"
	// insideB is an internal IP of tenant B.
	insideB = "203.0.113.10"
	// transferPassword is the password of the protected transfers; it must
	// never appear in a mail or a log.
	transferPassword = "orange tulip harbor"
)

// cidRE extracts the Content-ID referenced by the QR image of the HTML part.
var cidRE = regexp.MustCompile(`<img src="cid:([^"]+)"`)

// Mail wording checked by the tests, per language (internal/mail/templates).
type wording struct {
	notificationSubject string
	confirmationSubject string
	problemsSubject     string
	notScannedSubject   string
	otherChannel        string
	notScanned          string
	partlyDelivered     string
	rejected            string
}

var wordings = map[string]wording{
	"en": {
		notificationSubject: "sent you files via " + nameA,
		confirmationSubject: "Your files have been sent via " + nameA,
		problemsSubject:     "Infected file deleted from your transfer via " + nameA,
		notScannedSubject:   "File not scanned by the antivirus in your transfer via " + nameA,
		otherChannel:        "The password will be sent to you by another channel",
		notScanned:          "Not scanned by the antivirus: the file is too large or too complex to be fully analyzed.",
		partlyDelivered:     "The other files of the transfer have been sent to the recipients.",
		rejected:            "No file of the transfer could be delivered: the transfer was not sent and the recipients have not been notified.",
	},
	"fr": {
		notificationSubject: "vous a envoyé des fichiers via " + nameA,
		confirmationSubject: "Vos fichiers ont été envoyés via " + nameA,
		problemsSubject:     "Fichier infecté supprimé de votre transfert via " + nameA,
		notScannedSubject:   "Fichier non analysé par l'antivirus",
		otherChannel:        "Le mot de passe vous sera transmis par un autre canal",
		notScanned:          "Non analysé par l'antivirus : le fichier est trop volumineux ou trop complexe pour être entièrement analysé.",
		partlyDelivered:     "Les autres fichiers du transfert ont été envoyés aux destinataires.",
		rejected:            "Aucun fichier du transfert n'a pu être remis",
	},
}

// mpPart is an inline part or an attachment of a Mailpit message.
type mpPart struct {
	PartID      string `json:"PartID"`
	FileName    string `json:"FileName"`
	ContentType string `json:"ContentType"`
	ContentID   string `json:"ContentID"`
	Size        int    `json:"Size"`
}

// mpDetail is the detail of a Mailpit message.
type mpDetail struct {
	mpMessage
	Cc          []mpAddress `json:"Cc"`
	Bcc         []mpAddress `json:"Bcc"`
	Inline      []mpPart    `json:"Inline"`
	Attachments []mpPart    `json:"Attachments"`
}

// text returns the text part with LF line endings.
func (m mpDetail) text() string { return strings.ReplaceAll(m.Text, "\r\n", "\n") }

// fetch returns the raw body of a GET on the Mailpit API.
func (m *mailpit) fetch(t *testing.T, path string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, m.api+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: waitTimeout, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatalf("Mailpit GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Mailpit GET %s: %s", path, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Mailpit GET %s: %v", path, err)
	}
	return b
}

// detail returns the detail of the message msgID.
func (m *mailpit) detail(t *testing.T, msgID string) mpDetail {
	t.Helper()
	var d mpDetail
	if err := json.Unmarshal(m.fetch(t, "/api/v1/message/"+url.PathEscape(msgID)), &d); err != nil {
		t.Fatalf("Mailpit message %s: %v", msgID, err)
	}
	return d
}

// raw returns the whole RFC 5322 source of the message msgID.
func (m *mailpit) raw(t *testing.T, msgID string) string {
	t.Helper()
	return string(m.fetch(t, "/api/v1/message/"+url.PathEscape(msgID)+"/raw"))
}

// content returns everything a reader of the message msgID can see: its
// raw source (headers included) and its decoded text and HTML parts, since
// the quoted-printable encoding of the source may wrap long values.
func (m *mailpit) content(t *testing.T, msgID string) string {
	t.Helper()
	d := m.detail(t, msgID)
	return m.raw(t, msgID) + "\n" + d.Text + "\n" + d.HTML
}

// part returns the decoded content of a part of the message msgID.
func (m *mailpit) part(t *testing.T, msgID, partID string) []byte {
	t.Helper()
	return m.fetch(t, "/api/v1/message/"+url.PathEscape(msgID)+"/part/"+url.PathEscape(partID))
}

// waitSubject waits for the message to addr whose subject contains subject
// and returns its detail.
func (m *mailpit) waitSubject(t *testing.T, addr, subject string) mpDetail {
	t.Helper()
	msg := m.find(t, addr, func(msg mpMessage) bool { return strings.Contains(msg.Subject, subject) })
	return m.detail(t, msg.ID)
}

// subjects returns the subjects of every message to addr.
func (m *mailpit) subjects(t *testing.T, addr string) []string {
	t.Helper()
	var out []string
	for _, msg := range m.messagesTo(t, addr) {
		out = append(out, msg.Subject)
	}
	return out
}

// startScanDeposit starts a deposit server whose tenant A sends its mails
// to Mailpit, with a fake clamd that really scans.
func startScanDeposit(t *testing.T, e storetest.Engine, o serverOptions) (*depositEnv, *antivirustest.Server) {
	t.Helper()
	o, av := withScanner(t, o)
	return startDeposit(t, e, o, true), av
}

// uploadedFile is a file to deposit.
type uploadedFile struct {
	name    string
	content []byte
}

// deposit creates a transfer of c with the files, uploads them and returns
// the transfer (not finalized).
func (c *depositor) deposit(t *testing.T, req transferCreate, files ...uploadedFile) senderTransferJSON {
	t.Helper()
	req.Files = nil
	for _, f := range files {
		req.Files = append(req.Files, fileDecl{Name: f.name, Size: int64(len(f.content))})
	}
	if req.ExpiryDays == 0 {
		req.ExpiryDays = 7
	}
	tr := c.mustCreate(t, req)
	for i, f := range files {
		c.upload(t, tr.Files[i].UploadURL, f.content)
	}
	return tr
}

// mustFinalize finalizes the transfer and expects 202.
func (c *depositor) mustFinalize(t *testing.T, trfID string) {
	t.Helper()
	if resp := c.finalize(t, trfID); resp.status != http.StatusAccepted {
		t.Fatalf("finalize %s: %d %s", trfID, resp.status, resp.body)
	}
}

// waitStatus polls getTransfer until the transfer has the status want, for
// at most bound. It fails fast on another final status.
func (c *depositor) waitStatus(t *testing.T, trfID, want string, bound time.Duration) senderTransferJSON {
	t.Helper()
	deadline := time.Now().Add(bound)
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		got := c.mustGet(t, trfID)
		switch {
		case got.Status == want:
			return got
		case got.Status != "scanning":
			t.Fatalf("transfer %s became %q, want %q\nserver errors:\n%s", trfID, got.Status, want, c.d.errorLines())
		case time.Now().After(deadline):
			t.Fatalf("transfer %s still %q after %s, want %q\nserver errors:\n%s", trfID, got.Status, bound, want, c.d.errorLines())
		}
		<-tick.C
	}
}

// waitFileScanning waits until the worker has marked the file scanning in
// the database: its analysis has started.
func (d *depositEnv) waitFileScanning(t *testing.T, trfID, fileID string) {
	t.Helper()
	eventually(t, "file "+fileID+" scanning", func() bool {
		return d.fileRow(t, trfID, fileID).ScanStatus == store.ScanScanning
	})
}

// tokenOf returns the download token of a download link of host.
func tokenOf(t *testing.T, host, link string) string {
	t.Helper()
	tok, ok := strings.CutPrefix(link, "https://"+host+id.DownloadPath)
	if !ok || !strings.HasPrefix(tok, "dl_") || len(tok) < 40 {
		t.Fatalf("download link %q, want https://%s/d/dl_<256-bit token>", link, host)
	}
	return tok
}

// wantFile is a file expected in a mail.
type wantFile struct {
	name, sha  string
	size       int64
	notScanned bool
}

// fileOf returns the expectation of the API file f with its content.
func fileOf(f senderFileJSON, content []byte, notScanned bool) wantFile {
	return wantFile{name: f.Name, sha: sha256Hex(content), size: f.Size, notScanned: notScanned}
}

// recipientMail is what a transfer_notification mail must show.
type recipientMail struct {
	to      string
	others  []string // the other recipients, which must not appear
	from    string
	lang    string
	link    string
	expires time.Time
	files   []wantFile
	absent  []string // names and digests of the files not delivered
	// password is set for a protected transfer: the "other channel"
	// sentence must be present and the password itself absent.
	password string
}

// expectRecipientMail waits for the single transfer_notification mail of
// w.to and checks it entirely: one recipient, the link, the inline QR code
// of the link, the files with their digests, the expiry, the password
// notice and the language.
func (d *depositEnv) expectRecipientMail(t *testing.T, w recipientMail) {
	t.Helper()
	wd := wordings[w.lang]
	msg := d.mp.waitSubject(t, w.to, wd.notificationSubject)
	if n := len(d.mp.messagesTo(t, w.to)); n != 1 {
		t.Errorf("%d messages to the recipient %s, want 1: %q", n, w.to, d.mp.subjects(t, w.to))
	}
	if len(msg.To) != 1 || !strings.EqualFold(msg.To[0].Address, w.to) || len(msg.Cc) != 0 || len(msg.Bcc) != 0 {
		t.Errorf("recipients To=%v Cc=%v Bcc=%v, want only %s", msg.To, msg.Cc, msg.Bcc, w.to)
	}
	if msg.From.Address != w.from {
		t.Errorf("From = %q, want %q", msg.From.Address, w.from)
	}
	raw := d.mp.content(t, msg.ID)
	for _, o := range w.others {
		if strings.Contains(strings.ToLower(raw), strings.ToLower(o)) {
			t.Errorf("the mail to %s names the other recipient %s", w.to, o)
		}
	}
	text := msg.text()
	if !strings.Contains(text, "\n"+w.link+"\n") || !strings.Contains(msg.HTML, `href="`+w.link+`"`) {
		t.Errorf("the mail to %s lacks the link %s:\n%s", w.to, w.link, text)
	}
	if exp := mail.FormatDateTime(w.lang, w.expires); !strings.Contains(text, exp) || !strings.Contains(msg.HTML, exp) {
		t.Errorf("the mail to %s lacks the expiry %q:\n%s", w.to, exp, text)
	}
	for _, f := range w.files {
		block := fmt.Sprintf("- %s (%s)\n  SHA-256%s: %s\n", f.name, mail.FormatSize(w.lang, f.size), map[string]string{"en": "", "fr": " "}[w.lang], f.sha)
		if f.notScanned {
			block += "  " + wd.notScanned + "\n"
		}
		if !strings.Contains(text, block) {
			t.Errorf("the mail to %s lacks the entry:\n%s\nin:\n%s", w.to, block, text)
		}
		if !f.notScanned && strings.Contains(text, block+"  "+wd.notScanned) {
			t.Errorf("the scanned file %s is flagged as not scanned", f.name)
		}
		if !strings.Contains(msg.HTML, f.sha) {
			t.Errorf("the HTML part to %s lacks the SHA-256 of %s", w.to, f.name)
		}
	}
	if n := strings.Count(text, wd.notScanned); n != countNotScanned(w.files) {
		t.Errorf("%d \"not scanned\" flags in the mail to %s, want %d", n, w.to, countNotScanned(w.files))
	}
	for _, a := range w.absent {
		if strings.Contains(raw, a) || strings.Contains(text, a) {
			t.Errorf("the mail to %s mentions the undelivered %q", w.to, a)
		}
	}
	if got := strings.Contains(text, wd.otherChannel); got != (w.password != "") {
		t.Errorf("\"other channel\" sentence present = %v, want %v", got, w.password != "")
	}
	if w.password != "" && (strings.Contains(raw, w.password) || strings.Contains(text, w.password) || strings.Contains(msg.HTML, w.password)) {
		t.Errorf("the mail to %s contains the transfer password", w.to)
	}
	if got := d.qrOf(t, msg); got != w.link {
		t.Errorf("the QR code decodes to %q, want the link %q", got, w.link)
	}
}

func countNotScanned(files []wantFile) int {
	n := 0
	for _, f := range files {
		if f.notScanned {
			n++
		}
	}
	return n
}

// qrOf checks the inline QR part of msg (a PNG whose Content-ID is the one
// the HTML image references, no attachment) and returns its decoded text.
func (d *depositEnv) qrOf(t *testing.T, msg mpDetail) string {
	t.Helper()
	if len(msg.Attachments) != 0 {
		t.Errorf("the mail has attachments %+v, want only the inline QR code", msg.Attachments)
	}
	m := cidRE.FindStringSubmatch(msg.HTML)
	if m == nil {
		t.Fatalf("no <img src=\"cid:...\"> in the HTML part:\n%s", msg.HTML)
	}
	if strings.Contains(msg.HTML, `src="http`) {
		t.Error("the HTML part references a remote image")
	}
	if len(msg.Inline) != 1 {
		t.Fatalf("inline parts %+v, want exactly the QR code", msg.Inline)
	}
	p := msg.Inline[0]
	if p.ContentType != "image/png" || p.ContentID != m[1] {
		t.Fatalf("inline part %+v, want image/png with Content-ID %q", p, m[1])
	}
	img, err := png.Decode(bytes.NewReader(d.mp.part(t, msg.ID, p.PartID)))
	if err != nil {
		t.Fatalf("the inline QR part is not a PNG: %v", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	res, err := gozxingqr.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		t.Fatalf("decode the QR code: %v", err)
	}
	return res.GetText()
}

// expectNoLeak asserts that neither log holds a token, an address, the
// password or a file content (CLAUDE.md section 16.2, threat T-101).
func expectNoLeak(t *testing.T, s *server, c *depositor, secrets ...string) {
	t.Helper()
	noSecretInLogs(t, s, append([]string{c.cookie, c.csrf, c.known, transferPassword}, secrets...)...)
}

// TestScanCleanFlow: a clean transfer becomes available; each recipient
// gets a mail of their own with the link, its QR code, the digests, the
// expiry and the password notice, in the language of the transfer; the
// sender gets the confirmation.
func TestScanCleanFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, av := startScanDeposit(t, e, serverOptions{})
		for _, tc := range []struct {
			lang     string
			password bool
		}{{"en", true}, {"fr", false}} {
			t.Run(tc.lang, func(t *testing.T) {
				alice, sender := internalSession(t, d, "alice")
				r1, r2 := uniqueEmail(t, "rcpt-one", "example.net"), uniqueEmail(t, "rcpt-two", "example.org")
				files := []uploadedFile{
					{"report-" + tc.lang + ".pdf", []byte("clean report content " + tc.lang)},
					{"photo-" + tc.lang + ".jpg", seededBytes(t, 3, 70_000)},
				}
				req := transferCreate{Recipients: []string{r1, r2}, Language: tc.lang, Message: "Files for the meeting"}
				if tc.password {
					req.Password = new(transferPassword)
				}
				tr := alice.deposit(t, req, files...)
				start := time.Now()
				alice.mustFinalize(t, tr.ID)
				got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
				t.Logf("%s: available %s after finalize", e.Name, time.Since(start).Round(time.Millisecond))
				token := tokenOf(t, hostA, got.DownloadURL)
				if got.ExpiresAt == nil {
					t.Fatal("available transfer without expiresAt")
				}
				var want []wantFile
				for i, f := range got.Files {
					if f.ScanStatus != "clean" || f.ScanSig != "" || f.Sha256 != sha256Hex(files[i].content) {
						t.Errorf("file %d = %+v, want clean with the SHA-256 of its content", i, f)
					}
					want = append(want, fileOf(f, files[i].content, false))
				}
				pw := ""
				if tc.password {
					pw = transferPassword
				}
				for _, r := range []struct{ to, other string }{{r1, r2}, {r2, r1}} {
					d.expectRecipientMail(t, recipientMail{
						to: r.to, others: []string{r.other}, from: "noreply@" + domainA, lang: tc.lang,
						link: got.DownloadURL, expires: *got.ExpiresAt, files: want, password: pw,
					})
				}
				conf := d.mp.waitSubject(t, sender, wordings[tc.lang].confirmationSubject)
				text := conf.text()
				for _, s := range []string{got.DownloadURL, r1, r2, want[0].sha, want[1].sha, mail.FormatDateTime(tc.lang, *got.ExpiresAt)} {
					if !strings.Contains(text, s) {
						t.Errorf("the confirmation lacks %q:\n%s", s, text)
					}
				}
				if strings.Contains(d.mp.content(t, conf.ID), transferPassword) {
					t.Error("the confirmation contains the transfer password")
				}
				// Code mail and confirmation only: no alert for a clean transfer.
				if subj := d.mp.subjects(t, sender); len(subj) != 2 {
					t.Errorf("sender mails %q, want the code and the confirmation", subj)
				}
				expectNoLeak(t, d.server, alice, token, sender, r1, r2, string(files[0].content))
			})
		}
		if n := len(av.Scans()); n != 4 {
			t.Errorf("clamd received %d scans, want 4 (one per file)", n)
		}
	})
}

// TestScanInfectedFile: the infected file of a transfer is erased (data key
// and disk file) but keeps its row with its signature; the transfer is
// delivered with the clean file only and the sender is told which file was
// infected.
func TestScanInfectedFile(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, sender := internalSession(t, d, "alice")
		r := uniqueEmail(t, "rcpt", "example.net")
		clean := []byte("quarterly figures, nothing harmful")
		tr := alice.deposit(t, transferCreate{Recipients: []string{r}},
			uploadedFile{"invoice.exe", antivirustest.EICAR()}, uploadedFile{"figures.csv", clean})
		infectedRow := d.fileRow(t, tr.ID, tr.Files[0].ID)
		cleanRow := d.fileRow(t, tr.ID, tr.Files[1].ID)
		if infectedRow.DEKKeyID == "" || !exists(t, d.encPath(infectedRow.StorageName)) {
			t.Fatalf("infected file before the scan = %+v, want a data key and a file on disk", infectedRow)
		}
		alice.mustFinalize(t, tr.ID)
		got := alice.waitStatus(t, tr.ID, "available", waitTimeout)

		if f := got.Files[0]; f.ScanStatus != "infected" || f.ScanSig != antivirustest.EicarSignature {
			t.Errorf("infected file in the API = %+v", f)
		}
		if f := got.Files[1]; f.ScanStatus != "clean" {
			t.Errorf("clean file in the API = %+v", f)
		}
		row := d.fileRow(t, tr.ID, infectedRow.ID)
		if row.ScanStatus != store.ScanInfected || row.ScanSignature != antivirustest.EicarSignature || row.DEKKeyID != "" {
			t.Errorf("infected row = %+v, want infected, the signature and no data key", row)
		}
		d.expectKeyDestroyed(t, infectedRow.DEKKeyID)
		if exists(t, d.encPath(infectedRow.StorageName)) {
			t.Error("the infected file is still on disk")
		}
		if !exists(t, d.encPath(cleanRow.StorageName)) || !bytes.Equal(d.decrypt(t, d.fileRow(t, tr.ID, cleanRow.ID)), clean) {
			t.Error("the clean file is not intact on disk")
		}

		d.expectRecipientMail(t, recipientMail{
			to: r, from: "noreply@" + domainA, lang: "en", link: got.DownloadURL, expires: *got.ExpiresAt,
			files:  []wantFile{fileOf(got.Files[1], clean, false)},
			absent: []string{"invoice.exe", sha256Hex(antivirustest.EICAR()), antivirustest.EicarSignature},
		})
		problems := d.mp.waitSubject(t, sender, wordings["en"].problemsSubject)
		text := problems.text()
		for _, s := range []string{"- invoice.exe\n  Detected threat: " + antivirustest.EicarSignature, wordings["en"].partlyDelivered} {
			if !strings.Contains(text, s) {
				t.Errorf("file_problems lacks %q:\n%s", s, text)
			}
		}
		if strings.Contains(text, "figures.csv") {
			t.Error("file_problems names the clean file")
		}
		d.mp.waitSubject(t, sender, wordings["en"].confirmationSubject)
		expectNoLeak(t, d.server, alice, tokenOf(t, hostA, got.DownloadURL), sender, r, string(clean), string(antivirustest.EICAR()))
	})
}

// TestScanAllInfected: a transfer whose files are all infected is rejected:
// no link, nothing to the recipients, the "rejected" alert to the sender.
func TestScanAllInfected(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, sender := internalSession(t, d, "alice")
		r := uniqueEmail(t, "rcpt", "example.net")
		second := append([]byte("prefix before the test string "), antivirustest.EICAR()...)
		tr := alice.deposit(t, transferCreate{Recipients: []string{r}, Language: "fr"},
			uploadedFile{"one.bin", antivirustest.EICAR()}, uploadedFile{"two.bin", second})
		rows := d.files(t, tr.ID)
		alice.mustFinalize(t, tr.ID)
		got := alice.waitStatus(t, tr.ID, "rejected", waitTimeout)
		if got.DownloadURL != "" {
			t.Errorf("rejected transfer with downloadUrl %q", got.DownloadURL)
		}
		for i, f := range got.Files {
			if f.ScanStatus != "infected" || f.ScanSig != antivirustest.EicarSignature {
				t.Errorf("file %d = %+v, want infected", i, f)
			}
			d.expectKeyDestroyed(t, rows[i].DEKKeyID)
			if exists(t, d.encPath(rows[i].StorageName)) {
				t.Errorf("infected file %d still on disk", i)
			}
		}
		problems := d.mp.waitSubject(t, sender, wordings["fr"].problemsSubject)
		text := problems.text()
		for _, s := range []string{"- one.bin\n", "- two.bin\n", wordings["fr"].rejected, antivirustest.EicarSignature} {
			if !strings.Contains(text, s) {
				t.Errorf("file_problems lacks %q:\n%s", s, text)
			}
		}
		// The mails of a transfer are queued together, recipients first,
		// and a tenant's mails are delivered in order: once the sender's
		// alert is in Mailpit, a recipient mail would be too.
		if n := len(d.mp.messagesTo(t, r)); n != 0 || d.mailSentLines(t, r) != 0 {
			t.Errorf("%d mails to the recipient of a rejected transfer, want none", n)
		}
		if subj := d.mp.subjects(t, sender); len(subj) != 2 {
			t.Errorf("sender mails %q, want the code and file_problems only", subj)
		}
		expectNoLeak(t, d.server, alice, sender, r, string(antivirustest.EICAR()))
	})
}

// TestScanTooLarge: a file above the scan limit, whether TransTeira's own
// (TT_CLAMAV_MAX_SCAN_BYTES) or clamd's (StreamMaxLength reply), is
// delivered flagged as not scanned; the sender gets file_not_scanned.
func TestScanTooLarge(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		env       map[string]string
		clamLimit int64
		size      int
	}{
		{"over TT_CLAMAV_MAX_SCAN_BYTES", map[string]string{config.EnvClamAVMaxScanBytes: "1048576"}, 0, 2 * oneMiB},
		{"clamd size limit exceeded", nil, 4096, 64 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forEngine(t, func(t *testing.T, e storetest.Engine) {
				d, av := startScanDeposit(t, e, serverOptions{env: tc.env})
				av.SetSizeLimit(tc.clamLimit)
				alice, sender := internalSession(t, d, "alice")
				r := uniqueEmail(t, "rcpt", "example.net")
				big := seededBytes(t, 9, tc.size)
				small := []byte("small scanned file")
				tr := alice.deposit(t, transferCreate{Recipients: []string{r}},
					uploadedFile{"archive.tar", big}, uploadedFile{"notes.txt", small})
				alice.mustFinalize(t, tr.ID)
				got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
				if f := got.Files[0]; f.ScanStatus != "not_scanned_too_large" || f.ScanSig != "" {
					t.Errorf("big file = %+v, want not_scanned_too_large", f)
				}
				if f := got.Files[1]; f.ScanStatus != "clean" {
					t.Errorf("small file = %+v, want clean", f)
				}
				scans := av.Scans()
				if tc.clamLimit == 0 {
					// Never sent to clamd: only the small file was scanned.
					if len(scans) != 1 || !bytes.Equal(scans[0].Data, small) {
						t.Errorf("clamd scans = %d, want only the small file", len(scans))
					}
				} else if !slices.ContainsFunc(scans, func(s antivirustest.Scan) bool { return int64(len(s.Data)) > tc.clamLimit }) {
					t.Error("the big file never reached clamd")
				}
				d.expectRecipientMail(t, recipientMail{
					to: r, from: "noreply@" + domainA, lang: "en", link: got.DownloadURL, expires: *got.ExpiresAt,
					files: []wantFile{fileOf(got.Files[0], big, true), fileOf(got.Files[1], small, false)},
				})
				ns := d.mp.waitSubject(t, sender, wordings["en"].notScannedSubject)
				text := ns.text()
				if !strings.Contains(text, "- archive.tar (") || !strings.Contains(text, sha256Hex(big)) || strings.Contains(text, "notes.txt") {
					t.Errorf("file_not_scanned does not list exactly the big file:\n%s", text)
				}
				d.mp.waitSubject(t, sender, wordings["en"].confirmationSubject)
				expectNoLeak(t, d.server, alice, tokenOf(t, hostA, got.DownloadURL), sender, r, string(small))
			})
		})
	}
}

// TestScanEncryptedArchive: a file clamd reports as an encrypted archive
// (AlertEncryptedArchive) is delivered unscanned and flagged
// (not_scanned_encrypted), like a file too large to be analyzed: the
// transfer becomes available and the file keeps its key and content.
func TestScanEncryptedArchive(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, av := startScanDeposit(t, e, serverOptions{})
		av.SetMode(antivirustest.ModeEncrypted)
		alice, _ := internalSession(t, d, "alice")
		content := []byte("PK encrypted archive stand-in")
		tr := alice.deposit(t, transferCreate{Recipients: []string{uniqueEmail(t, "rcpt", "example.net")}},
			uploadedFile{"secret.zip", content})
		alice.mustFinalize(t, tr.ID)
		got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
		if f := got.Files[0]; f.ScanStatus != "not_scanned_encrypted" || f.ScanSig != "" {
			t.Errorf("encrypted archive = %+v, want not_scanned_encrypted without signature", f)
		}
		tokenOf(t, hostA, got.DownloadURL)
		f := d.files(t, tr.ID)[0]
		if f.DEKKeyID == "" || !bytes.Equal(d.decrypt(t, f), content) {
			t.Error("the encrypted archive was not kept for delivery")
		}
	})
}

// countLines returns the number of application log lines containing msg.
func countLines(s *server, msg string) int {
	return strings.Count(s.appLog.String(), msg)
}

// TestScanFailClosed: while clamd is down, finalized transfers stay
// scanning and no mail leaves; a single warning reports the incident; once
// clamd is back, the transfers become available (the retry delays are
// shortened to 100-400 ms with app.WithScanOptions), and their expiry runs
// from the availability, not from the finalization.
func TestScanFailClosed(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, av := startScanDeposit(t, e, serverOptions{scanRetry: 100 * time.Millisecond})
		alice, sender := internalSession(t, d, "alice")
		r1, r2 := uniqueEmail(t, "rcpt-one", "example.net"), uniqueEmail(t, "rcpt-two", "example.net")
		tr1 := alice.deposit(t, transferCreate{Recipients: []string{r1}}, uploadedFile{"first.txt", []byte("first")})
		tr2 := alice.deposit(t, transferCreate{Recipients: []string{r2}}, uploadedFile{"second.txt", []byte("second")})

		av.Stop()
		start := time.Now()
		alice.mustFinalize(t, tr1.ID)
		select {
		case <-d.appLog.wait(msgClamdDown):
		case <-time.After(waitTimeout):
			t.Fatalf("no %q warning within %s\napp log:\n%s", msgClamdDown, waitTimeout, d.appLog)
		}
		// A second transfer analyzed during the same incident fails too,
		// without a second warning.
		alice.mustFinalize(t, tr2.ID)
		d.waitFileScanning(t, tr2.ID, tr2.Files[0].ID)

		for _, tr := range []senderTransferJSON{tr1, tr2} {
			got := alice.mustGet(t, tr.ID)
			if got.Status != "scanning" || got.DownloadURL != "" || got.ExpiresAt != nil || got.Files[0].ScanStatus != "scanning" {
				t.Errorf("transfer during the outage = %+v, want scanning without a link nor expiresAt", got)
			}
		}
		for _, r := range []string{r1, r2} {
			if n := len(d.mp.messagesTo(t, r)); n != 0 || d.mailSentLines(t, r) != 0 {
				t.Errorf("%d mails to %s during the outage, want none", n, r)
			}
		}
		if subj := d.mp.subjects(t, sender); len(subj) != 1 {
			t.Errorf("sender mails during the outage %q, want the code only", subj)
		}

		// Keep the outage long enough to tell the availability from the
		// finalization in the expiry.
		time.Sleep(time.Second)
		av.Restart(t)
		restarted := time.Now()
		for _, tr := range []senderTransferJSON{tr1, tr2} {
			got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
			tokenOf(t, hostA, got.DownloadURL)
			if got.FinalizedAt == nil || got.ExpiresAt == nil ||
				!got.ExpiresAt.After(got.FinalizedAt.AddDate(0, 0, got.ExpiryDays).Add(500*time.Millisecond)) {
				t.Errorf("expiresAt %v, finalizedAt %v: want the %d days counted from the availability, after the outage",
					got.ExpiresAt, got.FinalizedAt, got.ExpiryDays)
			}
		}
		t.Logf("%s: available %s after clamd restarted (%s after the first finalize)",
			e.Name, time.Since(restarted).Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
		d.mp.waitSubject(t, r1, wordings["en"].notificationSubject)
		d.mp.waitSubject(t, r2, wordings["en"].notificationSubject)
		if n := countLines(d.server, msgClamdDown); n != 1 {
			t.Errorf("%d %q warnings, want exactly 1\napp log:\n%s", n, msgClamdDown, d.appLog)
		}
		if n := countLines(d.server, msgClamdUp); n != 1 {
			t.Errorf("%d %q lines, want exactly 1", n, msgClamdUp)
		}
		expectNoLeak(t, d.server, alice, sender, r1, r2)
	})
}

// restart runs a new app.Run on the configuration (database, data
// directory, master key, clamd address) of the stopped server s, as an
// operator restarting the container would.
func (s *server) restart(t *testing.T) *server {
	t.Helper()
	if !s.stopped.Load() {
		t.Fatal("restart of a running server")
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s2 := &server{
		addr: ln.Addr().String(), logDir: s.logDir, appLog: newWatchBuffer(), done: make(chan error, 1),
		cfg: s.cfg, tenantA: s.tenantA, tenantB: s.tenantB, client: s.client,
	}
	ctx, cancel := context.WithCancel(context.Background())
	s2.cancel = cancel
	go func() { s2.done <- app.Run(ctx, s.cfg, app.WithListener(ln), app.WithLogOutput(s2.appLog)) }()
	select {
	case <-s2.appLog.wait("HTTP server listening"):
	case err := <-s2.done:
		s2.stopped.Store(true)
		t.Fatalf("app.Run failed at restart: %v\napp log:\n%s", err, s2.appLog)
	case <-time.After(waitTimeout):
		t.Fatalf("server did not restart within %s\napp log:\n%s", waitTimeout, s2.appLog)
	}
	t.Cleanup(func() {
		if err := s2.stop(); err != nil {
			t.Errorf("app.Run returned %v after shutdown, want nil\napp log:\n%s", err, s2.appLog)
		}
	})
	return s2
}

// TestScanRestartDuringScan: a server stopped while clamd hangs on an
// analysis leaves the transfer scanning; the start-up sweep of the next
// server analyzes it and delivers it.
func TestScanRestartDuringScan(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, av := startScanDeposit(t, e, serverOptions{})
		alice, sender := internalSession(t, d, "alice")
		r := uniqueEmail(t, "rcpt", "example.net")
		content := []byte("analyzed after the restart")
		tr := alice.deposit(t, transferCreate{Recipients: []string{r}}, uploadedFile{"late.txt", content})
		av.SetMode(antivirustest.ModeHang)
		alice.mustFinalize(t, tr.ID)
		d.waitFileScanning(t, tr.ID, tr.Files[0].ID)

		stopStart := time.Now()
		if err := d.stop(); err != nil {
			t.Fatalf("stop during the analysis: %v\napp log:\n%s", err, d.appLog)
		}
		t.Logf("%s: server stopped in %s with an analysis hanging", e.Name, time.Since(stopStart).Round(time.Millisecond))
		if row := d.fileRow(t, tr.ID, tr.Files[0].ID); row.ScanStatus != store.ScanScanning || row.ScanAttempts != 0 {
			t.Errorf("file after the shutdown = %+v, want scanning without a counted attempt", row)
		}
		if n := len(d.mp.messagesTo(t, r)); n != 0 {
			t.Errorf("%d mails to the recipient before the analysis, want none", n)
		}

		av.SetMode(antivirustest.ModeScan)
		d2 := &depositEnv{server: d.restart(t), db: d.db, mp: d.mp}
		alice.d = d2
		select {
		case <-d2.appLog.wait(`"msg":"antivirus sweep","scanning":1,"queued":1`):
		case <-time.After(waitTimeout):
			t.Fatalf("no start-up sweep of the scanning transfer\napp log:\n%s", d2.appLog)
		}
		got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
		if got.Files[0].ScanStatus != "clean" {
			t.Errorf("file after the sweep = %+v, want clean", got.Files[0])
		}
		d2.expectRecipientMail(t, recipientMail{
			to: r, from: "noreply@" + domainA, lang: "en", link: got.DownloadURL, expires: *got.ExpiresAt,
			files: []wantFile{fileOf(got.Files[0], content, false)},
		})
		d2.mp.waitSubject(t, sender, wordings["en"].confirmationSubject)
		expectNoLeak(t, d2.server, alice, tokenOf(t, hostA, got.DownloadURL), sender, r, string(content))
		expectNoLeak(t, d.server, alice, sender, r, string(content))
	})
}

// TestScanTenantIsolation: the mails of a transfer leave with the SMTP
// settings of its own tenant, a download link is never shown to another
// tenant, and a transfer of A is invisible under B (404 like an unknown
// transfer).
func TestScanTenantIsolation(t *testing.T) {
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
		senderB := uniqueEmail(t, "bob", domainB)
		bob.openSession(t, senderB, "")

		rA, rB := uniqueEmail(t, "rcpt-a", "example.net"), uniqueEmail(t, "rcpt-b", "example.org")
		contentA, contentB := []byte("content of tenant A"), []byte("content of tenant B")
		trA := alice.deposit(t, transferCreate{Recipients: []string{rA}}, uploadedFile{"a.txt", contentA})
		trB := bob.deposit(t, transferCreate{Recipients: []string{rB}}, uploadedFile{"b.txt", contentB})
		alice.mustFinalize(t, trA.ID)
		bob.mustFinalize(t, trB.ID)
		gotA := alice.waitStatus(t, trA.ID, "available", waitTimeout)
		gotB := bob.waitStatus(t, trB.ID, "available", waitTimeout)
		tokA, tokB := tokenOf(t, hostA, gotA.DownloadURL), tokenOf(t, hostB, gotB.DownloadURL)

		d.expectRecipientMail(t, recipientMail{
			to: rA, from: "noreply@" + domainA, lang: "en", link: gotA.DownloadURL, expires: *gotA.ExpiresAt,
			files: []wantFile{fileOf(gotA.Files[0], contentA, false)},
		})
		msgB := d.mp.find(t, rB, func(m mpMessage) bool { return strings.Contains(m.Subject, "sent you files via "+nameB) })
		confA := d.mp.waitSubject(t, senderA, wordings["en"].confirmationSubject)
		confB := d.mp.waitSubject(t, senderB, "Your files have been sent via "+nameB)
		for _, c := range []struct {
			who   string
			msg   mpMessage
			from  string
			name  string
			own   string
			other string
		}{
			{"recipient of B", msgB, "noreply@" + domainB, nameB, tokB, tokA},
			{"sender of A", confA.mpMessage, "noreply@" + domainA, nameA, tokA, tokB},
			{"sender of B", confB.mpMessage, "noreply@" + domainB, nameB, tokB, tokA},
		} {
			if c.msg.From.Address != c.from || c.msg.From.Name != c.name {
				t.Errorf("%s: From = %+v, want %s <%s>", c.who, c.msg.From, c.name, c.from)
			}
			raw := d.mp.content(t, c.msg.ID)
			if !strings.Contains(raw, c.own) || strings.Contains(raw, c.other) {
				t.Errorf("%s: the mail must hold its own link and never the other tenant's", c.who)
			}
		}
		// Nothing of A ever reaches B's sender or recipient.
		for _, addr := range []string{senderB, rB} {
			for _, m := range d.mp.messagesTo(t, addr) {
				raw := d.mp.content(t, m.ID)
				if strings.Contains(raw, tokA) || strings.Contains(raw, nameA) || strings.Contains(raw, "noreply@"+domainA) {
					t.Errorf("a mail to %s (%q) holds data of tenant A", addr, m.Subject)
				}
			}
		}

		unknown := bob.getTransfer(t, id.New(id.Transfer))
		expectProblem(t, unknown, http.StatusNotFound, "not-found")
		for _, c := range []struct {
			who  *depositor
			trID string
		}{{bob, trA.ID}, {alice, trB.ID}} {
			resp := c.who.getTransfer(t, c.trID)
			expectProblem(t, resp, http.StatusNotFound, "not-found")
			if problemWithoutInstance(t, resp.body) != problemWithoutInstance(t, unknown.body) {
				t.Errorf("getTransfer of the other tenant's transfer differs from an unknown one: %s", resp.body)
			}
			if bytes.Contains(resp.body, []byte(tokA)) || bytes.Contains(resp.body, []byte(tokB)) {
				t.Error("a 404 holds a download token")
			}
		}
		expectNoLeak(t, d.server, alice, tokA, tokB, senderA, senderB, rA, rB, bob.cookie, bob.csrf, string(contentA), string(contentB))
	})
}
