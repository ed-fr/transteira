package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
)

// Helpers of the download tests (CLAUDE.md section 10, api/openapi.yaml
// "Downloads", threat model T-47 to T-57, decisions P3, P4, P9 and P23).

// Download API paths, cookie and values.
const (
	pathDownloads   = "/api/v1/downloads/"
	grantCookieName = "__Host-tt_dl"
	grantPrefix     = "dg_"
	grantMaxAge     = 3600
	// firstDownloadSubject is the subject of the first_download mail
	// (internal/mail/templates/en/first_download.subject.tmpl).
	firstDownloadSubject = "Your transfer has been downloaded via " + nameA
	// msgFirstDownload is the log line of the request that records the
	// first complete download of a transfer (internal/download).
	msgFirstDownload = `"msg":"transfer downloaded for the first time"`
	// msgArchiveCut is the log line of an archive not written to its end.
	msgArchiveCut = `"msg":"archive not sent to its end"`
	// stateSuffix is the extension of the served range state of a
	// transfer (internal/storage, documented layout).
	stateSuffix = ".dlstate"
	// recipientNet prefixes the X-Forwarded-For addresses of the
	// recipients: a documentation range (RFC 5737) outside every tenant
	// range.
	recipientNet = "198.51.100."
)

// Members allowed by the PublicTransfer and PublicFile schemas, the
// required ones, and the members of a locked page (exactly these).
var (
	publicTransferMembers  = []string{"senderEmail", "message", "expiresAt", "passwordProtected", "locked", "deleteAfterFirstDownload", "totalBytes", "archiveUrl", "files"}
	publicTransferRequired = []string{"senderEmail", "expiresAt", "passwordProtected", "locked"}
	publicFileMembers      = []string{"id", "name", "size", "mediaType", "sha256", "scanStatus", "downloadUrl"}
	publicFileRequired     = []string{"id", "name", "size", "sha256", "scanStatus", "downloadUrl"}
	lockedPageMembers      = []string{"senderEmail", "expiresAt", "passwordProtected", "locked"}
)

// publicFileJSON is the PublicFile schema.
type publicFileJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	MediaType   string `json:"mediaType"`
	Sha256      string `json:"sha256"`
	ScanStatus  string `json:"scanStatus"`
	DownloadURL string `json:"downloadUrl"`
}

// publicTransferJSON is the PublicTransfer schema.
type publicTransferJSON struct {
	SenderEmail              string           `json:"senderEmail"`
	Message                  *string          `json:"message"`
	ExpiresAt                time.Time        `json:"expiresAt"`
	PasswordProtected        bool             `json:"passwordProtected"`
	Locked                   bool             `json:"locked"`
	DeleteAfterFirstDownload *bool            `json:"deleteAfterFirstDownload"`
	TotalBytes               *int64           `json:"totalBytes"`
	ArchiveURL               *string          `json:"archiveUrl"`
	Files                    []publicFileJSON `json:"files"`
}

// recipient is a client of the download API: a tenant host, a client IP
// sent through the trusted proxy and, once unlocked, the grant cookie.
type recipient struct {
	d     *depositEnv
	host  string
	ip    string // X-Forwarded-For; "" sends none
	grant string // __Host-tt_dl value; "" sends none
}

// newRecipient returns a recipient of tenant A from recipientNet+n.
func (d *depositEnv) newRecipient(n int) *recipient {
	return &recipient{d: d, host: hostA, ip: recipientNet + strconv.Itoa(n)}
}

// headers returns the headers of a request of r, plus extra.
func (r *recipient) headers(extra http.Header) http.Header {
	h := http.Header{}
	if r.ip != "" {
		h.Set(hdrXFF, r.ip)
	}
	if r.grant != "" {
		h.Set("Cookie", grantCookieName+"="+r.grant)
	}
	for k, vs := range extra {
		h[k] = vs
	}
	return h
}

// pagePath, filePath and archivePath are the paths of the download
// resources of token.
func pagePath(token string) string         { return pathDownloads + token }
func filePath(token, fileID string) string { return pathDownloads + token + "/files/" + fileID }
func archivePath(token string) string      { return pathDownloads + token + "/archive" }
func unlockPath(token string) string       { return pathDownloads + token + "/unlock" }
func statePath(d *depositEnv, trf string) string {
	return filepath.Join(d.tenantDir(), storage.StateName(trf)+stateSuffix)
}

// page sends getDownload.
func (r *recipient) page(t *testing.T, token string) response {
	t.Helper()
	return r.d.do(t, request{host: r.host, path: pagePath(token), headers: r.headers(nil)})
}

// mustPage sends getDownload and parses the 200 PublicTransfer.
func (r *recipient) mustPage(t *testing.T, token string) publicTransferJSON {
	t.Helper()
	return parsePage(t, r.page(t, token))
}

// unlock sends unlockDownload with password and extra headers. A 204 with
// a grant cookie stores the cookie in r.
func (r *recipient) unlock(t *testing.T, token, password string, extra http.Header) response {
	t.Helper()
	b, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		t.Fatal(err)
	}
	resp := r.d.do(t, request{method: http.MethodPost, host: r.host, path: unlockPath(token), body: b, headers: r.headers(extra)})
	if resp.status == http.StatusNoContent {
		if v := grantFrom(t, resp.header); v != "" {
			r.grant = v
		}
	}
	return resp
}

// get sends a GET of path (a file or the archive) and reads the whole
// response, then waits until the server closes the connection: the request
// carries "Connection: close", and the server closes it only once the
// handler has returned, which is when the served ranges are recorded and a
// first download is detected. This makes the checks that follow a download
// deterministic without any sleep.
func (r *recipient) get(t *testing.T, path string, extra http.Header) response {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: waitTimeout}).DialContext(context.Background(), "tcp", r.d.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(waitTimeout))
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", path, r.host)
	for k, vs := range r.headers(extra) {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("GET %s: read response: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", path, err)
	}
	// Content-Length is moved out of the header by ReadResponse; put it
	// back so that the tests compare it with the body.
	if resp.ContentLength >= 0 && resp.Header.Get("Content-Length") == "" {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	if n, err := io.Copy(io.Discard, br); err != nil || n != 0 {
		t.Fatalf("GET %s: %d bytes after the response (%v), want the server to close the connection", path, n, err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: body}
}

// getRange sends a GET of path with a Range header.
func (r *recipient) getRange(t *testing.T, path, rng string) response {
	t.Helper()
	return r.get(t, path, http.Header{"Range": {rng}})
}

// cutArchive starts a download of the archive of token, reads its headers
// and at most n bytes of its body, then resets the connection (SO_LINGER
// 0), as a recipient closing the browser would. It waits until the server
// logs that the archive was not sent to its end.
func (r *recipient) cutArchive(t *testing.T, token, trfID string, n int64) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: waitTimeout}).DialContext(context.Background(), "tcp", r.d.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := conn.(*net.TCPConn)
	_ = tc.SetDeadline(time.Now().Add(waitTimeout))
	// A small receive buffer keeps the server from pushing the whole
	// archive into the socket buffers before the reset, which would let it
	// complete (code review 16).
	_ = tc.SetReadBuffer(4096)
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", archivePath(token), r.host)
	for k, vs := range r.headers(nil) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, vs[0])
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(tc, b.String()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("archive: read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archive: status %d, want 200", resp.StatusCode)
	}
	if resp.ContentLength <= 4*n {
		t.Fatalf("archive of %d bytes: too small to be cut after %d bytes", resp.ContentLength, n)
	}
	if _, err := io.CopyN(io.Discard, resp.Body, n); err != nil {
		t.Fatalf("archive: read the first %d bytes: %v", n, err)
	}
	_ = tc.SetLinger(0)
	_ = tc.Close()
	select {
	case <-r.d.appLog.wait(msgArchiveCut + `,"tenant":"` + string(r.d.tenantA.ID) + `","transfer":"` + trfID + `"`):
	case <-time.After(waitTimeout):
		t.Fatalf("the server never reported the cut archive of %s\napp log:\n%s", trfID, r.d.appLog)
	}
}

// grantFrom returns the value of the grant cookie set by h ("" when none),
// after checking that it is a technical cookie (CLAUDE.md section 16.2):
// Path=/, Max-Age 3600, Secure, HttpOnly, SameSite=Strict, no Domain.
func grantFrom(t *testing.T, h http.Header) string {
	t.Helper()
	values := h.Values("Set-Cookie")
	if len(values) == 0 {
		return ""
	}
	if len(values) != 1 {
		t.Fatalf("Set-Cookie = %q, want the grant cookie only", values)
	}
	c, err := http.ParseSetCookie(values[0])
	if err != nil {
		t.Fatalf("parse Set-Cookie %q: %v", values[0], err)
	}
	if c.Name != grantCookieName || !strings.HasPrefix(c.Value, grantPrefix) || len(c.Value) < 20 {
		t.Errorf("Set-Cookie %q, want %s=%s...", values[0], grantCookieName, grantPrefix)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != grantMaxAge {
		t.Errorf("grant cookie %q: want Path=/, Max-Age=%d, Secure, HttpOnly, SameSite=Strict and no Domain", values[0], grantMaxAge)
	}
	return c.Value
}

// parsePage checks a 200 PublicTransfer response against the members of
// the schema (a locked page has exactly lockedPageMembers) and decodes it.
func parsePage(t *testing.T, resp response) publicTransferJSON {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("getDownload: status %d, want 200; body %s", resp.status, resp.body)
	}
	if ct := resp.header.Get("Content-Type"); ct != contentJSON {
		t.Errorf("getDownload Content-Type = %q, want %q", ct, contentJSON)
	}
	expectSecurityHeaders(t, "getDownload", resp.header)
	var members map[string]json.RawMessage
	mustJSON(t, resp.body, &members)
	checkMembers(t, "PublicTransfer", members, publicTransferMembers, publicTransferRequired)
	var p publicTransferJSON
	mustJSON(t, resp.body, &p)
	if p.Locked {
		keys := make([]string, 0, len(members))
		for k := range members {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		want := slices.Sorted(slices.Values(lockedPageMembers))
		if !slices.Equal(keys, want) {
			t.Errorf("locked page members %q, want exactly %q", keys, want)
		}
		return p
	}
	if raw, ok := members["files"]; ok {
		var files []map[string]json.RawMessage
		mustJSON(t, raw, &files)
		for _, f := range files {
			checkMembers(t, "PublicFile", f, publicFileMembers, publicFileRequired)
		}
	}
	return p
}

// expectPageFiles asserts the unlocked page of token: the archive URL, the
// total and exactly the files want (by position) with their digests and
// download URLs, and no identifier of the transfer.
func expectPageFiles(t *testing.T, p publicTransferJSON, token string, tr senderTransferJSON, want []senderFileJSON) {
	t.Helper()
	if p.Locked || p.TotalBytes == nil || p.ArchiveURL == nil || p.DeleteAfterFirstDownload == nil {
		t.Fatalf("page = %+v, want an unlocked page with total, archiveUrl and deleteAfterFirstDownload", p)
	}
	if *p.ArchiveURL != archivePath(token) {
		t.Errorf("archiveUrl = %q, want %q", *p.ArchiveURL, archivePath(token))
	}
	if p.SenderEmail != tr.SenderEmail || !p.ExpiresAt.Equal(*tr.ExpiresAt) || *p.DeleteAfterFirstDownload != tr.DeleteAfterFirstDownload {
		t.Errorf("page sender/expiry/delete = %s/%s/%v, want %s/%s/%v", p.SenderEmail, p.ExpiresAt, *p.DeleteAfterFirstDownload,
			tr.SenderEmail, tr.ExpiresAt, tr.DeleteAfterFirstDownload)
	}
	var total int64
	for _, f := range want {
		total += f.Size
	}
	if *p.TotalBytes != total {
		t.Errorf("totalBytes = %d, want %d", *p.TotalBytes, total)
	}
	if len(p.Files) != len(want) {
		t.Fatalf("page lists %d files, want %d: %+v", len(p.Files), len(want), p.Files)
	}
	for i, f := range p.Files {
		w := want[i]
		if f.ID != w.ID || f.Name != w.Name || f.Size != w.Size || f.Sha256 != w.Sha256 || f.ScanStatus != w.ScanStatus ||
			f.DownloadURL != filePath(token, w.ID) {
			t.Errorf("page file %d = %+v, want %s %q (%d bytes, %s, %s) at %s", i, f, w.ID, w.Name, w.Size, w.Sha256, w.ScanStatus, filePath(token, w.ID))
		}
	}
}

// attachmentRE is the Content-Disposition of a download: the ASCII
// fallback, then the RFC 5987 filename*.
var attachmentRE = regexp.MustCompile("^attachment; filename=\"([^\"\\\\]*)\"; filename\\*=UTF-8''([A-Za-z0-9!#$&+.^_`|~%-]*)$")

// expectAttachment asserts the forced-download headers of a file or archive
// response (CLAUDE.md section 10, api/openapi.yaml downloadFile and
// downloadArchive): the media type, Content-Disposition whose fallback is
// printable ASCII and whose filename* decodes to name, nosniff, the sandbox
// CSP, no-store, and the other security headers.
func expectAttachment(t *testing.T, label string, resp response, contentType, name string) {
	t.Helper()
	h := resp.header
	if got := h.Get("Content-Type"); got != contentType {
		t.Errorf("%s: Content-Type = %q, want %q", label, got, contentType)
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
		"Cache-Control":           "no-store",
	} {
		if got := h.Values(k); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %s = %q, want exactly %q", label, k, got, want)
		}
	}
	for k, want := range securityHeaders {
		if k == "Content-Security-Policy" {
			continue
		}
		if got := h.Get(k); got != want {
			t.Errorf("%s: %s = %q, want %q", label, k, got, want)
		}
	}
	cd := h.Get("Content-Disposition")
	m := attachmentRE.FindStringSubmatch(cd)
	if m == nil {
		t.Errorf("%s: Content-Disposition %q, want attachment; filename=\"...\"; filename*=UTF-8''...", label, cd)
		return
	}
	fallback := m[1]
	for i := 0; i < len(fallback); i++ {
		if c := fallback[i]; c < 0x20 || c > 0x7e {
			t.Errorf("%s: the filename fallback %q holds the non-ASCII byte %#x", label, fallback, c)
		}
	}
	if utf8.RuneCountInString(name) != len(fallback) {
		t.Errorf("%s: the fallback %q does not map %q character for character", label, fallback, name)
	}
	disp, params, err := mime.ParseMediaType(cd)
	if err != nil {
		t.Errorf("%s: mime.ParseMediaType(%q): %v", label, cd, err)
		return
	}
	// The standard library decodes filename* into "filename", preferring
	// it over the fallback, as browsers do.
	if disp != "attachment" || params["filename"] != name {
		t.Errorf("%s: Content-Disposition %q parses to %q filename %q, want attachment %q", label, cd, disp, params["filename"], name)
	}
}

// expectFile asserts a complete 200 file response of content named name.
func expectFile(t *testing.T, label string, resp response, name string, content []byte) {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("%s: status %d, want 200; body %.200s", label, resp.status, resp.body)
	}
	expectAttachment(t, label, resp, "application/octet-stream", name)
	if got := resp.header.Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("%s: Accept-Ranges = %q, want bytes", label, got)
	}
	if got := resp.header.Get("Content-Length"); got != strconv.Itoa(len(content)) {
		t.Errorf("%s: Content-Length = %q, want %d", label, got, len(content))
	}
	if resp.header.Get("Content-Range") != "" {
		t.Errorf("%s: Content-Range %q on a full response", label, resp.header.Get("Content-Range"))
	}
	if sha256Hex(resp.body) != sha256Hex(content) {
		t.Errorf("%s: %d bytes with SHA-256 %s, want %d bytes with %s", label, len(resp.body), sha256Hex(resp.body), len(content), sha256Hex(content))
	}
}

// expectPartial asserts a 206 response of the bytes [from, to] of content.
func expectPartial(t *testing.T, label string, resp response, name string, content []byte, from, to int) {
	t.Helper()
	if resp.status != http.StatusPartialContent {
		t.Fatalf("%s: status %d, want 206; body %.200s", label, resp.status, resp.body)
	}
	expectAttachment(t, label, resp, "application/octet-stream", name)
	if got, want := resp.header.Get("Content-Range"), fmt.Sprintf("bytes %d-%d/%d", from, to, len(content)); got != want {
		t.Errorf("%s: Content-Range = %q, want %q", label, got, want)
	}
	if got := resp.header.Get("Content-Length"); got != strconv.Itoa(to-from+1) {
		t.Errorf("%s: Content-Length = %q, want %d", label, got, to-from+1)
	}
	if string(resp.body) != string(content[from:to+1]) {
		t.Errorf("%s: %d bytes, want the %d bytes [%d, %d]", label, len(resp.body), to-from+1, from, to)
	}
}

// availableTransfer deposits files through c (the empty ones are complete
// at creation and need no upload), finalizes the transfer and waits until
// the fake clamd made it available. It returns the transfer and its
// download token. A request without recipients gets a unique one.
func (c *depositor) availableTransfer(t *testing.T, req transferCreate, files ...uploadedFile) (senderTransferJSON, string) {
	t.Helper()
	got := c.finalizedTransfer(t, req, files...)
	got = c.waitStatus(t, got.ID, "available", waitTimeout)
	return got, tokenOf(t, c.host, got.DownloadURL)
}

// finalizedTransfer creates the transfer, uploads its files and finalizes
// it, without waiting for the analysis.
func (c *depositor) finalizedTransfer(t *testing.T, req transferCreate, files ...uploadedFile) senderTransferJSON {
	t.Helper()
	req.Files = nil
	for _, f := range files {
		req.Files = append(req.Files, fileDecl{Name: f.name, Size: int64(len(f.content))})
	}
	if req.ExpiryDays == 0 {
		req.ExpiryDays = 7
	}
	if len(req.Recipients) == 0 {
		req.Recipients = []string{uniqueEmail(t, "rcpt", "example.net")}
	}
	tr := c.mustCreate(t, req)
	for i, f := range files {
		if len(f.content) > 0 {
			c.upload(t, tr.Files[i].UploadURL, f.content)
		}
	}
	c.mustFinalize(t, tr.ID)
	return tr
}

// mailBarrier makes c invite a new external address and waits until that
// invitation mail is delivered. The mail queue delivers in order, so every
// mail queued before it (a first_download mail queued by a download that
// has returned) has been handled too: counting mails after it is exact.
func (d *depositEnv) mailBarrier(t *testing.T, c *depositor) {
	t.Helper()
	guest := uniqueEmail(t, "barrier", externalDomain)
	resp := c.invite(t, `{"email":"`+guest+`"}`, c.withCSRF())
	if resp.status != http.StatusCreated {
		t.Fatalf("createInvitation (mail barrier): %d %s", resp.status, resp.body)
	}
	d.waitMailSent(t, guest)
}

// countSubject returns the number of messages to addr whose subject
// contains subject.
func (m *mailpit) countSubject(t *testing.T, addr, subject string) int {
	t.Helper()
	n := 0
	for _, s := range m.subjects(t, addr) {
		if strings.Contains(s, subject) {
			n++
		}
	}
	return n
}

// firstDownloads returns the number of first download records of the
// transfer trfID in the application log of s.
func firstDownloads(s *server, trfID string) int {
	n := 0
	for _, l := range strings.Split(s.appLog.String(), "\n") {
		if strings.Contains(l, msgFirstDownload) && strings.Contains(l, `"transfer":"`+trfID+`"`) {
			n++
		}
	}
	return n
}

// transferRow returns the row of the transfer trfID of tenant A.
func (d *depositEnv) transferRow(t *testing.T, trfID string) store.TransferDetails {
	t.Helper()
	tr, err := d.db.Transfers().Get(context.Background(), d.tenantA.ID, trfID)
	if err != nil {
		t.Fatalf("get transfer %s: %v", trfID, err)
	}
	return tr
}

// nowMillis returns the current time plus offset in Unix milliseconds, the
// timestamp format of both schemas.
func nowMillis(offset time.Duration) int64 { return time.Now().Add(offset).UnixMilli() }

// expectGone asserts a 410 transfer-gone Problem.
func expectGone(t *testing.T, label string, resp response) {
	t.Helper()
	if resp.status != http.StatusGone {
		t.Errorf("%s: status %d, want 410; body %.200s", label, resp.status, resp.body)
		return
	}
	expectProblem(t, resp, http.StatusGone, "transfer-gone")
}

// expectNoFileOnDisk asserts that path does not exist.
func expectNoFileOnDisk(t *testing.T, what, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Errorf("%s is still on disk", what)
	}
}
