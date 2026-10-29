//go:build bigfile

package bigfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/test/internal/seeded"
)

// Addresses of the test tenant (example domains only).
const (
	internalDomain = "example.com"
	senderEmail    = "alice@" + internalDomain
	recipientEmail = "bigfile-recipient@example.org"
	adminUsername  = "bigfile-admin"
	adminEmail     = "bigfile-admin@" + internalDomain
)

// API shapes read by the test (api/openapi.yaml).
type (
	senderFile struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Size       int64  `json:"size"`
		Sha256     string `json:"sha256"`
		ScanStatus string `json:"scanStatus"`
		UploadURL  string `json:"uploadUrl"`
	}
	senderTransfer struct {
		ID     string       `json:"id"`
		Status string       `json:"status"`
		Files  []senderFile `json:"files"`
	}
	publicFile struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Size        int64  `json:"size"`
		Sha256      string `json:"sha256"`
		ScanStatus  string `json:"scanStatus"`
		DownloadURL string `json:"downloadUrl"`
	}
	publicTransfer struct {
		Locked bool         `json:"locked"`
		Files  []publicFile `json:"files"`
	}
)

// TestBigFile is the automated 20 GiB test of CLAUDE.md section 24.2
// against the production stack behind the reference Caddy (started by
// scripts/bigfile.sh, which sets the BIGFILE_* variables, see LoadConfig):
//
//  1. first-run setup with the logged setup token and TOTP confirmation,
//     a tenant on the host of BIGFILE_BASE_URL with the 20 GiB limit, its
//     internal domain, its SMTP pointed at the Mailpit sink and an API token;
//  2. a token deposit of one generated file of BIGFILE_BYTES declaring its
//     SHA-256, uploaded with tus in BIGFILE_CHUNK PATCHes through Caddy;
//  3. at BIGFILE_CUT_AT, a PATCH cut by a TCP reset in the middle of its
//     body once the server checkpointed inside it; HEAD must report an
//     offset between that checkpoint and the bytes sent, and the upload
//     resumes from it with the content regenerated from that offset;
//  4. finalize, then the transfer must become available with the expected
//     scan status and the server's SHA-256 must equal the expected one; the
//     recipient's personal link is read from the mail they received (the
//     API never returns links);
//  5. a full download hashed on the fly, then a download abandoned at
//     BIGFILE_DL_CUT_AT and resumed with Range and If-Range: both hash to
//     the expected SHA-256.
//
// The memory of the containers is measured by the orchestration; the phases
// of the JSON report (BIGFILE_REPORT) carry UTC timestamps to match them.
func TestBigFile(t *testing.T) {
	cfg, err := LoadConfig(os.Getenv)
	if err != nil {
		t.Fatalf("configuration (normally set by scripts/bigfile.sh, see make bigfile):\n%v", err)
	}
	rep := &Report{
		Engine: cfg.Engine, StartedAt: time.Now().UTC(), Bytes: cfg.Bytes, ChunkBytes: cfg.Chunk,
		Seed: cfg.Seed, TenantHost: cfg.TenantHost(), Phases: []Phase{},
	}
	r := &run{t: t, rep: rep}
	t.Cleanup(func() {
		rep.FinishedAt = time.Now().UTC()
		rep.Passed = !t.Failed()
		if t.Failed() && rep.Error == "" {
			rep.Error = "failed: see the test log"
		}
		if cfg.Report == "" {
			return
		}
		if err := rep.Write(cfg.Report); err != nil {
			t.Errorf("%v", err)
			return
		}
		t.Logf("report written to %s", cfg.Report)
	})
	t.Logf("%s engine, %d bytes (%.2f GiB), PATCH %d MiB, upload cut at %.0f%%, download cut at %.0f%%, seed %d",
		orUnknown(cfg.Engine), cfg.Bytes, float64(cfg.Bytes)/(1<<30), cfg.Chunk>>20, cfg.CutAt*100, cfg.DownloadCutAt*100, cfg.Seed)

	c := newClient(r, cfg)
	bootstrap(r, c)

	start := time.Now()
	expected := seeded.SumHex(cfg.Seed, cfg.Bytes)
	rep.SHA256.Expected = expected
	r.phase("expected-sha256", start, cfg.Bytes)
	r.logf("expected SHA-256 %s", expected)

	trf := upload(r, c, expected)
	file := waitAvailable(r, c, trf, expected)
	downloadAll(r, c, file, expected)
}

// orUnknown returns s, or "unknown" when empty.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// bootstrap runs the first-run setup, creates the tenant and its API token.
func bootstrap(r *run, c *client) {
	r.t.Helper()
	cfg := c.cfg
	start := time.Now()
	res, err := c.do(must(r)(c.request(r.t.Context(), cfg.AdminURL, http.MethodGet, "/healthz", nil, 0)))
	if err != nil {
		r.fatalf("GET /healthz: %v", err)
	}
	expect(r, "GET /healthz through Caddy", res, http.StatusOK)
	res, err = c.do(must(r)(c.request(r.t.Context(), cfg.AdminURL, http.MethodGet, "/api/v1/version", nil, 0)))
	if err != nil {
		r.fatalf("GET /api/v1/version: %v", err)
	}
	expect(r, "GET /api/v1/version", res, http.StatusOK)
	r.logf("stack healthy through Caddy, version %s", strings.TrimSpace(string(res.body)))

	var enrollment struct {
		Secret string `json:"secret"`
	}
	c.admin(r, http.MethodPost, "/admin/setup", map[string]any{
		"username": adminUsername, "email": adminEmail,
		"password": "bigfile-" + randomString(r, 18), "setupToken": cfg.SetupToken,
	}, &enrollment, http.StatusCreated)
	if enrollment.Secret == "" {
		r.fatalf("setup did not return a TOTP secret")
	}
	code, err := TOTPCode(enrollment.Secret, TOTPStep(time.Now()))
	if err != nil {
		r.fatalf("%v", err)
	}
	c.admin(r, http.MethodPost, "/admin/me/totp/confirm", map[string]any{"code": code}, nil, http.StatusOK)

	var tenant struct {
		ID string `json:"id"`
	}
	c.admin(r, http.MethodPost, "/admin/tenants", map[string]any{
		"name": "Bigfile Entity", "fqdn": cfg.TenantHost(), "defaultLanguage": "en",
		// Room for the file and a margin; the quota reserves the declared size.
		"storageQuotaBytes": cfg.Bytes + 1<<30,
		"maxTransferBytes":  MaxBytes, "maxTransferCeiling": MaxBytes,
	}, &tenant, http.StatusCreated)
	// A token deposit replaces the tenant's internal IP ranges by the
	// token's allowedCidrs: only the internal domain of the sender is
	// needed here, no IP range is opened on the tenant.
	c.admin(r, http.MethodPut, "/admin/tenants/"+tenant.ID+"/network", map[string]any{
		"internalCidrs": []string{}, "internalDomains": []string{internalDomain},
	}, nil, http.StatusOK)
	// The mail sink (Mailpit, on a network of its own shared with TransTeira,
	// scripts/bigfile.sh): an unauthenticated relay like docs/install/smtp.md.
	c.admin(r, http.MethodPut, "/admin/tenants/"+tenant.ID+"/smtp", map[string]any{
		"host": "mailpit", "port": 1025, "security": "none", "fromAddress": "transfer@" + internalDomain,
	}, nil, http.StatusOK)
	// Any client address: the stack is a throwaway one bound to the
	// loopback interface, and the address the server sees behind Docker's
	// port publishing and Caddy depends on the Docker engine (Desktop, WSL,
	// native), so it cannot be known before the first request. The real
	// client IP through the proxy is checked by the deployment smoke test.
	var token struct {
		Token string `json:"token"`
	}
	c.admin(r, http.MethodPost, "/admin/tenants/"+tenant.ID+"/api-tokens", map[string]any{
		"name": "bigfile", "allowedCidrs": []string{"0.0.0.0/0", "::/0"}, "allowedSenders": []string{senderEmail},
	}, &token, http.StatusCreated)
	if token.Token == "" {
		r.fatalf("the API token creation returned no secret")
	}
	c.token = token.Token
	r.phase("setup", start, 0)
	r.logf("super admin set up with TOTP, tenant %s on %s, API token created", tenant.ID, cfg.TenantHost())
}

// must returns a function failing the test on a non-nil error, for calls
// returning a value and an error.
func must(r *run) func(*http.Request, error) *http.Request {
	return func(req *http.Request, err error) *http.Request {
		r.t.Helper()
		if err != nil {
			r.fatalf("%v", err)
		}
		return req
	}
}

// upload creates the transfer and uploads the file with a cut and a
// resume; it returns the transfer identifier.
func upload(r *run, c *client, expected string) string {
	r.t.Helper()
	cfg := c.cfg
	ctx := r.t.Context()
	var trf senderTransfer
	c.api(r, http.MethodPost, "/api/v1/transfers", map[string]any{
		"senderEmail": senderEmail, "recipients": []string{recipientEmail}, "expiryDays": 1, "language": "en",
		"files": []map[string]any{{
			"name": "bigfile.bin", "size": cfg.Bytes, "mediaType": "application/octet-stream", "expectedSha256": expected,
		}},
	}, &trf, http.Header{"Idempotency-Key": {randomString(r, 16)}}, http.StatusCreated)
	if len(trf.Files) != 1 || trf.Files[0].UploadURL == "" {
		r.fatalf("created transfer %+v: want one file with an upload URL", trf)
	}
	r.rep.TransferID = trf.ID
	uploadURL := trf.Files[0].UploadURL
	plan := PlanCut(cfg.Bytes, cfg.Chunk, cfg.CutAt)
	r.rep.Upload.CutStart, r.rep.Upload.CutAt = plan.Start, plan.At
	r.logf("transfer %s created; upload plan: PATCHes up to %d, interrupted PATCH from %d cut after %d (checkpoint expected: %v)",
		trf.ID, plan.Start, plan.Start, plan.At, plan.Checkpoint)

	uploadStart := time.Now()
	patches := func(name string, from, to int64) {
		r.t.Helper()
		start := time.Now()
		for _, ch := range Chunks(from, to, cfg.Chunk) {
			t0 := time.Now()
			if err := c.patch(ctx, uploadURL, ch[0], ch[1]); err != nil {
				r.fatalf("%v", err)
			}
			r.rep.Upload.Patches++
			d := time.Since(t0)
			r.logf("  PATCH [%d, %d) %d MiB in %s (%.1f MiB/s)", ch[0], ch[1], (ch[1]-ch[0])>>20,
				d.Round(time.Millisecond), float64(ch[1]-ch[0])/(1<<20)/d.Seconds())
		}
		r.phase(name, start, to-from)
	}
	patches("upload-before-cut", 0, plan.Start)

	start := time.Now()
	seen := c.cutPatch(r, uploadURL, plan)
	r.rep.Upload.Patches++
	r.rep.Upload.CheckpointSeen = seen
	r.phase("upload-interrupted", start, plan.At-plan.Start)
	r.logf("connection reset after %d bytes of the PATCH started at %d (HEAD showed %d before the cut)", plan.At-plan.Start, plan.Start, seen)

	start = time.Now()
	c.waitUnlocked(r, trf.ID)
	off, length, err := c.head(ctx, uploadURL)
	if err != nil {
		r.fatalf("HEAD after the cut: %v", err)
	}
	r.rep.Upload.ResumeOffset, r.rep.Upload.LostBytes = off, plan.At-off
	r.phase("upload-cut-detected", start, 0)
	r.logf("HEAD after the cut: offset %d of %d (%d bytes sent before the cut, %d to send again)", off, length, plan.At, plan.At-off)
	switch {
	case length != cfg.Bytes:
		r.fatalf("HEAD after the cut: Upload-Length %d, want %d", length, cfg.Bytes)
	case off > plan.At:
		r.fatalf("resume offset %d is past the %d bytes sent before the cut", off, plan.At)
	case off < plan.Start:
		r.fatalf("resume offset %d is before the start %d of the interrupted PATCH: completed PATCHes were lost", off, plan.Start)
	case plan.Checkpoint && off < seen:
		// seen > plan.Start (cutPatch waited for it): this also catches a
		// checkpoint inside the interrupted PATCH that was lost.
		r.fatalf("resume offset %d is before the checkpoint %d HEAD showed before the cut", off, seen)
	}

	patches("upload-resume", off, cfg.Bytes)
	// Throughput of the whole upload, the cut, its detection and the
	// bytes sent again included.
	r.phase("upload-total", uploadStart, cfg.Bytes)
	return trf.ID
}

// waitAvailable finalizes the transfer, waits until the analysis is over
// and checks the state and the SHA-256 computed by the server; it returns
// the file as listed on the download page.
func waitAvailable(r *run, c *client, trfID, expected string) publicFile {
	r.t.Helper()
	cfg := c.cfg
	start := time.Now()
	c.api(r, http.MethodPost, "/api/v1/transfers/"+trfID+"/finalize", nil, nil, nil, http.StatusOK, http.StatusAccepted)
	var trf senderTransfer
	poll(r, "transfer available after finalize", cfg.ScanTimeout, func() bool {
		trf = senderTransfer{}
		c.api(r, http.MethodGet, "/api/v1/transfers/"+trfID, nil, &trf, nil, http.StatusOK)
		return trf.Status != "uploading" && trf.Status != "scanning"
	})
	r.phase("finalize-to-available", start, 0)
	if trf.Status != "available" || len(trf.Files) != 1 {
		r.fatalf("transfer after finalize: status %q with %d files, want available with 1", trf.Status, len(trf.Files))
	}
	f := trf.Files[0]
	r.rep.SHA256.Server, r.rep.ScanStatus = f.Sha256, f.ScanStatus
	r.logf("transfer available: scan status %s, server SHA-256 %s", f.ScanStatus, f.Sha256)
	if f.Sha256 != expected {
		r.fatalf("SHA-256 computed by the server %s, want %s", f.Sha256, expected)
	}
	if want := cfg.ExpectedScanStatus(); f.ScanStatus != want {
		r.fatalf("scan status %q, want %q (file of %d bytes, ClamAV limit %d)", f.ScanStatus, want, cfg.Bytes, cfg.ClamAVMaxScanBytes)
	}

	// The sender view carries no link: the recipient's personal link comes
	// from the mail the recipient received.
	link := c.recipientLink(r, recipientEmail)
	var page publicTransfer
	c.api(r, http.MethodGet, "/api/v1/downloads/"+url.PathEscape(path.Base(link)), nil, &page, nil, http.StatusOK)
	if page.Locked || len(page.Files) != 1 {
		r.fatalf("download page: locked %v with %d files, want 1 unlocked file", page.Locked, len(page.Files))
	}
	p := page.Files[0]
	r.rep.SHA256.Page = p.Sha256
	if p.Sha256 != expected || p.ScanStatus != f.ScanStatus || p.Size != cfg.Bytes || p.DownloadURL == "" {
		r.fatalf("download page file %+v: want size %d, SHA-256 %s, scan status %s and a download URL", p, cfg.Bytes, expected, f.ScanStatus)
	}
	return p
}

// downloadAll downloads the file entirely, then with a cut and a Range
// resume, hashing both on the fly.
func downloadAll(r *run, c *client, f publicFile, expected string) {
	r.t.Helper()
	cfg := c.cfg
	size := cfg.Bytes
	etag := `"` + expected + `"`
	buf := make([]byte, ioBuffer)

	// Full download.
	start := time.Now()
	resp, err := c.download(r.t.Context(), f.DownloadURL, nil)
	if err != nil {
		r.fatalf("full download: %v", err)
	}
	checkDownloadHeaders(r, "full download", resp, http.StatusOK, size, etag)
	h := sha256.New()
	n, err := io.CopyBuffer(h, resp.Body, buf)
	_ = resp.Body.Close()
	if err != nil || n != size {
		r.fatalf("full download: %d bytes read (%v), want %d", n, err, size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	r.rep.SHA256.Download = got
	r.phase("download-full", start, size)
	if got != expected {
		r.fatalf("full download SHA-256 %s, want %s", got, expected)
	}
	r.logf("full download SHA-256 matches")

	// A download abandoned at DownloadCutAt, then resumed with Range.
	cut := min(max(int64(cfg.DownloadCutAt*float64(size)), 1), size-1)
	r.rep.Download.CutAt, r.rep.Download.ETag = cut, etag
	start = time.Now()
	ctx, cancel := context.WithCancel(r.t.Context())
	resp, err = c.download(ctx, f.DownloadURL, nil)
	if err != nil {
		cancel()
		r.fatalf("download before the cut: %v", err)
	}
	checkDownloadHeaders(r, "download before the cut", resp, http.StatusOK, size, etag)
	h.Reset()
	n, err = io.CopyBuffer(h, io.LimitReader(resp.Body, cut), buf)
	// Abandon the stream: cancel the request, then close the body.
	cancel()
	_ = resp.Body.Close()
	if err != nil || n != cut {
		r.fatalf("download before the cut: %d bytes read (%v), want %d", n, err, cut)
	}
	r.phase("download-before-cut", start, cut)

	start = time.Now()
	resp, err = c.download(r.t.Context(), f.DownloadURL, http.Header{
		"Range": {fmt.Sprintf("bytes=%d-", cut)}, "If-Range": {etag},
	})
	if err != nil {
		r.fatalf("resumed download: %v", err)
	}
	checkDownloadHeaders(r, "resumed download", resp, http.StatusPartialContent, size-cut, etag)
	if want := fmt.Sprintf("bytes %d-%d/%d", cut, size-1, size); resp.Header.Get("Content-Range") != want {
		_ = resp.Body.Close()
		r.fatalf("resumed download: Content-Range %q, want %q", resp.Header.Get("Content-Range"), want)
	}
	n, err = io.CopyBuffer(h, resp.Body, buf)
	_ = resp.Body.Close()
	if err != nil || n != size-cut {
		r.fatalf("resumed download: %d bytes read (%v), want %d", n, err, size-cut)
	}
	got = hex.EncodeToString(h.Sum(nil))
	r.rep.SHA256.ResumedDownload = got
	r.phase("download-resume", start, size-cut)
	if got != expected {
		r.fatalf("resumed download SHA-256 %s (cut at %d), want %s", got, cut, expected)
	}
	r.logf("download cut at %d and resumed with Range: SHA-256 matches", cut)
}

// checkDownloadHeaders checks the status and the headers of a file
// download (CLAUDE.md section 10: forced download, never compressed by the
// proxy, strong ETag for If-Range); it closes the body on failure.
func checkDownloadHeaders(r *run, what string, resp *http.Response, status int, length int64, etag string) {
	r.t.Helper()
	var problems []string
	if resp.StatusCode != status {
		problems = append(problems, fmt.Sprintf("status %d, want %d", resp.StatusCode, status))
	}
	if resp.ContentLength != length {
		problems = append(problems, fmt.Sprintf("Content-Length %d, want %d", resp.ContentLength, length))
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		problems = append(problems, fmt.Sprintf("Content-Encoding %q (compressed by the proxy)", ce))
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		problems = append(problems, fmt.Sprintf("Content-Disposition %q, want attachment", cd))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		problems = append(problems, "no X-Content-Type-Options: nosniff")
	}
	if got := resp.Header.Get("ETag"); got != etag {
		problems = append(problems, fmt.Sprintf("ETag %q, want %q", got, etag))
	}
	if len(problems) > 0 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 600))
		_ = resp.Body.Close()
		r.fatalf("%s: %s: %s", what, strings.Join(problems, "; "), b)
	}
}
