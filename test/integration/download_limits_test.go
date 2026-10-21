package integration_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// openStream sends a GET of path for r on a new connection with a small
// receive buffer, reads the response head and returns the connection,
// leaving the body unread.
func (r *recipient) openStream(t *testing.T, path string) (*net.TCPConn, *http.Response) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: waitTimeout}).DialContext(context.Background(), "tcp", r.d.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := conn.(*net.TCPConn)
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetReadBuffer(4096)
	_ = tc.SetDeadline(time.Now().Add(waitTimeout))
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, r.host)
	for k, vs := range r.headers(nil) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, vs[0])
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(tc, b.String()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("GET %s: read response: %v", path, err)
	}
	return tc, resp
}

// TestDownloadStalledReader: a recipient who stops reading a download is
// cut after TT_DOWNLOAD_IDLE_TIMEOUT (5 s here), and the download does not
// count as complete (security finding M1).
func TestDownloadStalledReader(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{env: map[string]string{
			config.EnvDownloadIdleTimeout: "5s", config.EnvClamAVMaxScanBytes: "1048576",
		}})
		alice, _ := internalSession(t, d, "alice")
		content := seededBytes(t, 81, 32<<20)
		tr, token := alice.availableTransfer(t, transferCreate{}, uploadedFile{"big.bin", content})
		r := d.newRecipient(8)
		tc, resp := r.openStream(t, filePath(token, tr.Files[0].ID)) //nolint:bodyclose // held open on purpose: the connection is closed at cleanup
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		// The recipient stops reading; the server must give up.
		start := time.Now()
		time.Sleep(8 * time.Second)
		_ = tc.SetReadDeadline(time.Now().Add(waitTimeout))
		n, err := io.Copy(io.Discard, resp.Body)
		if err == nil && n == int64(len(content)) {
			t.Fatalf("the stalled download was served in full after %s", time.Since(start))
		}
		if !d.transferRow(t, tr.ID).FirstDownloadedAt.IsZero() {
			t.Error("a cut download counted as the first download")
		}
	})
}

// TestDownloadRangeProblemAndETag: an unsatisfiable range is a
// range-not-satisfiable Problem with Content-Range; the strong ETag is the
// SHA-256 of the file, and If-Range resumes only when it matches.
func TestDownloadRangeProblemAndETag(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{})
		alice, _ := internalSession(t, d, "alice")
		content := []byte("0123456789abcdef")
		tr, token := alice.availableTransfer(t, transferCreate{}, uploadedFile{"data.txt", content})
		r := d.newRecipient(9)
		path := filePath(token, tr.Files[0].ID)

		resp := r.getRange(t, path, "bytes=100-200")
		expectProblem(t, resp, http.StatusRequestedRangeNotSatisfiable, "range-not-satisfiable")
		if got := resp.header.Get("Content-Range"); got != fmt.Sprintf("bytes */%d", len(content)) {
			t.Errorf("Content-Range = %q", got)
		}
		if resp.header.Get("Content-Disposition") != "" || resp.header.Get("Cache-Control") != "no-store" {
			t.Errorf("416 headers = %v", resp.header)
		}

		full := r.get(t, path, nil)
		etag := full.header.Get("ETag")
		if etag != `"`+sha256Hex(content)+`"` {
			t.Fatalf("ETag = %q, want the quoted SHA-256", etag)
		}
		if got := r.get(t, path, http.Header{"Range": {"bytes=4-7"}, "If-Range": {etag}}); got.status != http.StatusPartialContent || string(got.body) != "4567" {
			t.Errorf("If-Range matching: %d %q", got.status, got.body)
		}
		if got := r.get(t, path, http.Header{"Range": {"bytes=4-7"}, "If-Range": {`"stale"`}}); got.status != http.StatusOK || string(got.body) != string(content) {
			t.Errorf("If-Range not matching: %d %q", got.status, got.body)
		}
	})
}

// TestDownloadStreamCap: at most 2 simultaneous streams per client on one
// transfer, 4 per transfer and 8 per client (all transfers of the tenant);
// over any cap the request gets 429 rate-limited with Retry-After: 30 and
// a rate_limited security event (scope download_streams) is written. A
// slot freed by a closed stream is reused. Clients are told apart by the
// trusted proxy header.
func TestDownloadStreamCap(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{env: map[string]string{config.EnvClamAVMaxScanBytes: "1048576"}})
		alice, _ := internalSession(t, d, "alice")
		content := seededBytes(t, 82, 8<<20)
		type link struct{ token, path string }
		var links []link
		for i := range 5 {
			tr, token := alice.availableTransfer(t, transferCreate{}, uploadedFile{fmt.Sprintf("big-%d.bin", i), content})
			links = append(links, link{token, filePath(token, tr.Files[0].ID)})
		}
		r, other, third := d.newRecipient(10), d.newRecipient(11), d.newRecipient(12)
		expectCapped := func(label string, resp response) {
			t.Helper()
			p := expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
			if resp.header.Get(hdrRetryAfter) != "30" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 30 {
				t.Errorf("%s: Retry-After %q, retryAfterSeconds %v, want 30", label, resp.header.Get(hdrRetryAfter), p.RetryAfterSeconds)
			}
		}
		var held []*net.TCPConn
		hold := func(c *recipient, l link) {
			t.Helper()
			tc, resp := c.openStream(t, l.path) //nolint:bodyclose // held open on purpose: the connection is closed at cleanup
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("stream: status %d, want 200", resp.StatusCode)
			}
			held = append(held, tc)
		}

		// Two streams of one client on the first transfer: its third is
		// refused, for the file and for the archive.
		hold(r, links[0])
		hold(r, links[0])
		expectCapped("3rd stream of a client on a transfer", r.get(t, links[0].path, nil))
		expectCapped("archive over the client cap", r.get(t, archivePath(links[0].token), nil))

		// Another client takes the two other slots of the transfer: a third
		// client is refused.
		hold(other, links[0])
		hold(other, links[0])
		expectCapped("5th stream of a transfer", third.get(t, links[0].path, nil))

		// Six more streams of the first client on three other transfers
		// reach its limit of 8.
		for _, l := range links[1:4] {
			hold(r, l)
			hold(r, l)
		}
		expectCapped("9th stream of a client", r.get(t, links[4].path, nil))
		// Another client is not affected.
		if got := third.get(t, links[4].path, nil); got.status != http.StatusOK || len(got.body) != len(content) {
			t.Errorf("another client: %d, %d bytes", got.status, len(got.body))
		}

		// Each refusing client got a download_streams event (throttled per
		// client, so at least one each).
		ips := map[string]bool{}
		for _, l := range eventsOf(t, d.securityLines(t), "rate_limited") {
			if strings.Contains(l.fields, `scope="download_streams"`) {
				if !strings.Contains(l.fields, `transfer="`) {
					t.Errorf("event without transfer: %s", l.raw)
				}
				ips[l.ip] = true
			}
		}
		if !ips[r.ip] || !ips[third.ip] || ips[other.ip] {
			t.Errorf("download_streams events from %v", ips)
		}

		// Closing a stream frees its slot.
		_ = held[4].SetLinger(0)
		_ = held[4].Close()
		eventually(t, "a slot freed by a closed stream", func() bool {
			tc, resp := r.openStream(t, links[4].path) //nolint:bodyclose // the connection is closed, never the body (it would drain the file)
			defer func() { _ = tc.Close() }()
			return resp.StatusCode == http.StatusOK
		})
	})
}
