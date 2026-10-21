package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// defaultBigDownloadBytes is the size of the memory stability download
// when TT_TEST_BIGFILE_BYTES is not set: 512 MiB.
const defaultBigDownloadBytes = 512 << 20

// bigDownloadBytes returns the size of the memory stability download:
// TT_TEST_BIGFILE_BYTES when set, defaultBigDownloadBytes otherwise.
func bigDownloadBytes(t *testing.T) int64 {
	t.Helper()
	if os.Getenv(envBigFileBytes) == "" {
		return defaultBigDownloadBytes
	}
	return bigFileBytes(t)
}

// streamGet sends a GET of path for r with the Go client and returns the
// response with its body still open; the caller closes it.
func (r *recipient) streamGet(t *testing.T, ctx context.Context, path string, extra http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.d.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = r.host
	for k, vs := range r.headers(extra) {
		req.Header[k] = vs
	}
	resp, err := streamClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// TestDownloadMemoryStability uploads a large file (TT_TEST_BIGFILE_BYTES,
// 512 MiB by default) generated on the fly, then downloads it entirely and,
// once more, as a download cut in the middle and resumed with a Range
// request, while HeapInuse is sampled: the heap of the process (client and
// server) must stay within heapGrowthBound of its baseline, and both
// downloads must hash to the SHA-256 of the generated content and of the
// page. The file is above TT_CLAMAV_MAX_SCAN_BYTES, so it is delivered
// unscanned and never buffered by the fake clamd. Not parallel, so that no
// other test shares the heap; skipped with -short.
func TestDownloadMemoryStability(t *testing.T) {
	if testing.Short() {
		t.Skip("large download skipped with -short")
	}
	size := bigDownloadBytes(t)
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{env: map[string]string{config.EnvClamAVMaxScanBytes: "1048576"}})
		alice, _ := internalSession(t, d, "alice")
		d.setLimits(t, max(size, 1<<30), 1<<40)
		tr := alice.mustCreate(t, transferCreate{
			Recipients: []string{uniqueEmail(t, "rcpt", "example.net")}, ExpiryDays: 1,
			Files: []fileDecl{{Name: "big.bin", Size: size}},
		})
		gen := newHashingReader(io.LimitReader(seededStream(70), size))
		start := time.Now()
		resp, err := alice.tryTus(http.MethodPatch, tr.Files[0].UploadURL, func(h http.Header) {
			h.Set(hdrUploadOffset, "0")
		}, gen, size, uploadTimeout)
		if err != nil || resp.status != http.StatusNoContent {
			t.Fatalf("PATCH of %d bytes: %v, status %d", size, err, resp.status)
		}
		t.Logf("%s: uploaded %d MiB in %s", e.Name, size>>20, time.Since(start).Round(time.Millisecond))
		want := gen.sum()
		alice.mustFinalize(t, tr.ID)
		got := alice.waitStatus(t, tr.ID, "available", waitTimeout)
		if f := got.Files[0]; f.ScanStatus != "not_scanned_too_large" || f.Sha256 != want {
			t.Fatalf("file = %+v, want not_scanned_too_large with SHA-256 %s", f, want)
		}
		token := tokenOf(t, hostA, got.DownloadURL)
		r := d.newRecipient(50)
		p := r.mustPage(t, token)
		if len(p.Files) != 1 || p.Files[0].Sha256 != want || p.Files[0].ScanStatus != "not_scanned_too_large" || p.ArchiveURL == nil {
			t.Fatalf("page files %+v, want big.bin flagged not scanned with SHA-256 %s", p.Files, want)
		}
		path := p.Files[0].DownloadURL
		ctx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
		defer cancel()

		base := heapBaseline()
		sampler := sampleHeap()
		start = time.Now()

		// Full download.
		full := r.streamGet(t, ctx, path, nil)
		if full.StatusCode != http.StatusOK || full.ContentLength != size {
			_ = full.Body.Close()
			sampler.finish()
			t.Fatalf("full download: status %d, Content-Length %d; want 200 with %d", full.StatusCode, full.ContentLength, size)
		}
		h := sha256.New()
		n, err := io.Copy(h, full.Body)
		_ = full.Body.Close()
		if err != nil || n != size {
			sampler.finish()
			t.Fatalf("full download: %d bytes read (%v), want %d", n, err, size)
		}
		fullSum := hex.EncodeToString(h.Sum(nil))
		fullTime := time.Since(start)

		// A download cut in the middle, then resumed from there.
		mid := size/2 + 12345
		h.Reset()
		first := r.streamGet(t, ctx, path, nil)
		_, err = io.CopyN(h, first.Body, mid)
		_ = first.Body.Close()
		if err != nil {
			sampler.finish()
			t.Fatalf("first half: %v", err)
		}
		rest := r.streamGet(t, ctx, path, http.Header{"Range": {fmt.Sprintf("bytes=%d-", mid)}})
		wantRange := fmt.Sprintf("bytes %d-%d/%d", mid, size-1, size)
		if rest.StatusCode != http.StatusPartialContent || rest.Header.Get("Content-Range") != wantRange || rest.ContentLength != size-mid {
			_ = rest.Body.Close()
			sampler.finish()
			t.Fatalf("resume: status %d, Content-Range %q, Content-Length %d; want 206, %q, %d",
				rest.StatusCode, rest.Header.Get("Content-Range"), rest.ContentLength, wantRange, size-mid)
		}
		n, err = io.Copy(h, rest.Body)
		_ = rest.Body.Close()
		resumedSum := hex.EncodeToString(h.Sum(nil))
		if err != nil || n != size-mid {
			sampler.finish()
			t.Fatalf("resume: %d bytes read (%v), want %d", n, err, size-mid)
		}

		// The ZIP archive of the same file, streamed on the fly.
		zipResp := r.streamGet(t, ctx, *p.ArchiveURL, nil)
		if zipResp.StatusCode != http.StatusOK || zipResp.ContentLength <= size {
			_ = zipResp.Body.Close()
			sampler.finish()
			t.Fatalf("archive: status %d, Content-Length %d; want 200 with more than %d", zipResp.StatusCode, zipResp.ContentLength, size)
		}
		n, err = io.Copy(io.Discard, zipResp.Body)
		_ = zipResp.Body.Close()
		if err != nil || n != zipResp.ContentLength {
			sampler.finish()
			t.Fatalf("archive: %d bytes read (%v), want %d", n, err, zipResp.ContentLength)
		}
		elapsed := time.Since(start)
		peak, samples := sampler.finish()

		growth := int64(peak) - int64(base)
		t.Logf("%s: downloaded %d MiB in %s (%.0f MiB/s), then cut and resumed at %d, then as an archive; HeapInuse baseline %d MiB, peak %d MiB (+%d MiB) over %d samples, %s in all",
			e.Name, size>>20, fullTime.Round(time.Millisecond), float64(size)/(1<<20)/fullTime.Seconds(), mid,
			base>>20, peak>>20, growth>>20, samples, elapsed.Round(time.Millisecond))
		if growth > heapGrowthBound {
			t.Errorf("HeapInuse grew by %d MiB during the downloads, want at most %d MiB", growth>>20, heapGrowthBound>>20)
		}
		if fullSum != want {
			t.Errorf("full download SHA-256 %s, want %s", fullSum, want)
		}
		if resumedSum != want {
			t.Errorf("cut and resumed download SHA-256 %s, want %s", resumedSum, want)
		}
	})
}
