package integration_test

import (
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Memory stability of a large tus upload (CLAUDE.md sections 8.6 and
// 24.2): the content is generated on the fly and never held in memory, the
// server runs in the test process, so the heap of the process bounds the
// memory of the upload path (client and server together).

const (
	// envBigFileBytes overrides the size of the memory stability upload.
	envBigFileBytes = "TT_TEST_BIGFILE_BYTES"
	// defaultBigFileBytes is that size by default: 2 GiB.
	defaultBigFileBytes = 2 << 30
	// heapGrowthBound is the largest growth of HeapInuse accepted during
	// the upload.
	heapGrowthBound = 64 << 20
	// memSampleInterval is the period of the heap samples.
	memSampleInterval = 50 * time.Millisecond
)

// bigFileBytes returns the size of the memory stability upload.
func bigFileBytes(t *testing.T) int64 {
	t.Helper()
	v := os.Getenv(envBigFileBytes)
	if v == "" {
		return defaultBigFileBytes
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 2 {
		t.Fatalf("%s=%q: want a size in bytes of at least 2", envBigFileBytes, v)
	}
	return n
}

// heapSampler records the peak HeapInuse of the process.
type heapSampler struct {
	stop chan struct{}
	done sync.WaitGroup
	peak uint64
	n    int
}

// sampleHeap starts sampling HeapInuse every memSampleInterval.
func sampleHeap() *heapSampler {
	s := &heapSampler{stop: make(chan struct{})}
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		tick := time.NewTicker(memSampleInterval)
		defer tick.Stop()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			s.peak = max(s.peak, ms.HeapInuse)
			s.n++
			select {
			case <-s.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return s
}

// finish stops the sampler and returns the peak and the sample count.
func (s *heapSampler) finish() (uint64, int) {
	close(s.stop)
	s.done.Wait()
	return s.peak, s.n
}

// heapBaseline returns HeapInuse after two collections.
func heapBaseline() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// TestUploadMemoryStability streams a large file (TT_TEST_BIGFILE_BYTES,
// 2 GiB by default) through tus in two PATCHes and asserts that the heap
// of the process stays within heapGrowthBound of its baseline, then checks
// the SHA-256 computed by the server and the decrypted file on disk against
// the hash computed while generating the content. It is not parallel, so
// that no other test shares the heap, and is skipped with -short.
func TestUploadMemoryStability(t *testing.T) {
	if testing.Short() {
		t.Skip("large upload skipped with -short")
	}
	size := bigFileBytes(t)
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		d.setLimits(t, max(size, 1<<30), 1<<40)
		tr := alice.mustCreate(t, oneFile("big.bin", size))
		url := tr.Files[0].UploadURL

		gen := newHashingReader(seededStream(60, size))
		first := size / 2
		base := heapBaseline()
		sampler := sampleHeap()
		start := time.Now()
		for _, part := range [][2]int64{{0, first}, {first, size}} {
			resp, err := alice.tryTus(http.MethodPatch, url, func(h http.Header) {
				h.Set(hdrUploadOffset, strconv.FormatInt(part[0], 10))
			}, io.LimitReader(gen, part[1]-part[0]), part[1]-part[0], uploadTimeout)
			if err != nil || resp.status != http.StatusNoContent || resp.header.Get(hdrUploadOffset) != strconv.FormatInt(part[1], 10) {
				sampler.finish()
				t.Fatalf("PATCH [%d, %d): %v, %d %v", part[0], part[1], err, resp.status, resp.header)
			}
		}
		elapsed := time.Since(start)
		peak, samples := sampler.finish()
		growth := int64(peak) - int64(base)
		t.Logf("%s: uploaded %d MiB in %s (%.0f MiB/s); HeapInuse baseline %d MiB, peak %d MiB (+%d MiB) over %d samples",
			e.Name, size>>20, elapsed.Round(time.Millisecond), float64(size)/(1<<20)/elapsed.Seconds(),
			base>>20, peak>>20, growth>>20, samples)
		if growth > heapGrowthBound {
			t.Errorf("HeapInuse grew by %d MiB during the upload, want at most %d MiB", growth>>20, heapGrowthBound>>20)
		}
		if gen.N() != size {
			t.Fatalf("generated %d bytes, want %d", gen.N(), size)
		}

		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		if got := alice.mustGet(t, tr.ID).Files[0].Sha256; got != gen.Hex() {
			t.Errorf("sha256 reported by the server = %s, want %s", got, gen.Hex())
		}
		start = time.Now()
		plain := newHashingReader(d.openFile(t, d.fileRow(t, tr.ID, tr.Files[0].ID)))
		if _, err := io.Copy(io.Discard, plain); err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		t.Logf("%s: decrypted from disk in %s", e.Name, time.Since(start).Round(time.Millisecond))
		if plain.N() != size || plain.Hex() != gen.Hex() {
			t.Errorf("decrypted file: %d bytes, sha256 %s; want %d bytes, %s", plain.N(), plain.Hex(), size, gen.Hex())
		}
	})
}
