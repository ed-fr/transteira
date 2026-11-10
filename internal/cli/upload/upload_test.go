package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/tte2"
)

// pattern returns n deterministic bytes.
func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) + seed + byte(i>>12)
	}
	return b
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// baseOptions returns the options of a deposit of paths with a state file
// in a temporary directory.
func baseOptions(t *testing.T, paths ...string) Options {
	t.Helper()
	return Options{
		Paths: paths, Recipients: []string{"finance@entity-a.example.com"}, Sender: "reporting@entity-a.example.com",
		ExpiryDays: 7, ChunkSize: 64 << 10, StatePath: filepath.Join(t.TempDir(), "state.json"),
		PollInterval: time.Millisecond,
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestMultiFileFolder(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "plans")
	want := []struct {
		name, path string
		data       []byte
		local      string
	}{
		{"top.pdf", "", pattern(70<<10, 3), filepath.Join(dir, "top.pdf")},
		{"a.txt", "plans", pattern(1000, 1), filepath.Join(tree, "a.txt")},
		{"b.bin", "plans/sub", pattern(200<<10, 2), filepath.Join(tree, "sub", "b.bin")},
		{"empty.dat", "plans/sub", []byte{}, filepath.Join(tree, "sub", "empty.dat")},
	}
	for _, w := range want {
		writeFile(t, w.local, w.data)
	}
	writeFile(t, filepath.Join(tree, StatePrefix+"x.json"), []byte("{}"))
	var warnings []string
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(dir, "top.pdf"), filepath.Join(tree, "link.pdf")); err != nil {
			t.Fatal(err)
		}
	}
	fs := newFakeServer(t)
	o := baseOptions(t, filepath.Join(dir, "top.pdf"), tree, filepath.Join(dir, "top.pdf"))
	o.Message = "Nightly export"
	o.Warn = func(s string) { warnings = append(warnings, s) }
	phases := map[string]bool{}
	var stateMode os.FileMode
	o.Progress = func(p Progress) {
		phases[p.Phase] = true
		if p.Phase == PhaseUpload && stateMode == 0 {
			if info, err := os.Stat(o.StatePath); err == nil {
				stateMode = info.Mode().Perm()
			}
		}
	}
	res, err := Run(context.Background(), fs.client(t, testToken, nil), o)
	if err != nil {
		t.Fatal(err)
	}
	tr := fs.only()
	if len(tr.req.Files) != len(want) || len(res.Files) != len(want) {
		t.Fatalf("files %+v", tr.req.Files)
	}
	for i, w := range want {
		d := tr.req.Files[i]
		if d.Name != w.name || d.Path != w.path {
			t.Errorf("file %d: %+v, want %s %s", i, d, w.name, w.path)
		}
		if !bytes.Equal(tr.uploads[i].data.Bytes(), w.data) || d.ExpectedSHA256 != sum(w.data) {
			t.Errorf("file %d: content differs", i)
		}
		if r := res.Files[i]; r.Name != w.name || r.Path != w.path || r.SHA256 != sum(w.data) || r.ScanStatus != "clean" || r.Size != int64(len(w.data)) {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if tr.req.Files[0].MediaType != "application/pdf" || tr.req.Message != "Nightly export" || tr.req.SenderEmail != o.Sender {
		t.Errorf("request %+v", tr.req)
	}
	if res.Status != statusAvailable || res.TransferID != tr.id || res.Key != "" || res.Link != "" || res.ExpiresAt.IsZero() {
		t.Errorf("result %+v", res)
	}
	if fileExists(o.StatePath) {
		t.Error("state file kept after success")
	}
	if !phases[PhaseHash] || !phases[PhaseUpload] || !phases[PhaseScan] {
		t.Errorf("phases %v", phases)
	}
	if runtime.GOOS != "windows" && stateMode != 0o600 {
		t.Errorf("state file mode %v", stateMode)
	}
	wantWarnings := 1 // duplicate
	if runtime.GOOS != "windows" {
		wantWarnings++
	}
	if len(warnings) != wantWarnings {
		t.Errorf("warnings %q", warnings)
	}
}

func TestCutMidPatchResumes(t *testing.T) {
	dir := t.TempDir()
	data := pattern(300<<10, 4)
	writeFile(t, filepath.Join(dir, "f.bin"), data)
	fs := newFakeServer(t)
	cuts := 0
	fs.cut = func(_ *fakeUpload, offset int64) int64 {
		if offset == 64<<10 && cuts == 0 {
			cuts++
			return 10000
		}
		return -1
	}
	var sleeps []time.Duration
	res, err := Run(context.Background(), fs.client(t, testToken, &sleeps), baseOptions(t, filepath.Join(dir, "f.bin")))
	if err != nil {
		t.Fatal(err)
	}
	tr := fs.only()
	if !bytes.Equal(tr.uploads[0].data.Bytes(), data) || res.Files[0].SHA256 != sum(data) {
		t.Fatal("content differs")
	}
	if cuts != 1 || fs.count("HEAD ") != 2 || len(sleeps) != 1 {
		t.Errorf("cuts %d, HEAD %d, sleeps %v", cuts, fs.count("HEAD "), sleeps)
	}
	// Only the bytes after the cut were sent again.
	if got := tr.uploads[0].received; got != int64(len(data)) {
		t.Errorf("received %d bytes for %d", got, len(data))
	}
}

func TestCrashThenResume(t *testing.T) {
	for _, e2e := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "e2e"}[e2e], func(t *testing.T) {
			dir := t.TempDir()
			data := pattern(3<<20+5, 5)
			writeFile(t, filepath.Join(dir, "f.bin"), data)
			fs := newFakeServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			fs.afterPatch = func(*fakeUpload) { cancel() }
			o := baseOptions(t, filepath.Join(dir, "f.bin"))
			o.ChunkSize, o.E2E = 1<<20, e2e
			c := fs.client(t, testToken, nil)
			if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
				t.Fatalf("first run: %v", err)
			}
			if !fileExists(o.StatePath) {
				t.Fatal("state file removed after an interruption")
			}
			fs.afterPatch = nil
			hashed := false
			o.Progress = func(p Progress) { hashed = hashed || p.Phase == PhaseHash }
			res, err := Run(context.Background(), c, o)
			if err != nil {
				t.Fatal(err)
			}
			tr := fs.only()
			up := tr.uploads[0]
			if hashed || fs.count("POST "+transfersPath) != 2 || fs.count("GET "+transfersPath+"/") < 2 {
				t.Errorf("hashed %v, requests %q", hashed, fs.requests)
			}
			if fs.count("POST "+transfersPath+"/") != 1 { // a single finalize
				t.Errorf("requests %q", fs.requests)
			}
			if up.received != up.length {
				t.Errorf("received %d bytes for %d", up.received, up.length)
			}
			got := up.data.Bytes()
			if e2e {
				key, err := tte2.DecodeKey(res.Key)
				if err != nil {
					t.Fatal(err)
				}
				got = decrypt(t, got, key, 0)
			}
			if !bytes.Equal(got, data) {
				t.Error("content differs")
			}
		})
	}
}

func decrypt(t *testing.T, ct, key []byte, index int) []byte {
	t.Helper()
	r, err := tte2.NewReader(bytes.NewReader(ct), key, index)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func TestStateMismatchAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	writeFile(t, path, pattern(200<<10, 6))
	fs := newFakeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	fs.afterPatch = func(*fakeUpload) { cancel() }
	o := baseOptions(t, path)
	c := fs.client(t, testToken, nil)
	if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	fs.afterPatch = nil
	old := fs.only()
	data := pattern(150<<10, 7)
	writeFile(t, path, data)
	if _, err := Run(context.Background(), c, o); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v", err)
	}
	o.Restart = true
	if _, err := Run(context.Background(), c, o); err != nil {
		t.Fatal(err)
	}
	if !old.canceled || !bytes.Equal(fs.only().uploads[0].data.Bytes(), data) {
		t.Error("old transfer not canceled or new content wrong")
	}
	// Another state file with other options is refused.
	writeFile(t, o.StatePath, nil)
	if _, err := Run(context.Background(), c, o); err != nil { // Restart ignores an invalid state
		t.Fatal(err)
	}
	o.Restart = false
	writeFile(t, o.StatePath, []byte("{"))
	if _, err := Run(context.Background(), c, o); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("invalid state: %v", err)
	}
}

func TestOtherIdentityRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	writeFile(t, path, pattern(1000, 8))
	fs := newFakeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	fs.afterPatch = func(*fakeUpload) { cancel() }
	o := baseOptions(t, path)
	c := fs.client(t, testToken, nil)
	if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	o.Recipients = []string{"other@entity-a.example.com"}
	if _, err := Run(context.Background(), c, o); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v", err)
	}
	// Another list of files.
	o = baseOptions(t, path)
	o.StatePath = filepath.Join(dir, "s.json")
	st := &state{Version: stateVersion, IdempotencyKey: "k", Files: []fileState{{localFile: localFile{Path: path}}, {localFile: localFile{Path: path}}}}
	abs, _ := absolutePaths(o.Paths)
	o2, _ := o.normalize(c)
	st.Identity = identity(c.BaseURL(), abs, o2)
	if err := st.save(o.StatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), c, o); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestUnauthorizedStops(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("x"))
	fs := newFakeServer(t)
	o := baseOptions(t, filepath.Join(dir, "f"))
	_, err := Run(context.Background(), fs.client(t, "tt_wrongtoken0000000000", nil), o)
	var p *client.Problem
	if !errors.As(err, &p) || p.Status != http.StatusUnauthorized {
		t.Fatalf("got %v", err)
	}
	if len(fs.requests) != 1 || fileExists(o.StatePath) {
		t.Errorf("requests %q, state kept %v", fs.requests, fileExists(o.StatePath))
	}
}

func TestUnauthorizedOnPatchKeepsState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("xyz"))
	fs := newFakeServer(t)
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	}
	o := baseOptions(t, filepath.Join(dir, "f"))
	_, err := Run(context.Background(), fs.client(t, testToken, nil), o)
	if !isStatus(err, http.StatusUnauthorized) || fs.count("PATCH") != 1 || !fileExists(o.StatePath) {
		t.Fatalf("got %v, %q", err, fs.requests)
	}
}

func TestRetryAfter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), pattern(5000, 9))
	fs := newFakeServer(t)
	first := true
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == transfersPath && first {
			first = false
			w.Header().Set("Retry-After", "7")
			problem(w, http.StatusTooManyRequests, "rate-limited")
			return true
		}
		if r.Method == http.MethodPatch && fs.count("PATCH") == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	}
	var sleeps []time.Duration
	if _, err := Run(context.Background(), fs.client(t, testToken, &sleeps), baseOptions(t, filepath.Join(dir, "f"))); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sleeps, []time.Duration{7 * time.Second, 3 * time.Second}) {
		t.Errorf("sleeps %v", sleeps)
	}
}

func TestRejected(t *testing.T) {
	for _, outcome := range []string{"rejected", "infected"} {
		t.Run(outcome, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "a"), []byte("a"))
			writeFile(t, filepath.Join(dir, "b"), []byte("b"))
			fs := newFakeServer(t)
			fs.outcome, fs.scanPolls = outcome, 2
			o := baseOptions(t, filepath.Join(dir, "a"), filepath.Join(dir, "b"))
			res, err := Run(context.Background(), fs.client(t, testToken, nil), o)
			if !errors.Is(err, ErrRejected) || res == nil || res.Files[0].ScanStatus != "infected" {
				t.Fatalf("got %+v, %v", res, err)
			}
			if fileExists(o.StatePath) {
				t.Error("state file kept")
			}
		})
	}
}

func TestLinkOnlyAndNoWait(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.pdf"), pattern(2000, 10))
	fs := newFakeServer(t)
	o := baseOptions(t, filepath.Join(dir, "r.pdf"))
	o.Recipients, o.LinkOnly, o.NoWait = nil, true, true
	o.Password, o.MaxDownloads, o.Level, o.Language, o.DeleteAfterFirstDownload = "s3cret", 3, "internal", "fr", true
	res, err := Run(context.Background(), fs.client(t, testToken, nil), o)
	if err != nil {
		t.Fatal(err)
	}
	tr := fs.only()
	if res.Link != fs.srv.URL+"/d/dl_linkonly0123456789" || res.Status != statusScanning || fileExists(o.StatePath) {
		t.Errorf("result %+v", res)
	}
	q := tr.req
	if !q.LinkOnly || q.Recipients != nil || q.Password != "s3cret" || *q.MaxDownloads != 3 || q.ConfidentialityLevel != "internal" ||
		q.Language != "fr" || !q.DeleteAfterFirstDownload {
		t.Errorf("request %+v", q)
	}
	if fs.count("GET ") != 0 {
		t.Error("polled with NoWait")
	}
}

func TestE2E(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "docs")
	plains := [][]byte{pattern(2<<20+100, 11), {}, pattern(1<<20, 12)}
	paths := []string{filepath.Join(dir, "a.pdf"), filepath.Join(tree, "empty.txt"), filepath.Join(tree, "x", "c.zz9")}
	for i, p := range paths {
		writeFile(t, p, plains[i])
	}
	fs := newFakeServer(t)
	o := baseOptions(t, paths[0], tree)
	o.E2E, o.Message, o.Password, o.ChunkSize = true, "Le message secret", "pw", 1<<20
	res, err := Run(context.Background(), fs.client(t, testToken, nil), o)
	if err != nil {
		t.Fatal(err)
	}
	key, err := tte2.DecodeKey(res.Key)
	if err != nil {
		t.Fatal(err)
	}
	tr := fs.only()
	if !tr.req.EndToEndEncrypted || tr.req.Message != "" || tr.req.Password != "pw" {
		t.Fatalf("request %+v", tr.req)
	}
	if msg, err := tte2.OpenMessage(key, tr.req.EncryptedMessage); err != nil || msg != o.Message {
		t.Errorf("message %q, %v", msg, err)
	}
	want := []struct{ name, path, typ string }{{"a.pdf", "", "application/pdf"}, {"empty.txt", "docs", "text/plain"}, {"c.zz9", "docs/x", ""}}
	for i, d := range tr.req.Files {
		ct := tr.uploads[i].data.Bytes()
		if d.Name != e2eName(i) || d.MediaType != "" || d.Path != "" || d.Size != int64(len(ct)) ||
			d.Size != tte2.CiphertextSize(int64(len(plains[i])), tte2.DefaultChunkSize) || d.ExpectedSHA256 != sum(ct) {
			t.Errorf("declaration %d: %+v", i, d)
		}
		if !bytes.Equal(decrypt(t, ct, key, i), plains[i]) {
			t.Errorf("file %d: plaintext differs", i)
		}
		m, err := tte2.OpenMetadata(key, i, d.EncryptedMetadata)
		if err != nil {
			t.Fatal(err)
		}
		if m.Index != i || m.Count != 3 || m.Name != want[i].name || m.Path != want[i].path || m.Type != want[i].typ ||
			m.Size != int64(len(plains[i])) || m.SHA256 != sum(plains[i]) {
			t.Errorf("metadata %d: %+v", i, m)
		}
		if r := res.Files[i]; r.Name != want[i].name || r.SHA256 != sum(plains[i]) || r.ScanStatus != "not_scanned_e2e" {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if tr.uploads[0].data.Len() < 3 || tr.uploads[0].data.Bytes()[0] != 'T' {
		t.Error("no TTE2 header")
	}
}

func TestE2EResumeOffsets(t *testing.T) {
	c := int64(tte2.DefaultChunkSize)
	for name, cutAt := range map[string]int64{
		"header":   10,
		"midChunk": tte2.HeaderSize + 1000,
		"boundary": tte2.ChunkOffset(1, tte2.DefaultChunkSize),
		"tag":      tte2.HeaderSize + c + 5,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			plain := pattern(int(2*c+777), 13)
			writeFile(t, filepath.Join(dir, "f"), plain)
			fs := newFakeServer(t)
			cut := false
			fs.cut = func(_ *fakeUpload, offset int64) int64 {
				if offset == 0 && !cut {
					cut = true
					return cutAt
				}
				return -1
			}
			o := baseOptions(t, filepath.Join(dir, "f"))
			o.E2E, o.ChunkSize = true, 64<<20
			res, err := Run(context.Background(), fs.client(t, testToken, nil), o)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := tte2.DecodeKey(res.Key)
			up := fs.only().uploads[0]
			if !cut || up.received != up.length || !bytes.Equal(decrypt(t, up.data.Bytes(), key, 0), plain) {
				t.Errorf("cut %v, received %d/%d", cut, up.received, up.length)
			}
		})
	}
}

func TestModifiedBetweenHashAndUpload(t *testing.T) {
	for _, tc := range []struct {
		name     string
		e2e      bool
		sameSize bool
	}{{"plainSize", false, false}, {"plainSameSize", false, true}, {"e2eSameSize", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "f")
			data := pattern(1<<20+10, 14)
			writeFile(t, path, data)
			info, _ := os.Stat(path)
			fs := newFakeServer(t)
			o := baseOptions(t, path)
			o.E2E = tc.e2e
			done := false
			fs.hook = func(_ http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodPost || r.URL.Path != transfersPath || done {
					return false
				}
				done = true
				changed := slices.Clone(data)
				if !tc.sameSize {
					changed = append(changed, 1)
				}
				changed[len(changed)-1] ^= 0xff
				writeFile(t, path, changed)
				if tc.sameSize {
					_ = os.Chtimes(path, info.ModTime(), info.ModTime())
				}
				return false
			}
			_, err := Run(context.Background(), fs.client(t, testToken, nil), o)
			if !errors.Is(err, ErrStateMismatch) {
				t.Fatalf("got %v", err)
			}
			if !fileExists(o.StatePath) {
				t.Error("state removed: --restart could not cancel the transfer")
			}
			// Run gave up in the middle of a PATCH: wait for its handler to
			// end before reading what the server received.
			fs.settle()
			up := fs.only().uploads[0]
			fs.mu.Lock()
			offset, length := up.offset, up.length
			fs.mu.Unlock()
			if tc.e2e && offset >= length-int64(tte2.TagSize) {
				t.Errorf("the changed chunk was sent (%d of %d bytes)", offset, length)
			}
		})
	}
}

func TestGoneRemovesState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("abc"))
	fs := newFakeServer(t)
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusGone)
			return true
		}
		return false
	}
	o := baseOptions(t, filepath.Join(dir, "f"))
	_, err := Run(context.Background(), fs.client(t, testToken, nil), o)
	if !errors.Is(err, errGone) || fileExists(o.StatePath) {
		t.Fatalf("got %v", err)
	}
}

func TestUploadIncompleteThenFinalize(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), pattern(100<<10, 15))
	fs := newFakeServer(t)
	first := true
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/finalize") && first {
			first = false
			problem(w, http.StatusConflict, codeUploadIncomplete)
			return true
		}
		return false
	}
	if _, err := Run(context.Background(), fs.client(t, testToken, nil), baseOptions(t, filepath.Join(dir, "f"))); err != nil {
		t.Fatal(err)
	}
	if fs.count("HEAD") != 2 || fs.count("POST "+transfersPath+"/") != 2 {
		t.Errorf("requests %q", fs.requests)
	}
}

func TestFinalizeErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		check  func(error) bool
		kept   bool
	}{
		{http.StatusConflict, codeUploadIncomplete, func(err error) bool { return isStatus(err, http.StatusConflict) }, true},
		{http.StatusForbidden, "blocked-file", func(err error) bool { return isStatus(err, http.StatusForbidden) }, true},
		{http.StatusNotFound, "not-found", func(err error) bool { return errors.Is(err, errGone) }, false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "f"), []byte("abc"))
			fs := newFakeServer(t)
			fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if strings.HasSuffix(r.URL.Path, "/finalize") {
					problem(w, tc.status, tc.code)
					return true
				}
				return false
			}
			o := baseOptions(t, filepath.Join(dir, "f"))
			_, err := Run(context.Background(), fs.client(t, testToken, nil), o)
			if !tc.check(err) || fileExists(o.StatePath) != tc.kept {
				t.Fatalf("got %v, kept %v", err, fileExists(o.StatePath))
			}
		})
	}
}

func TestResumeAfterLostFinalize(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("abc"))
	fs := newFakeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	fs.hook = func(_ http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/finalize") {
			fs.finalize(httptest.NewRecorder(), strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, transfersPath+"/"), "/finalize"))
			cancel()
			<-r.Context().Done()
			return true
		}
		return false
	}
	o := baseOptions(t, filepath.Join(dir, "f"))
	o.LinkOnly = true
	c := fs.client(t, testToken, nil)
	if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	fs.hook = nil
	var warnings []string
	o.Warn = func(s string) { warnings = append(warnings, s) }
	res, err := Run(context.Background(), c, o)
	if err != nil || res.Link != "" || len(warnings) != 1 {
		t.Fatalf("got %+v, %v, %q", res, err, warnings)
	}
}

func TestResumeTransferGone(t *testing.T) {
	for _, status := range []string{"missing", statusExpired} {
		t.Run(status, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "f"), []byte("abc"))
			fs := newFakeServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			fs.afterPatch = func(*fakeUpload) { cancel() }
			o := baseOptions(t, filepath.Join(dir, "f"))
			c := fs.client(t, testToken, nil)
			if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			tr := fs.only()
			fs.mu.Lock()
			if status == "missing" {
				delete(fs.transfers, tr.id)
			} else {
				tr.status = status
			}
			fs.mu.Unlock()
			if _, err := Run(context.Background(), c, o); !errors.Is(err, errGone) || fileExists(o.StatePath) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestOptionsValidation(t *testing.T) {
	fs := newFakeServer(t)
	c := fs.client(t, testToken, nil)
	anon := fs.client(t, "", nil)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("x"))
	for name, mod := range map[string]func(*Options){
		"noPaths":   func(o *Options) { o.Paths = nil },
		"expiry":    func(o *Options) { o.ExpiryDays = 3 },
		"noRcpt":    func(o *Options) { o.Recipients = nil },
		"noSender":  func(o *Options) { o.Sender = "" },
		"chunk":     func(o *Options) { o.ChunkSize = -1 },
		"emptyPw":   func(o *Options) { o.HasPassword = true },
		"longPw":    func(o *Options) { o.Password = strings.Repeat("p", 1025) },
		"maxDl":     func(o *Options) { o.MaxDownloads = 1001 },
		"verifyLo":  func(o *Options) { o.LinkOnly, o.VerifyRecipients = true, true },
		"level":     func(o *Options) { o.Level = "Bad Level" },
		"message":   func(o *Options) { o.Message = strings.Repeat("m", 20001) },
		"missing":   func(o *Options) { o.Paths = []string{filepath.Join(dir, "nope")} },
		"emptyDir":  func(o *Options) { o.Paths = []string{t.TempDir()} },
		"e2eLongMs": func(o *Options) { o.E2E, o.Message = true, strings.Repeat("m", 5001) },
	} {
		t.Run(name, func(t *testing.T) {
			o := baseOptions(t, filepath.Join(dir, "f"))
			mod(&o)
			if _, err := Run(context.Background(), c, o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Without a token, no sender is needed (it is refused by the server
	// here); the default state path is in the working directory.
	t.Chdir(t.TempDir())
	o := baseOptions(t, filepath.Join(dir, "f"))
	o.Sender, o.StatePath = "", ""
	if _, err := Run(context.Background(), anon, o); !isStatus(err, http.StatusUnauthorized) {
		t.Fatalf("got %v", err)
	}
	if m, _ := filepath.Glob(StatePrefix + "*"); len(m) != 0 {
		t.Errorf("state files left: %v", m)
	}
}

func TestDefaultStatePathResume(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("abc"))
	t.Chdir(t.TempDir())
	fs := newFakeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	fs.afterPatch = func(*fakeUpload) { cancel() }
	o := baseOptions(t, filepath.Join(dir, "f"))
	o.StatePath = ""
	c := fs.client(t, testToken, nil)
	if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(StatePrefix + "*.json")
	if len(m) != 1 || len(m[0]) != len(StatePrefix)+64+len(".json") {
		t.Fatalf("state files %v", m)
	}
	fs.afterPatch = nil
	if _, err := Run(context.Background(), c, o); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(StatePrefix + "*"); len(m) != 0 {
		t.Errorf("state files left: %v", m)
	}
}

// TestMemoryBounded streams a 256 MiB file with end-to-end encryption and
// checks that the heap does not grow with the file.
func TestMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("256 MiB stream")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "big")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const size = 256 << 20
	if err := f.Truncate(size); err != nil { // sparse: zeros
		t.Fatal(err)
	}
	_ = f.Close()
	fs := newFakeServer(t)
	fs.keep = false
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var mu sync.Mutex
	var peak uint64
	o := baseOptions(t, path)
	o.E2E, o.ChunkSize = true, 32<<20
	samples := 0
	o.Progress = func(Progress) {
		samples++
		if samples%16 != 0 {
			return
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		mu.Lock()
		peak = max(peak, m.HeapInuse)
		mu.Unlock()
	}
	if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); err != nil {
		t.Fatal(err)
	}
	up := fs.only().uploads[0]
	if up.received != tte2.CiphertextSize(size, tte2.DefaultChunkSize) {
		t.Fatalf("received %d", up.received)
	}
	if growth := int64(peak) - int64(before.HeapInuse); growth > 64<<20 {
		t.Errorf("heap grew by %d MiB", growth>>20)
	}
}
