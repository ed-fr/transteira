package upload

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/tte2"
)

// oneFile writes a file of n bytes and returns options sending it.
func oneFile(t *testing.T, n int) (Options, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.bin")
	writeFile(t, path, pattern(n, 20))
	return baseOptions(t, path), path
}

// runHook runs a deposit of a file of n bytes on a fake server whose
// hook is h, and returns its error.
func runHook(t *testing.T, n int, h func(w http.ResponseWriter, r *http.Request) bool) error {
	t.Helper()
	o, _ := oneFile(t, n)
	fs := newFakeServer(t)
	fs.hook = h
	_, err := Run(context.Background(), fs.client(t, testToken, nil), o)
	return err
}

func skipUnlessUnixUser(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
}

func TestCollectSpecialAndErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a"), []byte("a"))
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no Unix sockets:", err)
	}
	defer func() { _ = l.Close() }()
	var warnings []string
	files, err := collect([]string{dir}, func(s string) { warnings = append(warnings, s) })
	if err != nil || len(files) != 1 || len(warnings) != 1 || !strings.Contains(warnings[0], "not a regular file") {
		t.Fatalf("files %v, warnings %q, %v", files, warnings, err)
	}
	skipUnlessUnixUser(t)
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(locked, "x"), []byte("x"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(locked, 0o700) }()
	if _, err := collect([]string{dir}, func(string) {}); err == nil {
		t.Fatal("unreadable directory accepted")
	}
}

func TestFolderOfAndMediaType(t *testing.T) {
	sep := string(filepath.Separator)
	if got := folderOf(sep, sep+"x"); got != "" {
		t.Errorf("root: %q", got)
	}
	if got := folderOf(sep+"a", sep+"a"+sep+"d"+sep+"e"+sep+"x"); got != "d/e" {
		t.Errorf("got %q", got)
	}
	if mediaType("x.txt") != "text/plain" || mediaType("x") != "" {
		t.Error("media type")
	}
}

func TestNormalizeDefaults(t *testing.T) {
	fs := newFakeServer(t)
	o, err := Options{Paths: []string{"x"}, Recipients: []string{"r@example.com"}, Sender: "s@example.com", ExpiryDays: 1}.normalize(fs.client(t, testToken, nil))
	if err != nil || o.ChunkSize != DefaultChunkSize || o.PollInterval != DefaultPollInterval || o.HasPassword {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestProgressReaderAndEOF(t *testing.T) {
	p := &progressReader{r: strings.NewReader("abc")}
	if p.close() != nil {
		t.Fatal("error")
	}
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, errBodyClosed) {
		t.Fatalf("got %v", err)
	}
	boom := errors.New("boom")
	p = &progressReader{r: iotest.ErrReader(boom)}
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, boom) || !errors.Is(p.close(), boom) {
		t.Fatal("error not kept")
	}
	if err := atEOF(iotest.ErrReader(boom), "f"); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if err := atEOF(strings.NewReader("x"), "f"); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v", err)
	}
	if err := readError("f", boom); !errors.Is(err, boom) || errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestHashE2EErrors(t *testing.T) {
	key, _ := tte2.NewKey()
	h, _ := tte2.NewHeader(tte2.DefaultChunkSize)
	cc, _ := tte2.NewChunkCipher(key, 0, h)
	fs := &fileState{localFile: localFile{Path: t.TempDir(), Size: 1 << 62}, ChunkSize: h.ChunkSize, Salt: h.Salt[:]}
	if err := hashE2E(context.Background(), fs, cc, nil); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
	// A directory: open works, read fails.
	fs.Size = 10
	if err := hashE2E(context.Background(), fs, cc, nil); err == nil || errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v", err)
	}
	fs.Path = filepath.Join(fs.Path, "missing")
	if err := hashE2E(context.Background(), fs, cc, nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
	st := &state{Key: key, Files: []fileState{{ChunkSize: 3}}}
	if _, err := st.cipher(0); err == nil {
		t.Fatal("invalid header accepted")
	}
}

// TestChangedDuringHash changes the file once the hash pass announced it,
// before it is opened.
func TestChangedDuringHash(t *testing.T) {
	for _, tc := range []struct {
		name   string
		e2e    bool
		change func(path string, data []byte)
		want   error
	}{
		{"plainGrew", false, func(p string, d []byte) { writeRaw(p, append(d, 1)) }, ErrStateMismatch},
		{"plainTouched", false, func(p string, _ []byte) { touch(p) }, ErrStateMismatch},
		{"e2eGrew", true, func(p string, d []byte) { writeRaw(p, append(d, 1)) }, ErrStateMismatch},
		{"e2eShrank", true, func(p string, d []byte) { writeRaw(p, d[:len(d)-1]) }, ErrStateMismatch},
		{"e2eTouched", true, func(p string, _ []byte) { touch(p) }, ErrStateMismatch},
		{"plainRemoved", false, func(p string, _ []byte) { _ = os.Remove(p) }, os.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, path := oneFile(t, 1000)
			data, _ := os.ReadFile(path)
			o.E2E = tc.e2e
			o.Progress = func(p Progress) {
				if p.Phase == PhaseHash && p.Done == 0 {
					tc.change(path, data)
				}
			}
			fs := newFakeServer(t)
			if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func writeRaw(path string, data []byte) { _ = os.WriteFile(path, data, 0o600) }

func touch(path string) {
	later := time.Now().Add(time.Hour)
	_ = os.Chtimes(path, later, later)
}

func TestCanceledDuringHash(t *testing.T) {
	o, _ := oneFile(t, 1000)
	ctx, cancel := context.WithCancel(context.Background())
	o.Progress = func(Progress) { cancel() }
	fs := newFakeServer(t)
	if _, err := Run(ctx, fs.client(t, testToken, nil), o); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestRandomFailures(t *testing.T) {
	boom := errors.New("no entropy")
	defer func() { newKey, newHeader = tte2.NewKey, tte2.NewHeader }()
	newKey = func() ([]byte, error) { return nil, boom }
	fs := newFakeServer(t)
	o, _ := oneFile(t, 10)
	o.E2E = true
	if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	newKey = tte2.NewKey
	newHeader = func(int) (tte2.Header, error) { return tte2.Header{}, boom }
	if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestStateValidateAndLoad(t *testing.T) {
	key, _ := tte2.NewKey()
	good := func() *state {
		return &state{Version: stateVersion, IdempotencyKey: "k", Key: key, Files: []fileState{{
			localFile: localFile{Path: "/x", Size: 10}, Salt: make([]byte, tte2.SaltSize), ChunkSize: tte2.DefaultChunkSize,
			CipherSize: tte2.CiphertextSize(10, tte2.DefaultChunkSize), ChunkDigests: make([]byte, 32), Metadata: "m",
		}}}
	}
	if err := good().validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*state){
		"version": func(s *state) { s.Version = 2 },
		"key":     func(s *state) { s.Key = []byte{1} },
		"size":    func(s *state) { s.Files[0].Size = -1 },
		"salt":    func(s *state) { s.Files[0].Salt = nil },
	} {
		s := good()
		mod(s)
		if s.validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	writeFile(t, file, []byte("{}"))
	if _, err := loadState(filepath.Join(file, "x")); err == nil || errors.Is(err, ErrStateMismatch) {
		t.Errorf("got %v", err)
	}
	if runtime.GOOS != "windows" {
		if _, err := loadState(dir); err == nil {
			t.Error("directory accepted")
		}
	}
	defer func(n int) { maxStateBytes = n }(maxStateBytes)
	maxStateBytes = 1
	if _, err := loadState(file); !errors.Is(err, ErrStateMismatch) {
		t.Errorf("got %v", err)
	}
	// save: missing directory, rename over a non-empty directory.
	if err := good().save(filepath.Join(dir, "missing", "s.json")); err == nil {
		t.Error("saved in a missing directory")
	}
	full := filepath.Join(dir, "full")
	writeFile(t, filepath.Join(full, "x"), nil)
	if err := good().save(full); err == nil {
		t.Error("saved over a directory")
	}
	if err := removeState(full); err == nil {
		t.Error("removed a non-empty directory")
	}
}

func TestRestartErrors(t *testing.T) {
	o, _ := oneFile(t, 10)
	fs := newFakeServer(t)
	c := fs.client(t, testToken, nil)
	// A state path that cannot be removed.
	o.Restart = true
	o.StatePath = t.TempDir()
	writeFile(t, filepath.Join(o.StatePath, "x"), nil)
	var warnings []string
	o.Warn = func(s string) { warnings = append(warnings, s) }
	if _, err := Run(context.Background(), c, o); err == nil || len(warnings) != 1 {
		t.Fatalf("got %v, %q", err, warnings)
	}
	// A cancellation refused.
	o, _ = oneFile(t, 10)
	ctx, cancel := context.WithCancel(context.Background())
	fs.afterPatch = func(*fakeUpload) { cancel() }
	if _, err := Run(ctx, c, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	fs.afterPatch = nil
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete {
			problem(w, http.StatusForbidden, "ip-not-allowed")
			return true
		}
		return false
	}
	o.Restart = true
	if _, err := Run(context.Background(), c, o); !isStatus(err, http.StatusForbidden) {
		t.Fatalf("got %v", err)
	}
}

func TestStateWriteFailures(t *testing.T) {
	// The state cannot be written before the creation.
	o, _ := oneFile(t, 10)
	o.StatePath = filepath.Join(t.TempDir(), "missing", "s.json")
	fs := newFakeServer(t)
	if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); err == nil || len(fs.requests) != 0 {
		t.Fatalf("got %v, %q", err, fs.requests)
	}
	// The state cannot be written after the creation or the finalization.
	for _, after := range []string{"create", "finalize"} {
		t.Run(after, func(t *testing.T) {
			o, _ := oneFile(t, 10)
			fs := newFakeServer(t)
			fs.hook = func(_ http.ResponseWriter, r *http.Request) bool {
				if (after == "create" && r.URL.Path == transfersPath) || (after == "finalize" && strings.HasSuffix(r.URL.Path, "/finalize")) {
					_ = os.Remove(o.StatePath)
					writeFile(t, filepath.Join(o.StatePath, "x"), nil)
				}
				return false
			}
			if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); err == nil || !strings.Contains(err.Error(), "state file") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestServerAnswers(t *testing.T) {
	for _, tc := range []struct {
		name string
		hook func(w http.ResponseWriter, r *http.Request) bool
		want string
	}{
		{"filesMismatch", func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != transfersPath {
				return false
			}
			writeJSON(w, http.StatusCreated, transfer{ID: "trf_1"})
			return true
		}, "unexpected answer"},
		{"noUploadURL", func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != transfersPath {
				return false
			}
			writeJSON(w, http.StatusCreated, transfer{ID: "trf_1", Status: statusUploading, Files: []senderFile{{Name: "f"}}})
			return true
		}, "no upload URL"},
		{"foreignUploadURL", func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != transfersPath {
				return false
			}
			writeJSON(w, http.StatusCreated, transfer{ID: "trf_1", Status: statusUploading, Files: []senderFile{{UploadURL: "https://other.example.com/u"}}})
			return true
		}, client.ErrForeignOrigin.Error()},
		{"headNoOffset", func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodHead {
				return false
			}
			w.WriteHeader(http.StatusOK)
			return true
		}, "invalid Upload-Offset"},
		{"headOtherLength", func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodHead {
				return false
			}
			w.Header().Set("Upload-Offset", "0")
			w.Header().Set("Upload-Length", "1")
			w.WriteHeader(http.StatusOK)
			return true
		}, "another size"},
		{"patchNoOffset", func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodPatch {
				return false
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
			return true
		}, "invalid Upload-Offset"},
		{"patchNoProgress", func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodPatch {
				return false
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Upload-Offset", "0")
			w.WriteHeader(http.StatusNoContent)
			return true
		}, "did not store any byte"},
		{"pollGone", func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodGet {
				return false
			}
			problem(w, http.StatusNotFound, "not-found")
			return true
		}, errGone.Error()},
		{"pollExpired", func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodGet {
				return false
			}
			writeJSON(w, http.StatusOK, transfer{ID: "trf_1", Status: statusExpired})
			return true
		}, "status expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runHook(t, 100, tc.hook)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestPatchFailuresThenHead(t *testing.T) {
	// A pause that fails stops the upload.
	o, _ := oneFile(t, 100)
	fs := newFakeServer(t)
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	}
	stop := errors.New("stop")
	c := clientWithSleep(t, fs, func(context.Context, time.Duration) error { return stop })
	if _, err := Run(context.Background(), c, o); !errors.Is(err, stop) {
		t.Fatalf("got %v", err)
	}
	// A HEAD failing after a failed PATCH.
	heads := 0
	fs.hook = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.Method {
		case http.MethodPatch:
			w.WriteHeader(http.StatusConflict)
			return true
		case http.MethodHead:
			heads++
			if heads > 1 {
				w.WriteHeader(http.StatusForbidden)
				return true
			}
		}
		return false
	}
	o.Restart = true
	if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !isStatus(err, http.StatusForbidden) {
		t.Fatalf("got %v", err)
	}
}

func clientWithSleep(t *testing.T, fs *fakeServer, sleep func(context.Context, time.Duration) error) *client.Client {
	t.Helper()
	c := fs.client(t, testToken, nil)
	pool := c.HTTPClient().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c, err := client.New(client.Config{URL: fs.srv.URL, Token: testToken}, client.WithRootCAs(pool), client.WithSleep(sleep))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUploadErrorsOnFile(t *testing.T) {
	t.Run("removed", func(t *testing.T) {
		o, path := oneFile(t, 100)
		fs := newFakeServer(t)
		fs.hook = func(_ http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == transfersPath {
				_ = os.Remove(path)
			}
			return false
		}
		if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		skipUnlessUnixUser(t)
		o, path := oneFile(t, 100)
		fs := newFakeServer(t)
		fs.hook = func(_ http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == transfersPath {
				_ = os.Chmod(path, 0)
			}
			return false
		}
		if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("truncatedDuringE2E", func(t *testing.T) {
		o, path := oneFile(t, 3<<20)
		o.E2E, o.ChunkSize = true, 1<<20
		info, _ := os.Stat(path)
		fs := newFakeServer(t)
		fs.afterPatch = func(*fakeUpload) {
			_ = os.Truncate(path, 1<<20+100)
			_ = os.Chtimes(path, info.ModTime(), info.ModTime())
		}
		if _, err := Run(context.Background(), fs.client(t, testToken, nil), o); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSealReaderBeyondStream(t *testing.T) {
	key, _ := tte2.NewKey()
	h, _ := tte2.NewHeader(tte2.DefaultChunkSize)
	cc, _ := tte2.NewChunkCipher(key, 0, h)
	fs := &fileState{Size: 10, ChunkSize: h.ChunkSize}
	end := tte2.ChunkOffset(1, h.ChunkSize)
	r := &sealReader{cc: cc, fs: fs, count: 1, pos: end, end: end + 1}
	if _, err := r.Read(make([]byte, 1)); err == nil {
		t.Fatal("read beyond the stream")
	}
}

func TestWaitCanceled(t *testing.T) {
	o, _ := oneFile(t, 10)
	o.PollInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	o.Progress = func(p Progress) {
		if p.Phase == PhaseScan {
			cancel()
		}
	}
	fs := newFakeServer(t)
	if _, err := Run(ctx, fs.client(t, testToken, nil), o); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
