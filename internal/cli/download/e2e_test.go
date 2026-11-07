package download

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/tte2"
)

// e2eFake returns a fake encrypted transfer of the given plaintexts, with
// the folders and names given as "path/name" (no slash: root).
func e2eFake(t *testing.T, key []byte, names []string, plains [][]byte) *fake {
	t.Helper()
	files := make([]*fakeFile, len(plains))
	for i, p := range plains {
		path, name := "", names[i]
		if j := strings.LastIndexByte(name, '/'); j >= 0 {
			path, name = name[:j], name[j+1:]
		}
		files[i] = sealedFile(t, key, i, len(plains), path, name, p)
	}
	f := newFake(t, files...)
	f.e2e = true
	return f
}

func TestE2ERoundTrip(t *testing.T) {
	key, enc := newKey(t)
	a, b, c := pattern("a", 3*testChunk+100), pattern("b", 2*testChunk), []byte{}
	f := e2eFake(t, key, []string{"plans/v3/a.pdf", "b.mp4", "plans/empty"}, [][]byte{a, b, c})
	msg, err := tte2.SealMessage(key, "Budget\u202e files\r\nas agreed")
	if err != nil {
		t.Fatal(err)
	}
	f.encMsg = msg
	res, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc, FromFragment: true}, Archive: false})
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, out); !slices.Equal(got, []string{"b.mp4", "plans/empty", "plans/v3/a.pdf"}) {
		t.Errorf("files = %v", got)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "plans", "v3", "a.pdf")), a) || !bytes.Equal(readFile(t, filepath.Join(out, "b.mp4")), b) {
		t.Error("content differs")
	}
	if !res.EndToEnd || res.Message != "Budget files\nas agreed" || res.Files[0].SHA256 != hexSHA(a) ||
		res.Files[0].Size != int64(len(a)) || res.Files[0].ScanStatus != "not_scanned_e2e" {
		t.Errorf("result = %+v", res)
	}
	for _, r := range f.log() {
		if strings.Contains(r, enc) {
			t.Errorf("key sent: %s", r)
		}
	}
}

func TestE2EKeyPrompt(t *testing.T) {
	key, enc := newKey(t)
	f := e2eFake(t, key, []string{"a"}, [][]byte{[]byte("x")})
	f.password = "pw"
	asked := 0
	_, out, err := run(t, f, Options{
		Key: func() (string, error) {
			asked++
			return "https://h.example.com/d/" + testToken + "#k=" + enc + "\n", nil
		},
		Password: func() (string, error) { return "pw", nil },
	})
	if err != nil || asked != 1 {
		t.Fatalf("err = %v, asked %d", err, asked)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a")), []byte("x")) {
		t.Error("content differs")
	}
	// No key and no prompt: refused before the password is asked.
	_, _, err = run(t, f, Options{Password: func() (string, error) { t.Error("password asked"); return "", nil }})
	if !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("err = %v", err)
	}
	boom := errors.New("boom")
	if _, _, err := run(t, f, Options{Password: func() (string, error) { return "pw", nil }, Key: func() (string, error) { return "", boom }}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	for _, bad := range []string{"short", "https://h/d/x#k=short"} {
		_, _, err := run(t, f, Options{Password: func() (string, error) { return "pw", nil }, Key: func() (string, error) { return bad, nil }})
		if !errors.Is(err, ErrWrongKey) {
			t.Fatalf("%q: err = %v", bad, err)
		}
	}
}

func TestE2EArchiveRefused(t *testing.T) {
	key, enc := newKey(t)
	f := e2eFake(t, key, []string{"a"}, [][]byte{[]byte("x")})
	f.password = "pw"
	_, _, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Archive: true, Password: func() (string, error) { return "pw", nil }})
	if !errors.Is(err, ErrArchiveE2E) {
		t.Fatalf("err = %v", err)
	}
	if got := f.log(); len(got) != 1 {
		t.Errorf("requests = %v", got)
	}
}

func TestE2EWrongKey(t *testing.T) {
	key, _ := newKey(t)
	_, other := newKey(t)
	f := e2eFake(t, key, []string{"a", "b"}, [][]byte{[]byte("x"), []byte("y")})
	_, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: other}})
	if !errors.Is(err, ErrWrongKey) || strings.Contains(err.Error(), other) {
		t.Fatalf("err = %v", err)
	}
	if got := listDir(t, out); len(got) != 0 {
		t.Errorf("files = %v", got)
	}
}

// TestE2ENoFile refuses an encrypted transfer listing no file, whatever
// the key: a sender always seals one, and nothing could check the key.
func TestE2ENoFile(t *testing.T) {
	key, _ := newKey(t)
	_, other := newKey(t)
	g := e2eFake(t, key, nil, nil)
	g.encMsg, _ = tte2.SealMessage(key, "hi")
	for _, k := range []string{other, mustEncode(t, key)} {
		if _, _, err := run(t, g, Options{Link: Link{Token: testToken, Key: k}}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("no file: %v", err)
		}
	}
	if got := g.log(); len(got) != 2 {
		t.Errorf("requests = %v", got)
	}
}

func mustEncode(t *testing.T, key []byte) string {
	t.Helper()
	s, err := tte2.EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestE2EAlteredTransfer(t *testing.T) {
	key, enc := newKey(t)
	plains := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	names := []string{"1", "2", "3"}
	link := Link{Token: testToken, Key: enc}
	cases := map[string]func(f *fake){
		"swapped":      func(f *fake) { f.files[0], f.files[1] = f.files[1], f.files[0] },
		"removed":      func(f *fake) { f.files = f.files[:2] },
		"missing meta": func(f *fake) { f.files[2].meta = "" },
		"tampered msg": func(f *fake) { f.encMsg = "AQ" + strings.Repeat("A", 40) },
		"foreign message": func(f *fake) {
			_, other := newKey(t)
			k, _ := tte2.DecodeKey(other)
			f.encMsg, _ = tte2.SealMessage(k, "x")
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			f := e2eFake(t, key, names, plains)
			alter(f)
			_, out, err := run(t, f, Options{Link: link})
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("err = %v", err)
			}
			if got := listDir(t, out); len(got) != 0 {
				t.Errorf("files = %v", got)
			}
		})
	}
	// Count disagreeing with the list: one more file sealed for a
	// transfer of 4 added to a transfer of 3.
	f := e2eFake(t, key, names, plains)
	f.files = append(f.files, sealedFile(t, key, 3, 4, "", "4", []byte("four")))
	if _, _, err := run(t, f, Options{Link: link}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("count: %v", err)
	}
}

func TestE2EHostileNames(t *testing.T) {
	key, enc := newKey(t)
	names := []string{"../../evil", "CON", "/etc/passwd", "dup", "DUP", "a:b", "x/../../y", ".dup.part"}
	plains := make([][]byte, len(names))
	for i := range plains {
		plains[i] = []byte(fmt.Sprint(i))
	}
	f := e2eFake(t, key, nil, nil)
	for i, n := range names {
		f.files = append(f.files, sealedFile(t, key, i, len(names), "", n, plains[i]))
	}
	// Paths inside the metadata are attacker-controlled too.
	f.files[6] = sealedFile(t, key, 6, len(names), "../../x", "y", plains[6])
	parent := t.TempDir()
	out := filepath.Join(parent, "out")
	res, _, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, parent); len(got) != len(names) {
		t.Errorf("files = %v", got)
	}
	seen := map[string]bool{}
	for i, r := range res.Files {
		rel, err := filepath.Rel(out, r.Path)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) || seen[strings.ToLower(rel)] {
			t.Errorf("unsafe path %q", r.Path)
		}
		seen[strings.ToLower(rel)] = true
		if !bytes.Equal(readFile(t, r.Path), plains[i]) {
			t.Errorf("%q: content differs", r.Path)
		}
		if base := filepath.Base(rel); strings.EqualFold(base, "CON") || strings.ContainsAny(base, ":") {
			t.Errorf("reserved name %q", rel)
		}
	}
}

func TestE2ETampered(t *testing.T) {
	key, enc := newKey(t)
	plain := pattern("t", 3*testChunk+7)
	link := Link{Token: testToken, Key: enc}
	cases := map[string]func(ff *fakeFile){
		"flipped chunk": func(ff *fakeFile) { ff.data[tte2.HeaderSize+testChunk+20] ^= 1 },
		"bad header":    func(ff *fakeFile) { ff.data[0] = 'X' },
		"other salt":    func(ff *fakeFile) { ff.data[20] ^= 1 },
		"truncated":     func(ff *fakeFile) { ff.data = ff.data[:len(ff.data)-(testChunk+tte2.TagSize)] },
		"chunk dropped": func(ff *fakeFile) {
			ff.data = slices.Delete(slices.Clone(ff.data), tte2.HeaderSize, tte2.HeaderSize+testChunk+tte2.TagSize)
		},
		"invalid size":   func(ff *fakeFile) { ff.data = ff.data[:len(ff.data)-3] },
		"listed shorter": func(ff *fakeFile) { ff.listedSize = int64(len(ff.data)) - 1 },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
			alter(f.files[0])
			f.files[0].sha = ""
			_, out, err := run(t, f, Options{Link: link})
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("err = %v", err)
			}
			if got := listDir(t, out); len(got) != 0 {
				t.Errorf("files = %v", got)
			}
		})
	}
}

func TestE2ETruncatedStream(t *testing.T) {
	// The connection is cut for good: the part file stays for a later run.
	key, enc := newKey(t)
	plain := pattern("t", 3*testChunk)
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
	f.shortBody[f.files[0].id] = int64(tte2.HeaderSize + testChunk + tte2.TagSize + 10)
	f.fail = func(path string) int {
		if strings.Contains(path, "/files/") && len(f.requests) > 2 {
			return 404
		}
		return 0
	}
	_, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}})
	if err == nil {
		t.Fatal("accepted")
	}
	if got := listDir(t, out); !slices.Equal(got, []string{".a.bin.part"}) {
		t.Fatalf("files = %v", got)
	}
	if fi, _ := os.Stat(filepath.Join(out, ".a.bin.part")); fi.Size() != testChunk {
		t.Errorf("part size %d", fi.Size())
	}
	f.set(func() { f.fail = nil; delete(f.shortBody, f.files[0].id) })
	if _, _, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Output: out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), plain) {
		t.Error("content differs")
	}
}

func TestE2EResume(t *testing.T) {
	key, enc := newKey(t)
	odd, even := pattern("r", 5*testChunk+333), pattern("e", 3*testChunk)
	cases := map[string]struct {
		plain []byte
		have  int
	}{
		"boundary":          {odd, 2 * testChunk},
		"mid-chunk":         {odd, 2*testChunk + 100},
		"complete":          {odd, len(odd)},
		"complete boundary": {even, len(even)},
		"longer":            {odd, len(odd) + 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := e2eFake(t, key, []string{"a.bin"}, [][]byte{c.plain})
			out := t.TempDir()
			prefix := append(slices.Clone(c.plain), 'x')
			if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), prefix[:c.have], 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Output: out}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), c.plain) {
				t.Error("content differs")
			}
			files := apiPrefix + testToken + "/files/" + f.files[0].id
			k := int64(c.have / testChunk)
			want := []string{"GET " + files + " " + headerRange}
			switch {
			case c.have > len(c.plain):
				want = []string{"GET " + files}
			case int(k)*testChunk < len(c.plain):
				want = append(want, fmt.Sprintf("GET %s bytes=%d-", files, tte2.ChunkOffset(k, testChunk)))
			}
			if log := f.log()[1:]; !slices.Equal(log, want) {
				t.Errorf("requests = %v, want %v", log, want)
			}
		})
	}
}

func TestE2EResumeCorruptedPart(t *testing.T) {
	key, enc := newKey(t)
	plain := pattern("r", 3*testChunk)
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), make([]byte, testChunk), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Output: out}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
	if got := listDir(t, out); len(got) != 0 {
		t.Errorf("files = %v", got)
	}
}

func TestE2EResumeInProcess(t *testing.T) {
	key, enc := newKey(t)
	plain := pattern("p", 4*testChunk+1)
	for name, cut := range map[string]int64{"in header": 10, "mid chunk": tte2.HeaderSize + testChunk + 5} {
		t.Run(name, func(t *testing.T) {
			f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
			f.cut[f.files[0].id] = cut
			_, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), plain) {
				t.Error("content differs")
			}
		})
	}
}

func TestE2ERangeIgnored(t *testing.T) {
	key, enc := newKey(t)
	plain := pattern("i", 3*testChunk+9)
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
	f.ignoreRange = true
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), plain[:testChunk+3], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Output: out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), plain) {
		t.Error("content differs")
	}
	// The stream changed since the part file was written (another header).
	g := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
	g.ignoreRange = true
	out2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(out2, ".a.bin.part"), plain[:testChunk+3], 0o644); err != nil {
		t.Fatal(err)
	}
	other := sealedFile(t, key, 0, 1, "", "a.bin", plain)
	g.fail = func(string) int {
		if len(g.requests) == 3 { // header read, then the full answer
			g.files[0].data = other.data
		}
		return 0
	}
	if _, _, err := run(t, g, Options{Link: Link{Token: testToken, Key: enc}, Output: out2}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
}

// TestE2EMemory decrypts a 256 MiB stream generated on the fly and checks
// that the heap stays bounded.
func TestE2EMemory(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("large stream, measured without -short and -race only")
	}
	const size = 256 << 20
	const chunk = tte2.DefaultChunkSize
	key, enc := newKey(t)
	gen := func(w io.Writer) {
		block := pattern("mem", chunk)
		for i := 0; i < size/chunk; i++ {
			block[0], block[1] = byte(i), byte(i>>8)
			if _, err := w.Write(block); err != nil {
				return
			}
		}
	}
	h := newHashWriter()
	gen(h)
	meta, err := tte2.SealMetadata(key, 0, tte2.Metadata{Index: 0, Count: 1, Name: "big.bin", Type: "x", Size: size, SHA256: h.hex()})
	if err != nil {
		t.Fatal(err)
	}
	ff := &fakeFile{
		id: "fil_big", name: "Encrypted file 1", scan: "not_scanned_e2e", meta: meta,
		listedSize: tte2.CiphertextSize(size, chunk), sha: strings.Repeat("0", 64),
		gen: func(w io.Writer) {
			tw, err := tte2.NewWriter(w, key, 0, tte2.WithChunkSize(chunk))
			if err != nil {
				return
			}
			gen(tw)
			_ = tw.Close()
		},
	}
	f := newFake(t, ff)
	f.e2e = true
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	})
	_, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}})
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(out, "big.bin")); err != nil || fi.Size() != size {
		t.Fatalf("result: %v", err)
	}
	if growth := int64(peak.Load()) - int64(base.HeapInuse); growth > 64<<20 {
		t.Errorf("heap grew by %d MiB", growth>>20)
	}
}

func TestRunCanceled(t *testing.T) {
	key, enc := newKey(t)
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{pattern("c", 2*testChunk)})
	f.cut[f.files[0].id] = 100
	ctx, cancel := context.WithCancel(context.Background())
	c := f.client(t)
	cancel()
	if _, err := Run(ctx, c, Options{Link: Link{Token: testToken, Key: enc}, Output: t.TempDir()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
