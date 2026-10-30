package zipstream

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/filename"
)

// pattern is a reader of size bytes repeating a short pattern that depends on
// seed, so that two entries never share their content.
type pattern struct {
	seed      byte
	remaining int64
	pos       int64
}

func newPattern(seed byte, size int64) *pattern { return &pattern{seed: seed, remaining: size} }

func (p *pattern) Read(b []byte) (int, error) {
	if p.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > p.remaining {
		b = b[:p.remaining]
	}
	for i := range b {
		b[i] = p.seed + byte((p.pos+int64(i))%251)
	}
	p.pos += int64(len(b))
	p.remaining -= int64(len(b))
	return len(b), nil
}

// patternBytes returns the full content of newPattern(seed, size).
func patternBytes(seed byte, size int64) []byte {
	b, _ := io.ReadAll(newPattern(seed, size))
	return b
}

// zeros is a reader of n zero bytes.
type zeros struct{ remaining int64 }

func (z *zeros) Read(b []byte) (int, error) {
	if z.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > z.remaining {
		b = b[:z.remaining]
	}
	clear(b)
	z.remaining -= int64(len(b))
	return len(b), nil
}

// counter discards what it receives and counts it.
type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// sparse records an archive in memory, storing long runs of zero bytes as a
// length only, and serves it back as an io.ReaderAt: archives of several GiB
// made of zero entries are then read back by archive/zip without storing them.
type sparse struct {
	segs []segment
	size int64
}

type segment struct {
	off   int64
	data  []byte // nil for a zero run
	zeros int64
}

func (s *segment) len() int64 {
	if s.data == nil {
		return s.zeros
	}
	return int64(len(s.data))
}

var zeroChunk = make([]byte, bufferSize)

func (s *sparse) Write(p []byte) (int, error) {
	var last *segment
	if len(s.segs) > 0 {
		last = &s.segs[len(s.segs)-1]
	}
	switch {
	case len(p) >= 1024 && len(p) <= len(zeroChunk) && bytes.Equal(p, zeroChunk[:len(p)]):
		if last != nil && last.data == nil {
			last.zeros += int64(len(p))
		} else {
			s.segs = append(s.segs, segment{off: s.size, zeros: int64(len(p))})
		}
	case last != nil && last.data != nil:
		last.data = append(last.data, p...)
	default:
		s.segs = append(s.segs, segment{off: s.size, data: append([]byte(nil), p...)})
	}
	s.size += int64(len(p))
	return len(p), nil
}

func (s *sparse) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= s.size {
			return n, io.EOF
		}
		i := sort.Search(len(s.segs), func(i int) bool { return s.segs[i].off+s.segs[i].len() > pos })
		seg := &s.segs[i]
		in := pos - seg.off
		var c int
		if seg.data == nil {
			c = int(min(seg.zeros-in, int64(len(p)-n)))
			clear(p[n : n+c])
		} else {
			c = copy(p[n:], seg.data[in:])
		}
		n += c
	}
	return n, nil
}

var stamp = time.Date(2026, 10, 21, 13, 37, 43, 0, time.FixedZone("CEST", 2*3600))

// openPatterns opens entry i as a pattern reader seeded with i.
func openPatterns(entries []Entry) func(int) (io.Reader, error) {
	return func(i int) (io.Reader, error) {
		return newPattern(byte(i), entries[i].Size), nil
	}
}

// build writes the archive of entries with f and checks its length against
// f.Size.
func build(t *testing.T, f Format, entries []Entry) []byte {
	t.Helper()
	want, err := f.Size(entries)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	var buf bytes.Buffer
	if err := f.Write(&buf, entries, openPatterns(entries)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if int64(buf.Len()) != want {
		t.Fatalf("Write produced %d bytes, Size said %d", buf.Len(), want)
	}
	return buf.Bytes()
}

// readBack opens the archive with archive/zip and checks names, sizes, CRCs,
// timestamps and contents against the entries.
func readBack(t *testing.T, r io.ReaderAt, size int64, entries []Entry, content func(i int) []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(r, size)
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	if len(zr.File) != len(entries) {
		t.Fatalf("archive has %d files, want %d", len(zr.File), len(entries))
	}
	for i, zf := range zr.File {
		e := entries[i]
		if zf.Name != e.Name {
			t.Errorf("file %d: name %q, want %q", i, zf.Name, e.Name)
		}
		if zf.Method != zip.Store || zf.Flags != flags || zf.NonUTF8 {
			t.Errorf("file %d: method %d flags %#x nonUTF8 %v", i, zf.Method, zf.Flags, zf.NonUTF8)
		}
		if zf.UncompressedSize64 != uint64(e.Size) || zf.CompressedSize64 != uint64(e.Size) {
			t.Errorf("file %d: sizes %d/%d, want %d", i, zf.UncompressedSize64, zf.CompressedSize64, e.Size)
		}
		if mode := zf.Mode(); mode != 0o644 {
			t.Errorf("file %d: mode %v", i, mode)
		}
		if content == nil {
			continue
		}
		data := content(i)
		if data == nil {
			continue
		}
		if zf.CRC32 != crc32.ChecksumIEEE(data) {
			t.Errorf("file %d: CRC %08x, want %08x", i, zf.CRC32, crc32.ChecksumIEEE(data))
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatalf("file %d: Open: %v", i, err)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("file %d: read: %v", i, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("file %d: content differs", i)
		}
	}
	return zr
}

func formats() map[string]Format {
	return map[string]Format{
		"always":     {},
		"whenNeeded": {Zip64Threshold: Zip64WhenNeeded},
		"threshold":  {Zip64Threshold: 100},
		"negative":   {Zip64Threshold: -1},
	}
}

func TestRoundTrip(t *testing.T) {
	entries := []Entry{
		{Name: "rapport annuel.pdf", Size: 1000, Modified: stamp},
		{Name: "vide.txt", Size: 0, Modified: stamp},
		{Name: "été/données (2).csv", Size: 99, Modified: stamp},
		{Name: "big.bin", Size: 3*bufferSize + 17, Modified: stamp},
		{Name: "日本語.txt", Size: 100, Modified: stamp},
	}
	for name, f := range formats() {
		t.Run(name, func(t *testing.T) {
			data := build(t, f, entries)
			zr := readBack(t, bytes.NewReader(data), int64(len(data)), entries, func(i int) []byte {
				return patternBytes(byte(i), entries[i].Size)
			})
			wantTime := time.Date(2026, 10, 21, 11, 37, 42, 0, time.UTC)
			if got := zr.File[0].Modified; !got.Equal(wantTime) {
				t.Errorf("Modified %v, want %v", got, wantTime)
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	entries := []Entry{{Name: "a", Size: 10, Modified: stamp}, {Name: "b", Size: 20, Modified: stamp}}
	if !bytes.Equal(build(t, Format{}, entries), build(t, Format{}, entries)) {
		t.Fatal("two archives of the same entries differ")
	}
}

func TestSizeFormula(t *testing.T) {
	entries := []Entry{{Name: "abc", Size: 5}, {Name: "de", Size: 0}}
	// Always ZIP64: per entry 30+20+24 (local) + 46+28 (central) + name*2 + size.
	want := int64(0)
	for _, e := range entries {
		want += 30 + 20 + 24 + 46 + 28 + 2*int64(len(e.Name)) + e.Size
	}
	want += 56 + 20 + 22
	got, err := Size(entries)
	if err != nil || got != want {
		t.Fatalf("Size = %d, %v; want %d", got, err, want)
	}
	// Classic layout: per entry 30+16 (local) + 46 (central) + name*2 + size.
	want = 0
	for _, e := range entries {
		want += 30 + 16 + 46 + 2*int64(len(e.Name)) + e.Size
	}
	want += 22
	got, err = Format{Zip64Threshold: Zip64WhenNeeded}.Size(entries)
	if err != nil || got != want {
		t.Fatalf("classic Size = %d, %v; want %d", got, err, want)
	}
	if got, err := Size(nil); err != nil || got != 98 {
		t.Fatalf("empty Size = %d, %v", got, err)
	}
}

func TestEmptyArchive(t *testing.T) {
	for name, f := range formats() {
		t.Run(name, func(t *testing.T) {
			data := build(t, f, nil)
			readBack(t, bytes.NewReader(data), int64(len(data)), nil, nil)
		})
	}
}

func TestPackageWrite(t *testing.T) {
	entries := []Entry{{Name: "x", Size: 3}}
	var buf bytes.Buffer
	if err := Write(&buf, entries, openPatterns(entries)); err != nil {
		t.Fatal(err)
	}
	if n, _ := Size(entries); int64(buf.Len()) != n {
		t.Fatalf("Write produced %d bytes, Size said %d", buf.Len(), n)
	}
}

func TestLayoutFields(t *testing.T) {
	entries := []Entry{{Name: "a", Size: 3, Modified: stamp}}
	data := build(t, Format{}, entries)
	// Local header: version 45, sizes marked, ZIP64 extra with zero sizes.
	if v := le.Uint16(data[4:]); v != versionZip64 {
		t.Errorf("local version %d", v)
	}
	if s := le.Uint32(data[18:]); s != max32 {
		t.Errorf("local size %#x", s)
	}
	if id, n := le.Uint16(data[31:]), le.Uint16(data[33:]); id != zip64ExtraID || n != 16 {
		t.Errorf("local extra %#x/%d", id, n)
	}
	// Data descriptor: signature, CRC, 8-byte sizes.
	dd := data[30+1+20+3:]
	if le.Uint32(dd) != dataDescriptorSig || le.Uint64(dd[8:]) != 3 || le.Uint64(dd[16:]) != 3 {
		t.Errorf("descriptor % x", dd[:24])
	}
	// End record: markers that send readers to the ZIP64 end record.
	end := data[len(data)-endLen:]
	if le.Uint16(end[8:]) != max16 || le.Uint32(end[12:]) != max32 || le.Uint32(end[16:]) != max32 {
		t.Errorf("end record % x", end)
	}
	loc := data[len(data)-endLen-zip64LocatorLen:]
	if le.Uint32(loc) != zip64LocatorSig || le.Uint32(loc[16:]) != 1 {
		t.Errorf("locator % x", loc[:zip64LocatorLen])
	}

	// Classic layout: version 20, no extra, 4-byte descriptor, plain end.
	data = build(t, Format{Zip64Threshold: Zip64WhenNeeded}, entries)
	if v, n := le.Uint16(data[4:]), le.Uint16(data[28:]); v != versionClassic || n != 0 {
		t.Errorf("classic local version %d extra %d", v, n)
	}
	end = data[len(data)-endLen:]
	if le.Uint32(end) != endSig || le.Uint16(end[8:]) != 1 {
		t.Errorf("classic end record % x", end)
	}
}

func TestDosTime(t *testing.T) {
	tests := []struct {
		in    time.Time
		date  uint16
		clock uint16
	}{
		{time.Time{}, 1<<5 | 1, 0},
		{time.Date(1979, 12, 31, 23, 59, 59, 0, time.UTC), 1<<5 | 1, 0},
		{time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC), 1<<5 | 1, 0},
		{time.Date(2108, 1, 1, 0, 0, 0, 0, time.UTC), 127<<9 | 12<<5 | 31, 23<<11 | 59<<5 | 29},
		{time.Date(2026, 10, 21, 13, 37, 43, 0, time.FixedZone("x", 2*3600)), 46<<9 | 10<<5 | 21, 11<<11 | 37<<5 | 21},
	}
	for _, tt := range tests {
		d, c := dosTime(tt.in)
		if d != tt.date || c != tt.clock {
			t.Errorf("dosTime(%v) = %#x %#x, want %#x %#x", tt.in, d, c, tt.date, tt.clock)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := []string{
		"", "/abs", "a/", "a//b", "..", "../x", "a/../b", "a/..", ".", "./a",
		`a\b`, "C:x", "a\x00b", "a\nb", "a\x7fb", "a\u0085b", "\xff",
		strings.Repeat("a", maxNameLen+1),
	}
	for _, name := range bad {
		_, err := Size([]Entry{{Name: name}})
		if !errors.Is(err, ErrInvalidName) {
			t.Errorf("Size(%q) error = %v, want ErrInvalidName", name, err)
		}
	}
	good := []string{"a", ".env", "a..b", "dir/sub/file.txt", "…", strings.Repeat("a", maxNameLen)}
	for _, name := range good {
		if _, err := Size([]Entry{{Name: name}}); err != nil {
			t.Errorf("Size(%q) error = %v", name, err)
		}
	}

	if _, err := Size([]Entry{{Name: "A.txt"}, {Name: "a.TXT"}}); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := Size([]Entry{{Name: "a", Size: -1}}); !errors.Is(err, ErrNegativeSize) {
		t.Errorf("negative: %v", err)
	}
	if _, err := Size([]Entry{{Name: "a", Size: math.MaxInt64}}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("entry overflow: %v", err)
	}
	// The entries themselves fit, the end records do not.
	if _, err := Size([]Entry{{Name: "a", Size: math.MaxInt64 - (30 + 1 + 20 + 24)}}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("total overflow: %v", err)
	}

	// Write refuses invalid entries without writing anything.
	var c counter
	err := Write(&c, []Entry{{Name: "ok"}, {Name: "../x"}}, func(int) (io.Reader, error) {
		t.Fatal("open called")
		return nil, nil
	})
	if !errors.Is(err, ErrInvalidName) || c.n != 0 {
		t.Errorf("Write: %v, %d bytes", err, c.n)
	}
}

// closeTracker records whether it was closed.
type closeTracker struct {
	io.Reader
	closed   bool
	closeErr error
}

func (c *closeTracker) Close() error {
	c.closed = true
	return c.closeErr
}

// stallReader returns (0, nil) forever.
type stallReader struct{}

func (stallReader) Read([]byte) (int, error) { return 0, nil }

// slowReader returns a few (0, nil) reads before each byte.
type slowReader struct {
	r     io.Reader
	calls int
}

func (s *slowReader) Read(b []byte) (int, error) {
	s.calls++
	if s.calls%5 != 0 {
		return 0, nil
	}
	return s.r.Read(b[:1])
}

// eofWithData returns its whole content together with io.EOF.
type eofWithData struct{ data []byte }

func (e *eofWithData) Read(b []byte) (int, error) {
	n := copy(b, e.data)
	return n, io.EOF
}

type failWriter struct {
	limit int64
	n     int64
	short bool
}

var errWrite = errors.New("write failed")

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n+int64(len(p)) > f.limit {
		if f.short {
			return 0, nil
		}
		return 0, errWrite
	}
	f.n += int64(len(p))
	return len(p), nil
}

func TestReaderErrors(t *testing.T) {
	entries := []Entry{{Name: "a", Size: 10}}
	errOpen := errors.New("open failed")
	errRead := errors.New("read failed")
	errClose := errors.New("close failed")
	tests := []struct {
		name   string
		reader func() io.Reader
		open   error
		want   error
	}{
		{"open", nil, errOpen, errOpen},
		{"short", func() io.Reader { return newPattern(0, 9) }, nil, ErrShortEntry},
		{"long", func() io.Reader { return newPattern(0, 11) }, nil, ErrLongEntry},
		{"long in one read", func() io.Reader { return bytes.NewReader(make([]byte, 100)) }, nil, ErrLongEntry},
		{"read error", func() io.Reader { return io.MultiReader(newPattern(0, 4), errReader{errRead}) }, nil, errRead},
		{"stall", func() io.Reader { return stallReader{} }, nil, io.ErrNoProgress},
		{"close error", func() io.Reader { return &closeTracker{Reader: newPattern(0, 10), closeErr: errClose} }, nil, errClose},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Write(io.Discard, entries, func(int) (io.Reader, error) {
				if tt.open != nil {
					return nil, tt.open
				}
				return tt.reader(), nil
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Write error = %v, want %v", err, tt.want)
			}
		})
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestReaderVariants(t *testing.T) {
	entries := []Entry{{Name: "a", Size: 10}, {Name: "b", Size: 10}, {Name: "c", Size: 10}}
	content := patternBytes(7, 10)
	trackers := []*closeTracker{}
	open := func(i int) (io.Reader, error) {
		switch i {
		case 0:
			return &slowReader{r: bytes.NewReader(content)}, nil
		case 1:
			return &eofWithData{data: content}, nil
		default:
			c := &closeTracker{Reader: bytes.NewReader(content)}
			trackers = append(trackers, c)
			return c, nil
		}
	}
	var buf bytes.Buffer
	if err := Write(&buf, entries, open); err != nil {
		t.Fatal(err)
	}
	if len(trackers) != 1 || !trackers[0].closed {
		t.Fatal("closer not closed")
	}
	readBack(t, bytes.NewReader(buf.Bytes()), int64(buf.Len()), entries, func(int) []byte { return content })

	// A failing entry is closed too.
	c := &closeTracker{Reader: newPattern(0, 3)}
	if err := Write(io.Discard, entries[:1], func(int) (io.Reader, error) { return c, nil }); !errors.Is(err, ErrShortEntry) || !c.closed {
		t.Fatalf("Write = %v, closed %v", err, c.closed)
	}
}

func TestWriterErrors(t *testing.T) {
	entries := []Entry{{Name: "a", Size: 10}, {Name: "b", Size: 10}}
	total, _ := Size(entries)
	// Fail at every write position: local header, data, descriptor, central
	// header and end records.
	failures := 0
	for limit := range total {
		for _, short := range []bool{false, true} {
			w := &failWriter{limit: limit, short: short}
			err := Write(w, entries, openPatterns(entries))
			want := errWrite
			if short {
				want = io.ErrShortWrite
			}
			if err == nil {
				t.Fatalf("limit %d: no error", limit)
			}
			if !errors.Is(err, want) {
				t.Fatalf("limit %d: error %v, want %v", limit, err, want)
			}
			failures++
		}
	}
	if failures == 0 {
		t.Fatal("no failure tested")
	}
}

// TestManyEntries writes more than 65535 entries and reads them back.
func TestManyEntries(t *testing.T) {
	const n = 70000
	entries := make([]Entry, n)
	for i := range entries {
		entries[i] = Entry{Name: fmt.Sprintf("d/%05d.txt", i), Size: int64(i % 3), Modified: stamp}
	}
	for name, f := range map[string]Format{"always": {}, "whenNeeded": {Zip64Threshold: Zip64WhenNeeded}} {
		t.Run(name, func(t *testing.T) {
			data := build(t, f, entries)
			end := data[len(data)-endLen:]
			if le.Uint16(end[8:]) != max16 {
				t.Errorf("end record entries %d, want the ZIP64 marker", le.Uint16(end[8:]))
			}
			readBack(t, bytes.NewReader(data), int64(len(data)), entries, func(i int) []byte {
				return patternBytes(byte(i), entries[i].Size)
			})
		})
	}
}

// TestBeyond4GiB writes an entry larger than 4 GiB followed by entries whose
// local headers start beyond 4 GiB, and reads everything back with
// archive/zip through a sparse in-memory recording.
func TestBeyond4GiB(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and reads back more than 8 GiB of synthetic data")
	}
	const big = 1<<32 + 1
	entries := []Entry{
		{Name: "small-first.txt", Size: 5, Modified: stamp},
		{Name: "big.bin", Size: big, Modified: stamp},
		{Name: "after.txt", Size: 100, Modified: stamp},
		{Name: "empty", Size: 0, Modified: stamp},
	}
	open := func(i int) (io.Reader, error) {
		if i == 1 {
			return &zeros{remaining: big}, nil
		}
		return newPattern(byte(i), entries[i].Size), nil
	}
	for name, f := range map[string]Format{"always": {}, "whenNeeded": {Zip64Threshold: Zip64WhenNeeded}} {
		t.Run(name, func(t *testing.T) {
			want, err := f.Size(entries)
			if err != nil {
				t.Fatal(err)
			}
			var s sparse
			if err := f.Write(&s, entries, open); err != nil {
				t.Fatal(err)
			}
			if s.size != want {
				t.Fatalf("Write produced %d bytes, Size said %d", s.size, want)
			}
			// Contents of the big entry are checked by archive/zip itself
			// (CRC and size); only the small entries are compared.
			zr := readBack(t, &s, s.size, entries, func(i int) []byte {
				if i == 1 {
					return nil
				}
				return patternBytes(byte(i), entries[i].Size)
			})
			rc, err := zr.File[1].Open()
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, rc)
			if err != nil || n != big {
				t.Fatalf("big entry: %d bytes, %v", n, err)
			}
			if off, _ := zr.File[2].DataOffset(); off <= big {
				t.Fatalf("entry after the big one at %d", off)
			}
		})
	}
}

// TestHugeSizes checks Size against the produced length for entries and
// archives far beyond 4 GiB without storing anything.
func TestHugeSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("streams more than 4 GiB of synthetic data")
	}
	entries := []Entry{
		{Name: "a", Size: max32},     // exactly the marker value: ZIP64 required
		{Name: "b", Size: max32 - 1}, // the largest classic size
		{Name: "c", Size: 1},
	}
	open := func(i int) (io.Reader, error) { return &zeros{remaining: entries[i].Size}, nil }
	for name, f := range formats() {
		t.Run(name, func(t *testing.T) {
			want, err := f.Size(entries)
			if err != nil {
				t.Fatal(err)
			}
			var c counter
			if err := f.Write(&c, entries, open); err != nil {
				t.Fatal(err)
			}
			if c.n != want {
				t.Fatalf("Write produced %d bytes, Size said %d", c.n, want)
			}
		})
	}
}

// FuzzSize checks, for arbitrary small entries, that Size equals the length
// of the output and that archive/zip reads it back.
func FuzzSize(f *testing.F) {
	f.Add("a\nb/c.txt\nd", []byte{3, 0, 200}, int64(0))
	f.Add("x", []byte{}, int64(5))
	f.Add("A\na", []byte{1}, int64(-3))
	f.Add("../x\n", []byte{9}, int64(0))
	f.Fuzz(func(t *testing.T, names string, sizes []byte, threshold int64) {
		parts := strings.Split(names, "\n")
		if len(parts) > 50 {
			parts = parts[:50]
		}
		entries := make([]Entry, len(parts))
		for i, name := range parts {
			var size int64
			if len(sizes) > 0 {
				size = int64(sizes[i%len(sizes)]) * int64(1+i%3)
			}
			entries[i] = Entry{Name: name, Size: size, Modified: stamp.Add(time.Duration(i) * time.Hour)}
		}
		fm := Format{Zip64Threshold: threshold % 1000}
		want, sizeErr := fm.Size(entries)
		var buf bytes.Buffer
		writeErr := fm.Write(&buf, entries, openPatterns(entries))
		if sizeErr != nil {
			if writeErr == nil || buf.Len() != 0 {
				t.Fatalf("Size failed (%v) but Write returned %v after %d bytes", sizeErr, writeErr, buf.Len())
			}
			return
		}
		if writeErr != nil {
			t.Fatalf("Write: %v", writeErr)
		}
		if int64(buf.Len()) != want {
			t.Fatalf("Write produced %d bytes, Size said %d", buf.Len(), want)
		}
		readBack(t, bytes.NewReader(buf.Bytes()), int64(buf.Len()), entries, func(i int) []byte {
			return patternBytes(byte(i), entries[i].Size)
		})
	})
}

// TestFolderExtraction streams an archive of files dropped as folders, named
// by filename.ArchiveEntries, then extracts it under a confined root (threat
// T-227): folders merged by case and NFC, duplicate names and a file named as
// a folder all land in distinct files, even on a case-insensitive file
// system.
func TestFolderExtraction(t *testing.T) {
	files := []filename.ArchiveFile{
		{Path: "Plans/2026", Name: "a.pdf"},
		{Path: "PLANS/2026", Name: "A.PDF"},
		{Path: "été", Name: "x.txt"},
		{Path: "ÉTÉ", Name: "X.TXT"},
		{Path: "", Name: "plans"},
		{Path: "Plans", Name: "2026"},
		{Path: "../../etc", Name: "passwd"},
		{Path: "%2e%2e", Name: "lit"},
	}
	names := filename.ArchiveEntries(files)
	want := []string{
		"Plans/2026/a.pdf", "Plans/2026/A (2).PDF", "été/x.txt", "été/X (2).TXT",
		"plans (2)", "Plans/2026 (2)", "passwd", "%2e%2e/lit",
	}
	entries := make([]Entry, len(names))
	for i, n := range names {
		if n != want[i] {
			t.Fatalf("entry %d: %q, want %q", i, n, want[i])
		}
		entries[i] = Entry{Name: n, Size: int64(100 + i), Modified: stamp}
	}
	data := build(t, Format{}, entries)
	content := func(i int) []byte { return patternBytes(byte(i), entries[i].Size) }
	zr := readBack(t, bytes.NewReader(data), int64(len(data)), entries, content)

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, zf := range zr.File {
		if !filepath.IsLocal(zf.Name) {
			t.Fatalf("entry %q escapes the extraction folder", zf.Name)
		}
		if dir := path.Dir(zf.Name); dir != "." {
			if err := root.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir %q: %v", dir, err)
			}
		}
		w, err := root.OpenFile(zf.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			t.Fatalf("create %q: %v", zf.Name, err)
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(w, rc)
		_ = rc.Close()
		if cerr := w.Close(); err != nil || cerr != nil {
			t.Fatalf("extract %q: %v %v", zf.Name, err, cerr)
		}
	}
	for i, e := range entries {
		got, err := root.ReadFile(e.Name)
		if err != nil || !bytes.Equal(got, content(i)) {
			t.Errorf("extracted %q differs (%v)", e.Name, err)
		}
	}
}
