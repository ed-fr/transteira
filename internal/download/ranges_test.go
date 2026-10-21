package download

import (
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
)

func TestAddSpan(t *testing.T) {
	base := []span{{10, 20}, {30, 40}, {50, 60}}
	cases := []struct {
		add  span
		want []span
	}{
		{span{0, 5}, []span{{0, 5}, {10, 20}, {30, 40}, {50, 60}}},
		{span{70, 80}, []span{{10, 20}, {30, 40}, {50, 60}, {70, 80}}},
		{span{22, 28}, []span{{10, 20}, {22, 28}, {30, 40}, {50, 60}}},
		{span{20, 30}, []span{{10, 40}, {50, 60}}},           // adjacent on both sides
		{span{15, 55}, []span{{10, 60}}},                     // spanning several
		{span{0, 100}, []span{{0, 100}}},                     // covering all
		{span{32, 38}, []span{{10, 20}, {30, 40}, {50, 60}}}, // inside
		{span{5, 10}, []span{{5, 20}, {30, 40}, {50, 60}}},
	}
	for _, c := range cases {
		if got := addSpan(slices.Clone(base), c.add); !slices.Equal(got, c.want) {
			t.Errorf("addSpan(%v) = %v, want %v", c.add, got, c.want)
		}
	}
	if got := addSpan(nil, span{1, 2}); !slices.Equal(got, []span{{1, 2}}) {
		t.Errorf("addSpan on empty = %v", got)
	}
}

func TestServedAddComplete(t *testing.T) {
	f1, f2, f3 := id.New(id.File), id.New(id.File), id.New(id.File)
	files := []store.TransferFile{{ID: f1, Size: 100}, {ID: f2, Size: 0}, {ID: f3, Size: 10}}
	st := served{}
	if st.complete(files) {
		t.Fatal("empty state complete")
	}
	add := func(fid string, size int64, spans ...span) (int64, bool) { return st.add(fid, size, spans) }
	if g, c := add(f1, 100, span{-5, 0}, span{100, 120}); g != 0 || c {
		t.Error("spans outside the file changed the state")
	}
	if g, c := add(f1, 100, span{0, 40}, span{60, 150}); g != 80 || !c {
		t.Errorf("gained %d, %v", g, c)
	}
	if g, c := add(f1, 100, span{0, 40}); g != 0 || c {
		t.Error("change reporting")
	}
	if g, c := add(f1, 100, span{30, 70}); g != 20 || !c {
		t.Errorf("overlap gained %d", g)
	}
	st[f1] = []span{{0, 40}, {60, 100}}
	if _, c := add(f2, 0); !c {
		t.Error("empty file change reporting")
	}
	if _, c := add(f2, 0); c {
		t.Error("empty file change reporting")
	}
	if st.fileDone(store.TransferFile{ID: f1, Size: 100}) || !st.fileDone(store.TransferFile{ID: f2}) || st.spanCount() != 2 {
		t.Error("fileDone or spanCount")
	}
	st.add(f3, 10, []span{{0, 10}})
	if st.complete(files) {
		t.Fatal("complete with a gap")
	}
	st.add(f1, 100, []span{{40, 60}})
	if !st.complete(files) {
		t.Fatalf("incomplete: %v", st)
	}
	delete(st, f2)
	if st.complete(files) {
		t.Fatal("complete without the empty file")
	}
	st[f2] = nil
	st[f3] = []span{{1, 10}}
	if st.complete(files) {
		t.Fatal("complete without the first byte")
	}
	st[f3] = []span{{0, 4}, {5, 10}}
	if st.complete(files) {
		t.Fatal("complete with two spans")
	}
}

func TestStateRoundTrip(t *testing.T) {
	f1, f2 := id.New(id.File), id.New(id.File)
	st := served{f1: {{0, 5}, {7, 1 << 40}}, f2: nil}
	b, err := st.encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeServed(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !slices.Equal(got[f1], st[f1]) || got[f2] != nil {
		t.Fatalf("decoded %v, want %v", got, st)
	}
	if _, ok := got[f2]; !ok {
		t.Fatal("empty file lost")
	}
}

func TestDecodeCorrupt(t *testing.T) {
	fid := id.New(id.File)
	head := func(n int, idv string) []byte {
		b := []byte{stateVersion}
		b = binary.AppendUvarint(b, uint64(n))
		b = binary.AppendUvarint(b, uint64(len(idv)))
		return append(b, idv...)
	}
	spans := func(b []byte, v ...uint64) []byte {
		for _, x := range v {
			b = binary.AppendUvarint(b, x)
		}
		return b
	}
	dup := spans(head(2, fid), 0)
	dup = binary.AppendUvarint(dup, uint64(len(fid)))
	dup = spans(append(dup, fid...), 0)
	cases := map[string][]byte{
		"empty":            nil,
		"version":          {2, 0},
		"bad varint":       {stateVersion, 0x80},
		"short id":         append([]byte{stateVersion, 1, 40}, "fil_"...),
		"invalid id":       spans(head(1, "fil_bad"), 0),
		"duplicate id":     dup,
		"zero length":      spans(head(1, fid), 1, 0, 0),
		"zero gap":         spans(head(1, fid), 2, 0, 5, 0, 5),
		"gap overflow":     spans(head(1, fid), 2, 0, 5, math.MaxInt64, 1),
		"length overflow":  spans(head(1, fid), 1, 5, math.MaxInt64),
		"missing spans":    spans(head(1, fid), 2, 0, 5),
		"trailing":         spans(head(1, fid), 0, 9),
		"too many files":   spans([]byte{stateVersion}, storage.MaxStateSize+1),
		"truncated length": spans(head(1, fid), 1, 3),
	}
	for name, b := range cases {
		if _, err := decodeServed(b); !errors.Is(err, errCorruptState) {
			t.Errorf("%s: error %v, want corrupt", name, err)
		}
	}
}

func TestEncodePrunes(t *testing.T) {
	st := served{}
	fid := id.New(id.File)
	var list []span
	// Spans of growing length, far apart: the encoding exceeds the limit.
	for i := range int64(20000) {
		list = append(list, span{i * 1_000_000, i*1_000_000 + 1 + i})
	}
	st[fid] = list
	b, err := st.encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > storage.MaxStateSize {
		t.Fatalf("%d bytes", len(b))
	}
	got, err := decodeServed(b)
	if err != nil {
		t.Fatal(err)
	}
	kept := got[fid]
	if len(kept) == 0 || len(kept) == len(list) || kept[len(kept)-1] != list[len(list)-1] || kept[0] == list[0] {
		t.Fatalf("pruning kept %d spans, from %v", len(kept), kept[0])
	}

	// A file whose last span is dropped disappears.
	other := id.New(id.File)
	small := served{fid: {{0, 1}}, other: {{0, 5}, {10, 11}, {20, 30}}}
	small.drop(2)
	if len(small) != 1 || !slices.Equal(small[other], []span{{0, 5}, {20, 30}}) {
		t.Fatalf("drop left %v", small)
	}
	tie := served{fid: {{0, 1}}, other: {{0, 1}}}
	tie.drop(1)
	if _, ok := tie[min(fid, other)]; ok || len(tie) != 1 {
		t.Fatalf("tie broken badly: %v", tie)
	}
	two := served{fid: {{0, 1}, {5, 6}}}
	two.drop(1)
	if !slices.Equal(two[fid], []span{{5, 6}}) {
		t.Fatalf("position tie broken badly: %v", two)
	}
	empty := served{}
	empty.drop(1)

	// Without spans left to drop, the state cannot fit.
	huge := served{}
	for range 3000 {
		huge[id.New(id.File)] = nil
	}
	if _, err := huge.encode(); !errors.Is(err, errStateTooLarge) {
		t.Fatalf("error %v, want too large", err)
	}
}
