package tte2

import "testing"

func TestSizeFormula(t *testing.T) {
	c := testChunk
	block := int64(c + TagSize)
	cases := []struct {
		plain, total int64
	}{
		{0, 48},
		{1, 49},
		{int64(c), HeaderSize + block},
		{int64(c) + 1, HeaderSize + block + 17},
		{3 * int64(c), HeaderSize + 3*block},
	}
	for _, tc := range cases {
		if got := CiphertextSize(tc.plain, c); got != tc.total {
			t.Fatalf("CiphertextSize(%d) = %d, want %d", tc.plain, got, tc.total)
		}
		if p, ok := PlaintextSize(tc.total, c); !ok || p != tc.plain {
			t.Fatalf("PlaintextSize(%d) = %d %v", tc.total, p, ok)
		}
	}
	for _, bad := range []struct {
		plain int64
		chunk int
	}{{-1, c}, {0, c + 1}, {MaxChunks*int64(c) + 1, c}} {
		if got := CiphertextSize(bad.plain, bad.chunk); got != -1 {
			t.Fatalf("CiphertextSize(%d, %d) = %d", bad.plain, bad.chunk, got)
		}
	}
	if got := CiphertextSize(MaxChunks*int64(c), c); got != HeaderSize+MaxChunks*block {
		t.Fatalf("max: %d", got)
	}
	invalid := []int64{
		0, 47, // below the minimum
		HeaderSize + block + 16, // empty final chunk after data
		HeaderSize + block + 1,  // final chunk shorter than a tag
		HeaderSize + block + 15,
		HeaderSize + MaxChunks*block + 17, // one chunk too many
	}
	for _, total := range invalid {
		if ValidSize(total, c) {
			t.Fatalf("ValidSize(%d) accepted", total)
		}
	}
	if !ValidSize(HeaderSize+MaxChunks*block, c) {
		t.Fatal("max rejected")
	}
	if ValidSize(48, c+1) {
		t.Fatal("bad chunk accepted")
	}
}

// TestSizeExhaustive checks that ValidSize accepts exactly the sizes
// CiphertextSize produces, over the first three chunks.
func TestSizeExhaustive(t *testing.T) {
	c := testChunk
	valid := map[int64]int64{}
	for p := int64(0); p <= 3*int64(c); p++ {
		valid[CiphertextSize(p, c)] = p
	}
	for total := int64(0); total <= HeaderSize+3*int64(c+TagSize)+1; total++ {
		p, ok := PlaintextSize(total, c)
		want, exists := valid[total]
		if ok != exists || (ok && p != want) {
			t.Fatalf("total %d: got %d %v, want %d %v", total, p, ok, want, exists)
		}
	}
}
