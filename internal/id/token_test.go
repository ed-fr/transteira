package id

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestTokenLen(t *testing.T) {
	tests := []struct {
		n, want int
	}{
		{-1, 0},
		{0, 0},
		{1, 2},
		{16, 22},
		{18, 25},
		{24, 33},
		{32, 43},
		{64, 86},
	}
	for _, tc := range tests {
		if got := TokenLen(tc.n); got != tc.want {
			t.Errorf("TokenLen(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestNewToken(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		n       int
		wantErr error
	}{
		{"download 16", "dl", 16, nil},
		{"download 32", "dl", 32, nil},
		{"upload 24", "upl", 24, nil},
		{"max", "inv", MaxTokenBytes, nil},
		{"too little entropy", "dl", 15, ErrEntropy},
		{"too much entropy", "dl", MaxTokenBytes + 1, ErrEntropy},
		{"bad prefix", "DL", 16, ErrPrefix},
		{"empty prefix", "", 16, ErrPrefix},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewToken(tc.prefix, tc.n)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				if got != "" {
					t.Fatalf("got %q on error", got)
				}
				return
			}
			l := TokenLen(tc.n)
			if !TokenValid(tc.prefix, got, l, l) {
				t.Fatalf("token %q not valid for length %d", got, l)
			}
		})
	}
}

func TestNewTokenDeterministic(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"zeros padded", make([]byte, 16), "dl_" + strings.Repeat("0", 22)},
		{"one", append(make([]byte, 15), 1), "dl_" + strings.Repeat("0", 21) + "1"},
		{"max", bytes.Repeat([]byte{0xFF}, 16), "dl_7N42dgm5tFLK9N8MT7fHC7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newToken(bytes.NewReader(tc.in), "dl", 16)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewTokenRandomError(t *testing.T) {
	if _, err := newToken(errReader{}, "dl", 16); err == nil {
		t.Fatal("want error")
	}
}

func TestNewTokenUniqueness(t *testing.T) {
	const n = 100_000
	seen := make(map[string]struct{}, n)
	for range n {
		s, err := NewToken("dl", MinTokenBytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate token %q", s)
		}
		seen[s] = struct{}{}
	}
}

func TestTokenValid(t *testing.T) {
	body22 := strings.Repeat("aZ9", 7) + "x"
	tests := []struct {
		name     string
		p, s     string
		min, max int
		want     bool
	}{
		{"ok", "dl", "dl_" + body22, 22, 43, true},
		{"too short", "dl", "dl_" + body22[:21], 22, 43, false},
		{"too long", "vch", "vch_" + strings.Repeat("a", 33), 16, 32, false},
		{"wrong prefix", "dl", "upl_" + body22, 22, 43, false},
		{"no underscore", "dl", "dl" + body22, 22, 43, false},
		{"bad char", "dl", "dl_" + body22[:21] + "-", 22, 43, false},
		{"bad prefix arg", "D", "D_" + body22, 22, 43, false},
		{"empty", "dl", "", 22, 43, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := TokenValid(tc.p, tc.s, tc.min, tc.max); got != tc.want {
				t.Fatalf("TokenValid = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDepositTokenConstants(t *testing.T) {
	if MinTokenBodyLen != TokenLen(ChallengeTokenBytes) || MaxTokenBodyLen != TokenLen(SessionTokenBytes) ||
		MaxTokenBodyLen != TokenLen(InvitationTokenBytes) {
		t.Errorf("token body bounds %d..%d do not match the token sizes", MinTokenBodyLen, MaxTokenBodyLen)
	}
	for _, p := range []string{ChallengeTokenPrefix, SessionTokenPrefix, InvitationTokenPrefix} {
		tok, err := NewToken(p, MinTokenBytes)
		if err != nil || !TokenValid(p, tok, MinTokenBodyLen, MaxTokenBodyLen) {
			t.Errorf("NewToken(%s) = %q, %v", p, tok, err)
		}
	}
}
