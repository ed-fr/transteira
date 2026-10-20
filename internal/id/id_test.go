package id

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// errReader always fails.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// fixedClock returns a clock always reporting t.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// refEncode encodes ms and entropy with math/big, as an independent oracle.
func refEncode(ms uint64, entropy [10]byte) string {
	v := new(big.Int).SetUint64(ms)
	v.Lsh(v, 80)
	v.Or(v, new(big.Int).SetBytes(entropy[:]))
	out := make([]byte, ulidLen)
	mask := big.NewInt(31)
	for i := ulidLen - 1; i >= 0; i-- {
		out[i] = crockford[new(big.Int).And(v, mask).Int64()]
		v.Rsh(v, 5)
	}
	return string(out)
}

func TestEncode(t *testing.T) {
	ff := [10]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	tests := []struct {
		name    string
		ms      uint64
		entropy [10]byte
		want    string
	}{
		{"zero", 0, [10]byte{}, "00000000000000000000000000"},
		{"max", maxTimestamp, ff, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"},
		{"ulid spec timestamp", 1469918176385, [10]byte{}, "01ARYZ6S410000000000000000"},
		{"entropy ones", 0, ff, "0000000000ZZZZZZZZZZZZZZZZ"},
		{"pattern", 1700000000123, [10]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, ""},
		{"straddle", 42, [10]byte{0, 0x0F, 0xF0, 0, 0, 0, 0, 0, 0, 0}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = refEncode(tc.ms, tc.entropy)
			}
			if got := encode(tc.ms, tc.entropy); got != want {
				t.Fatalf("encode = %q, want %q", got, want)
			}
			if got := refEncode(tc.ms, tc.entropy); got != want {
				t.Fatalf("refEncode = %q, want %q", got, want)
			}
		})
	}
}

func TestEncodeMatchesReference(t *testing.T) {
	g := NewGenerator(nil, nil)
	for range 2000 {
		var e [10]byte
		if _, err := g.rand.Read(e[:]); err != nil {
			t.Fatal(err)
		}
		ms := uint64(time.Now().UnixMilli()) ^ uint64(e[0])<<40
		if got, want := encode(ms, e), refEncode(ms, e); got != want {
			t.Fatalf("encode(%d, %x) = %q, want %q", ms, e, got, want)
		}
	}
}

func TestGeneratorNew(t *testing.T) {
	ts := time.Date(2026, 10, 19, 12, 0, 0, 123_000_000, time.UTC)
	tests := []struct {
		name    string
		prefix  Prefix
		clock   func() time.Time
		rand    *bytes.Reader
		want    string
		wantErr error
	}{
		{"ok", Transfer, fixedClock(ts), bytes.NewReader(make([]byte, 10)), "trf_" + refEncode(uint64(ts.UnixMilli()), [10]byte{}), nil},
		{"bad prefix", Prefix("Trf"), fixedClock(ts), bytes.NewReader(make([]byte, 10)), "", ErrPrefix},
		{"before epoch", Tenant, fixedClock(time.Unix(-1, 0)), bytes.NewReader(make([]byte, 10)), "", ErrTimestamp},
		{"after range", Tenant, fixedClock(time.UnixMilli(maxTimestamp + 1)), bytes.NewReader(make([]byte, 10)), "", ErrTimestamp},
		{"short random", File, fixedClock(ts), bytes.NewReader(make([]byte, 9)), "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewGenerator(tc.clock, tc.rand).New(tc.prefix)
			if tc.name == "short random" {
				if err == nil || got != "" {
					t.Fatalf("want read error, got %q, %v", got, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGeneratorRandomError(t *testing.T) {
	_, err := NewGenerator(nil, errReader{}).New(Admin)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestNewGeneratorDefaults(t *testing.T) {
	g := NewGenerator(nil, nil)
	if g.clock == nil || g.rand == nil {
		t.Fatal("defaults not applied")
	}
}

func TestNewAllPrefixes(t *testing.T) {
	for _, p := range []Prefix{Tenant, Transfer, File, Invitation, Blocklist, APIToken, Admin, Rotation, WrappedKey, Audit, Request} {
		before := time.Now().Add(-time.Millisecond)
		s := New(p)
		if !strings.HasPrefix(s, string(p)+"_") || len(s) != len(p)+1+ulidLen {
			t.Fatalf("New(%q) = %q", p, s)
		}
		ts, err := Parse(p, s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if ts.Before(before) || ts.After(time.Now().Add(time.Millisecond)) {
			t.Fatalf("timestamp %v out of range", ts)
		}
	}
}

func TestNewPanicsOnRandomFailure(t *testing.T) {
	saved := cryptoReader
	cryptoReader = errReader{}
	defer func() {
		cryptoReader = saved
		if recover() == nil {
			t.Fatal("New did not panic")
		}
	}()
	New(Tenant)
}

func TestNewUniqueness(t *testing.T) {
	const n = 100_000
	seen := make(map[string]struct{}, n)
	for range n {
		s := New(Transfer)
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate id %q", s)
		}
		seen[s] = struct{}{}
	}
}

func TestParse(t *testing.T) {
	valid := "trf_01ARYZ6S410000000000000000"
	tests := []struct {
		name    string
		prefix  Prefix
		s       string
		wantMs  int64
		wantErr error
	}{
		{"valid", Transfer, valid, 1469918176385, nil},
		{"max", Transfer, "trf_7ZZZZZZZZZZZZZZZZZZZZZZZZZ", maxTimestamp, nil},
		{"zero", Tenant, "ten_00000000000000000000000000", 0, nil},
		{"bad prefix arg", Prefix(""), valid, 0, ErrPrefix},
		{"wrong prefix", Tenant, valid, 0, ErrInvalid},
		{"missing underscore", Transfer, "trf-01ARYZ6S410000000000000000", 0, ErrInvalid},
		{"too short", Transfer, valid[:len(valid)-1], 0, ErrInvalid},
		{"too long", Transfer, valid + "0", 0, ErrInvalid},
		{"overflow first char", Transfer, "trf_81ARYZ6S410000000000000000", 0, ErrInvalid},
		{"lowercase", Transfer, "trf_01aryz6s410000000000000000", 0, ErrInvalid},
		{"letter I", Transfer, "trf_01ARYZ6S41000000000000000I", 0, ErrInvalid},
		{"letter L", Transfer, "trf_01ARYZ6S41000000000000000L", 0, ErrInvalid},
		{"letter O", Transfer, "trf_01ARYZ6S41000000000000000O", 0, ErrInvalid},
		{"letter U", Transfer, "trf_01ARYZ6S41000000000000000U", 0, ErrInvalid},
		{"non ascii", Transfer, "trf_01ARYZ6S4100000000000000\xc3\xa9"[:len(valid)], 0, ErrInvalid},
		{"empty", Transfer, "", 0, ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.prefix, tc.s)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && got.UnixMilli() != tc.wantMs {
				t.Fatalf("ms = %d, want %d", got.UnixMilli(), tc.wantMs)
			}
			if err == nil && got.Location() != time.UTC {
				t.Fatalf("location = %v, want UTC", got.Location())
			}
			if v := Valid(tc.prefix, tc.s); v != (tc.wantErr == nil) {
				t.Fatalf("Valid = %v", v)
			}
		})
	}
}

func TestValidPrefix(t *testing.T) {
	tests := []struct {
		p    string
		want bool
	}{
		{"ten", true},
		{"a", true},
		{"abcdefghijklmnop", true},
		{"abcdefghijklmnopq", false},
		{"", false},
		{"Ten", false},
		{"t3n", false},
		{"t_n", false},
	}
	for _, tc := range tests {
		if got := validPrefix(tc.p); got != tc.want {
			t.Errorf("validPrefix(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func FuzzValid(f *testing.F) {
	f.Add("trf", "trf_01ARYZ6S410000000000000000")
	f.Add("ten", "ten_7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
	f.Add("fil", "fil_8ZZZZZZZZZZZZZZZZZZZZZZZZZ")
	f.Add("", "_")
	f.Fuzz(func(t *testing.T, p, s string) {
		if !Valid(Prefix(p), s) {
			return
		}
		// A valid identifier must round-trip through Parse and re-encode
		// to the same timestamp characters.
		ts, err := Parse(Prefix(p), s)
		if err != nil {
			t.Fatalf("Valid but Parse failed: %v", err)
		}
		u := s[len(p)+1:]
		if got := encode(uint64(ts.UnixMilli()), [10]byte{})[:10]; got != u[:10] {
			t.Fatalf("timestamp chars %q, want %q", got, u[:10])
		}
		if strings.ContainsAny(u, "ILOUabcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("invalid chars accepted in %q", s)
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add("trf_01ARYZ6S410000000000000000")
	f.Add("trf_7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
	f.Add("trf_")
	f.Fuzz(func(t *testing.T, s string) {
		ts, err := Parse(Transfer, s)
		if err != nil {
			return
		}
		ms := ts.UnixMilli()
		if ms < 0 || ms > maxTimestamp {
			t.Fatalf("timestamp %d out of range", ms)
		}
		var e [10]byte
		re := "trf_" + encode(uint64(ms), e)
		if re[:14] != s[:14] {
			t.Fatalf("re-encoded prefix %q, want %q", re[:14], s[:14])
		}
	})
}
