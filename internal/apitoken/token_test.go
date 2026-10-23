package apitoken

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// testSecret returns a secret of the right shape built at run time, so
// that no realistic token literal appears in the sources.
func testSecret(fill byte) string {
	return secretPrefix + "_" + strings.Repeat(string(fill), secretBodyLen)
}

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		g, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(g.Secret))
		if len(g.Secret) != SecretLen || !ValidSecret(g.Secret) || g.Prefix != g.Secret[:PrefixLen] ||
			!strings.HasPrefix(g.Prefix, "tt_") || !bytes.Equal(g.Hash, sum[:]) {
			t.Fatalf("Generate = prefix %q, length %d, hash %x", g.Prefix, len(g.Secret), g.Hash)
		}
		if seen[g.Secret] {
			t.Fatal("Generate repeated a secret")
		}
		seen[g.Secret] = true
	}
}

func TestGenerateFailure(t *testing.T) {
	boom := errors.New("no entropy")
	saved := newSecret
	newSecret = func() (string, error) { return "", boom }
	defer func() { newSecret = saved }()
	if _, err := Generate(); !errors.Is(err, boom) {
		t.Fatalf("Generate = %v, want the random failure", err)
	}
}

func TestValidSecret(t *testing.T) {
	cases := map[string]bool{
		testSecret('a'):                       true,
		testSecret('Z'):                       true,
		testSecret('a')[:SecretLen-1]:         false,
		testSecret('a') + "b":                 false,
		"xx_" + strings.Repeat("a", 43):       false,
		"tt-" + strings.Repeat("a", 43):       false,
		"tt_" + strings.Repeat("a", 42) + "-": false,
		"":                                    false,
	}
	for s, want := range cases {
		if got := ValidSecret(s); got != want {
			t.Errorf("ValidSecret(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestParseAuthorization(t *testing.T) {
	secret := testSecret('k')
	cases := []struct {
		header string
		want   error
	}{
		{"Bearer " + secret, nil},
		{"bearer " + secret, nil},
		{"BEARER " + secret, nil},
		{"", ErrMissing},
		{"Basic dXNlcjpwYXNz", ErrMissing},
		{"Bearerx " + secret, ErrMissing},
		{" Bearer " + secret, ErrMissing},
		{"Bearer", ErrInvalid},
		{"Bearer ", ErrInvalid},
		{"Bearer  " + secret, ErrInvalid},
		{"Bearer " + secret + " ", ErrInvalid},
		{"Bearer " + secret + " extra", ErrInvalid},
		{"Bearer\t" + secret, ErrMissing},
		{"Bearer " + secret[:SecretLen-1], ErrInvalid},
		{"Bearer " + strings.ToUpper(secret[:2]) + secret[2:], ErrInvalid},
	}
	for _, c := range cases {
		got, err := ParseAuthorization(c.header)
		if !errors.Is(err, c.want) {
			t.Errorf("ParseAuthorization(%q) err = %v, want %v", c.header, err, c.want)
			continue
		}
		if c.want == nil && got != secret {
			t.Errorf("ParseAuthorization(%q) = %q", c.header, got)
		}
		if c.want != nil && got != "" {
			t.Errorf("ParseAuthorization(%q) returned %q with an error", c.header, got)
		}
	}
}

// FuzzParseAuthorization checks that any header either yields a secret of
// the right shape, which the header ends with after exactly "Bearer ", or
// one of the two sentinel errors.
func FuzzParseAuthorization(f *testing.F) {
	for _, seed := range []string{"", "Bearer", "Bearer ", "bearer " + testSecret('a'), "Basic x", "Bearer  x", "Bearer \x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		got, err := ParseAuthorization(header)
		switch {
		case err == nil:
			if !ValidSecret(got) || len(header) != len(bearerScheme)+1+len(got) || !strings.HasSuffix(header, " "+got) ||
				!strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
				t.Fatalf("ParseAuthorization(%q) = %q", header, got)
			}
		case errors.Is(err, ErrMissing), errors.Is(err, ErrInvalid):
			if got != "" {
				t.Fatalf("ParseAuthorization(%q) = %q, %v", header, got, err)
			}
		default:
			t.Fatalf("ParseAuthorization(%q) err = %v", header, err)
		}
	})
}
