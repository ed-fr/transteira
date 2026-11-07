package download

import (
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tte2"
)

const testKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // gitleaks:allow (fake test key)

func TestParseLink(t *testing.T) {
	ok := []struct {
		raw  string
		want Link
	}{
		{testToken, Link{Token: testToken}},
		{"  " + testToken + "\n", Link{Token: testToken}},
		{"https://transfer.entity-a.example.com/d/" + testToken, Link{Origin: "https://transfer.entity-a.example.com", Token: testToken}},
		{"https://Transfer.Entity-A.example.com:443/d/" + testToken + "/reply", Link{Origin: "https://transfer.entity-a.example.com", Token: testToken}},
		{"https://transfer.entity-a.example.com:8443/d/" + testToken + "#k=" + testKey, Link{Origin: "https://transfer.entity-a.example.com:8443", Token: testToken, Key: testKey, FromFragment: true}},
		{"HTTPS://[::1]/d/" + testToken, Link{Origin: "https://[::1]", Token: testToken}},
	}
	for _, c := range ok {
		got, err := ParseLink(c.raw)
		if err != nil || got != c.want {
			t.Errorf("ParseLink(%q) = %+v, %v; want %+v", c.raw, got, err, c.want)
		}
	}
	bad := []string{
		"", "dl_short", "http://transfer.entity-a.example.com/d/" + testToken,
		"https://user@transfer.entity-a.example.com/d/" + testToken,
		"https://transfer.entity-a.example.com/d/" + testToken + "?x=1",
		"https://transfer.entity-a.example.com/d/" + testToken + "?",
		"https://transfer.entity-a.example.com/x/" + testToken,
		"https://transfer.entity-a.example.com/d/" + testToken + "/",
		"https://transfer.entity-a.example.com/d/" + testToken + "/other",
		"https://transfer.entity-a.example.com/d/%64l_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf",
		"https://transfer.entity-a.example.com/d/" + testToken + "#",
		"https://transfer.entity-a.example.com/d/" + testToken + "#x=" + testKey,
		"https://transfer.entity-a.example.com/d/" + testToken + "#k=" + testKey + "#k=" + testKey,
		"https://transfer.entity-a.example.com/d/" + testToken + " x",
		"https://transfér.example.com/d/" + testToken,
		"https:/d/" + testToken, "https:///d/" + testToken, "https://host:0/d/" + testToken,
		"mailto:" + testToken, "https://h/d/" + testToken + "\u202e",
		strings.Repeat("a", MaxLinkBytes+1),
		"%zz",
	}
	for _, raw := range bad {
		if l, err := ParseLink(raw); !errors.Is(err, ErrInvalidLink) {
			t.Errorf("ParseLink(%q) = %+v, %v; want ErrInvalidLink", raw, l, err)
		}
	}
	// A malformed key is refused without being quoted.
	badKey := "https://transfer.entity-a.example.com/d/" + testToken + "#k=" + testKey[:42] + "_"
	if _, err := ParseLink(badKey); err == nil || strings.Contains(err.Error(), testKey[:20]) {
		t.Errorf("bad key: %v", err)
	}
}

func TestLinkString(t *testing.T) {
	l := Link{Origin: "https://h.example.com", Token: testToken, Key: testKey}
	if s := l.String(); strings.Contains(s, testKey) || strings.Contains(s, testToken) || !strings.HasPrefix(s, "https://h.example.com/d/dl_Xk4L") {
		t.Errorf("String() = %q", s)
	}
}

func TestKeyFromInput(t *testing.T) {
	for in, want := range map[string]string{
		testKey + "\n": testKey,
		"https://h.example.com/d/" + testToken + "#k=" + testKey: testKey,
	} {
		if got, err := keyFromInput(in); err != nil || got != want {
			t.Errorf("keyFromInput(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := keyFromInput("https://h/d/x#nope"); !errors.Is(err, ErrWrongKey) {
		t.Errorf("bad fragment: %v", err)
	}
}

func FuzzParseLink(f *testing.F) {
	f.Add(testToken)
	f.Add("https://transfer.entity-a.example.com/d/" + testToken + "#k=" + testKey)
	f.Add("https://transfer.entity-a.example.com:8443/d/" + testToken + "/reply")
	f.Add("https://a/d/dl_" + strings.Repeat("A", 43) + "#k=")
	f.Fuzz(func(t *testing.T, raw string) {
		l, err := ParseLink(raw)
		if err != nil {
			if strings.Contains(raw, "#k=") && len(raw) > 60 {
				if k := raw[strings.Index(raw, "#k=")+3:]; len(k) >= 8 && strings.Contains(err.Error(), k) {
					t.Fatalf("error quotes the key: %v", err)
				}
			}
			return
		}
		if !id.DownloadTokenValid(l.Token) {
			t.Fatalf("invalid token %q", l.Token)
		}
		if l.Key != "" {
			if _, err := tte2.DecodeKey(l.Key); err != nil || !l.FromFragment {
				t.Fatalf("invalid key accepted: %+v", l)
			}
		}
		if l.Origin != "" && !strings.HasPrefix(l.Origin, "https://") {
			t.Fatalf("origin %q", l.Origin)
		}
		if l.Origin == "" && (l.Key != "" || l.Token != strings.TrimSpace(raw)) {
			t.Fatalf("bare token %+v from %q", l, raw)
		}
	})
}
