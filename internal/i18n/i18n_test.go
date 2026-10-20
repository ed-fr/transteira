package i18n

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestSupported(t *testing.T) {
	got := Supported()
	if len(got) != 2 || got[0] != French || got[1] != English {
		t.Fatalf("Supported() = %v", got)
	}
	got[0] = "xx"
	if Supported()[0] != French {
		t.Fatal("Supported() must return a copy")
	}
	if !IsSupported("fr") || !IsSupported("en") || IsSupported("de") || IsSupported("FR") {
		t.Fatal("IsSupported mismatch")
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"fr": "fr", "FR": "fr", "fr-CH": "fr", "fr_FR": "fr", "en-GB": "en", "\ten": "en", "EN-us": "en",
	}
	for in, want := range cases {
		if got, ok := Normalize(in); !ok || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "de", "*", "f1", "-fr", "abcdefghi", "fré"} {
		if got, ok := Normalize(in); ok {
			t.Errorf("Normalize(%q) = %q, true; want false", in, got)
		}
	}
}

func TestNegotiate(t *testing.T) {
	cases := []struct {
		header, tenant, want string
	}{
		{"", "fr", "fr"},
		{"", "en", "en"},
		{"", "", "en"},
		{"", "de", "en"},
		{"", "fr-CA", "fr"},
		{"fr-CH, fr;q=0.9, en;q=0.8", "en", "fr"},
		{"de-DE,de;q=0.9", "fr", "fr"},
		{"de-DE,de;q=0.9,en;q=0.5", "fr", "en"},
		{"en;q=0.5, fr;q=0.8", "en", "fr"},
		{"en, fr", "fr", "en"},
		{"fr;q=0.7, en;q=0.7", "en", "fr"},
		{"fr;q=0, en;q=0.1", "fr", "en"},
		{"fr;q=0", "en", "en"},
		{"fr;q=abc, en;q=0.2", "fr", "en"},
		{"fr;q=1.5", "en", "en"},
		{"fr;q=-1", "en", "en"},
		{"*", "fr", "fr"},
		{"*;q=1, en;q=0.1", "fr", "en"},
		{"fr;level=1;q=0.4, en;q=0.3", "en", "fr"},
		{"fr ; Q = 0.9 , en;q=0.95", "fr", "en"},
		{",,, ;;; ,fr", "en", "fr"},
		{"\r\nfr", "en", "fr"},
	}
	for _, c := range cases {
		if got := Negotiate(c.header, c.tenant); got != c.want {
			t.Errorf("Negotiate(%q, %q) = %q; want %q", c.header, c.tenant, got, c.want)
		}
	}
}

func TestNegotiateLimits(t *testing.T) {
	// The supported language sits beyond the entry limit: it is ignored.
	h := strings.Repeat("de,", maxAcceptLanguageEntries) + "fr"
	if got := Negotiate(h, "en"); got != "en" {
		t.Fatalf("entry limit: got %q", got)
	}
	// The supported language sits beyond the length limit: it is ignored.
	h = strings.Repeat(" ", maxAcceptLanguageLen) + "fr"
	if got := Negotiate(h, "en"); got != "en" {
		t.Fatalf("length limit: got %q", got)
	}
}

func FuzzNegotiate(f *testing.F) {
	f.Add("fr-CH, fr;q=0.9, en;q=0.8", "fr")
	f.Add("*;q=0.1", "")
	f.Add("en;q=0.", "de")
	f.Fuzz(func(t *testing.T, header, tenant string) {
		if got := Negotiate(header, tenant); !IsSupported(got) {
			t.Fatalf("Negotiate returned unsupported %q", got)
		}
	})
}

func TestCatalogComplete(t *testing.T) {
	c := DefaultCatalog()
	ref := c.Keys(Default)
	if len(ref) == 0 {
		t.Fatal("empty default catalog")
	}
	for _, lang := range Supported() {
		got := c.Keys(lang)
		if strings.Join(got, ",") != strings.Join(ref, ",") {
			t.Errorf("catalog %q keys %v differ from %v", lang, got, ref)
		}
		for _, k := range got {
			if s, _ := c.Lookup(lang, k); strings.TrimSpace(s) == "" {
				t.Errorf("catalog %q key %q is empty", lang, k)
			}
		}
	}
}

func TestT(t *testing.T) {
	c := &Catalog{messages: map[string]map[string]string{
		"en": {"hello": "Hello {name}, from {org}", "only.en": "English only"},
		"fr": {"hello": "Bonjour {name}, de la part de {org}"},
	}}
	if got := c.T("fr", "hello", "name", "Alice", "org", "Entity A"); got != "Bonjour Alice, de la part de Entity A" {
		t.Errorf("fr: %q", got)
	}
	if got := c.T("fr", "only.en"); got != "English only" {
		t.Errorf("fallback: %q", got)
	}
	if got := c.T("de", "hello", "name", "{org}", "org", "X"); got != "Hello {org}, from X" {
		t.Errorf("unknown language / no re-expansion: %q", got)
	}
	if got := c.T("en", "missing.key"); got != "missing.key" {
		t.Errorf("missing key: %q", got)
	}
	if got := c.T("en", "hello", "name"); got != "Hello {name}, from {org}" {
		t.Errorf("odd pairs: %q", got)
	}
	if got := T("fr", "mail.footer.automated", "tenant", "Entité A"); !strings.Contains(got, "Entité A") {
		t.Errorf("package T: %q", got)
	}
}

func TestLoadCatalogErrors(t *testing.T) {
	if _, err := LoadCatalog(fstest.MapFS{"l/en.json": {Data: []byte(`{}`)}}, "l"); err == nil {
		t.Error("missing fr.json: want error")
	}
	bad := fstest.MapFS{
		"l/en.json": {Data: []byte(`{}`)},
		"l/fr.json": {Data: []byte(`[1]`)},
	}
	if _, err := LoadCatalog(bad, "l"); err == nil {
		t.Error("invalid JSON: want error")
	}
}

func TestFormatDate(t *testing.T) {
	d := time.Date(2026, time.August, 1, 23, 30, 0, 0, time.FixedZone("x", -2*3600))
	if got := FormatDate("fr", d); got != "2 août 2026" {
		t.Errorf("fr: %q", got)
	}
	if got := FormatDate("en", d); got != "August 2, 2026" {
		t.Errorf("en: %q", got)
	}
	if got := FormatDate("de", d); got != "August 2, 2026" {
		t.Errorf("fallback: %q", got)
	}
}
