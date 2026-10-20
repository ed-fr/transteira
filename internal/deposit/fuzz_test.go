package deposit

import (
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

func FuzzParseRecognition(f *testing.F) {
	entry := strings.Repeat("A", recognitionEntryLen)
	f.Add("")
	f.Add(entry)
	f.Add(strings.Repeat(entry+".", 7))
	f.Add("junk..%%." + entry)
	f.Fuzz(func(t *testing.T, raw string) {
		entries := parseRecognition(raw)
		if len(entries) > RecognitionMaxEntries {
			t.Fatalf("%d entries", len(entries))
		}
		for i, e := range entries {
			if len(e) != recognitionRawLen {
				t.Fatalf("entry of %d bytes", len(e))
			}
			for _, o := range entries[:i] {
				if string(o) == string(e) {
					t.Fatal("duplicate entry")
				}
			}
		}
	})
}

func FuzzParseEmail(f *testing.F) {
	f.Add("Alice@Entity-A.example.com")
	f.Add(" a.b+c@example.com ")
	f.Add("user@192.0.2.1")
	f.Add("\"q\"@example.com")
	f.Fuzz(func(t *testing.T, raw string) {
		addr, err := parseEmail(raw)
		if err != nil {
			return
		}
		norm, err := store.NormalizeEmail(addr.mailbox)
		if err != nil || norm != addr.normalized || strings.ToLower(addr.mailbox) != addr.normalized {
			t.Fatalf("parseEmail(%q) = %+v, inconsistent", raw, addr)
		}
		if strings.ContainsFunc(addr.mailbox, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
			t.Fatalf("mailbox %q holds a space, control or non-ASCII character", addr.mailbox)
		}
	})
}

func FuzzValidCode(f *testing.F) {
	f.Add("123456")
	f.Add("12345a")
	f.Add("١٢٣٤٥٦")
	f.Fuzz(func(t *testing.T, code string) {
		want := len(code) == CodeDigits && strings.Trim(code, "0123456789") == ""
		if validCode(code) != want {
			t.Fatalf("validCode(%q) = %v", code, !want)
		}
	})
}

// TestLanguagesAgree checks that the languages i18n can render are exactly
// the languages a tenant and an invitation may carry.
func TestLanguagesAgree(t *testing.T) {
	t.Parallel()
	got, want := slices.Sorted(slices.Values(i18n.Supported())), slices.Sorted(slices.Values(tenant.Languages()))
	if !slices.Equal(got, want) {
		t.Fatalf("i18n.Supported() = %v, tenant.Languages() = %v", got, want)
	}
	for _, l := range append(want, "de", "EN", "") {
		if i18n.IsSupported(l) != tenant.IsLanguage(l) {
			t.Errorf("language %q: i18n %v, tenant %v", l, i18n.IsSupported(l), tenant.IsLanguage(l))
		}
	}
}
