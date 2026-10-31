package textproposals_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/markup"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/textproposals"
	"github.com/ed-fr/transteira/internal/textsafe"
)

var docs = []string{textproposals.LegalNotice, textproposals.PrivacyPolicy}

// markers matches every marker of the templates, in both languages.
var markers = regexp.MustCompile(`\[(À compléter|To complete) ?: [^\]]*\]`)

func facts() textproposals.Facts {
	return textproposals.Facts{
		TenantName: "Entity A", FQDN: "transfer.entity-a.example.com",
		ValidityDays: []int{30, 1, 7, 7}, VerifiedRetentionMonths: 9, InvitationRetentionMonths: 8,
		LogRetentionMonths: 7, AntivirusEnabled: true,
	}
}

// validLegal replicates the check of tenantadmin.UpdateLegal.
func validLegal(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && utf8.RuneCountInString(s) <= store.MaxLegalContentLen
}

func TestProposeAll(t *testing.T) {
	for _, lang := range i18n.Supported() {
		for _, doc := range docs {
			md, err := textproposals.Propose(doc, lang, facts())
			if err != nil {
				t.Fatalf("%s/%s: %v", doc, lang, err)
			}
			if !validLegal(md) || strings.Contains(md, "\r") || strings.Contains(md, "{{") {
				t.Errorf("%s/%s: invalid proposal", doc, lang)
			}
			if !strings.Contains(md, "Entity A") || !strings.Contains(md, `transfer\.entity\-a\.example\.com`) {
				t.Errorf("%s/%s: facts missing", doc, lang)
			}
			if !textproposals.HasPlaceholder(md) {
				t.Errorf("%s/%s: no marker", doc, lang)
			}
			html := markup.Markdown(md)
			if !strings.Contains(html, "<h2>") || strings.Contains(html, "<a ") || strings.Contains(html, "{{") {
				t.Errorf("%s/%s: unexpected rendering", doc, lang)
			}
			if done := markers.ReplaceAllString(md, "Done"); textproposals.HasPlaceholder(done) {
				t.Errorf("%s/%s: marker left after replacement:\n%s", doc, lang, done)
			}
		}
	}
}

func TestPrivacyContent(t *testing.T) {
	fr, _ := textproposals.Propose(textproposals.PrivacyPolicy, "fr", facts())
	for _, w := range []string{"1, 7 et 30 jours", "vérifiées sont supprimées après 9 mois", "invitations sont supprimées après 8 mois", "conservés 7 mois", "analysé par un antivirus", "CNIL", "cookies strictement techniques"} {
		if !strings.Contains(fr, w) {
			t.Errorf("fr: missing %q", w)
		}
	}
	en, _ := textproposals.Propose(textproposals.PrivacyPolicy, "en", facts())
	for _, w := range []string{"1, 7 and 30 days", "addresses are deleted after 9 months", "Invitations are deleted after 8 months", "kept for 7 months", "scanned by an antivirus", "supervisory authority"} {
		if !strings.Contains(en, w) {
			t.Errorf("en: missing %q", w)
		}
	}
}

func TestFactsVariants(t *testing.T) {
	f := textproposals.Facts{TenantName: "A", FQDN: "a.example.com"}
	md, _ := textproposals.Propose(textproposals.PrivacyPolicy, "fr", f)
	if strings.Contains(md, "antivirus") || strings.Count(md, "12 mois") != 3 ||
		!strings.Contains(md, "[À compléter : durées de validité") {
		t.Errorf("defaults not applied:\n%s", md)
	}
	for days, want := range map[string]string{"1": "after 1 day depending", "0,-3,7": "after 7 days depending", "7,30": "7 and 30 days"} {
		f.ValidityDays = nil
		for _, d := range strings.Split(days, ",") {
			n := 0
			neg := strings.HasPrefix(d, "-")
			for _, c := range strings.TrimPrefix(d, "-") {
				n = n*10 + int(c-'0')
			}
			if neg {
				n = -n
			}
			f.ValidityDays = append(f.ValidityDays, n)
		}
		md, _ = textproposals.Propose(textproposals.PrivacyPolicy, "en", f)
		if !strings.Contains(md, want) {
			t.Errorf("days %s: missing %q in %s", days, want, md)
		}
	}
}

func TestUnknown(t *testing.T) {
	for _, c := range [][2]string{{"x", "fr"}, {"legal-notice", "de"}, {"../legal-notice", "fr"}, {"legal-notice", "../fr"}, {"", ""}} {
		if _, err := textproposals.Propose(c[0], c[1], facts()); !errors.Is(err, textproposals.ErrUnknown) {
			t.Errorf("%v: err = %v", c, err)
		}
	}
}

var hostile = []string{
	"[x](javascript:alert(1))", "<b>bold</b>", "<script>alert(1)</script>", "# Title", "- item", "1. item",
	"**bold**", "_it_", "`code`", "a\n\n# Injected\n- x", "a\r\nb\tc", "x" + string(rune(0x202e)) + "evil" + string(rune(0x2066)) + "",
	"![i](https://e.example.com/p.png)", "<https://evil.example.com>", `\`, `a\`,
	"[À compléter : x]", "[To complete: x]", "[" + string(rune(0x200b)) + "To complete: x]", "{{FQDN}}", "mailto:a@example.com",
}

func TestHostileFacts(t *testing.T) {
	for _, h := range hostile {
		for _, lang := range i18n.Supported() {
			for _, doc := range docs {
				md, err := textproposals.Propose(doc, lang, textproposals.Facts{TenantName: h, FQDN: h})
				if err != nil {
					t.Fatal(err)
				}
				html := markup.Markdown(md)
				for _, bad := range []string{"<a ", "<img", "<script", "<b>", "<h4>Title", "Injected</h", "<li>item"} {
					if strings.Contains(html, bad) && !strings.Contains(h, "item") {
						t.Errorf("%q: %q in %s", h, bad, html)
					}
				}
				for _, r := range md {
					if r != '\n' && textsafe.IsHidden(r) {
						t.Errorf("%q: hidden rune %U kept", h, r)
					}
				}
			}
		}
	}
}

func TestValueNeverAddsOrHidesMarker(t *testing.T) {
	prefixes := []string{"[À compléter", "[To complete"}
	for _, lang := range i18n.Supported() {
		for _, doc := range docs {
			ref, _ := textproposals.Propose(doc, lang, textproposals.Facts{TenantName: "A", FQDN: "b"})
			for _, v := range []string{"[À compléter : x]", "[To complete: x]", `\[To complete`, `\`, "[" + string(rune(0x202e)) + "À compléter", "[[To complete"} {
				md, _ := textproposals.Propose(doc, lang, textproposals.Facts{TenantName: v, FQDN: v})
				for _, p := range prefixes {
					if strings.Count(md, p) != strings.Count(ref, p) {
						t.Errorf("%s/%s %q: marker count changed for %q", doc, lang, v, p)
					}
				}
			}
			md, _ := textproposals.Propose(doc, lang, textproposals.Facts{TenantName: `\`, FQDN: `\`})
			if !textproposals.HasPlaceholder(md) {
				t.Errorf("%s/%s: marker hidden", doc, lang)
			}
		}
	}
}

func TestEscapeValue(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"  plain  ":                      "plain",
		"a.b-c":                          `a\.b\-c`,
		"# T":                            `\# T`,
		"a\nb":                           "a b",
		"x" + string(rune(0x202e)) + "y": "xy",
		`a\b`:                            `a\\b`,
		"[To complete: x]":               "To complete: x",
		"[x](y)":                         `\[x\]\(y\)`,
		"<b>!+*_</b>":                    `\<b\>\!\+\*\_\</b\>`,
	}
	for in, want := range cases {
		if got := textproposals.EscapeValue(in); got != want {
			t.Errorf("EscapeValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasPlaceholder(t *testing.T) {
	for in, want := range map[string]bool{
		"": false, "done": false, "[À compléter : x]": true, `\[À compléter : x]`: true,
		"[To complete: x]": true, `\[To complete: x]`: true, "to complete": false, "[a complete]": false,
	} {
		if got := textproposals.HasPlaceholder(in); got != want {
			t.Errorf("HasPlaceholder(%q) = %v", in, got)
		}
	}
}

func TestNoticeKey(t *testing.T) {
	if textproposals.NoticeKey != "setup.textProposal.reviewNotice" {
		t.Fatal("unexpected key")
	}
}

func FuzzPropose(f *testing.F) {
	for _, s := range hostile {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, name, fqdn string) {
		for _, lang := range i18n.Supported() {
			for _, doc := range docs {
				md, err := textproposals.Propose(doc, lang, textproposals.Facts{TenantName: name, FQDN: fqdn, AntivirusEnabled: true})
				if err != nil {
					t.Fatal(err)
				}
				if !textproposals.HasPlaceholder(md) {
					t.Fatal("markers lost")
				}
				html := markup.Markdown(md)
				for _, bad := range []string{"<a ", "<img", "<script", "<iframe", "<h1"} {
					if strings.Contains(html, bad) {
						t.Fatalf("active content %q for %q/%q: %s", bad, name, fqdn, html)
					}
				}
				// A raw "<" of the input never reaches the Markdown unescaped.
				if strings.Count(md, "<") != strings.Count(md, `\<`) {
					t.Fatalf("raw < for %q/%q", name, fqdn)
				}
			}
		}
	})
}
