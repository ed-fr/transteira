// Package i18n holds the language support of TransTeira (CLAUDE.md section
// 14): the list of supported languages, the negotiation of the language of a
// request from its Accept-Language header and the tenant default, a small
// message catalog and locale-aware date formatting.
//
// The catalog is deliberately minimal: it serves the mail templates today
// and will be extended by the web interface. Adding a language means adding
// its code to [Supported], a locales/<code>.json file and its month names.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Language codes supported by TransTeira.
const (
	// French.
	French = "fr"
	// English.
	English = "en"
	// Default is the last-resort language, used when neither the request nor
	// the tenant names a supported language.
	Default = English
)

// Limits applied to an Accept-Language header, so that a hostile header
// cannot make negotiation expensive.
const (
	maxAcceptLanguageLen     = 1024
	maxAcceptLanguageEntries = 32
)

// supported lists the supported languages, in display order.
var supported = []string{French, English}

// Supported returns the supported language codes, in display order. The
// returned slice is a copy.
func Supported() []string {
	return append([]string(nil), supported...)
}

// IsSupported reports whether lang is exactly a supported language code
// (lowercase primary subtag, for example "fr").
func IsSupported(lang string) bool {
	for _, l := range supported {
		if l == lang {
			return true
		}
	}
	return false
}

// Normalize maps a BCP 47 language tag (or a POSIX-style one using "_") to a
// supported language code by its primary subtag, case-insensitively: "fr-CH",
// "FR" and "fr_FR" all give "fr". It reports false when the tag is malformed
// or its language is not supported.
func Normalize(tag string) (string, bool) {
	tag = strings.TrimSpace(tag)
	primary, _, _ := strings.Cut(strings.ReplaceAll(tag, "_", "-"), "-")
	if primary == "" || len(primary) > 8 {
		return "", false
	}
	for i := range len(primary) {
		c := primary[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return "", false
		}
	}
	lang := strings.ToLower(primary)
	if !IsSupported(lang) {
		return "", false
	}
	return lang, true
}

// candidate is one acceptable language read from an Accept-Language header.
type candidate struct {
	lang string
	q    float64
}

// Negotiate picks the language of a request (CLAUDE.md section 14): the
// supported language with the highest quality value in acceptLanguage (an
// HTTP Accept-Language header, RFC 9110 section 12.5.4), matched by primary
// subtag so that "fr-CH" selects "fr". Entries with q=0, a malformed q-value
// or an unsupported language are ignored, as is the "*" wildcard. Among equal
// q-values the first listed wins. When nothing matches, the tenant default
// is used if it is supported, then [Default].
func Negotiate(acceptLanguage, tenantDefault string) string {
	if len(acceptLanguage) > maxAcceptLanguageLen {
		acceptLanguage = acceptLanguage[:maxAcceptLanguageLen]
	}
	var cands []candidate
	for i, part := range strings.Split(acceptLanguage, ",") {
		if i >= maxAcceptLanguageEntries {
			break
		}
		if c, ok := parseEntry(part); ok {
			cands = append(cands, c)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].q > cands[j].q })
	if len(cands) > 0 {
		return cands[0].lang
	}
	if lang, ok := Normalize(tenantDefault); ok {
		return lang
	}
	return Default
}

// parseEntry parses one "tag;q=0.8" element of an Accept-Language header.
func parseEntry(part string) (candidate, bool) {
	tag, params, _ := strings.Cut(part, ";")
	q := 1.0
	for p := range strings.SplitSeq(params, ";") {
		k, v, found := strings.Cut(p, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || parsed < 0 || parsed > 1 {
			return candidate{}, false
		}
		q = parsed
	}
	if q <= 0 {
		return candidate{}, false
	}
	lang, ok := Normalize(tag)
	if !ok {
		return candidate{}, false
	}
	return candidate{lang: lang, q: q}, true
}

//go:embed locales/*.json
var localeFS embed.FS

// Catalog maps, for each language, message keys to translated texts. Texts
// may contain {name} placeholders, replaced by [Catalog.T]. A Catalog is
// read-only once built and safe for concurrent use.
type Catalog struct {
	messages map[string]map[string]string
}

// defaultCatalog is the catalog embedded in the binary.
var defaultCatalog = mustLoadDefault()

// mustLoadDefault loads the embedded catalog; a broken embedded file is a
// build defect, caught by the tests.
func mustLoadDefault() *Catalog {
	c, err := LoadCatalog(localeFS, "locales")
	if err != nil {
		panic(err)
	}
	return c
}

// DefaultCatalog returns the catalog embedded in the binary.
func DefaultCatalog() *Catalog {
	return defaultCatalog
}

// LoadCatalog reads one <lang>.json file per supported language from dir in
// fsys. Each file is a flat JSON object of key to text. A missing or invalid
// file is an error.
func LoadCatalog(fsys fs.FS, dir string) (*Catalog, error) {
	c := &Catalog{messages: make(map[string]map[string]string, len(supported))}
	for _, lang := range supported {
		raw, err := fs.ReadFile(fsys, path.Join(dir, lang+".json"))
		if err != nil {
			return nil, fmt.Errorf("i18n: read catalog %q: %w", lang, err)
		}
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("i18n: parse catalog %q: %w", lang, err)
		}
		c.messages[lang] = m
	}
	return c, nil
}

// Keys returns the sorted message keys defined for lang.
func (c *Catalog) Keys(lang string) []string {
	keys := make([]string, 0, len(c.messages[lang]))
	for k := range c.messages[lang] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Lookup returns the raw text of key in lang, without placeholder
// substitution or fallback.
func (c *Catalog) Lookup(lang, key string) (string, bool) {
	s, ok := c.messages[lang][key]
	return s, ok
}

// T returns the text of key in lang, falling back to [Default] and then to
// the key itself, so that a missing translation is visible but never fatal.
// pairs are name, value, name, value...: each {name} placeholder is replaced
// by its value. An odd trailing name is ignored. Values are inserted as-is:
// escaping is the caller's job (html/template does it for mail templates).
func (c *Catalog) T(lang, key string, pairs ...string) string {
	s, ok := c.Lookup(lang, key)
	if !ok {
		if s, ok = c.Lookup(Default, key); !ok {
			return key
		}
	}
	if len(pairs) < 2 {
		return s
	}
	oldnew := make([]string, 0, len(pairs)&^1)
	for i := 0; i+1 < len(pairs); i += 2 {
		oldnew = append(oldnew, "{"+pairs[i]+"}", pairs[i+1])
	}
	return strings.NewReplacer(oldnew...).Replace(s)
}

// T is [Catalog.T] on the [DefaultCatalog].
func T(lang, key string, pairs ...string) string {
	return defaultCatalog.T(lang, key, pairs...)
}

// monthNames holds the month names of the languages whose dates are not
// formatted with the English layout.
var monthNames = map[string][12]string{
	French: {
		"janvier", "février", "mars", "avril", "mai", "juin",
		"juillet", "août", "septembre", "octobre", "novembre", "décembre",
	},
}

// FormatDate formats the calendar date of t, in UTC, the way lang writes it:
// "20 octobre 2026" in French, "October 20, 2026" in English (and for any
// unsupported language).
func FormatDate(lang string, t time.Time) string {
	t = t.UTC()
	if names, ok := monthNames[lang]; ok {
		return fmt.Sprintf("%d %s %d", t.Day(), names[t.Month()-1], t.Year())
	}
	return t.Format("January 2, 2006")
}
