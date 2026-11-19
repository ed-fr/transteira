package tenantops

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/id"
)

// FuzzClassifySearchQuery checks that ClassifySearchQuery never panics,
// that a refusal is always an *InvalidError on the query field, that it
// refuses every query longer than MaxSearchQueryLen characters, that a
// transfer identifier it reads is a valid identifier equal to the trimmed
// query but for its case, and that an address it reads holds "@" and is
// left unchanged by the normalization of the email filter of the transfer
// list (normalizeAddress), which the per-tenant reads apply again.
func FuzzClassifySearchQuery(f *testing.F) {
	for _, s := range []string{
		"trf_01JCQ3V8K2M4N6P8R0S2T4W6Y8", "trf_01jcq3v8k2m4n6p8r0s2t4w6y8", "TRF_01JCQ3V8K2M4N6P8R0S2T4W6Y8",
		" \u00a0trf_01JCQ3V8K2M4N6P8R0S2T4W6Y8\u3000", "trf_81JCQ3V8K2M4N6P8R0S2T4W6Y8", "trf_01JCQ3V8K2M4N6P8R0S2T4W6YU",
		"trf_01JCQ3V8K2M4N6P8R0S2T4W6Y", "trf_", "trf", "inv_01JCQ3V8K2M4N6P8R0S2T4W6Y8", "trf_\u0131JCQ3V8K2M4N6P8R0S2T4W6Y8", "trf_01JCQ3V8K2M4N6P8R0S2T4W6\u017f",
		"carol@customer.example.net", "Carol@Customer.Example.NET", " carol@customer.example.net\t", "carol@",
		"@customer.example.net", "Carol <carol@customer.example.net>", "carol@customer.example.net, dave@partner.example.org",
		"\"carol\"@customer.example.net", "carol@[192.0.2.1]", "carol", "%carol%", "", "   ", "@", "\xff",
		strings.Repeat("a", MaxSearchQueryLen), strings.Repeat("\u00e9", MaxSearchQueryLen+1), "a@b\r\nBcc: x@y.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		kind, value, err := ClassifySearchQuery(q)
		if err != nil {
			var ie *InvalidError
			if !errors.As(err, &ie) || ie.Field != FieldSearchQuery || kind != "" || value != "" {
				t.Fatalf("ClassifySearchQuery(%q) = %q, %q, %v: want an invalid %s alone", q, kind, value, err, FieldSearchQuery)
			}
			if ie.NotAnAddress && !strings.Contains(q, "@") {
				t.Fatalf("ClassifySearchQuery(%q): invalid-email without @", q)
			}
			return
		}
		if utf8.RuneCountInString(q) > MaxSearchQueryLen || !utf8.ValidString(q) {
			t.Fatalf("ClassifySearchQuery(%q) accepted a query of %d characters", q, utf8.RuneCountInString(q))
		}
		switch kind {
		case SearchByTransferID:
			if !id.Valid(id.Transfer, value) || !strings.EqualFold(strings.TrimSpace(q), value) {
				t.Fatalf("ClassifySearchQuery(%q) = transfer %q", q, value)
			}
		case SearchByEmail:
			again, ok := normalizeAddress(value)
			if !ok || again != value || !strings.Contains(value, "@") {
				t.Fatalf("ClassifySearchQuery(%q) = address %q, normalized again %q, %v", q, value, again, ok)
			}
		default:
			t.Fatalf("ClassifySearchQuery(%q) = unknown kind %q", q, kind)
		}
	})
}
