package admin

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// FuzzDecodeDropLinkUpdate checks that decodeDropLinkUpdate never panics,
// that it either decodes or answers validation-failed with field errors,
// and that what it decodes is a JSON object holding only the known
// members, none null but confidentialityLevel.
func FuzzDecodeDropLinkUpdate(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"label":"x"}`, `{"recipients":["a@entity-a.example.com"],"validityDays":7,"enabled":true}`,
		`{"confidentialityLevel":null}`, `{"confidentialityLevel":""}`, `{"confidentialityLevel":5}`,
		`{"label":null}`, `{"recipients":[]}`, `{"recipients":[1]}`, `{"validityDays":"7"}`,
		`{"unknown":1}`, `[1]`, `null`, `{`, `{"a/b~c":1}`, `{"enabled":null,"recipients":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		in, err := decodeDropLinkUpdate(raw)
		if err != nil {
			var p *problem.Problem
			if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) == 0 {
				t.Fatalf("decodeDropLinkUpdate(%q) error %v is not validation-failed", raw, err)
			}
			return
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			t.Fatalf("decodeDropLinkUpdate(%q) accepted a non-object", raw)
		}
		for name, v := range members {
			switch name {
			case "label", "recipients", "validityDays", "enabled":
				if string(v) == "null" {
					t.Fatalf("decodeDropLinkUpdate(%q) accepted a null %s", raw, name)
				}
			case "confidentialityLevel":
			default:
				t.Fatalf("decodeDropLinkUpdate(%q) accepted the unknown member %q", raw, name)
			}
		}
		if _, ok := members["confidentialityLevel"]; ok != in.LevelSet {
			t.Fatalf("decodeDropLinkUpdate(%q): level presence %v, LevelSet %v", raw, ok, in.LevelSet)
		}
		if _, ok := members["recipients"]; ok != (in.Recipients != nil) {
			t.Fatalf("decodeDropLinkUpdate(%q): recipients presence %v, decoded %#v", raw, ok, in.Recipients)
		}
	})
}
