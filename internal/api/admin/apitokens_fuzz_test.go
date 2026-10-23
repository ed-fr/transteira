package admin

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// FuzzDecodeAPITokenUpdate checks that decodeAPITokenUpdate never panics,
// that it either decodes or answers validation-failed, and that what it
// decodes is a JSON object holding only the known members, none null.
func FuzzDecodeAPITokenUpdate(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"name":"x"}`, `{"allowedCidrs":["10.0.0.0/8"],"allowedSenders":[]}`, `{"name":null}`,
		`{"allowedSenders":["a@b.example","b.example"]}`, `{"unknown":1}`, `[1]`, `null`, `{`, `{"name":5}`,
		`{"a/b~c":1}`, `{"allowedSenders":null,"allowedCidrs":null,"name":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		in, err := decodeAPITokenUpdate(raw)
		if err != nil {
			var p *problem.Problem
			if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) == 0 {
				t.Fatalf("decodeAPITokenUpdate(%q) error %v is not validation-failed", raw, err)
			}
			return
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			t.Fatalf("decodeAPITokenUpdate(%q) accepted a non-object", raw)
		}
		for name := range members {
			switch name {
			case "name", "allowedCidrs", "allowedSenders":
			default:
				t.Fatalf("decodeAPITokenUpdate(%q) accepted the unknown member %q", raw, name)
			}
		}
		if _, ok := members["name"]; ok != (in.Name != nil) {
			t.Fatalf("decodeAPITokenUpdate(%q): name presence %v, decoded %v", raw, ok, in.Name)
		}
		if _, ok := members["allowedCidrs"]; ok != (in.AllowedCIDRs != nil) {
			t.Fatalf("decodeAPITokenUpdate(%q): allowedCidrs presence %v, decoded %#v", raw, ok, in.AllowedCIDRs)
		}
		if _, ok := members["allowedSenders"]; ok != (in.AllowedSenders != nil) {
			t.Fatalf("decodeAPITokenUpdate(%q): allowedSenders presence %v, decoded %#v", raw, ok, in.AllowedSenders)
		}
	})
}
