package antivirus

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustRule(t testing.TB, s string) Rule {
	t.Helper()
	r, err := ParseRule(s)
	if err != nil {
		t.Fatalf("ParseRule(%q): %v", s, err)
	}
	return r
}

func mustJSON(t testing.TB, s string) any {
	t.Helper()
	v, err := decodeJSON([]byte(s))
	if err != nil {
		t.Fatalf("decodeJSON(%q): %v", s, err)
	}
	return v
}

func TestParseRuleValid(t *testing.T) {
	for in, want := range map[string]string{
		"status=200":                            "status=200",
		"  status=200-299  ":                    "status=200-299",
		"status=200, 204 - 206":                 "status=200, 204 - 206",
		`status=200&&json:/Status="OK"`:         `status=200 && json:/Status="OK"`,
		`json:/a/0!= null`:                      `json:/a/0!= null`,
		`json:={"a":[1,2]}`:                     `json:={"a":[1,2]}`,
		`json:/m~0n/a~1b = 1.5e3`:               `json:/m~0n/a~1b = 1.5e3`,
		`json:/infected=true && status=200,406`: `json:/infected=true && status=200,406`,
	} {
		r, err := ParseRule(in)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", in, err)
			continue
		}
		if got := r.String(); got != want {
			t.Errorf("ParseRule(%q).String() = %q, want %q", in, got, want)
		}
		if r.IsZero() {
			t.Errorf("ParseRule(%q) is zero", in)
		}
		if again := mustRule(t, r.String()); again.String() != r.String() {
			t.Errorf("String of %q does not round-trip", in)
		}
	}
	if mustRule(t, "status=200").NeedsJSON() {
		t.Error("status rule needs JSON")
	}
	if !mustRule(t, `status=200 && json:/x=1`).NeedsJSON() {
		t.Error("JSON rule does not need JSON")
	}
}

func TestParseRuleInvalid(t *testing.T) {
	for _, in := range []string{
		"", " ", "status=200 &&", "&& status=200", "status=", "status=20", "status=2000", "status=099",
		"status=600", "status=abc", "status=2x0", "status=299-200", "status=200-", "status=200,,204",
		"stat=200", "json:/a", "json:a=1", "json:/a~2=1", "json:/a~=1", "json:/a=", "json:/a=nope",
		`json:/a="x" y`, `json:/a={"b":`, "json:/a=1 2", "STATUS=200",
		strings.Repeat("status=200&&", MaxRuleConditions) + "status=200",
		"status=200" + strings.Repeat(" ", MaxRuleLen),
	} {
		if r, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) = %q, want an error", in, r)
		}
	}
	// Exactly the bounds are accepted.
	if _, err := ParseRule(strings.Repeat("status=200&&", MaxRuleConditions-1) + "status=200"); err != nil {
		t.Errorf("rule with %d conditions: %v", MaxRuleConditions, err)
	}
	if _, err := ParseRule("status=200" + strings.Repeat(" ", MaxRuleLen-10)); err != nil {
		t.Errorf("rule of %d bytes: %v", MaxRuleLen, err)
	}
}

func TestRuleEval(t *testing.T) {
	doc := `{"Status":"OK","n":1,"f":1.0,"big":12345678901234567890,"arr":[1,"x",{"k":null}],` +
		`"obj":{"b":true,"a":[1,2]},"a/b":"slash","m~n":"tilde","":"empty","nul":null}`
	cases := []struct {
		rule   string
		status int
		want   bool
	}{
		{"status=200", 200, true},
		{"status=200", 201, false},
		{"status=200-299", 299, true},
		{"status=200-299", 300, false},
		{"status=200,204-206,406", 205, true},
		{"status=200,204-206,406", 406, true},
		{"status=200,204-206,406", 203, false},
		{`json:/Status="OK"`, 0, true},
		{`json:/Status!="OK"`, 0, false},
		{`json:/Status="FOUND"`, 0, false},
		{`json:/Status!="FOUND"`, 0, true},
		{`json:/n=1.0`, 0, true},
		{`json:/n=1e0`, 0, true},
		{`json:/f=1`, 0, true},
		{`json:/n=2`, 0, false},
		{`json:/n="1"`, 0, false},
		{`json:/big=12345678901234567890`, 0, true},
		{`json:/big=12345678901234567891`, 0, true}, // above int64: compared as float64
		{`json:/arr=[1,"x",{"k":null}]`, 0, true},
		{`json:/arr=[1,"x"]`, 0, false},
		{`json:/arr=[1,"x",{"k":0}]`, 0, false},
		{`json:/arr/2/k=null`, 0, true},
		{`json:/arr/1="x"`, 0, true},
		{`json:/obj={"a":[1,2],"b":true}`, 0, true},
		{`json:/obj={"a":[1,2]}`, 0, false},
		{`json:/obj={"a":[1,2],"c":true}`, 0, false},
		{`json:/obj/b=true`, 0, true},
		{`json:/obj/b=false`, 0, false},
		{`json:/obj/b="true"`, 0, false},
		{`json:/a~1b="slash"`, 0, true},
		{`json:/m~0n="tilde"`, 0, true},
		{`json:/="empty"`, 0, true},
		{`json:/nul=null`, 0, true},
		{`json:/nul!=null`, 0, false},
		{`json:/nul=false`, 0, false},
		{`status=200 && json:/Status="OK"`, 200, true},
		{`status=200 && json:/Status="OK"`, 406, false},
		{`status=406 && json:/missing="x"`, 200, false}, // stops at the first false condition
	}
	d := mustJSON(t, doc)
	for _, c := range cases {
		got, err := mustRule(t, c.rule).Eval(c.status, d)
		if err != nil || got != c.want {
			t.Errorf("Eval(%q, %d) = %t, %v, want %t", c.rule, c.status, got, err, c.want)
		}
	}
	for _, rule := range []string{
		`json:/missing="x"`, `json:/missing!="x"`, `json:/arr/3=1`, `json:/arr/-=1`, `json:/arr/01=1`,
		`json:/arr/x=1`, `json:/Status/0="O"`, `json:/nul/a=1`, `status=200 && json:/missing!=1`,
	} {
		got, err := mustRule(t, rule).Eval(200, d)
		if !errors.Is(err, errPointerMissing) || got {
			t.Errorf("Eval(%q) = %t, %v, want errPointerMissing", rule, got, err)
		}
	}
	if got, err := (Rule{}).Eval(200, d); !errors.Is(err, errRuleEmpty) || got {
		t.Errorf("zero Rule Eval = %t, %v", got, err)
	}
	// A nil document (body not decoded) only satisfies the empty pointer.
	if got, err := mustRule(t, `json:=null`).Eval(200, nil); err != nil || !got {
		t.Errorf("Eval on nil doc = %t, %v", got, err)
	}
	if _, err := mustRule(t, `json:/a=1`).Eval(200, nil); !errors.Is(err, errPointerMissing) {
		t.Errorf("Eval of a member on nil doc: %v", err)
	}
	long := `json:/` + strings.Repeat("p", 100) + `=1`
	if _, err := mustRule(t, long).Eval(200, map[string]any{}); err == nil || len(err.Error()) > 200 {
		t.Errorf("missing long pointer error = %v", err)
	}
}

func TestLookupPointer(t *testing.T) {
	// RFC 6901 section 5 examples.
	doc := mustJSON(t, `{"foo":["bar","baz"],"":0,"a/b":1,"c%d":2,"e^f":3,"g|h":4,"i\\j":5,"k\"l":6," ":7,"m~n":8}`)
	for ptr, want := range map[string]string{
		"/foo": `["bar","baz"]`, "/foo/0": `"bar"`, "/": "0", "/a~1b": "1", "/c%d": "2", "/e^f": "3",
		"/g|h": "4", "/i\\j": "5", "/k\"l": "6", "/\x20": "7", "/m~0n": "8",
	} {
		v, found, err := lookupPointer(doc, ptr)
		if err != nil || !found {
			t.Errorf("lookupPointer(%q) = %v, %t, %v", ptr, v, found, err)
			continue
		}
		if !jsonEqual(v, mustJSON(t, want)) {
			t.Errorf("lookupPointer(%q) = %v, want %s", ptr, v, want)
		}
	}
	if v, found, err := lookupPointer(doc, ""); err != nil || !found || !jsonEqual(v, doc) {
		t.Errorf("empty pointer = %v, %t, %v", v, found, err)
	}
	for _, ptr := range []string{"/nope", "/foo/2", "/foo/-", "/foo/00", "/foo/-1", "/foo/1234567890", "/foo/0/x", "/foo/"} {
		if _, found, err := lookupPointer(doc, ptr); err != nil || found {
			t.Errorf("lookupPointer(%q) found = %t, err = %v", ptr, found, err)
		}
	}
	for _, ptr := range []string{"foo", "/~", "/~2", "/a~"} {
		if _, _, err := lookupPointer(doc, ptr); err == nil {
			t.Errorf("lookupPointer(%q) accepted", ptr)
		}
	}
}

func TestJSONEqual(t *testing.T) {
	if jsonEqual(struct{}{}, struct{}{}) {
		t.Error("unknown types compare equal")
	}
	if jsonEqual(nil, false) || jsonEqual(json.Number("1"), "1") || jsonEqual(true, "true") {
		t.Error("values of different types compare equal")
	}
	if !numberEqual("1e400", "2e400") {
		t.Error("out-of-range numbers do not compare as infinities")
	}
	if numberEqual("9007199254740993", "9007199254740992") {
		t.Error("int64 values compared as float64")
	}
}

func FuzzParseRule(f *testing.F) {
	for _, s := range []string{
		"status=200", "status=200-299,406", `status=200 && json:/Status="OK"`, `json:/a/0!={"b":[1,null]}`,
		`json:/m~0n~1=1.5e3`, "status=", "json:", "&&", "json:/a!=",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRule(s)
		if err != nil {
			if !r.IsZero() {
				t.Fatal("error with a non-zero rule")
			}
			return
		}
		if r.IsZero() || len(r.conds) > MaxRuleConditions || len(s) > MaxRuleLen {
			t.Fatalf("accepted out-of-bounds rule %q", s)
		}
		again, err := ParseRule(r.String())
		if err != nil {
			t.Fatalf("String %q of %q does not parse: %v", r.String(), s, err)
		}
		if again.String() != r.String() || again.NeedsJSON() != r.NeedsJSON() {
			t.Fatalf("String of %q does not round-trip", s)
		}
	})
}

func FuzzRuleEval(f *testing.F) {
	f.Add(`status=200 && json:/Status="OK"`, `{"Status":"OK","Description":""}`, 200)
	f.Add(`status=406 && json:/Status="FOUND"`, `{"Status":"FOUND","Description":"Eicar-Test-Signature"}`, 406)
	f.Add(`json:/a/1!=[1,{"b":2}]`, `{"a":[0,[1,{"b":2.0}]]}`, 200)
	f.Add(`json:=null`, `null`, 500)
	f.Add(`status=200`, `not json`, 200)
	f.Add(`json:/x=1`, `[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]`, 302)
	f.Fuzz(func(t *testing.T, rule, body string, status int) {
		r, err := ParseRule(rule)
		if err != nil {
			return
		}
		doc, derr := decodeJSON([]byte(body))
		if derr == nil {
			if ok, err := r.Eval(status, doc); err != nil && ok {
				t.Fatal("true with an error")
			}
		}
		// The whole verdict path: only a Clean or Infected result, or a
		// classified error.
		c := &HTTPClient{
			url: mustURL(t, "http://engine.example.com/scan"), clean: r, infected: mustRule(t, `json:/infected=true`),
			needJSON: true, sigPointer: "/sig",
		}
		res, err := c.verdict(status, []byte(body))
		switch {
		case err != nil:
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("verdict error not ErrProtocol: %v", err)
			}
		case res.Verdict == Clean:
			if res.Signature != "" {
				t.Fatal("clean with a signature")
			}
		case res.Verdict == Infected:
			if res.Signature == "" || res.Signature != sanitizeSignature(res.Signature) || len(res.Signature) > MaxSignatureLen {
				t.Fatalf("unsafe signature %q", res.Signature)
			}
		default:
			t.Fatalf("unexpected result %+v", res)
		}
	})
}

func FuzzJSONPointer(f *testing.F) {
	f.Add(`{"foo":["bar","baz"],"a/b":1,"m~n":{"x":[null]}}`, "/foo/1")
	f.Add(`{"a/b":1}`, "/a~1b")
	f.Add(`{"m~n":{"x":[null]}}`, "/m~0n/x/0")
	f.Add(`[1,2,3]`, "/-")
	f.Add(`1`, "")
	f.Add(`{}`, "/~2")
	f.Fuzz(func(t *testing.T, body, ptr string) {
		doc, err := decodeJSON([]byte(body))
		if err != nil {
			return
		}
		v, found, err := lookupPointer(doc, ptr)
		if (err != nil) != (checkPointer(ptr) != nil) {
			t.Fatalf("lookupPointer(%q) error %v disagrees with checkPointer", ptr, err)
		}
		if err != nil && (found || v != nil) {
			t.Fatal("found with an error")
		}
		if !found && v != nil {
			t.Fatal("value without found")
		}
		if ptr == "" && (!found || !jsonEqual(v, doc)) {
			t.Fatal("empty pointer does not designate the document")
		}
	})
}

func TestConditionEvalInvalidPointer(t *testing.T) {
	// Pointers are validated when a rule is parsed: eval still refuses one
	// that was not.
	c := condition{isJSON: true, pointer: "no-slash"}
	if ok, err := c.eval(200, map[string]any{}); ok || err == nil {
		t.Fatalf("eval = %t, %v", ok, err)
	}
}
