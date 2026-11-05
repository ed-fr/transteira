package strictjson

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// testSchema is a small tree exercising every node kind.
func testSchema() *Schema {
	return Object(map[string]*Schema{
		"name": Scalar(),
		"a/b~": Scalar(),
		"tags": Array(Scalar()),
		"config": Object(map[string]*Schema{
			"network": Object(map[string]*Schema{
				"internalCidrs": Array(Scalar()),
			}),
			"levels": Array(Object(map[string]*Schema{
				"id":    Scalar(),
				"rules": Object(map[string]*Schema{"x": Scalar()}).OrNull(),
			})),
		}),
		"matrix": Array(Array(Scalar())),
		"few":    Array(Object(map[string]*Schema{"k": Scalar()})).Max(2),
		"none":   Array(Scalar()).Max(0),
		"need": Object(map[string]*Schema{
			"a": Scalar(), "b": Object(map[string]*Schema{}).OrNull(), "c": Scalar(),
		}).Require("b").Require("a"),
	})
}

// TestCheck covers accepted documents and every failure reason with its
// pointer.
func TestCheck(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		maxDepth int
		wantPtr  string
		want     Reason // "" means accepted
	}{
		{name: "empty object", in: `{}`},
		{name: "full", in: `{"name":"x","a/b~":1.5e3,"tags":["a",true,null,-1],` +
			`"config":{"network":{"internalCidrs":["10.0.0.0/8"]},` +
			`"levels":[{"id":"c","rules":{"x":false}},{"rules":null}]},` +
			`"matrix":[[1],[]]}`, maxDepth: 5},
		{name: "whitespace around", in: " \n{\"name\" : null}\t "},
		{name: "escaped allowed name", in: `{"name":"x"}`},
		{name: "no depth bound", in: `{"matrix":[[1]]}`, maxDepth: 0},

		{name: "empty input", in: ``, want: ReasonSyntax, wantPtr: ""},
		{name: "only spaces", in: `   `, want: ReasonSyntax, wantPtr: ""},
		{name: "trailing value", in: `{} {}`, want: ReasonSyntax, wantPtr: ""},
		{name: "trailing garbage", in: `{}x`, want: ReasonSyntax, wantPtr: ""},
		{name: "trailing close", in: `{}]`, want: ReasonSyntax, wantPtr: ""},
		{name: "bad top token", in: `}`, want: ReasonSyntax, wantPtr: ""},
		{name: "unterminated object", in: `{"name":"x"`, want: ReasonSyntax, wantPtr: ""},
		{name: "trailing comma object", in: `{"name":1,}`, want: ReasonSyntax, wantPtr: ""},
		{name: "missing value", in: `{"name":}`, want: ReasonSyntax, wantPtr: "/name"},
		{name: "missing colon", in: `{"name" 1}`, want: ReasonSyntax, wantPtr: "/name"},
		{name: "non string key", in: `{1:2}`, want: ReasonSyntax, wantPtr: ""},
		{name: "bad number", in: `{"tags":[01]}`, want: ReasonSyntax, wantPtr: "/tags/1"},
		{name: "bad item", in: `{"tags":[1,x]}`, want: ReasonSyntax, wantPtr: "/tags/1"},
		{name: "trailing comma array", in: `{"tags":[1,]}`, want: ReasonSyntax, wantPtr: "/tags/1"},
		{name: "unterminated array", in: `{"tags":[1`, want: ReasonSyntax, wantPtr: "/tags/1"},
		{name: "mismatched close", in: `{"tags":[1}`, want: ReasonSyntax, wantPtr: "/tags"},

		{name: "duplicate", in: `{"name":1,"name":2}`, want: ReasonDuplicate, wantPtr: "/name"},
		{name: "duplicate escaped", in: `{"name":1,"name":2}`, want: ReasonDuplicate, wantPtr: "/name"},
		{
			name: "duplicate nested", in: `{"config":{"levels":[{},{"id":1,"id":1}]}}`,
			want: ReasonDuplicate, wantPtr: "/config/levels/1/id",
		},

		{name: "unknown", in: `{"nope":1}`, want: ReasonUnknownMember, wantPtr: "/nope"},
		{name: "case differs", in: `{"Name":"x"}`, want: ReasonUnknownMember, wantPtr: "/Name"},
		{
			name: "kelvin fold", in: `{"config":{"networK":{}}}`, want: ReasonUnknownMember,
			wantPtr: "/config/networK",
		},
		{name: "unknown escaped pointer", in: `{"x/y~z":1}`, want: ReasonUnknownMember, wantPtr: "/x~1y~0z"},
		{name: "allowed escaped pointer", in: `{"a/b~":{}}`, want: ReasonType, wantPtr: "/a~1b~0"},
		{
			name: "unknown nested", in: `{"config":{"network":{"internalCidrs":[],"extra":1}}}`,
			want: ReasonUnknownMember, wantPtr: "/config/network/extra",
		},

		{name: "root array", in: `[]`, want: ReasonType, wantPtr: ""},
		{name: "root scalar", in: `"x"`, want: ReasonType, wantPtr: ""},
		{name: "root null", in: `null`, want: ReasonType, wantPtr: ""},
		{name: "object for scalar", in: `{"name":{}}`, want: ReasonType, wantPtr: "/name"},
		{name: "array for scalar", in: `{"name":[]}`, want: ReasonType, wantPtr: "/name"},
		{name: "object for array", in: `{"tags":{}}`, want: ReasonType, wantPtr: "/tags"},
		{name: "scalar for array", in: `{"tags":"a"}`, want: ReasonType, wantPtr: "/tags"},
		{name: "null for array", in: `{"tags":null}`, want: ReasonType, wantPtr: "/tags"},
		{name: "array for object", in: `{"config":[]}`, want: ReasonType, wantPtr: "/config"},
		{
			name: "item shape", in: `{"config":{"network":{"internalCidrs":["a",["b"]]}}}`,
			want: ReasonType, wantPtr: "/config/network/internalCidrs/1",
		},
		{
			name: "nullable object wrong", in: `{"config":{"levels":[{"rules":1}]}}`,
			want: ReasonType, wantPtr: "/config/levels/0/rules",
		},

		{name: "too deep root", in: `{}`, maxDepth: 1},
		{name: "too deep", in: `{"matrix":[[1]]}`, maxDepth: 2, want: ReasonTooDeep, wantPtr: "/matrix/0"},
		{name: "depth ok", in: `{"matrix":[[1]]}`, maxDepth: 3},
		{name: "too deep object", in: `{"config":{}}`, maxDepth: 1, want: ReasonTooDeep, wantPtr: "/config"},

		{name: "at the limit", in: `{"few":[{},{"k":1}],"none":[]}`},
		{name: "too many", in: `{"few":[{},{},{}]}`, want: ReasonTooMany, wantPtr: "/few"},
		{name: "too many stops reading", in: `{"few":[{},{},{},x`, want: ReasonTooMany, wantPtr: "/few"},
		{name: "none allowed", in: `{"none":[1]}`, want: ReasonTooMany, wantPtr: "/none"},
		{name: "item before limit checked", in: `{"few":[{"x":1},{},{}]}`, want: ReasonUnknownMember, wantPtr: "/few/0/x"},

		{name: "required present", in: `{"need":{"a":1,"b":null}}`},
		{name: "required missing first given", in: `{"need":{}}`, want: ReasonRequired, wantPtr: "/need/b"},
		{name: "required missing", in: `{"need":{"b":{},"c":1}}`, want: ReasonRequired, wantPtr: "/need/a"},
		{name: "member error before required", in: `{"need":{"z":1}}`, want: ReasonUnknownMember, wantPtr: "/need/z"},

		{
			name: "long name truncated", in: `{"` + strings.Repeat("x", 70) + `":1}`, want: ReasonUnknownMember,
			wantPtr: "/" + strings.Repeat("x", 64) + "…",
		},
		{
			name: "long name cut at a character", in: `{"` + strings.Repeat("x", 63) + `é~":1}`, want: ReasonUnknownMember,
			wantPtr: "/" + strings.Repeat("x", 63) + "…",
		},
		{
			name: "name at the bound kept", in: `{"` + strings.Repeat("y", 64) + `":1}`, want: ReasonUnknownMember,
			wantPtr: "/" + strings.Repeat("y", 64),
		},
	}
	s := testSchema()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check([]byte(tt.in), s, tt.maxDepth)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Check(%s) = %v, want nil", tt.in, err)
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("Check(%s) = %v, want *Error", tt.in, err)
			}
			if e.Reason != tt.want || e.Pointer != tt.wantPtr {
				t.Fatalf("Check(%s) = {%q, %s}, want {%q, %s}", tt.in, e.Pointer, e.Reason, tt.wantPtr, tt.want)
			}
		})
	}
}

// TestErrorMessageHidesValue checks that the message names the reason and
// pointer only.
func TestErrorMessageHidesValue(t *testing.T) {
	err := Check([]byte(`{"name":"s3cr3t-value","nope":"s3cr3t-value"}`), testSchema(), 0)
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cr3t") {
		t.Fatalf("message leaks the value: %s", msg)
	}
	if msg != `strictjson: unknown-member at "/nope"` {
		t.Fatalf("message = %s", msg)
	}
	err = Check([]byte(`{"name":s3cr3t}`), testSchema(), 0)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("syntax message = %v", err)
	}
	if got := (&Error{Pointer: "/a\nb", Reason: ReasonType}).Error(); strings.Contains(got, "\n") {
		t.Fatalf("control character not quoted: %q", got)
	}
}

// TestPointer covers the RFC 6901 escapes and the segment types.
func TestPointer(t *testing.T) {
	tests := []struct {
		segs []any
		want string
	}{
		{nil, ""},
		{[]any{""}, "/"},
		{[]any{"a", 0, "b"}, "/a/0/b"},
		{[]any{"a/b", "m~n", "~1"}, "/a~1b/m~0n/~01"},
		{[]any{int64(7), uint8(3), "x"}, "/7/3/x"},
		{[]any{struct{ A string }{"/"}}, "/{~1}"},
	}
	for _, tt := range tests {
		if got := Pointer(tt.segs...); got != tt.want {
			t.Errorf("Pointer(%v) = %q, want %q", tt.segs, got, tt.want)
		}
	}
}

// TestSchemaAccessors covers the introspection used to compare a tree with
// the OpenAPI schemas.
func TestSchemaAccessors(t *testing.T) {
	s := testSchema()
	if s.Kind() != KindObject || s.Nullable() || s.Item() != nil {
		t.Fatal("root node")
	}
	want := []string{"a/b~", "config", "few", "matrix", "name", "need", "none", "tags"}
	if got := s.MemberNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("MemberNames = %v", got)
	}
	tags, ok := s.Member("tags")
	if !ok || tags.Kind() != KindArray || tags.Item().Kind() != KindScalar || !tags.Item().Nullable() {
		t.Fatal("tags node")
	}
	if got := tags.MemberNames(); len(got) != 0 {
		t.Fatalf("array MemberNames = %v", got)
	}
	if n, ok := tags.MaxItems(); ok || n != 0 {
		t.Fatal("tags has no limit")
	}
	few, _ := s.Member("few")
	if n, ok := few.MaxItems(); !ok || n != 2 {
		t.Fatalf("few limit = %d, %v", n, ok)
	}
	if none, _ := s.Member("none"); func() bool { n, ok := none.MaxItems(); return !ok || n != 0 }() {
		t.Fatal("none limit")
	}
	need, _ := s.Member("need")
	if got := need.Required(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("Required = %v", got)
	}
	if got := s.Required(); len(got) != 0 || tags.Required() == nil {
		t.Fatalf("root Required = %v", got)
	}
	// Max and Require copy: the original node is unchanged.
	base := Array(Scalar())
	if base.Max(1); func() bool { _, ok := base.MaxItems(); return ok }() {
		t.Fatal("Max must copy")
	}
	obj := Object(map[string]*Schema{"a": Scalar()})
	if obj.Require("a"); len(obj.Required()) != 0 {
		t.Fatal("Require must copy")
	}
	if _, ok := s.Member("Name"); ok {
		t.Fatal("Member must be case-sensitive")
	}
	n := tags.OrNull()
	if !n.Nullable() || tags.Nullable() {
		t.Fatal("OrNull must copy")
	}
	// The members map is copied: later changes to it do not leak in.
	m := map[string]*Schema{"a": Scalar()}
	o := Object(m)
	m["b"] = Scalar()
	if _, ok := o.Member("b"); ok {
		t.Fatal("Object must copy its map")
	}
}

// TestPanics covers the programmer errors.
func TestPanics(t *testing.T) {
	tests := map[string]func(){
		"nil member":      func() { Object(map[string]*Schema{"a": nil}) },
		"case clash":      func() { Object(map[string]*Schema{"name": Scalar(), "NAME": Scalar()}) },
		"nil item":        func() { Array(nil) },
		"nil schema":      func() { _ = Check([]byte(`{}`), nil, 0) },
		"max object":      func() { Object(nil).Max(1) },
		"max scalar":      func() { Scalar().Max(1) },
		"max negative":    func() { Array(Scalar()).Max(-1) },
		"require array":   func() { Array(Scalar()).Require() },
		"require unknown": func() { Object(map[string]*Schema{"a": Scalar()}).Require("b") },
		"require twice":   func() { Object(map[string]*Schema{"a": Scalar()}).Require("a", "a") },
		"require again":   func() { Object(map[string]*Schema{"a": Scalar()}).Require("a").Require("a") },
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("want a panic")
				}
			}()
			f()
		})
	}
}

// validPointer reports whether p is a syntactically valid RFC 6901 pointer.
func validPointer(p string) bool {
	if p == "" {
		return true
	}
	if p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' && (i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1')) {
			return false
		}
	}
	return true
}

// FuzzCheck asserts that Check never panics, that an accepted document is
// valid JSON and that a failure carries a known reason and a valid pointer.
func FuzzCheck(f *testing.F) {
	for _, seed := range []string{
		``, `{}`, `[]`, `null`, `{"name":"x"}`, `{"name":1,"name":2}`, `{"Name":1}`,
		`{"tags":[1,2,{"a":1}]}`, `{"config":{"network":{"internalCidrs":["10.0.0.0/8"]}}}`,
		`{"config":{"levels":[{"id":"c","rules":null}]}}`, `{"matrix":[[[1]]]}`,
		`{"a/b~":"\u0000"}`, `{"name":1}`, `{} {}`, `{"x/y~z":1}`, `{"tags":[1,]}`,
		"{\"name\":\"\xff\"}", `{"matrix":[[1e400]]}`,
		`{"few":[{},{},{}]}`, `{"none":[]}`, `{"need":{"a":1}}`, `{"need":{"a":1,"b":null}}`,
	} {
		f.Add([]byte(seed), 3)
	}
	s := testSchema()
	reasons := map[Reason]bool{
		ReasonSyntax: true, ReasonDuplicate: true,
		ReasonUnknownMember: true, ReasonType: true, ReasonTooDeep: true,
		ReasonTooMany: true, ReasonRequired: true,
	}
	f.Fuzz(func(t *testing.T, data []byte, maxDepth int) {
		err := Check(data, s, maxDepth)
		if err == nil {
			if !json.Valid(data) {
				t.Fatalf("accepted invalid JSON %q", data)
			}
			return
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("error %T is not *Error", err)
		}
		if !reasons[e.Reason] {
			t.Fatalf("unknown reason %q", e.Reason)
		}
		if !validPointer(e.Pointer) {
			t.Fatalf("invalid pointer %q", e.Pointer)
		}
		for _, seg := range strings.Split(e.Pointer, "/") {
			if len(seg) > 2*MaxPointerSegment+len("…") {
				t.Fatalf("pointer segment not truncated: %q", e.Pointer)
			}
		}
	})
}
