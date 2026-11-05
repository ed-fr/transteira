package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestCanonicalizeRFC8785Vectors checks the RFC 8785 examples that fall
// within the integer-only subset.
func TestCanonicalizeRFC8785Vectors(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			// RFC 8785 section 3.2.2.2.
			name: "string escaping",
			in:   `"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"`,
			want: `"€$\u000f\nA'B\"\\\\\"/"`,
		},
		{
			// RFC 8785 section 3.2.3: UTF-16 code unit ordering.
			name: "member sorting",
			in: `{
   "\u20ac": "Euro Sign",
   "\r": "Carriage Return",
   "\ufb33": "Hebrew Letter Dalet With Dagesh",
   "1": "One",
   "\ud83d\ude00": "Emoji: Grinning Face",
   "\u0080": "Control",
   "\u00f6": "Latin Small Letter O With Diaeresis"
}`,
			want: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\"," +
				"\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\"," +
				"\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
		{
			// RFC 8785 section 3.2.4, without the floating-point numbers.
			name: "sample without floats",
			in: `{
  "numbers": [333333333, 4, 2e0],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`,
			want: "",
		},
		{
			name: "sample integers only",
			in: `{
  "numbers": [333333333, 4, 2, -9007199254740991],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`,
			want: `{"literals":[null,true,false],"numbers":[333333333,4,2,-9007199254740991],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if tt.want == "" {
				if !errors.Is(err, ErrNumber) {
					t.Fatalf("err = %v, want ErrNumber", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// TestCanonicalizeValid covers accepted inputs and their canonical form.
func TestCanonicalizeValid(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty object", ` { } `, `{}`},
		{"empty array", "\t[\r\n]\n", `[]`},
		{"true", `true`, `true`},
		{"false", `false`, `false`},
		{"null", `null`, `null`},
		{"zero", `0`, `0`},
		{"negative", `-42`, `-42`},
		{"max safe integer", `9007199254740991`, `9007199254740991`},
		{"min safe integer", `-9007199254740991`, `-9007199254740991`},
		{"sixteen digits", `1000000000000000`, `1000000000000000`},
		{"empty string", `""`, `""`},
		{"nested", `{"b":[1,{"d":null,"c":[]}],"a":{}}`, `{"a":{},"b":[1,{"c":[],"d":null}]}`},
		{"array order kept", `[3, 1, 2]`, `[3,1,2]`},
		{"whitespace everywhere", " { \"a\" : [ 1 , 2 ] , \"b\" : \"x\" } ", `{"a":[1,2],"b":"x"}`},
		{"short escapes", `"\b\f\n\r\t\"\\\/"`, `"\b\f\n\r\t\"\\/"`},
		{"short escapes from \\u", `"\u0008\u000C\u000a\u000D\u0009"`, `"\b\f\n\r\t"`},
		{"other controls lowercase", `"\u0000\u001F\u001b\u007f"`, "\"\\u0000\\u001f\\u001b\u007f\""},
		{"no html escaping", `"<>&\u003c\u003E\u0026"`, `"<>&<>&"`},
		{"line separators literal", `"\u2028\u2029"`, "\"\u2028\u2029\""},
		{"non-ASCII literal", `"é漢😀"`, `"é漢😀"`},
		{"surrogate pair escape", `"\uD83D\uDE02"`, `"😂"`},
		{"noncharacter", `"\uffff"`, "\"\uffff\""},
		{"replacement character", `"\ufffd"`, "\"\ufffd\""},
		{
			"UTF-16 order differs from byte order",
			`{"\uffff":1,"😀":2,"\ue000":3}`,
			"{\"😀\":2,\"\ue000\":3,\"\uffff\":1}",
		},
		{"prefix sorts first", `{"ab":1,"a":2,"":3}`, `{"":3,"a":2,"ab":1}`},
		{"keys with escapes", `{"a\nb":1,"a\u0000":2}`, `{"a\u0000":2,"a\nb":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Fatalf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// TestCanonicalizeErrors covers every rejection and its sentinel error.
func TestCanonicalizeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", ``, ErrSyntax},
		{"only whitespace", `  `, ErrSyntax},
		{"trailing garbage", `{} x`, ErrSyntax},
		{"two values", `1 2`, ErrSyntax},
		{"bad literal", `nul`, ErrSyntax},
		{"capitalized literal", `True`, ErrSyntax},
		{"unexpected character", `@`, ErrSyntax},
		{"plus sign", `+1`, ErrSyntax},
		{"lone minus", `-`, ErrSyntax},
		{"minus letter", `-a`, ErrSyntax},
		{"leading zero", `01`, ErrNumber},
		{"negative leading zero", `-00`, ErrNumber},
		{"negative zero", `-0`, ErrNumber},
		{"fraction", `1.0`, ErrNumber},
		{"exponent", `1E2`, ErrNumber},
		{"lower exponent", `1e2`, ErrNumber},
		{"zero fraction", `0.5`, ErrNumber},
		{"two to the 53", `9007199254740992`, ErrNumber},
		{"minus two to the 53", `-9007199254740992`, ErrNumber},
		{"seventeen digits", `10000000000000000`, ErrNumber},
		{"huge", `123456789012345678901234567890`, ErrNumber},
		{"number in array", `[1.5]`, ErrNumber},
		{"unterminated object", `{`, ErrSyntax},
		{"object missing name", `{1:2}`, ErrSyntax},
		{"object missing colon", `{"a" 1}`, ErrSyntax},
		{"object missing value", `{"a":}`, ErrSyntax},
		{"object trailing comma", `{"a":1,}`, ErrSyntax},
		{"object missing separator", `{"a":1 "b":2}`, ErrSyntax},
		{"object truncated after value", `{"a":1`, ErrSyntax},
		{"object bad name", `{"\x":1}`, ErrSyntax},
		{"duplicate key", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"duplicate key by escape", `{"a":1,"\u0061":2}`, ErrDuplicateKey},
		{"nested duplicate key", `[{"b":{"x":1,"y":2,"x":3}}]`, ErrDuplicateKey},
		{"unterminated array", `[`, ErrSyntax},
		{"array trailing comma", `[1,]`, ErrSyntax},
		{"array missing separator", `[1 2]`, ErrSyntax},
		{"array truncated after value", `[1`, ErrSyntax},
		{"unterminated string", `"abc`, ErrSyntax},
		{"raw control character", "\"a\x01\"", ErrSyntax},
		{"raw newline", "\"a\n\"", ErrSyntax},
		{"unterminated escape", `"\`, ErrSyntax},
		{"invalid escape", `"\x"`, ErrSyntax},
		{"single quote escape", `"\'"`, ErrSyntax},
		{"truncated unicode escape", `"\u12"`, ErrSyntax},
		{"bad hex digit", `"\u12g4"`, ErrSyntax},
		{"invalid UTF-8", "\"\xff\"", ErrUTF8},
		{"truncated UTF-8", "\"\xc3\"", ErrUTF8},
		{"overlong UTF-8", "\"\xc0\xaf\"", ErrUTF8},
		{"encoded surrogate UTF-8", "\"\xed\xa0\x80\"", ErrUTF8},
		{"invalid UTF-8 in key", "{\"\xfe\":1}", ErrUTF8},
		{"lone high surrogate", `"\ud800"`, ErrUTF8},
		{"lone high surrogate then text", `"\ud800abcdef"`, ErrUTF8},
		{"lone low surrogate", `"\udc00"`, ErrUTF8},
		{"high surrogate then non-surrogate", `"\ud800\u0041"`, ErrUTF8},
		{"two high surrogates", `"\ud800\ud800"`, ErrUTF8},
		{"high surrogate truncated pair", `"\ud800\u12"`, ErrSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Canonicalize(%q) = %q, %v; want %v", tt.in, got, err, tt.want)
			}
			if got != nil {
				t.Fatalf("output %q returned with an error", got)
			}
		})
	}
}

// TestCanonicalizeDepth checks the nesting bound on arrays and objects.
func TestCanonicalizeDepth(t *testing.T) {
	arrays := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	objects := func(n int) string {
		return strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat("}", n-1)
	}
	for _, in := range []string{arrays(MaxDepth), objects(MaxDepth)} {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != in {
			t.Fatalf("depth %d: got %q, %v", MaxDepth, got, err)
		}
	}
	for _, in := range []string{arrays(MaxDepth + 1), objects(MaxDepth + 1), arrays(100000)} {
		if _, err := Canonicalize([]byte(in)); !errors.Is(err, ErrDepth) {
			t.Fatalf("depth above %d: err = %v, want ErrDepth", MaxDepth, err)
		}
	}
}

// TestCanonicalizeSize checks the input size bound.
func TestCanonicalizeSize(t *testing.T) {
	// A string padded with whitespace to exactly MaxSize bytes is accepted.
	in := append([]byte(`"x"`), bytes.Repeat([]byte(" "), MaxSize-3)...)
	got, err := Canonicalize(in)
	if err != nil || string(got) != `"x"` {
		t.Fatalf("MaxSize input: got %q, %v", got, err)
	}
	in = append(in, ' ')
	if _, err := Canonicalize(in); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("MaxSize+1 input: err = %v, want ErrTooLarge", err)
	}
}

// TestCanonicalizeErrorContext checks that errors carry the offset.
func TestCanonicalizeErrorContext(t *testing.T) {
	_, err := Canonicalize([]byte(`[1, 2.5]`))
	if err == nil || !strings.Contains(err.Error(), "offset 5") {
		t.Fatalf("err = %v, want the offset of the fraction", err)
	}
}

// TestMarshal checks the encoding of Go values.
func TestMarshal(t *testing.T) {
	type file struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	type statement struct {
		SchemaVersion int               `json:"schemaVersion"`
		Kind          string            `json:"kind"`
		CreatedAt     string            `json:"createdAt"`
		Files         []file            `json:"files"`
		Labels        map[string]string `json:"labels"`
		Note          *string           `json:"note"`
	}
	s := statement{
		SchemaVersion: 1,
		Kind:          "deposit",
		CreatedAt:     "2026-11-05T10:00:00Z",
		Files:         []file{{Name: "a<b>&c.txt", Size: 21474836480, SHA256: "ab"}},
		Labels:        map[string]string{"z": "1", "a": "2"},
	}
	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"createdAt":"2026-11-05T10:00:00Z","files":[{"name":"a<b>&c.txt","sha256":"ab","size":21474836480}],` +
		`"kind":"deposit","labels":{"a":"2","z":"1"},"note":null,"schemaVersion":1}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// TestMarshalErrors checks values outside the subset and unsupported types.
func TestMarshalErrors(t *testing.T) {
	if _, err := Marshal(1.5); !errors.Is(err, ErrNumber) {
		t.Fatalf("float: err = %v, want ErrNumber", err)
	}
	if _, err := Marshal(int64(1) << 53); !errors.Is(err, ErrNumber) {
		t.Fatalf("2^53: err = %v, want ErrNumber", err)
	}
	if _, err := Marshal(make(chan int)); err == nil || !strings.HasPrefix(err.Error(), "jcs: marshal:") {
		t.Fatalf("channel: err = %v, want a marshal error", err)
	}
}

// TestParseDigits checks the decimal digit parser.
func TestParseDigits(t *testing.T) {
	if got := parseDigits([]byte("9007199254740991")); got != MaxSafeInteger {
		t.Fatalf("parseDigits = %d", got)
	}
	if got := parseDigits(nil); got != 0 {
		t.Fatalf("parseDigits(nil) = %d", got)
	}
}

// TestAppendString checks the string serializer on every ASCII control.
func TestAppendString(t *testing.T) {
	for c := 0; c < 0x20; c++ {
		got := appendString(nil, string(rune(c)))
		var back string
		if err := json.Unmarshal(got, &back); err != nil || back != string(rune(c)) {
			t.Fatalf("control %#02x: %q does not round-trip (%v)", c, got, err)
		}
		if bytes.ContainsAny(got, "ABCDEF") {
			t.Fatalf("control %#02x: %q has uppercase hexadecimal", c, got)
		}
	}
}

// FuzzCanonicalize checks that Canonicalize never panics and that a
// successful output is valid JSON, idempotent, and equal in value to the
// input.
func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{
		`{}`, `[]`, `0`, `-1`, `true`, `null`, `""`,
		`{"b":1,"a":[true,false,null,"x"]}`,
		`"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"`,
		`{"\u20ac":1,"\r":2,"\ufb33":3,"1":4,"\ud83d\ude00":5,"\u0080":6,"\u00f6":7}`,
		`9007199254740991`, `9007199254740992`, `-0`, `01`, `1.0`, `1e2`,
		`{"a":1,"a":2}`, `"\ud800"`, "\"\xff\"", `[[[[[]]]]]`, `{} x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Canonicalize(in)
		if err != nil {
			if out != nil {
				t.Fatalf("output with error %v", err)
			}
			return
		}
		if !json.Valid(out) {
			t.Fatalf("invalid JSON output %q for %q", out, in)
		}
		again, err := Canonicalize(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %q -> %q, %v", out, again, err)
		}
		want, wantErr := decode(in)
		got, gotErr := decode(out)
		if wantErr != nil || gotErr != nil {
			t.Fatalf("encoding/json rejects accepted input %q (%v) or output %q (%v)", in, wantErr, out, gotErr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("value changed: %q -> %q", in, out)
		}
	})
}

// decode parses data with encoding/json, numbers kept as json.Number.
func decode(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	err := d.Decode(&v)
	return v, err
}
