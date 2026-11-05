// Package strictjson pre-validates a JSON document against a whitelist tree
// before it is decoded with encoding/json.
//
// encoding/json silently keeps the last of duplicate member names, matches
// member names case-insensitively and reports no location for a problem.
// Check closes these gaps for untrusted documents (for example a tenant
// configuration import): it walks the document token by token and refuses
// duplicate member names (compared after JSON unescaping), members outside
// the schema (exact, case-sensitive match only), missing required members,
// values of the wrong shape, arrays longer than their limit, nesting
// deeper than a limit, invalid JSON and trailing data after the top value.
// An array is refused as soon as it holds one item too many, so that the
// memory of a later typed decode is bounded by the schema. The first
// problem is reported as an *Error carrying an RFC 6901 JSON pointer and a
// stable reason, never the offending value (member names longer than
// MaxPointerSegment bytes are truncated in the pointer), so the error can
// be returned to clients and logged.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the shape of the values a Schema node accepts.
type Kind int

const (
	// KindScalar accepts a string, a number, a boolean or null.
	KindScalar Kind = iota + 1
	// KindObject accepts an object whose members are all listed in the node.
	KindObject
	// KindArray accepts an array whose items all match the item node.
	KindArray
)

// Schema is a node of a whitelist tree describing the accepted shape of a
// JSON document. Build it with Scalar, Object and Array; a Schema is
// immutable once built and safe for concurrent use.
type Schema struct {
	kind     Kind
	nullable bool
	members  map[string]*Schema
	required []string
	item     *Schema
	maxItems int
	limited  bool
}

// Scalar returns a leaf node accepting any scalar value (string, number,
// boolean or null) and refusing objects and arrays.
func Scalar() *Schema {
	return &Schema{kind: KindScalar, nullable: true}
}

// Object returns a node accepting an object whose member names are all keys
// of members, each member value matching its child node. Members are
// optional unless made required with Require; Check refuses names that are
// not listed. The map is
// copied. Object panics on a nil child or on two names that differ only by
// case (encoding/json could not tell them apart on decode).
func Object(members map[string]*Schema) *Schema {
	m := make(map[string]*Schema, len(members))
	for name, child := range members {
		if child == nil {
			panic("strictjson: nil schema for member " + strconv.Quote(name))
		}
		for other := range m {
			if strings.EqualFold(name, other) {
				panic("strictjson: members " + strconv.Quote(name) + " and " +
					strconv.Quote(other) + " differ only by case")
			}
		}
		m[name] = child
	}
	return &Schema{kind: KindObject, members: m}
}

// Array returns a node accepting an array whose items all match item.
// Array panics on a nil item.
func Array(item *Schema) *Schema {
	if item == nil {
		panic("strictjson: nil array item schema")
	}
	return &Schema{kind: KindArray, item: item}
}

// OrNull returns a copy of s that also accepts null. Object and Array nodes
// refuse null unless built with OrNull; Scalar nodes always accept it.
func (s *Schema) OrNull() *Schema {
	c := *s
	c.nullable = true
	return &c
}

// Require returns a copy of the object node s in which the members named
// in names are required: Check refuses an object missing one of them
// (reason ReasonRequired, pointer of the missing member, the first in the
// order given). A required member may still be null when its node accepts null.
// Require panics on a node that is not an object, on a name that is not a
// member of s and on a name given twice (including by an earlier Require).
func (s *Schema) Require(names ...string) *Schema {
	if s.kind != KindObject {
		panic("strictjson: Require on a node that is not an object")
	}
	c := *s
	c.required = append([]string(nil), s.required...)
	for _, name := range names {
		if _, ok := s.members[name]; !ok {
			panic("strictjson: required member " + strconv.Quote(name) + " is not a member")
		}
		if slices.Contains(c.required, name) {
			panic("strictjson: member " + strconv.Quote(name) + " required twice")
		}
		c.required = append(c.required, name)
	}
	return &c
}

// Max returns a copy of the array node s accepting at most n items: Check
// refuses a longer array (reason ReasonTooMany, pointer of the array) as
// soon as it reaches item n+1, without reading the rest. Max panics on a
// node that is not an array and on n below 0.
func (s *Schema) Max(n int) *Schema {
	if s.kind != KindArray {
		panic("strictjson: Max on a node that is not an array")
	}
	if n < 0 {
		panic("strictjson: negative array limit")
	}
	c := *s
	c.maxItems, c.limited = n, true
	return &c
}

// Kind returns the shape accepted by s.
func (s *Schema) Kind() Kind { return s.kind }

// Nullable reports whether s accepts null.
func (s *Schema) Nullable() bool { return s.nullable }

// Member returns the child node of the member name of an object node, and
// whether name is allowed. The match is exact (case-sensitive).
func (s *Schema) Member(name string) (*Schema, bool) {
	child, ok := s.members[name]
	return child, ok
}

// MemberNames returns the allowed member names of an object node, sorted.
// It returns an empty slice for other nodes.
func (s *Schema) MemberNames() []string {
	names := make([]string, 0, len(s.members))
	for name := range s.members {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Item returns the item node of an array node, nil for other nodes.
func (s *Schema) Item() *Schema { return s.item }

// MaxItems returns the item limit of an array node set by Max, and whether
// it has one.
func (s *Schema) MaxItems() (int, bool) { return s.maxItems, s.limited }

// Required returns the required member names of an object node, sorted. It
// returns an empty slice for other nodes and for objects without required
// members.
func (s *Schema) Required() []string {
	names := append([]string{}, s.required...)
	sort.Strings(names)
	return names
}

// Reason is a stable machine-readable cause of a Check failure.
type Reason string

const (
	// ReasonSyntax means invalid JSON, or data after the top-level value.
	ReasonSyntax Reason = "syntax"
	// ReasonDuplicate means a member name appears twice in the same object.
	ReasonDuplicate Reason = "duplicate"
	// ReasonUnknownMember means a member name is not allowed by the schema.
	ReasonUnknownMember Reason = "unknown-member"
	// ReasonType means a value has a shape the schema does not accept.
	ReasonType Reason = "type"
	// ReasonTooDeep means objects and arrays are nested deeper than allowed.
	ReasonTooDeep Reason = "too-deep"
	// ReasonTooMany means an array holds more items than allowed; the
	// pointer is that of the array.
	ReasonTooMany Reason = "too-many"
	// ReasonRequired means a required member is missing; the pointer is
	// that of the missing member.
	ReasonRequired Reason = "required"
)

// MaxPointerSegment is the longest member name, in bytes, that the pointer
// of an *Error reproduces: a longer name is cut at a character boundary at
// or below this length and followed by "…", so that a hostile document
// cannot make its error answer or log line arbitrarily long.
const MaxPointerSegment = 64

// Error is the first problem found by Check. Pointer is the RFC 6901 JSON
// pointer of the offending member or value ("" for the root); for a syntax
// error it is the position being read, as a best effort. The
// offending value itself is never included.
type Error struct {
	Pointer string
	Reason  Reason
}

// Error implements error. The message holds only the reason and the
// pointer, quoted so that control characters in member names stay inert.
func (e *Error) Error() string {
	return fmt.Sprintf("strictjson: %s at %q", e.Reason, e.Pointer)
}

// Pointer builds an RFC 6901 JSON pointer from path segments: strings are
// escaped ("~" as "~0", "/" as "~1"), ints are written in decimal, any other
// value is formatted with fmt.Sprint and escaped. No segment gives "", the
// pointer of the root.
func Pointer(segments ...any) string {
	var b strings.Builder
	for _, seg := range segments {
		b.WriteByte('/')
		switch v := seg.(type) {
		case string:
			b.WriteString(escape(v))
		case int:
			b.WriteString(strconv.Itoa(v))
		default:
			b.WriteString(escape(fmt.Sprint(v)))
		}
	}
	return b.String()
}

// escaper applies the RFC 6901 escapes, "~" first.
var escaper = strings.NewReplacer("~", "~0", "/", "~1")

func escape(s string) string { return escaper.Replace(s) }

// Check validates data against the schema s and returns nil or an *Error
// for the first problem found. maxDepth bounds the nesting of objects and
// arrays (the root object or array is at depth 1); a value below 1 disables
// the bound, leaving only the depth of the schema itself. Check panics on a
// nil schema.
func Check(data []byte, s *Schema, maxDepth int) error {
	if s == nil {
		panic("strictjson: nil schema")
	}
	c := &checker{dec: json.NewDecoder(bytes.NewReader(data)), maxDepth: maxDepth}
	c.dec.UseNumber()
	tok, err := c.dec.Token()
	if err != nil {
		return c.fail(ReasonSyntax)
	}
	if err := c.value(tok, s, 0); err != nil {
		return err
	}
	if _, err := c.dec.Token(); err != io.EOF {
		return c.fail(ReasonSyntax)
	}
	return nil
}

// checker holds the state of one Check walk.
type checker struct {
	dec      *json.Decoder
	maxDepth int
	path     []any // member names (string) and array indexes (int)
}

// fail returns an *Error at the current path, its member names truncated
// (see MaxPointerSegment).
func (c *checker) fail(r Reason) *Error {
	segs := make([]any, len(c.path))
	for i, seg := range c.path {
		if name, ok := seg.(string); ok {
			seg = truncate(name)
		}
		segs[i] = seg
	}
	return &Error{Pointer: Pointer(segs...), Reason: r}
}

// truncate returns name cut to at most MaxPointerSegment bytes at a
// character boundary, followed by "…" when it was cut.
func truncate(name string) string {
	if len(name) <= MaxPointerSegment {
		return name
	}
	cut := MaxPointerSegment
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return name[:cut] + "…"
}

// value checks the value starting with tok against s; depth is the number of
// containers enclosing it. The recursion is bounded by the schema tree,
// since a scalar node refuses objects and arrays.
func (c *checker) value(tok json.Token, s *Schema, depth int) error {
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		if s.kind == KindScalar || (tok == nil && s.nullable) {
			return nil
		}
		return c.fail(ReasonType)
	}
	// In a value position the decoder only returns '{' or '[': a closing
	// delimiter there is reported as a syntax error by Token itself.
	want := KindArray
	if delim == '{' {
		want = KindObject
	}
	if s.kind != want {
		return c.fail(ReasonType)
	}
	if c.maxDepth > 0 && depth+1 > c.maxDepth {
		return c.fail(ReasonTooDeep)
	}
	if want == KindObject {
		return c.object(s, depth+1)
	}
	return c.array(s, depth+1)
}

// object checks the members of an object whose '{' was just read, then
// consumes its closing '}'.
func (c *checker) object(s *Schema, depth int) error {
	seen := make(map[string]struct{})
	for c.dec.More() {
		tok, err := c.dec.Token()
		if err != nil {
			return c.fail(ReasonSyntax)
		}
		// In a key position the decoder only returns a string (already
		// unescaped); anything else is a syntax error from Token.
		name, _ := tok.(string)
		c.path = append(c.path, name)
		if _, dup := seen[name]; dup {
			return c.fail(ReasonDuplicate)
		}
		seen[name] = struct{}{}
		child, ok := s.members[name]
		if !ok {
			return c.fail(ReasonUnknownMember)
		}
		if tok, err = c.dec.Token(); err != nil {
			return c.fail(ReasonSyntax)
		}
		if err := c.value(tok, child, depth); err != nil {
			return err
		}
		c.path = c.path[:len(c.path)-1]
	}
	for _, name := range s.required {
		if _, ok := seen[name]; !ok {
			c.path = append(c.path, name)
			return c.fail(ReasonRequired)
		}
	}
	return c.close()
}

// array checks the items of an array whose '[' was just read, then consumes
// its closing ']'.
func (c *checker) array(s *Schema, depth int) error {
	for i := 0; c.dec.More(); i++ {
		if s.limited && i == s.maxItems {
			return c.fail(ReasonTooMany)
		}
		c.path = append(c.path, i)
		tok, err := c.dec.Token()
		if err != nil {
			return c.fail(ReasonSyntax)
		}
		if err := c.value(tok, s.item, depth); err != nil {
			return err
		}
		c.path = c.path[:len(c.path)-1]
	}
	return c.close()
}

// close consumes the closing delimiter of the current container. The
// decoder refuses a mismatched delimiter, so only the error needs checking.
func (c *checker) close() error {
	if _, err := c.dec.Token(); err != nil {
		return c.fail(ReasonSyntax)
	}
	return nil
}
