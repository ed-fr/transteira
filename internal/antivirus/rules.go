package antivirus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Bounds of a verdict rule.
const (
	// MaxRuleLen bounds the length in bytes of a rule.
	MaxRuleLen = 1 << 10
	// MaxRuleConditions bounds the number of conditions of a rule.
	MaxRuleConditions = 16
)

// Rule prefixes and operators.
const (
	ruleAnd          = "&&"
	statusPrefix     = "status="
	jsonPrefix       = "json:"
	minRuleStatus    = 100
	maxRuleStatus    = 599
	maxStatusDigits  = 3
	pointerSeparator = "/"
)

// errRuleEmpty is returned by Eval on the zero Rule, which must never be
// taken for a satisfied rule.
var errRuleEmpty = errors.New("antivirus: empty verdict rule")

// errPointerMissing is wrapped by Eval when a JSON pointer of a condition
// designates no value in the document.
var errPointerMissing = errors.New("antivirus: JSON pointer designates no value")

// Rule is a verdict rule of the HTTP engine: a conjunction of conditions on
// the HTTP status code and on values of the JSON response body. It is
// parsed by ParseRule; the zero Rule has no condition and never evaluates
// to true.
//
// The grammar is one or more conditions joined by "&&" (spaces around each
// condition are ignored):
//
//   - status=200, status=200-299 or status=200,204-206: the status code is
//     one of the listed codes or inclusive ranges (100 to 599);
//   - json:<pointer>=<literal>: the value designated by the RFC 6901 JSON
//     pointer is deeply equal to the JSON literal;
//   - json:<pointer>!=<literal>: the value designated by the pointer is not
//     deeply equal to the literal.
//
// The pointer extends to the first "=" (a trailing "!" being part of the
// "!=" operator), so it cannot contain "=" nor end with "!"; a literal
// cannot contain "&&". Numbers are compared by value ("1" equals "1.0"),
// exactly for integers, as float64 otherwise. A pointer that designates no
// value is an evaluation error, for "=" and "!=" alike (fail-closed,
// decision P44): a response missing the field is never read as a verdict.
type Rule struct {
	conds []condition
}

// condition is one condition of a Rule.
type condition struct {
	text string
	// status condition: a list of inclusive ranges.
	ranges [][2]int
	// JSON condition (pointer set when isJSON).
	isJSON  bool
	pointer string
	negate  bool
	want    any
}

// ParseRule parses and validates a verdict rule (see Rule for the grammar).
// The error never echoes literals in full, but may quote short parts of the
// rule.
func ParseRule(s string) (Rule, error) {
	if len(s) > MaxRuleLen {
		return Rule{}, fmt.Errorf("antivirus: verdict rule longer than %d bytes", MaxRuleLen)
	}
	parts := strings.Split(s, ruleAnd)
	if len(parts) > MaxRuleConditions {
		return Rule{}, fmt.Errorf("antivirus: verdict rule with more than %d conditions", MaxRuleConditions)
	}
	conds := make([]condition, 0, len(parts))
	for i, p := range parts {
		c, err := parseCondition(strings.TrimSpace(p))
		if err != nil {
			return Rule{}, fmt.Errorf("antivirus: verdict rule condition %d: %w", i+1, err)
		}
		conds = append(conds, c)
	}
	return Rule{conds: conds}, nil
}

// parseCondition parses one trimmed condition.
func parseCondition(s string) (condition, error) {
	switch {
	case s == "":
		return condition{}, errors.New("empty condition")
	case strings.HasPrefix(s, statusPrefix):
		ranges, err := parseStatusList(s[len(statusPrefix):])
		if err != nil {
			return condition{}, err
		}
		return condition{text: s, ranges: ranges}, nil
	case strings.HasPrefix(s, jsonPrefix):
		return parseJSONCondition(s)
	default:
		return condition{}, errors.New(`condition must start with "status=" or "json:"`)
	}
}

// parseStatusList parses "200", "200-299" or a comma-separated list of
// them.
func parseStatusList(s string) ([][2]int, error) {
	items := strings.Split(s, ",")
	ranges := make([][2]int, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		lo, hi, isRange := strings.Cut(item, "-")
		from, err := parseStatus(strings.TrimSpace(lo))
		if err != nil {
			return nil, err
		}
		to := from
		if isRange {
			if to, err = parseStatus(strings.TrimSpace(hi)); err != nil {
				return nil, err
			}
			if to < from {
				return nil, fmt.Errorf("status range %d-%d is reversed", from, to)
			}
		}
		ranges = append(ranges, [2]int{from, to})
	}
	return ranges, nil
}

// parseStatus parses a status code of exactly three digits in 100..599.
func parseStatus(s string) (int, error) {
	if len(s) != maxStatusDigits {
		return 0, errors.New("status code must have three digits")
	}
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("status code must have three digits")
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < minRuleStatus || n > maxRuleStatus {
		return 0, fmt.Errorf("status code %d out of range %d-%d", n, minRuleStatus, maxRuleStatus)
	}
	return n, nil
}

// parseJSONCondition parses "json:<pointer>=<literal>" or
// "json:<pointer>!=<literal>".
func parseJSONCondition(s string) (condition, error) {
	rest := s[len(jsonPrefix):]
	ptr, lit, ok := strings.Cut(rest, "=")
	if !ok {
		return condition{}, errors.New(`JSON condition without "=" or "!="`)
	}
	negate := strings.HasSuffix(ptr, "!")
	if negate {
		ptr = ptr[:len(ptr)-1]
	}
	ptr = strings.TrimSpace(ptr)
	if err := checkPointer(ptr); err != nil {
		return condition{}, err
	}
	want, err := decodeJSON([]byte(strings.TrimSpace(lit)))
	if err != nil {
		return condition{}, errors.New("invalid JSON literal")
	}
	return condition{text: s, isJSON: true, pointer: ptr, negate: negate, want: want}, nil
}

// decodeJSON decodes exactly one JSON value, numbers kept as json.Number.
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// NeedsJSON reports whether the rule has a JSON condition, so that the
// response body must be decoded to evaluate it.
func (r Rule) NeedsJSON() bool {
	for _, c := range r.conds {
		if c.isJSON {
			return true
		}
	}
	return false
}

// IsZero reports whether r is the zero Rule (no condition).
func (r Rule) IsZero() bool { return len(r.conds) == 0 }

// Eval reports whether the response with the given status code and decoded
// JSON body (from a decoder using UseNumber; nil when the body was not
// decoded) satisfies every condition of the rule. Conditions are evaluated
// left to right and evaluation stops at the first false one. A JSON pointer
// that designates no value, or the zero Rule, gives an error.
func (r Rule) Eval(status int, doc any) (bool, error) {
	if len(r.conds) == 0 {
		return false, errRuleEmpty
	}
	for _, c := range r.conds {
		ok, err := c.eval(status, doc)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// eval evaluates one condition.
func (c condition) eval(status int, doc any) (bool, error) {
	if !c.isJSON {
		for _, rg := range c.ranges {
			if status >= rg[0] && status <= rg[1] {
				return true, nil
			}
		}
		return false, nil
	}
	got, found, err := lookupPointer(doc, c.pointer)
	if err != nil {
		return false, err
	}
	if !found {
		return false, fmt.Errorf("%w: %q", errPointerMissing, truncateForError(c.pointer))
	}
	return jsonEqual(got, c.want) != c.negate, nil
}

// String returns the rule in canonical form: its conditions joined by
// " && ".
func (r Rule) String() string {
	texts := make([]string, len(r.conds))
	for i, c := range r.conds {
		texts[i] = c.text
	}
	return strings.Join(texts, " "+ruleAnd+" ")
}

// checkPointer validates the syntax of an RFC 6901 JSON pointer: empty, or
// a sequence of "/"-prefixed tokens where "~" is followed by "0" or "1".
func checkPointer(ptr string) error {
	if ptr != "" && !strings.HasPrefix(ptr, pointerSeparator) {
		return errors.New(`JSON pointer must be empty or start with "/"`)
	}
	for i := 0; i < len(ptr); i++ {
		if ptr[i] == '~' && (i+1 >= len(ptr) || (ptr[i+1] != '0' && ptr[i+1] != '1')) {
			return errors.New(`invalid "~" escape in JSON pointer`)
		}
	}
	return nil
}

// lookupPointer returns the value designated by the RFC 6901 pointer ptr in
// doc, a value decoded by encoding/json. found is false when the pointer
// designates no value (missing member, index out of range or not a valid
// array index, "-", or a scalar in the path). err is set only for a
// syntactically invalid pointer.
func lookupPointer(doc any, ptr string) (value any, found bool, err error) {
	if err := checkPointer(ptr); err != nil {
		return nil, false, err
	}
	if ptr == "" {
		return doc, true, nil
	}
	cur := doc
	for _, tok := range strings.Split(ptr[1:], pointerSeparator) {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[tok]
			if !ok {
				return nil, false, nil
			}
			cur = next
		case []any:
			i, ok := arrayIndex(tok)
			if !ok || i >= len(v) {
				return nil, false, nil
			}
			cur = v[i]
		default:
			return nil, false, nil
		}
	}
	return cur, true, nil
}

// arrayIndex parses an RFC 6901 array index: "0" or digits without a
// leading zero.
func arrayIndex(tok string) (int, bool) {
	if tok == "" || len(tok) > 9 || (len(tok) > 1 && tok[0] == '0') {
		return 0, false
	}
	n := 0
	for i := range len(tok) {
		if tok[i] < '0' || tok[i] > '9' {
			return 0, false
		}
		n = n*10 + int(tok[i]-'0')
	}
	return n, true
}

// jsonEqual reports whether two values decoded with UseNumber are deeply
// equal, numbers compared by value.
func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && numberEqual(x, y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !jsonEqual(xv, yv) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// numberEqual compares two JSON numbers by value: exactly when both are
// integers that fit in an int64, as float64 otherwise.
func numberEqual(a, b json.Number) bool {
	if a == b {
		return true
	}
	ai, aerr := strconv.ParseInt(string(a), 10, 64)
	bi, berr := strconv.ParseInt(string(b), 10, 64)
	if aerr == nil && berr == nil {
		return ai == bi
	}
	// Decoded numbers are always valid; values out of the float64 range
	// parse as ±Inf (or 0) with a range error and still compare
	// consistently.
	af, _ := strconv.ParseFloat(string(a), 64)
	bf, _ := strconv.ParseFloat(string(b), 64)
	return af == bf
}

// truncateForError bounds a string quoted in an error message.
func truncateForError(s string) string {
	const maxQuoted = 64
	if len(s) <= maxQuoted {
		return s
	}
	return s[:maxQuoted] + "..."
}
