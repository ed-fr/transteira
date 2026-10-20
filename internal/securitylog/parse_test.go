package securitylog

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parsedLine is a security log line parsed back by the strict reference
// parser below, which documents (and checks) the grammar of the format.
type parsedLine struct {
	ts     time.Time
	ip     string
	tenant string
	event  string
	fields []Field
}

// parseLine parses one line, trailing newline included, and fails on any
// deviation from the grammar: exactly four fixed tokens, then only
// ` key="escaped value"` pairs.
func parseLine(line string) (parsedLine, error) {
	var p parsedLine
	body, ok := strings.CutSuffix(line, "\n")
	if !ok || strings.ContainsAny(body, "\n\r") {
		return p, errors.New("not exactly one line")
	}
	parts := strings.SplitN(body, " ", 5)
	if len(parts) < 4 {
		return p, errors.New("missing fixed tokens")
	}
	ts, err := time.Parse(TimeLayout, parts[0])
	if err != nil {
		return p, fmt.Errorf("timestamp: %w", err)
	}
	p.ts = ts
	for i, prefix := range []string{"ip=", "tenant=", "event="} {
		v, ok := strings.CutPrefix(parts[i+1], prefix)
		if !ok {
			return p, fmt.Errorf("token %d: want %s", i+2, prefix)
		}
		switch i {
		case 0:
			p.ip = v
		case 1:
			p.tenant = v
		default:
			p.event = v
		}
	}
	if len(parts) == 5 {
		p.fields, err = parseFields(" " + parts[4])
	}
	return p, err
}

func parseFields(s string) ([]Field, error) {
	var out []Field
	for s != "" {
		if s[0] != ' ' {
			return nil, errors.New("field not separated by a space")
		}
		eq := strings.Index(s, `="`)
		if eq < 0 {
			return nil, errors.New("field without quoted value")
		}
		key := s[1:eq]
		if !validKey(key) {
			return nil, fmt.Errorf("invalid key %q", key)
		}
		val, rest, err := unquote(s[eq+2:])
		if err != nil {
			return nil, err
		}
		out = append(out, Field{key, val})
		s = rest
	}
	return out, nil
}

// unquote reads an escaped value up to its closing quote and returns the
// decoded value and the remainder after the quote.
func unquote(s string) (val, rest string, err error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			return b.String(), s[i+1:], nil
		case c < 0x20 || c == 0x7f:
			return "", "", fmt.Errorf("raw control byte %#x", c)
		case c != '\\':
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", "", errors.New("dangling backslash")
		}
		i++
		switch s[i] {
		case '\\', '"':
			b.WriteByte(s[i])
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[s[i]]
			if i+n >= len(s) {
				return "", "", errors.New("short escape")
			}
			v, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32)
			if err != nil {
				return "", "", fmt.Errorf("bad escape: %w", err)
			}
			if s[i] == 'x' {
				b.WriteByte(byte(v))
			} else {
				b.WriteRune(rune(v))
			}
			i += n
		default:
			return "", "", fmt.Errorf("unknown escape \\%c", s[i])
		}
	}
	return "", "", errors.New("unterminated value")
}
