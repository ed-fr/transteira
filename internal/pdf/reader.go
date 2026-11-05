package pdf

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
)

// Parser bounds.
const (
	maxDepth   = 32
	maxObjects = 100000
	maxToken   = 18 // digits of an integer
	maxName    = 4096
)

type (
	pname string
	pref  int
	pdict map[string]any
)

// pobject is an indirect object: its value and, for a stream, its data.
type pobject struct {
	val    any
	stream []byte
	has    bool
}

type parser struct {
	b   []byte
	pos int
}

func malformed(msg string) error {
	return fmt.Errorf("%w: %s", ErrMalformed, msg)
}

func isSpace(c byte) bool { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }

func isDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func (p *parser) eof() bool { return p.pos >= len(p.b) }

// skip advances over white space and comments.
func (p *parser) skip() {
	for p.pos < len(p.b) {
		c := p.b[p.pos]
		switch {
		case isSpace(c):
			p.pos++
		case c == '%':
			for p.pos < len(p.b) && p.b[p.pos] != '\n' && p.b[p.pos] != '\r' {
				p.pos++
			}
		default:
			return
		}
	}
}

// token reads a run of regular characters.
func (p *parser) token() []byte {
	start := p.pos
	for p.pos < len(p.b) && !isSpace(p.b[p.pos]) && !isDelim(p.b[p.pos]) {
		p.pos++
	}
	return p.b[start:p.pos]
}

// uint reads an unsigned integer token.
func (p *parser) uint() (int, bool) {
	p.skip()
	t := p.token()
	if len(t) == 0 || len(t) > maxToken {
		return 0, false
	}
	n, err := strconv.ParseUint(string(t), 10, 62)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// value parses one object.
func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, malformed("nesting too deep")
	}
	p.skip()
	if p.eof() {
		return nil, malformed("unexpected end")
	}
	switch c := p.b[p.pos]; {
	case c == '/':
		return p.name()
	case c == '(':
		return p.literal()
	case c == '<' && p.pos+1 < len(p.b) && p.b[p.pos+1] == '<':
		return p.dict(depth)
	case c == '<':
		return p.hexString()
	case c == '[':
		p.pos++
		arr := []any{}
		for {
			p.skip()
			if p.eof() {
				return nil, malformed("unterminated array")
			}
			if p.b[p.pos] == ']' {
				p.pos++
				return arr, nil
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
	default:
		return p.scalar()
	}
}

func (p *parser) name() (any, error) {
	p.pos++ // '/'
	t := p.token()
	if len(t) > maxName {
		return nil, malformed("name too long")
	}
	out := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		if t[i] == '#' {
			if i+2 >= len(t) {
				return nil, malformed("bad name escape")
			}
			h, ok := unhex2(t[i+1 : i+3])
			if !ok {
				return nil, malformed("bad name escape")
			}
			out = append(out, h)
			i += 2
			continue
		}
		out = append(out, t[i])
	}
	return pname(out), nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func unhex2(b []byte) (byte, bool) {
	h, ok1 := hexVal(b[0])
	l, ok2 := hexVal(b[1])
	return h<<4 | l, ok1 && ok2
}

func (p *parser) hexString() (any, error) {
	p.pos++ // '<'
	var out []byte
	var hi byte
	half := false
	for p.pos < len(p.b) {
		c := p.b[p.pos]
		p.pos++
		switch {
		case c == '>':
			if half {
				out = append(out, hi<<4)
			}
			return out, nil
		case isSpace(c):
		default:
			v, ok := hexVal(c)
			if !ok {
				return nil, malformed("bad hex string")
			}
			if half {
				out = append(out, hi<<4|v)
			} else {
				hi = v
			}
			half = !half
		}
	}
	return nil, malformed("unterminated hex string")
}

func (p *parser) literal() (any, error) {
	p.pos++ // '('
	out := []byte{}
	nest := 1
	for p.pos < len(p.b) {
		c := p.b[p.pos]
		p.pos++
		switch c {
		case '(':
			nest++
			out = append(out, c)
		case ')':
			nest--
			if nest == 0 {
				return out, nil
			}
			out = append(out, c)
		case '\\':
			if p.pos >= len(p.b) {
				return nil, malformed("unterminated string")
			}
			e := p.b[p.pos]
			p.pos++
			switch {
			case e == 'n':
				out = append(out, '\n')
			case e == 'r':
				out = append(out, '\r')
			case e == 't':
				out = append(out, '\t')
			case e == 'b':
				out = append(out, '\b')
			case e == 'f':
				out = append(out, '\f')
			case e >= '0' && e <= '7':
				v := int(e - '0')
				for i := 0; i < 2 && p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '7'; i++ {
					v = v<<3 | int(p.b[p.pos]-'0')
					p.pos++
				}
				out = append(out, byte(v))
			case e == '\r':
				if p.pos < len(p.b) && p.b[p.pos] == '\n' {
					p.pos++
				}
			case e == '\n':
			default:
				out = append(out, e)
			}
		default:
			out = append(out, c)
		}
	}
	return nil, malformed("unterminated string")
}

func (p *parser) dict(depth int) (any, error) {
	p.pos += 2 // "<<"
	d := pdict{}
	for {
		p.skip()
		if p.eof() {
			return nil, malformed("unterminated dictionary")
		}
		if bytes.HasPrefix(p.b[p.pos:], []byte(">>")) {
			p.pos += 2
			return d, nil
		}
		if p.b[p.pos] != '/' {
			return nil, malformed("dictionary key is not a name")
		}
		k, err := p.name()
		if err != nil {
			return nil, err
		}
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		if _, dup := d[string(k.(pname))]; dup {
			return nil, malformed("duplicate dictionary key")
		}
		d[string(k.(pname))] = v
	}
}

// scalar parses a number, a reference or a keyword.
func (p *parser) scalar() (any, error) {
	t := p.token()
	if len(t) == 0 {
		p.pos++ // an unexpected delimiter: make progress and fail
		return nil, malformed("unexpected character")
	}
	switch string(t) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}
	if len(t) > maxToken {
		return nil, malformed("number too long")
	}
	if n, err := strconv.ParseUint(string(t), 10, 62); err == nil {
		save := p.pos
		if _, ok := p.uint(); ok {
			p.skip()
			if p.pos < len(p.b) && p.b[p.pos] == 'R' && (p.pos+1 == len(p.b) || isSpace(p.b[p.pos+1]) || isDelim(p.b[p.pos+1])) {
				p.pos++
				return pref(n), nil
			}
		}
		p.pos = save
		return int64(n), nil
	}
	if n, err := strconv.ParseInt(string(t), 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(string(t), 64); err == nil {
		return f, nil
	}
	return nil, malformed("unknown token")
}

// parsedFile is a PDF of exactly the structure [Write] emits: one header,
// the sequential objects numbered 1..N, one xref section, one trailer, one
// startxref and the end-of-file marker.
type parsedFile struct {
	objs map[int]*pobject
	root pref
}

// parseFile reads data strictly: it rejects incremental updates, data after
// the end-of-file marker, and a cross-reference table that does not match
// the objects actually read.
func parseFile(data []byte) (*parsedFile, error) {
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, malformed("missing header")
	}
	p := &parser{b: data}
	objs := map[int]*pobject{}
	offs := map[int]int{}
	xrefPos := -1
	for xrefPos < 0 {
		p.skip()
		if p.eof() {
			return nil, malformed("missing xref")
		}
		save := p.pos
		if bytes.Equal(p.token(), []byte("xref")) {
			xrefPos = save
			break
		}
		p.pos = save
		n, ok := p.uint()
		if !ok {
			return nil, malformed("object number expected")
		}
		if g, ok := p.uint(); !ok || g != 0 {
			return nil, malformed("generation 0 expected")
		}
		p.skip()
		if !bytes.Equal(p.token(), []byte("obj")) {
			return nil, malformed("obj keyword expected")
		}
		if len(objs) >= maxObjects {
			return nil, malformed("too many objects")
		}
		if objs[n] != nil {
			return nil, malformed("duplicate object number")
		}
		v, err := p.value(0)
		if err != nil {
			return nil, err
		}
		o := &pobject{val: v}
		if d, isDict := v.(pdict); isDict {
			p.skip()
			if bytes.HasPrefix(p.b[p.pos:], []byte("stream")) {
				if err := p.readStream(o, d, objs); err != nil {
					return nil, err
				}
			}
		}
		p.skip()
		if !bytes.Equal(p.token(), []byte("endobj")) {
			return nil, malformed("endobj expected")
		}
		objs[n] = o
		offs[n] = save
	}
	// The cross-reference table, byte for byte.
	var xr bytes.Buffer
	fmt.Fprintf(&xr, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for n := 1; n <= len(objs); n++ {
		off, ok := offs[n]
		if !ok {
			return nil, malformed("objects are not numbered 1..N")
		}
		fmt.Fprintf(&xr, "%010d 00000 n \n", off)
	}
	if !bytes.HasPrefix(data[xrefPos:], xr.Bytes()) {
		return nil, malformed("cross-reference table does not match the objects")
	}
	p.pos = xrefPos + xr.Len()
	if !bytes.HasPrefix(data[p.pos:], []byte("trailer\n")) {
		return nil, malformed("trailer expected")
	}
	p.pos += len("trailer\n")
	tv, err := p.value(0)
	if err != nil {
		return nil, err
	}
	tr, _ := tv.(pdict)
	size, _ := tr["Size"].(int64)
	root, isRef := tr["Root"].(pref)
	if size != int64(len(objs)+1) || !isRef {
		return nil, malformed("bad trailer")
	}
	for _, k := range []string{"Prev", "XRefStm", "Encrypt"} {
		if _, bad := tr[k]; bad {
			return nil, malformed("unsupported trailer entry /" + k)
		}
	}
	tail := fmt.Sprintf("\nstartxref\n%d\n%%%%EOF", xrefPos)
	if !bytes.HasPrefix(data[p.pos:], []byte(tail)) {
		return nil, malformed("bad startxref or end of file")
	}
	for _, c := range data[p.pos+len(tail):] {
		if c != '\n' && c != '\r' && c != ' ' {
			return nil, malformed("data after the end of file")
		}
	}
	return &parsedFile{objs: objs, root: root}, nil
}

// readStream reads the data of a stream whose dictionary is d.
func (p *parser) readStream(o *pobject, d pdict, objs map[int]*pobject) error {
	p.pos += len("stream")
	switch {
	case bytes.HasPrefix(p.b[p.pos:], []byte("\r\n")):
		p.pos += 2
	case p.pos < len(p.b) && p.b[p.pos] == '\n':
		p.pos++
	default:
		return malformed("stream keyword must end with a line break")
	}
	length, ok := d["Length"]
	if r, isRef := length.(pref); isRef {
		target := objs[int(r)]
		if target == nil {
			return malformed("stream length not yet defined")
		}
		length = target.val
	}
	n, isInt := length.(int64)
	if !ok || !isInt || n < 0 || n > int64(len(p.b)-p.pos) {
		return malformed("bad stream length")
	}
	o.stream, o.has = p.b[p.pos:p.pos+int(n)], true
	p.pos += int(n)
	p.skip()
	if !bytes.HasPrefix(p.b[p.pos:], []byte("endstream")) {
		return malformed("endstream expected")
	}
	p.pos += len("endstream")
	return nil
}

// textString decodes a PDF text string (UTF-16BE with BOM, else Latin-1).
func textString(b []byte) (string, bool) {
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		b = b[2:]
		if len(b)%2 != 0 {
			return "", false
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		return string(utf16.Decode(u)), true
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r), true
}

// ReadAttachments extracts the embedded files of a PDF produced by [Write],
// by file name. It reads at most limit bytes (ErrTooLarge beyond). It is
// strict: it only accepts the exact structure [Write] emits (a single
// cross-reference section, a catalog whose /Names /EmbeddedFiles tree lists
// the attachments, each as an indirect /Filespec), and rejects anything
// else, in particular a second update, data after the end of file, or a
// /Filespec that the name tree does not reference, with ErrMalformed, so
// that a viewer cannot show another statement than the one returned. It
// returns ErrNoAttachments when the file holds none. Streams with a /Filter
// are not supported.
func ReadAttachments(r io.Reader, limit int64) (map[string][]byte, error) {
	if limit <= 0 {
		return nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("pdf: read: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	f, err := parseFile(data)
	if err != nil {
		return nil, err
	}
	tree, err := nameTree(f)
	if err != nil {
		return nil, err
	}
	// Any file specification outside the name tree is a forgery.
	for n, o := range f.objs {
		d, top := o.val.(pdict)
		if top && isFilespec(d) && !tree.nums[n] {
			return nil, malformed("file specification outside the name tree")
		}
		if hasNestedFilespec(o.val, true) {
			return nil, malformed("inline file specification")
		}
	}
	out := map[string][]byte{}
	for _, e := range tree.entries {
		content, err := filespec(f.objs, e.name, int(e.ref))
		if err != nil {
			return nil, err
		}
		out[e.name] = content
	}
	if len(out) == 0 {
		return nil, ErrNoAttachments
	}
	return out, nil
}

type treeEntry struct {
	name string
	ref  pref
}

type nameTreeInfo struct {
	entries []treeEntry
	nums    map[int]bool
}

// nameTree reads the catalog and its /Names /EmbeddedFiles name tree, which
// must be a single /Names array of (name, reference) pairs.
func nameTree(f *parsedFile) (*nameTreeInfo, error) {
	var cat pdict
	if ro := f.objs[int(f.root)]; ro != nil {
		cat, _ = ro.val.(pdict)
	}
	if t, _ := cat["Type"].(pname); t != "Catalog" {
		return nil, malformed("the root is not a catalog")
	}
	info := &nameTreeInfo{nums: map[int]bool{}}
	names, hasNames := cat["Names"]
	af, hasAF := cat["AF"]
	if !hasNames {
		if hasAF {
			return nil, malformed("/AF without name tree")
		}
		return info, nil
	}
	nd, ok := names.(pdict)
	if !ok || len(nd) != 1 {
		return nil, malformed("bad /Names dictionary")
	}
	ef, ok := nd["EmbeddedFiles"].(pdict)
	if !ok || len(ef) != 1 {
		return nil, malformed("bad /EmbeddedFiles name tree")
	}
	arr, ok := ef["Names"].([]any)
	if !ok || len(arr)%2 != 0 {
		return nil, malformed("bad name tree array")
	}
	seen := map[string]bool{}
	for i := 0; i < len(arr); i += 2 {
		key, ok := arr[i].([]byte)
		if !ok {
			return nil, malformed("name tree key is not a string")
		}
		name, ok := textString(key)
		if !ok || name == "" {
			return nil, malformed("bad file name")
		}
		ref, ok := arr[i+1].(pref)
		if !ok {
			return nil, malformed("name tree value is not a reference")
		}
		if seen[name] {
			return nil, malformed("duplicate attachment name")
		}
		if info.nums[int(ref)] {
			return nil, malformed("file specification listed twice")
		}
		seen[name] = true
		info.nums[int(ref)] = true
		info.entries = append(info.entries, treeEntry{name, ref})
	}
	list, ok := af.([]any)
	if !hasAF || !ok || len(list) != len(info.entries) {
		return nil, malformed("/AF differs from the name tree")
	}
	for _, v := range list {
		r, ok := v.(pref)
		if !ok || !info.nums[int(r)] {
			return nil, malformed("/AF differs from the name tree")
		}
	}
	return info, nil
}

func isFilespec(d pdict) bool {
	t, _ := d["Type"].(pname)
	_, hasEF := d["EF"]
	return t == "Filespec" || hasEF
}

// hasNestedFilespec reports whether v holds, below its top level, a
// dictionary that looks like a file specification.
func hasNestedFilespec(v any, top bool) bool {
	switch x := v.(type) {
	case pdict:
		if !top && isFilespec(x) {
			return true
		}
		for _, e := range x {
			if hasNestedFilespec(e, false) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if hasNestedFilespec(e, false) {
				return true
			}
		}
	}
	return false
}

// filespec returns the data of the file specification object num, listed in
// the name tree under name.
func filespec(objs map[int]*pobject, name string, num int) ([]byte, error) {
	o := objs[num]
	var d pdict
	if o != nil {
		d, _ = o.val.(pdict)
	}
	if t, _ := d["Type"].(pname); t != "Filespec" {
		return nil, malformed("name tree value is not a file specification")
	}
	uf, _ := d["UF"].([]byte)
	if dec, ok := textString(uf); !ok || dec != name {
		return nil, malformed("file name differs from the name tree")
	}
	efd, ok := d["EF"].(pdict)
	if !ok {
		return nil, malformed("attachment without /EF")
	}
	ref, isRef := efd["F"].(pref)
	if !isRef {
		return nil, malformed("/EF /F is not a reference")
	}
	if u, has := efd["UF"]; has && u != any(ref) {
		return nil, malformed("/EF /UF differs from /F")
	}
	so := objs[int(ref)]
	if so == nil || !so.has {
		return nil, malformed("embedded file is not a stream")
	}
	sd, _ := so.val.(pdict)
	if t, _ := sd["Type"].(pname); t != "EmbeddedFile" {
		return nil, malformed("embedded file without /Type /EmbeddedFile")
	}
	if _, filtered := sd["Filter"]; filtered {
		return nil, malformed("filtered embedded files are not supported")
	}
	return bytes.Clone(so.stream), nil
}
