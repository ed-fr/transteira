package problem

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// readRepoFile reads a file given relative to the repository root.
func readRepoFile(t *testing.T, elem ...string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	parts := append([]string{filepath.Dir(file), "..", "..", ".."}, elem...)
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(elem...), err)
	}
	return raw
}

// loadSpec parses api/openapi.yaml into a generic tree.
func loadSpec(t *testing.T) map[string]any {
	t.Helper()
	raw := readRepoFile(t, "api", "openapi.yaml")
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return doc
}

// dig walks nested maps by key.
func dig(t *testing.T, node any, keys ...string) any {
	t.Helper()
	for _, k := range keys {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("spec: %q is not under a mapping", k)
		}
		node, ok = m[k]
		if !ok {
			t.Fatalf("spec: missing key %q", k)
		}
	}
	return node
}

func TestSpecProblemCodeEnumMatchesCatalog(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	enum, ok := dig(t, doc, "components", "schemas", "ProblemCode", "enum").([]any)
	if !ok {
		t.Fatal("ProblemCode.enum is not a list")
	}
	inSpec := make(map[Code]bool, len(enum))
	for _, v := range enum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("non-string enum value %v", v)
		}
		inSpec[Code(s)] = true
		if _, ok := Lookup(Code(s)); !ok {
			t.Errorf("spec code %q missing from Go catalog", s)
		}
	}
	for _, c := range Codes() {
		if !inSpec[c] {
			t.Errorf("Go code %q missing from spec ProblemCode enum", c)
		}
	}
}

// problemExample is a code/status/type/title tuple found in a spec example.
type problemExample struct {
	where  string
	code   string
	status int
	typ    string
	title  string
}

// collectExamples recursively finds every mapping that looks like a Problem
// example (has string "code" and integer "status").
func collectExamples(node any, where string, out *[]problemExample) {
	switch n := node.(type) {
	case map[string]any:
		code, okCode := n["code"].(string)
		status, okStatus := n["status"].(int)
		if okCode && okStatus {
			typ, _ := n["type"].(string)
			title, _ := n["title"].(string)
			*out = append(*out, problemExample{where, code, status, typ, title})
		}
		for k, v := range n {
			collectExamples(v, where+"/"+k, out)
		}
	case []any:
		for _, v := range n {
			collectExamples(v, where+"[]", out)
		}
	}
}

func TestSpecResponseExamplesMatchCatalog(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	responses, ok := dig(t, doc, "components", "responses").(map[string]any)
	if !ok {
		t.Fatal("components/responses is not a mapping")
	}
	tests := []struct {
		name string
		node any
		min  int
		// checkTitle requires the example title to equal the default title.
		checkTitle bool
	}{
		// Every shared error response carries at least one Problem example.
		{"components/responses", responses, len(responses), true},
		{"paths", dig(t, doc, "paths"), 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var examples []problemExample
			collectExamples(tt.node, tt.name, &examples)
			if len(examples) < tt.min {
				t.Fatalf("found %d problem examples, want >= %d", len(examples), tt.min)
			}
			for _, ex := range examples {
				def, ok := Lookup(Code(ex.code))
				if !ok {
					t.Errorf("%s: code %q not in catalog", ex.where, ex.code)
					continue
				}
				if def.Status != ex.status {
					t.Errorf("%s: code %q status %d, catalog %d", ex.where, ex.code, ex.status, def.Status)
				}
				if tt.checkTitle && ex.title != def.Title {
					t.Errorf("%s: code %q title %q, catalog %q", ex.where, ex.code, ex.title, def.Title)
				}
				if strings.HasPrefix(ex.typ, TypeBaseURI) && ex.typ != Code(ex.code).TypeURI() {
					t.Errorf("%s: type %q does not match code %q", ex.where, ex.typ, ex.code)
				}
			}
		})
	}
}

func TestErrorsDocMatchesCatalog(t *testing.T) {
	t.Parallel()
	raw := readRepoFile(t, "docs", "api", "errors.md")
	const statusPrefix = "- **HTTP status:** "
	inDoc := make(map[Code]bool)
	docStatus := make(map[Code]int)
	var current Code
	for line := range strings.Lines(string(raw)) {
		line = strings.TrimRight(line, "\r\n")
		if heading, ok := strings.CutPrefix(line, "### "); ok {
			current = Code(heading)
			if inDoc[current] {
				t.Errorf("errors.md: duplicate heading %q", heading)
			}
			inDoc[current] = true
			if _, ok := Lookup(current); !ok {
				t.Errorf("errors.md: heading %q is not a catalog code", heading)
			}
			continue
		}
		if strings.HasPrefix(line, "## ") {
			current = ""
			continue
		}
		rest, ok := strings.CutPrefix(line, statusPrefix)
		if !ok || current == "" {
			continue
		}
		num, _, _ := strings.Cut(rest, " ")
		status, err := strconv.Atoi(num)
		if err != nil {
			t.Errorf("errors.md: %s: unparsable status line %q", current, line)
			continue
		}
		if _, dup := docStatus[current]; dup {
			t.Errorf("errors.md: %s: several status lines", current)
		}
		docStatus[current] = status
	}
	for _, c := range Codes() {
		if !inDoc[c] {
			t.Errorf("errors.md: missing heading \"### %s\"", c)
			continue
		}
		got, ok := docStatus[c]
		if !ok {
			t.Errorf("errors.md: %s: missing %q line", c, statusPrefix)
			continue
		}
		if def, _ := Lookup(c); got != def.Status {
			t.Errorf("errors.md: %s: status %d, catalog %d", c, got, def.Status)
		}
	}
}
