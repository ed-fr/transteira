// Command genstubs generates, from the oapi-codegen output internal/api/gen/gen.go, a type
// Unimplemented that satisfies gen.StrictServerInterface by answering "404 not-found" for
// every operation. The HTTP server embeds it, and each real handler method shadows the stub.
//
// Each stub returns ErrNotImplemented, which the strict handler's response error handler maps
// to a complete 404 not-found problem (with the request identifier as instance). The only
// exception is an operation whose spec declares a bodiless 404 response (tus endpoints): its
// stub returns that response, since no problem body is expected there.
//
// Usage (from api/, via go:generate):
//
//	go run ../tools/genstubs -in ../internal/api/gen/gen.go -out ../internal/api/stubs/stubs_gen.go
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultGenImport = "github.com/ed-fr/transteira/internal/api/gen"
	interfaceName    = "StrictServerInterface"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args, generates the stubs and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genstubs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "path of the oapi-codegen output (gen.go)")
	out := fs.String("out", "", "output file (standard output when empty)")
	cfg := config{}
	fs.StringVar(&cfg.pkg, "pkg", "stubs", "package name of the generated file")
	fs.StringVar(&cfg.genImport, "gen-import", defaultGenImport, "import path of the generated API package")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" {
		_, _ = fmt.Fprintln(stderr, "genstubs: -in is required")
		return 2
	}
	src, err := os.ReadFile(*in)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "genstubs: %v\n", err)
		return 1
	}
	code, err := generate(*in, src, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "genstubs: %v\n", err)
		return 1
	}
	if *out == "" {
		_, _ = stdout.Write(code)
		return 0
	}
	if err := os.WriteFile(*out, code, 0o600); err != nil { //nolint:gosec // G703: the output path is a developer-supplied flag of a build tool.
		_, _ = fmt.Fprintf(stderr, "genstubs: %v\n", err)
		return 1
	}
	return 0
}

// config holds the generation parameters.
type config struct {
	pkg       string
	genImport string
}

// source is the parsed generated API file.
type source struct {
	fset    *token.FileSet
	file    *ast.File
	types   map[string]ast.Expr // top-level type name -> type expression
	imports map[string]string   // package name -> import path
}

// method is one operation of the strict server interface, ready to be printed.
type method struct {
	name    string
	params  []string
	results []string
	body    string
}

// generate returns the gofmt'ed stubs file for the Go source src.
func generate(filename string, src []byte, cfg config) ([]byte, error) {
	s, err := parseSource(filename, src)
	if err != nil {
		return nil, err
	}
	iface, err := s.findInterface()
	if err != nil {
		return nil, err
	}
	genPkg := s.file.Name.Name
	usedImports := map[string]string{}
	var methods []method
	for _, field := range iface.Methods.List {
		ft, ok := field.Type.(*ast.FuncType)
		if !ok || len(field.Names) != 1 {
			return nil, fmt.Errorf("%s: embedded interfaces are not supported", interfaceName)
		}
		m := method{name: field.Names[0].Name}
		if m.params, err = s.typeList(ft.Params, genPkg, usedImports); err != nil {
			return nil, fmt.Errorf("method %s: %w", m.name, err)
		}
		if m.results, err = s.typeList(ft.Results, genPkg, usedImports); err != nil {
			return nil, fmt.Errorf("method %s: %w", m.name, err)
		}
		if len(m.results) != 2 || m.results[1] != "error" {
			return nil, fmt.Errorf("method %s: must return (response, error)", m.name)
		}
		m.body = s.notFoundBody(m.name, genPkg)
		methods = append(methods, m)
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i].name < methods[j].name })
	return render(cfg, genPkg, usedImports, methods)
}

// parseSource parses src and indexes its top-level types and imports.
func parseSource(filename string, src []byte) (*source, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	s := &source{fset: fset, file: file, types: map[string]ast.Expr{}, imports: map[string]string{}}
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value) // the parser guarantees a valid literal
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		s.imports[name] = path
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts := spec.(*ast.TypeSpec) //nolint:forcetypeassert // TYPE declarations only hold TypeSpecs.
			s.types[ts.Name.Name] = ts.Type
		}
	}
	return s, nil
}

// findInterface returns the StrictServerInterface declaration.
func (s *source) findInterface() (*ast.InterfaceType, error) {
	expr, ok := s.types[interfaceName]
	if !ok {
		return nil, fmt.Errorf("type %s not found", interfaceName)
	}
	iface, ok := expr.(*ast.InterfaceType)
	if !ok {
		return nil, fmt.Errorf("%s is not an interface", interfaceName)
	}
	return iface, nil
}

// typeList prints the types of fields (one entry per declared name), qualifying the types
// declared in the source package with genPkg and recording the other packages used.
func (s *source) typeList(fields *ast.FieldList, genPkg string, used map[string]string) ([]string, error) {
	if fields == nil {
		return nil, nil
	}
	var out []string
	for _, f := range fields.List {
		typ, err := s.qualify(f.Type, genPkg, used)
		if err != nil {
			return nil, err
		}
		n := max(len(f.Names), 1)
		for range n {
			out = append(out, typ)
		}
	}
	return out, nil
}

// qualify prints expr with the package-local exported types prefixed by genPkg.
func (s *source) qualify(expr ast.Expr, genPkg string, used map[string]string) (string, error) {
	var err error
	ast.Inspect(expr, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			// In a type expression, a selector is always a package-qualified identifier.
			pkg := x.X.(*ast.Ident) //nolint:forcetypeassert // guaranteed by the Go grammar.
			path, ok := s.imports[pkg.Name]
			if !ok {
				err = fmt.Errorf("unknown package %q", pkg.Name)
				return false
			}
			used[pkg.Name] = path
			return false
		case *ast.Ident:
			if _, local := s.types[x.Name]; local && ast.IsExported(x.Name) {
				x.Name = genPkg + "." + x.Name
			}
		}
		return true
	})
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, s.fset, expr); err != nil {
		return "", fmt.Errorf("print type: %w", err)
	}
	return buf.String(), nil
}

// notFoundBody returns the body of the stub of operation op: the bodiless 404 response when
// the spec declares one, ErrNotImplemented otherwise.
func (s *source) notFoundBody(op, genPkg string) string {
	emptyResp := op + "404Response"
	if st, ok := s.types[emptyResp].(*ast.StructType); ok && len(st.Fields.List) == 0 {
		return "return " + genPkg + "." + emptyResp + "{}, nil"
	}
	return "return nil, ErrNotImplemented"
}

// render writes the stubs file and formats it.
func render(cfg config, genPkg string, used map[string]string, methods []method) ([]byte, error) {
	var b bytes.Buffer
	w := func(format string, a ...any) { _, _ = fmt.Fprintf(&b, format, a...) }

	w("// Code generated by genstubs. DO NOT EDIT.\n\n")
	w("// Package %s provides Unimplemented, a %s.%s whose every operation answers\n", cfg.pkg, genPkg, interfaceName)
	w("// 404 not-found. The server embeds it so that each real handler method replaces a stub.\n")
	w("package %s\n\nimport (\n", cfg.pkg)
	specs := []string{importSpec("errors", "errors")}
	for name, path := range used {
		specs = append(specs, importSpec(name, path))
	}
	sort.Strings(specs)
	for _, spec := range specs {
		w("%s\n", spec)
	}
	w("\n%q\n)\n\n", cfg.genImport)
	w("// ErrNotImplemented is returned by the stubs; the strict handler's response error handler\n")
	w("// maps it to a 404 not-found problem.\n")
	w("var ErrNotImplemented = errors.New(%q)\n\n", cfg.pkg+": operation not implemented")
	w("// Unimplemented implements %s.%s with 404 not-found answers.\n", genPkg, interfaceName)
	w("type Unimplemented struct{}\n\n")
	w("var _ %s.%s = Unimplemented{}\n\n", genPkg, interfaceName)
	for _, m := range methods {
		params := make([]string, len(m.params))
		for i, p := range m.params {
			params[i] = "_ " + p
		}
		w("// %s answers 404 not-found until the operation is implemented.\n", m.name)
		w("func (Unimplemented) %s(%s) (%s) {\n%s\n}\n\n",
			m.name, strings.Join(params, ", "), strings.Join(m.results, ", "), m.body)
	}
	code, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format: %w", err)
	}
	return code, nil
}

// importSpec returns the import line of path, naming it only when name differs from the
// last path element.
func importSpec(name, path string) string {
	if path[strings.LastIndex(path, "/")+1:] == name {
		return strconv.Quote(path)
	}
	return name + " " + strconv.Quote(path)
}
