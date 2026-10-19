package config

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// recordingEnv wraps a getenv function and records every variable read.
type recordingEnv struct {
	mu    sync.Mutex
	names map[string]bool
	env   func(string) string
}

func (r *recordingEnv) getenv(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[name] = true
	return r.env(name)
}

// TestVariablesMatchLoad ensures that the documentation listing and Load never
// drift apart: every variable read by Load is documented, and every documented
// variable is read by Load.
func TestVariablesMatchLoad(t *testing.T) {
	t.Parallel()
	documented := make(map[string]Var)
	for _, v := range Variables() {
		if _, dup := documented[v.Name]; dup {
			t.Errorf("%s documented twice", v.Name)
		}
		documented[v.Name] = v
		if !strings.HasPrefix(v.Name, envPrefix) || v.Group == "" || v.Description == "" {
			t.Errorf("%s: incomplete documentation %+v", v.Name, v)
		}
		if v.Required && v.Example == "" {
			t.Errorf("%s: required variable without example", v.Name)
		}
	}

	// Several environments exercise every code path (postgres, files...).
	envs := []map[string]string{
		nil,
		{EnvDBDriver: DriverPostgres, EnvDBDSN: "postgres://x", EnvSetupToken: fakeToken},
		{EnvDBDSNFile: "/nonexistent", EnvSetupTokenFile: "/nonexistent", EnvMasterKeyNewFile: "/run/k2"},
	}
	read := make(map[string]bool)
	for _, vars := range envs {
		rec := &recordingEnv{names: make(map[string]bool), env: envFunc(vars)}
		_, _ = Load(rec.getenv)
		for name := range rec.names {
			read[name] = true
		}
	}
	for name := range read {
		if _, ok := documented[name]; !ok {
			t.Errorf("%s is read by Load but missing from Variables()", name)
		}
	}
	for name := range documented {
		if !read[name] {
			t.Errorf("%s is documented but never read by Load", name)
		}
	}
}

// TestVariablesDefaultsLoad checks that documented defaults are accepted by
// Load (an .env.example with every default uncommented must be valid).
func TestVariablesDefaultsLoad(t *testing.T) {
	t.Parallel()
	vars := make(map[string]string)
	for _, v := range Variables() {
		switch {
		case v.Required:
			vars[v.Name] = v.Example
		case v.Default != "":
			vars[v.Name] = v.Default
		}
	}
	mustLoad(t, vars)
}

func TestWriteEnvExample(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := WriteEnvExample(&buf); err != nil {
		t.Fatalf("WriteEnvExample() error: %v", err)
	}
	out := buf.String()
	for _, v := range Variables() {
		line := "# " + v.Name + "=" + v.Default + "\n"
		if v.Required {
			line = "\n" + v.Name + "=" + v.Example + "\n"
		}
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q", line)
		}
	}
	for _, want := range []string{"# Database\n", "# Default: " + DefaultListenAddr, "# Required.", "# Secret:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// failingWriter always fails.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteEnvExampleError(t *testing.T) {
	t.Parallel()
	if err := WriteEnvExample(failingWriter{}); err == nil {
		t.Error("WriteEnvExample() ignored a write error")
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()
	got := wrap("aa bb cc averyveryverylongword dd", 6)
	want := []string{"aa bb", "cc", "averyveryverylongword", "dd"}
	if !slices.Equal(got, want) {
		t.Errorf("wrap() = %q, want %q", got, want)
	}
	if wrap("   ", 10) != nil {
		t.Error("wrap of blanks should be nil")
	}
}

func TestUnknownVariables(t *testing.T) {
	t.Parallel()
	got := UnknownVariables([]string{
		"PATH=/bin", "TT_LOG_LEVEL=info", "TT_TRUSTED_PROXY=1.2.3.4", "TT_ZZZ", "TT_TRUSTED_PROXY=x", "TT_AAA=",
	})
	want := []string{"TT_AAA", "TT_TRUSTED_PROXY", "TT_ZZZ"}
	if !slices.Equal(got, want) {
		t.Errorf("UnknownVariables() = %v, want %v", got, want)
	}
}
