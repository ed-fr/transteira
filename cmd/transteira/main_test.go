package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/version"
)

// failWriter is an io.Writer that always fails.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
		noStdout   bool
		noStderr   bool
	}{
		{name: "no args", args: nil, wantCode: exitOK, wantStdout: []string{"Usage:", "serve", "rotate-master-key", "healthcheck", "version", "help"}, noStderr: true},
		{name: "help", args: []string{"help"}, wantCode: exitOK, wantStdout: []string{"Usage:", "migrate", "backup"}, noStderr: true},
		{name: "short help flag", args: []string{"-h"}, wantCode: exitOK, wantStdout: []string{"Usage:"}, noStderr: true},
		{name: "long help flag", args: []string{"--help"}, wantCode: exitOK, wantStdout: []string{"Usage:"}, noStderr: true},
		{name: "unknown", args: []string{"bogus"}, wantCode: exitUsage, wantStderr: []string{`unknown command "bogus"`, "Usage:"}, noStdout: true},
		{name: "version", args: []string{"version"}, wantCode: exitOK, wantStdout: []string{version.Get().String()}, noStderr: true},
		{name: "version help", args: []string{"version", "-h"}, wantCode: exitOK, wantStderr: []string{"-json"}, noStdout: true},
		{name: "version bad flag", args: []string{"version", "--nope"}, wantCode: exitUsage, wantStderr: []string{"nope"}, noStdout: true},
		{name: "version extra arg", args: []string{"version", "extra"}, wantCode: exitUsage, wantStderr: []string{`unexpected argument "extra"`}, noStdout: true},
		{name: "migrate help", args: []string{"migrate", "-h"}, wantCode: exitOK, wantStderr: []string{"-status"}, noStdout: true},
		{name: "migrate extra arg", args: []string{"migrate", "extra"}, wantCode: exitUsage, noStdout: true},
		{name: "rotate-master-key help", args: []string{"rotate-master-key", "-h"}, wantCode: exitOK, wantStderr: []string{"-batch-size"}, noStdout: true},
		{name: "rotate-master-key extra arg", args: []string{"rotate-master-key", "extra"}, wantCode: exitUsage, noStdout: true},
		{name: "rotate-master-key abandon and recover", args: []string{"rotate-master-key", "-abandon", "-recover-from", "/x"}, wantCode: exitUsage, wantStderr: []string{"cannot be combined"}, noStdout: true},
		{name: "rotate-master-key bad batch", args: []string{"rotate-master-key", "-batch-size", "0"}, wantCode: exitUsage, wantStderr: []string{"must be positive"}, noStdout: true},
		{name: "backup help", args: []string{"backup", "-h"}, wantCode: exitOK, wantStderr: []string{"-out"}, noStdout: true},
		{name: "backup bad flag", args: []string{"backup", "-x"}, wantCode: exitUsage, noStdout: true},
		{name: "backup extra arg", args: []string{"backup", "extra"}, wantCode: exitUsage, wantStderr: []string{`unexpected argument "extra"`}, noStdout: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Fatalf("run(%q) = %d, want %d; stderr=%q", tt.args, got, tt.wantCode, stderr.String())
			}
			for _, s := range tt.wantStdout {
				if !strings.Contains(stdout.String(), s) {
					t.Errorf("stdout %q does not contain %q", stdout.String(), s)
				}
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("stderr %q does not contain %q", stderr.String(), s)
				}
			}
			if tt.noStdout && stdout.Len() != 0 {
				t.Errorf("unexpected stdout %q", stdout.String())
			}
			if tt.noStderr && stderr.Len() != 0 {
				t.Errorf("unexpected stderr %q", stderr.String())
			}
		})
	}
}

func TestRunVersionJSON(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version", "--json"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code %d, stderr=%q", code, stderr.String())
	}
	var got version.Info
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if want := version.Get(); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestRunVersionWriteError(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"version"}, {"version", "--json"}} {
		var stderr bytes.Buffer
		if code := run(args, failWriter{}, &stderr); code != exitError {
			t.Errorf("run(%q) = %d, want %d", args, code, exitError)
		}
		if !strings.Contains(stderr.String(), "write failed") {
			t.Errorf("stderr %q does not report the write error", stderr.String())
		}
	}
}

func TestUsageListsEveryCommand(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	usage(&b)
	for _, c := range commands() {
		if !strings.Contains(b.String(), c.name) || !strings.Contains(b.String(), c.summary) {
			t.Errorf("usage is missing %q", c.name)
		}
	}
}
