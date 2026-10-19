package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunWritesEveryVariable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(&stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr: %s", code, stderr.String())
	}
	for _, name := range []string{"TT_DB_DRIVER", "TT_MASTER_KEY_FILE", "TT_TRUSTED_PROXIES"} {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("output does not mention %s", name)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRunReportsWriteErrors(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(failingWriter{}, &stderr); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "disk full") {
		t.Errorf("stderr = %q, want the write error", stderr.String())
	}
}
