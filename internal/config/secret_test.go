package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretRedaction(t *testing.T) {
	t.Parallel()
	const value = "hunter2-very-secret"
	s := NewSecret(value)
	if s.Reveal() != value || !s.IsSet() {
		t.Fatalf("Reveal() = %q, IsSet() = %v", s.Reveal(), s.IsSet())
	}
	if (Secret{}).IsSet() {
		t.Error("zero Secret reports IsSet")
	}

	outputs := map[string]string{
		"String":   s.String(),
		"GoString": s.GoString(),
		"%v":       fmt.Sprintf("%v", s),
		"%s":       fmt.Sprintf("%s", s),
		"%q":       fmt.Sprintf("%q", s),
		"%x":       fmt.Sprintf("%x", s),
		"%#v":      fmt.Sprintf("%#v", s),
		"%+v cfg":  fmt.Sprintf("%+v", Config{DBDSN: s, SetupToken: s}),
		"%#v cfg":  fmt.Sprintf("%#v", Config{DBDSN: s}),
	}
	jsonOut, err := json.Marshal(struct{ DSN Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	outputs["json"] = string(jsonOut)
	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	outputs["text"] = string(text)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("cfg", "dsn", s)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", "dsn", s)
	outputs["slog"] = buf.String()

	for name, out := range outputs {
		if strings.Contains(out, value) {
			t.Errorf("%s leaks the secret: %s", name, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s does not contain %s: %s", name, Redacted, out)
		}
	}
	if string(jsonOut) != `{"DSN":"[REDACTED]"}` {
		t.Errorf("json = %s", jsonOut)
	}
}
