package tenant

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestSecretDurations(t *testing.T) {
	t.Parallel()
	all := AllSecretDurations()
	want := []SecretDuration{"1h", "12h", "1d", "3d", "7d", "30d"}
	if !slices.Equal(all, want) {
		t.Fatalf("AllSecretDurations = %v", all)
	}
	for i, d := range all {
		if !d.Valid() || (i > 0 && d.Duration() <= all[i-1].Duration()) {
			t.Errorf("%s: valid %v, duration %v", d, d.Valid(), d.Duration())
		}
	}
	if SecretDuration30d.Duration() != 30*24*time.Hour {
		t.Error("30d")
	}
	for _, d := range []SecretDuration{"", "2d", "1H"} {
		if d.Valid() || d.Duration() != 0 {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestSecretDurationSet(t *testing.T) {
	t.Parallel()
	s, err := NewSecretDurationSet(SecretDuration30d, SecretDuration1h, SecretDuration3d)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.String(); got != "1h,3d,30d" {
		t.Errorf("String = %q", got)
	}
	if !s.Has(SecretDuration3d) || s.Has(SecretDuration7d) || s.Has("x") || s.Empty() || s.Shortest() != SecretDuration1h {
		t.Errorf("set %v", s.Codes())
	}
	back, err := ParseSecretDurationSet("1h,3d,30d")
	if err != nil || back != s {
		t.Errorf("Parse = %v, %v", back, err)
	}
	var empty SecretDurationSet
	if !empty.Empty() || empty.Shortest() != "" || empty.String() != "" || empty.Codes() != nil {
		t.Error("empty set")
	}
	for _, bad := range []string{"", "1h,1h", "2d", "1h,", ",1h"} {
		if _, err := ParseSecretDurationSet(bad); !errors.Is(err, ErrInvalidTenant) {
			t.Errorf("Parse(%q) = %v", bad, err)
		}
	}
}

func TestSecretSettings(t *testing.T) {
	t.Parallel()
	d := DefaultSecretSettings()
	if !d.Enabled || d.Durations.String() != "1h,1d,7d" || d.DefaultDuration != "" || !d.FileAllowed ||
		d.FileMaxBytes != 10<<20 || !d.EmailAllowed || d.EmailRequiresPassphrase {
		t.Fatalf("defaults = %+v", d)
	}
	if err := d.Validate(); err != nil || d.EffectiveDefaultDuration() != SecretDuration1h {
		t.Fatalf("Validate = %v, effective %s", err, d.EffectiveDefaultDuration())
	}
	d.DefaultDuration = SecretDuration7d
	if err := d.Validate(); err != nil || d.EffectiveDefaultDuration() != SecretDuration7d {
		t.Fatalf("Validate = %v", err)
	}
	for name, mod := range map[string]func(*SecretSettings){
		"empty":        func(s *SecretSettings) { s.Durations = 0 },
		"unknown bit":  func(s *SecretSettings) { s.Durations |= 1 << 7 },
		"not offered":  func(s *SecretSettings) { s.DefaultDuration = SecretDuration30d },
		"small file":   func(s *SecretSettings) { s.FileMaxBytes = MinSecretFileBytes - 1 },
		"large file":   func(s *SecretSettings) { s.FileMaxBytes = MaxSecretFileBytes + 1 },
		"unknown code": func(s *SecretSettings) { s.DefaultDuration = "2d" },
	} {
		s := DefaultSecretSettings()
		mod(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalidTenant) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
