package tenant

import (
	"errors"
	"slices"
	"testing"
)

func TestExpressDurations(t *testing.T) {
	t.Parallel()
	got := ExpressDurations()
	if want := []SecretDuration{SecretDuration1h, SecretDuration1d, SecretDuration7d}; !slices.Equal(got, want) {
		t.Fatalf("ExpressDurations = %v, want %v", got, want)
	}
	got[0] = SecretDuration30d // a copy: the fixed list is unchanged
	if ExpressDurations()[0] != SecretDuration1h {
		t.Error("ExpressDurations returned the internal array")
	}
	for _, d := range AllSecretDurations() {
		want := d == SecretDuration1h || d == SecretDuration1d || d == SecretDuration7d
		if d.ExpressDuration() != want {
			t.Errorf("%s.ExpressDuration() = %v, want %v", d, !want, want)
		}
	}
	if SecretDuration("").ExpressDuration() || SecretDuration("1H").ExpressDuration() {
		t.Error("unknown code accepted as an express duration")
	}
}

func TestExpressSettings(t *testing.T) {
	t.Parallel()
	d := DefaultExpressSettings()
	if d.Enabled || d.PerHourPerIP != 10 || d.PerHourPerToken != 100 || d.MaxPending != 1000 {
		t.Fatalf("defaults = %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate(defaults) = %v", err)
	}
	if got := (ExpressSettings{}).WithDefaults(); got != d {
		t.Errorf("zero WithDefaults = %+v", got)
	}
	set := ExpressSettings{Enabled: true, PerHourPerIP: 5, PerHourPerToken: 7, MaxPending: 9}
	if got := set.WithDefaults(); got != set {
		t.Errorf("WithDefaults changed set values: %+v", got)
	}
	bounds := ExpressSettings{
		PerHourPerIP: MaxExpressPerHourPerIP, PerHourPerToken: MaxExpressPerHourPerToken,
		MaxPending: MaxExpressMaxPending,
	}
	if err := bounds.Validate(); err != nil {
		t.Errorf("Validate(max bounds) = %v", err)
	}
	low := ExpressSettings{
		PerHourPerIP: MinExpressPerHourPerIP, PerHourPerToken: MinExpressPerHourPerToken,
		MaxPending: MinExpressMaxPending,
	}
	if err := low.Validate(); err != nil {
		t.Errorf("Validate(min bounds) = %v", err)
	}
	for name, mod := range map[string]func(*ExpressSettings){
		"ip zero":       func(s *ExpressSettings) { s.PerHourPerIP = 0 },
		"ip high":       func(s *ExpressSettings) { s.PerHourPerIP = MaxExpressPerHourPerIP + 1 },
		"token zero":    func(s *ExpressSettings) { s.PerHourPerToken = 0 },
		"token high":    func(s *ExpressSettings) { s.PerHourPerToken = MaxExpressPerHourPerToken + 1 },
		"pending zero":  func(s *ExpressSettings) { s.MaxPending = 0 },
		"pending high":  func(s *ExpressSettings) { s.MaxPending = MaxExpressMaxPending + 1 },
		"pending minus": func(s *ExpressSettings) { s.MaxPending = -1 },
	} {
		s := DefaultExpressSettings()
		mod(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalidTenant) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}
