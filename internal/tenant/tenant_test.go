package tenant

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func validTenant() Tenant {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return Tenant{
		ID:                 validID,
		Name:               "Entity A",
		FQDN:               "transfer.entity-a.example.com",
		DefaultLanguage:    "fr",
		MaxTransferBytes:   MaxTransferLimit,
		MaxTransferCeiling: MaxTransferLimit,
		StorageQuotaBytes:  1 << 40,
		Status:             StatusActive,
		PrimaryColor:       DefaultPrimaryColor,
		AccentColor:        DefaultAccentColor,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func TestTenantValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Tenant)
		ok     bool
	}{
		{"valid", func(*Tenant) {}, true},
		{"no id yet", func(x *Tenant) { x.ID = "" }, true},
		{"english", func(x *Tenant) { x.DefaultLanguage = "en" }, true},
		{"name of 100 runes", func(x *Tenant) { x.Name = strings.Repeat("é", 100) }, true},
		{"min transfer", func(x *Tenant) { x.MaxTransferBytes = 1 }, true},
		{"bad id", func(x *Tenant) { x.ID = "ten_bad" }, false},
		{"empty name", func(x *Tenant) { x.Name = "" }, false},
		{"long name", func(x *Tenant) { x.Name = strings.Repeat("a", 101) }, false},
		{"invalid utf8 name", func(x *Tenant) { x.Name = "a\xffb" }, false},
		{"invalid fqdn", func(x *Tenant) { x.FQDN = "192.0.2.1" }, false},
		{"empty fqdn", func(x *Tenant) { x.FQDN = "" }, false},
		{"unnormalised fqdn", func(x *Tenant) { x.FQDN = "Transfer.Example.com:443" }, false},
		{"unknown language", func(x *Tenant) { x.DefaultLanguage = "de" }, false},
		{"empty language", func(x *Tenant) { x.DefaultLanguage = "" }, false},
		{"zero transfer", func(x *Tenant) { x.MaxTransferBytes = 0 }, false},
		{"negative transfer", func(x *Tenant) { x.MaxTransferBytes = -1 }, false},
		{"transfer over limit", func(x *Tenant) { x.MaxTransferBytes = MaxTransferLimit + 1 }, false},
		{"transfer under ceiling", func(x *Tenant) { x.MaxTransferBytes, x.MaxTransferCeiling = 10, 11 }, true},
		{"transfer over ceiling", func(x *Tenant) { x.MaxTransferBytes, x.MaxTransferCeiling = 12, 11 }, false},
		{"zero ceiling", func(x *Tenant) { x.MaxTransferCeiling = 0 }, false},
		{"ceiling over limit", func(x *Tenant) { x.MaxTransferCeiling = MaxTransferLimit + 1 }, false},
		{"deleting", func(x *Tenant) { x.Status = StatusDeleting }, true},
		{"empty status", func(x *Tenant) { x.Status = "" }, false},
		{"unknown status", func(x *Tenant) { x.Status = "archived" }, false},
		{"lower-case colors", func(x *Tenant) { x.PrimaryColor, x.AccentColor = "#abcdef", "#000000" }, true},
		{"empty primary", func(x *Tenant) { x.PrimaryColor = "" }, false},
		{"short accent", func(x *Tenant) { x.AccentColor = "#FFF" }, false},
		{"assets", func(x *Tenant) { x.HasLogo, x.HasBackground = true, true }, true},
		{"zero quota", func(x *Tenant) { x.StorageQuotaBytes = 0 }, false},
		{"negative quota", func(x *Tenant) { x.StorageQuotaBytes = -5 }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ten := validTenant()
			tc.mutate(&ten)
			err := ten.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("Validate() = %v, want ErrInvalidTenant", err)
			}
		})
	}
}

func TestMaxTransferLimit(t *testing.T) {
	t.Parallel()
	if MaxTransferLimit != 21474836480 {
		t.Fatalf("MaxTransferLimit = %d, want 21474836480 (OpenAPI maximum)", MaxTransferLimit)
	}
}

func TestClone(t *testing.T) {
	t.Parallel()
	var nilTenant *Tenant
	if nilTenant.Clone() != nil {
		t.Fatal("Clone of nil is not nil")
	}
	orig := validTenant()
	c := orig.Clone()
	if c == &orig || *c != orig {
		t.Fatal("Clone is not an equal, distinct copy")
	}
	c.Name = "changed"
	if orig.Name == "changed" {
		t.Fatal("Clone shares state with the original")
	}
}

func TestLanguages(t *testing.T) {
	t.Parallel()
	langs := Languages()
	if !slices.Equal(langs, []string{"en", "fr"}) {
		t.Fatalf("Languages() = %v", langs)
	}
	for _, l := range langs {
		if !IsLanguage(l) {
			t.Fatalf("IsLanguage(%q) = false", l)
		}
	}
	langs[0] = "xx"
	if Languages()[0] != "en" {
		t.Fatal("Languages() returns shared state")
	}
	if IsLanguage("EN") || IsLanguage("de") {
		t.Fatal("IsLanguage accepted an unsupported code")
	}
}

func TestValidColor(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"#000000", "#FFFFFF", "#1f4e79", DefaultPrimaryColor, DefaultAccentColor} {
		if !ValidColor(c) {
			t.Errorf("ValidColor(%q) = false", c)
		}
	}
	for _, c := range []string{"", "#", "#FFF", "000000", "#0000000", "#GGGGGG", "##00000", "red", "#00000\n"} {
		if ValidColor(c) {
			t.Errorf("ValidColor(%q) = true", c)
		}
	}
}

func TestStatusValid(t *testing.T) {
	t.Parallel()
	if !StatusActive.Valid() || !StatusDeleting.Valid() || Status("").Valid() || Status("Active").Valid() {
		t.Fatal("Status.Valid is wrong")
	}
}

func TestWithDefaults(t *testing.T) {
	t.Parallel()
	bare := Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "en", MaxTransferBytes: 5, StorageQuotaBytes: 9}
	d := bare.WithDefaults()
	if d == &bare || d.MaxTransferCeiling != 5 || d.Status != StatusActive ||
		d.PrimaryColor != DefaultPrimaryColor || d.AccentColor != DefaultAccentColor {
		t.Fatalf("WithDefaults() = %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
	if bare.Status != "" || bare.MaxTransferCeiling != 0 {
		t.Fatal("WithDefaults modified its receiver")
	}
	set := validTenant()
	set.MaxTransferBytes, set.MaxTransferCeiling = 1, 2
	set.Status, set.PrimaryColor, set.AccentColor = StatusDeleting, "#010203", "#040506"
	if got := set.WithDefaults(); *got != set {
		t.Fatalf("WithDefaults changed set fields: %+v", got)
	}
}

func TestAntivirusEffective(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		enabled, instanceDisabled, want bool
	}{
		{true, false, true},
		{true, true, false},
		{false, false, false},
		{false, true, false},
	} {
		tn := Tenant{AntivirusEnabled: c.enabled}
		if got := tn.AntivirusEffective(c.instanceDisabled); got != c.want {
			t.Errorf("AntivirusEffective(enabled %v, instance disabled %v) = %v", c.enabled, c.instanceDisabled, got)
		}
	}
}
