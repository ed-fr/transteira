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
		ID:                validID,
		Name:              "Entity A",
		FQDN:              "transfer.entity-a.example.com",
		DefaultLanguage:   "fr",
		MaxTransferBytes:  MaxTransferLimit,
		StorageQuotaBytes: 1 << 40,
		CreatedAt:         now,
		UpdatedAt:         now,
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
