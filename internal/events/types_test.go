package events

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTypeLists(t *testing.T) {
	t.Parallel()
	for _, typ := range TenantTypes() {
		if !IsTenant(typ) || IsSystem(typ) || !IsSubscribable(typ) {
			t.Errorf("%s: tenant=%v system=%v subscribable=%v", typ, IsTenant(typ), IsSystem(typ), IsSubscribable(typ))
		}
	}
	for _, typ := range SystemTypes() {
		if IsTenant(typ) || !IsSystem(typ) || !IsSubscribable(typ) {
			t.Errorf("%s: tenant=%v system=%v subscribable=%v", typ, IsTenant(typ), IsSystem(typ), IsSubscribable(typ))
		}
	}
	for _, typ := range []Type{WebhookTest, LogAudit, LogSecurity, "unknown.type", ""} {
		if IsTenant(typ) || IsSystem(typ) || IsSubscribable(typ) {
			t.Errorf("%s must not be subscribable", typ)
		}
	}
	// Callers may modify the returned slices without affecting later calls.
	TenantTypes()[0], SystemTypes()[0] = "x", "x"
	if TenantTypes()[0] != VirusDetected || SystemTypes()[0] != DiskAlertRaised {
		t.Error("the type lists are shared between calls")
	}
}

// TestTypeListsMatchSpec checks that the tenant and system types are
// exactly the WebhookEventType enumeration of api/openapi.yaml, minus
// webhook.test.
func TestTypeListsMatchSpec(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Enum []string `yaml:"enum"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var spec []string
	for _, v := range doc.Components.Schemas["WebhookEventType"].Enum {
		if Type(v) != WebhookTest {
			spec = append(spec, v)
		}
	}
	if !slices.Contains(doc.Components.Schemas["WebhookEventType"].Enum, string(WebhookTest)) {
		t.Errorf("WebhookEventType lacks %s", WebhookTest)
	}
	var code []string
	for _, typ := range append(TenantTypes(), SystemTypes()...) {
		code = append(code, string(typ))
	}
	slices.Sort(spec)
	slices.Sort(code)
	if len(spec) == 0 || !slices.Equal(spec, code) {
		t.Errorf("tenant and system types = %v, want the WebhookEventType enumeration %v", code, spec)
	}
}
