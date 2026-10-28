// Package integrations_test checks that the monitoring integrations shipped in
// this folder (Grafana dashboard, Zabbix template) parse and only reference
// metrics that TransTeira really exposes.
package integrations_test

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/internal/metrics"
)

var (
	metricToken = regexp.MustCompile(`transteira_[a-z0-9_]+`)
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// catalog returns the set of metric names exposed by TransTeira.
func catalog(t *testing.T) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, m := range metrics.Catalog() {
		set[m.Name] = true
	}
	if len(set) == 0 {
		t.Fatal("metrics.Catalog() is empty")
	}
	return set
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkMetrics(t *testing.T, content []byte) {
	t.Helper()
	known := catalog(t)
	found := metricToken.FindAllString(string(content), -1)
	if len(found) == 0 {
		t.Fatal("no transteira_ metric referenced")
	}
	for _, name := range found {
		if !known[name] {
			t.Errorf("metric %q is not in metrics.Catalog()", name)
		}
	}
}

func TestGrafanaDashboard(t *testing.T) {
	raw := readFile(t, "grafana/transteira-dashboard.json")
	var d struct {
		Inputs []struct {
			Name     string `json:"name"`
			PluginID string `json:"pluginId"`
		} `json:"__inputs"`
		SchemaVersion int `json:"schemaVersion"`
		Panels        []struct {
			ID   int    `json:"id"`
			Type string `json:"type"`
		} `json:"panels"`
		Templating struct {
			List []struct {
				Name string `json:"name"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	if len(d.Inputs) != 1 || d.Inputs[0].PluginID != "prometheus" {
		t.Errorf("expected one Prometheus datasource input, got %+v", d.Inputs)
	}
	if d.SchemaVersion < 36 {
		t.Errorf("schemaVersion = %d", d.SchemaVersion)
	}
	vars := map[string]bool{}
	for _, v := range d.Templating.List {
		vars[v.Name] = true
	}
	if !vars["datasource"] || !vars["tenant"] {
		t.Errorf("templating variables = %v, want datasource and tenant", vars)
	}
	ids := map[int]bool{}
	for _, p := range d.Panels {
		if ids[p.ID] {
			t.Errorf("duplicate panel id %d", p.ID)
		}
		ids[p.ID] = true
	}
	if len(d.Panels) < 10 {
		t.Errorf("only %d panels", len(d.Panels))
	}
	checkMetrics(t, raw)
}

// collectUUIDs walks a decoded YAML tree and returns every "uuid" value.
func collectUUIDs(n any, out *[]string) {
	switch v := n.(type) {
	case map[string]any:
		for k, c := range v {
			if s, ok := c.(string); ok && k == "uuid" {
				*out = append(*out, s)
				continue
			}
			collectUUIDs(c, out)
		}
	case []any:
		for _, c := range v {
			collectUUIDs(c, out)
		}
	}
}

func TestZabbixTemplate(t *testing.T) {
	raw := readFile(t, "zabbix/transteira-template.yaml")
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("template is not valid YAML: %v", err)
	}
	export, ok := doc["zabbix_export"].(map[string]any)
	if !ok {
		t.Fatal("zabbix_export is missing")
	}
	if export["version"] != "7.0" {
		t.Errorf("version = %v, want 7.0", export["version"])
	}
	var uuids []string
	collectUUIDs(export, &uuids)
	if len(uuids) < 20 {
		t.Errorf("only %d uuids found", len(uuids))
	}
	seen := map[string]bool{}
	for _, id := range uuids {
		if !uuidRe.MatchString(id) {
			t.Errorf("uuid %q is not 32 lowercase hex characters", id)
		}
		// Zabbix requires UUID version 4: the 13th character is 4.
		if len(id) == 32 && id[12] != '4' {
			t.Errorf("uuid %q is not a version 4 UUID", id)
		}
		if seen[id] {
			t.Errorf("duplicate uuid %q", id)
		}
		seen[id] = true
	}
	checkMetrics(t, raw)
}
