// Package integrations_test checks that the monitoring integrations shipped in
// this folder (Grafana dashboard, Zabbix template) parse and only reference
// metrics that TransTeira really exposes.
package integrations_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
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

// TestSSOFail2banFilter checks the failregex of the single sign-on filter on
// the exact line TransTeira writes, and that it ignores other events and
// lines without a client address.
func TestSSOFail2banFilter(t *testing.T) {
	content := string(readFile(t, "fail2ban/filter.d/transteira-sso.conf"))
	m := regexp.MustCompile(`(?m)^failregex\s*=\s*(.+)$`).FindStringSubmatch(content)
	if m == nil {
		t.Fatal("no failregex")
	}
	addr := `(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)`
	re := regexp.MustCompile(strings.ReplaceAll(m[1], "<ADDR>", addr))
	// fail2ban removes the matched date before applying failregex.
	const prefix = "2026-11-05T08:12:00.123Z"
	cases := map[string]string{
		` ip=203.0.113.7 tenant=- event=sso_failed reason="state_invalid"`:                           "203.0.113.7",
		` ip=2001:db8::1 tenant=transfer.entity-a.example.com event=sso_failed reason="mfa_missing"`: "2001:db8::1",
		` ip=203.0.113.7 tenant=- event=admin_login_failed reason="password"`:                        "",
		` ip=- tenant=- event=sso_failed reason="issuer_error"`:                                      "",
		` ip=203.0.113.7 tenant=- event=sso_failed_other`:                                            "",
		` ip=- tenant=- event=sso_failed x=" ip=198.51.100.9 tenant=- event=sso_failed"`:             "",
	}
	for line, want := range cases {
		got := ""
		if sub := re.FindStringSubmatch(line); sub != nil {
			got = sub[re.SubexpIndex("ip")]
		}
		if got != want {
			t.Errorf("%s%s: matched %q, want %q", prefix, line, got, want)
		}
	}
}

// TestSSOCrowdsecScenario checks that the single sign-on scenario parses, only
// counts sso_failed, and has a higher capacity than the brute force scenario.
func TestSSOCrowdsecScenario(t *testing.T) {
	type scenario struct {
		Name     string `yaml:"name"`
		Filter   string `yaml:"filter"`
		Capacity int    `yaml:"capacity"`
	}
	load := func(path string) scenario {
		var sc scenario
		if err := yaml.Unmarshal(readFile(t, path), &sc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return sc
	}
	sso := load("crowdsec/scenarios/transteira-sso-bf.yaml")
	bf := load("crowdsec/scenarios/transteira-bf.yaml")
	if !strings.Contains(sso.Filter, "'sso_failed'") || strings.Count(sso.Filter, "transteira_event") != 1 {
		t.Errorf("filter %q must select sso_failed only", sso.Filter)
	}
	if strings.Contains(bf.Filter, "sso_failed") {
		t.Error("the brute force scenario must not count sso_failed")
	}
	if sso.Capacity <= bf.Capacity {
		t.Errorf("sso capacity %d must exceed the brute force capacity %d", sso.Capacity, bf.Capacity)
	}
}

// tokenPaths are the path prefixes whose next segment is a capability token
// (threat model T-161): the access log of every reverse proxy configuration
// must mask it (Caddy, Nginx, Apache) or leave the request out (Traefik).
var tokenPaths = []string{
	"d", "i", "s", "drop",
	"api/v1/downloads", "api/v1/invitations", "api/v1/drop-links", "api/v1/secret-links",
}

// TestProxyTokenRedaction checks that every reverse proxy configuration
// covers every token path, one-time secret links included.
func TestProxyTokenRedaction(t *testing.T) {
	t.Parallel()
	const dir = "reverse-proxy/"
	cases := []struct {
		file   string
		marker string // selects the line(s) that carry the redaction rule
		form   func(path string) string
	}{
		{dir + "caddy/Caddyfile", `request>uri regexp`, func(p string) string { return "|" + p + "|" }},
		{dir + "caddy/Caddyfile.on-demand", `request>uri regexp`, func(p string) string { return "|" + p + "|" }},
		{dir + "nginx/transteira.conf", `tt_prefix>`, func(p string) string { return "|" + p + "|" }},
		{dir + "apache/transteira.conf", `TT_TOKEN_PREFIX=`, func(p string) string { return "|/" + p + "/" }},
		{dir + "traefik/dynamic/transteira.yml", "rule:", func(p string) string { return "PathPrefix(`/" + p + "/`)" }},
		{dir + "traefik/docker-compose.labels.yml", "transteira-tokens.rule", func(p string) string { return "PathPrefix(`/" + p + "/`)" }},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			t.Parallel()
			var lines []string
			for _, line := range strings.Split(string(readFile(t, c.file)), "\n") {
				if strings.Contains(line, c.marker) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					lines = append(lines, line)
				}
			}
			// The Traefik file holds the rule of several routers: only the
			// one that mentions a token path is the token router.
			traefik := strings.HasPrefix(c.file, dir+"traefik")
			if traefik {
				var tokens []string
				for _, l := range lines {
					if strings.Contains(l, "PathPrefix(`/d/`)") {
						tokens = append(tokens, l)
					}
				}
				lines = tokens
			}
			if len(lines) == 0 {
				t.Fatalf("no redaction rule found (marker %q)", c.marker)
			}
			for _, line := range lines {
				// Wrap the first alternation so that the first and last
				// names also match the |name| form.
				probe := strings.NewReplacer("(?:", "|", "(", "|", ")", "|").Replace(line)
				for _, p := range tokenPaths {
					if traefik && p == "api/v1/downloads" {
						continue // its own router, transteira-downloads
					}
					if !strings.Contains(probe, c.form(p)) && !strings.Contains(line, c.form(p)) {
						t.Errorf("token path %q is not covered by: %s", p, strings.TrimSpace(line))
					}
				}
			}
		})
	}
}
