package config

import (
	"strings"
	"testing"
)

func TestMetricsConfig(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, nil)
	if c.MetricsToken.IsSet() || len(c.MetricsAllowedIPs) != 0 {
		t.Errorf("defaults: token set %v, allowed %v", c.MetricsToken.IsSet(), c.MetricsAllowedIPs)
	}

	token := strings.Repeat("m", minMetricsTokenLength)
	c = mustLoad(t, map[string]string{
		EnvMetricsToken:      " " + token + " ",
		EnvMetricsAllowedIPs: "192.0.2.0/24, 2001:db8::1",
	})
	if c.MetricsToken.Reveal() != token {
		t.Error("the token is not trimmed")
	}
	if len(c.MetricsAllowedIPs) != 2 {
		t.Errorf("allowed = %v", c.MetricsAllowedIPs)
	}

	c = mustLoad(t, map[string]string{EnvMetricsTokenFile: "/run/secrets/metrics"},
		WithReadFile(func(string) ([]byte, error) { return []byte(token + "\n"), nil }))
	if c.MetricsToken.Reveal() != token {
		t.Error("the token file is not read")
	}

	for _, tc := range []struct {
		name string
		vars map[string]string
		want string
	}{
		{"short", map[string]string{EnvMetricsToken: token[1:]}, EnvMetricsToken},
		{"long", map[string]string{EnvMetricsToken: strings.Repeat("m", maxMetricsTokenLength+1)}, EnvMetricsToken},
		{"both", map[string]string{EnvMetricsToken: token, EnvMetricsTokenFile: "/x"}, EnvMetricsToken},
		{"bad list", map[string]string{EnvMetricsAllowedIPs: "nowhere"}, EnvMetricsAllowedIPs},
	} {
		verr := mustFail(t, tc.vars)
		if !verr.Has(tc.want) {
			t.Errorf("%s: problems = %v, want one on %s", tc.name, verr.Problems, tc.want)
		}
		for _, p := range verr.Problems {
			if strings.Contains(p.Reason, "mmmm") {
				t.Errorf("%s: a problem reveals the token: %s", tc.name, p.Reason)
			}
		}
	}
	if verr := mustFail(t, map[string]string{EnvMetricsTokenFile: "/run/secrets/metrics"},
		WithReadFile(func(string) ([]byte, error) { return []byte("short"), nil })); !verr.Has(EnvMetricsTokenFile) {
		t.Errorf("short file: problems = %v", verr.Problems)
	}
}
