package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestSSOVariables(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, nil)
	if c.SSOUseProxy || c.SSOAllowNetworks != nil {
		t.Errorf("defaults: %v %v", c.SSOUseProxy, c.SSOAllowNetworks)
	}
	c = mustLoad(t, map[string]string{EnvSSOUseProxy: "true", EnvSSOAllowNetworks: "10.20.30.0/28, 192.0.2.7"})
	want := []netip.Prefix{netip.MustParsePrefix("10.20.30.0/28"), netip.MustParsePrefix("192.0.2.7/32")}
	if !c.SSOUseProxy || !slices.Equal(c.SSOAllowNetworks, want) {
		t.Errorf("set: %v %v", c.SSOUseProxy, c.SSOAllowNetworks)
	}
	for name, vars := range map[string]map[string]string{
		"proxy":     {EnvSSOUseProxy: "maybe"},
		"malformed": {EnvSSOAllowNetworks: "nowhere"},
		"metadata":  {EnvSSOAllowNetworks: "169.254.169.254"},
	} {
		verr := mustFail(t, vars)
		for v := range vars {
			if !verr.Has(v) {
				t.Errorf("%s: problems = %v", name, verr.Problems)
			}
		}
	}
	if verr := mustFail(t, map[string]string{EnvSSOAllowNetworks: "0.0.0.0/0"}); !strings.Contains(verr.Error(), "never be opened") {
		t.Errorf("core: %v", verr)
	}
}
