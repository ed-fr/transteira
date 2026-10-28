package config

import (
	"strings"
	"testing"
)

func TestWebhookNetworksCore(t *testing.T) {
	t.Parallel()
	// Loopback stays openable, for the tests with local receivers.
	c := mustLoad(t, map[string]string{
		EnvWebhookAllowNetworks:     "127.0.0.0/8",
		EnvWebhookAllowHTTPNetworks: "127.0.0.0/8",
	})
	if len(c.WebhookAllowNetworks) != 1 || len(c.WebhookAllowHTTPNetworks) != 1 {
		t.Errorf("loopback: %v %v", c.WebhookAllowNetworks, c.WebhookAllowHTTPNetworks)
	}
	for _, tc := range []struct {
		name string
		vars map[string]string
		want string
		text string
	}{
		{"metadata", map[string]string{EnvWebhookAllowNetworks: "169.254.169.254"}, EnvWebhookAllowNetworks, "never be opened"},
		{"everything", map[string]string{EnvWebhookAllowNetworks: "0.0.0.0/0"}, EnvWebhookAllowNetworks, "never be opened"},
		{"http multicast", map[string]string{
			EnvWebhookAllowNetworks: "10.0.0.0/8", EnvWebhookAllowHTTPNetworks: "224.0.0.0/4",
		}, EnvWebhookAllowHTTPNetworks, "never be opened"},
		{
			"http not allowed",
			map[string]string{EnvWebhookAllowHTTPNetworks: "10.20.30.0/24"},
			EnvWebhookAllowHTTPNetworks, EnvWebhookAllowNetworks,
		},
	} {
		verr := mustFail(t, tc.vars)
		found := false
		for _, p := range verr.Problems {
			if p.Variable == tc.want && strings.Contains(p.Reason, tc.text) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: problems = %v, want one on %s mentioning %q", tc.name, verr.Problems, tc.want, tc.text)
		}
	}
	// A malformed list is reported alone, without the overlap checks.
	if verr := mustFail(t, map[string]string{
		EnvWebhookAllowNetworks: "nowhere", EnvWebhookAllowHTTPNetworks: "10.0.0.0/8",
	}); verr.Has(EnvWebhookAllowHTTPNetworks) {
		t.Errorf("problems = %v", verr.Problems)
	}
}
