package httpserver

import (
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestSecurityEventsTenantID checks which events of the middlewares are
// filed under the tenant of the request (threat model T-283): those that
// name the FQDN of that tenant; never an unknown FQDN, the monitoring or
// the provisioning events, nor an event naming another FQDN than the
// tenant of the context.
func TestSecurityEventsTenantID(t *testing.T) {
	t.Parallel()
	tn := &tenant.Tenant{ID: "ten_01JAB00000000000000ENT1TYA", FQDN: "transfer.entity-a.example.com"}
	ip := netip.MustParseAddr("192.0.2.1")
	withTenant := tenant.WithTenant(context.Background(), tn)
	for name, tc := range map[string]struct {
		emit func(*SecurityEvents)
		want string
	}{
		"rate limited": {func(s *SecurityEvents) { s.RateLimited(withTenant, ip, tn.FQDN, ScopeGlobal) }, string(tn.ID)},
		"api token":    {func(s *SecurityEvents) { s.APITokenInvalid(withTenant, ip, tn.FQDN) }, string(tn.ID)},
		"deposit":      {func(s *SecurityEvents) { s.DepositRefused(withTenant, ip, tn.FQDN, securitylog.ReasonIP) }, string(tn.ID)},
		"unknown fqdn": {func(s *SecurityEvents) { s.UnknownFQDN(withTenant, ip, "evil.example.net") }, ""},
		"metrics":      {func(s *SecurityEvents) { s.MetricsTokenInvalid(withTenant, ip) }, ""},
		"provisioning": {func(s *SecurityEvents) { s.ProvisioningTokenInvalid(withTenant, ip) }, ""},
		"no tenant":    {func(s *SecurityEvents) { s.RateLimited(context.Background(), ip, tn.FQDN, ScopeGlobal) }, ""},
		"other fqdn":   {func(s *SecurityEvents) { s.RateLimited(withTenant, ip, "transfer.entity-b.example.com", ScopeGlobal) }, ""},
		"global scope": {func(s *SecurityEvents) { s.RateLimited(withTenant, ip, "", ScopeGlobal) }, ""},
	} {
		rec := &events.Recorder{}
		tc.emit(NewSecurityEvents(securitylog.New(io.Discard, securitylog.WithPublisher(rec)), nil))
		got := rec.Events()
		if len(got) != 1 || got[0].Log.TenantID != tc.want {
			t.Errorf("%s: published %+v", name, got)
		}
	}
}
