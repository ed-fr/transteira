package transfer

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestLogEventCarriesTenantID checks that the security events of this
// emitter are filed under their tenant for the copy of the security log in
// the database (threat model T-283), and that the line carries no address
// (T-285).
func TestLogEventCarriesTenantID(t *testing.T) {
	t.Parallel()
	rec := &events.Recorder{}
	s := &Service{seclog: securitylog.New(io.Discard, securitylog.WithPublisher(rec)), logger: slog.New(slog.DiscardHandler)}
	tn := &tenant.Tenant{ID: "ten_01JAB00000000000000ENT1TYA", FQDN: "transfer.entity-a.example.com"}
	ip := netip.MustParseAddr("192.0.2.1")
	s.logEvent(context.Background(), tn, ip, securitylog.DepositRefused, securitylog.Field{Key: securitylog.KeyReason, Value: securitylog.ReasonIP})
	got := rec.Events()
	if len(got) != 1 || got[0].Log == nil {
		t.Fatalf("published %+v", got)
	}
	lr := got[0].Log
	if lr.TenantID != string(tn.ID) || lr.Tenant != tn.FQDN || lr.Action != "deposit_refused" || lr.IP != ip {
		t.Fatalf("published record %+v", lr)
	}
	for _, f := range lr.Fields {
		for _, c := range f.Value {
			if c == '@' {
				t.Fatalf("field %s holds an address: %q", f.Key, f.Value)
			}
		}
	}
}
