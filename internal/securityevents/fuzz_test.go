package securityevents

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
)

// FuzzMapRecord feeds attacker-controlled field values (the host of an
// unknown FQDN, any reason) to the mapping: a row is always one the store
// accepts, with a token reason, bounded JSON details, never an "@" and a
// host only when well formed (T-285).
func FuzzMapRecord(f *testing.F) {
	for _, s := range [][3]string{
		{"rate_limited", "code", ""},
		{"unknown_fqdn", "", "evil.example.net"},
		{"admin_login_failed", "password", "a@b"},
		{"sso_failed", "Bad Reason", "\x00\"\\<>&"},
		{"x", strings.Repeat("a", 65), strings.Repeat("\x01", 256)},
		{"Bad", "", ""},
		{"deposit_refused", "ip", "\xff\xfe"},
		{"rate_limited", "", "@"},
		{"rate_limited", "", "\\u0040"},
		{"rate_limited", "", `a\U0040b`},
		{"unknown_fqdn", "", "Evil.Example.NET"},
		{"unknown_fqdn", "", "evil.example.net:8443"},
		{"unknown_fqdn", "", "drop table;--"},
		{"unknown_fqdn", "", strings.Repeat("a", 254)},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, typ, reason, value string) {
		ev, ok := mapRecord(events.LogRecord{
			Stream: events.StreamSecurity, Time: t0, Action: typ, TenantID: string(tenantA),
			Fields: []events.Field{{Key: "reason", Value: reason}, {Key: "host", Value: value}, {Key: "scope", Value: value}},
		})
		if !ok {
			if store.ValidSecurityEventType(typ) {
				t.Fatalf("valid type %q refused", typ)
			}
			return
		}
		if ev.Reason != "" && (ev.Reason != reason || !store.ValidSecurityEventType(ev.Reason)) {
			t.Fatalf("reason %q stored as %q", reason, ev.Reason)
		}
		if len(ev.Details) > store.MaxSecurityEventDetailsBytes || bytes.ContainsRune(ev.Details, '@') ||
			bytes.Contains(bytes.ToLower(ev.Details), []byte(`\u0040`)) {
			t.Fatalf("details %q", ev.Details)
		}
		if ev.Details != nil {
			var m map[string]string
			if err := json.Unmarshal(ev.Details, &m); err != nil || len(m) == 0 {
				t.Fatalf("details %q: %v", ev.Details, err)
			}
			if h, ok := m["host"]; ok && !validHost(h) {
				t.Fatalf("malformed host %q kept", h)
			}
		}
		if strings.ContainsAny(value, `@\`) && ev.Details != nil {
			t.Fatalf("value with an address kept: %q", ev.Details)
		}
	})
}
