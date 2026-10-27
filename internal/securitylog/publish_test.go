package securitylog

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
)

func TestLogPublishesTheLine(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 20, 7, 41, 0, 123e6, time.UTC)
	var buf bytes.Buffer
	rec := &events.Recorder{}
	l := New(&buf, WithClock(func() time.Time { return at }), WithPublisher(rec))
	ip := netip.MustParseAddr("203.0.113.7")
	err := l.Log(Event{
		Type: UnknownFQDN, IP: ip, Tenant: "transfer.entity-a.example.com",
		Fields: []Field{{Key: KeyHost, Value: "evil.example.net\n" + strings.Repeat("x", MaxValueLen)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Type: RateLimited, Tenant: "Bad Tenant"}); err != nil {
		t.Fatal(err)
	}
	got := rec.Events()
	if len(got) != 2 {
		t.Fatalf("published %d events, want 2", len(got))
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	first := got[0]
	lr := first.Log
	if first.Type != events.LogSecurity || first.Severity != events.SeverityInfo || !first.OccurredAt.Equal(at) ||
		first.TenantID != "" || lr.Stream != events.StreamSecurity || !lr.Time.Equal(at) ||
		lr.Tenant != "transfer.entity-a.example.com" || lr.Action != "unknown_fqdn" || lr.IP != ip ||
		lr.Line != lines[0] || len(lr.Fields) != 1 || lr.Fields[0].Key != KeyHost ||
		len(lr.Fields[0].Value) != MaxValueLen || !strings.HasPrefix(lr.Fields[0].Value, "evil.example.net\n") {
		t.Fatalf("published %+v, log %+v", first, lr)
	}
	if second := got[1].Log; second.Tenant != "" || second.Line != lines[1] || len(second.Fields) != 0 || second.IP.IsValid() {
		t.Fatalf("second published log = %+v", second)
	}
}

func TestLogPublishesNothingOnFailure(t *testing.T) {
	t.Parallel()
	rec := &events.Recorder{}
	l := New(failWriter{}, WithPublisher(rec))
	if err := l.Log(Event{Type: RateLimited}); err == nil {
		t.Fatal("Log on a failing writer = nil")
	}
	if err := l.Log(Event{Type: "Bad Type"}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("Log(bad type) = %v", err)
	}
	if n := len(rec.Events()); n != 0 {
		t.Fatalf("published %d events for lines never written", n)
	}
	// A nil publisher publishes nothing and still writes.
	var buf bytes.Buffer
	if err := New(&buf, WithPublisher(nil)).Log(Event{Type: RateLimited}); err != nil || buf.Len() == 0 {
		t.Fatalf("Log with a nil publisher = %v", err)
	}
}
