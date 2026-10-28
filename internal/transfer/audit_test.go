package transfer

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// syncBuffer is a goroutine-safe log buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// auditSpy records the audit events of the service and writes them with the
// real writer when set, so that its checks (personal-data guard included)
// apply; err makes every call fail instead.
type auditSpy struct {
	mu     sync.Mutex
	writer *audit.Writer
	err    error
	events []audit.Event
	tids   []tenant.ID
	errs   []error
}

func (a *auditSpy) RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events, a.tids = append(a.events, ev), append(a.tids, tid)
	if a.err != nil {
		return a.err
	}
	if a.writer == nil {
		return nil
	}
	err := a.writer.RecordScoped(ctx, tid, ev)
	if err != nil {
		a.errs = append(a.errs, err)
	}
	return err
}

func (a *auditSpy) snapshot() ([]audit.Event, []tenant.ID, []error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...), append([]tenant.ID(nil), a.tids...), append([]error(nil), a.errs...)
}

// usageCall is one call of the usage hook.
type usageCall struct {
	tid   tenant.ID
	bytes int64
	at    time.Time
}

// usageSpy records the usage hook calls.
type usageSpy struct {
	mu    sync.Mutex
	calls []usageCall
}

func (u *usageSpy) TransferFinalized(tid tenant.ID, totalBytes int64, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, usageCall{tid, totalBytes, at})
}

// quotaCall is one call of the quota hook.
type quotaCall struct {
	tid     tenant.ID
	refused bool
}

// hooks plugs the spies into the service of ev.
type hooks struct {
	audit *auditSpy
	usage *usageSpy
	logs  *syncBuffer
	mu    sync.Mutex
	quota []quotaCall
}

func (h *hooks) quotaCalls() []quotaCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]quotaCall(nil), h.quota...)
}

func (ev *env) withHooks(spy *auditSpy) *hooks {
	h := &hooks{audit: spy, usage: &usageSpy{}, logs: &syncBuffer{}}
	ev.svc.audit, ev.svc.usage = spy, h.usage
	ev.svc.logger = slog.New(slog.NewTextHandler(h.logs, nil))
	ev.svc.onQuota = func(tid tenant.ID, refused bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.quota = append(h.quota, quotaCall{tid, refused})
	}
	return h
}

// wantEvent checks one recorded event.
func wantEvent(t *testing.T, got audit.Event, action audit.Action, actor string, ip netip.Addr, trfID string, details map[string]any) {
	t.Helper()
	if got.Action != action || got.ActorKind != store.ActorDepositor || got.Actor != actor || got.IP != ip ||
		got.ObjectKind != audit.ObjectTransfer || got.ObjectID != trfID || got.TenantID != "" ||
		len(got.Details) != len(details) {
		t.Errorf("event = %+v, want %s by %s on %s", got, action, actor, trfID)
	}
	for k, v := range details {
		if got.Details[k] != v {
			t.Errorf("%s details[%s] = %#v, want %#v", action, k, got.Details[k], v)
		}
	}
}

func TestAuditEvents(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})

		// Internal: created, finalized.
		sender := internalSender()
		d := ev.mustCreate(t, sender, request())
		ev.complete(t, d.ID, "")
		ev.clock.Advance(time.Minute)
		if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		// External from an IPv4-mapped address: created, canceled.
		ext := ev.external()
		ext.ClientIP = netip.MustParseAddr("::ffff:203.0.113.7")
		x := ev.mustCreate(t, ext, request())
		if err := ev.svc.Cancel(ctx, ev.a, ext, x.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}

		events, tids, errs := h.audit.snapshot()
		if len(errs) != 0 {
			t.Fatalf("audit write errors: %v", errs)
		}
		if len(events) != 4 {
			t.Fatalf("got %d events: %+v", len(events), events)
		}
		for i, tid := range tids {
			if tid != ev.a.ID {
				t.Errorf("event %d in tenant %s", i, tid)
			}
		}
		wantEvent(t, events[0], audit.ActionTransferCreated, alice, internalIP, d.ID,
			map[string]any{"fileCount": 2, "totalBytes": int64(300), "origin": "internal", "confidentialityLevel": "internal"})
		wantEvent(t, events[1], audit.ActionTransferFinalized, alice, internalIP, d.ID,
			map[string]any{"fileCount": 2, "totalBytes": int64(300)})
		wantEvent(t, events[2], audit.ActionTransferCreated, bob, ext.ClientIP, x.ID,
			map[string]any{"fileCount": 2, "totalBytes": int64(300), "origin": "invitation", "confidentialityLevel": "internal"})
		wantEvent(t, events[3], audit.ActionTransferDeleted, bob, ext.ClientIP, x.ID,
			map[string]any{"by": "sender"})

		// Stored in the tenant, never an address in the details.
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{TenantID: ev.a.ID, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 4 {
			t.Errorf("stored %d events", len(page.Items))
		}
		for _, row := range page.Items {
			if strings.Contains(string(row.Details), "@") {
				t.Errorf("details of %s hold an address: %s", row.Action, row.Details)
			}
		}

		// The usage hook counts the finalization at its time.
		if len(h.usage.calls) != 1 || h.usage.calls[0] != (usageCall{ev.a.ID, 300, testStart.Add(time.Minute)}) {
			t.Errorf("usage calls = %+v", h.usage.calls)
		}
		// The quota hook follows every committed creation.
		want := []quotaCall{{ev.a.ID, false}, {ev.a.ID, false}}
		if got := h.quotaCalls(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("quota calls = %+v", got)
		}

		// The sender IP is stored at creation (IPv4-mapped as IPv4).
		got, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || got.SenderIP != internalIP {
			t.Errorf("SenderIP = %v, %v", got.SenderIP, err)
		}
		if h.logs.String() != "" {
			t.Errorf("unexpected log: %s", h.logs.String())
		}
	})
}

func TestAuditSenderIPMapped(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ext := ev.external()
		ext.ClientIP = netip.MustParseAddr("::ffff:203.0.113.7")
		x := ev.mustCreate(t, ext, request())
		got, err := ev.db.Transfers().Get(context.Background(), ev.a.ID, x.ID)
		if err != nil || got.SenderIP != externalIP {
			t.Errorf("SenderIP = %v, %v; want %v", got.SenderIP, err, externalIP)
		}
	})
}

func TestAuditQuotaRefused(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		ev.setQuota(t, ev.a, 299)
		_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), request(), "")
		if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("Create = %v, want ErrQuotaExceeded", err)
		}
		if got := h.quotaCalls(); len(got) != 1 || got[0] != (quotaCall{ev.a.ID, true}) {
			t.Errorf("quota calls = %+v", got)
		}
		if events, _, _ := h.audit.snapshot(); len(events) != 0 {
			t.Errorf("events = %+v", events)
		}
	})
}

func TestAuditReplayRecordsNothing(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHooks(&auditSpy{})
		for range 2 {
			if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), request(), "key-1"); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
		if events, _, _ := h.audit.snapshot(); len(events) != 1 {
			t.Errorf("got %d events, want 1", len(events))
		}
		if got := h.quotaCalls(); len(got) != 1 {
			t.Errorf("quota calls = %+v", got)
		}
	})
}

func TestAuditFailureDoesNotFail(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		h := ev.withHooks(&auditSpy{err: errors.New("audit down")})
		sender := internalSender()
		d := ev.mustCreate(t, sender, request())
		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		x := ev.mustCreate(t, sender, request())
		if err := ev.svc.Cancel(ctx, ev.a, sender, x.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		if n := strings.Count(h.logs.String(), "audit write failed"); n != 4 {
			t.Errorf("logged %d failures: %s", n, h.logs.String())
		}
		if strings.Contains(h.logs.String(), "@") {
			t.Errorf("the log holds an address: %s", h.logs.String())
		}
	})
}

func TestAuditNilRecorder(_ *testing.T) {
	var s Service
	// No recorder: nothing happens, nothing panics.
	s.record(context.Background(), &tenant.Tenant{}, internalSender(), alice, audit.ActionTransferCreated, "", nil)
}
