package deposit

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

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

// snapshot returns the recorded events and the write errors.
func (a *auditSpy) snapshot() ([]audit.Event, []tenant.ID, []error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...), append([]tenant.ID(nil), a.tids...), append([]error(nil), a.errs...)
}

// withAudit plugs spy into the service of ev and returns the buffer of its
// application log.
func (ev *env) withAudit(spy *auditSpy) *syncBuffer {
	ev.svc.audit = spy
	buf := &syncBuffer{}
	ev.svc.logger = slog.New(slog.NewTextHandler(buf, nil))
	return buf
}

// wantEvent checks one recorded event.
func wantEvent(t *testing.T, got audit.Event, action audit.Action, actor, objectKind, objectID string, details map[string]any) {
	t.Helper()
	if got.Action != action || got.ActorKind != store.ActorDepositor || got.Actor != actor ||
		got.ObjectKind != objectKind || got.ObjectID != objectID || len(got.Details) != len(details) {
		t.Errorf("event = %+v, want %s by %s on %s/%s", got, action, actor, objectKind, objectID)
	}
	for k, v := range details {
		if got.Details[k] != v {
			t.Errorf("%s details[%s] = %v, want %v", action, k, got.Details[k], v)
		}
	}
	if got.TenantID != "" {
		t.Errorf("%s: TenantID = %q, want it left to RecordScoped", action, got.TenantID)
	}
}

func TestAuditEvents(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		logs := ev.withAudit(spy)

		// Internal verification, then a recognized session (no event).
		internal := ev.mustSession(t, ev.a, internalIP, alice, "")
		ev.mustSession(t, ev.a, internalIP, alice, "")
		inv, token := ev.mustInvite(t, bob)

		// The invited person verifies twice: the invitation is used once.
		ev.clock.Advance(time.Minute)
		ext := ev.mustSession(t, ev.a, externalIP, bob, token)
		ev.clock.Advance(time.Minute)
		ext2 := ev.mustSession(t, ev.a, externalIP, bob, token)

		events, tids, errs := spy.snapshot()
		if len(errs) != 0 {
			t.Fatalf("audit write errors: %v", errs)
		}
		if len(events) != 5 {
			t.Fatalf("got %d events: %+v", len(events), events)
		}
		for i, tid := range tids {
			if tid != ev.a.ID {
				t.Errorf("event %d in tenant %s", i, tid)
			}
		}
		wantEvent(t, events[0], audit.ActionAddressVerified, aliceNorm, audit.ObjectDepositSession, internal.ID,
			map[string]any{"origin": "internal"})
		if events[0].IP != internalIP {
			t.Errorf("IP = %v", events[0].IP)
		}
		// mustInvite opens a session of alice again (recognized: no event).
		wantEvent(t, events[1], audit.ActionInvitationCreated, aliceNorm, audit.ObjectInvitation, inv.ID,
			map[string]any{"language": "en"})
		wantEvent(t, events[2], audit.ActionAddressVerified, bob, audit.ObjectDepositSession, ext.ID,
			map[string]any{"origin": "invitation"})
		wantEvent(t, events[3], audit.ActionInvitationUsed, bob, audit.ObjectInvitation, inv.ID,
			map[string]any{"sessionId": ext.ID})
		if events[3].IP != externalIP {
			t.Errorf("IP = %v", events[3].IP)
		}
		wantEvent(t, events[4], audit.ActionAddressVerified, bob, audit.ObjectDepositSession, ext2.ID,
			map[string]any{"origin": "invitation"})

		// The events are stored, in the tenant, with the address in the
		// actor column only.
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{TenantID: ev.a.ID, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != len(events) {
			t.Errorf("stored %d events, want %d", len(page.Items), len(events))
		}
		for _, row := range page.Items {
			if strings.Contains(string(row.Details), "@") {
				t.Errorf("details of %s hold an address: %s", row.Action, row.Details)
			}
		}
		if logs.String() != "" {
			t.Errorf("unexpected log: %s", logs.String())
		}
	})
}

func TestAuditFailureDoesNotFail(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		spy := &auditSpy{err: errors.New("audit down")}
		logs := ev.withAudit(spy)
		_, token := ev.mustInvite(t, bob)
		ev.mustSession(t, ev.a, externalIP, bob, token)
		events, _, _ := spy.snapshot()
		if len(events) != 4 {
			t.Errorf("got %d events", len(events))
		}
		if n := strings.Count(logs.String(), "audit write failed"); n != 4 {
			t.Errorf("logged %d failures: %s", n, logs.String())
		}
		if strings.Contains(logs.String(), "@") {
			t.Errorf("the log holds an address: %s", logs.String())
		}
	})
}

func TestAuditNilRecorder(_ *testing.T) {
	var s Service
	// No recorder: nothing happens, nothing panics.
	s.record(context.Background(), &tenant.Tenant{}, internalIP, aliceNorm, audit.ActionAddressVerified, "", "", nil)
}
