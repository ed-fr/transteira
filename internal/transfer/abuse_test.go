package transfer

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeAbuse is an AbuseChecker recording its calls. check decides the
// block; nil never blocks.
type fakeAbuse struct {
	mu      sync.Mutex
	check   func(ctx context.Context, tx *store.ScopedTx, f AbuseFacts) (*AbuseBlock, error)
	checks  []AbuseFacts
	blocked []AbuseFacts
	blocks  []AbuseBlock
	created []AbuseFacts
	ctxErrs []error
}

func (a *fakeAbuse) CheckCreateTx(ctx context.Context, tx *store.ScopedTx, _ *tenant.Tenant, f AbuseFacts) (*AbuseBlock, error) {
	a.mu.Lock()
	a.checks = append(a.checks, f)
	check := a.check
	a.mu.Unlock()
	if tx == nil {
		return nil, errors.New("no transaction")
	}
	if check == nil {
		return nil, nil
	}
	return check(ctx, tx, f)
}

func (a *fakeAbuse) Blocked(ctx context.Context, _ *tenant.Tenant, f AbuseFacts, b AbuseBlock) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blocked, a.blocks, a.ctxErrs = append(a.blocked, f), append(a.blocks, b), append(a.ctxErrs, ctx.Err())
}

func (a *fakeAbuse) AfterCreate(ctx context.Context, _ *tenant.Tenant, f AbuseFacts) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.created, a.ctxErrs = append(a.created, f), append(a.ctxErrs, ctx.Err())
}

func (a *fakeAbuse) counts() (checks, blocked, created int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.checks), len(a.blocked), len(a.created)
}

// blockWith returns a check that always blocks on rule.
func blockWith(rule store.AbuseRule) func(context.Context, *store.ScopedTx, AbuseFacts) (*AbuseBlock, error) {
	return func(context.Context, *store.ScopedTx, AbuseFacts) (*AbuseBlock, error) {
		return &AbuseBlock{Rule: rule, Value: 3, Threshold: 2}, nil
	}
}

func TestAbuseAfterCreate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ab := &fakeAbuse{}
		ev.svc.abuse = ab
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		d, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "key-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		want := AbuseFacts{
			SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 300, Recipients: []string{dave},
			At: testStart, ClientIP: internalIP,
		}
		if len(ab.checks) != 1 || !reflect.DeepEqual(ab.checks[0], want) {
			t.Errorf("checks = %+v, want %+v", ab.checks, want)
		}
		want.TransferID = d.ID
		if len(ab.created) != 1 || !reflect.DeepEqual(ab.created[0], want) {
			t.Errorf("created = %+v, want %+v", ab.created, want)
		}
		// A replay is neither checked nor evaluated again.
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "key-1"); err != nil {
			t.Fatalf("replay: %v", err)
		}
		if c, b, a := ab.counts(); c != 1 || b != 0 || a != 1 {
			t.Errorf("calls after replay = %d checks, %d blocked, %d created", c, b, a)
		}
		// The recipient of an external sender is the inviter.
		x := ev.mustCreate(t, ev.external(), request())
		got := ab.created[1]
		if got.TransferID != x.ID || got.Kind != store.DepositorExternal || got.SenderEmail != bob ||
			!reflect.DeepEqual(got.Recipients, []string{alice}) || got.ClientIP != externalIP {
			t.Errorf("external facts = %+v", got)
		}
		// The best-effort calls do not inherit the cancellation of the request.
		cancel()
		for i, err := range ab.ctxErrs {
			if err != nil {
				t.Errorf("call %d got a canceled context", i)
			}
		}
	})
}

func TestAbuseBlocked(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHooks(&auditSpy{})
		ab := &fakeAbuse{check: blockWith(store.AbuseRuleDailyBytes)}
		ev.svc.abuse = ab
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		pw := "secret"
		req := request()
		req.Password = &pw

		for _, key := range []string{"", "key-1"} {
			_, err := ev.svc.Create(ctx, ev.a, internalSender(), req, key)
			var be *AbuseBlockedError
			if !errors.Is(err, ErrAbuseBlocked) || !errors.As(err, &be) || be.Rule != store.AbuseRuleDailyBytes {
				t.Fatalf("Create(%q) = %v, want ErrAbuseBlocked", key, err)
			}
			if be.Error() != "transfer: abuse threshold exceeded (daily_bytes)" {
				t.Errorf("message = %q", be.Error())
			}
		}
		// Nothing created, nothing reserved, nothing audited or logged here.
		if n := ev.transferCount(t, ev.a); n != 0 {
			t.Errorf("%d transfers created", n)
		}
		if n := ev.usedBytes(t, ev.a); n != 0 {
			t.Errorf("used bytes = %d", n)
		}
		if len(ev.seclog.events) != 0 {
			t.Errorf("security events = %+v", ev.seclog.events)
		}
		if events, _, _ := h.audit.snapshot(); len(events) != 0 {
			t.Errorf("audit events = %+v", events)
		}
		if got := h.quotaCalls(); len(got) != 0 {
			t.Errorf("quota calls = %+v", got)
		}
		// The detector records each refusal, with the facts and the block.
		want := AbuseFacts{
			SenderEmail: alice, Kind: store.DepositorInternal, Bytes: 300, Recipients: []string{dave},
			At: testStart, ClientIP: internalIP,
		}
		if c, b, a := ab.counts(); c != 2 || b != 2 || a != 0 {
			t.Errorf("calls = %d checks, %d blocked, %d created", c, b, a)
		}
		if !reflect.DeepEqual(ab.blocked[0], want) || ab.blocks[0] != (AbuseBlock{Rule: store.AbuseRuleDailyBytes, Value: 3, Threshold: 2}) {
			t.Errorf("blocked = %+v %+v", ab.blocked[0], ab.blocks[0])
		}
		cancel()
		for i, err := range ab.ctxErrs {
			if err != nil {
				t.Errorf("call %d got a canceled context", i)
			}
		}

		// The same key once allowed: created, then replayed even when the
		// rules block from then on.
		ab.check = nil
		d, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, "key-2")
		if err != nil {
			t.Fatal(err)
		}
		ab.check = blockWith(store.AbuseRuleDailyTransfers)
		r, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, "key-2")
		if err != nil || r.ID != d.ID {
			t.Errorf("replay = %s, %v; want %s", r.ID, err, d.ID)
		}
	})
}

func TestAbuseCheckFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ab := &fakeAbuse{check: func(context.Context, *store.ScopedTx, AbuseFacts) (*AbuseBlock, error) {
			return nil, errFault
		}}
		ev.svc.abuse = ab
		_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), request(), "")
		if !errors.Is(err, errFault) || errors.Is(err, ErrAbuseBlocked) || errors.Is(err, ErrForbidden) {
			t.Fatalf("Create = %v", err)
		}
		if n := ev.transferCount(t, ev.a); n != 0 {
			t.Errorf("%d transfers created", n)
		}
		if _, b, a := ab.counts(); b != 0 || a != 0 {
			t.Errorf("%d blocked, %d created calls", b, a)
		}
	})
}

// TestAbuseConcurrent shows that the check runs under the tenant lock: a
// rule allowing one transfer per sender lets exactly one of two concurrent
// creations through.
func TestAbuseConcurrent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.svc.abuse = &fakeAbuse{check: func(ctx context.Context, tx *store.ScopedTx, f AbuseFacts) (*AbuseBlock, error) {
			n, err := ev.db.Transfers().CountUploadingTx(ctx, tx, f.SenderEmail, f.At.Add(-time.Hour))
			if err != nil || n == 0 {
				return nil, err
			}
			return &AbuseBlock{Rule: store.AbuseRuleDailyTransfers, Value: float64(n + 1), Threshold: 1}, nil
		}}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Go(func() {
				_, errs[i] = ev.svc.Create(context.Background(), ev.a, internalSender(), request(), "")
			})
		}
		wg.Wait()
		ok, blocked := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrAbuseBlocked):
				blocked++
			default:
				t.Errorf("Create: %v", err)
			}
		}
		if ok != 1 || blocked != 1 {
			t.Errorf("%d created, %d blocked", ok, blocked)
		}
	})
}

func TestAbuseFaultInTx(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.svc.abuse = &fakeAbuse{}
	f := ev.faults()
	f.fail["checkAbuse"] = errFault
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), request(), ""); !errors.Is(err, errFault) {
		t.Errorf("Create = %v", err)
	}
}
