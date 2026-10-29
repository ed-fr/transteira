package mytransfers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

const day = 24 * time.Hour

// rulesOf returns level rules allowing exactly days.
func rulesOf(t *testing.T, days ...int) *store.ConfidentialityRules {
	t.Helper()
	mask, ok := store.ExpiryDaysMaskOf(days)
	if !ok {
		t.Fatalf("mask of %v", days)
	}
	return &store.ConfidentialityRules{ExpiryDaysMask: mask}
}

// fixture is an env with a session of alice in A and transfers of every
// kind.
type fixture struct {
	*env
	sess SessionInfo
	// available and scanning are transfers in progress of alice in A,
	// leveled an available one with a level allowing 1 and 7 days,
	// uploading and expired transfers of alice in A that are not in
	// progress, byToken a transfer of alice's address created with an API
	// token, ofBob a transfer of bob in A, inB a transfer of alice in B.
	available, scanning, leveled, uploading, expired, byToken, ofBob, inB string
}

func newFixture(t *testing.T, e storetest.Engine) *fixture {
	t.Helper()
	ev := newEnv(t, e)
	f := &fixture{env: ev}
	f.sess = ev.mustSession(ev.a, alice).SessionInfo
	f.uploading = ev.seed(ev.a, seedOptions{status: store.TransferUploading})
	f.expired = ev.seed(ev.a, seedOptions{status: store.TransferExpired})
	f.byToken = ev.seed(ev.a, seedOptions{apiToken: true})
	f.ofBob = ev.seed(ev.a, seedOptions{sender: bob})
	f.inB = ev.seed(ev.b, seedOptions{})
	ev.clock.Advance(time.Second)
	f.scanning = ev.seed(ev.a, seedOptions{status: store.TransferScanning, perRecipient: true})
	ev.clock.Advance(time.Second)
	f.leveled = ev.seed(ev.a, seedOptions{rules: rulesOf(t, 1, 7), perRecipient: true})
	ev.clock.Advance(time.Second)
	f.available = ev.seed(ev.a, seedOptions{})
	return f
}

func TestList(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newFixture(t, e)
		page, err := f.svc.List(ctx, f.a, f.sess, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, it := range page.Items {
			ids = append(ids, it.ID)
		}
		if want := []string{f.available, f.leveled, f.scanning}; !slices.Equal(ids, want) || page.NextCursor != "" {
			t.Fatalf("List = %v (next %q), want %v", ids, page.NextCursor, want)
		}
		if page.Items[1].LevelLabel != "Secret FR" || page.Items[0].LevelLabel != "" {
			t.Errorf("labels = %q, %q", page.Items[1].LevelLabel, page.Items[0].LevelLabel)
		}
		if !slices.Equal(page.Items[0].Recipients, []string{carol, dave}) || page.Items[0].FileCount != 1 {
			t.Errorf("item = %+v", page.Items[0])
		}

		// Pages of one.
		p1, err := f.svc.List(ctx, f.a, f.sess, "", 1)
		if err != nil || len(p1.Items) != 1 || p1.NextCursor == "" {
			t.Fatalf("page 1 = %+v, %v", p1, err)
		}
		p2, err := f.svc.List(ctx, f.a, f.sess, p1.NextCursor, 1)
		if err != nil || len(p2.Items) != 1 || p2.Items[0].ID != f.leveled {
			t.Fatalf("page 2 = %+v, %v", p2, err)
		}

		// The same address in tenant B sees its own transfer only.
		sessB := f.mustSession(f.b, alice).SessionInfo
		pageB, err := f.svc.List(ctx, f.b, sessB, "", 0)
		if err != nil || len(pageB.Items) != 1 || pageB.Items[0].ID != f.inB {
			t.Errorf("List in B = %+v, %v", pageB, err)
		}

		_, err = f.svc.List(ctx, f.a, f.sess, "not a cursor", 0)
		wantInvalid(t, "cursor", err, FieldCursor)
		f.fail("list")
		if _, err := f.svc.List(ctx, f.a, f.sess, "", 0); !errors.Is(err, errBoom) || errors.Is(err, ErrInvalid) {
			t.Errorf("List with a failure = %v", err)
		}
	})
}

func TestGet(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newFixture(t, e)
		now := f.clock.Now()

		d, err := f.svc.Get(ctx, f.a, f.sess, f.available)
		if err != nil {
			t.Fatal(err)
		}
		if d.ID != f.available || len(d.Files) != 1 || len(d.Tracking) != 0 || d.LevelLabel != "" ||
			!d.ExtendableTo.Equal(now.Add(30*day)) {
			t.Errorf("Get = %+v", d)
		}
		d, err = f.svc.Get(ctx, f.a, f.sess, f.leveled)
		// Allowed 1 and 7 days: now + 7 days, one second after the expiry.
		if err != nil || len(d.Tracking) != 2 || d.LevelLabel != "Secret FR" || !d.ExtendableTo.Equal(now.Add(7*day)) {
			t.Errorf("Get leveled = %+v, %v", d, err)
		}
		d, err = f.svc.Get(ctx, f.a, f.sess, f.scanning)
		if err != nil || !d.ExtendableTo.IsZero() {
			t.Errorf("Get scanning = %+v, %v", d, err)
		}
		for name, trfID := range map[string]string{
			"uploading": f.uploading, "expired": f.expired, "api token": f.byToken, "other sender": f.ofBob,
			"other tenant": f.inB, "unknown": "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS", "malformed": "x'; --",
		} {
			_, err := f.svc.Get(ctx, f.a, f.sess, trfID)
			wantErr(t, name, err, ErrNotFound)
		}
		f.fail("get")
		if _, err := f.svc.Get(ctx, f.a, f.sess, f.available); !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) {
			t.Errorf("Get with a failure = %v", err)
		}
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newFixture(t, e)

		for _, trfID := range []string{f.available, f.scanning} {
			if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, trfID); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if st := f.transfer(f.a, trfID).Status; st != store.TransferDeleted {
				t.Errorf("status after Delete = %s", st)
			}
		}
		evs := f.auditEvents(f.a.ID, audit.ActionTransferDeleted)
		if len(evs) != 2 || evs[0].Actor != aliceNorm || evs[0].ActorKind != store.ActorDepositor ||
			evs[0].ObjectKind != audit.ObjectTransfer || evs[0].IP != clientIP {
			t.Errorf("audit = %+v", evs)
		}
		calls := f.eraser.calls

		// Ended: a no-op, without erasure nor audit.
		for _, trfID := range []string{f.available, f.expired} {
			if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, trfID); err != nil {
				t.Errorf("Delete of an ended transfer: %v", err)
			}
		}
		if f.eraser.calls != calls || len(f.auditEvents(f.a.ID, audit.ActionTransferDeleted)) != 2 {
			t.Error("an ended transfer was erased or audited")
		}

		// Not the sender's in progress: 404, untouched.
		for name, trfID := range map[string]string{
			"uploading": f.uploading, "api token": f.byToken, "other sender": f.ofBob, "other tenant": f.inB,
			"unknown": "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS",
		} {
			wantErr(t, name, f.svc.Delete(ctx, f.a, f.sess, clientIP, trfID), ErrNotFound)
		}
		if f.transfer(f.a, f.ofBob).Status != store.TransferAvailable || f.transfer(f.b, f.inB).Status != store.TransferAvailable {
			t.Error("a transfer of someone else was deleted")
		}
		if f.eraser.calls != calls {
			t.Error("the eraser ran for a transfer of someone else")
		}
	})
}

// endedEraser reports every transfer as already ended.
type endedEraser struct{}

func (endedEraser) EraseTransfer(context.Context, tenant.ID, string, lifecycle.EraseMode) (lifecycle.EraseResult, error) {
	return lifecycle.AlreadyEnded, nil
}

func TestDeleteEraserOutcomes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, storetest.SQLite(t))

	// Busy a few times: retried, then erased.
	f.eraser.busy = 2
	if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, f.available); err != nil {
		t.Fatalf("Delete after busy: %v", err)
	}
	// Busy beyond the retries: a BusyError.
	f.eraser.busy = DefaultBusyRetries + 1
	err := f.svc.Delete(ctx, f.a, f.sess, clientIP, f.leveled)
	var busy *BusyError
	if !errors.As(err, &busy) || !errors.Is(err, ErrBusy) || busy.RetryAfter != DefaultBusyRetryAfter {
		t.Fatalf("Delete while busy = %v", err)
	}
	f.eraser.busy = 0
	// Gone in the meantime.
	f.eraser.err = fmt.Errorf("%w: gone", lifecycle.ErrNotFound)
	wantErr(t, "erased concurrently", f.svc.Delete(ctx, f.a, f.sess, clientIP, f.leveled), ErrNotFound)
	f.eraser.err = errBoom
	if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, f.leveled); !errors.Is(err, errBoom) {
		t.Errorf("Delete with a failing eraser = %v", err)
	}
	// Ended in the meantime: no audit.
	before := len(f.auditEvents(f.a.ID, audit.ActionTransferDeleted))
	f.svc.eraser = endedEraser{}
	if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, f.leveled); err != nil {
		t.Errorf("Delete ended concurrently = %v", err)
	}
	if len(f.auditEvents(f.a.ID, audit.ActionTransferDeleted)) != before {
		t.Error("a transfer ended concurrently was audited")
	}
	f.fail("status")
	if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, f.leveled); !errors.Is(err, errBoom) {
		t.Errorf("Delete with a failing status read = %v", err)
	}
}

func TestDeleteCanceled(t *testing.T) {
	t.Parallel()
	f := newFixture(t, storetest.SQLite(t))
	f.eraser.busy = 1
	f.svc.busyDelay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.svc.Delete(ctx, f.a, f.sess, clientIP, f.available); !errors.Is(err, context.Canceled) {
		t.Errorf("Delete canceled = %v", err)
	}
}

func TestExtend(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newFixture(t, e)
		f.clock.Advance(day)
		now := f.clock.Now().UTC().Truncate(time.Millisecond)
		before := f.transfer(f.a, f.available)

		d, err := f.svc.Extend(ctx, f.a, f.sess, clientIP, f.available, 30)
		if err != nil {
			t.Fatalf("Extend: %v", err)
		}
		if !d.ExpiresAt.Equal(now.Add(30*day)) || d.ExtensionCount != 1 || !d.ExtendableTo.IsZero() {
			t.Errorf("Extend = expires %s, count %d, extendable to %s", d.ExpiresAt, d.ExtensionCount, d.ExtendableTo)
		}
		evs := f.auditEvents(f.a.ID, audit.ActionTransferExtended)
		if len(evs) != 1 || evs[0].Actor != aliceNorm || evs[0].ObjectID != f.available || evs[0].IP != clientIP {
			t.Fatalf("audit = %+v", evs)
		}
		det := details(t, evs[0])
		if det["previousExpiresAt"] != before.ExpiresAt.UTC().Format(time.RFC3339Nano) ||
			det["expiresAt"] != d.ExpiresAt.UTC().Format(time.RFC3339Nano) || det["extensionCount"] != float64(1) {
			t.Errorf("audit details = %v", det)
		}

		// Shortening, or a duration outside the allowed ones: not-allowed.
		_, err = f.svc.Extend(ctx, f.a, f.sess, clientIP, f.available, 7)
		var na *NotAllowedError
		if !errors.As(err, &na) || !errors.Is(err, ErrNotAllowed) || !slices.Equal(na.Allowed, []int{1, 7, 30}) {
			t.Errorf("shortening = %v", err)
		}
		_, err = f.svc.Extend(ctx, f.a, f.sess, clientIP, f.leveled, 30)
		if !errors.As(err, &na) || !slices.Equal(na.Allowed, []int{1, 7}) {
			t.Errorf("outside the level = %v", err)
		}
		_, err = f.svc.Extend(ctx, f.a, f.sess, clientIP, f.leveled, 2)
		wantErr(t, "2 days", err, ErrNotAllowed)
		// Within the level: allowed.
		if d, err := f.svc.Extend(ctx, f.a, f.sess, clientIP, f.leveled, 7); err != nil || !d.ExpiresAt.Equal(now.Add(7*day)) {
			t.Errorf("within the level = %+v, %v", d.ExpiresAt, err)
		}

		// Not available: state conflict.
		_, err = f.svc.Extend(ctx, f.a, f.sess, clientIP, f.scanning, 30)
		wantErr(t, "scanning", err, ErrNotExtendable)
		for name, trfID := range map[string]string{
			"uploading": f.uploading, "expired": f.expired, "api token": f.byToken, "other sender": f.ofBob,
			"other tenant": f.inB,
		} {
			_, err := f.svc.Extend(ctx, f.a, f.sess, clientIP, trfID, 30)
			wantErr(t, name, err, ErrNotFound)
		}
		if f.transfer(f.a, f.ofBob).ExtensionCount != 0 || f.transfer(f.b, f.inB).ExtensionCount != 0 {
			t.Error("a transfer of someone else was extended")
		}

		// Beyond 90 days after the creation.
		old := f.seed(f.a, seedOptions{created: now.Add(-80 * day)})
		_, err = f.svc.Extend(ctx, f.a, f.sess, clientIP, old, 30)
		wantErr(t, "beyond 90 days", err, ErrExtensionLimit)
		if d, err := f.svc.Get(ctx, f.a, f.sess, old); err != nil || !d.ExtendableTo.Equal(now.Add(-80*day).Add(store.MaxTransferLifetime)) {
			t.Errorf("extendable to = %s, %v", d.ExtendableTo, err)
		}

		f.fail("extend")
		if _, err := f.svc.Extend(ctx, f.a, f.sess, clientIP, f.available, 30); !errors.Is(err, errBoom) {
			t.Errorf("Extend with a failure = %v", err)
		}
	})
}

func TestExtendScoped(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	r := storeRepo{db: ev.db}
	_, _, err := r.extend(context.Background(), "", "trf_x", aliceNorm, testStart, func(store.SenderTransferDetail) (time.Time, error) {
		return testStart, nil
	})
	if err == nil {
		t.Error("extend accepted an empty tenant")
	}
}

func TestExtendableTo(t *testing.T) {
	t.Parallel()
	now := testStart
	one := 1
	base := store.Transfer{
		Status: store.TransferAvailable, CreatedAt: now.Add(-day), ExpiresAt: now.Add(6 * day),
	}
	cases := []struct {
		name string
		mod  func(*store.Transfer)
		want time.Time
	}{
		{"plain", nil, now.Add(30 * day)},
		{"scanning", func(t *store.Transfer) { t.Status = store.TransferScanning }, time.Time{}},
		{"past expiry", func(t *store.Transfer) { t.ExpiresAt = now }, time.Time{}},
		{"delete after", func(t *store.Transfer) { t.DeleteAfter = now.Add(time.Hour) }, time.Time{}},
		{"max downloads reached", func(t *store.Transfer) { t.MaxDownloads, t.DownloadCount = &one, 1 }, time.Time{}},
		{"max downloads left", func(t *store.Transfer) { t.MaxDownloads = &one }, now.Add(30 * day)},
		{"no duration", func(t *store.Transfer) { t.Rules = &store.ConfidentialityRules{} }, time.Time{}},
		{"level", func(t *store.Transfer) {
			mask, _ := store.ExpiryDaysMaskOf([]int{1, 7})
			t.Rules = &store.ConfidentialityRules{ExpiryDaysMask: mask}
		}, now.Add(7 * day)},
		{"level, not later", func(t *store.Transfer) {
			mask, _ := store.ExpiryDaysMaskOf([]int{1})
			t.Rules = &store.ConfidentialityRules{ExpiryDaysMask: mask}
		}, time.Time{}},
		{"90 days", func(t *store.Transfer) { t.CreatedAt = now.Add(-80 * day) }, now.Add(10 * day)},
		{"90 days reached", func(t *store.Transfer) {
			t.CreatedAt, t.ExpiresAt = now.Add(-80*day), now.Add(10*day)
		}, time.Time{}},
	}
	for _, c := range cases {
		tr := base
		if c.mod != nil {
			c.mod(&tr)
		}
		if got := ExtendableTo(tr, now); !got.Equal(c.want) {
			t.Errorf("%s: ExtendableTo = %s, want %s", c.name, got, c.want)
		}
	}
	// AllowedExpiryDays never shares its slice.
	a := AllowedExpiryDays(base)
	a[0] = 99
	if AllowedExpiryDays(base)[0] != 1 {
		t.Error("AllowedExpiryDays shares its slice")
	}
}

// fakeAbuse records the extensions it is told of.
type fakeAbuse struct {
	mu         sync.Mutex
	tenants    []tenant.ID
	facts      []AbuseFacts
	cancelable []bool
}

func (a *fakeAbuse) AfterExtend(ctx context.Context, t *tenant.Tenant, f AbuseFacts) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tenants = append(a.tenants, t.ID)
	a.facts = append(a.facts, f)
	a.cancelable = append(a.cancelable, ctx.Done() != nil)
}

// TestExtendAbuse tells the abuse notifier once per successful extension,
// with the facts of the transfer, and never on a refused one.
func TestExtendAbuse(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		f := newFixture(t, e)
		fake := &fakeAbuse{}
		f.svc.abuse = fake
		f.clock.Advance(day)
		now := f.clock.Now()
		before := f.transfer(f.a, f.available)

		// The notifier gets a context that cannot be canceled.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if _, err := f.svc.Extend(ctx, f.a, f.sess, clientIP, f.available, 30); err != nil {
			t.Fatalf("Extend: %v", err)
		}
		if len(fake.facts) != 1 || fake.tenants[0] != f.a.ID || fake.cancelable[0] {
			t.Fatalf("calls = %+v (cancelable %v)", fake.facts, fake.cancelable)
		}
		got := fake.facts[0]
		if got.TransferID != f.available || got.SenderEmail != aliceNorm || got.Kind != before.SenderKind ||
			got.Bytes != before.TotalBytes || !slices.Equal(got.Recipients, before.Recipients) ||
			!got.At.Equal(now) || got.ClientIP != clientIP {
			t.Errorf("facts = %+v, want the transfer %+v", got, before)
		}

		// A refused extension tells nothing.
		_, err := f.svc.Extend(context.Background(), f.a, f.sess, clientIP, f.available, 7)
		wantErr(t, "shortening", err, ErrNotAllowed)
		_, err = f.svc.Extend(context.Background(), f.a, f.sess, clientIP, f.ofBob, 30)
		wantErr(t, "other sender", err, ErrNotFound)
		if len(fake.facts) != 1 {
			t.Errorf("calls after refusals = %d", len(fake.facts))
		}
	})
}
