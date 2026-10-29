package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// scriptedEraser answers EraseTransfer with the next error of errs (nil
// once exhausted), recording the calls.
type scriptedEraser struct {
	errs  []error
	calls int
	modes []EraseMode
	ctxs  []context.Context
}

func (e *scriptedEraser) EraseTransfer(ctx context.Context, _ tenant.ID, _ string, mode EraseMode) (EraseResult, error) {
	e.calls++
	e.modes = append(e.modes, mode)
	e.ctxs = append(e.ctxs, ctx)
	if len(e.errs) == 0 {
		return Erased, nil
	}
	err := e.errs[0]
	e.errs = e.errs[1:]
	if err != nil {
		return 0, err
	}
	return Erased, nil
}

func TestEraseRetrying(t *testing.T) {
	t.Parallel()
	other := errors.New("boom")
	cases := []struct {
		name    string
		errs    []error
		retries int
		calls   int
		want    error
	}{
		{"first attempt", nil, 3, 1, nil},
		{"busy then erased", []error{ErrBusy, ErrBusy}, 3, 3, nil},
		{"busy exhausted", []error{ErrBusy, ErrBusy, ErrBusy}, 2, 3, ErrBusy},
		{"no retry", []error{ErrBusy}, 0, 1, ErrBusy},
		{"negative retries", []error{ErrBusy}, -1, 1, ErrBusy},
		{"other error not retried", []error{other}, 3, 1, other},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := &scriptedEraser{errs: c.errs}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res, err := EraseRetrying(ctx, e, "tnt_x", "trf_x", c.retries, time.Millisecond)
			if !errors.Is(err, c.want) || (c.want == nil && res != Erased) {
				t.Fatalf("EraseRetrying = %v, %v, want %v", res, err, c.want)
			}
			if e.calls != c.calls {
				t.Errorf("calls = %d, want %d", e.calls, c.calls)
			}
			for i, m := range e.modes {
				if m != MarkDeleted {
					t.Errorf("mode %d = %v, want MarkDeleted", i, m)
				}
				// The erasure itself runs without cancellation.
				cancel()
				if e.ctxs[i].Err() != nil {
					t.Errorf("attempt %d ran with a cancelable context", i)
				}
			}
		})
	}
}

func TestEraseRetryingStopsWithContext(t *testing.T) {
	t.Parallel()
	e := &scriptedEraser{errs: []error{ErrBusy, ErrBusy}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := EraseRetrying(ctx, e, "tnt_x", "trf_x", 5, time.Hour)
	if !errors.Is(err, context.Canceled) || res != 0 || e.calls != 1 {
		t.Fatalf("EraseRetrying = %v, %v after %d calls, want canceled after 1", res, err, e.calls)
	}
}
