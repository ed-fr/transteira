package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// TransferEraser erases a transfer on request: [Sweeper.EraseTransfer].
type TransferEraser interface {
	EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode EraseMode) (EraseResult, error)
}

// EraseRetrying erases the transfer trfID of tenant tid with eraser in
// mode MarkDeleted, as a deletion requested by a person (an administrator,
// or the sender through "my transfers") does: while an upload request
// holds one of its files (ErrBusy), the erasure is tried again, at most
// retries more times (none when retries <= 0), delay apart. The last
// ErrBusy is returned once the retries are exhausted, for the caller to
// answer with a Retry-After delay.
//
// The waits between the attempts stop when ctx is done (ctx.Err() is then
// returned); each erasure itself runs without cancellation, so that it is
// never interrupted halfway.
func EraseRetrying(ctx context.Context, eraser TransferEraser, tid tenant.ID, trfID string, retries int, delay time.Duration) (EraseResult, error) {
	for attempt := 0; ; attempt++ {
		res, err := eraser.EraseTransfer(context.WithoutCancel(ctx), tid, trfID, MarkDeleted)
		if !errors.Is(err, ErrBusy) || attempt >= retries {
			return res, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
}
