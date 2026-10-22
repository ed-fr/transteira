package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// EraseMode is how [Sweeper.EraseTransfer] ends a transfer.
type EraseMode int

const (
	// MarkDeleted erases the transfer and marks it deleted, keeping its row
	// so that its link answers "gone" (an administrator's deletion). A
	// transfer already expired or deleted is left as it is.
	MarkDeleted EraseMode = iota + 1
	// DeleteRow erases the transfer, whatever its status, and deletes its
	// row with its recipients and files (a GDPR erasure).
	DeleteRow
)

// EraseResult is what [Sweeper.EraseTransfer] did.
type EraseResult int

const (
	// Erased means the transfer was erased, then marked deleted or deleted.
	Erased EraseResult = iota + 1
	// AlreadyEnded means that, with MarkDeleted, the transfer had already
	// expired or been deleted; nothing was done (the caller records no
	// audit event).
	AlreadyEnded
)

// Errors of [Sweeper.EraseTransfer].
var (
	// ErrNotFound reports a transfer that does not exist, or is not a
	// transfer of the tenant.
	ErrNotFound = errors.New("lifecycle: transfer not found")
	// ErrBusy reports an upload request holding a file of the transfer: no
	// key was destroyed and nothing changed. It is not retried inside; the
	// caller retries after a short delay.
	ErrBusy = errors.New("lifecycle: transfer busy: an upload request holds one of its files")
)

// noHolder is the [Holder] used without antivirus worker: it holds
// nothing.
type noHolder struct{}

func (noHolder) Hold(context.Context, tenant.ID, string, HoldIntent) (func(), error) {
	return func() {}, nil
}

// EraseTransfer erases the transfer trfID of tenant tid now, whatever its
// status, for an administrator (mode MarkDeleted) or a GDPR erasure (mode
// DeleteRow), through the erasure path of the cleanup task (see the
// package documentation):
//
//  1. the antivirus worker is held (Deps.Holder, HoldForErase), before
//     any read or key destruction: an analysis in progress is canceled and waited for, a
//     queued one dropped, so that a transfer still scanning never becomes
//     available and no mail reaches its recipients once EraseTransfer has
//     started; the hold is released at the end, whatever the outcome;
//  2. the transfer is read, the upload locks of its files are taken (an
//     upload request holding one yields ErrBusy at once, with nothing
//     changed), and it is read again under them;
//  3. the data key of every file is destroyed, then the files and their
//     checkpoints are removed, then the download state;
//  4. in one transaction, its sealed download token is destroyed and it is
//     marked deleted from any status (MarkDeleted: its row and token hash
//     stay, so its link answers "gone"), or its row is deleted with its
//     recipients and files by cascade (DeleteRow).
//
// With MarkDeleted, a transfer already expired or deleted, before or
// during the erasure, yields AlreadyEnded and is left as it is, and the
// database is scrubbed after an erasure; with DeleteRow, the caller
// scrubs once after all its erasures (store.DB.ScrubDeleted). It returns
// ErrNotFound for a transfer that does not exist or belongs to another
// tenant, store.ErrInvalid for an unknown mode or a malformed tenant ID,
// ctx.Err() when ctx is done before the antivirus stopped, and any other
// failure wrapped with its step: every step is idempotent, and a new call
// completes the erasure (the keys already destroyed are skipped). It may
// run alongside the periodic tasks: the upload locks and the final
// transaction keep the two erasures of a transfer consistent.
func (s *Sweeper) EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode EraseMode) (EraseResult, error) {
	var k kind
	switch mode {
	case MarkDeleted:
		k = kindAdmin
	case DeleteRow:
		k = kindSubject
	default:
		return 0, fmt.Errorf("lifecycle: erase transfer: %w: unknown mode %d", store.ErrInvalid, mode)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	release, err := s.holder.Hold(ctx, tid, trfID, HoldForErase)
	if err != nil {
		return 0, fmt.Errorf("lifecycle: erase transfer %s: hold the antivirus: %w", trfID, err)
	}
	defer release()
	tt := store.TenantTransfer{TenantID: tid, TransferID: trfID}
	out, step, err := s.eraseSteps(ctx, k, tt, s.now())
	switch out {
	case erased:
		if k == kindAdmin {
			s.scrub(context.WithoutCancel(ctx))
		}
		s.logger.InfoContext(ctx, "lifecycle: transfer erased on request", slog.String("tenant", string(tid)),
			slog.String("transfer", trfID), slog.Bool("row_deleted", k == kindSubject))
		return Erased, nil
	case skipped:
		return AlreadyEnded, nil
	case missing:
		return 0, fmt.Errorf("%w: %s", ErrNotFound, trfID)
	}
	if step == stepLock {
		return 0, fmt.Errorf("%w: %s: %w", ErrBusy, trfID, err)
	}
	s.logger.WarnContext(ctx, "lifecycle: transfer erasure on request failed", slog.String("tenant", string(tid)),
		slog.String("transfer", trfID), slog.String("step", step), slog.Any("error", err))
	return 0, fmt.Errorf("lifecycle: erase transfer %s: %s: %w", trfID, step, err)
}
