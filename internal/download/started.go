package download

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Recording of the download starts.
const (
	// startTimeout bounds the recording of a download start, which the
	// first byte of the response waits for.
	startTimeout = 5 * time.Second
	// archiveObject is the detail of an audit event recording the start of
	// an archive download, in place of a file ID.
	archiveObject = "archive"
	// linkActor is the actor of a download: in V1 the single download link
	// of a transfer does not identify which recipient uses it.
	linkActor = "link"
)

// Usage receives the download counters of the tenant statistics. The
// usage package implements it; a nil Deps.Usage counts nothing.
type Usage interface {
	// DownloadStarted counts one download start of tenant tid at at.
	DownloadStarted(tid tenant.ID, at time.Time)
	// BytesServed counts n plaintext bytes served for tenant tid at at.
	BytesServed(tid tenant.ID, n int64, at time.Time)
}

// noUsage is the Usage of a service built without one.
type noUsage struct{}

func (noUsage) DownloadStarted(tenant.ID, time.Time)    {}
func (noUsage) BytesServed(tenant.ID, int64, time.Time) {}

// startEvent is the audit event of a download start of the transfer trfID
// by the client ip: object is the file ID, or archiveObject for the
// archive. It holds identifiers only, never an address.
func startEvent(trfID, object string, ip netip.Addr) audit.Event {
	return audit.Event{
		ActorKind: store.ActorRecipient, Actor: linkActor, IP: ip,
		Action: audit.ActionTransferDownloaded, ObjectKind: audit.ObjectTransfer, ObjectID: trfID,
		Details: map[string]any{"file": object},
	}
}

// downloadStarted records a download start of the object (a file ID, or
// archiveObject) of the transfer trfID of tenant t by the client ip: the
// usage counter, then the transfer.downloaded audit event and the download
// count of the transfer, in one transaction. A start of the same object by
// the same client within Options.StartWindow of the last one recorded is
// not recorded again (see [startDedup]). The recording is detached from
// the cancellation of ctx and bounded by startTimeout. Serving never
// depends on it: a failure is logged, and the download goes on without its
// audit event and count.
func (s *Service) downloadStarted(ctx context.Context, t *tenant.Tenant, trfID, object string, ip netip.Addr) {
	now := s.now()
	if !s.starts.first(newStartKey(t.ID, trfID, object, ip), now) {
		return
	}
	s.usage.DownloadStarted(t.ID, now)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), startTimeout)
	defer cancel()
	if err := s.repo.started(ctx, t.ID, trfID, startEvent(trfID, object, ip)); err != nil {
		s.log(ctx, slog.LevelError, "download start not recorded", t.ID, trfID, slog.Any("error", err))
	}
}

// claimStart decides, before any byte is sent, a request for the object
// (a file ID, or archiveObject) of the transfer d of tenant t, which has a
// download limit, by the client ip. get is false for a HEAD request.
//
// A client whose start of that object is remembered (see [startDedup.claim],
// [Service.touchStart]) is served without being counted again, whatever
// the range it asks for: a resumed range, or a new start within the
// window. Any other GET is a download start, counted synchronously by a
// conditional update (repo.claim, with its audit event, in one
// transaction): refused with ErrMaxDownloads once the limit is reached,
// otherwise remembered and counted in the usage. The start reaching the
// limit makes the transfer due for deletion Options.Grace later. A HEAD
// request is never counted: it is refused with ErrMaxDownloads when the
// GET would be (limit reached, from the state read by resolve), and
// served otherwise. The decisions on a transfer are serialized by its
// in-process lock, so that concurrent requests of one client are counted
// once. A transfer deleted or no longer available meanwhile is ErrGone. A
// failure of the count refuses the request (fail closed); its error is
// internal, logged unless the client is gone (ctx done).
//
// An allowed GET returns the time its start was counted, for
// [Service.touchStart]; the zero time otherwise.
func (s *Service) claimStart(ctx context.Context, t *tenant.Tenant, d store.TransferDetails, object string, ip netip.Addr, get bool) (time.Time, error) {
	k := newStartKey(t.ID, d.ID, object, ip)
	unlock := s.lock(key{tid: t.ID, id: d.ID})
	defer unlock()
	now := s.now()
	if claimed, ok := s.starts.seen(k, now); ok {
		return claimed, nil
	}
	switch {
	case !get && limitReached(d):
		return time.Time{}, ErrMaxDownloads
	case !get:
		return time.Time{}, nil
	}
	cctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	_, err := s.repo.claim(cctx, t.ID, d.ID, now.Add(s.opts.Grace), startEvent(d.ID, object, ip))
	switch {
	case errors.Is(err, store.ErrMaxDownloads):
		return time.Time{}, ErrMaxDownloads
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
		return time.Time{}, ErrGone
	case err != nil:
		level := slog.LevelError
		if ctx.Err() != nil {
			level = slog.LevelDebug // the client is gone
		}
		s.log(ctx, level, "download start not counted", t.ID, d.ID, slog.Any("error", err))
		return time.Time{}, fmt.Errorf("download: count download start: %w", err)
	}
	s.starts.claim(k, now)
	s.usage.DownloadStarted(t.ID, now)
	return now, nil
}

// touchStart moves to now the deduplication window of the start of the
// object of the transfer trfID by the client ip, counted at claimed, at
// the end of an interrupted response of a file (a write error or a client
// gone before the end of the file), so that the client may resume it
// within the window, but never past claimed plus startCeilingWindows
// windows (see [startDedup.extend]). A response written to its end moves
// nothing, whether it delivered the end of the file or a range the client
// chose to end before it: a client downloading the same file again after
// the window is counted again, and a client looping on a short range
// cannot keep its window open.
func (s *Service) touchStart(tid tenant.ID, trfID, object string, ip netip.Addr, claimed time.Time) {
	s.starts.extend(newStartKey(tid, trfID, object, ip), claimed, s.now())
}

// bytesServed counts n plaintext bytes served for tenant tid, if any.
func (s *Service) bytesServed(tid tenant.ID, n int64) {
	if n > 0 {
		s.usage.BytesServed(tid, n, s.now())
	}
}
