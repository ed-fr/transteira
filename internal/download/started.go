package download

import (
	"context"
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

// bytesServed counts n plaintext bytes served for tenant tid, if any.
func (s *Service) bytesServed(tid tenant.ID, n int64) {
	if n > 0 {
		s.usage.BytesServed(tid, n, s.now())
	}
}
