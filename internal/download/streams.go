package download

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Concurrent stream limits (threat model T-55): each file or archive
// response holds one slot of its transfer, one slot of its client on that
// transfer and one slot of its client until it ends, so that one link or
// one client cannot saturate the bandwidth and the decryption, and one
// client cannot take every slot of a transfer. A client is keyed like the
// password failures: an IPv4 address, an IPv6 /64. The counters are in
// process: TransTeira runs as a single instance (CLAUDE.md section 17).
const (
	// MaxStreamsPerTransfer bounds the responses streaming the files of one
	// transfer at once, all clients together.
	MaxStreamsPerTransfer = 4
	// MaxStreamsPerTransferClient bounds the responses streaming the files
	// of one transfer to one client at once. It is below
	// MaxStreamsPerTransfer, so that other clients keep a slot.
	MaxStreamsPerTransferClient = 2
	// MaxStreamsPerClient bounds the responses streaming to one client at
	// once, all transfers of the tenant together.
	MaxStreamsPerClient = 8
	// StreamRetryAfter is the Retry-After hint of a refusal.
	StreamRetryAfter = 30 * time.Second
	// StreamEventInterval is the minimum interval between two rate_limited
	// security events (scope download_streams) for the same client of a
	// tenant, so that a client hammering the limits cannot flood the
	// security log; one event per interval is enough for fail2ban and
	// CrowdSec to keep counting it.
	StreamEventInterval = 10 * time.Second
	// scopeDownloadStreams names the stream limits in the rate_limited
	// events.
	scopeDownloadStreams = "download_streams"
)

// streamKey identifies a stream counter: a transfer (client unset), a
// client (trf unset) or a client on a transfer (both set).
type streamKey struct {
	tid    tenant.ID
	trf    string
	client string
}

// streams counts the open streams.
type streams struct {
	mu     sync.Mutex
	counts map[streamKey]int
}

// limit returns the bound of the counter k.
func (k streamKey) limit() int {
	switch {
	case k.client == "":
		return MaxStreamsPerTransfer
	case k.trf == "":
		return MaxStreamsPerClient
	default:
		return MaxStreamsPerTransferClient
	}
}

// acquire takes a slot of the transfer trfID, of the client ip on that
// transfer and of the client ip in tenant tid, and returns its release,
// which may be called more than once (only the first call releases). It
// returns a *TooManyStreamsError when any limit is reached, and
// ErrNoClientIP for an invalid ip.
func (s *streams) acquire(tid tenant.ID, trfID string, ip netip.Addr) (func(), error) {
	if !ip.IsValid() {
		return nil, ErrNoClientIP
	}
	ck := store.IPFailureKey(ip).Key
	keys := [...]streamKey{{tid: tid, trf: trfID}, {tid: tid, trf: trfID, client: ck}, {tid: tid, client: ck}}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		if s.counts[k] >= k.limit() {
			return nil, &TooManyStreamsError{RetryAfter: StreamRetryAfter}
		}
	}
	for _, k := range keys {
		s.counts[k]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, k := range keys {
				if s.counts[k]--; s.counts[k] == 0 {
					delete(s.counts, k)
				}
			}
		})
	}, nil
}

// newEventThrottle returns the limiter of the download_streams events:
// one event per key per StreamEventInterval, with the bounded memory of
// the ratelimit table.
func newEventThrottle(clock func() time.Time) *ratelimit.Limiter {
	return ratelimit.New(rate.Every(StreamEventInterval), 1, ratelimit.WithClock(clock))
}

// acquireStream takes the stream slots of a response of the transfer
// trfID of tenant t to the client ip (see streams.acquire). A refusal over
// a limit writes a rate_limited security event (scope download_streams),
// at most one per client of the tenant per StreamEventInterval.
func (s *Service) acquireStream(ctx context.Context, t *tenant.Tenant, trfID string, ip netip.Addr) (func(), error) {
	release, err := s.streams.acquire(t.ID, trfID, ip)
	var te *TooManyStreamsError
	if errors.As(err, &te) {
		if ok, _ := s.events.Allow(t.ID.String() + " " + store.IPFailureKey(ip).Key + " " + scopeDownloadStreams); ok {
			s.logEvent(ctx, t, ip, trfID, securitylog.RateLimited,
				securitylog.Field{Key: securitylog.KeyScope, Value: scopeDownloadStreams})
		}
	}
	return release, err
}
