package secret

import (
	"container/list"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Bounds of the default per-client limiters of the express secrets
// ([NewExpressWindow]): the anonymous creations (Options.ExpressPerIP)
// and the abuse reports on them (Options.ReportsPerIP).
const (
	// ExpressIPWindow is the sliding window of
	// tenant.ExpressSettings.PerHourPerIP.
	ExpressIPWindow = time.Hour
	// ExpressIPMaxKeys bounds the clients a limiter keeps in memory for
	// one tenant (threat model T-390: the clients of one tenant never take
	// the place of those of another). A client whose events all left the
	// window is forgotten first. When a tenant holds that many clients, a
	// new one takes the place of a client without event in the window,
	// else of the least recently seen client below the limit (which loses
	// its partial count); a client at its limit is never forgotten, so
	// that no counter is lifted early. A tenant whose least recently seen
	// clients are all at their limit refuses a new client (fail closed),
	// reported as saturated so that the refusal is never written as the
	// fault of that client (T-405).
	ExpressIPMaxKeys = 100_000
	// expressEvictScan bounds the least recently seen clients inspected
	// to choose the one to forget, so that admitting a client into a full
	// table stays O(1).
	expressEvictScan = 256
)

// ExpressLimiter counts events per tenant and client over a sliding window
// with a limit given at each call (the setting of the tenant, which may
// change at any time). *ExpressWindow implements it.
type ExpressLimiter interface {
	// Allow records one event for client on tenant tid when fewer than
	// limit events of that client were counted in the window. Otherwise ok
	// is false and retryAfter the time until an event may be allowed;
	// saturated is then true when the refusal comes from the bound of the
	// clients kept for tid (nothing was counted for client), false when it
	// comes from the events of client.
	Allow(tid, client string, limit int) (ok bool, retryAfter time.Duration, saturated bool)
}

// ExpressWindow is an exact sliding window in memory, one table of clients
// per tenant: it keeps the time of every counted event of the last period,
// at most tenant.MaxExpressPerHourPerIP per client, and at most maxKeys
// clients per tenant (see ExpressIPMaxKeys for the eviction). Its state is
// lost at a restart (data-model-v2.3.md 2.3: at worst one extra hour of
// quota). It is safe for concurrent use.
type ExpressWindow struct {
	mu      sync.Mutex
	period  time.Duration
	maxKeys int
	clock   func() time.Time
	tenants map[string]*clientTable
}

// clientTable holds the clients of one tenant, most recently seen first.
type clientTable struct {
	items map[string]*list.Element
	order *list.List // of *clientEntry, front = most recently seen
}

// clientEntry is the counter of one client.
type clientEntry struct {
	client   string
	events   []time.Time // counted events of the window, oldest first
	lastSeen time.Time   // last call, counted or refused
}

// NewExpressWindow returns an ExpressWindow over period keeping at most
// maxKeys clients (at least one) per tenant, reading the time from clock
// (time.Now when nil).
func NewExpressWindow(period time.Duration, maxKeys int, clock func() time.Time) *ExpressWindow {
	if clock == nil {
		clock = time.Now
	}
	return &ExpressWindow{period: period, maxKeys: max(maxKeys, 1), clock: clock, tenants: make(map[string]*clientTable)}
}

// Allow implements ExpressLimiter. limit is clamped to 1 to
// tenant.MaxExpressPerHourPerIP. retryAfter is in whole seconds, at least
// one: the time until enough events of client leave the window, or, for a
// new client refused because the table of tid is saturated, until one of
// the inspected clients drops below the limit.
func (w *ExpressWindow) Allow(tid, client string, limit int) (bool, time.Duration, bool) {
	limit = min(max(limit, 1), tenant.MaxExpressPerHourPerIP)
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	w.expire(now)
	tab := w.tenants[tid]
	if tab == nil {
		tab = &clientTable{items: make(map[string]*list.Element), order: list.New()}
		w.tenants[tid] = tab
	}
	el, known := tab.items[client]
	if !known {
		if len(tab.items) >= w.maxKeys {
			victim, retry := w.victim(tab, limit, now)
			if victim == nil {
				return false, retry, true
			}
			tab.remove(victim)
		}
		el = tab.order.PushFront(&clientEntry{client: client})
		tab.items[client] = el
	}
	tab.order.MoveToFront(el)
	e := el.Value.(*clientEntry)
	e.lastSeen = now
	e.events = w.prune(e.events, now)
	if n := len(e.events); n >= limit {
		return false, ceilSecond(e.events[n-limit].Add(w.period).Sub(now)), false
	}
	e.events = append(e.events, now)
	return true, 0, false
}

// prune drops the events that left the window at now: an event at t
// counts while now is before t+period.
func (w *ExpressWindow) prune(events []time.Time, now time.Time) []time.Time {
	k := 0
	for k < len(events) && !now.Before(events[k].Add(w.period)) {
		k++
	}
	return events[k:]
}

// expire forgets, in every tenant, the clients not seen for a period
// (their events all left the window: an event is never after the last
// call), and the tenants left without client. The tables are ordered by
// last call, so only their oldest clients are inspected.
func (w *ExpressWindow) expire(now time.Time) {
	for tid, tab := range w.tenants {
		for back := tab.order.Back(); back != nil; back = tab.order.Back() {
			if now.Before(back.Value.(*clientEntry).lastSeen.Add(w.period)) {
				break
			}
			tab.remove(back)
		}
		if len(tab.items) == 0 {
			delete(w.tenants, tid)
		}
	}
}

// victim returns the client of tab to forget for a new one at now: among
// the expressEvictScan least recently seen, the first without event in
// the window, else the least recently seen below limit. It returns nil
// when all of them are at their limit, with the time until the first of
// them drops below it.
func (w *ExpressWindow) victim(tab *clientTable, limit int, now time.Time) (*list.Element, time.Duration) {
	var (
		below *list.Element
		free  time.Time
	)
	for el, n := tab.order.Back(), 0; el != nil && n < expressEvictScan; el, n = el.Prev(), n+1 {
		e := el.Value.(*clientEntry)
		e.events = w.prune(e.events, now)
		k := len(e.events)
		switch {
		case k == 0:
			return el, 0
		case k < limit:
			if below == nil {
				below = el
			}
		default:
			if at := e.events[k-limit].Add(w.period); free.IsZero() || at.Before(free) {
				free = at
			}
		}
	}
	if below != nil {
		return below, 0
	}
	return nil, ceilSecond(free.Sub(now))
}

// remove forgets the client of el.
func (t *clientTable) remove(el *list.Element) {
	delete(t.items, el.Value.(*clientEntry).client)
	t.order.Remove(el)
}

// Len returns the number of clients kept, all tenants together.
func (w *ExpressWindow) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, tab := range w.tenants {
		n += len(tab.items)
	}
	return n
}

// ceilSecond rounds d up to a whole number of seconds, at least one.
func ceilSecond(d time.Duration) time.Duration {
	return max(time.Second, (d + time.Second - 1).Truncate(time.Second))
}
