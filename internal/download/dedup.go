package download

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of the deduplication of the download starts (see [Options]).
const (
	// DefaultStartWindow is how long a download start of an object by a
	// client keeps the next ones from being recorded again.
	DefaultStartWindow = time.Hour
	// DefaultMaxStarts bounds the download starts remembered for the
	// deduplication. An entry holds a few identifiers, about 300 bytes, so
	// the default bounds the memory at about 30 MB.
	DefaultMaxStarts = 100_000
	// DefaultMaxStartsPerTransfer bounds the download starts recorded for
	// one transfer within a window, whatever the clients: a client cycling
	// many keys (the 65,536 /64s of an IPv6 /48) evicts the remembered
	// starts, but not this count.
	DefaultMaxStartsPerTransfer = 1000
)

// startKey identifies the download starts that count as one within the
// window: an object (a file ID, or archiveObject) of a transfer, by one
// client (its IPv4 address, or its IPv6 /64, as the rate limits key it).
type startKey struct {
	tid    tenant.ID
	trf    string
	object string
	client string
}

// transferKey identifies a transfer, for the count of its recorded starts.
type transferKey struct {
	tid tenant.ID
	trf string
}

// transferCount is the count of the starts recorded for a transfer within
// the window opened at its first one.
type transferCount struct {
	key transferKey
	at  time.Time
	n   int
}

// startEntry is a remembered download start.
type startEntry struct {
	key startKey
	at  time.Time
}

// startDedup remembers the download starts recorded within the window, so
// that a client looping on a range from offset 0 (or aborting after the
// first byte) writes one audit event, one download count and one usage
// count per object per window, not one per request (threat of a flood of
// append-only audit rows kept 12 months in the shared database).
//
// It is bounded: entries expire after the window, and when max entries
// are held the oldest is evicted, so that its client may be counted again
// before the end of its window. Since a client holding many keys (an IPv6
// /48 holds 65,536 /64s) could so evict every entry, the starts recorded
// for one transfer are also counted in a separate map, within a window
// opened at the first one: beyond perTransfer, no start of that transfer
// is recorded until that window is over. That map is bounded by max
// transfers, the oldest window evicted first; evicting a count needs as
// many other transfers started, whose links a client cannot make up. It is
// in memory only: a restart forgets it, which only lets a start be counted
// once more. It is safe for concurrent use.
type startDedup struct {
	window      time.Duration
	max         int
	perTransfer int

	mu sync.Mutex
	// order holds the *startEntry values by recording time, oldest first.
	order *list.List
	items map[startKey]*list.Element
	// counted holds the *transferCount values by window start, oldest
	// first.
	counted   *list.List
	transfers map[transferKey]*list.Element
}

// newStartDedup returns a deduplication over window, holding at most max
// entries and max transfer counts, recording at most perTransfer starts
// of a transfer per window.
func newStartDedup(window time.Duration, maxEntries, perTransfer int) *startDedup {
	return &startDedup{
		window: window, max: maxEntries, perTransfer: perTransfer,
		order: list.New(), items: map[startKey]*list.Element{},
		counted: list.New(), transfers: map[transferKey]*list.Element{},
	}
}

// first reports whether the download start k at now must be recorded: no
// start of k was recorded within the window, and fewer than perTransfer
// starts of its transfer were recorded within the transfer window. It then
// remembers k at now and counts it; a start within the window does not
// extend it.
func (d *startDedup) first(k startKey, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for el := d.order.Front(); el != nil && d.expired(el.Value.(*startEntry).at, now); el = d.order.Front() {
		d.remove(el)
	}
	for el := d.counted.Front(); el != nil && d.expired(el.Value.(*transferCount).at, now); el = d.counted.Front() {
		d.removeCount(el)
	}
	if el, ok := d.items[k]; ok {
		if !d.expired(el.Value.(*startEntry).at, now) {
			return false
		}
		// The clock went back: the entry is not at the front.
		d.remove(el)
	}
	if !d.count(transferKey{tid: k.tid, trf: k.trf}, now) {
		return false
	}
	if len(d.items) >= d.max {
		d.remove(d.order.Front())
	}
	d.items[k] = d.order.PushBack(&startEntry{key: k, at: now})
	return true
}

// count counts a start of the transfer tk at now and reports whether it is
// within perTransfer for the transfer window, opened at now when none is.
func (d *startDedup) count(tk transferKey, now time.Time) bool {
	if el, ok := d.transfers[tk]; ok {
		c := el.Value.(*transferCount)
		if !d.expired(c.at, now) {
			if c.n >= d.perTransfer {
				return false
			}
			c.n++
			return true
		}
		// The clock went back: the count is not at the front.
		d.removeCount(el)
	}
	if len(d.transfers) >= d.max {
		d.removeCount(d.counted.Front())
	}
	d.transfers[tk] = d.counted.PushBack(&transferCount{key: tk, at: now, n: 1})
	return true
}

// expired reports whether a window opened at at is over at now, or opened
// after now (the clock went back), which counts as over too.
func (d *startDedup) expired(at, now time.Time) bool {
	return now.Sub(at) >= d.window || now.Before(at)
}

// removeCount forgets the transfer count el.
func (d *startDedup) removeCount(el *list.Element) {
	delete(d.transfers, el.Value.(*transferCount).key)
	d.counted.Remove(el)
}

// remove forgets the entry el.
func (d *startDedup) remove(el *list.Element) {
	delete(d.items, el.Value.(*startEntry).key)
	d.order.Remove(el)
}

// len returns the number of entries held.
func (d *startDedup) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.items)
}

// newStartKey returns the deduplication key of a download start.
func newStartKey(tid tenant.ID, trfID, object string, ip netip.Addr) startKey {
	return startKey{tid: tid, trf: trfID, object: object, client: store.IPFailureKey(ip).Key}
}
