package metrics

import (
	"maps"
	"sync"
	"sync/atomic"
)

// httpClasses are the label values of transteira_http_requests_total, in
// the order of the status hundreds 1 to 5.
var httpClasses = [5]string{"1xx", "2xx", "3xx", "4xx", "5xx"}

// TLS ask results, the label values of transteira_tls_ask_total.
const (
	// TLSAskAllowed is a /tls/ask answered 200 (FQDN of a tenant).
	TLSAskAllowed = "allowed"
	// TLSAskUnknown is a /tls/ask answered 404 for a domain that is not
	// the FQDN of a tenant.
	TLSAskUnknown = "unknown"
	// TLSAskRefused is a /tls/ask refused before the domain is looked up:
	// endpoint disabled, peer address not allowed, relay header or method.
	TLSAskRefused = "refused"
)

// tlsAskResults are the label values of transteira_tls_ask_total, in
// output order.
var tlsAskResults = [3]string{TLSAskAllowed, TLSAskUnknown, TLSAskRefused}

// Counters holds the in-memory counters of the process: usage per tenant,
// HTTP responses per status class, download streams in progress and
// answers of /tls/ask. The zero value is ready to use and every method is
// safe for concurrent use. The cardinality is bounded by the number of
// tenants.
type Counters struct {
	mu      sync.Mutex
	tenants map[string]Usage

	http    [5]atomic.Uint64
	streams atomic.Int64
	tlsAsk  [3]atomic.Uint64
}

var _ Recorder = (*Counters)(nil)

// NewCounters returns empty counters.
func NewCounters() *Counters { return &Counters{} }

// AddUsage implements [Recorder]: it adds u to the counters of tenantID.
// Negative members are ignored (a counter never decreases), and so is an
// empty tenantID.
func (c *Counters) AddUsage(tenantID string, u Usage) {
	if tenantID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tenants == nil {
		c.tenants = map[string]Usage{}
	}
	cur := c.tenants[tenantID]
	cur.Transfers += max(u.Transfers, 0)
	cur.UploadedBytes += max(u.UploadedBytes, 0)
	cur.Downloads += max(u.Downloads, 0)
	cur.DownloadedBytes += max(u.DownloadedBytes, 0)
	cur.VirusDetections += max(u.VirusDetections, 0)
	c.tenants[tenantID] = cur
}

// HTTPRequest implements [Recorder]: it counts a response in the class of
// status (1xx to 5xx). A status outside 100-599 is ignored.
func (c *Counters) HTTPRequest(status int) {
	if i := status/100 - 1; status >= 100 && i < len(c.http) {
		c.http[i].Add(1)
	}
}

// StreamOpened implements [Recorder]: one more download stream.
func (c *Counters) StreamOpened() { c.streams.Add(1) }

// StreamClosed implements [Recorder]: one download stream less. The gauge
// never goes below zero, even after an unbalanced call.
func (c *Counters) StreamClosed() {
	for {
		n := c.streams.Load()
		if n <= 0 || c.streams.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// TLSAsk counts one answer of /tls/ask with result TLSAskAllowed,
// TLSAskUnknown or TLSAskRefused; any other value is ignored.
func (c *Counters) TLSAsk(result string) {
	for i, r := range tlsAskResults {
		if r == result {
			c.tlsAsk[i].Add(1)
			return
		}
	}
}

// countersView is a copy of the counters at one instant.
type countersView struct {
	tenants map[string]Usage
	http    [5]uint64
	streams int64
	tlsAsk  [3]uint64
}

// view returns a copy of the counters.
func (c *Counters) view() countersView {
	c.mu.Lock()
	v := countersView{tenants: maps.Clone(c.tenants)}
	c.mu.Unlock()
	if v.tenants == nil {
		v.tenants = map[string]Usage{}
	}
	for i := range c.http {
		v.http[i] = c.http[i].Load()
	}
	for i := range c.tlsAsk {
		v.tlsAsk[i] = c.tlsAsk[i].Load()
	}
	v.streams = max(c.streams.Load(), 0)
	return v
}
