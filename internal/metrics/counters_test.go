package metrics

import (
	"sync"
	"testing"
)

func TestCountersUsage(t *testing.T) {
	t.Parallel()
	var c Counters // the zero value is usable
	c.AddUsage("", Usage{Transfers: 1})
	c.AddUsage("ten_a", Usage{Transfers: 1, UploadedBytes: 10, Downloads: 2, DownloadedBytes: 20, VirusDetections: 1})
	c.AddUsage("ten_a", Usage{Transfers: -5, UploadedBytes: 5, Downloads: -1, DownloadedBytes: -1, VirusDetections: -1})
	v := c.view()
	if len(v.tenants) != 1 {
		t.Fatalf("tenants = %v", v.tenants)
	}
	if got, want := v.tenants["ten_a"], (Usage{Transfers: 1, UploadedBytes: 15, Downloads: 2, DownloadedBytes: 20, VirusDetections: 1}); got != want {
		t.Fatalf("usage = %+v, want %+v", got, want)
	}
	// The view is a copy.
	v.tenants["ten_a"] = Usage{}
	if c.view().tenants["ten_a"].Transfers != 1 {
		t.Fatal("view shares the map")
	}
	if NewCounters().view().tenants == nil {
		t.Fatal("empty view has a nil map")
	}
}

func TestCountersHTTPAndStreams(t *testing.T) {
	t.Parallel()
	c := NewCounters()
	for _, status := range []int{0, 99, 100, 200, 204, 301, 404, 500, 599, 600, -1} {
		c.HTTPRequest(status)
	}
	if got, want := c.view().http, [5]uint64{1, 2, 1, 1, 2}; got != want {
		t.Fatalf("http = %v, want %v", got, want)
	}
	c.StreamClosed() // unbalanced: stays at 0
	c.StreamOpened()
	c.StreamOpened()
	c.StreamClosed()
	if got := c.view().streams; got != 1 {
		t.Fatalf("streams = %d, want 1", got)
	}
	c.StreamClosed()
	c.StreamClosed()
	if got := c.view().streams; got != 0 {
		t.Fatalf("streams = %d, want 0", got)
	}
	c.streams.Store(-3) // defensive clamp of the view
	if got := c.view().streams; got != 0 {
		t.Fatalf("streams = %d, want 0", got)
	}
}

func TestCountersConcurrent(t *testing.T) {
	t.Parallel()
	c := NewCounters()
	const workers, rounds = 8, 500
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tenant := "ten_" + string(rune('a'+w%2))
			for range rounds {
				c.AddUsage(tenant, Usage{Transfers: 1, UploadedBytes: 2})
				c.HTTPRequest(200)
				c.StreamOpened()
				_ = c.view()
				c.StreamClosed()
			}
		}()
	}
	wg.Wait()
	v := c.view()
	if v.tenants["ten_a"].Transfers+v.tenants["ten_b"].Transfers != workers*rounds {
		t.Fatalf("transfers = %v", v.tenants)
	}
	if v.http[1] != workers*rounds || v.streams != 0 {
		t.Fatalf("http = %v, streams = %d", v.http, v.streams)
	}
}
