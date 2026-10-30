package metrics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/health"
)

// testNow is the fixed clock of the tests.
var testNow = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

// fakeState is a StateReader returning state or err, counting the calls.
type fakeState struct {
	mu    sync.Mutex
	state InstanceState
	err   error
	calls int
	block chan struct{} // when set, InstanceState waits for it or ctx
}

func (f *fakeState) InstanceState(ctx context.Context) (InstanceState, error) {
	f.mu.Lock()
	f.calls++
	st, err, block := f.state, f.err, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return InstanceState{}, ctx.Err()
		}
	}
	return st, err
}

func (f *fakeState) set(st InstanceState, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state, f.err = st, err
}

func (f *fakeState) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type flag bool

func (f flag) Up() bool     { return bool(f) }
func (f flag) Active() bool { return bool(f) }

type fakeQueue struct {
	n       int
	dropped uint64
}

func (q fakeQueue) Len() int        { return q.n }
func (q fakeQueue) Dropped() uint64 { return q.dropped }

type fakeBus map[string]uint64

func (b fakeBus) Dropped(name string) uint64 { return b[name] }

type fakeWebhook struct{ delivered, failed, dropped, skipped uint64 }

func (w fakeWebhook) Delivered() uint64          { return w.delivered }
func (w fakeWebhook) Failed() uint64             { return w.failed }
func (w fakeWebhook) Dropped() uint64            { return w.dropped }
func (w fakeWebhook) SkippedOpenCircuit() uint64 { return w.skipped }

type fakeSyslog struct{ sent, failed, dropped uint64 }

func (s fakeSyslog) Sent() uint64    { return s.sent }
func (s fakeSyslog) Failed() uint64  { return s.failed }
func (s fakeSyslog) Dropped() uint64 { return s.dropped }

// fullState is a state with two tenants, in reverse ID order.
func fullState() InstanceState {
	return InstanceState{
		DiskTotalBytes: 1000, DiskUsedBytes: 300, DiskAlertThreshold: 0.85,
		ScanQueueFiles: 2,
		Tenants: []TenantState{
			{ID: "ten_B", Name: `Entity "B"`},
			{ID: "ten_A", Name: "Entity A", StorageUsedBytes: 250, StorageQuotaBytes: 1000, ActiveTransfers: 3, TransfersLast24h: 2},
		},
	}
}

// fullSources returns sources with every member set.
func fullSources(st *fakeState) Sources {
	okReport := health.Report{Database: health.StatusOK, Antivirus: health.StatusOK, Storage: health.StatusOK}
	return Sources{
		State:       st,
		Health:      func(context.Context) health.Report { return okReport },
		Antivirus:   flag(true),
		AVAlert:     flag(false),
		Maintenance: flag(true),
		Mail:        []QueueState{fakeQueue{2, 1}, nil, fakeQueue{1, 0}},
		Bus:         fakeBus{"webhook": 2},
		Webhook:     fakeWebhook{5, 1, 0, 2},
		Syslog:      fakeSyslog{7, 1, 2},
		LastRun: func(task string) time.Time {
			if task == "expire" {
				return time.Date(2026, 10, 27, 10, 59, 30, 500e6, time.FixedZone("CET", 2*3600))
			}
			return time.Time{}
		},
		Tasks:                   []string{"expire", "backup"},
		Subscribers:             []string{"webhook", "mail"},
		AntivirusEngine:         "clamd",
		AntivirusSelfTestPassed: func() bool { return true },
	}
}

// fullCounters returns counters with activity on ten_A and on ten_C, a
// tenant absent from the state.
func fullCounters() *Counters {
	c := NewCounters()
	c.AddUsage("ten_A", Usage{Transfers: 1, UploadedBytes: 100, Downloads: 2, DownloadedBytes: 200})
	c.AddUsage("ten_C", Usage{Transfers: 1, UploadedBytes: 10, VirusDetections: 1})
	for range 10 {
		c.HTTPRequest(200)
	}
	c.HTTPRequest(503)
	c.StreamOpened()
	c.StreamOpened()
	return c
}

// newTestCollector returns a collector of src with the fixed clock and a
// start 864000 seconds before it.
func newTestCollector(src Sources, c *Counters, opts ...CollectorOption) *Collector {
	col := NewCollector(src, c, append([]CollectorOption{
		WithClock(func() time.Time { return testNow }),
		WithStartTime(testNow.Add(-864000 * time.Second)),
	}, opts...)...)
	col.build.Version, col.build.Commit = "1.1.0", "3f9c2ab"
	return col
}

const goldenMetrics = `# HELP transteira_build_info Version of the running instance.
# TYPE transteira_build_info gauge
transteira_build_info{version="1.1.0",commit="3f9c2ab"} 1
# HELP transteira_uptime_seconds Seconds since the start of the process.
# TYPE transteira_uptime_seconds gauge
transteira_uptime_seconds 864000
# HELP transteira_maintenance Whether maintenance mode is active (1) or not (0).
# TYPE transteira_maintenance gauge
transteira_maintenance 1
# HELP transteira_transfers_total Transfers made available, per tenant.
# TYPE transteira_transfers_total counter
transteira_transfers_total{tenant="ten_A"} 1
transteira_transfers_total{tenant="ten_B"} 0
transteira_transfers_total{tenant="ten_C"} 1
# HELP transteira_uploaded_bytes_total Bytes of the transfers made available, per tenant.
# TYPE transteira_uploaded_bytes_total counter
transteira_uploaded_bytes_total{tenant="ten_A"} 100
transteira_uploaded_bytes_total{tenant="ten_B"} 0
transteira_uploaded_bytes_total{tenant="ten_C"} 10
# HELP transteira_downloads_total Downloads served, per tenant.
# TYPE transteira_downloads_total counter
transteira_downloads_total{tenant="ten_A"} 2
transteira_downloads_total{tenant="ten_B"} 0
transteira_downloads_total{tenant="ten_C"} 0
# HELP transteira_downloaded_bytes_total Bytes downloaded, per tenant.
# TYPE transteira_downloaded_bytes_total counter
transteira_downloaded_bytes_total{tenant="ten_A"} 200
transteira_downloaded_bytes_total{tenant="ten_B"} 0
transteira_downloaded_bytes_total{tenant="ten_C"} 0
# HELP transteira_antivirus_detections_total Files found infected, per tenant.
# TYPE transteira_antivirus_detections_total counter
transteira_antivirus_detections_total{tenant="ten_A"} 0
transteira_antivirus_detections_total{tenant="ten_B"} 0
transteira_antivirus_detections_total{tenant="ten_C"} 1
# HELP transteira_storage_used_bytes Storage used, per tenant.
# TYPE transteira_storage_used_bytes gauge
transteira_storage_used_bytes{tenant="ten_A"} 250
transteira_storage_used_bytes{tenant="ten_B"} 0
# HELP transteira_storage_quota_bytes Storage quota, per tenant.
# TYPE transteira_storage_quota_bytes gauge
transteira_storage_quota_bytes{tenant="ten_A"} 1000
transteira_storage_quota_bytes{tenant="ten_B"} 0
# HELP transteira_active_transfers Transfers currently available, per tenant.
# TYPE transteira_active_transfers gauge
transteira_active_transfers{tenant="ten_A"} 3
transteira_active_transfers{tenant="ten_B"} 0
# HELP transteira_scan_queue_files Files waiting for or under analysis.
# TYPE transteira_scan_queue_files gauge
transteira_scan_queue_files 2
# HELP transteira_antivirus_up Whether the antivirus engine answers (1) or not (0).
# TYPE transteira_antivirus_up gauge
transteira_antivirus_up 1
# HELP transteira_antivirus_alert Whether the antivirus outage alert is raised (1) or not (0).
# TYPE transteira_antivirus_alert gauge
transteira_antivirus_alert 0
# HELP transteira_disk_used_ratio Usage of the filesystem holding the data directory.
# TYPE transteira_disk_used_ratio gauge
transteira_disk_used_ratio 0.3
# HELP transteira_disk_used_bytes Bytes used on the filesystem holding the data directory.
# TYPE transteira_disk_used_bytes gauge
transteira_disk_used_bytes 300
# HELP transteira_disk_total_bytes Size of the filesystem holding the data directory, in bytes.
# TYPE transteira_disk_total_bytes gauge
transteira_disk_total_bytes 1000
# HELP transteira_disk_alert Whether the disk space alert is raised (1) or not (0).
# TYPE transteira_disk_alert gauge
transteira_disk_alert 0
# HELP transteira_download_streams Download streams in progress.
# TYPE transteira_download_streams gauge
transteira_download_streams 2
# HELP transteira_http_requests_total HTTP requests, per status class.
# TYPE transteira_http_requests_total counter
transteira_http_requests_total{class="1xx"} 0
transteira_http_requests_total{class="2xx"} 10
transteira_http_requests_total{class="3xx"} 0
transteira_http_requests_total{class="4xx"} 0
transteira_http_requests_total{class="5xx"} 1
# HELP transteira_webhook_deliveries_total Webhook deliveries, per result.
# TYPE transteira_webhook_deliveries_total counter
transteira_webhook_deliveries_total{result="delivered"} 5
transteira_webhook_deliveries_total{result="dropped"} 0
transteira_webhook_deliveries_total{result="failed"} 1
transteira_webhook_deliveries_total{result="skipped_open_circuit"} 2
# HELP transteira_events_dropped_total Internal events dropped because a subscriber queue was full, per subscriber.
# TYPE transteira_events_dropped_total counter
transteira_events_dropped_total{subscriber="mail"} 0
transteira_events_dropped_total{subscriber="webhook"} 2
# HELP transteira_syslog_messages_total Syslog messages, per result.
# TYPE transteira_syslog_messages_total counter
transteira_syslog_messages_total{result="dropped"} 2
transteira_syslog_messages_total{result="failed"} 1
transteira_syslog_messages_total{result="sent"} 7
# HELP transteira_mail_dropped_total Mails dropped when a tenant circuit opened or at shutdown.
# TYPE transteira_mail_dropped_total counter
transteira_mail_dropped_total 1
# HELP transteira_mail_queue_length Mails waiting in the queues.
# TYPE transteira_mail_queue_length gauge
transteira_mail_queue_length 3
# HELP transteira_lifecycle_last_success_timestamp_seconds End of the last successful run of each cleanup task, as a Unix timestamp.
# TYPE transteira_lifecycle_last_success_timestamp_seconds gauge
transteira_lifecycle_last_success_timestamp_seconds{task="expire"} 1793091570.5
`

// render returns the metrics text of the current snapshot of col.
func render(t *testing.T, col *Collector) string {
	t.Helper()
	s := col.snapshot()
	if s == nil {
		t.Fatal("no snapshot")
	}
	var b bytes.Buffer
	renderMetrics(&b, s, col.Counters().view())
	return b.String()
}

func TestRenderGolden(t *testing.T) {
	t.Parallel()
	col := newTestCollector(fullSources(&fakeState{state: fullState()}), fullCounters())
	col.collect(t.Context())
	got := render(t, col)
	if got != goldenMetrics {
		t.Fatalf("got:\n%s\nwant:\n%s", got, goldenMetrics)
	}
	parseExposition(t, got)
}

func TestRenderNilSources(t *testing.T) {
	t.Parallel()
	col := newTestCollector(Sources{}, nil)
	col.collect(t.Context())
	got := parseExposition(t, render(t, col))
	want := map[string]bool{nameBuildInfo: true, nameUptime: true, nameDownloadStreams: true, nameHTTPRequests: true}
	for name := range got {
		if !want[name] {
			t.Errorf("unexpected family %s without sources", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("families = %d, want %d", len(got), len(want))
	}
}

func TestDiskRatioClamped(t *testing.T) {
	t.Parallel()
	if r := diskRatio(InstanceState{DiskUsedBytes: 5}); r != 0 {
		t.Fatalf("ratio without size = %v", r)
	}
	if r := diskRatio(InstanceState{DiskUsedBytes: 5, DiskTotalBytes: 4}); r != 1 {
		t.Fatalf("ratio over size = %v", r)
	}
	s := &snapshot{at: testNow, started: testNow.Add(time.Hour)}
	if s.uptime() != 0 {
		t.Fatal("negative uptime")
	}
}

func TestCollectorStateErrorKeepsPrevious(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	st := &fakeState{err: errors.New("database is locked")}
	col := newTestCollector(Sources{State: st}, nil, WithLogger(logger), WithLogger(nil))

	// A failure before any success: no state.
	col.collect(t.Context())
	if s := col.snapshot(); s.hasState {
		t.Fatal("state without a successful read")
	}
	st.set(fullState(), nil)
	col.collect(t.Context())
	s := col.snapshot()
	if !s.hasState || len(s.state.Tenants) != 2 || s.state.Tenants[0].ID != "ten_A" {
		t.Fatalf("state = %+v", s.state)
	}
	st.set(InstanceState{}, errors.New("database is locked"))
	col.collect(t.Context())
	if s2 := col.snapshot(); s2 == s || !s2.hasState || s2.state.DiskUsedBytes != 300 {
		t.Fatalf("previous state not kept: %+v", s2.state)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 2 {
		t.Fatalf("%d warnings logged, want 2:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "database is locked") {
		t.Fatalf("error not logged:\n%s", logs.String())
	}
}

func TestCollectorStartAndClose(t *testing.T) {
	t.Parallel()
	st := &fakeState{state: fullState()}
	col := NewCollector(Sources{State: st}, nil, WithInterval(time.Millisecond), WithInterval(0))
	if col.interval != time.Millisecond {
		t.Fatalf("interval = %v", col.interval)
	}
	if col.snapshot() != nil {
		t.Fatal("snapshot before Start")
	}
	if err := col.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if col.snapshot() == nil {
		t.Fatal("Start did not collect synchronously")
	}
	if err := col.Start(t.Context()); !errors.Is(err, ErrStarted) {
		t.Fatalf("second Start = %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for st.count() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("the loop does not collect")
		}
		time.Sleep(time.Millisecond)
	}
	if err := col.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := col.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := col.Start(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close = %v", err)
	}
}

func TestCollectorCloseNotStarted(t *testing.T) {
	t.Parallel()
	before := time.Now()
	col := NewCollector(Sources{}, nil)
	if col.started.Before(before) {
		t.Fatal("start time not defaulted to now")
	}
	if err := col.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorCloseTimeout(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	release := make(chan struct{})
	src := Sources{Health: func(context.Context) health.Report {
		if calls.Add(1) > 1 {
			<-release // a stuck source ignoring its context
		}
		return health.Report{}
	}}
	col := NewCollector(src, nil, WithInterval(time.Millisecond))
	if err := col.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the loop does not collect")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := col.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v, want context.Canceled", err)
	}
	close(release)
	if err := col.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
