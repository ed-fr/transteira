// Package metrics serves the supervision endpoints of the instance: the
// Prometheus metrics (/metrics, text exposition format 0.0.4, written by
// this package without any client library) and the JSON status (/status).
// Both are protected by the monitoring token (TT_METRICS_TOKEN) and the
// optional client allowlist (TT_METRICS_ALLOWED_IPS), threats T-191 to
// T-193.
//
// Gauges are computed by a [Collector] every [CollectInterval] into an
// immutable snapshot; a request never queries the database. Counters
// (_total) live in memory in [Counters] and count since the start of the
// process, the usual Prometheus semantics.
package metrics

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/metrics/metricstate"
)

// CollectInterval is the period of the collector (threat T-192).
const CollectInterval = 15 * time.Second

// The types below are defined in the leaf package metricstate, so that the
// domain packages feeding the supervision (stats, usage) do not depend on the
// HTTP code of this package.
type (
	// TenantState is [metricstate.TenantState].
	TenantState = metricstate.TenantState
	// InstanceState is [metricstate.InstanceState].
	InstanceState = metricstate.InstanceState
	// StateReader is [metricstate.StateReader].
	StateReader = metricstate.StateReader
	// Usage is [metricstate.Usage].
	Usage = metricstate.Usage
)

// HealthFunc runs the component checks of /healthz (health.Service.Run).
type HealthFunc func(ctx context.Context) health.Report

// AntivirusState reports whether the antivirus engine answers.
// *scan.Worker implements it.
type AntivirusState interface {
	Up() bool
}

// AlertState reports whether an alert is raised. *avalert.Monitor
// implements it for the antivirus outage alert.
type AlertState interface {
	Active() bool
}

// MaintenanceState reports the maintenance mode. *maintenance.Mode
// implements it.
type MaintenanceState interface {
	Active() bool
}

// QueueState reports a mail queue. *mail.Queue implements it.
type QueueState interface {
	Len() int
	Dropped() uint64
}

// BusState reports the events dropped per subscriber. *events.Bus
// implements it.
type BusState interface {
	Dropped(subscriber string) uint64
}

// WebhookState reports the webhook deliveries. *webhook.Dispatcher
// implements it.
type WebhookState interface {
	Delivered() uint64
	Failed() uint64
	Dropped() uint64
	SkippedOpenCircuit() uint64
}

// SyslogState reports the syslog export. *syslog.Exporter implements it.
type SyslogState interface {
	Sent() uint64
	Dropped() uint64
	Failed() uint64
}

// LastRunFunc returns the end of the last successful run of a cleanup task,
// zero when it never succeeded (lifecycle.Sweeper.LastRun).
type LastRunFunc func(task string) time.Time

// Sources gathers everything the collector reads. Nil members are skipped:
// their metrics and fields are left out.
type Sources struct {
	State       StateReader
	Health      HealthFunc
	Antivirus   AntivirusState
	AVAlert     AlertState
	Maintenance MaintenanceState
	// Mail lists the mail queues (tenant and system); their lengths and
	// drops are summed.
	Mail    []QueueState
	Bus     BusState
	Webhook WebhookState
	Syslog  SyslogState
	LastRun LastRunFunc
	// Tasks lists the cleanup task names passed to LastRun.
	Tasks []string
	// Subscribers lists the bus subscriber names passed to Bus.Dropped.
	Subscribers []string
	// AntivirusEngine is the engine name reported by /status ("clamd").
	AntivirusEngine string
}

// Recorder is the method set of [*Counters] that the instrumented packages
// call through their own small interfaces: usage (AddUsage) and httpserver
// (requests and download streams). Tenant identifiers are the only label
// values.
type Recorder interface {
	// AddUsage adds u to the counters of the tenant.
	AddUsage(tenantID string, u Usage)
	// HTTPRequest counts a response by its status code.
	HTTPRequest(status int)
	// StreamOpened and StreamClosed track the download streams in progress.
	StreamOpened()
	StreamClosed()
}
