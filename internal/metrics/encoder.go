package metrics

import (
	"bytes"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ContentType is the media type of the Prometheus text exposition format
// 0.0.4 served by /metrics.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// MetricType is the TYPE of a metric family.
type MetricType string

// Metric types of the catalog.
const (
	Counter MetricType = "counter"
	Gauge   MetricType = "gauge"
)

// Desc describes one metric family of the catalog.
type Desc struct {
	// Name is the full metric name, prefixed with transteira_.
	Name string
	// Type is counter or gauge.
	Type MetricType
	// Help is the HELP text.
	Help string
	// Labels lists the label names of the samples, in output order.
	Labels []string
}

// Metric names, all prefixed with transteira_.
const (
	nameBuildInfo            = "transteira_build_info"
	nameUptime               = "transteira_uptime_seconds"
	nameMaintenance          = "transteira_maintenance"
	nameTransfers            = "transteira_transfers_total"
	nameUploadedBytes        = "transteira_uploaded_bytes_total"
	nameDownloads            = "transteira_downloads_total"
	nameDownloadedBytes      = "transteira_downloaded_bytes_total"
	nameDetections           = "transteira_antivirus_detections_total"
	nameStorageUsed          = "transteira_storage_used_bytes"
	nameStorageQuota         = "transteira_storage_quota_bytes"
	nameActiveTransfers      = "transteira_active_transfers"
	nameScanQueue            = "transteira_scan_queue_files"
	nameAntivirusUp          = "transteira_antivirus_up"
	nameAntivirusAlert       = "transteira_antivirus_alert"
	nameDiskUsedRatio        = "transteira_disk_used_ratio"
	nameDiskUsedBytes        = "transteira_disk_used_bytes"
	nameDiskTotalBytes       = "transteira_disk_total_bytes"
	nameDiskAlert            = "transteira_disk_alert"
	nameDownloadStreams      = "transteira_download_streams"
	nameHTTPRequests         = "transteira_http_requests_total"
	nameWebhookDeliveries    = "transteira_webhook_deliveries_total"
	nameEventsDropped        = "transteira_events_dropped_total"
	nameSyslogMessages       = "transteira_syslog_messages_total"
	nameMailDropped          = "transteira_mail_dropped_total"
	nameMailQueueLength      = "transteira_mail_queue_length"
	nameLifecycleLastSuccess = "transteira_lifecycle_last_success_timestamp_seconds"
)

// Label names.
const (
	labelVersion    = "version"
	labelCommit     = "commit"
	labelTenant     = "tenant"
	labelClass      = "class"
	labelResult     = "result"
	labelSubscriber = "subscriber"
	labelTask       = "task"
)

// catalog is the fixed list of the metric families, in output order.
// Names are never renamed within 1.x (OpenAPI getMetrics).
var catalog = []Desc{
	{nameBuildInfo, Gauge, "Version of the running instance.", []string{labelVersion, labelCommit}},
	{nameUptime, Gauge, "Seconds since the start of the process.", nil},
	{nameMaintenance, Gauge, "Whether maintenance mode is active (1) or not (0).", nil},
	{nameTransfers, Counter, "Transfers made available, per tenant.", []string{labelTenant}},
	{nameUploadedBytes, Counter, "Bytes of the transfers made available, per tenant.", []string{labelTenant}},
	{nameDownloads, Counter, "Downloads served, per tenant.", []string{labelTenant}},
	{nameDownloadedBytes, Counter, "Bytes downloaded, per tenant.", []string{labelTenant}},
	{nameDetections, Counter, "Files found infected, per tenant.", []string{labelTenant}},
	{nameStorageUsed, Gauge, "Storage used, per tenant.", []string{labelTenant}},
	{nameStorageQuota, Gauge, "Storage quota, per tenant.", []string{labelTenant}},
	{nameActiveTransfers, Gauge, "Transfers currently available, per tenant.", []string{labelTenant}},
	{nameScanQueue, Gauge, "Files waiting for or under analysis.", nil},
	{nameAntivirusUp, Gauge, "Whether the antivirus engine answers (1) or not (0).", nil},
	{nameAntivirusAlert, Gauge, "Whether the antivirus outage alert is raised (1) or not (0).", nil},
	{nameDiskUsedRatio, Gauge, "Usage of the filesystem holding the data directory.", nil},
	{nameDiskUsedBytes, Gauge, "Bytes used on the filesystem holding the data directory.", nil},
	{nameDiskTotalBytes, Gauge, "Size of the filesystem holding the data directory, in bytes.", nil},
	{nameDiskAlert, Gauge, "Whether the disk space alert is raised (1) or not (0).", nil},
	{nameDownloadStreams, Gauge, "Download streams in progress.", nil},
	{nameHTTPRequests, Counter, "HTTP requests, per status class.", []string{labelClass}},
	{nameWebhookDeliveries, Counter, "Webhook deliveries, per result.", []string{labelResult}},
	{nameEventsDropped, Counter, "Internal events dropped because a subscriber queue was full, per subscriber.", []string{labelSubscriber}},
	{nameSyslogMessages, Counter, "Syslog messages, per result.", []string{labelResult}},
	{nameMailDropped, Counter, "Mails dropped when a tenant circuit opened or at shutdown.", nil},
	{nameMailQueueLength, Gauge, "Mails waiting in the queues.", nil},
	{nameLifecycleLastSuccess, Gauge, "End of the last successful run of each cleanup task, as a Unix timestamp.", []string{labelTask}},
}

// Catalog returns the metric families exposed by /metrics, in output
// order. The list is stable: names are only added, never renamed within
// 1.x. The result is a copy the caller may modify.
func Catalog() []Desc {
	out := make([]Desc, len(catalog))
	for i, d := range catalog {
		d.Labels = slices.Clone(d.Labels)
		out[i] = d
	}
	return out
}

// sample is one line of a family: its label values (in the order of
// Desc.Labels) and its formatted value.
type sample struct {
	labels []string
	value  string
}

// exposition accumulates samples per family and writes them in the text
// format, in catalog order. Families without samples are left out, and
// so are names absent from the catalog.
type exposition struct {
	samples map[string][]sample
}

// newExposition returns an empty exposition.
func newExposition() *exposition {
	return &exposition{samples: map[string][]sample{}}
}

// add appends a sample of family name with the formatted value and the
// label values, in the order of the family's Desc.Labels.
func (e *exposition) add(name, value string, labelValues ...string) {
	e.samples[name] = append(e.samples[name], sample{labels: labelValues, value: value})
}

// writeTo writes every family with samples to b: HELP and TYPE lines, then
// the samples sorted by label values.
func (e *exposition) writeTo(b *bytes.Buffer) {
	for _, d := range catalog {
		samples := e.samples[d.Name]
		if len(samples) == 0 {
			continue
		}
		slices.SortStableFunc(samples, func(x, y sample) int { return slices.Compare(x.labels, y.labels) })
		b.WriteString("# HELP " + d.Name + " " + escapeHelp(d.Help) + "\n")
		b.WriteString("# TYPE " + d.Name + " " + string(d.Type) + "\n")
		for _, s := range samples {
			b.WriteString(d.Name)
			if len(d.Labels) > 0 {
				b.WriteByte('{')
				for i, l := range d.Labels {
					if i > 0 {
						b.WriteByte(',')
					}
					v := ""
					if i < len(s.labels) {
						v = s.labels[i]
					}
					b.WriteString(l + `="` + escapeLabel(v) + `"`)
				}
				b.WriteByte('}')
			}
			b.WriteString(" " + s.value + "\n")
		}
	}
}

// labelEscaper escapes a label value: backslash, double quote and line
// feed (text format 0.0.4).
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// helpEscaper escapes a HELP text: backslash and line feed.
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

// escapeLabel returns v escaped for a label value, invalid UTF-8 replaced
// by U+FFFD (label values must be UTF-8).
func escapeLabel(v string) string {
	return labelEscaper.Replace(toValidUTF8(v))
}

// escapeHelp returns h escaped for a HELP line.
func escapeHelp(h string) string {
	return helpEscaper.Replace(toValidUTF8(h))
}

// toValidUTF8 replaces the invalid UTF-8 sequences of s by U+FFFD.
func toValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// formatFloat formats v as Prometheus expects: NaN, +Inf and -Inf by name,
// integral values below 2^53 without exponent nor fraction, others in the
// shortest representation, without exponent between 1e-4 and 1e21.
func formatFloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case v == math.Trunc(v) && math.Abs(v) < 1<<53:
		return strconv.FormatInt(int64(v), 10)
	case math.Abs(v) >= 1e-4 && math.Abs(v) < 1e21:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// formatInt formats an integer value.
func formatInt(v int64) string { return strconv.FormatInt(v, 10) }

// formatUint formats an unsigned integer value.
func formatUint(v uint64) string { return strconv.FormatUint(v, 10) }

// formatBool formats a boolean gauge: 1 or 0.
func formatBool(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
