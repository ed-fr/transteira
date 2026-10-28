package metrics

import (
	"bytes"
	"time"

	"github.com/ed-fr/transteira/internal/health"
)

// renderMetrics writes the snapshot s and the counters v in the text
// exposition format.
func renderMetrics(b *bytes.Buffer, s *snapshot, v countersView) {
	e := newExposition()
	e.add(nameBuildInfo, "1", s.version, s.commit)
	e.add(nameUptime, formatInt(int64(s.uptime()/time.Second)))
	if s.hasMaintenance {
		e.add(nameMaintenance, formatBool(s.maintenance))
	}

	// Usage counters: every tenant of the state (0 without activity yet)
	// and every tenant with activity.
	tenants := map[string]Usage{}
	for _, t := range s.state.Tenants {
		tenants[t.ID] = Usage{}
	}
	for id, u := range v.tenants {
		tenants[id] = u
	}
	for id, u := range tenants {
		e.add(nameTransfers, formatInt(u.Transfers), id)
		e.add(nameUploadedBytes, formatInt(u.UploadedBytes), id)
		e.add(nameDownloads, formatInt(u.Downloads), id)
		e.add(nameDownloadedBytes, formatInt(u.DownloadedBytes), id)
		e.add(nameDetections, formatInt(u.VirusDetections), id)
	}

	if s.hasState {
		st := s.state
		for _, t := range st.Tenants {
			e.add(nameStorageUsed, formatInt(t.StorageUsedBytes), t.ID)
			e.add(nameStorageQuota, formatInt(t.StorageQuotaBytes), t.ID)
			e.add(nameActiveTransfers, formatInt(t.ActiveTransfers), t.ID)
		}
		e.add(nameScanQueue, formatInt(st.ScanQueueFiles))
		e.add(nameDiskUsedRatio, formatFloat(diskRatio(st)))
		e.add(nameDiskUsedBytes, formatUint(st.DiskUsedBytes))
		e.add(nameDiskTotalBytes, formatUint(st.DiskTotalBytes))
		e.add(nameDiskAlert, formatBool(st.DiskAlertActive))
	}
	if s.hasAntivirus {
		e.add(nameAntivirusUp, formatBool(s.antivirusUp))
	}
	if s.hasAVAlert {
		e.add(nameAntivirusAlert, formatBool(s.avAlert))
	}
	e.add(nameDownloadStreams, formatInt(v.streams))
	for i, class := range httpClasses {
		e.add(nameHTTPRequests, formatUint(v.http[i]), class)
	}
	if s.hasWebhook {
		e.add(nameWebhookDeliveries, formatUint(s.webhook.delivered), "delivered")
		e.add(nameWebhookDeliveries, formatUint(s.webhook.failed), "failed")
		e.add(nameWebhookDeliveries, formatUint(s.webhook.dropped), "dropped")
		e.add(nameWebhookDeliveries, formatUint(s.webhook.skippedOpenCircuit), "skipped_open_circuit")
	}
	for name, n := range s.eventsDropped {
		e.add(nameEventsDropped, formatUint(n), name)
	}
	if s.hasSyslog {
		e.add(nameSyslogMessages, formatUint(s.syslog.sent), "sent")
		e.add(nameSyslogMessages, formatUint(s.syslog.failed), "failed")
		e.add(nameSyslogMessages, formatUint(s.syslog.dropped), "dropped")
	}
	if s.hasMail {
		e.add(nameMailDropped, formatUint(s.mailDropped))
		e.add(nameMailQueueLength, formatInt(s.mailLength))
	}
	for task, t := range s.lifecycle {
		e.add(nameLifecycleLastSuccess, formatFloat(float64(t.UnixMilli())/1000), task)
	}
	e.writeTo(b)
}

// diskRatio returns the used ratio of the disk, clamped to [0, 1] (0 for
// an unknown size).
func diskRatio(st InstanceState) float64 {
	if st.DiskTotalBytes == 0 {
		return 0
	}
	return min(float64(st.DiskUsedBytes)/float64(st.DiskTotalBytes), 1)
}

// Overall statuses of the InstanceStatus schema.
const (
	statusOK       = "ok"
	statusDegraded = "degraded"
)

// instanceStatus is the InstanceStatus schema of the OpenAPI document.
type instanceStatus struct {
	Status        string               `json:"status"`
	Version       string               `json:"version"`
	CheckedAt     time.Time            `json:"checkedAt"`
	UptimeSeconds int64                `json:"uptimeSeconds"`
	Maintenance   bool                 `json:"maintenance"`
	Checks        statusChecks         `json:"checks"`
	Disk          statusDisk           `json:"disk"`
	Antivirus     statusAntivirus      `json:"antivirus"`
	Lifecycle     map[string]time.Time `json:"lifecycle,omitempty"`
	Tenants       []statusTenant       `json:"tenants"`
}

// statusChecks is InstanceStatus.checks.
type statusChecks struct {
	Database  health.Status `json:"database"`
	Antivirus health.Status `json:"antivirus"`
	Storage   health.Status `json:"storage"`
}

// statusDisk is InstanceStatus.disk.
type statusDisk struct {
	TotalBytes     uint64  `json:"totalBytes"`
	UsedBytes      uint64  `json:"usedBytes"`
	UsedRatio      float64 `json:"usedRatio"`
	AlertThreshold float64 `json:"alertThreshold"`
	AlertActive    bool    `json:"alertActive"`
}

// statusAntivirus is InstanceStatus.antivirus.
type statusAntivirus struct {
	Engine      string `json:"engine,omitempty"`
	QueuedFiles int64  `json:"queuedFiles"`
	AlertActive bool   `json:"alertActive"`
}

// statusTenant is one row of InstanceStatus.tenants.
type statusTenant struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	StorageUsedBytes  int64   `json:"storageUsedBytes"`
	StorageQuotaBytes int64   `json:"storageQuotaBytes"`
	StorageUsedRatio  float64 `json:"storageUsedRatio"`
	ActiveTransfers   int64   `json:"activeTransfers"`
	TransfersLast24h  int64   `json:"transfersLast24h"`
}

// componentStatus maps a health status to the ComponentHealth enum:
// anything but ok is unavailable.
func componentStatus(st health.Status) health.Status {
	if st == health.StatusOK {
		return health.StatusOK
	}
	return health.StatusUnavailable
}

// buildStatus returns the /status answer of snapshot s. Without a health
// source, every component is reported unavailable.
func buildStatus(s *snapshot) instanceStatus {
	st := s.state
	out := instanceStatus{
		Status:        statusOK,
		Version:       s.version,
		CheckedAt:     s.at.UTC(),
		UptimeSeconds: int64(s.uptime() / time.Second),
		Maintenance:   s.hasMaintenance && s.maintenance,
		Checks: statusChecks{
			Database:  componentStatus(s.health.Database),
			Antivirus: componentStatus(s.health.Antivirus),
			Storage:   componentStatus(s.health.Storage),
		},
		Disk: statusDisk{
			TotalBytes:     st.DiskTotalBytes,
			UsedBytes:      st.DiskUsedBytes,
			UsedRatio:      diskRatio(st),
			AlertThreshold: st.DiskAlertThreshold,
			AlertActive:    st.DiskAlertActive,
		},
		Antivirus: statusAntivirus{
			Engine:      s.engine,
			QueuedFiles: max(st.ScanQueueFiles, 0),
			AlertActive: s.hasAVAlert && s.avAlert,
		},
		Lifecycle: s.lifecycle,
		Tenants:   make([]statusTenant, 0, len(st.Tenants)),
	}
	if !s.hasHealth || !s.health.Healthy() {
		out.Status = statusDegraded
	}
	for _, t := range st.Tenants {
		ratio := 0.0
		if t.StorageQuotaBytes > 0 {
			ratio = max(float64(t.StorageUsedBytes)/float64(t.StorageQuotaBytes), 0)
		}
		out.Tenants = append(out.Tenants, statusTenant{
			ID:                t.ID,
			Name:              t.Name,
			StorageUsedBytes:  max(t.StorageUsedBytes, 0),
			StorageQuotaBytes: max(t.StorageQuotaBytes, 0),
			StorageUsedRatio:  ratio,
			ActiveTransfers:   max(t.ActiveTransfers, 0),
			TransfersLast24h:  max(t.TransfersLast24h, 0),
		})
	}
	return out
}
