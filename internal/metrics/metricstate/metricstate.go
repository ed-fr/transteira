// Package metricstate holds the data types exchanged between the
// supervision (package metrics) and the domain packages that feed it
// (stats, usage). It imports nothing from the application, so those
// packages never depend on the HTTP code of package metrics.
package metricstate

import "context"

// TenantState is the state of one active tenant read at each collection.
type TenantState struct {
	// ID is the tenant identifier (ten_...), the only tenant label.
	ID string
	// Name is the tenant display name, shown in /status only.
	Name string
	// StorageUsedBytes is the storage currently used by the tenant.
	StorageUsedBytes int64
	// StorageQuotaBytes is the storage quota of the tenant.
	StorageQuotaBytes int64
	// ActiveTransfers counts the transfers currently available.
	ActiveTransfers int64
	// TransfersLast24h counts the transfers made available during the last
	// 24 hours.
	TransfersLast24h int64
	// SecretFileBytes sums the declared sizes of the stored one-time secret
	// files, counted in StorageUsedBytes (since 2.1).
	SecretFileBytes int64
	// SecretsCreatedLast24h, SecretsReadLast24h and SecretsLockedLast24h
	// count the one-time secrets created, read and locked during the last
	// 24 hours, among the secret rows still present (since 2.1).
	SecretsCreatedLast24h, SecretsReadLast24h, SecretsLockedLast24h int64
}

// InstanceState is what the collector reads from the database and the
// disk at each collection.
type InstanceState struct {
	// DiskTotalBytes and DiskUsedBytes measure the filesystem holding the
	// data directory.
	DiskTotalBytes, DiskUsedBytes uint64
	// DiskAlertThreshold is the disk alert threshold, as a ratio in (0, 1].
	DiskAlertThreshold float64
	// DiskAlertActive is true while the disk alert is raised.
	DiskAlertActive bool
	// ScanQueueFiles counts the files waiting for or under analysis.
	ScanQueueFiles int64
	// Tenants has one row per active tenant, sorted by ID.
	Tenants []TenantState
}

// StateReader reads the [InstanceState] without any principal: it is only
// called by the collector. *stats.Service implements it.
type StateReader interface {
	InstanceState(ctx context.Context) (InstanceState, error)
}

// Usage is an increment of the per-tenant counters, mirroring the daily
// usage aggregate (store.UsageCounts) recorded at the same place. The
// one-time secrets read and locked have no daily aggregate: they are only
// counted in memory.
type Usage struct {
	Transfers       int64
	UploadedBytes   int64
	Downloads       int64
	DownloadedBytes int64
	VirusDetections int64
	// SecretsCreated, SecretsRead and SecretsLocked count the one-time
	// secrets created, read and locked after wrong proofs (since 2.1).
	SecretsCreated int64
	SecretsRead    int64
	SecretsLocked  int64
}
