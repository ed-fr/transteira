// Package stats computes the dashboard statistics of the administration
// (CLAUDE.md section 21.2): per tenant, the volumes, transfers, downloads
// and antivirus detections of a period with their breakdown, and the
// storage used against the quota; for the super admin, the disk usage and
// one row per active tenant.
//
// # Definitions
//
// The counters come from the daily usage aggregates ([store.TenantUsage]),
// which hold no personal data:
//
//   - transfers and bytes uploaded: the transfers finalized during the
//     period and their declared size, whatever happened to them afterwards;
//   - downloads: the download starts of a file (a GET without Range, or
//     with a range starting at 0) or of the archive, never HEAD requests;
//   - bytes downloaded: the clear bytes served;
//   - virus detections: the files found infected.
//
// The days are UTC days. The 7d and 30d periods are broken down by day (7
// and 30 points, today included), the 12m period by calendar month (12
// points, the current month included, each dated on the first day of its
// month). Every point is present, zero-filled when there was no activity.
// The storage figures are the current values.
package stats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/diskusage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DefaultDiskAlertThreshold is the share of the disk above which the super
// admin is alerted, reported by the global statistics until the runtime
// system settings exist.
const DefaultDiskAlertThreshold = 0.85

// Period is a statistics period.
type Period string

// Periods.
const (
	// Period7Days is the last 7 UTC days, today included, by day.
	Period7Days Period = "7d"
	// Period30Days is the last 30 UTC days, today included, by day.
	Period30Days Period = "30d"
	// Period12Months is the last 12 calendar months (UTC), the current one
	// included, by month.
	Period12Months Period = "12m"
	// DefaultPeriod is the period of a request without one.
	DefaultPeriod = Period30Days
)

var (
	// ErrInvalidPeriod reports an unknown period (400 validation-failed).
	ErrInvalidPeriod = errors.New("stats: invalid period")
	// ErrNotFound reports a missing tenant, a tenant being deleted or a
	// tenant the caller is not attached to (404 not-found). It is
	// [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrForbidden reports a global statistics request by an administrator
	// other than a super admin (403 forbidden). It is
	// [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
)

// ParsePeriod returns the period named s, DefaultPeriod for "", and
// ErrInvalidPeriod otherwise.
func ParsePeriod(s string) (Period, error) {
	switch p := Period(s); p {
	case "":
		return DefaultPeriod, nil
	case Period7Days, Period30Days, Period12Months:
		return p, nil
	}
	return "", ErrInvalidPeriod
}

// Point is the activity of one day or one month of a period.
type Point struct {
	// Date is 00:00 UTC of the day, or of the first day of the month.
	Date time.Time
	// Transfers counts the transfers finalized.
	Transfers int64
	// BytesUploaded sums their declared sizes.
	BytesUploaded int64
}

// Storage is the current storage of a tenant.
type Storage struct {
	// UsedBytes is the storage used: the declared sizes of the transfers
	// uploading, scanning or available.
	UsedBytes int64
	// QuotaBytes is the storage quota.
	QuotaBytes int64
	// UsedRatio is UsedBytes / QuotaBytes (may exceed 1; 0 without quota).
	UsedRatio float64
}

// TenantStats are the statistics of a tenant over a period.
type TenantStats struct {
	// Period is the period of the counters.
	Period Period
	// Counters are the totals over the period.
	store.UsageCounts
	// Storage is the current storage.
	Storage
	// Series breaks Transfers and BytesUploaded down over the period,
	// oldest first.
	Series []Point
}

// Disk is the usage of the filesystem holding the data directory.
type Disk struct {
	// TotalBytes is the size of the filesystem.
	TotalBytes uint64
	// UsedBytes is TotalBytes minus the space available.
	UsedBytes uint64
	// UsedRatio is UsedBytes / TotalBytes (0 for an empty filesystem).
	UsedRatio float64
	// AlertThreshold is the ratio above which the super admin is alerted.
	AlertThreshold float64
}

// TenantRow is the row of a tenant in the global statistics.
type TenantRow struct {
	// TenantID and Name identify the tenant.
	TenantID tenant.ID
	Name     string
	// Transfers and BytesUploaded are the totals over the period.
	Transfers     int64
	BytesUploaded int64
	// Storage is the current storage.
	Storage
}

// GlobalStats are the statistics of the instance over a period.
type GlobalStats struct {
	// Period is the period of the counters.
	Period Period
	// Disk is the current disk usage.
	Disk Disk
	// Tenants has one row per active tenant, by ID.
	Tenants []TenantRow
}

// repo is the data the service reads. storeRepo implements it.
type repo interface {
	tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	activeTenants(ctx context.Context) ([]*tenant.Tenant, error)
	usedBytes(ctx context.Context, tid tenant.ID) (int64, error)
	usedBytesAll(ctx context.Context) (map[tenant.ID]int64, error)
	usage(ctx context.Context, tid tenant.ID, fromDay time.Time) ([]store.DailyUsage, error)
	usageAll(ctx context.Context, fromDay time.Time) (map[tenant.ID]store.UsageCounts, error)
}

// Options configure a Service.
type Options struct {
	// DataDir is the data directory (encrypted files), whose filesystem the
	// global statistics measure (required).
	DataDir string
	// Now is the clock (time.Now).
	Now func() time.Time
	// Logger receives the disk measure failures (discarded when nil).
	Logger *slog.Logger
}

// Service computes the statistics. It is safe for concurrent use.
type Service struct {
	repo    repo
	dataDir string
	measure func(path string) (total, free uint64, err error)
	now     func() time.Time
	logger  *slog.Logger
}

// errInvalidOptions reports a [New] call without a database or data
// directory.
var errInvalidOptions = errors.New("stats: database and data directory required")

// New returns the service over db.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil || opts.DataDir == "" {
		return nil, errInvalidOptions
	}
	return newService(storeRepo{db: db}, opts), nil
}

// newService returns the service over r.
func newService(r repo, opts Options) *Service {
	s := &Service{repo: r, dataDir: opts.DataDir, measure: diskusage.Measure, now: opts.Now, logger: opts.Logger}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	return s
}

// TenantStats returns the statistics of tenant tid over period, for p.
// It returns adminauth.ErrUnauthenticated for a session that is not
// authenticated, ErrNotFound for a tenant p may not read, missing or being
// deleted, and ErrInvalidPeriod for an unknown period, checked after the
// access so that a tenant p may not read answers ErrNotFound whatever the
// period. An empty period is DefaultPeriod.
func (s *Service) TenantStats(ctx context.Context, p adminauth.Principal, tid tenant.ID, period Period) (TenantStats, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return TenantStats{}, err
	}
	if err := adminauth.RequireTenantAccess(p.Admin, tid); err != nil {
		return TenantStats{}, err
	}
	period, err := ParsePeriod(string(period))
	if err != nil {
		return TenantStats{}, err
	}
	w := newWindow(period, s.now())
	t, err := s.repo.tenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return TenantStats{}, ErrNotFound
	case err != nil:
		return TenantStats{}, fmt.Errorf("stats: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return TenantStats{}, ErrNotFound
	}
	days, err := s.repo.usage(ctx, tid, w.from)
	if err != nil {
		return TenantStats{}, fmt.Errorf("stats: read usage: %w", err)
	}
	used, err := s.repo.usedBytes(ctx, tid)
	if err != nil {
		return TenantStats{}, fmt.Errorf("stats: read storage used: %w", err)
	}
	out := TenantStats{Period: period, Storage: storage(used, t.StorageQuotaBytes), Series: w.points()}
	for _, d := range days {
		i := w.index(d.Day)
		if i < 0 {
			continue // after today (clock skew): outside the period
		}
		out.Series[i].Transfers += d.Transfers
		out.Series[i].BytesUploaded += d.BytesUploaded
		out.UsageCounts = add(out.UsageCounts, d.UsageCounts)
	}
	return out, nil
}

// GlobalStats returns the statistics of the instance over period, for p.
// It returns adminauth.ErrUnauthenticated for a session that is not
// authenticated, ErrForbidden unless p is a super admin, ErrInvalidPeriod
// for an unknown period (checked after the role; empty is DefaultPeriod),
// and an error when the disk cannot be measured
// (logged; never reported as zeros).
func (s *Service) GlobalStats(ctx context.Context, p adminauth.Principal, period Period) (GlobalStats, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return GlobalStats{}, err
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return GlobalStats{}, err
	}
	period, err := ParsePeriod(string(period))
	if err != nil {
		return GlobalStats{}, err
	}
	w := newWindow(period, s.now())
	total, free, err := s.measure(s.dataDir)
	if err != nil {
		s.logger.ErrorContext(ctx, "stats: disk usage unavailable", slog.String("error", err.Error()))
		return GlobalStats{}, fmt.Errorf("stats: measure disk: %w", err)
	}
	tenants, err := s.repo.activeTenants(ctx)
	if err != nil {
		return GlobalStats{}, fmt.Errorf("stats: list tenants: %w", err)
	}
	usage, err := s.repo.usageAll(ctx, w.from)
	if err != nil {
		return GlobalStats{}, fmt.Errorf("stats: read usage: %w", err)
	}
	used, err := s.repo.usedBytesAll(ctx)
	if err != nil {
		return GlobalStats{}, fmt.Errorf("stats: read storage used: %w", err)
	}
	out := GlobalStats{Period: period, Disk: disk(total, free), Tenants: make([]TenantRow, 0, len(tenants))}
	for _, t := range tenants {
		u := usage[t.ID]
		out.Tenants = append(out.Tenants, TenantRow{
			TenantID: t.ID, Name: t.Name, Transfers: u.Transfers, BytesUploaded: u.BytesUploaded,
			Storage: storage(used[t.ID], t.StorageQuotaBytes),
		})
	}
	return out, nil
}

// storage returns the storage figures of used bytes of a quota.
func storage(used, quota int64) Storage {
	s := Storage{UsedBytes: used, QuotaBytes: quota}
	if quota > 0 {
		s.UsedRatio = float64(used) / float64(quota)
	}
	return s
}

// disk returns the disk figures of a filesystem of total bytes with free
// bytes available (free <= total, see diskusage.Measure).
func disk(total, free uint64) Disk {
	d := Disk{TotalBytes: total, UsedBytes: total - min(free, total), AlertThreshold: DefaultDiskAlertThreshold}
	if total > 0 {
		d.UsedRatio = float64(d.UsedBytes) / float64(total)
	}
	return d
}

// add returns the counters a + b.
func add(a, b store.UsageCounts) store.UsageCounts {
	return store.UsageCounts{
		Transfers:       a.Transfers + b.Transfers,
		BytesUploaded:   a.BytesUploaded + b.BytesUploaded,
		Downloads:       a.Downloads + b.Downloads,
		BytesDownloaded: a.BytesDownloaded + b.BytesDownloaded,
		VirusDetections: a.VirusDetections + b.VirusDetections,
	}
}

// window is the range of days of a period and its breakdown.
type window struct {
	// from is 00:00 UTC of the first day of the period.
	from time.Time
	// starts are the starts of the points, oldest first.
	starts []time.Time
	// monthly tells whether the points are months.
	monthly bool
}

// newWindow returns the window of period (a value returned by
// ParsePeriod) ending today (the UTC day of now).
func newWindow(period Period, now time.Time) window {
	today := store.DayOf(now)
	var w window
	if period == Period12Months {
		w.monthly = true
		first := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
		for i := 11; i >= 0; i-- {
			w.starts = append(w.starts, first.AddDate(0, -i, 0))
		}
	} else {
		n := 30
		if period == Period7Days {
			n = 7
		}
		for i := n - 1; i >= 0; i-- {
			w.starts = append(w.starts, today.AddDate(0, 0, -i))
		}
	}
	w.from = w.starts[0]
	return w
}

// points returns the zero-filled points of the window.
func (w window) points() []Point {
	out := make([]Point, len(w.starts))
	for i, s := range w.starts {
		out[i].Date = s
	}
	return out
}

// index returns the point of day (00:00 UTC, not before w.from), -1 when
// it is after the last point.
func (w window) index(day time.Time) int {
	day = day.UTC()
	if w.monthly {
		day = time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	for i := len(w.starts) - 1; i >= 0; i-- {
		if w.starts[i].Equal(day) {
			return i
		}
	}
	return -1
}
