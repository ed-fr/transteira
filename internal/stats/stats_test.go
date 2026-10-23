package stats

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

var (
	errBoom = errors.New("boom")
	_       = repo(storeRepo{})
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestParsePeriod(t *testing.T) {
	for in, want := range map[string]Period{"": Period30Days, "7d": Period7Days, "30d": Period30Days, "12m": Period12Months} {
		if got, err := ParsePeriod(in); err != nil || got != want {
			t.Errorf("ParsePeriod(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"1d", "30D", " 7d", "12M"} {
		if _, err := ParsePeriod(in); !errors.Is(err, ErrInvalidPeriod) {
			t.Errorf("ParsePeriod(%q): %v", in, err)
		}
	}
}

func TestWindow(t *testing.T) {
	plus2 := time.FixedZone("UTC+2", 2*3600)
	cases := []struct {
		name        string
		period      Period
		now         time.Time
		first, last time.Time
		n           int
	}{
		{"7d end of January", Period7Days, time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC), day(2026, 1, 25), day(2026, 1, 31), 7},
		{"7d new year", Period7Days, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC), day(2026, 12, 27), day(2027, 1, 2), 7},
		{"30d leap day", Period30Days, time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), day(2024, 1, 31), day(2024, 2, 29), 30},
		{"30d first of March", Period30Days, time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC), day(2023, 1, 31), day(2023, 3, 1), 30},
		{"30d local zone", Period30Days, time.Date(2026, 1, 1, 0, 30, 0, 0, plus2), day(2025, 12, 2), day(2025, 12, 31), 30},
		{"12m 31 December", Period12Months, time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC), day(2026, 1, 1), day(2026, 12, 1), 12},
		{"12m 31 January", Period12Months, time.Date(2026, 1, 31, 8, 0, 0, 0, time.UTC), day(2025, 2, 1), day(2026, 1, 1), 12},
		{"12m leap day", Period12Months, time.Date(2024, 2, 29, 8, 0, 0, 0, time.UTC), day(2023, 3, 1), day(2024, 2, 1), 12},
	}
	for _, c := range cases {
		w := newWindow(c.period, c.now)
		pts := w.points()
		if len(pts) != c.n || !w.from.Equal(c.first) || !pts[0].Date.Equal(c.first) || !pts[c.n-1].Date.Equal(c.last) {
			t.Errorf("%s: %d points from %v to %v", c.name, len(pts), pts[0].Date, pts[len(pts)-1].Date)
		}
		for i := 1; i < len(pts); i++ {
			step := pts[i].Date.Sub(pts[i-1].Date)
			if !c.period.monthly() && step != 24*time.Hour {
				t.Errorf("%s: step %v", c.name, step)
			}
			if c.period.monthly() && pts[i].Date.Day() != 1 {
				t.Errorf("%s: month point %v", c.name, pts[i].Date)
			}
		}
		if w.index(c.last.AddDate(0, 2, 0)) != -1 {
			t.Errorf("%s: future day inside the window", c.name)
		}
	}
}

// monthly tells whether p is broken down by month (test helper).
func (p Period) monthly() bool { return p == Period12Months }

func TestDisk(t *testing.T) {
	if d := disk(0, 0); d.UsedRatio != 0 || d.UsedBytes != 0 || d.AlertThreshold != DefaultDiskAlertThreshold {
		t.Fatalf("empty disk %+v", d)
	}
	if d := disk(1000, 250); d.UsedBytes != 750 || d.UsedRatio != 0.75 {
		t.Fatalf("disk %+v", d)
	}
	if d := disk(1000, 2000); d.UsedBytes != 0 {
		t.Fatalf("disk %+v", d)
	}
	if s := storage(10, 0); s.UsedRatio != 0 {
		t.Fatalf("storage %+v", s)
	}
}

// faultRepo wraps a repo and injects failures.
type faultRepo struct {
	repo
	tenantErr, activeErr, usedErr, usedAllErr, usageErr, usageAllErr error
}

func (f *faultRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if f.tenantErr != nil {
		return nil, f.tenantErr
	}
	return f.repo.tenant(ctx, tid)
}

func (f *faultRepo) activeTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	if f.activeErr != nil {
		return nil, f.activeErr
	}
	return f.repo.activeTenants(ctx)
}

func (f *faultRepo) usedBytes(ctx context.Context, tid tenant.ID) (int64, error) {
	if f.usedErr != nil {
		return 0, f.usedErr
	}
	return f.repo.usedBytes(ctx, tid)
}

func (f *faultRepo) usedBytesAll(ctx context.Context) (map[tenant.ID]int64, error) {
	if f.usedAllErr != nil {
		return nil, f.usedAllErr
	}
	return f.repo.usedBytesAll(ctx)
}

func (f *faultRepo) usage(ctx context.Context, tid tenant.ID, from time.Time) ([]store.DailyUsage, error) {
	if f.usageErr != nil {
		return nil, f.usageErr
	}
	return f.repo.usage(ctx, tid, from)
}

func (f *faultRepo) usageAll(ctx context.Context, from time.Time) (map[tenant.ID]store.UsageCounts, error) {
	if f.usageAllErr != nil {
		return nil, f.usageAllErr
	}
	return f.repo.usageAll(ctx, from)
}

// env is a service over a real database.
type env struct {
	t     *testing.T
	db    *store.DB
	fault *faultRepo
	svc   *Service
	logs  *bytes.Buffer
	n     int
}

func newEnv(t *testing.T, e storetest.Engine, now time.Time) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ev := &env{t: t, db: db, fault: &faultRepo{repo: storeRepo{db: db}}, logs: &bytes.Buffer{}}
	ev.svc = newService(ev.fault, Options{
		DataDir: t.TempDir(), Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)),
	})
	return ev
}

func (ev *env) tenant(quota int64) *tenant.Tenant {
	ev.t.Helper()
	ev.n++
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: fmt.Sprintf("Entity %d", ev.n), FQDN: fmt.Sprintf("transfer.entity-%d.example.com", ev.n),
		DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: quota,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return tn
}

func (ev *env) add(tn *tenant.Tenant, d time.Time, c store.UsageCounts) {
	ev.t.Helper()
	if err := ev.db.TenantUsage().Add(context.Background(), tn.ID, d, c); err != nil {
		ev.t.Fatal(err)
	}
}

// use stores an uploading transfer of tn declaring size bytes.
func (ev *env) use(tn *tenant.Tenant, size int64) {
	ev.t.Helper()
	ctx := context.Background()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		wk := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: "mk_0123456789abcdef", Blob: []byte("k")}
		if err := ev.db.WrappedKeys().CreateTx(ctx, tx, wk); err != nil {
			return err
		}
		upl, err := id.NewUploadToken()
		if err != nil {
			return err
		}
		name := make([]byte, store.StorageNameLen/2)
		_, _ = rand.Read(name)
		f := store.TransferFile{
			ID: id.New(id.File), Name: "file.bin", Size: size, DEKKeyID: wk.ID, StorageName: hex.EncodeToString(name), UploadID: upl,
		}
		tr := store.Transfer{ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal, ExpiryDays: 7}
		return ev.db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@example.com"}, []store.TransferFile{f})
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

func principal(role store.AdminRole, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: "admin", Role: role, TenantIDs: tids},
	}
}

func counts(tr, up, dl, bd, v int64) store.UsageCounts {
	return store.UsageCounts{Transfers: tr, BytesUploaded: up, Downloads: dl, BytesDownloaded: bd, VirusDetections: v}
}

func TestNew(t *testing.T) {
	db, err := store.Open(context.Background(), storetest.SQLite(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := New(nil, Options{DataDir: t.TempDir()}); !errors.Is(err, errInvalidOptions) {
		t.Fatal(err)
	}
	if _, err := New(db, Options{}); !errors.Is(err, errInvalidOptions) {
		t.Fatal(err)
	}
	s, err := New(db, Options{DataDir: t.TempDir()})
	if err != nil || s.now == nil || s.logger == nil || s.measure == nil {
		t.Fatalf("New: %v %+v", err, s)
	}
}

func TestTenantStats(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		now := time.Date(2024, 2, 29, 15, 0, 0, 0, time.UTC) // leap day
		ev := newEnv(t, e, now)
		tn := ev.tenant(1000)
		other := ev.tenant(1000)
		ev.use(tn, 250)
		ev.use(other, 999)
		ev.add(tn, day(2023, 2, 28), counts(100, 100, 100, 100, 100)) // before every period
		ev.add(tn, day(2024, 1, 30), counts(1, 10, 2, 20, 0))         // 12m only
		ev.add(tn, day(2024, 1, 31), counts(2, 20, 3, 30, 1))         // first day of 30d
		ev.add(tn, day(2024, 2, 23), counts(4, 40, 5, 50, 0))         // first day of 7d
		ev.add(tn, day(2024, 2, 29), counts(8, 80, 9, 90, 2))         // today
		ev.add(tn, day(2024, 3, 1), counts(50, 50, 50, 50, 50))       // tomorrow: ignored
		ev.add(other, day(2024, 2, 29), counts(70, 70, 70, 70, 70))   // another tenant
		ctx := context.Background()
		p := principal(store.RoleDelegatedAdmin, tn.ID)

		s, err := ev.svc.TenantStats(ctx, p, tn.ID, Period30Days)
		if err != nil {
			t.Fatal(err)
		}
		if s.Period != Period30Days || s.UsageCounts != counts(14, 140, 17, 170, 3) {
			t.Fatalf("30d totals %+v", s.UsageCounts)
		}
		if s.Storage != (Storage{UsedBytes: 250, QuotaBytes: 1000, UsedRatio: 0.25}) {
			t.Fatalf("storage %+v", s.Storage)
		}
		if len(s.Series) != 30 || !s.Series[0].Date.Equal(day(2024, 1, 31)) || !s.Series[29].Date.Equal(day(2024, 2, 29)) {
			t.Fatalf("30d series %+v", s.Series)
		}
		wantNonZero := map[int]Point{
			0:  {Date: day(2024, 1, 31), Transfers: 2, BytesUploaded: 20},
			23: {Date: day(2024, 2, 23), Transfers: 4, BytesUploaded: 40},
			29: {Date: day(2024, 2, 29), Transfers: 8, BytesUploaded: 80},
		}
		for i, pt := range s.Series {
			want, ok := wantNonZero[i]
			if !ok {
				want = Point{Date: day(2024, 1, 31).AddDate(0, 0, i)}
			}
			if pt != want {
				t.Fatalf("30d point %d = %+v, want %+v", i, pt, want)
			}
		}

		s, err = ev.svc.TenantStats(ctx, p, tn.ID, Period7Days)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Series) != 7 || s.UsageCounts != counts(12, 120, 14, 140, 2) || s.Series[0].Transfers != 4 || s.Series[6].Transfers != 8 {
			t.Fatalf("7d %+v", s)
		}

		s, err = ev.svc.TenantStats(ctx, principal(store.RoleSuperAdmin), tn.ID, Period12Months)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Series) != 12 || s.UsageCounts != counts(15, 150, 19, 190, 3) {
			t.Fatalf("12m totals %+v", s.UsageCounts)
		}
		for i, pt := range s.Series {
			want := Point{Date: day(2023, 3, 1).AddDate(0, i, 0)}
			switch i {
			case 10:
				want.Transfers, want.BytesUploaded = 3, 30 // January 2024
			case 11:
				want.Transfers, want.BytesUploaded = 12, 120 // February 2024
			}
			if pt != want {
				t.Fatalf("12m point %d = %+v, want %+v", i, pt, want)
			}
		}
	})
}

func TestTenantStatsRights(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
		tn, other, gone := ev.tenant(1000), ev.tenant(1000), ev.tenant(1000)
		ctx := context.Background()
		if err := ev.db.Tenants().SetStatus(ctx, gone.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name string
			p    adminauth.Principal
			tid  tenant.ID
			per  Period
			want error
		}{
			{"unauthenticated", adminauth.Principal{}, tn.ID, Period7Days, adminauth.ErrUnauthenticated},
			{"not attached", principal(store.RoleDelegatedAdmin, other.ID), tn.ID, Period7Days, ErrNotFound},
			{"not attached, bad period", principal(store.RoleDelegatedAdmin, other.ID), tn.ID, "1y", ErrNotFound},
			{"bad period", principal(store.RoleDelegatedAdmin, tn.ID), tn.ID, "1y", ErrInvalidPeriod},
			{"being deleted", principal(store.RoleSuperAdmin), gone.ID, Period7Days, ErrNotFound},
			{"unknown", principal(store.RoleSuperAdmin), "ten_01JAB00000000000000UNKNWN", Period7Days, ErrNotFound},
			{"attached", principal(store.RoleDelegatedAdmin, tn.ID), tn.ID, Period7Days, nil},
		}
		for _, c := range cases {
			s, err := ev.svc.TenantStats(ctx, c.p, c.tid, c.per)
			if !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
			if c.want == nil && (len(s.Series) != 7 || s.UsageCounts != (store.UsageCounts{}) || s.UsedBytes != 0) {
				t.Errorf("%s: empty tenant %+v", c.name, s)
			}
		}
		if s, err := ev.svc.TenantStats(ctx, principal(store.RoleDelegatedAdmin, tn.ID), tn.ID, ""); err != nil || s.Period != DefaultPeriod || len(s.Series) != 30 {
			t.Errorf("default period: %v, %s with %d points", err, s.Period, len(s.Series))
		}
	})
}

func TestGlobalStats(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC))
		a, b, gone := ev.tenant(1000), ev.tenant(4000), ev.tenant(1000)
		ctx := context.Background()
		ev.use(a, 500)
		ev.use(gone, 10)
		ev.add(a, day(2026, 12, 2), counts(3, 30, 1, 1, 0)) // first day of 30d
		ev.add(a, day(2026, 12, 1), counts(5, 50, 1, 1, 0)) // outside 30d
		ev.add(gone, day(2026, 12, 31), counts(9, 9, 9, 9, 9))
		if err := ev.db.Tenants().SetStatus(ctx, gone.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		ev.svc.measure = func(path string) (uint64, uint64, error) {
			if path != ev.svc.dataDir {
				t.Errorf("measured %q", path)
			}
			return 1000, 300, nil
		}
		g, err := ev.svc.GlobalStats(ctx, principal(store.RoleSuperAdmin), Period30Days)
		if err != nil {
			t.Fatal(err)
		}
		if g.Period != Period30Days || g.Disk != (Disk{TotalBytes: 1000, UsedBytes: 700, UsedRatio: 0.7, AlertThreshold: 0.85}) {
			t.Fatalf("global %+v", g)
		}
		want := []TenantRow{
			{TenantID: a.ID, Name: a.Name, Transfers: 3, BytesUploaded: 30, Storage: Storage{UsedBytes: 500, QuotaBytes: 1000, UsedRatio: 0.5}},
			{TenantID: b.ID, Name: b.Name, Storage: Storage{QuotaBytes: 4000}},
		}
		slices.SortFunc(want, func(x, y TenantRow) int { return strings.Compare(string(x.TenantID), string(y.TenantID)) })
		if !slices.Equal(g.Tenants, want) {
			t.Fatalf("rows %+v, want %+v", g.Tenants, want)
		}
		g, err = ev.svc.GlobalStats(ctx, principal(store.RoleSuperAdmin), Period12Months)
		if err != nil || g.Tenants[slices.IndexFunc(g.Tenants, func(r TenantRow) bool { return r.TenantID == a.ID })].Transfers != 8 {
			t.Fatalf("12m: %v %+v", err, g)
		}
	})
}

func TestGlobalStatsRealDisk(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
	g, err := ev.svc.GlobalStats(context.Background(), principal(store.RoleSuperAdmin), Period7Days)
	if err != nil {
		t.Fatal(err)
	}
	if g.Disk.TotalBytes == 0 || g.Disk.UsedBytes > g.Disk.TotalBytes || g.Disk.UsedRatio < 0 || g.Disk.UsedRatio > 1 ||
		g.Tenants == nil || len(g.Tenants) != 0 {
		t.Fatalf("disk %+v tenants %v", g.Disk, g.Tenants)
	}
	// A data directory that cannot be measured is an error, never zeros.
	ev.svc.dataDir = filepath.Join(t.TempDir(), "missing")
	if _, err := ev.svc.GlobalStats(context.Background(), principal(store.RoleSuperAdmin), Period7Days); err == nil {
		t.Fatal("measure failure must fail")
	}
	if !strings.Contains(ev.logs.String(), "disk usage unavailable") {
		t.Fatalf("logs: %s", ev.logs.String())
	}
}

func TestGlobalStatsRights(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
	tn := ev.tenant(1000)
	ctx := context.Background()
	if _, err := ev.svc.GlobalStats(ctx, adminauth.Principal{}, Period7Days); !errors.Is(err, adminauth.ErrUnauthenticated) {
		t.Fatal(err)
	}
	if _, err := ev.svc.GlobalStats(ctx, principal(store.RoleDelegatedAdmin, tn.ID), Period7Days); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := ev.svc.GlobalStats(ctx, principal(store.RoleDelegatedAdmin, tn.ID), "1y"); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := ev.svc.GlobalStats(ctx, principal(store.RoleSuperAdmin), "1y"); !errors.Is(err, ErrInvalidPeriod) {
		t.Fatal(err)
	}
}

func TestRepoFailures(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
	tn := ev.tenant(1000)
	ctx := context.Background()
	super := principal(store.RoleSuperAdmin)
	for name, set := range map[string]func(f *faultRepo){
		"tenant": func(f *faultRepo) { f.tenantErr = errBoom },
		"usage":  func(f *faultRepo) { f.usageErr = errBoom },
		"used":   func(f *faultRepo) { f.usedErr = errBoom },
	} {
		*ev.fault = faultRepo{repo: ev.fault.repo}
		set(ev.fault)
		if _, err := ev.svc.TenantStats(ctx, super, tn.ID, Period7Days); !errors.Is(err, errBoom) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, set := range map[string]func(f *faultRepo){
		"active":   func(f *faultRepo) { f.activeErr = errBoom },
		"usageAll": func(f *faultRepo) { f.usageAllErr = errBoom },
		"usedAll":  func(f *faultRepo) { f.usedAllErr = errBoom },
	} {
		*ev.fault = faultRepo{repo: ev.fault.repo}
		set(ev.fault)
		if _, err := ev.svc.GlobalStats(ctx, super, Period7Days); !errors.Is(err, errBoom) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStoreRepo(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
		r := storeRepo{db: ev.db}
		ctx := context.Background()
		if _, err := r.usedBytes(ctx, "bad"); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("usedBytes: %v", err)
		}
		a, b, c := ev.tenant(10), ev.tenant(10), ev.tenant(10)
		if err := ev.db.Tenants().SetStatus(ctx, b.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		old := listPageSize
		listPageSize = 1
		t.Cleanup(func() { listPageSize = old })
		ts, err := r.activeTenants(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ids []tenant.ID
		for _, x := range ts {
			ids = append(ids, x.ID)
		}
		want := []tenant.ID{a.ID, c.ID}
		slices.Sort(want)
		if !slices.Equal(ids, want) {
			t.Fatalf("active tenants %v, want %v", ids, want)
		}
		_ = ev.db.Close()
		if _, err := r.activeTenants(ctx); err == nil {
			t.Fatal("list on a closed database")
		}
	})
}

// settingsFunc is a SettingsReader.
type settingsFunc func(ctx context.Context) (store.SystemSettingsRow, error)

func (f settingsFunc) Get(ctx context.Context) (store.SystemSettingsRow, error) { return f(ctx) }

func TestGlobalStatsSettings(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
		ctx := context.Background()
		super := principal(store.RoleSuperAdmin)
		ev.svc.measure = func(string) (uint64, uint64, error) { return 1000, 100, nil }

		// Without a reader: the default threshold, no alert, no mail.
		g, err := ev.svc.GlobalStats(ctx, super, Period7Days)
		if err != nil || g.Disk.AlertThreshold != DefaultDiskAlertThreshold || g.Disk.AlertActive || g.Disk.AlertMailConfigured {
			t.Fatalf("no reader: %v %+v", err, g.Disk)
		}

		// The real settings: the stored threshold and level.
		ev.svc.settings, ev.svc.mailOK = ev.db.SystemSettings(), true
		if _, err := ev.db.SystemSettings().UpdateTx(ctx, func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
			s.DiskAlertThresholdBP = 9050
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		g, err = ev.svc.GlobalStats(ctx, super, Period7Days)
		if err != nil || g.Disk.AlertThreshold != 0.905 || g.Disk.AlertActive || !g.Disk.AlertMailConfigured {
			t.Fatalf("settings: %v %+v", err, g.Disk)
		}
		if ok, err := ev.db.SystemSettings().CompareAndSetDiskLevel(ctx, store.DiskAlertLevelNormal, store.DiskAlertLevelRaised, time.Time{}); !ok || err != nil {
			t.Fatalf("raise: %v %v", ok, err)
		}
		g, err = ev.svc.GlobalStats(ctx, super, Period7Days)
		if err != nil || !g.Disk.AlertActive {
			t.Fatalf("raised: %v %+v", err, g.Disk)
		}

		// A settings failure is an error, never a default.
		ev.svc.settings = settingsFunc(func(context.Context) (store.SystemSettingsRow, error) {
			return store.SystemSettingsRow{}, errBoom
		})
		if _, err := ev.svc.GlobalStats(ctx, super, Period7Days); !errors.Is(err, errBoom) {
			t.Fatalf("settings failure: %v", err)
		}
	})
}

func TestNewOptions(t *testing.T) {
	db, err := store.Open(context.Background(), storetest.SQLite(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db, Options{DataDir: t.TempDir(), Settings: db.SystemSettings(), AlertMailConfigured: true})
	if err != nil || s.settings == nil || !s.mailOK {
		t.Fatalf("New: %v %+v", err, s)
	}
}
