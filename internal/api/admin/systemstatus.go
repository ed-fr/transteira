package admin

import (
	"context"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/health"
)

// ComponentChecks runs the component checks shared with /healthz
// (*health.Service): its report is cached for health.CacheTTL and
// concurrent callers share one run, so the system status adds no probe of
// its own.
type ComponentChecks interface {
	// RunAt returns the report and when its checks ran.
	RunAt(ctx context.Context) (health.Report, time.Time)
}

// Compile-time check that the health service fits.
var _ ComponentChecks = (*health.Service)(nil)

// systemStatusSources is what getSystemStatus reports besides the services
// of the server (maintenance mode, update check).
type systemStatusSources struct {
	checks       ComponentChecks
	dbEngine     string
	antivirusEng string
}

// WithSystemStatus serves getSystemStatus: checks are the component checks
// of /healthz, dbEngine the database engine (TT_DB_DRIVER: sqlite or
// postgres) and antivirusEngine the antivirus engine (TT_ANTIVIRUS_ENGINE:
// clamd, icap, http or none, which reports the antivirus disabled). It also
// needs WithMaintenance and WithUpdateCheck. Without it the operation
// answers 500.
func WithSystemStatus(checks ComponentChecks, dbEngine, antivirusEngine string) Option {
	return func(s *Server) {
		s.statusSources = &systemStatusSources{checks: checks, dbEngine: dbEngine, antivirusEng: antivirusEngine}
	}
}

// errNoSystemStatus is the wiring error of getSystemStatus, answered 500.
var errNoSystemStatus = errors.New("admin: no system status sources configured")

// GetSystemStatus returns the state of the instance components (super
// admin): the shared health checks, the engines, the maintenance mode, the
// instance kill switch of the express secrets (WithExpressKillSwitch, since
// 2.3) and the last outcome of the update check, which it never starts. It answers
// 200 whatever the components' state: statuses only, the cause of a failed
// check stays in the application log. The session and the role are checked
// before anything.
func (s *Server) GetSystemStatus(ctx context.Context, _ gen.GetSystemStatusRequestObject) (gen.GetSystemStatusResponseObject, error) {
	src := s.statusSources
	if src == nil || src.checks == nil || s.maintenance == nil || s.updates == nil {
		return nil, errNoSystemStatus
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSuperAdminSession(p); err != nil {
		return nil, err
	}
	maint, err := s.maintenance.Get(ctx, p)
	if err != nil {
		return nil, systemError(err)
	}
	upd, err := s.updates.Status(ctx, p)
	if err != nil {
		return nil, updateCheckError(err)
	}
	report, at := src.checks.RunAt(ctx)

	var body gen.SystemStatus
	body.CheckedAt = at.UTC()
	body.Status = gen.SystemStatusStatusOk
	if !report.Healthy() {
		body.Status = gen.SystemStatusStatusDegraded
	}
	body.Database.Engine = gen.SystemStatusDatabaseEngine(src.dbEngine)
	body.Database.Status = componentHealth(report.Database)
	body.Antivirus.Engine = gen.AntivirusEngine(src.antivirusEng)
	body.Antivirus.Status = antivirusStatus(src.antivirusEng, report.Antivirus)
	body.Storage.Status = componentHealth(report.Storage)
	body.Maintenance.Enabled = maint.Enabled
	body.Maintenance.Source = gen.MaintenanceSource(maint.Source)
	body.ExpressSecrets.InstanceDisabled = s.expressDisabled
	body.Version.Version = s.version().Version
	body.Version.UpdateCheckEnabled = upd.Enabled
	body.Version.UpdateAvailable = upd.UpdateAvailable
	body.Version.LatestVersion = optional(upd.LatestVersion)
	return gen.GetSystemStatus200JSONResponse(body), nil
}

// componentHealth converts a health status to the OpenAPI ComponentHealth.
func componentHealth(st health.Status) gen.ComponentHealth {
	if st == health.StatusOK {
		return gen.ComponentHealthOk
	}
	return gen.ComponentHealthUnavailable
}

// antivirusStatus is disabled for the engine none, else the status of the
// antivirus check.
func antivirusStatus(engine string, st health.Status) gen.SystemStatusAntivirusStatus {
	switch {
	case engine == string(gen.AntivirusEngineNone):
		return gen.SystemStatusAntivirusStatusDisabled
	case st == health.StatusOK:
		return gen.SystemStatusAntivirusStatusOk
	default:
		return gen.SystemStatusAntivirusStatusUnavailable
	}
}
