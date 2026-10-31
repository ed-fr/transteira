package admin

import (
	"context"
	"errors"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/updatecheck"
)

// UpdateCheckService serves the check for a newer release
// (*updatecheck.Service), for the super admin only.
type UpdateCheckService interface {
	Status(ctx context.Context, p adminauth.Principal) (updatecheck.Status, error)
	CheckNow(ctx context.Context, p adminauth.Principal) (updatecheck.Status, error)
}

// Compile-time check that the update check service fits.
var _ UpdateCheckService = (*updatecheck.Service)(nil)

// WithUpdateCheck serves the system version operations with svc. Without
// it they answer 500.
func WithUpdateCheck(svc UpdateCheckService) Option {
	return func(s *Server) { s.updates = svc }
}

// errNoUpdateCheck is the wiring error of the system version operations,
// answered 500.
var errNoUpdateCheck = errors.New("admin: no update check service configured")

// GetSystemVersion returns the running version and the outcome of the last
// check for a newer release (super admin). The session and the role are
// checked before anything, so another administrator gets 403; the service
// checks them again. Every admin reads the running version through
// getVersion.
func (s *Server) GetSystemVersion(ctx context.Context, _ gen.GetSystemVersionRequestObject) (gen.GetSystemVersionResponseObject, error) {
	if s.updates == nil {
		return nil, errNoUpdateCheck
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSuperAdminSession(p); err != nil {
		return nil, err
	}
	st, err := s.updates.Status(ctx, p)
	if err != nil {
		return nil, updateCheckError(err)
	}
	return gen.GetSystemVersion200JSONResponse(s.systemVersionBody(st)), nil
}

// CheckSystemVersion runs the check for a newer release at once (super
// admin) and returns its outcome; a failure of the check is reported in
// updateCheck.lastError with 200. It answers 409 update-check-disabled
// when TT_UPDATE_CHECK is false and 429 rate-limited within a minute of
// the previous manual check. The session and the role are checked before
// anything.
func (s *Server) CheckSystemVersion(ctx context.Context, _ gen.CheckSystemVersionRequestObject) (gen.CheckSystemVersionResponseObject, error) {
	if s.updates == nil {
		return nil, errNoUpdateCheck
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSuperAdminSession(p); err != nil {
		return nil, err
	}
	st, err := s.updates.CheckNow(ctx, p)
	if err != nil {
		return nil, updateCheckError(err)
	}
	return gen.CheckSystemVersion200JSONResponse(s.systemVersionBody(st)), nil
}

// requireSuperAdminSession checks, before anything, that p is a fully
// signed-in session (401 otherwise) of a super admin (403 otherwise).
func requireSuperAdminSession(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return serviceError(err)
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return serviceError(err)
	}
	return nil
}

// updateCheckError maps an error of the update check service: 409
// update-check-disabled, 429 rate-limited with its delay, the adminauth
// errors through serviceError, anything else 500.
func updateCheckError(err error) error {
	var limited *updatecheck.RateLimitError
	switch {
	case errors.Is(err, updatecheck.ErrDisabled):
		return problem.New(problem.CodeUpdateCheckDisabled)
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	default:
		return serviceError(err)
	}
}

// systemVersionBody renders the OpenAPI SystemVersion: the running version
// and commit (as getVersion), and the outcome st, with null for an unknown
// version, URL or date.
func (s *Server) systemVersionBody(st updatecheck.Status) gen.SystemVersion {
	info := s.version()
	body := gen.SystemVersion{
		Version: info.Version,
		UpdateCheck: gen.UpdateCheck{
			Enabled: st.Enabled, UpdateAvailable: st.UpdateAvailable,
			LastError:     gen.UpdateCheckLastError(st.LastError),
			LatestVersion: optional(st.LatestVersion), ReleaseUrl: optional(st.ReleaseURL),
		},
	}
	if info.Commit != "" && info.Commit != unknownCommit {
		commit := info.Commit
		body.Commit = &commit
	}
	if !st.CheckedAt.IsZero() {
		at := st.CheckedAt.UTC()
		body.UpdateCheck.CheckedAt = &at
	}
	return body
}
