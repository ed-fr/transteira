// Package public implements the operations of the TransTeira API
// (gen.StrictServerInterface) and serves the OpenAPI document.
//
// Server embeds stubs.Unimplemented, so that every operation not written yet
// answers 404 not-found; each real method defined here replaces its stub.
// Every operation behind /api/v1 runs after the tenant middleware, which has
// already resolved the tenant from the Host header.
package public

import (
	"context"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/stubs"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

// unknownCommit is the commit reported by internal/version when the
// revision is not known; it is not exposed.
const unknownCommit = "unknown"

// Server implements gen.StrictServerInterface.
type Server struct {
	stubs.Unimplemented

	// version returns the build information (replaceable in tests).
	version func() version.Info
}

// Compile-time check that Server implements the strict server interface.
var _ gen.StrictServerInterface = (*Server)(nil)

// NewServer returns a Server.
func NewServer() *Server {
	return &Server{version: version.Get}
}

// GetVersion returns the version of the running instance and the API major
// version. The route is tenant-scoped: without a tenant in the context
// (which the tenant middleware guarantees), it answers 421 unknown-tenant.
func (s *Server) GetVersion(ctx context.Context, _ gen.GetVersionRequestObject) (gen.GetVersionResponseObject, error) {
	if _, ok := tenant.FromContext(ctx); !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	info := s.version()
	resp := gen.GetVersion200JSONResponse{Version: info.Version, ApiVersion: gen.V1}
	if info.Commit != "" && info.Commit != unknownCommit {
		commit := info.Commit
		resp.Commit = &commit
	}
	return resp, nil
}
