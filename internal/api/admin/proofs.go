package admin

import (
	"bytes"
	"context"
	"errors"
	"net/netip"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/apiutil"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ProofService serves the proofs of deposit and delivery to the
// administrators of a tenant and the public keys that verify them
// (*proof.Service).
type ProofService interface {
	TenantProof(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID string, kind store.ProofKind,
		recipient, lang string, ip netip.Addr) (proof.Document, error)
	Keys(ctx context.Context) ([]proof.PublicKey, error)
}

var _ ProofService = (*proof.Service)(nil)

// WithProofService serves the proof operations with svc. Without it they
// answer 500.
func WithProofService(svc ProofService) Option {
	return func(s *Server) { s.proofSvc = svc }
}

// errNoProofService reports a server built without WithProofService: a
// wiring error, answered 500.
var errNoProofService = errors.New("admin: no proof service configured")

// GetTenantTransferProof returns the proof of deposit or delivery of a
// transfer of a tenant as a PDF, in the language of the administrator
// (the default language of the tenant when the account has none).
func (s *Server) GetTenantTransferProof(ctx context.Context, req gen.GetTenantTransferProofRequestObject) (gen.GetTenantTransferProofResponseObject, error) {
	if s.proofSvc == nil {
		return nil, errNoProofService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	recipient := ""
	if req.Params.Recipient != nil {
		recipient = string(*req.Params.Recipient)
	}
	doc, err := s.proofSvc.TenantProof(ctx, p, tenant.ID(req.TenantId), req.TransferId, store.ProofKind(req.Params.Kind),
		recipient, p.Admin.Language, middleware.ClientIP(ctx))
	if err != nil {
		return nil, proofError(err)
	}
	disposition, noStore, noSniff := apiutil.ProofDisposition(doc.FileName), "no-store", "nosniff"
	return gen.GetTenantTransferProof200ApplicationpdfResponse{
		Body:          bytes.NewReader(doc.PDF),
		ContentLength: int64(len(doc.PDF)),
		Headers: gen.GetTenantTransferProof200ResponseHeaders{
			CacheControl: &noStore, ContentDisposition: &disposition, XContentTypeOptions: &noSniff,
		},
	}, nil
}

// ListProofKeys lists the public keys that verify the proofs, most recent
// first. The keys belong to the instance: the answer is the one of the
// tenant hosts.
func (s *Server) ListProofKeys(ctx context.Context, _ gen.ListProofKeysRequestObject) (gen.ListProofKeysResponseObject, error) {
	if s.proofSvc == nil {
		return nil, errNoProofService
	}
	keys, err := s.proofSvc.Keys(ctx)
	if err != nil {
		return nil, err
	}
	return gen.ListProofKeys200JSONResponse(apiutil.ProofKeyList(keys)), nil
}

// proofError maps an error of the proof service to the error the strict
// handler renders: the errors of the service, then the authorization
// errors of package adminauth as for the other tenant operations.
func proofError(err error) error {
	return operationError(apiutil.ProofError(err))
}
