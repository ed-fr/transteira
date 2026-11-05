package public

import (
	"bytes"
	"context"
	"errors"
	"net/netip"

	"github.com/ed-fr/transteira/internal/api/apiutil"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ProofService serves the proofs of deposit and delivery to the sender of
// a transfer and the public keys that verify them (*proof.Service).
type ProofService interface {
	MyProof(ctx context.Context, t *tenant.Tenant, senderEmail, trfID string, kind store.ProofKind,
		recipient, lang string, ip netip.Addr) (proof.Document, error)
	Keys(ctx context.Context) ([]proof.PublicKey, error)
}

var _ ProofService = (*proof.Service)(nil)

// WithProofs serves the proof operations with svc. Without it they answer
// 500.
func WithProofs(svc ProofService) Option {
	return func(s *Server) { s.proofs = svc }
}

// errNoProofService reports a server built without WithProofs: a wiring
// error, answered 500.
var errNoProofService = errors.New("public: no proof service configured")

// GetMyTransferProof returns the proof of deposit or delivery of one of
// the transfers of the session, as a PDF in the language of the request.
func (s *Server) GetMyTransferProof(ctx context.Context, req gen.GetMyTransferProofRequestObject) (gen.GetMyTransferProofResponseObject, error) {
	t, info, _, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	if s.proofs == nil {
		return nil, errNoProofService
	}
	recipient := ""
	if req.Params.Recipient != nil {
		recipient = string(*req.Params.Recipient)
	}
	doc, err := s.proofs.MyProof(ctx, t, info.Email, req.TransferId, store.ProofKind(req.Params.Kind),
		recipient, downloadLanguage(ctx, t), middleware.ClientIP(ctx))
	if err != nil {
		return nil, apiutil.ProofError(err)
	}
	disposition, noStore, noSniff := apiutil.ProofDisposition(doc.FileName), "no-store", "nosniff"
	return gen.GetMyTransferProof200ApplicationpdfResponse{
		Body:          bytes.NewReader(doc.PDF),
		ContentLength: int64(len(doc.PDF)),
		Headers: gen.GetMyTransferProof200ResponseHeaders{
			CacheControl: &noStore, ContentDisposition: &disposition, XContentTypeOptions: &noSniff,
		},
	}, nil
}

// ListProofKeys lists the public keys that verify the proofs, most recent
// first.
func (s *Server) ListProofKeys(ctx context.Context, _ gen.ListProofKeysRequestObject) (gen.ListProofKeysResponseObject, error) {
	if _, ok := tenant.FromContext(ctx); !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	if s.proofs == nil {
		return nil, errNoProofService
	}
	keys, err := s.proofs.Keys(ctx)
	if err != nil {
		return nil, err
	}
	return gen.ListProofKeys200JSONResponse(apiutil.ProofKeyList(keys)), nil
}
