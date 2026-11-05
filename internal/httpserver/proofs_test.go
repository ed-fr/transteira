package httpserver

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeProofs serves one key and a fixed document, and records the language
// it was asked for.
type fakeProofs struct {
	lang string
}

func (*fakeProofs) Keys(context.Context) ([]proof.PublicKey, error) {
	return []proof.PublicKey{{
		KeyID: "psk_01", PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
		CreatedAt: time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC),
	}}, nil
}

func (f *fakeProofs) MyProof(_ context.Context, _ *tenant.Tenant, _, _ string, _ store.ProofKind, _, lang string, _ netip.Addr) (proof.Document, error) {
	f.lang = lang
	return proof.Document{FileName: "transteira-proof-deposit-trf_x.pdf", PDF: []byte("%PDF-1.7")}, nil
}

func (*fakeProofs) TenantProof(context.Context, adminauth.Principal, tenant.ID, string, store.ProofKind, string, string, netip.Addr) (proof.Document, error) {
	return proof.Document{}, nil
}

// The public keys of the proofs are served on the hosts of the known
// tenants and on the admin hosts, without any session, and an unknown host
// is refused like for every tenant endpoint.
func TestProofKeysRouting(t *testing.T) {
	t.Parallel()
	f := &fakeProofs{}
	e := newEnv(t, envConfig{
		api:           public.NewServer(public.WithMyTransfers(fakeMyTransfers{}), public.WithProofs(f)),
		sessions:      fakeSessions{},
		myTransfers:   fakeMeSessions{},
		adminSessions: fakeAdminSessions{},
		adminAPI:      admin.NewServer(admin.WithProofService(f)),
	})
	for _, host := range []string{hostA, hostAdmin} {
		rec := e.do(t, http.MethodGet, "/api/v1/proof-keys", host, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"keyId":"psk_01"`) ||
			!strings.Contains(rec.Body.String(), `"retiredAt":null`) || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %v %s", host, rec.Code, rec.Header(), rec.Body)
		}
		assertSecurityHeaders(t, rec)
		if rec := e.do(t, http.MethodPost, "/api/v1/proof-keys", host, nil); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s POST: %d", host, rec.Code)
		}
	}
	decodeProblem(t, e.do(t, http.MethodGet, "/api/v1/proof-keys", hostUnknown, nil), http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
}

// The proof of a transfer is served to the session of the sender in the
// language of the request.
func TestMyTransferProofRoute(t *testing.T) {
	t.Parallel()
	f := &fakeProofs{}
	e := newEnv(t, envConfig{
		api:         public.NewServer(public.WithMyTransfers(fakeMyTransfers{}), public.WithProofs(f)),
		sessions:    fakeSessions{},
		myTransfers: fakeMeSessions{},
	})
	target := "/api/v1/me/transfers/trf_x/proof?kind=deposit"
	decodeProblem(t, e.do(t, http.MethodGet, target, hostA, nil), http.StatusUnauthorized, problem.CodeUnauthenticated)
	rec := e.do(t, http.MethodGet, target, hostA, nil, "Cookie", middleware.MyTransfersCookie+"="+meToken, "Accept-Language", "fr")
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.7" || rec.Header().Get("Content-Type") != "application/pdf" ||
		rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") || f.lang != "fr" {
		t.Errorf("%d %v %q lang %q", rec.Code, rec.Header(), rec.Body, f.lang)
	}
}
