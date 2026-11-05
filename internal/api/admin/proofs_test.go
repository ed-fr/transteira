package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeProofs is a ProofService recording its calls.
type fakeProofs struct {
	doc  proof.Document
	keys []proof.PublicKey
	err  error

	gotPrincipal              adminauth.Principal
	gotTenant                 tenant.ID
	gotTransfer, gotRecipient string
	gotLang                   string
	gotKind                   store.ProofKind
	gotIP                     netip.Addr
}

func (f *fakeProofs) TenantProof(_ context.Context, p adminauth.Principal, tid tenant.ID, trfID string, kind store.ProofKind,
	recipient, lang string, ip netip.Addr,
) (proof.Document, error) {
	f.gotPrincipal, f.gotTenant, f.gotTransfer, f.gotKind, f.gotRecipient, f.gotLang, f.gotIP = p, tid, trfID, kind, recipient, lang, ip
	return f.doc, f.err
}

func (f *fakeProofs) Keys(context.Context) ([]proof.PublicKey, error) { return f.keys, f.err }

func proofServer(f *fakeProofs) *Server {
	s := NewServer(WithProofService(f))
	s.now = func() time.Time { return now }
	return s
}

func TestGetTenantTransferProof(t *testing.T) {
	t.Parallel()
	f := &fakeProofs{doc: proof.Document{FileName: "transteira-proof-delivery-trf_01.pdf", PDF: []byte("%PDF-1.7 test")}}
	srv := proofServer(f)
	rcpt := gen.ProofRecipient("carol@customer.example.net")
	resp, err := srv.GetTenantTransferProof(ctxWith(store.SessionAuthenticated, superRoot), gen.GetTenantTransferProofRequestObject{
		TenantId: "ten_a", TransferId: "trf_01", Params: gen.GetTenantTransferProofParams{Kind: gen.Delivery, Recipient: &rcpt},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitGetTenantTransferProofResponse(rec); err != nil {
		t.Fatal(err)
	}
	h := rec.Header()
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.7 test" || h.Get("Content-Type") != "application/pdf" ||
		h.Get("Content-Length") != "13" || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Content-Disposition") != `attachment; filename="transteira-proof-delivery-trf_01.pdf"` {
		t.Errorf("response %d %v %q", rec.Code, h, rec.Body)
	}
	if f.gotPrincipal.Admin.ID != superRoot.ID || f.gotTenant != "ten_a" || f.gotTransfer != "trf_01" || f.gotKind != store.ProofDelivery ||
		f.gotRecipient != string(rcpt) || f.gotLang != "fr" || f.gotIP != clientIP {
		t.Errorf("service got %+v", f)
	}

	// Without a recipient, an account without language.
	if _, err := srv.GetTenantTransferProof(ctxWith(store.SessionAuthenticated, delegated), gen.GetTenantTransferProofRequestObject{
		TenantId: "ten_a", TransferId: "trf_01", Params: gen.GetTenantTransferProofParams{Kind: gen.Deposit},
	}); err != nil || f.gotRecipient != "" || f.gotLang != "" {
		t.Errorf("no recipient: %v, got %+v", err, f)
	}
}

func TestGetTenantTransferProofErrors(t *testing.T) {
	t.Parallel()
	req := gen.GetTenantTransferProofRequestObject{TenantId: "ten_a", TransferId: "trf_01", Params: gen.GetTenantTransferProofParams{Kind: gen.Deposit}}
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	f := &fakeProofs{}
	srv := proofServer(f)

	_, err := NewServer().GetTenantTransferProof(ctx, req)
	if !errors.Is(err, errNoProofService) {
		t.Errorf("without service: %v", err)
	}
	_, err = srv.GetTenantTransferProof(ctxWith("", delegated), req)
	if p := (*problem.Problem)(nil); !errors.As(err, &p) || p.Code != problem.CodeUnauthenticated {
		t.Errorf("without session: %v", err)
	}

	for _, c := range []struct {
		err   error
		code  problem.Code
		field string
		retry int
	}{
		{&proof.InvalidError{Param: proof.ParamRecipient}, problem.CodeValidationFailed, "recipient", 0},
		{&proof.RateLimitError{RetryAfter: 1500 * time.Millisecond}, problem.CodeRateLimited, "", 2},
		{proof.ErrNotFound, problem.CodeNotFound, "", 0},
		{proof.ErrNotAvailable, problem.CodeProofNotAvailable, "", 0},
		{adminauth.ErrUnauthenticated, problem.CodeUnauthenticated, "", 0},
		{adminauth.ErrNotFound, problem.CodeNotFound, "", 0},
	} {
		f.err = c.err
		_, err := srv.GetTenantTransferProof(ctx, req)
		var p *problem.Problem
		if !errors.As(err, &p) || p.Code != c.code {
			t.Fatalf("%v: error = %v, want %s", c.err, err, c.code)
		}
		if c.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != c.field) {
			t.Errorf("%v: errors = %+v", c.err, p.Errors)
		}
		if c.retry != 0 && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != c.retry) {
			t.Errorf("%v: retry = %v", c.err, p.RetryAfterSeconds)
		}
	}
	f.err = errors.New("boom")
	if _, err := srv.GetTenantTransferProof(ctx, req); !errors.Is(err, f.err) {
		t.Errorf("unknown error = %v", err)
	}
}

func TestListProofKeys(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	f := &fakeProofs{keys: []proof.PublicKey{{KeyID: "psk_1", PublicKey: make([]byte, 32), CreatedAt: created, RetiredAt: created.Add(time.Hour)}}}
	srv := proofServer(f)
	// No session is needed: the keys belong to the instance.
	resp, err := srv.ListProofKeys(context.Background(), gen.ListProofKeysRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	list := gen.ProofKeyList(resp.(gen.ListProofKeys200JSONResponse))
	if len(list.Items) != 1 || list.Items[0].KeyId != "psk_1" || list.Items[0].RetiredAt == nil ||
		list.Items[0].PublicKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("list = %+v", list)
	}
	f.err = errors.New("boom")
	if _, err := srv.ListProofKeys(context.Background(), gen.ListProofKeysRequestObject{}); !errors.Is(err, f.err) {
		t.Errorf("service error = %v", err)
	}
	if _, err := NewServer().ListProofKeys(context.Background(), gen.ListProofKeysRequestObject{}); !errors.Is(err, errNoProofService) {
		t.Errorf("without service: %v", err)
	}
}
