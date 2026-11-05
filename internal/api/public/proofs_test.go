package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

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

	gotSender, gotTransfer, gotRecipient, gotLang string
	gotKind                                       store.ProofKind
	gotIP                                         netip.Addr
}

func (f *fakeProofs) MyProof(_ context.Context, _ *tenant.Tenant, sender, trfID string, kind store.ProofKind,
	recipient, lang string, ip netip.Addr,
) (proof.Document, error) {
	f.gotSender, f.gotTransfer, f.gotKind, f.gotRecipient, f.gotLang, f.gotIP = sender, trfID, kind, recipient, lang, ip
	return f.doc, f.err
}

func (f *fakeProofs) Keys(context.Context) ([]proof.PublicKey, error) { return f.keys, f.err }

func newProofServer(f *fakeProofs) *Server {
	s := NewServer(WithMyTransfers(&fakeMe{}), WithProofs(f))
	s.now = func() time.Time { return expires.Add(-time.Hour) }
	return s
}

func TestGetMyTransferProof(t *testing.T) {
	t.Parallel()
	f := &fakeProofs{doc: proof.Document{FileName: "transteira-proof-deposit-trf_x.pdf", PDF: []byte("%PDF-1.7 test")}}
	srv := newProofServer(f)
	rcpt := gen.ProofRecipient("dave@entity-b.example.com")
	resp, err := srv.GetMyTransferProof(meCtx(t, true), gen.GetMyTransferProofRequestObject{
		TransferId: "trf_x", Params: gen.GetMyTransferProofParams{Kind: gen.Delivery, Recipient: &rcpt},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitGetMyTransferProofResponse(rec); err != nil {
		t.Fatal(err)
	}
	h := rec.Header()
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.7 test" || h.Get("Content-Type") != "application/pdf" ||
		h.Get("Content-Length") != "13" || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Content-Disposition") != `attachment; filename="transteira-proof-deposit-trf_x.pdf"` {
		t.Errorf("response %d %v %q", rec.Code, h, rec.Body)
	}
	if f.gotSender != meInfo().Email || f.gotTransfer != "trf_x" || f.gotKind != store.ProofDelivery ||
		f.gotRecipient != string(rcpt) || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service got %+v", f)
	}

	// Without a recipient.
	if _, err := srv.GetMyTransferProof(meCtx(t, true), gen.GetMyTransferProofRequestObject{
		TransferId: "trf_x", Params: gen.GetMyTransferProofParams{Kind: gen.Deposit},
	}); err != nil || f.gotRecipient != "" {
		t.Errorf("no recipient: %v, got %q", err, f.gotRecipient)
	}
}

func TestGetMyTransferProofLanguage(t *testing.T) {
	t.Parallel()
	f := &fakeProofs{}
	srv := newProofServer(f)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "fr")
	var ctx context.Context
	RequestMiddleware(func(c context.Context, _ http.ResponseWriter, _ *http.Request, _ any) (any, error) {
		ctx = c
		return nil, nil
	}, "GetMyTransferProof")(meCtx(t, true), httptest.NewRecorder(), r, nil) //nolint:errcheck // captures the context
	if _, err := srv.GetMyTransferProof(ctx, gen.GetMyTransferProofRequestObject{TransferId: "trf_x"}); err != nil {
		t.Fatal(err)
	}
	if f.gotLang != "fr" {
		t.Errorf("language = %q, want fr", f.gotLang)
	}
}

func TestGetMyTransferProofErrors(t *testing.T) {
	t.Parallel()
	req := gen.GetMyTransferProofRequestObject{TransferId: "trf_x"}
	f := &fakeProofs{}
	srv := newProofServer(f)

	// No session, no tenant, no proof service.
	_, err := srv.GetMyTransferProof(meCtx(t, false), req)
	wantProblem(t, err, problem.CodeUnauthenticated)
	_, err = srv.GetMyTransferProof(context.Background(), req)
	wantProblem(t, err, problem.CodeUnknownTenant)
	_, err = newMeServer(&fakeMe{}).GetMyTransferProof(meCtx(t, true), req)
	if !errors.Is(err, errNoProofService) {
		t.Errorf("without service: %v", err)
	}

	// Service errors.
	for _, c := range []struct {
		err  error
		code problem.Code
	}{
		{&proof.InvalidError{Param: proof.ParamKind}, problem.CodeValidationFailed},
		{&proof.RateLimitError{RetryAfter: 1500 * time.Millisecond}, problem.CodeRateLimited},
		{proof.ErrNotFound, problem.CodeNotFound},
		{proof.ErrNotAvailable, problem.CodeProofNotAvailable},
	} {
		f.err = c.err
		_, err := srv.GetMyTransferProof(meCtx(t, true), req)
		p := problemOf(t, err, c.code)
		if c.code == problem.CodeRateLimited && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 2) {
			t.Errorf("rate limit problem = %+v", p)
		}
		if c.code == problem.CodeValidationFailed && (len(p.Errors) != 1 || p.Errors[0].Field != "kind") {
			t.Errorf("validation problem = %+v", p)
		}
	}
	f.err = errors.New("boom")
	if _, err := srv.GetMyTransferProof(meCtx(t, true), req); !errors.Is(err, f.err) {
		t.Errorf("unknown error = %v", err)
	}
}

func TestListProofKeys(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	retired := created.Add(time.Hour)
	pub := make([]byte, 32)
	pub[0], pub[31] = 0xfb, 0xff // base64url must use "-" and "_", no padding
	f := &fakeProofs{keys: []proof.PublicKey{
		{KeyID: "psk_2", PublicKey: pub, CreatedAt: retired},
		{KeyID: "psk_1", PublicKey: pub, CreatedAt: created, RetiredAt: retired},
	}}
	srv := newProofServer(f)
	resp, err := srv.ListProofKeys(tenantCtx(), gen.ListProofKeysRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	list := gen.ProofKeyList(resp.(gen.ListProofKeys200JSONResponse))
	if len(list.Items) != 2 || list.Items[0].KeyId != "psk_2" || list.Items[0].RetiredAt != nil ||
		list.Items[1].RetiredAt == nil || !list.Items[1].RetiredAt.Equal(retired) || list.Items[1].Algorithm != gen.Ed25519 ||
		list.Items[0].PublicKey != "-wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8" || !list.Items[1].CreatedAt.Equal(created) {
		t.Errorf("list = %+v", list)
	}

	// No key yet: an empty list, not null.
	f.keys = nil
	resp, err = srv.ListProofKeys(tenantCtx(), gen.ListProofKeysRequestObject{})
	if err != nil || resp.(gen.ListProofKeys200JSONResponse).Items == nil {
		t.Errorf("empty = %+v, %v", resp, err)
	}

	_, err = srv.ListProofKeys(context.Background(), gen.ListProofKeysRequestObject{})
	wantProblem(t, err, problem.CodeUnknownTenant)
	_, err = NewServer().ListProofKeys(tenantCtx(), gen.ListProofKeysRequestObject{})
	if !errors.Is(err, errNoProofService) {
		t.Errorf("without service: %v", err)
	}
	f.err = errors.New("boom")
	if _, err := srv.ListProofKeys(tenantCtx(), gen.ListProofKeysRequestObject{}); !errors.Is(err, f.err) {
		t.Errorf("service error = %v", err)
	}
}
