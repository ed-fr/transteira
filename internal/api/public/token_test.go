package public

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/upload"
)

// TestTokenSender checks that a request authenticated by an API token takes
// the token path, with or without a deposit session, on the transfer and
// the tus operations.
func TestTokenSender(t *testing.T) {
	t.Parallel()
	tokID := id.New(id.APIToken)
	principal := middleware.TokenPrincipal{TokenID: tokID, Name: "scanner"}
	want := store.Depositor{Kind: store.DepositorInternal, APITokenID: tokID}
	wantSender := transfer.Sender{Depositor: want, ClientIP: netip.MustParseAddr("192.0.2.7")}
	info := internalInfo()
	for name, ctx := range map[string]context.Context{
		"token only":          middleware.WithAPIToken(depositCtx(t, nil), principal),
		"token and a session": middleware.WithAPIToken(depositCtx(t, &info), principal),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeTransfers{details: uploadingDetails()}
			srv := NewServer(WithTransfers(f))
			sender := gen.Email("carol@entity-a.example.com")
			if _, err := srv.CreateTransfer(ctx, gen.CreateTransferRequestObject{Body: &gen.TransferCreate{
				SenderEmail: &sender, ExpiryDays: 1, Files: []gen.FileDeclaration{{Name: "a", Size: 1}},
			}}); err != nil {
				t.Fatal(err)
			}
			if f.sender != wantSender || f.req.SenderEmail != string(sender) {
				t.Errorf("create: sender %+v, senderEmail %q", f.sender, f.req.SenderEmail)
			}
			f.sender = transfer.Sender{}
			if _, err := srv.GetTransfer(ctx, gen.GetTransferRequestObject{TransferId: "trf_01"}); err != nil || f.sender != wantSender {
				t.Errorf("get: sender %+v, %v", f.sender, err)
			}

			u := &fakeUploads{status: upload.Status{Offset: 1, Length: 2}}
			usrv := NewServer(WithUploads(u))
			if _, err := usrv.GetUploadOffset(ctx, gen.GetUploadOffsetRequestObject{UploadId: "upl_1"}); err != nil || u.p != want {
				t.Errorf("head: principal %+v, %v", u.p, err)
			}
			u.p = upload.Principal{}
			if _, err := usrv.AppendUploadChunk(ctx, gen.AppendUploadChunkRequestObject{
				UploadId: "upl_1", Body: bytes.NewReader([]byte("x")),
			}); err != nil || u.p != want {
				t.Errorf("patch: principal %+v, %v", u.p, err)
			}
			u.p = upload.Principal{}
			if _, err := usrv.TerminateUpload(ctx, gen.TerminateUploadRequestObject{UploadId: "upl_1"}); err != nil || u.p != want {
				t.Errorf("delete: principal %+v, %v", u.p, err)
			}
		})
	}
}
