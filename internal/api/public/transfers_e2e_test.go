package public

import (
	"net/http"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/transfer"
)

// TestCreateTransferE2E passes the end-to-end members of the body to the
// service and shows them in the answer.
func TestCreateTransferE2E(t *testing.T) {
	t.Parallel()
	yes := true
	meta1, meta2, msg := gen.EncryptedMetadata("bWV0YSAx"), gen.EncryptedMetadata("bWV0YSAy"), "bWVzc2FnZQ"
	d := uploadingDetails()
	d.Message, d.E2E, d.EncryptedMessage = "", true, msg
	d.Files = []transfer.File{
		{ID: "fil_1", Name: "file-1.tte2", Size: 100, UploadID: "upl_1", EncryptedMetadata: string(meta1)},
		{ID: "fil_2", Name: "file-2.tte2", Size: 48, UploadID: "upl_2", EncryptedMetadata: string(meta2)},
	}
	info := internalInfo()
	f := &fakeTransfers{details: d}
	body := gen.TransferCreate{
		ExpiryDays: 7, EndToEndEncrypted: &yes, EncryptedMessage: &msg,
		Files: []gen.FileDeclaration{
			{Name: "file-1.tte2", Size: 100, EncryptedMetadata: &meta1},
			{Name: "file-2.tte2", Size: 48, EncryptedMetadata: &meta2},
		},
	}
	res, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("CreateTransfer: %v", err)
	}
	if !f.req.EndToEndEncrypted || f.req.EncryptedMessage != msg || f.req.Files[0].EncryptedMetadata != string(meta1) ||
		f.req.Files[1].EncryptedMetadata != string(meta2) {
		t.Errorf("request = %+v", f.req)
	}
	out := res.(gen.CreateTransfer201JSONResponse).Body
	if out.EndToEndEncrypted == nil || !*out.EndToEndEncrypted || out.EncryptedMessage == nil || *out.EncryptedMessage != msg ||
		out.Message != nil || out.Files[1].EncryptedMetadata == nil || *out.Files[1].EncryptedMetadata != meta2 {
		t.Errorf("body = %+v", out)
	}

	// A plain transfer shows none of them, and passes none.
	f = &fakeTransfers{details: uploadingDetails()}
	plain := gen.TransferCreate{ExpiryDays: 1, Files: []gen.FileDeclaration{{Name: "a", Size: 1}}}
	res, err = NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{Body: &plain})
	if err != nil {
		t.Fatal(err)
	}
	out = res.(gen.CreateTransfer201JSONResponse).Body
	if out.EndToEndEncrypted != nil || out.EncryptedMessage != nil || out.Files[0].EncryptedMetadata != nil {
		t.Errorf("plain body = %+v", out)
	}
	if f.req.EndToEndEncrypted || f.req.EncryptedMessage != "" || f.req.Files[0].EncryptedMetadata != "" {
		t.Errorf("plain request = %+v", f.req)
	}

	// The refusals of the policy map to their problems.
	for err, code := range map[error]problem.Code{
		transfer.ErrE2EForbidden: problem.CodeE2EForbidden, transfer.ErrE2ERequired: problem.CodeE2ERequired,
	} {
		f := &fakeTransfers{err: err}
		_, got := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{Body: &body})
		p := problemOf(t, got, code)
		if want := map[problem.Code]int{problem.CodeE2EForbidden: http.StatusForbidden, problem.CodeE2ERequired: http.StatusBadRequest}[code]; p.Status != want {
			t.Errorf("%s: status %d", code, p.Status)
		}
	}
}
