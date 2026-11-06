package public

import (
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
)

// The members of API 2.0 that are not implemented yet are refused with a
// 400 not-supported before the service is reached.
func TestInterimNotSupportedV20(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	meta, msg := gen.EncryptedMetadata("AbC1_dEf2"), "AbC1_dEf2"
	files := []gen.FileDeclaration{{Name: "a", Size: 1}}
	for name, tc := range map[string]struct {
		body  gen.TransferCreate
		field string
	}{
		"e2e":            {gen.TransferCreate{ExpiryDays: 1, Files: files, EndToEndEncrypted: &yes}, "/endToEndEncrypted"},
		"encrypted msg":  {gen.TransferCreate{ExpiryDays: 1, Files: files, EncryptedMessage: &msg}, "/encryptedMessage"},
		"encrypted meta": {gen.TransferCreate{ExpiryDays: 1, Files: []gen.FileDeclaration{{Name: "a", Size: 1}, {Name: "b", Size: 1, EncryptedMetadata: &meta}}}, "/files/1/encryptedMetadata"},
	} {
		info := externalInfo()
		f := &fakeTransfers{details: uploadingDetails()}
		_, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{Body: &tc.body})
		p := problemOf(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Field != tc.field || p.Errors[0].Code != "not-supported" {
			t.Errorf("%s: errors %+v", name, p.Errors)
		}
	}
	// False booleans are the defaults and harmless.
	info := externalInfo()
	f := &fakeTransfers{details: uploadingDetails()}
	if _, err := NewServer(WithTransfers(f)).CreateTransfer(depositCtx(t, &info), gen.CreateTransferRequestObject{
		Body: &gen.TransferCreate{ExpiryDays: 1, Files: files, LinkOnly: &no, EndToEndEncrypted: &no},
	}); err != nil {
		t.Errorf("false members: %v", err)
	}
}
