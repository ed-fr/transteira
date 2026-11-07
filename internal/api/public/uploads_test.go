package public

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tte2"
	"github.com/ed-fr/transteira/internal/upload"
)

func TestAppendUploadChunkE2EFormat(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	// e2e-format-invalid: unlike the other tus errors, a problem.
	err := fmt.Errorf("%w: %w", upload.ErrE2EFormat, tte2.ErrFormat)
	resp, gotErr := NewServer(WithUploads(&fakeUploads{err: err})).AppendUploadChunk(depositCtx(t, &info),
		gen.AppendUploadChunkRequestObject{Body: stringsReader("x")})
	var p *problem.Problem
	if resp != nil || !errors.As(gotErr, &p) || p.Code != problem.CodeE2EFormatInvalid {
		t.Fatalf("%T %v", resp, gotErr)
	}
}

func TestAppendBadRequestHasNoBody(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	if err := (appendBadRequest{}).VisitAppendUploadChunkResponse(rec); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}
