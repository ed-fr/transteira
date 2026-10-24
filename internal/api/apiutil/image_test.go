package apiutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ed-fr/transteira/internal/branding"
)

func TestWriteImage(t *testing.T) {
	t.Parallel()
	img := branding.Image{Data: []byte("png"), ContentType: branding.ContentTypePNG, ETag: `"abc"`}
	for _, tc := range []struct {
		name        string
		notModified bool
		status      int
		body        string
	}{
		{name: "ok", status: http.StatusOK, body: "png"},
		{name: "not modified", notModified: true, status: http.StatusNotModified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			if err := WriteImage(rec, img, "no-store", tc.notModified); err != nil {
				t.Fatal(err)
			}
			h := rec.Header()
			if rec.Code != tc.status || rec.Body.String() != tc.body || h.Get("ETag") != `"abc"` ||
				h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("got %d %q %v", rec.Code, rec.Body.String(), h)
			}
			if !tc.notModified && (h.Get("Content-Type") != branding.ContentTypePNG || h.Get("Content-Length") != "3") {
				t.Fatalf("headers %v", h)
			}
			if tc.notModified && h.Get("Content-Type") != "" {
				t.Fatalf("304 with a content type: %v", h)
			}
		})
	}
}
