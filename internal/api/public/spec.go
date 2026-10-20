package public

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// SpecContentType is the media type of the served OpenAPI document.
const SpecContentType = "application/yaml"

// SpecHandler serves spec (the embedded OpenAPI document, api.OpenAPISpec)
// for GET and HEAD, with a strong ETag derived from its SHA-256 so that
// clients can revalidate it cheaply (If-None-Match answers 304). The
// document is public and tenant-independent.
func SpecHandler(spec []byte) http.Handler {
	sum := sha256.Sum256(spec)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", SpecContentType)
		h.Set("ETag", etag)
		// Revalidate on every use instead of the API-wide no-store.
		h.Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(spec))
	})
}
