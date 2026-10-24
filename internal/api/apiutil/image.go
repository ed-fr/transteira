// Package apiutil holds small HTTP helpers shared by the API handler
// packages (internal/api/public and internal/api/admin), so that the domain
// packages they call stay free of net/http.
package apiutil

import (
	"net/http"
	"strconv"

	"github.com/ed-fr/transteira/internal/branding"
)

// WriteImage writes img as an HTTP response: its exact media type, its
// length, its strong ETag, X-Content-Type-Options nosniff and the given
// Cache-Control value. With notModified it answers 304 Not Modified with
// the same ETag, Cache-Control and nosniff headers and no body.
func WriteImage(w http.ResponseWriter, img branding.Image, cacheControl string, notModified bool) error {
	h := w.Header()
	h.Set("ETag", img.ETag)
	h.Set("Cache-Control", cacheControl)
	h.Set("X-Content-Type-Options", "nosniff")
	if notModified {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	h.Set("Content-Type", img.ContentType)
	h.Set("Content-Length", strconv.Itoa(len(img.Data)))
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(img.Data)
	return err
}
