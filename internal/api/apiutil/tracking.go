package apiutil

import (
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/store"
)

// RecipientTracking renders the download tracking of the recipients of a
// transfer with one link per recipient as the OpenAPI RecipientTracking
// list (P27): addresses, dates and counts only, never a link or a token.
// It returns an empty, non-nil list for no recipient.
func RecipientTracking(in []store.RecipientTracking) []gen.RecipientTracking {
	out := make([]gen.RecipientTracking, len(in))
	for i, r := range in {
		item := gen.RecipientTracking{
			Email: gen.Email(r.Email), VerifiedAt: optionalTime(r.VerifiedAt),
			FirstDownloadedAt: optionalTime(r.FirstDownloadedAt), LastDownloadedAt: optionalTime(r.LastDownloadedAt),
		}
		// The generated item type is anonymous: grow the slice rather than
		// spelling it out.
		// max(.., 1): a non-nil empty slice, so that the JSON is [] and not null.
		item.Downloads = slices.Grow(item.Downloads, max(len(r.Downloads), 1))[:len(r.Downloads)]
		for j, d := range r.Downloads {
			dl := &item.Downloads[j]
			dl.Count, dl.FirstAt, dl.LastAt = int(d.Count), d.FirstAt, d.LastAt
			if d.FileID != "" {
				fileID := d.FileID
				dl.FileId = &fileID
			}
		}
		out[i] = item
	}
	return out
}

// optionalTime returns &t, or nil for the zero time.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
