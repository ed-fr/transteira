package apiutil

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
)

func TestRecipientTracking(t *testing.T) {
	if got := RecipientTracking(nil); got == nil || len(got) != 0 {
		t.Errorf("nil = %#v, want an empty list", got)
	}
	at := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	got := RecipientTracking([]store.RecipientTracking{
		{LinkID: "rcl_1", Email: "dave@entity-a.example.com"},
		{
			LinkID: "rcl_2", Email: "erin@example.net", VerifiedAt: at, FirstDownloadedAt: at, LastDownloadedAt: at.Add(time.Hour),
			Downloads: []store.RecipientDownload{
				{FileID: "fil_1", FirstAt: at, LastAt: at, Count: 1},
				{FirstAt: at, LastAt: at.Add(time.Hour), Count: 2},
			},
		},
	})
	if len(got) != 2 || got[0].VerifiedAt != nil || got[0].FirstDownloadedAt != nil || len(got[0].Downloads) != 0 {
		t.Fatalf("first = %+v", got)
	}
	r := got[1]
	if r.Email != "erin@example.net" || !r.VerifiedAt.Equal(at) || !r.LastDownloadedAt.Equal(at.Add(time.Hour)) ||
		len(r.Downloads) != 2 || *r.Downloads[0].FileId != "fil_1" || r.Downloads[1].FileId != nil || r.Downloads[1].Count != 2 {
		t.Errorf("second = %+v", r)
	}
	// Never a link or a token in the rendering (T-199).
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"rcl_", "dl_", "link", "token", "Url"} {
		if strings.Contains(string(b), s) {
			t.Errorf("rendering %s contains %q", b, s)
		}
	}
	// A recipient with no download renders [] and not null: the admin
	// interface maps over it.
	if !strings.Contains(string(b), `"downloads":[]`) || strings.Contains(string(b), `"downloads":null`) {
		t.Errorf("rendering %s: want \"downloads\":[]", b)
	}
}
