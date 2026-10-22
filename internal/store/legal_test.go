package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestTenantLegalDocumentsList(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.TenantLegalDocuments()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		if got, err := repo.List(ctx, a.ID); err != nil || got == nil || len(got) != 0 {
			t.Fatalf("List(none) = %#v, %v", got, err)
		}
		for _, d := range []store.LegalDocument{
			{Document: store.PrivacyPolicy, Language: "fr", Content: "fr"},
			{Document: store.PrivacyPolicy, Language: "en", Content: "en"},
			{Document: store.LegalNotice, Language: "fr", Content: "fr"},
		} {
			if _, err := repo.Put(ctx, a.ID, d); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := repo.Put(ctx, b.ID, store.LegalDocument{Document: store.LegalNotice, Language: "en", Content: "b"}); err != nil {
			t.Fatal(err)
		}
		want := []store.LegalDocumentKey{
			{Document: store.LegalNotice, Language: "fr"},
			{Document: store.PrivacyPolicy, Language: "en"},
			{Document: store.PrivacyPolicy, Language: "fr"},
		}
		if got, err := repo.List(ctx, a.ID); err != nil || !slices.Equal(got, want) {
			t.Fatalf("List(a) = %v, %v; want %v", got, err, want)
		}
		// Isolation: tenant B only sees its own document.
		if got, err := repo.List(ctx, b.ID); err != nil || !slices.Equal(got, []store.LegalDocumentKey{{Document: store.LegalNotice, Language: "en"}}) {
			t.Fatalf("List(b) = %v, %v", got, err)
		}
		if _, err := repo.List(ctx, "bad"); err == nil || errors.Is(err, store.ErrNotFound) {
			t.Errorf("List(malformed tenant) err = %v", err)
		}
	})
}
