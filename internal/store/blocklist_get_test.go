package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestBlocklistGet reads an entry back, and never the entry of another
// tenant.
func TestBlocklistGet(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		b := newTenant(t, db, "b.example.com")
		bl := db.Blocklist()
		entry, err := bl.Create(ctx, a.ID, store.BlocklistEntry{
			Kind: store.BlockDomain, Value: "Spam.example.net", Comment: "abuse", CreatedBy: "admin.a",
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := bl.Get(ctx, a.ID, entry.ID)
		if err != nil || got != entry {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, entry)
		}
		if _, err := bl.Get(ctx, b.ID, entry.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get from tenant B err = %v, want ErrNotFound", err)
		}
		if _, err := bl.Get(ctx, "bad", entry.ID); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Get with a malformed tenant err = %v, want ErrInvalid", err)
		}
	})
}
