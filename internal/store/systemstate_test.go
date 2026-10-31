package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestSystemState(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SystemState()

		// Never written: not found.
		_, err := repo.Get(ctx, store.SystemStateUpdateCheck)
		wantErr(t, "Get(never written)", err, store.ErrNotFound)

		// Written, then overwritten in place.
		first := `{"latestVersion":"1.2.0","releaseUrl":null,"checkedAt":"2026-10-31T06:00:00Z","lastError":"none"}`
		if err := repo.Put(ctx, store.SystemStateUpdateCheck, []byte(first)); err != nil {
			t.Fatalf("Put = %v", err)
		}
		got, err := repo.Get(ctx, store.SystemStateUpdateCheck)
		if err != nil || string(got.Value) != first || !got.UpdatedAt.Equal(msNow) {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		second := `{"lastError":"network"}`
		if err := repo.Put(ctx, store.SystemStateUpdateCheck, []byte(second)); err != nil {
			t.Fatalf("Put(overwrite) = %v", err)
		}
		if got, err := repo.Get(ctx, store.SystemStateUpdateCheck); err != nil || string(got.Value) != second {
			t.Errorf("Get(after overwrite) = %+v, %v", got, err)
		}

		// Unknown keys and invalid values are refused, the stored value
		// is unchanged.
		_, err = repo.Get(ctx, "other")
		wantErr(t, "Get(unknown key)", err, store.ErrInvalid)
		for name, c := range map[string]struct {
			key, value string
		}{
			"unknown key": {"other", "{}"},
			"empty key":   {"", "{}"},
			"empty value": {store.SystemStateUpdateCheck, ""},
			"not json":    {store.SystemStateUpdateCheck, "{not json"},
			"too long":    {store.SystemStateUpdateCheck, `"` + strings.Repeat("a", store.MaxSystemStateValueBytes) + `"`},
		} {
			wantErr(t, "Put("+name+")", repo.Put(ctx, c.key, []byte(c.value)), store.ErrInvalid)
		}
		if got, err := repo.Get(ctx, store.SystemStateUpdateCheck); err != nil || string(got.Value) != second {
			t.Errorf("Get(after refused puts) = %+v, %v", got, err)
		}
	})
}
