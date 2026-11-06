package store_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newDropLink returns a valid new drop link record and its raw token.
func newDropLink(t *testing.T) (store.DropLink, string) {
	t.Helper()
	tok, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	return store.DropLink{
		ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: "Supplier invoices",
		Recipients:   []string{" Accounting@Entity-A.example.com", "ap@entity-a.example.com"},
		ValidityDays: 7, ConfidentialityLevel: "internal", Enabled: true, CreatedBy: "adm_1",
	}, tok
}

// mustDropLink stores a new enabled drop link for tid and returns it.
func mustDropLink(t *testing.T, db *store.DB, tid tenant.ID) store.DropLink {
	t.Helper()
	l, _ := newDropLink(t)
	got, err := db.DropLinks().Create(context.Background(), tid, l)
	if err != nil {
		t.Fatalf("Create drop link: %v", err)
	}
	return got
}

func TestDropLinksCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		links := db.DropLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		in, tok := newDropLink(t)
		first, err := links.Create(ctx, a.ID, in)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		wantRcpts := []string{"accounting@entity-a.example.com", "ap@entity-a.example.com"}
		if !reflect.DeepEqual(first.Recipients, wantRcpts) || !first.CreatedAt.Equal(msNow) || first.UpdatedAt != first.CreatedAt ||
			!first.Usable(fixedNow) || first.Revoked() || !first.ExpiresAt.IsZero() ||
			first.MaxDepositsPerHour != store.DefaultDropLinkDepositsPerHour {
			t.Errorf("Create = %+v", first)
		}
		got, err := links.Get(ctx, a.ID, first.ID)
		if err != nil || !reflect.DeepEqual(got, first) {
			t.Errorf("Get = %+v, %v; want %+v", got, err, first)
		}
		if got, err := links.GetByTokenHash(ctx, a.ID, id.HashToken(tok), fixedNow); err != nil || got.ID != first.ID {
			t.Errorf("GetByTokenHash = %+v, %v", got, err)
		}
		// A link of A is unknown from B, by ID and by hash.
		_, err = links.Get(ctx, b.ID, first.ID)
		wantErr(t, "Get from B", err, store.ErrNotFound)
		_, err = links.GetByTokenHash(ctx, b.ID, id.HashToken(tok), fixedNow)
		wantErr(t, "GetByTokenHash from B", err, store.ErrNotFound)
		_, err = links.GetByTokenHash(ctx, a.ID, randomHash(t), fixedNow)
		wantErr(t, "GetByTokenHash(unknown)", err, store.ErrNotFound)
		_, err = links.GetByTokenHash(ctx, a.ID, []byte{1}, fixedNow)
		wantErr(t, "GetByTokenHash(short)", err, store.ErrInvalid)
		_, err = links.GetByTokenHash(ctx, "bogus", id.HashToken(tok), fixedNow)
		wantErr(t, "GetByTokenHash(bad tenant)", err, store.ErrInvalid)

		// A link without level, created later, comes first.
		second, _ := newDropLink(t)
		second.ConfidentialityLevel, second.Enabled, second.CreatedAt = "", false, fixedNow.Add(time.Hour)
		second, err = links.Create(ctx, a.ID, second)
		if err != nil {
			t.Fatal(err)
		}
		list, err := links.List(ctx, a.ID)
		if err != nil || len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID || list[0].ConfidentialityLevel != "" {
			t.Errorf("List = %+v, %v", list, err)
		}
		if list, err := links.List(ctx, b.ID); err != nil || len(list) != 0 {
			t.Errorf("List(B) = %+v, %v", list, err)
		}
		// A disabled link is not found by its token.
		_, err = links.GetByTokenHash(ctx, a.ID, second.TokenHash, fixedNow)
		wantErr(t, "GetByTokenHash(disabled)", err, store.ErrNotFound)

		// Revoke: idempotent, then the token is dead.
		rev, changed, err := links.Revoke(ctx, a.ID, first.ID, fixedNow.Add(2*time.Hour))
		if err != nil || !changed || !rev.Revoked() || rev.Usable(fixedNow) || !rev.UpdatedAt.Equal(rev.RevokedAt) {
			t.Fatalf("Revoke = %+v, %v, %v", rev, changed, err)
		}
		again, changed, err := links.Revoke(ctx, a.ID, first.ID, fixedNow.Add(3*time.Hour))
		if err != nil || changed || !again.RevokedAt.Equal(rev.RevokedAt) {
			t.Errorf("Revoke twice = %+v, %v, %v", again, changed, err)
		}
		_, err = links.GetByTokenHash(ctx, a.ID, id.HashToken(tok), fixedNow)
		wantErr(t, "GetByTokenHash(revoked)", err, store.ErrNotFound)
		_, _, err = links.Revoke(ctx, b.ID, second.ID, time.Time{})
		wantErr(t, "Revoke from B", err, store.ErrNotFound)
		_, _, err = links.Revoke(ctx, "bogus", second.ID, time.Time{})
		wantErr(t, "Revoke(bad tenant)", err, store.ErrInvalid)
	})
}

func TestDropLinksCreateErrors(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		links := db.DropLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")

		many := make([]string, store.MaxDropLinkRecipients+1)
		for i := range many {
			many[i] = "r" + strings.Repeat("x", i) + "@entity-a.example.com"
		}
		cases := map[string]func(*store.DropLink){
			"no recipient":       func(l *store.DropLink) { l.Recipients = nil },
			"too many":           func(l *store.DropLink) { l.Recipients = many },
			"bad recipient":      func(l *store.DropLink) { l.Recipients = []string{"not an address"} },
			"duplicate":          func(l *store.DropLink) { l.Recipients = []string{"a@entity-a.example.com", "A@entity-a.example.com"} },
			"bad id":             func(l *store.DropLink) { l.ID = "drl_x" },
			"bad hash":           func(l *store.DropLink) { l.TokenHash = []byte{1} },
			"empty label":        func(l *store.DropLink) { l.Label = "" },
			"two-line label":     func(l *store.DropLink) { l.Label = "a\nb" },
			"long label":         func(l *store.DropLink) { l.Label = strings.Repeat("a", store.MaxDropLinkLabelLen+1) },
			"bad validity":       func(l *store.DropLink) { l.ValidityDays = 3 },
			"bad level":          func(l *store.DropLink) { l.ConfidentialityLevel = "Bad Key" },
			"unknown level":      func(l *store.DropLink) { l.ConfidentialityLevel = "secret" },
			"no creator":         func(l *store.DropLink) { l.CreatedBy = "" },
			"long creator":       func(l *store.DropLink) { l.CreatedBy = strings.Repeat("a", 65) },
			"used":               func(l *store.DropLink) { l.LastUsedAt = fixedNow },
			"revoked at created": func(l *store.DropLink) { l.RevokedAt = fixedNow },
			"cap too high":       func(l *store.DropLink) { l.MaxDepositsPerHour = store.MaxDropLinkDepositsPerHour + 1 },
			"cap negative":       func(l *store.DropLink) { l.MaxDepositsPerHour = -1 },
			"expired at created": func(l *store.DropLink) { l.CreatedAt, l.ExpiresAt = fixedNow, fixedNow },
		}
		for name, mutate := range cases {
			l, _ := newDropLink(t)
			mutate(&l)
			_, err := links.Create(ctx, a.ID, l)
			wantErr(t, "Create("+name+")", err, store.ErrInvalid)
		}
		l, _ := newDropLink(t)
		_, err := links.Create(ctx, "bogus", l)
		wantErr(t, "Create(bad tenant)", err, store.ErrInvalid)
		l.ConfidentialityLevel = "" // the level of an unknown tenant is unknown too
		_, err = links.Create(ctx, tenant.ID(id.New(id.Tenant)), l)
		wantErr(t, "Create(unknown tenant)", err, store.ErrNotFound)

		first := mustDropLink(t, db, a.ID)
		dup, _ := newDropLink(t)
		dup.TokenHash = first.TokenHash
		_, err = links.Create(ctx, a.ID, dup)
		wantErr(t, "Create(duplicate hash)", err, store.ErrConflict)
		dup, _ = newDropLink(t)
		dup.ID = first.ID
		_, err = links.Create(ctx, a.ID, dup)
		wantErr(t, "Create(duplicate id)", err, store.ErrConflict)

		// The limit counts revoked links until they are purged.
		if _, _, err := links.Revoke(ctx, a.ID, first.ID, time.Time{}); err != nil {
			t.Fatal(err)
		}
		for range store.MaxDropLinks - 1 {
			mustDropLink(t, db, a.ID)
		}
		l, _ = newDropLink(t)
		_, err = links.Create(ctx, a.ID, l)
		wantErr(t, "Create(over the limit)", err, store.ErrLimitReached)
	})
}

func TestDropLinksUpdateRotateTouch(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		links := db.DropLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		l := mustDropLink(t, db, a.ID)
		later := fixedNow.Add(time.Hour)

		// No change: nothing written.
		same, changed, err := links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{
			Label: l.Label, Recipients: []string{"ACCOUNTING@entity-a.example.com", "ap@entity-a.example.com"},
			ValidityDays: 7, ConfidentialityLevel: ptr("internal"), Enabled: ptr(true),
		}, later)
		if err != nil || changed || !reflect.DeepEqual(same, l) {
			t.Errorf("Update(no change) = %+v, %v, %v", same, changed, err)
		}
		upd, changed, err := links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{
			Label: "Contracts", Recipients: []string{"legal@entity-a.example.com"}, ValidityDays: 30,
			ConfidentialityLevel: ptr(""), Enabled: ptr(false),
		}, later)
		if err != nil || !changed || upd.Label != "Contracts" || !reflect.DeepEqual(upd.Recipients, []string{"legal@entity-a.example.com"}) ||
			upd.ValidityDays != 30 || upd.ConfidentialityLevel != "" || upd.Enabled || !upd.UpdatedAt.Equal(later.Truncate(time.Millisecond)) {
			t.Fatalf("Update = %+v, %v, %v", upd, changed, err)
		}
		if got, err := links.Get(ctx, a.ID, l.ID); err != nil || !reflect.DeepEqual(got, upd) {
			t.Errorf("Get after Update = %+v, %v; want %+v", got, err, upd)
		}
		// Enabling with a level checks the level.
		_, _, err = links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{ConfidentialityLevel: ptr("secret"), Enabled: ptr(true)}, later)
		wantErr(t, "Update(unknown level)", err, store.ErrInvalid)
		if upd, _, err = links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{ConfidentialityLevel: ptr("confidential"), Enabled: ptr(true)}, later); err != nil || !upd.Enabled {
			t.Fatalf("Update(enable) = %+v, %v", upd, err)
		}
		for name, u := range map[string]store.DropLinkUpdate{
			"label":      {Label: "a\nb"},
			"validity":   {ValidityDays: 2},
			"level":      {ConfidentialityLevel: ptr("Bad")},
			"recipients": {Recipients: []string{}},
		} {
			_, _, err := links.Update(ctx, a.ID, l.ID, u, later)
			wantErr(t, "Update(bad "+name+")", err, store.ErrInvalid)
		}
		_, _, err = links.Update(ctx, b.ID, l.ID, store.DropLinkUpdate{Label: "X"}, later)
		wantErr(t, "Update from B", err, store.ErrNotFound)
		_, _, err = links.Update(ctx, "bogus", l.ID, store.DropLinkUpdate{Label: "X"}, later)
		wantErr(t, "Update(bad tenant)", err, store.ErrInvalid)

		// Rotate: the old token dies at once.
		newHash := randomHash(t)
		rot, err := links.Rotate(ctx, a.ID, l.ID, newHash, later.Add(time.Minute))
		if err != nil || !reflect.DeepEqual(rot.TokenHash, newHash) || !rot.UpdatedAt.Equal(later.Add(time.Minute).Truncate(time.Millisecond)) {
			t.Fatalf("Rotate = %+v, %v", rot, err)
		}
		_, err = links.GetByTokenHash(ctx, a.ID, l.TokenHash, time.Time{})
		wantErr(t, "GetByTokenHash(old token)", err, store.ErrNotFound)
		if got, err := links.GetByTokenHash(ctx, a.ID, newHash, time.Time{}); err != nil || got.ID != l.ID {
			t.Errorf("GetByTokenHash(new token) = %+v, %v", got, err)
		}
		other := mustDropLink(t, db, a.ID)
		_, err = links.Rotate(ctx, a.ID, other.ID, newHash, time.Time{})
		wantErr(t, "Rotate(duplicate hash)", err, store.ErrConflict)
		_, err = links.Rotate(ctx, a.ID, l.ID, []byte{1}, time.Time{})
		wantErr(t, "Rotate(short hash)", err, store.ErrInvalid)
		_, err = links.Rotate(ctx, b.ID, l.ID, randomHash(t), time.Time{})
		wantErr(t, "Rotate from B", err, store.ErrNotFound)
		_, err = links.Rotate(ctx, "bogus", l.ID, randomHash(t), time.Time{})
		wantErr(t, "Rotate(bad tenant)", err, store.ErrInvalid)

		// Touch: at most once per minute; unknown links are ignored.
		touch := func(at time.Time) time.Time {
			t.Helper()
			if err := links.TouchLastUsed(ctx, a.ID, l.ID, at); err != nil {
				t.Fatal(err)
			}
			got, err := links.Get(ctx, a.ID, l.ID)
			if err != nil {
				t.Fatal(err)
			}
			return got.LastUsedAt
		}
		if got := touch(later); !got.Equal(later.Truncate(time.Millisecond)) {
			t.Errorf("LastUsedAt = %v", got)
		}
		if got := touch(later.Add(30 * time.Second)); !got.Equal(later.Truncate(time.Millisecond)) {
			t.Errorf("LastUsedAt within a minute = %v", got)
		}
		if got := touch(later.Add(2 * time.Minute)); !got.Equal(later.Add(2 * time.Minute).Truncate(time.Millisecond)) {
			t.Errorf("LastUsedAt after a minute = %v", got)
		}
		if err := links.TouchLastUsed(ctx, b.ID, l.ID, later.Add(time.Hour)); err != nil {
			t.Errorf("TouchLastUsed from B = %v", err)
		}
		if got, _ := links.Get(ctx, a.ID, l.ID); !got.LastUsedAt.Equal(later.Add(2 * time.Minute).Truncate(time.Millisecond)) {
			t.Errorf("TouchLastUsed from B changed A: %v", got.LastUsedAt)
		}

		// A revoked link can neither change nor rotate.
		if _, _, err := links.Revoke(ctx, a.ID, l.ID, time.Time{}); err != nil {
			t.Fatal(err)
		}
		_, _, err = links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{Label: "X"}, time.Time{})
		wantErr(t, "Update(revoked)", err, store.ErrConflict)
		_, err = links.Rotate(ctx, a.ID, l.ID, randomHash(t), time.Time{})
		wantErr(t, "Rotate(revoked)", err, store.ErrConflict)
	})
}

func TestDropLinksPurgeAndErasure(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		links := db.DropLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		old := mustDropLink(t, db, a.ID)
		used := mustDropLink(t, db, a.ID)
		recent := mustDropLink(t, db, a.ID)
		active := mustDropLink(t, db, a.ID)
		inB := mustDropLink(t, db, b.ID)
		// A transfer refers to "used", which keeps it.
		tr := newTransfer()
		tr.SenderKind, tr.DropLinkID = store.DepositorDropLink, used.ID
		mustTransfer(t, db, a.ID, tr)
		for _, l := range []store.DropLink{old, used} {
			if _, _, err := links.Revoke(ctx, a.ID, l.ID, fixedNow.Add(-400*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := links.Revoke(ctx, a.ID, recent.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		if _, _, err := links.Revoke(ctx, b.ID, inB.ID, fixedNow.Add(-400*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		// A code and a session of the purged link go with it.
		ch := newChallenge(t, "x@partner.example.org", ipA)
		ch.DropLinkID = old.ID
		if err := db.Challenges().Create(ctx, a.ID, ch); err != nil {
			t.Fatal(err)
		}
		n, err := links.Purge(ctx, a.ID, fixedNow.Add(-365*24*time.Hour))
		if err != nil || n != 1 {
			t.Fatalf("Purge = %d, %v", n, err)
		}
		_, err = links.Get(ctx, a.ID, old.ID)
		wantErr(t, "Get(purged)", err, store.ErrNotFound)
		_, err = db.Challenges().Get(ctx, a.ID, ch.ID)
		wantErr(t, "Get(challenge of a purged link)", err, store.ErrNotFound)
		for _, l := range []store.DropLink{used, recent, active} {
			if _, err := links.Get(ctx, a.ID, l.ID); err != nil {
				t.Errorf("Get(%s kept) = %v", l.ID, err)
			}
		}
		if _, err := links.Get(ctx, b.ID, inB.ID); err != nil {
			t.Errorf("Purge(A) touched B: %v", err)
		}
		_, err = links.Purge(ctx, "bogus", fixedNow)
		wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)

		// Erasure: the address leaves every list; a list left empty
		// disables its link, which cannot be enabled without recipients.
		single, _ := newDropLink(t)
		single.Recipients = []string{"accounting@entity-a.example.com"}
		single, err = links.Create(ctx, a.ID, single)
		if err != nil {
			t.Fatal(err)
		}
		unrelated, _ := newDropLink(t)
		unrelated.Recipients = []string{"legal@entity-a.example.com"}
		if unrelated, err = links.Create(ctx, a.ID, unrelated); err != nil {
			t.Fatal(err)
		}
		if n, err := links.CountByRecipient(ctx, a.ID, "Accounting@entity-a.example.com"); err != nil || n != 4 {
			t.Errorf("CountByRecipient = %d, %v; want 4 (used, recent, active, single)", n, err)
		}
		if n, err := links.CountByRecipient(ctx, a.ID, "nobody@entity-a.example.com"); err != nil || n != 0 {
			t.Errorf("CountByRecipient(nobody) = %d, %v", n, err)
		}
		_, err = links.CountByRecipient(ctx, a.ID, "not an address")
		wantErr(t, "CountByRecipient(bad address)", err, store.ErrInvalid)
		var out store.DropLinkErasure
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			var err error
			out, err = links.RemoveRecipientTx(ctx, tx, "ACCOUNTING@entity-a.example.com", fixedNow.Add(time.Hour))
			return err
		})
		if err != nil || out != (store.DropLinkErasure{Updated: 4, Disabled: 1}) {
			t.Fatalf("RemoveRecipientTx = %+v, %v", out, err)
		}
		got, err := links.Get(ctx, a.ID, single.ID)
		if err != nil || got.Enabled || len(got.Recipients) != 0 || got.Recipients == nil {
			t.Errorf("emptied link = %+v, %v", got, err)
		}
		if got, err := links.Get(ctx, a.ID, unrelated.ID); err != nil || !reflect.DeepEqual(got, unrelated) {
			t.Errorf("unrelated link changed: %+v, %v", got, err)
		}
		got, err = links.Get(ctx, a.ID, active.ID)
		if err != nil || !got.Enabled || !reflect.DeepEqual(got.Recipients, []string{"ap@entity-a.example.com"}) {
			t.Errorf("link left with a recipient = %+v, %v", got, err)
		}
		if n, err := links.CountByRecipient(ctx, b.ID, "accounting@entity-a.example.com"); err != nil || n != 1 {
			t.Errorf("CountByRecipient(B) = %d, %v; the erasure of A must not touch B", n, err)
		}
		_, _, err = links.Update(ctx, a.ID, single.ID, store.DropLinkUpdate{Enabled: ptr(true)}, time.Time{})
		wantErr(t, "Update(enable without recipients)", err, store.ErrInvalid)
		if got, _, err := links.Update(ctx, a.ID, single.ID, store.DropLinkUpdate{
			Enabled: ptr(true), Recipients: []string{"new@entity-a.example.com"},
		}, time.Time{}); err != nil || !got.Usable(fixedNow) {
			t.Errorf("Update(enable with recipients) = %+v, %v", got, err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := links.RemoveRecipientTx(ctx, tx, "not an address", time.Time{})
			return err
		})
		wantErr(t, "RemoveRecipientTx(bad address)", err, store.ErrInvalid)
	})
}

func TestDropLinksLevels(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		levels := db.ConfidentialityLevels()
		a := newTenant(t, db, "transfer.entity-a.example.com")

		cur, err := levels.List(ctx, a.ID)
		if err != nil || len(cur) != 3 {
			t.Fatalf("List = %+v, %v", cur, err)
		}
		for _, l := range cur {
			if !l.LinkOnlyAllowed {
				t.Errorf("seeded level %s forbids link-only", l.Key)
			}
		}
		l := mustDropLink(t, db, a.ID) // level "internal"
		var withoutInternal []store.ConfidentialityLevel
		for _, lv := range cur {
			if lv.Key != "internal" {
				lv.IsDefault = lv.Key == "public"
				withoutInternal = append(withoutInternal, lv)
			}
		}
		_, err = levels.Replace(ctx, a.ID, withoutInternal, "admin", time.Time{})
		wantErr(t, "Replace(removing a level of an enabled drop link)", err, store.ErrConflict)
		// Keeping the level, with link-only forbidden on one level, passes.
		cur[2].LinkOnlyAllowed = false
		saved, err := levels.Replace(ctx, a.ID, cur, "admin", time.Time{})
		if err != nil || saved[2].LinkOnlyAllowed || !saved[1].LinkOnlyAllowed {
			t.Fatalf("Replace = %+v, %v", saved, err)
		}
		if got, err := levels.Get(ctx, a.ID, cur[2].Key); err != nil || got.LinkOnlyAllowed {
			t.Errorf("Get = %+v, %v", got, err)
		}
		// Once the link is disabled, the level may go.
		if _, _, err := db.DropLinks().Update(ctx, a.ID, l.ID, store.DropLinkUpdate{Enabled: ptr(false)}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := levels.Replace(ctx, a.ID, withoutInternal, "admin", time.Time{}); err != nil {
			t.Errorf("Replace(level of a disabled link) = %v", err)
		}
		// It cannot be enabled again on the removed level.
		_, _, err = db.DropLinks().Update(ctx, a.ID, l.ID, store.DropLinkUpdate{Enabled: ptr(true)}, time.Time{})
		wantErr(t, "Update(enable on a removed level)", err, store.ErrInvalid)
	})
}

func TestDropLinkSessionsChallengesTransfers(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		l := mustDropLink(t, db, a.ID)
		inB := mustDropLink(t, db, b.ID)

		if !store.DepositorDropLink.IsExternal() || store.DepositorDropLink.IsInternal() {
			t.Error("drop_link must follow the external rules")
		}

		// Sessions.
		s := newSession(t, "Supplier@Partner.example.org")
		s.Kind, s.DropLinkID = store.DepositorDropLink, l.ID
		if err := db.DepositSessions().Create(ctx, a.ID, s); err != nil {
			t.Fatalf("Create drop link session: %v", err)
		}
		got, err := db.DepositSessions().GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		if err != nil || got.Kind != store.DepositorDropLink || got.DropLinkID != l.ID {
			t.Errorf("GetByTokenHash = %+v, %v", got, err)
		}
		for name, mutate := range map[string]func(*store.DepositSession){
			"kind without link": func(s *store.DepositSession) { s.DropLinkID = "" },
			"link without kind": func(s *store.DepositSession) { s.Kind = store.DepositorInternal },
			"malformed link":    func(s *store.DepositSession) { s.DropLinkID = "drl_x" },
		} {
			bad := newSession(t, "x@partner.example.org")
			bad.Kind, bad.DropLinkID = store.DepositorDropLink, l.ID
			mutate(&bad)
			wantErr(t, "Create session("+name+")", db.DepositSessions().Create(ctx, a.ID, bad), store.ErrInvalid)
		}
		cross := newSession(t, "x@partner.example.org")
		cross.Kind, cross.DropLinkID = store.DepositorDropLink, inB.ID
		wantErr(t, "Create session(link of B)", db.DepositSessions().Create(ctx, a.ID, cross), store.ErrNotFound)

		// Challenges.
		ch := newChallenge(t, "supplier@partner.example.org", ipA)
		ch.DropLinkID = l.ID
		if err := db.Challenges().Create(ctx, a.ID, ch); err != nil {
			t.Fatalf("Create drop link challenge: %v", err)
		}
		if got, err := db.Challenges().Get(ctx, a.ID, ch.ID); err != nil || got.DropLinkID != l.ID {
			t.Errorf("Get challenge = %+v, %v", got, err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if n, err := db.Challenges().CountByDropLinkSinceTx(ctx, tx, l.ID, time.Unix(0, 0)); err != nil || n != 1 {
				t.Errorf("CountByDropLinkSinceTx = %d, %v; want 1", n, err)
			}
			if n, err := db.Challenges().CountByDropLinkSinceTx(ctx, tx, inB.ID, time.Unix(0, 0)); err != nil || n != 0 {
				t.Errorf("CountByDropLinkSinceTx(link of B) = %d, %v; want 0", n, err)
			}
			_, err := db.Challenges().CountByDropLinkSinceTx(ctx, tx, "drl_x", time.Unix(0, 0))
			wantErr(t, "CountByDropLinkSinceTx(malformed)", err, store.ErrInvalid)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		bad := newChallenge(t, "x@partner.example.org", ipA)
		bad.DropLinkID = "drl_x"
		wantErr(t, "Create challenge(malformed link)", db.Challenges().Create(ctx, a.ID, bad), store.ErrInvalid)
		bad = newChallenge(t, "x@partner.example.org", ipA)
		bad.DropLinkID, bad.InvitationID = l.ID, mustInvitation(t, db, a.ID).ID
		wantErr(t, "Create challenge(link and invitation)", db.Challenges().Create(ctx, a.ID, bad), store.ErrInvalid)
		bad = newChallenge(t, "x@partner.example.org", ipA)
		bad.DropLinkID, bad.Purpose, bad.RecipientIntent = l.ID, store.ChallengeRecipient, store.IntentDownload
		bad.RecipientLinkID = id.New(id.RecipientLink)
		wantErr(t, "Create challenge(recipient with link)", db.Challenges().Create(ctx, a.ID, bad), store.ErrInvalid)
		bad = newChallenge(t, "x@partner.example.org", ipA)
		bad.DropLinkID = inB.ID
		wantErr(t, "Create challenge(link of B)", db.Challenges().Create(ctx, a.ID, bad), store.ErrNotFound)

		// Transfers.
		tr := newTransfer()
		tr.SenderEmail, tr.SenderKind, tr.DropLinkID = "Supplier@Partner.example.org", store.DepositorDropLink, l.ID
		d := mustTransfer(t, db, a.ID, tr)
		if d.DropLinkID != l.ID || d.SenderKind != store.DepositorDropLink || d.LinkOnly {
			t.Errorf("drop link transfer = %+v", d.Transfer)
		}
		dep := store.Depositor{Email: "supplier@partner.example.org", Kind: store.DepositorDropLink, DropLinkID: l.ID}
		if !dep.Owns(d.Transfer) {
			t.Error("the drop link depositor does not own its transfer")
		}
		dep.DropLinkID = inB.ID
		if dep.Owns(d.Transfer) {
			t.Error("a depositor of another link owns the transfer")
		}
		// The file (and its key) is written before the transaction opens:
		// SQLite has a single writer.
		create := func(tr store.Transfer, file store.TransferFile, recipients ...string) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				return db.Transfers().CreateTx(ctx, tx, tr, recipients, []store.TransferFile{file})
			})
		}
		for name, mutate := range map[string]func(*store.Transfer){
			"kind without link": func(tr *store.Transfer) { tr.DropLinkID = "" },
			"link without kind": func(tr *store.Transfer) { tr.SenderKind = store.DepositorInternal },
			"malformed link":    func(tr *store.Transfer) { tr.DropLinkID = "drl_x" },
			"link-only per recipient": func(tr *store.Transfer) {
				tr.SenderKind, tr.DropLinkID, tr.LinkOnly, tr.LinkMode = store.DepositorInternal, "", true, store.LinkModePerRecipient
			},
			"no recipient": func(*store.Transfer) {},
		} {
			tr := newTransfer()
			tr.SenderKind, tr.DropLinkID = store.DepositorDropLink, l.ID
			mutate(&tr)
			rcpts := []string{"accounting@entity-a.example.com"}
			if name == "no recipient" {
				rcpts = nil
			}
			wantErr(t, "CreateTx("+name+")", create(tr, newFile(t, db, a.ID, "f.pdf", 1), rcpts...), store.ErrInvalid)
		}
		tr = newTransfer()
		tr.SenderKind, tr.DropLinkID = store.DepositorDropLink, inB.ID
		wantErr(t, "CreateTx(link of B)", create(tr, newFile(t, db, a.ID, "f.pdf", 1), "accounting@entity-a.example.com"), store.ErrNotFound)
		disabled := mustDropLink(t, db, a.ID)
		if _, _, err := db.DropLinks().Update(ctx, a.ID, disabled.ID, store.DropLinkUpdate{Enabled: ptr(false)}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		tr = newTransfer()
		tr.SenderKind, tr.DropLinkID = store.DepositorDropLink, disabled.ID
		wantErr(t, "CreateTx(disabled link)", create(tr, newFile(t, db, a.ID, "f.pdf", 1), "accounting@entity-a.example.com"), store.ErrNotFound)

		// A link-only transfer may have no recipient.
		tr = newTransfer()
		tr.LinkOnly = true
		if err := create(tr, newFile(t, db, a.ID, "f.pdf", 1)); err != nil {
			t.Fatalf("CreateTx(link-only without recipient): %v", err)
		}
		if got, err := db.Transfers().Get(ctx, a.ID, tr.ID); err != nil || !got.LinkOnly || got.LinkMode != store.LinkModeShared ||
			len(got.Recipients) != 0 || got.DropLinkID != "" {
			t.Errorf("link-only transfer = %+v, %v", got, err)
		}
	})
}

// linkOnlyTransfer creates a link-only transfer of tid with one complete
// file, still uploading.
func linkOnlyTransfer(t *testing.T, db *store.DB, tid tenant.ID) store.TransferDetails {
	t.Helper()
	f := newFile(t, db, tid, "f.bin", 10)
	f.SHA256, f.CiphertextSize, f.UploadedAt = sha1111, 50, fixedNow
	tr := newTransfer()
	tr.LinkOnly = true
	return mustTransfer(t, db, tid, tr, f)
}

func TestLinkOnlyTokens(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		run := func(tid tenant.ID, fn func(tx *store.ScopedTx) error) error { return inTx(t, db, tid, fn) }
		setToken := func(trfID string, hash []byte) error {
			return run(a.ID, func(tx *store.ScopedTx) error { return transfers.SetLinkOnlyTokenTx(ctx, tx, trfID, hash) })
		}
		replace := func(trfID string, hash []byte) error {
			return run(a.ID, func(tx *store.ScopedTx) error { return transfers.ReplaceDownloadTokenTx(ctx, tx, trfID, hash) })
		}
		markLinkOnly := func(tid tenant.ID, trfID string) error {
			return run(tid, func(tx *store.ScopedTx) error { return transfers.MarkLinkOnlyAvailableTx(ctx, tx, trfID, fixedNow) })
		}

		d := linkOnlyTransfer(t, db, a.ID)
		// Not scanning yet, and no token: no availability.
		wantErr(t, "MarkLinkOnlyAvailableTx(uploading)", markLinkOnly(a.ID, d.ID), store.ErrConflict)
		_, first := newDownloadToken(t)
		if err := setToken(d.ID, first); err != nil {
			t.Fatalf("SetLinkOnlyTokenTx(uploading): %v", err)
		}
		if err := run(a.ID, func(tx *store.ScopedTx) error { return transfers.FinalizeTx(ctx, tx, d.ID, fixedNow) }); err != nil {
			t.Fatal(err)
		}
		// A retried finalization may draw another token.
		_, hash := newDownloadToken(t)
		if err := setToken(d.ID, hash); err != nil {
			t.Fatalf("SetLinkOnlyTokenTx(scanning): %v", err)
		}
		// The sealed path refuses a link-only transfer.
		key := mustSecret(t, db, a.ID, store.KeyPurposeSecret)
		_, other := newDownloadToken(t)
		err := run(a.ID, func(tx *store.ScopedTx) error { return transfers.MarkAvailableTx(ctx, tx, d.ID, other, key, fixedNow) })
		wantErr(t, "MarkAvailableTx(link-only)", err, store.ErrInvalid)
		// A reissue while scanning replaces the token the availability
		// keeps.
		if err := replace(d.ID, other); err != nil {
			t.Fatalf("ReplaceDownloadTokenTx(scanning): %v", err)
		}
		hash = other
		_, other = newDownloadToken(t)
		wantErr(t, "MarkLinkOnlyAvailableTx from B", markLinkOnly(b.ID, d.ID), store.ErrNotFound)
		if err := markLinkOnly(a.ID, d.ID); err != nil {
			t.Fatalf("MarkLinkOnlyAvailableTx: %v", err)
		}
		got, err := transfers.Get(ctx, a.ID, d.ID)
		if err != nil || got.Status != store.TransferAvailable || !reflect.DeepEqual(got.DownloadTokenHash, hash) ||
			got.DownloadTokenKeyID != "" || !got.ExpiresAt.Equal(msNow.Add(7*24*time.Hour)) {
			t.Fatalf("available link-only transfer = %+v, %v", got.Transfer, err)
		}
		wantErr(t, "MarkLinkOnlyAvailableTx(twice)", markLinkOnly(a.ID, d.ID), store.ErrConflict)
		wantErr(t, "SetLinkOnlyTokenTx(available)", setToken(d.ID, other), store.ErrConflict)

		// Reissue: the old link dies.
		_, reissued := newDownloadToken(t)
		if err := replace(d.ID, reissued); err != nil {
			t.Fatalf("ReplaceDownloadTokenTx: %v", err)
		}
		if got, err := transfers.Get(ctx, a.ID, d.ID); err != nil || !reflect.DeepEqual(got.DownloadTokenHash, reissued) {
			t.Errorf("after reissue = %x, %v", got.DownloadTokenHash, err)
		}
		wantErr(t, "ReplaceDownloadTokenTx(short)", replace(d.ID, []byte{1}), store.ErrInvalid)
		wantErr(t, "SetLinkOnlyTokenTx(short)", setToken(d.ID, []byte{1}), store.ErrInvalid)
		wantErr(t, "ReplaceDownloadTokenTx(missing)", replace(id.New(id.Transfer), other), store.ErrNotFound)

		// Hash collisions and transfers that are not link-only.
		d2 := linkOnlyTransfer(t, db, a.ID)
		wantErr(t, "ReplaceDownloadTokenTx(uploading)", replace(d2.ID, other), store.ErrConflict)
		wantErr(t, "SetLinkOnlyTokenTx(duplicate hash)", setToken(d2.ID, reissued), store.ErrConflict)
		shared := mustTransfer(t, db, a.ID, newTransfer())
		wantErr(t, "SetLinkOnlyTokenTx(not link-only)", setToken(shared.ID, other), store.ErrInvalid)
		wantErr(t, "ReplaceDownloadTokenTx(not link-only)", replace(shared.ID, other), store.ErrInvalid)
		wantErr(t, "MarkLinkOnlyAvailableTx(not link-only)", markLinkOnly(a.ID, shared.ID), store.ErrInvalid)
	})
}

func TestTenantsLinkOnlyAllowed(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		if a.LinkOnlyAllowed {
			t.Fatal("a new tenant allows link-only transfers")
		}
		got, err := repo.SetLinkOnlyAllowed(ctx, a.ID, true)
		if err != nil || !got.LinkOnlyAllowed {
			t.Fatalf("SetLinkOnlyAllowed = %+v, %v", got, err)
		}
		// The general update never writes it.
		upd := got.Clone()
		upd.Name, upd.LinkOnlyAllowed = "Renamed", false
		if got, err := repo.Update(ctx, upd); err != nil || !got.LinkOnlyAllowed || got.Name != "Renamed" {
			t.Errorf("Update = %+v, %v", got, err)
		}
		// UpdateWithPolicies writes the selected parts together.
		upd.Name = "Again"
		got, err = repo.UpdateWithPolicies(ctx, upd, store.TenantParts{General: true, LinkOnly: true})
		if err != nil || got.LinkOnlyAllowed || got.Name != "Again" || !got.AntivirusEnabled {
			t.Errorf("UpdateWithPolicies = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got.LinkOnlyAllowed {
			t.Errorf("Get = %+v, %v", got, err)
		}
		_, err = repo.SetLinkOnlyAllowed(ctx, "bogus", true)
		wantErr(t, "SetLinkOnlyAllowed(bad id)", err, store.ErrNotFound)
		_, err = repo.SetLinkOnlyAllowed(ctx, tenant.ID(id.New(id.Tenant)), true)
		wantErr(t, "SetLinkOnlyAllowed(missing)", err, store.ErrNotFound)

		// Create stores the value given.
		c, err := repo.Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "C", FQDN: "transfer.entity-c.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1, StorageQuotaBytes: 1, LinkOnlyAllowed: true,
		})
		if err != nil || !c.LinkOnlyAllowed {
			t.Errorf("Create(link-only allowed) = %+v, %v", c, err)
		}
		if errors.Is(err, store.ErrInvalid) {
			t.Fatal(err)
		}
	})
}

func TestDropLinksExpiryAndCap(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		links := db.DropLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		end := fixedNow.Add(48 * time.Hour).Truncate(time.Millisecond)

		in, tok := newDropLink(t)
		in.CreatedAt, in.ExpiresAt, in.MaxDepositsPerHour = fixedNow, end.Add(500*time.Microsecond), 5
		l, err := links.Create(ctx, a.ID, in)
		if err != nil || !l.ExpiresAt.Equal(end) || l.MaxDepositsPerHour != 5 {
			t.Fatalf("Create = %+v, %v", l, err)
		}
		if got, err := links.Get(ctx, a.ID, l.ID); err != nil || !reflect.DeepEqual(got, l) {
			t.Errorf("Get = %+v, %v; want %+v", got, err, l)
		}
		// Usable until the expiry, excluded.
		if !l.Usable(end.Add(-time.Millisecond)) || l.Usable(end) || !l.Expired(end) || l.Expired(end.Add(-time.Millisecond)) {
			t.Errorf("Usable/Expired around %v wrong for %+v", end, l)
		}
		if _, err := links.GetByTokenHash(ctx, a.ID, id.HashToken(tok), end.Add(-time.Millisecond)); err != nil {
			t.Errorf("GetByTokenHash(before expiry) = %v", err)
		}
		_, err = links.GetByTokenHash(ctx, a.ID, id.HashToken(tok), end)
		wantErr(t, "GetByTokenHash(expired)", err, store.ErrNotFound)

		// A transfer through an expired link is refused.
		tr := newTransfer()
		tr.SenderKind, tr.DropLinkID, tr.CreatedAt = store.DepositorDropLink, l.ID, end
		file := newFile(t, db, a.ID, "a.pdf", 10)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@entity-a.example.com"}, []store.TransferFile{file})
		})
		wantErr(t, "CreateTx(expired link)", err, store.ErrNotFound)

		// Update: same values change nothing; a new expiry and cap are
		// written; a pointer to the zero time clears the expiry.
		later := fixedNow.Add(time.Hour)
		same, changed, err := links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{ExpiresAt: &end, MaxDepositsPerHour: 5}, later)
		if err != nil || changed || !reflect.DeepEqual(same, l) {
			t.Errorf("Update(same limits) = %+v, %v, %v", same, changed, err)
		}
		next := end.Add(24 * time.Hour)
		upd, changed, err := links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{ExpiresAt: &next, MaxDepositsPerHour: 1000}, later)
		if err != nil || !changed || !upd.ExpiresAt.Equal(next) || upd.MaxDepositsPerHour != 1000 {
			t.Errorf("Update(limits) = %+v, %v, %v", upd, changed, err)
		}
		upd, changed, err = links.Update(ctx, a.ID, l.ID, store.DropLinkUpdate{ExpiresAt: &time.Time{}}, later)
		if err != nil || !changed || !upd.ExpiresAt.IsZero() {
			t.Errorf("Update(clear expiry) = %+v, %v, %v", upd, changed, err)
		}
		if got, err := links.Get(ctx, a.ID, l.ID); err != nil || !reflect.DeepEqual(got, upd) {
			t.Errorf("Get after Update = %+v, %v; want %+v", got, err, upd)
		}
		before := fixedNow.Add(-time.Hour)
		for name, u := range map[string]store.DropLinkUpdate{
			"cap":            {MaxDepositsPerHour: 1001},
			"negative cap":   {MaxDepositsPerHour: -2},
			"expiry too old": {ExpiresAt: &before},
		} {
			_, _, err := links.Update(ctx, a.ID, l.ID, u, later)
			wantErr(t, "Update(bad "+name+")", err, store.ErrInvalid)
		}

		// Purge: a link expired for 12 months goes, unless a transfer
		// refers to it; a recent expiry stays.
		expired := func(at time.Time) store.DropLink {
			x, _ := newDropLink(t)
			x.CreatedAt, x.ExpiresAt = at.Add(-time.Hour), at
			x, err := links.Create(ctx, a.ID, x)
			if err != nil {
				t.Fatal(err)
			}
			return x
		}
		old := expired(fixedNow.Add(-400 * 24 * time.Hour))
		kept := expired(fixedNow.Add(-400 * 24 * time.Hour))
		recent := expired(fixedNow.Add(-24 * time.Hour))
		ref := newTransfer()
		ref.SenderKind, ref.DropLinkID, ref.CreatedAt = store.DepositorDropLink, kept.ID, fixedNow.Add(-401*24*time.Hour)
		mustTransfer(t, db, a.ID, ref)
		n, err := links.Purge(ctx, a.ID, fixedNow.Add(-365*24*time.Hour))
		if err != nil || n != 1 {
			t.Fatalf("Purge = %d, %v", n, err)
		}
		_, err = links.Get(ctx, a.ID, old.ID)
		wantErr(t, "Get(purged expired)", err, store.ErrNotFound)
		for _, x := range []store.DropLink{kept, recent, l} {
			if _, err := links.Get(ctx, a.ID, x.ID); err != nil {
				t.Errorf("Get(%s kept) = %v", x.ID, err)
			}
		}
	})
}
