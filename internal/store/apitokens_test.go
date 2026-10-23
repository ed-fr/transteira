package store_test

import (
	"context"
	"crypto/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// randomHash returns a random value of the size of a token hash.
func randomHash(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, store.TokenHashSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// newAPIToken returns a valid new token record.
func newAPIToken(t *testing.T) store.APIToken {
	t.Helper()
	return store.APIToken{
		ID: id.New(id.APIToken), Name: "Nightly export", Prefix: "tt_AbCd", TokenHash: randomHash(t),
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.7/24"), netip.MustParsePrefix("2001:db8::/32")},
		CreatedBy:    "admin.a",
	}
}

// mustAPIToken stores tok for tid and returns it.
func mustAPIToken(t *testing.T, db *store.DB, tid tenant.ID, tok store.APIToken) store.APIToken {
	t.Helper()
	got, err := db.APITokens().Create(context.Background(), tid, tok)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	return got
}

func TestAPITokensCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		tokens := db.APITokens()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		in := newAPIToken(t)
		in.ExpiresAt = fixedNow.Add(48 * time.Hour)
		first := mustAPIToken(t, db, a.ID, in)
		wantCIDRs := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
		if !reflect.DeepEqual(first.AllowedCIDRs, wantCIDRs) || !first.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) ||
			!first.ExpiresAt.Equal(in.ExpiresAt.Truncate(time.Millisecond)) {
			t.Errorf("Create = %+v", first)
		}
		got, err := tokens.Get(ctx, a.ID, first.ID)
		if err != nil || !reflect.DeepEqual(got, first) {
			t.Errorf("Get = %+v, %v; want %+v", got, err, first)
		}
		if got, err := tokens.GetByHash(ctx, a.ID, in.TokenHash); err != nil || got.ID != first.ID {
			t.Errorf("GetByHash = %+v, %v", got, err)
		}
		// A token of A is unknown from B, by ID and by hash (T-69).
		_, err = tokens.Get(ctx, b.ID, first.ID)
		wantErr(t, "Get from B", err, store.ErrNotFound)
		_, err = tokens.GetByHash(ctx, b.ID, in.TokenHash)
		wantErr(t, "GetByHash from B", err, store.ErrNotFound)
		_, err = tokens.GetByHash(ctx, a.ID, randomHash(t))
		wantErr(t, "GetByHash(unknown)", err, store.ErrNotFound)

		later := newAPIToken(t)
		later.CreatedAt = fixedNow.Add(time.Minute)
		second := mustAPIToken(t, db, a.ID, later)
		mustAPIToken(t, db, b.ID, newAPIToken(t))
		list, err := tokens.List(ctx, a.ID)
		if err != nil || len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
			t.Errorf("List(A) = %+v, %v", list, err)
		}
		if list, err := tokens.List(ctx, newTenant(t, db, "empty.example.com").ID); err != nil || list == nil || len(list) != 0 {
			t.Errorf("List(empty) = %#v, %v", list, err)
		}

		// Conflicts: same ID, same hash (even in another tenant).
		dupID := newAPIToken(t)
		dupID.ID = first.ID
		_, err = tokens.Create(ctx, a.ID, dupID)
		wantErr(t, "Create(duplicate id)", err, store.ErrConflict)
		dupHash := newAPIToken(t)
		dupHash.TokenHash = in.TokenHash
		_, err = tokens.Create(ctx, b.ID, dupHash)
		wantErr(t, "Create(duplicate hash)", err, store.ErrConflict)
		_, err = tokens.Create(ctx, tenant.ID(id.New(id.Tenant)), newAPIToken(t))
		wantErr(t, "Create(unknown tenant)", err, store.ErrNotFound)

		// Update: merge semantics.
		upd, err := tokens.Update(ctx, a.ID, first.ID, store.APITokenUpdate{Name: "Renamed"})
		if err != nil || upd.Name != "Renamed" || !reflect.DeepEqual(upd.AllowedCIDRs, wantCIDRs) {
			t.Errorf("Update(name) = %+v, %v", upd, err)
		}
		one := []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}
		upd, err = tokens.Update(ctx, a.ID, first.ID, store.APITokenUpdate{AllowedCIDRs: one})
		if err != nil || upd.Name != "Renamed" || !reflect.DeepEqual(upd.AllowedCIDRs, one) {
			t.Errorf("Update(cidrs) = %+v, %v", upd, err)
		}
		if upd, err := tokens.Update(ctx, a.ID, first.ID, store.APITokenUpdate{}); err != nil || upd.Name != "Renamed" {
			t.Errorf("Update(nothing) = %+v, %v", upd, err)
		}
		_, err = tokens.Update(ctx, b.ID, first.ID, store.APITokenUpdate{Name: "Stolen"})
		wantErr(t, "Update from B", err, store.ErrNotFound)
		_, err = tokens.Update(ctx, a.ID, id.New(id.APIToken), store.APITokenUpdate{Name: "x"})
		wantErr(t, "Update(unknown)", err, store.ErrNotFound)
		_, err = tokens.Update(ctx, a.ID, first.ID, store.APITokenUpdate{Name: "two\nlines"})
		wantErr(t, "Update(bad name)", err, store.ErrInvalid)
		_, err = tokens.Update(ctx, a.ID, first.ID, store.APITokenUpdate{AllowedCIDRs: []netip.Prefix{}})
		wantErr(t, "Update(no cidrs)", err, store.ErrInvalid)

		// Revoke: once, then a no-op; never from another tenant.
		_, _, err = tokens.Revoke(ctx, b.ID, first.ID, fixedNow)
		wantErr(t, "Revoke from B", err, store.ErrNotFound)
		_, _, err = tokens.Revoke(ctx, a.ID, id.New(id.APIToken), fixedNow)
		wantErr(t, "Revoke(unknown)", err, store.ErrNotFound)
		rev, did, err := tokens.Revoke(ctx, a.ID, first.ID, fixedNow.Add(time.Hour))
		if err != nil || !did || !rev.Revoked() || !rev.RevokedAt.Equal(fixedNow.Add(time.Hour).Truncate(time.Millisecond)) {
			t.Errorf("Revoke = %+v, %v, %v", rev, did, err)
		}
		again, did, err := tokens.Revoke(ctx, a.ID, first.ID, time.Time{})
		if err != nil || did || !again.RevokedAt.Equal(rev.RevokedAt) {
			t.Errorf("Revoke(again) = %+v, %v, %v", again, did, err)
		}
		_, err = tokens.Update(ctx, a.ID, first.ID, store.APITokenUpdate{Name: "Late"})
		wantErr(t, "Update(revoked)", err, store.ErrConflict)
		if got, _ := tokens.GetByHash(ctx, a.ID, in.TokenHash); !got.Revoked() || got.Name != "Renamed" {
			t.Errorf("revoked token = %+v", got)
		}

		// Last use: forward only; an unknown token is ignored.
		if err := tokens.TouchLastUsed(ctx, a.ID, second.ID, fixedNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := tokens.TouchLastUsed(ctx, a.ID, second.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		if got, _ := tokens.Get(ctx, a.ID, second.ID); !got.LastUsedAt.Equal(fixedNow.Add(time.Hour).Truncate(time.Millisecond)) {
			t.Errorf("LastUsedAt = %v", got.LastUsedAt)
		}
		if err := tokens.TouchLastUsed(ctx, b.ID, second.ID, time.Time{}); err != nil {
			t.Errorf("TouchLastUsed from B = %v", err)
		}
		if got, _ := tokens.Get(ctx, a.ID, second.ID); !got.LastUsedAt.Equal(fixedNow.Add(time.Hour).Truncate(time.Millisecond)) {
			t.Errorf("LastUsedAt after B = %v", got.LastUsedAt)
		}

		// Bad tenants.
		for _, tid := range badTenants {
			_, err := tokens.Create(ctx, tid, newAPIToken(t))
			wantErr(t, "Create(bad tenant)", err, store.ErrInvalid)
			_, err = tokens.Get(ctx, tid, first.ID)
			wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
			_, err = tokens.GetByHash(ctx, tid, in.TokenHash)
			wantErr(t, "GetByHash(bad tenant)", err, store.ErrInvalid)
			_, err = tokens.List(ctx, tid)
			wantErr(t, "List(bad tenant)", err, store.ErrInvalid)
			_, err = tokens.Update(ctx, tid, first.ID, store.APITokenUpdate{})
			wantErr(t, "Update(bad tenant)", err, store.ErrInvalid)
			_, _, err = tokens.Revoke(ctx, tid, first.ID, fixedNow)
			wantErr(t, "Revoke(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "TouchLastUsed(bad tenant)", tokens.TouchLastUsed(ctx, tid, first.ID, fixedNow), store.ErrInvalid)
		}
		_, err = tokens.GetByHash(ctx, a.ID, []byte("short"))
		wantErr(t, "GetByHash(short hash)", err, store.ErrInvalid)
	})
}

func TestAPITokensCreateValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t, storetest.SQLite(t))
	a := newTenant(t, db, "transfer.entity-a.example.com")
	v4 := netip.MustParsePrefix("192.0.2.0/24")
	many := make([]netip.Prefix, store.MaxAPITokenCIDRs+1)
	for i := range many {
		many[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)
	}
	cases := map[string]func(*store.APIToken){
		"id":             func(k *store.APIToken) { k.ID = id.New(id.Transfer) },
		"empty name":     func(k *store.APIToken) { k.Name = "" },
		"long name":      func(k *store.APIToken) { k.Name = strings.Repeat("n", store.MaxAPITokenNameLen+1) },
		"control name":   func(k *store.APIToken) { k.Name = "a\tb" },
		"empty prefix":   func(k *store.APIToken) { k.Prefix = "" },
		"long prefix":    func(k *store.APIToken) { k.Prefix = strings.Repeat("p", store.MaxAPITokenPrefixLen+1) },
		"hash":           func(k *store.APIToken) { k.TokenHash = []byte{1} },
		"no creator":     func(k *store.APIToken) { k.CreatedBy = "" },
		"bad creator":    func(k *store.APIToken) { k.CreatedBy = "a\nb" },
		"past expiry":    func(k *store.APIToken) { k.ExpiresAt = fixedNow },
		"used":           func(k *store.APIToken) { k.LastUsedAt = fixedNow },
		"revoked":        func(k *store.APIToken) { k.RevokedAt = fixedNow },
		"no cidrs":       func(k *store.APIToken) { k.AllowedCIDRs = nil },
		"too many cidrs": func(k *store.APIToken) { k.AllowedCIDRs = many },
		"invalid cidr":   func(k *store.APIToken) { k.AllowedCIDRs = []netip.Prefix{{}} },
		"duplicate cidr": func(k *store.APIToken) {
			k.AllowedCIDRs = []netip.Prefix{v4, netip.MustParsePrefix("192.0.2.1/24")}
		},
		"too many senders": func(k *store.APIToken) { k.AllowedSenders = make([]string, store.MaxAPITokenSenders+1) },
		"bad sender":       func(k *store.APIToken) { k.AllowedSenders = []string{"a@b@c"} },
		"bad domain":       func(k *store.APIToken) { k.AllowedSenders = []string{"example.com:25"} },
		"empty sender":     func(k *store.APIToken) { k.AllowedSenders = []string{""} },
		"duplicate sender": func(k *store.APIToken) {
			k.AllowedSenders = []string{"Ops@Example.com", "ops@example.com."}
		},
	}
	for name, mutate := range cases {
		tok := newAPIToken(t)
		mutate(&tok)
		_, err := db.APITokens().Create(ctx, a.ID, tok)
		wantErr(t, "Create("+name+")", err, store.ErrInvalid)
	}
}

// TestAPITokenSenders stores, reads and replaces the allowed senders of a
// token, on both engines.
func TestAPITokenSenders(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		tokens := db.APITokens()
		a := newTenant(t, db, "transfer.entity-a.example.com")

		// Absent: stored as an empty list, read back non-nil.
		plain := mustAPIToken(t, db, a.ID, newAPIToken(t))
		if plain.AllowedSenders == nil || len(plain.AllowedSenders) != 0 {
			t.Errorf("Create(no senders).AllowedSenders = %#v", plain.AllowedSenders)
		}
		if got, err := tokens.Get(ctx, a.ID, plain.ID); err != nil || got.AllowedSenders == nil || len(got.AllowedSenders) != 0 {
			t.Errorf("Get(no senders).AllowedSenders = %#v, %v", got.AllowedSenders, err)
		}

		in := newAPIToken(t)
		in.AllowedSenders = []string{" Reporting@Entity-A.Example.com ", "ERP.entity-a.example.com.", "bücher.example"}
		tok := mustAPIToken(t, db, a.ID, in)
		want := []string{"reporting@entity-a.example.com", "erp.entity-a.example.com", "xn--bcher-kva.example"}
		if !reflect.DeepEqual(tok.AllowedSenders, want) {
			t.Errorf("Create.AllowedSenders = %q, want %q", tok.AllowedSenders, want)
		}
		if got, err := tokens.Get(ctx, a.ID, tok.ID); err != nil || !reflect.DeepEqual(got.AllowedSenders, want) {
			t.Errorf("Get.AllowedSenders = %q, %v", got.AllowedSenders, err)
		}

		// nil keeps, a list replaces, an empty list clears.
		upd, err := tokens.Update(ctx, a.ID, tok.ID, store.APITokenUpdate{Name: "x"})
		if err != nil || !reflect.DeepEqual(upd.AllowedSenders, want) {
			t.Errorf("Update(name).AllowedSenders = %q, %v", upd.AllowedSenders, err)
		}
		upd, err = tokens.Update(ctx, a.ID, tok.ID, store.APITokenUpdate{AllowedSenders: []string{"Ops@entity-a.example.com"}})
		if err != nil || !reflect.DeepEqual(upd.AllowedSenders, []string{"ops@entity-a.example.com"}) {
			t.Errorf("Update(senders).AllowedSenders = %q, %v", upd.AllowedSenders, err)
		}
		upd, err = tokens.Update(ctx, a.ID, tok.ID, store.APITokenUpdate{AllowedSenders: []string{}})
		if err != nil || upd.AllowedSenders == nil || len(upd.AllowedSenders) != 0 {
			t.Errorf("Update(no senders).AllowedSenders = %#v, %v", upd.AllowedSenders, err)
		}
		_, err = tokens.Update(ctx, a.ID, tok.ID, store.APITokenUpdate{AllowedSenders: []string{"not a domain"}})
		wantErr(t, "Update(bad sender)", err, store.ErrInvalid)
	})
}

func TestAPITokenAllowsSender(t *testing.T) {
	t.Parallel()
	unrestricted := store.APIToken{}
	if !unrestricted.AllowsSender("alice@entity-a.example.com") {
		t.Error("a token without senders refuses an address")
	}
	tok := store.APIToken{AllowedSenders: []string{"reporting@entity-a.example.com", "erp.entity-a.example.com"}}
	for email, want := range map[string]bool{
		"reporting@entity-a.example.com":      true,
		"anyone@erp.entity-a.example.com":     true,
		"alice@entity-a.example.com":          false,
		"anyone@sub.erp.entity-a.example.com": false,
		"reporting@erp.entity-a.example.com":  true,
		"erp.entity-a.example.com":            false,
		"x@entity-a.example.com.evil.example": false,
	} {
		if got := tok.AllowsSender(email); got != want {
			t.Errorf("AllowsSender(%q) = %v, want %v", email, got, want)
		}
	}
}

func TestAPITokenState(t *testing.T) {
	t.Parallel()
	tok := store.APIToken{}
	if tok.Revoked() || tok.Expired(fixedNow) || !tok.Usable(fixedNow) {
		t.Errorf("fresh token state: revoked %v expired %v", tok.Revoked(), tok.Expired(fixedNow))
	}
	tok.ExpiresAt = fixedNow
	if !tok.Expired(fixedNow) || tok.Expired(fixedNow.Add(-time.Nanosecond)) || tok.Usable(fixedNow) {
		t.Error("expiry is not inclusive of its instant")
	}
	tok = store.APIToken{RevokedAt: fixedNow}
	if !tok.Revoked() || tok.Usable(fixedNow) {
		t.Error("revoked token is usable")
	}
}

func TestTransfersAPIToken(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		tokA := mustAPIToken(t, db, a.ID, newAPIToken(t))
		tokA2 := mustAPIToken(t, db, a.ID, newAPIToken(t))
		tokB := mustAPIToken(t, db, b.ID, newAPIToken(t))
		create := func(tid tenant.ID, tr store.Transfer, f store.TransferFile) error {
			return inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				return transfers.CreateTx(ctx, tx, tr, []string{"x@example.com"}, []store.TransferFile{f})
			})
		}
		byToken := func(tokID string) store.Transfer {
			tr := newTransfer()
			tr.APITokenID = tokID
			return tr
		}

		d := mustTransfer(t, db, a.ID, byToken(tokA.ID))
		if d.APITokenID != tokA.ID || d.SenderKind != store.DepositorInternal {
			t.Errorf("token transfer = %+v", d.Transfer)
		}
		if s := mustTransfer(t, db, a.ID, newTransfer()); s.APITokenID != "" {
			t.Errorf("session transfer APITokenID = %q", s.APITokenID)
		}

		// The token must be a usable token of the same tenant.
		wantErr(t, "CreateTx(token of B)", create(a.ID, byToken(tokB.ID), newFile(t, db, a.ID, "x", 1)), store.ErrNotFound)
		wantErr(t, "CreateTx(unknown token)", create(a.ID, byToken(id.New(id.APIToken)), newFile(t, db, a.ID, "x", 1)), store.ErrNotFound)
		wantErr(t, "CreateTx(malformed token)", create(a.ID, byToken("tok_bad"), newFile(t, db, a.ID, "x", 1)), store.ErrInvalid)
		ext := byToken(tokA.ID)
		ext.SenderKind, ext.InvitationID = store.DepositorExternal, id.New(id.Invitation)
		wantErr(t, "CreateTx(external token sender)", create(a.ID, ext, newFile(t, db, a.ID, "x", 1)), store.ErrInvalid)
		expiring := newAPIToken(t)
		expiring.ExpiresAt = fixedNow.Add(time.Hour)
		expiring = mustAPIToken(t, db, a.ID, expiring)
		late := byToken(expiring.ID)
		late.CreatedAt = fixedNow.Add(time.Hour)
		wantErr(t, "CreateTx(expired token)", create(a.ID, late, newFile(t, db, a.ID, "x", 1)), store.ErrNotFound)
		revoked := mustAPIToken(t, db, a.ID, newAPIToken(t))
		if _, _, err := db.APITokens().Revoke(ctx, a.ID, revoked.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "CreateTx(revoked token)", create(a.ID, byToken(revoked.ID), newFile(t, db, a.ID, "x", 1)), store.ErrNotFound)

		// Idempotency keys: per token for the tokens, per address for the
		// sessions; the two never collide.
		const key = "token-key-1"
		since := fixedNow.Add(-store.IdempotencyRetention)
		oldTok := byToken(tokA.ID)
		oldTok.IdempotencyKey, oldTok.CreatedAt = key, fixedNow.Add(-25*time.Hour)
		mustTransfer(t, db, a.ID, oldTok)
		withKey := byToken(tokA.ID)
		withKey.IdempotencyKey = key
		tk := mustTransfer(t, db, a.ID, withKey)
		if o, err := transfers.Get(ctx, a.ID, oldTok.ID); err != nil || o.IdempotencyKey != "" {
			t.Errorf("old token transfer kept its key: %+v, %v", o.Transfer, err)
		}
		session := newTransfer()
		session.IdempotencyKey = key
		sd := mustTransfer(t, db, a.ID, session)
		other := byToken(tokA2.ID)
		other.IdempotencyKey = key
		mustTransfer(t, db, a.ID, other)
		dup := byToken(tokA.ID)
		dup.IdempotencyKey, dup.SenderEmail = key, "dave@entity-a.example.com"
		wantErr(t, "CreateTx(token key in use)", create(a.ID, dup, newFile(t, db, a.ID, "x", 1)), store.ErrConflict)
		if got, err := transfers.GetByTokenIdempotencyKey(ctx, a.ID, tokA.ID, key, since); err != nil || !reflect.DeepEqual(got, tk) {
			t.Errorf("GetByTokenIdempotencyKey = %+v, %v; want %+v", got, err, tk)
		}
		if got, err := transfers.GetByIdempotencyKey(ctx, a.ID, session.SenderEmail, key, since); err != nil || got.ID != sd.ID {
			t.Errorf("GetByIdempotencyKey(session) = %s, %v; want %s", got.ID, err, sd.ID)
		}
		_, err := transfers.GetByTokenIdempotencyKey(ctx, b.ID, tokA.ID, key, since)
		wantErr(t, "GetByTokenIdempotencyKey from B", err, store.ErrNotFound)
		_, err = transfers.GetByTokenIdempotencyKey(ctx, a.ID, tokA.ID, key, fixedNow.Add(time.Second))
		wantErr(t, "GetByTokenIdempotencyKey(too old)", err, store.ErrNotFound)
		_, err = transfers.GetByTokenIdempotencyKey(ctx, a.ID, "tok_bad", key, since)
		wantErr(t, "GetByTokenIdempotencyKey(bad token)", err, store.ErrInvalid)
		_, err = transfers.GetByTokenIdempotencyKey(ctx, a.ID, tokA.ID, "", since)
		wantErr(t, "GetByTokenIdempotencyKey(bad key)", err, store.ErrInvalid)
		for _, tid := range badTenants {
			_, err = transfers.GetByTokenIdempotencyKey(ctx, tid, tokA.ID, key, since)
			wantErr(t, "GetByTokenIdempotencyKey(bad tenant)", err, store.ErrInvalid)
		}

		// Open transfers: per token; the session count ignores the token
		// transfers of the same address.
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if n, err := transfers.CountUploadingByTokenTx(ctx, tx, tokA.ID, time.Time{}); err != nil || n != 3 {
				t.Errorf("CountUploadingByTokenTx(tokA) = %d, %v; want 3", n, err)
			}
			if n, err := transfers.CountUploadingByTokenTx(ctx, tx, tokA.ID, fixedNow); err != nil || n != 2 {
				t.Errorf("CountUploadingByTokenTx(tokA, since) = %d, %v; want 2", n, err)
			}
			if n, err := transfers.CountUploadingByTokenTx(ctx, tx, tokB.ID, time.Time{}); err != nil || n != 0 {
				t.Errorf("CountUploadingByTokenTx(tokB in A) = %d, %v; want 0", n, err)
			}
			if n, err := transfers.CountUploadingTx(ctx, tx, "alice@entity-a.example.com", time.Time{}); err != nil || n != 2 {
				t.Errorf("CountUploadingTx(alice) = %d, %v; want 2", n, err)
			}
			list, err := transfers.ListUploadingByTokenTx(ctx, tx, tokA.ID, time.Time{}, 10)
			if err != nil || len(list) != 3 || list[2].ID != oldTok.ID {
				t.Errorf("ListUploadingByTokenTx = %+v, %v", list, err)
			}
			for _, tr := range list {
				if tr.APITokenID != tokA.ID {
					t.Errorf("listed transfer of token %q", tr.APITokenID)
				}
			}
			sessions, err := transfers.ListUploadingTx(ctx, tx, "alice@entity-a.example.com", time.Time{}, 10)
			if err != nil || len(sessions) != 2 {
				t.Errorf("ListUploadingTx(alice) = %d, %v; want 2", len(sessions), err)
			}
			_, err = transfers.CountUploadingByTokenTx(ctx, tx, "nope", time.Time{})
			wantErr(t, "CountUploadingByTokenTx(bad token)", err, store.ErrInvalid)
			_, err = transfers.ListUploadingByTokenTx(ctx, tx, "nope", time.Time{}, 10)
			wantErr(t, "ListUploadingByTokenTx(bad token)", err, store.ErrInvalid)
			for _, limit := range []int{0, store.MaxTransferFiles + 1} {
				_, err = transfers.ListUploadingByTokenTx(ctx, tx, tokA.ID, time.Time{}, limit)
				wantErr(t, "ListUploadingByTokenTx(bad limit)", err, store.ErrInvalid)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ctxDone, cancel := context.WithCancel(ctx)
		cancel()
		for i, call := range []func(tx *store.ScopedTx) error{
			func(tx *store.ScopedTx) error {
				_, err := transfers.CountUploadingByTokenTx(ctxDone, tx, tokA.ID, time.Time{})
				return err
			},
			func(tx *store.ScopedTx) error {
				_, err := transfers.ListUploadingByTokenTx(ctxDone, tx, tokA.ID, time.Time{}, 10)
				return err
			},
		} {
			if err := inTx(t, db, a.ID, call); err == nil {
				t.Errorf("call %d with a canceled context succeeded", i)
			}
		}

		// Ownership: the token owns its transfers only.
		if !(store.Depositor{APITokenID: tokA.ID}).Owns(d.Transfer) ||
			(store.Depositor{APITokenID: tokA2.ID}).Owns(d.Transfer) ||
			(store.Depositor{Email: d.SenderEmail, Kind: store.DepositorInternal}).Owns(d.Transfer) {
			t.Error("token transfer ownership")
		}
	})
}
