package store_test

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// testPseudonym is a well-formed pseudonym of an erased data subject.
const testPseudonym = "erased-0123456789abcdef"

// transferAt creates a transfer of tid sent by sender at created, with the
// default recipients of mustTransfer.
func transferAt(t *testing.T, db *store.DB, tid tenant.ID, sender string, created time.Time) store.TransferDetails {
	t.Helper()
	tr := newTransfer()
	tr.SenderEmail, tr.CreatedAt = sender, created
	return mustTransfer(t, db, tid, tr)
}

// transferIDs returns the identifiers of a page of transfers.
func transferIDs(p store.Page[store.AdminTransfer]) []string {
	out := make([]string, len(p.Items))
	for i, t := range p.Items {
		out[i] = t.ID
	}
	return out
}

func TestTransfersAdminView(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		// The sender IP is stored at creation, an IPv4-mapped address as
		// IPv4; a new transfer was never downloaded.
		tr := newTransfer()
		tr.CreatedAt = msNow.Add(-2 * time.Hour)
		tr.SenderIP = netip.MustParseAddr("::ffff:192.0.2.10")
		t1 := mustTransfer(t, db, a.ID, tr)
		if t1.SenderIP != netip.MustParseAddr("192.0.2.10") || t1.DownloadCount != 0 {
			t.Errorf("created transfer: ip %v, downloads %d", t1.SenderIP, t1.DownloadCount)
		}
		t2 := transferAt(t, db, a.ID, "dave@entity-a.example.com", msNow.Add(-time.Hour))
		if t2.SenderIP.IsValid() {
			t.Errorf("transfer without sender ip reads %v", t2.SenderIP)
		}
		t3 := transferAt(t, db, b.ID, "alice@entity-a.example.com", msNow)
		bad := newTransfer()
		bad.DownloadCount = 1
		badFile := newFile(t, db, a.ID, "x", 1)
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return transfers.CreateTx(ctx, tx, bad, []string{"bob@partner.example.org"}, []store.TransferFile{badFile})
		})
		wantErr(t, "CreateTx(downloaded)", err, store.ErrInvalid)

		list := func(f store.AdminTransferFilter) store.Page[store.AdminTransfer] {
			t.Helper()
			p, err := transfers.AdminList(ctx, a.ID, f)
			if err != nil {
				t.Fatalf("AdminList(%+v): %v", f, err)
			}
			return p
		}
		all := list(store.AdminTransferFilter{})
		if got := transferIDs(all); !slices.Equal(got, []string{t2.ID, t1.ID}) || all.NextCursor != "" {
			t.Fatalf("AdminList = %v, cursor %q", got, all.NextCursor)
		}
		want := store.AdminTransfer{Transfer: t1.Transfer, Recipients: t1.Recipients, FileCount: 1}
		if !reflect.DeepEqual(all.Items[1], want) {
			t.Errorf("AdminList item = %+v, want %+v", all.Items[1], want)
		}
		for _, tc := range []struct {
			name string
			f    store.AdminTransferFilter
			want []string
		}{
			{"sender", store.AdminTransferFilter{Email: "Alice@Entity-A.example.com"}, []string{t1.ID}},
			{"recipient", store.AdminTransferFilter{Email: "bob@partner.example.org"}, []string{t2.ID, t1.ID}},
			{"unknown address", store.AdminTransferFilter{Email: "nobody@example.com"}, []string{}},
			{"status", store.AdminTransferFilter{Status: store.TransferUploading}, []string{t2.ID, t1.ID}},
			{"other status", store.AdminTransferFilter{Status: store.TransferAvailable}, []string{}},
			{"created after", store.AdminTransferFilter{CreatedAfter: msNow.Add(-90 * time.Minute)}, []string{t2.ID}},
			{"created after, exclusive", store.AdminTransferFilter{CreatedAfter: t2.CreatedAt}, []string{}},
			{"combined", store.AdminTransferFilter{Status: store.TransferUploading, Email: "dave@entity-a.example.com"}, []string{t2.ID}},
		} {
			if got := transferIDs(list(tc.f)); !slices.Equal(got, tc.want) {
				t.Errorf("%s: AdminList = %v, want %v", tc.name, got, tc.want)
			}
		}
		first := list(store.AdminTransferFilter{Limit: 1})
		if got := transferIDs(first); !slices.Equal(got, []string{t2.ID}) || first.NextCursor == "" {
			t.Fatalf("first page = %v, cursor %q", got, first.NextCursor)
		}
		second := list(store.AdminTransferFilter{Limit: 1, Cursor: first.NextCursor})
		if got := transferIDs(second); !slices.Equal(got, []string{t1.ID}) || second.NextCursor != "" {
			t.Errorf("second page = %v, cursor %q", got, second.NextCursor)
		}
		// Tenant B sees its own transfer only, even with A's sender.
		pb, err := transfers.AdminList(ctx, b.ID, store.AdminTransferFilter{Email: "alice@entity-a.example.com"})
		if err != nil || !slices.Equal(transferIDs(pb), []string{t3.ID}) {
			t.Errorf("AdminList(B) = %v, %v", transferIDs(pb), err)
		}
		for name, f := range map[string]store.AdminTransferFilter{
			"status":         {Status: "lost"},
			"address":        {Email: "not an address"},
			"cursor":         {Cursor: "x"},
			"cursor id kind": {Cursor: "1:" + id.New(id.Invitation)},
		} {
			_, err := transfers.AdminList(ctx, a.ID, f)
			wantErr(t, "AdminList(bad "+name+")", err, store.ErrInvalid)
		}
		_, err = transfers.AdminList(ctx, "bad", store.AdminTransferFilter{})
		wantErr(t, "AdminList(bad tenant)", err, store.ErrInvalid)

		// Download counter.
		for range 2 {
			if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.IncrementDownloadsTx(ctx, tx, t1.ID) }); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := transfers.Get(ctx, a.ID, t1.ID); err != nil || got.DownloadCount != 2 {
			t.Errorf("download count = %d, %v", got.DownloadCount, err)
		}
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error { return transfers.IncrementDownloadsTx(ctx, tx, t1.ID) })
		wantErr(t, "IncrementDownloadsTx(other tenant)", err, store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.IncrementDownloadsTx(ctx, tx, id.New(id.Transfer)) })
		wantErr(t, "IncrementDownloadsTx(unknown)", err, store.ErrNotFound)

		// Lookups by address and invitation, in every status.
		inv := mustInvitation(t, db, a.ID)
		ext := newTransfer()
		ext.SenderEmail, ext.SenderKind, ext.InvitationID = inv.Email, store.DepositorExternal, inv.ID
		tx4 := mustTransfer(t, db, a.ID, ext)
		lookups := []struct {
			name string
			run  func() ([]string, error)
			want []string
		}{
			{"sender", func() ([]string, error) { return transfers.IDsBySender(ctx, a.ID, "ALICE@entity-a.example.com") }, []string{t1.ID}},
			{"sender B", func() ([]string, error) { return transfers.IDsBySender(ctx, b.ID, "alice@entity-a.example.com") }, []string{t3.ID}},
			{"recipient", func() ([]string, error) { return transfers.IDsByRecipient(ctx, a.ID, "bob@partner.example.org") }, sorted(t1.ID, t2.ID, tx4.ID)},
			{"no recipient", func() ([]string, error) { return transfers.IDsByRecipient(ctx, a.ID, "nobody@example.com") }, []string{}},
			{"invitation", func() ([]string, error) { return transfers.IDsByInvitation(ctx, a.ID, inv.ID) }, []string{tx4.ID}},
			{"invitation B", func() ([]string, error) { return transfers.IDsByInvitation(ctx, b.ID, inv.ID) }, []string{}},
		}
		for _, l := range lookups {
			if got, err := l.run(); err != nil || !slices.Equal(got, l.want) {
				t.Errorf("%s: %v, %v; want %v", l.name, got, err, l.want)
			}
		}
		for name, run := range map[string]func() error{
			"sender address":    func() error { _, err := transfers.IDsBySender(ctx, a.ID, "x"); return err },
			"recipient address": func() error { _, err := transfers.IDsByRecipient(ctx, a.ID, "x"); return err },
			"invitation":        func() error { _, err := transfers.IDsByInvitation(ctx, a.ID, "inv_x"); return err },
			"sender tenant":     func() error { _, err := transfers.IDsBySender(ctx, "bad", "a@example.com"); return err },
			"invitation tenant": func() error { _, err := transfers.IDsByInvitation(ctx, "bad", inv.ID); return err },
		} {
			wantErr(t, "bad "+name, run(), store.ErrInvalid)
		}

		// Recipient removal.
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if err := transfers.RemoveRecipientTx(ctx, tx, t1.ID, "Carol@Entity-A.example.com"); err != nil {
				return err
			}
			n, err := transfers.CountRecipientsTx(ctx, tx, t1.ID)
			if err == nil && n != 1 {
				t.Errorf("CountRecipientsTx = %d, want 1", n)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := transfers.Get(ctx, a.ID, t1.ID); err != nil || !slices.Equal(got.Recipients, []string{"bob@partner.example.org"}) {
			t.Errorf("recipients after removal = %v, %v", got.Recipients, err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return transfers.RemoveRecipientTx(ctx, tx, t1.ID, "carol@entity-a.example.com")
		})
		wantErr(t, "RemoveRecipientTx(twice)", err, store.ErrNotFound)
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			return transfers.RemoveRecipientTx(ctx, tx, t1.ID, "bob@partner.example.org")
		})
		wantErr(t, "RemoveRecipientTx(other tenant)", err, store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.RemoveRecipientTx(ctx, tx, t1.ID, "x") })
		wantErr(t, "RemoveRecipientTx(bad address)", err, store.ErrInvalid)
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			n, err := transfers.CountRecipientsTx(ctx, tx, t1.ID)
			if n != 0 {
				t.Errorf("CountRecipientsTx(other tenant) = %d", n)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}

		// Storage used by every tenant.
		newTenant(t, db, "transfer.entity-c.example.com")
		used, err := transfers.UsedBytesAll(ctx)
		if err != nil || !reflect.DeepEqual(used, map[tenant.ID]int64{a.ID: 30, b.ID: 10}) {
			t.Errorf("UsedBytesAll = %v, %v", used, err)
		}
	})
}

// sorted returns ids sorted.
func sorted(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

func TestInvitationsAdmin(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Invitations()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		create := func(tid tenant.ID, email, inviter string, created time.Time) store.Invitation {
			t.Helper()
			inv := newInvitation(t)
			inv.Email, inv.InvitedBy, inv.CreatedAt = email, inviter, created
			if err := repo.Create(ctx, tid, inv); err != nil {
				t.Fatalf("Create invitation: %v", err)
			}
			got, err := repo.Get(ctx, tid, inv.ID)
			if err != nil {
				t.Fatal(err)
			}
			return got
		}
		const alice = "alice@entity-a.example.com"
		expired := create(a.ID, "erin@partner.example.org", alice, msNow.AddDate(-1, -1, 0))
		pending := create(a.ID, "bob@partner.example.org", alice, msNow.Add(-3*time.Hour))
		used := create(a.ID, "carol@partner.example.org", alice, msNow.Add(-2*time.Hour))
		revoked := create(a.ID, "bob@partner.example.org", "dave@entity-a.example.com", msNow.Add(-time.Hour))
		other := create(b.ID, "bob@partner.example.org", alice, msNow)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, used.ID, msNow.Add(-time.Minute)) }); err != nil {
			t.Fatal(err)
		}
		if err := repo.Revoke(ctx, a.ID, revoked.ID, msNow.Add(-30*time.Minute)); err != nil {
			t.Fatal(err)
		}

		ids := func(p store.Page[store.Invitation]) []string {
			out := make([]string, len(p.Items))
			for i, inv := range p.Items {
				out[i] = inv.ID
			}
			return out
		}
		all, err := repo.List(ctx, a.ID, store.InvitationFilter{})
		if err != nil || !slices.Equal(ids(all), []string{revoked.ID, used.ID, pending.ID, expired.ID}) {
			t.Fatalf("List = %v, %v", ids(all), err)
		}
		wantStatus := []store.InvitationStatus{store.InvitationRevoked, store.InvitationUsed, store.InvitationPending, store.InvitationExpired}
		for i, inv := range all.Items {
			if got := inv.Status(msNow); got != wantStatus[i] {
				t.Errorf("%s status = %s, want %s", inv.ID, got, wantStatus[i])
			}
		}
		for status, want := range map[store.InvitationStatus]string{
			store.InvitationPending: pending.ID, store.InvitationUsed: used.ID,
			store.InvitationExpired: expired.ID, store.InvitationRevoked: revoked.ID,
		} {
			p, err := repo.List(ctx, a.ID, store.InvitationFilter{Status: status, Now: msNow})
			if err != nil || !slices.Equal(ids(p), []string{want}) {
				t.Errorf("List(%s) = %v, %v", status, ids(p), err)
			}
		}
		// The status follows Now: a year later, the pending one expired.
		p, err := repo.List(ctx, a.ID, store.InvitationFilter{Status: store.InvitationExpired, Now: msNow.AddDate(1, 0, 0)})
		if err != nil || !slices.Equal(ids(p), []string{used.ID, pending.ID, expired.ID}) {
			t.Errorf("List(expired, later) = %v, %v", ids(p), err)
		}
		page, err := repo.List(ctx, a.ID, store.InvitationFilter{Limit: 3})
		if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
			t.Fatalf("List(limit 3) = %v, %q, %v", ids(page), page.NextCursor, err)
		}
		next, err := repo.List(ctx, a.ID, store.InvitationFilter{Limit: 3, Cursor: page.NextCursor})
		if err != nil || !slices.Equal(ids(next), []string{expired.ID}) || next.NextCursor != "" {
			t.Errorf("List(page 2) = %v, %q, %v", ids(next), next.NextCursor, err)
		}
		if pb, err := repo.List(ctx, b.ID, store.InvitationFilter{}); err != nil || !slices.Equal(ids(pb), []string{other.ID}) {
			t.Errorf("List(B) = %v, %v", ids(pb), err)
		}
		_, err = repo.List(ctx, a.ID, store.InvitationFilter{Status: "lost"})
		wantErr(t, "List(bad status)", err, store.ErrInvalid)
		_, err = repo.List(ctx, a.ID, store.InvitationFilter{Cursor: "1:x"})
		wantErr(t, "List(bad cursor)", err, store.ErrInvalid)
		_, err = repo.List(ctx, "bad", store.InvitationFilter{})
		wantErr(t, "List(bad tenant)", err, store.ErrInvalid)

		// Counts of a data subject.
		for _, c := range []struct {
			email            string
			invitee, inviter int
		}{
			{"Bob@Partner.example.org", 2, 0},
			{alice, 0, 3},
			{"nobody@example.com", 0, 0},
		} {
			invitee, inviter, err := repo.CountByEmail(ctx, a.ID, c.email)
			if err != nil || invitee != c.invitee || inviter != c.inviter {
				t.Errorf("CountByEmail(%s) = %d, %d, %v", c.email, invitee, inviter, err)
			}
		}
		_, _, err = repo.CountByEmail(ctx, a.ID, "x")
		wantErr(t, "CountByEmail(bad address)", err, store.ErrInvalid)
		_, _, err = repo.CountByEmail(ctx, "bad", alice)
		wantErr(t, "CountByEmail(bad tenant)", err, store.ErrInvalid)
		// Invitations of a data subject, ordered by ID, tenant B excluded.
		bobIDs := []string{pending.ID, revoked.ID}
		slices.Sort(bobIDs)
		if got, err := repo.IDsByEmail(ctx, a.ID, "Bob@Partner.example.org"); err != nil || !slices.Equal(got, bobIDs) {
			t.Errorf("IDsByEmail(bob) = %v, %v, want %v", got, err, bobIDs)
		}
		if got, err := repo.IDsByEmail(ctx, a.ID, "nobody@example.com"); err != nil || len(got) != 0 {
			t.Errorf("IDsByEmail(nobody) = %v, %v", got, err)
		}
		_, err = repo.IDsByEmail(ctx, a.ID, "x")
		wantErr(t, "IDsByEmail(bad address)", err, store.ErrInvalid)
		_, err = repo.IDsByEmail(ctx, "bad", alice)
		wantErr(t, "IDsByEmail(bad tenant)", err, store.ErrInvalid)

		// Pseudonymisation of the inviter: revoked, the earlier revocation
		// kept; tenant B untouched.
		later := msNow.Add(time.Minute)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			n, err := repo.PseudonymiseInviterTx(ctx, tx, "ALICE@entity-a.example.com", testPseudonym, later)
			if err == nil && n != 3 {
				t.Errorf("PseudonymiseInviterTx = %d, want 3", n)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, inv := range []store.Invitation{expired, pending, used} {
			got, err := repo.Get(ctx, a.ID, inv.ID)
			if err != nil || got.InvitedBy != testPseudonym || !got.RevokedAt.Equal(later) {
				t.Errorf("pseudonymised invitation = %+v, %v", got, err)
			}
		}
		if got, err := repo.Get(ctx, a.ID, revoked.ID); err != nil || got.InvitedBy != "dave@entity-a.example.com" ||
			!got.RevokedAt.Equal(msNow.Add(-30*time.Minute)) {
			t.Errorf("invitation of another inviter = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, b.ID, other.ID); err != nil || got.InvitedBy != alice || !got.RevokedAt.IsZero() {
			t.Errorf("invitation of tenant B = %+v, %v", got, err)
		}
		for name, args := range map[string][2]string{
			"address":   {"x", testPseudonym},
			"pseudonym": {alice, "erased-XYZ"},
		} {
			err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
				_, err := repo.PseudonymiseInviterTx(ctx, tx, args[0], args[1], time.Time{})
				return err
			})
			wantErr(t, "PseudonymiseInviterTx(bad "+name+")", err, store.ErrInvalid)
		}
		// The zero time stands for the store's clock.
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			_, err := repo.PseudonymiseInviterTx(ctx, tx, alice, testPseudonym, time.Time{})
			return err
		})
		if got, _ := repo.Get(ctx, b.ID, other.ID); err != nil || !got.RevokedAt.Equal(msNow) {
			t.Errorf("PseudonymiseInviterTx(now) = %+v, %v", got, err)
		}

		// Deletion of the invitee: refused while a transfer references one
		// of its invitations, cascading to the challenges and sessions.
		ch := newChallenge(t, pending.Email, ipA)
		ch.InvitationID = pending.ID
		if err := db.Challenges().Create(ctx, a.ID, ch); err != nil {
			t.Fatal(err)
		}
		ext := newTransfer()
		ext.SenderEmail, ext.SenderKind, ext.InvitationID = revoked.Email, store.DepositorExternal, revoked.ID
		mustTransfer(t, db, a.ID, ext)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := repo.DeleteByEmailTx(ctx, tx, "bob@partner.example.org")
			return err
		})
		wantErr(t, "DeleteByEmailTx(referenced)", err, store.ErrConflict)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			n, err := repo.DeleteByEmailTx(ctx, tx, "Carol@Partner.example.org")
			if err == nil && n != 1 {
				t.Errorf("DeleteByEmailTx = %d, want 1", n)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(ctx, a.ID, used.ID); err == nil {
			t.Error("deleted invitation still readable")
		}
		if _, err := db.Challenges().Get(ctx, a.ID, ch.ID); err != nil {
			t.Errorf("challenge of a kept invitation: %v", err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := repo.DeleteByEmailTx(ctx, tx, "x")
			return err
		})
		wantErr(t, "DeleteByEmailTx(bad address)", err, store.ErrInvalid)
		if got, err := repo.Get(ctx, b.ID, other.ID); err != nil || got.ID != other.ID {
			t.Errorf("tenant B invitation after A's erasure: %v", err)
		}
	})
}

func TestDepositErasure(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		const alice, bob = "alice@entity-a.example.com", "bob@entity-a.example.com"

		type key struct {
			tid   tenant.ID
			email string
		}
		chs := map[key]store.Challenge{}
		sessions := map[key]store.DepositSession{}
		for _, tid := range []tenant.ID{a.ID, b.ID} {
			for _, email := range []string{alice, bob} {
				ch := newChallenge(t, email, ipA)
				if err := db.Challenges().Create(ctx, tid, ch); err != nil {
					t.Fatal(err)
				}
				chs[key{tid, email}] = ch
				s := newSession(t, email)
				if err := db.DepositSessions().Create(ctx, tid, s); err != nil {
					t.Fatal(err)
				}
				sessions[key{tid, email}] = s
				err := inTx(t, db, tid, func(tx *store.ScopedTx) error {
					_, err := db.VerifiedAddresses().UpsertTx(ctx, tx, store.VerifiedAddress{Email: email, FirstVerifiedIP: ipA})
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		}

		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			n, err := db.Challenges().DeleteByEmailTx(ctx, tx, "Alice@Entity-A.example.com")
			if err != nil || n != 1 {
				t.Errorf("Challenges.DeleteByEmailTx = %d, %v", n, err)
			}
			n, err = db.DepositSessions().DeleteByEmailTx(ctx, tx, "Alice@Entity-A.example.com")
			if err != nil || n != 1 {
				t.Errorf("DepositSessions.DeleteByEmailTx = %d, %v", n, err)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := db.VerifiedAddresses().Delete(ctx, a.ID, "ALICE@entity-a.example.com"); err != nil || !ok {
			t.Errorf("VerifiedAddresses.Delete = %v, %v", ok, err)
		}
		if ok, err := db.VerifiedAddresses().Delete(ctx, a.ID, alice); err != nil || ok {
			t.Errorf("VerifiedAddresses.Delete(twice) = %v, %v", ok, err)
		}
		// Only Alice's rows of tenant A are gone.
		erased := key{a.ID, alice}
		for k, ch := range chs {
			_, err := db.Challenges().Get(ctx, k.tid, ch.ID)
			if (k == erased) != (err != nil) {
				t.Errorf("challenge %v: err %v", k, err)
			}
		}
		for k, s := range sessions {
			_, err := db.DepositSessions().GetByTokenHash(ctx, k.tid, s.TokenHash, msNow)
			if (k == erased) != (err != nil) {
				t.Errorf("session %v: err %v", k, err)
			}
		}
		for k := range chs {
			_, err := db.VerifiedAddresses().Get(ctx, k.tid, k.email)
			if (k == erased) != (err != nil) {
				t.Errorf("verified address %v: err %v", k, err)
			}
		}

		for name, run := range map[string]func(tx *store.ScopedTx) error{
			"challenges": func(tx *store.ScopedTx) error { _, err := db.Challenges().DeleteByEmailTx(ctx, tx, "x"); return err },
			"sessions": func(tx *store.ScopedTx) error {
				_, err := db.DepositSessions().DeleteByEmailTx(ctx, tx, "x")
				return err
			},
		} {
			wantErr(t, name+" bad address", inTx(t, db, a.ID, run), store.ErrInvalid)
		}
		_, err = db.VerifiedAddresses().Delete(ctx, a.ID, "x")
		wantErr(t, "VerifiedAddresses.Delete(bad address)", err, store.ErrInvalid)
		_, err = db.VerifiedAddresses().Delete(ctx, "bad", alice)
		wantErr(t, "VerifiedAddresses.Delete(bad tenant)", err, store.ErrInvalid)
	})
}

func TestAuditOperations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AuditEvents()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		const alice = "alice@entity-a.example.com"

		ev := func(kind store.AuditActorKind, actor string) store.AuditEvent {
			return store.AuditEvent{ActorKind: kind, Actor: actor, Action: "transfer.created", ObjectKind: "transfer", ObjectID: id.New(id.Transfer)}
		}
		stored, err := repo.AppendScoped(ctx, a.ID, ev(store.ActorDepositor, alice))
		if err != nil || stored.TenantID != a.ID || stored.ID == "" || !stored.At.Equal(msNow) {
			t.Fatalf("AppendScoped = %+v, %v", stored, err)
		}
		for _, x := range []struct {
			tid tenant.ID
			ev  store.AuditEvent
		}{
			{a.ID, ev(store.ActorRecipient, alice)},
			{a.ID, ev(store.ActorDepositor, "bob@entity-a.example.com")},
			{a.ID, ev(store.ActorSystem, alice)},
			{b.ID, ev(store.ActorDepositor, alice)},
		} {
			if _, err := repo.AppendScoped(ctx, x.tid, x.ev); err != nil {
				t.Fatal(err)
			}
		}
		global := ev(store.ActorAdmin, "root")
		global.Action, global.ObjectKind, global.ObjectID = "admin.login", "admin", "root"
		if _, err := repo.Append(ctx, global); err != nil {
			t.Fatal(err)
		}
		cross := ev(store.ActorDepositor, alice)
		cross.TenantID = b.ID
		_, err = repo.AppendScoped(ctx, a.ID, cross)
		wantErr(t, "AppendScoped(other tenant)", err, store.ErrInvalid)
		_, err = repo.AppendScoped(ctx, a.ID, store.AuditEvent{})
		wantErr(t, "AppendScoped(bad event)", err, store.ErrInvalid)
		_, err = repo.AppendScoped(ctx, "bad", ev(store.ActorDepositor, alice))
		wantErr(t, "AppendScoped(bad tenant)", err, store.ErrInvalid)

		// The global listing: everything without tenant, one tenant without
		// the global events otherwise.
		count := func(f store.AuditFilter) int {
			t.Helper()
			p, err := repo.List(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			return len(p.Items)
		}
		if n := count(store.AuditFilter{}); n != 6 {
			t.Errorf("List(all) = %d events, want 6", n)
		}
		if n := count(store.AuditFilter{TenantID: a.ID}); n != 4 {
			t.Errorf("List(A) = %d events, want 4", n)
		}

		if n, err := repo.CountActor(ctx, a.ID, "Alice@Entity-A.example.com"); err != nil || n != 2 {
			t.Errorf("CountActor = %d, %v; want 2", n, err)
		}
		_, err = repo.CountActor(ctx, a.ID, "x")
		wantErr(t, "CountActor(bad address)", err, store.ErrInvalid)
		_, err = repo.CountActor(ctx, "bad", alice)
		wantErr(t, "CountActor(bad tenant)", err, store.ErrInvalid)

		n, err := repo.PseudonymiseActor(ctx, a.ID, "ALICE@entity-a.example.com", testPseudonym)
		if err != nil || n != 2 {
			t.Fatalf("PseudonymiseActor = %d, %v; want 2", n, err)
		}
		if n, err := repo.CountActor(ctx, a.ID, alice); err != nil || n != 0 {
			t.Errorf("CountActor after = %d, %v", n, err)
		}
		if n, err := repo.CountActor(ctx, b.ID, alice); err != nil || n != 1 {
			t.Errorf("CountActor(B) after = %d, %v", n, err)
		}
		if n := count(store.AuditFilter{TenantID: a.ID, Actor: testPseudonym}); n != 2 {
			t.Errorf("events of the pseudonym = %d, want 2", n)
		}
		if n := count(store.AuditFilter{TenantID: a.ID, Actor: alice}); n != 1 {
			t.Errorf("system events of the address = %d, want 1 (kept)", n)
		}
		for name, args := range map[string][3]string{
			"tenant":    {"bad", alice, testPseudonym},
			"address":   {string(a.ID), "x", testPseudonym},
			"pseudonym": {string(a.ID), alice, "erased-"},
		} {
			_, err := repo.PseudonymiseActor(ctx, tenant.ID(args[0]), args[1], args[2])
			wantErr(t, "PseudonymiseActor(bad "+name+")", err, store.ErrInvalid)
		}
		if !store.IsPseudonym(testPseudonym) || store.IsPseudonym("erased-0123456789ABCDEF") || store.IsPseudonym("0123456789abcdef") {
			t.Error("IsPseudonym is wrong")
		}
	})
}

func TestTenantUsage(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.TenantUsage()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		today := store.DayOf(fixedNow)
		if today != time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC) {
			t.Fatalf("DayOf = %v", today)
		}
		yesterday := today.AddDate(0, 0, -1)
		old := today.AddDate(0, -14, 0)
		adds := []struct {
			tid   tenant.ID
			day   time.Time
			delta store.UsageCounts
		}{
			{a.ID, today, store.UsageCounts{Transfers: 1, BytesUploaded: 100}},
			{a.ID, today, store.UsageCounts{Downloads: 2, BytesDownloaded: 50, VirusDetections: 1}},
			{a.ID, yesterday, store.UsageCounts{Transfers: 3, BytesUploaded: 7}},
			{a.ID, old, store.UsageCounts{Transfers: 9}},
			{b.ID, today, store.UsageCounts{Transfers: 5}},
			{b.ID, yesterday, store.UsageCounts{}}, // no row
		}
		for _, x := range adds {
			if err := repo.Add(ctx, x.tid, x.day, x.delta); err != nil {
				t.Fatalf("Add(%v): %v", x.day, err)
			}
		}
		got, err := repo.Range(ctx, a.ID, yesterday)
		want := []store.DailyUsage{
			{Day: yesterday, UsageCounts: store.UsageCounts{Transfers: 3, BytesUploaded: 7}},
			{Day: today, UsageCounts: store.UsageCounts{Transfers: 1, BytesUploaded: 100, Downloads: 2, BytesDownloaded: 50, VirusDetections: 1}},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("Range(A) = %+v, %v", got, err)
		}
		if got, err := repo.Range(ctx, b.ID, yesterday); err != nil || len(got) != 1 || got[0].Transfers != 5 {
			t.Errorf("Range(B) = %+v, %v", got, err)
		}
		all, err := repo.RangeAll(ctx, yesterday)
		wantAll := map[tenant.ID]store.UsageCounts{
			a.ID: {Transfers: 4, BytesUploaded: 107, Downloads: 2, BytesDownloaded: 50, VirusDetections: 1},
			b.ID: {Transfers: 5},
		}
		if err != nil || !reflect.DeepEqual(all, wantAll) {
			t.Errorf("RangeAll = %+v, %v", all, err)
		}
		if n, err := repo.Purge(ctx, today.AddDate(0, -13, 0)); err != nil || n != 1 {
			t.Errorf("Purge = %d, %v", n, err)
		}
		if got, err := repo.Range(ctx, a.ID, time.Time{}); err != nil || len(got) != 2 {
			t.Errorf("Range after purge = %+v, %v", got, err)
		}

		for name, run := range map[string]func() error{
			"day":      func() error { return repo.Add(ctx, a.ID, fixedNow, store.UsageCounts{Transfers: 1}) },
			"negative": func() error { return repo.Add(ctx, a.ID, today, store.UsageCounts{Downloads: -1}) },
			"tenant":   func() error { return repo.Add(ctx, "bad", today, store.UsageCounts{Transfers: 1}) },
			"range":    func() error { _, err := repo.Range(ctx, "bad", today); return err },
		} {
			wantErr(t, "bad "+name, run(), store.ErrInvalid)
		}
		unknown := tenant.ID(id.New(id.Tenant))
		wantErr(t, "Add(unknown tenant)", repo.Add(ctx, unknown, today, store.UsageCounts{Transfers: 1}), store.ErrNotFound)
		if !(store.UsageCounts{}).IsZero() || (store.UsageCounts{VirusDetections: 1}).IsZero() {
			t.Error("IsZero is wrong")
		}
	})
}

func TestQuotaAlerts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.QuotaAlerts()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		get := func(tid tenant.ID) store.QuotaAlert {
			t.Helper()
			q, err := repo.Get(ctx, tid)
			if err != nil {
				t.Fatal(err)
			}
			return q
		}
		if q := get(a.ID); q != (store.QuotaAlert{}) {
			t.Errorf("Get(new) = %+v", q)
		}
		cas := func(tid tenant.ID, old, level int, now time.Time, want bool) {
			t.Helper()
			ok, err := repo.CompareAndSet(ctx, tid, old, level, now)
			if err != nil || ok != want {
				t.Errorf("CompareAndSet(%d -> %d) = %v, %v; want %v", old, level, ok, err, want)
			}
		}
		later := msNow.Add(time.Hour)
		cas(a.ID, store.QuotaLevelNone, store.QuotaLevelWarning, time.Time{}, true)
		if q := get(a.ID); q != (store.QuotaAlert{Level: store.QuotaLevelWarning, ChangedAt: msNow}) {
			t.Errorf("Get after warning = %+v", q)
		}
		cas(a.ID, store.QuotaLevelNone, store.QuotaLevelReached, later, false) // row at 80
		cas(a.ID, store.QuotaLevelWarning, store.QuotaLevelReached, later, true)
		cas(a.ID, store.QuotaLevelWarning, store.QuotaLevelNone, later, false) // row at 100
		if q := get(a.ID); q != (store.QuotaAlert{Level: store.QuotaLevelReached, ChangedAt: later}) {
			t.Errorf("Get after reached = %+v", q)
		}
		cas(b.ID, store.QuotaLevelWarning, store.QuotaLevelReached, later, false) // no row: level 0
		if q := get(b.ID); q != (store.QuotaAlert{}) {
			t.Errorf("tenant B = %+v", q)
		}
		cas(a.ID, store.QuotaLevelReached, store.QuotaLevelNone, later, true)
		cas(a.ID, store.QuotaLevelNone, store.QuotaLevelWarning, later, true)

		_, err := repo.CompareAndSet(ctx, a.ID, 50, store.QuotaLevelWarning, later)
		wantErr(t, "CompareAndSet(bad old)", err, store.ErrInvalid)
		_, err = repo.CompareAndSet(ctx, a.ID, store.QuotaLevelNone, 90, later)
		wantErr(t, "CompareAndSet(bad level)", err, store.ErrInvalid)
		_, err = repo.CompareAndSet(ctx, "bad", store.QuotaLevelNone, store.QuotaLevelWarning, later)
		wantErr(t, "CompareAndSet(bad tenant)", err, store.ErrInvalid)
		_, err = repo.CompareAndSet(ctx, tenant.ID(id.New(id.Tenant)), store.QuotaLevelNone, store.QuotaLevelWarning, later)
		wantErr(t, "CompareAndSet(unknown tenant)", err, store.ErrNotFound)
		_, err = repo.Get(ctx, "bad")
		wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
	})
}

func TestAdminContacts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Admins()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		activate := func(adm store.Admin) store.Admin {
			t.Helper()
			if err := repo.SetPassword(ctx, adm.ID, testPHC); err != nil {
				t.Fatal(err)
			}
			return adm
		}
		d1 := activate(newDelegated(t, db, "delegate1", a.ID, b.ID))
		if _, err := repo.Update(ctx, d1.ID, store.AdminUpdate{Language: ptr("en")}); err != nil {
			t.Fatal(err)
		}
		d2 := activate(newDelegated(t, db, "delegate2", a.ID))
		newDelegated(t, db, "inactive", a.ID) // no password
		disabled := activate(newDelegated(t, db, "disabled", a.ID))
		if _, err := repo.Update(ctx, disabled.ID, store.AdminUpdate{Disabled: ptr(true)}); err != nil {
			t.Fatal(err)
		}
		activate(newDelegated(t, db, "delegateb", b.ID))
		root := newSuperAdmin(t, db, "root")
		if _, err := repo.Create(ctx, store.Admin{Username: "pending", Email: "pending@example.com", Role: store.RoleSuperAdmin}); err != nil {
			t.Fatal(err)
		}

		got, err := repo.TenantContacts(ctx, a.ID)
		want := sortContacts([]store.AdminContact{
			{AdminID: d1.ID, Email: "delegate1@example.com", Language: "en"},
			{AdminID: d2.ID, Email: "delegate2@example.com"},
		})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("TenantContacts(A) = %+v, %v; want %+v", got, err, want)
		}
		if got, err := repo.TenantContacts(ctx, tenant.ID(id.New(id.Tenant))); err != nil || len(got) != 0 {
			t.Errorf("TenantContacts(unknown) = %+v, %v", got, err)
		}
		_, err = repo.TenantContacts(ctx, "bad")
		wantErr(t, "TenantContacts(bad tenant)", err, store.ErrInvalid)
		supers, err := repo.SuperAdminContacts(ctx)
		if err != nil || !reflect.DeepEqual(supers, []store.AdminContact{{AdminID: root.ID, Email: "root@example.com"}}) {
			t.Errorf("SuperAdminContacts = %+v, %v", supers, err)
		}
	})
}

// sortContacts sorts contacts by administrator ID.
func sortContacts(cs []store.AdminContact) []store.AdminContact {
	slices.SortFunc(cs, func(x, y store.AdminContact) int {
		switch {
		case x.AdminID < y.AdminID:
			return -1
		case x.AdminID > y.AdminID:
			return 1
		}
		return 0
	})
	return cs
}
