package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// replier is the recipient of the source transfers who replies.
const replier = "bob@partner.example.org"

// newReplySession returns a valid reply session of replier answering the
// transfer trfID through the recipient link linkID.
func newReplySession(t *testing.T, trfID, linkID string) store.DepositSession {
	t.Helper()
	s := newSession(t, "Bob@Partner.example.org")
	s.Kind, s.ReplyToTransferID, s.RecipientLinkID = store.DepositorReply, trfID, linkID
	return s
}

// newReply returns a valid reply transfer of replier answering trfID.
func newReply(trfID string) store.Transfer {
	tr := newTransfer()
	tr.SenderEmail, tr.SenderKind, tr.ReplyToTransferID = replier, store.DepositorReply, trfID
	return tr
}

func TestDepositorKindIsExternal(t *testing.T) {
	t.Parallel()
	for k, want := range map[store.DepositorKind]bool{
		store.DepositorExternal: true, store.DepositorReply: true,
		store.DepositorInternal: false, store.DepositorInternalRemote: false, "robot": false, "": false,
	} {
		if got := k.IsExternal(); got != want {
			t.Errorf("%q.IsExternal() = %v", k, got)
		}
		if k.IsExternal() && k.IsInternal() {
			t.Errorf("%q is both internal and external", k)
		}
	}
}

func TestDepositSessionsReply(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.DepositSessions()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		src, links, _ := availablePerRecipient(t, db, a.ID, nil)
		other, otherLinks, _ := availablePerRecipient(t, db, a.ID, nil)
		srcB, linksB, _ := availablePerRecipient(t, db, b.ID, nil)

		// Round trip.
		s := newReplySession(t, src.ID, links[0].ID)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.CreateTx(ctx, tx, s) }); err != nil {
			t.Fatalf("CreateTx(reply): %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		if err != nil || got.Kind != store.DepositorReply || got.Email != replier || got.InvitationID != "" ||
			got.ReplyToTransferID != src.ID || got.RecipientLinkID != links[0].ID {
			t.Fatalf("GetByTokenHash(reply) = %+v, %v", got, err)
		}
		// Other kinds read both identifiers empty.
		in := newSession(t, replier)
		if err := repo.Create(ctx, a.ID, in); err != nil {
			t.Fatalf("Create(internal): %v", err)
		}
		if got, err := repo.GetByTokenHash(ctx, a.ID, in.TokenHash, fixedNow); err != nil ||
			got.ReplyToTransferID != "" || got.RecipientLinkID != "" {
			t.Errorf("GetByTokenHash(internal) = %+v, %v", got, err)
		}
		// Isolation: the reply session is worthless under B.
		_, err = repo.GetByTokenHash(ctx, b.ID, s.TokenHash, fixedNow)
		wantErr(t, "GetByTokenHash(reply) from B", err, store.ErrNotFound)

		// The source transfer and the link must exist in the tenant, and
		// the link must be one of the source transfer.
		refused := map[string][2]string{
			"source of B":            {srcB.ID, links[0].ID},
			"link of B":              {src.ID, linksB[0].ID},
			"source and link of B":   {srcB.ID, linksB[0].ID},
			"missing source":         {id.New(id.Transfer), links[0].ID},
			"missing link":           {src.ID, id.New(id.RecipientLink)},
			"link of another source": {src.ID, otherLinks[0].ID},
			"source of another link": {other.ID, links[1].ID},
		}
		for name, ids := range refused {
			x := newReplySession(t, ids[0], ids[1])
			wantErr(t, "Create("+name+")", repo.Create(ctx, a.ID, x), store.ErrNotFound)
		}
		// B cannot open a reply session on A's transfer either.
		wantErr(t, "Create(from B)", repo.Create(ctx, b.ID, newReplySession(t, src.ID, links[0].ID)), store.ErrNotFound)

		// Invariants: kind reply <=> both identifiers, no invitation.
		inv := mustInvitation(t, db, a.ID)
		invalid := map[string]func(*store.DepositSession){
			"reply without source": func(s *store.DepositSession) { s.ReplyToTransferID = "" },
			"reply without link":   func(s *store.DepositSession) { s.RecipientLinkID = "" },
			"reply without both":   func(s *store.DepositSession) { s.ReplyToTransferID, s.RecipientLinkID = "", "" },
			"reply with invitation": func(s *store.DepositSession) {
				s.InvitationID = inv.ID
			},
			"internal with source": func(s *store.DepositSession) { s.Kind, s.RecipientLinkID = store.DepositorInternal, "" },
			"internal with link":   func(s *store.DepositSession) { s.Kind, s.ReplyToTransferID = store.DepositorInternal, "" },
			"internal with both":   func(s *store.DepositSession) { s.Kind = store.DepositorInternal },
			"external with both": func(s *store.DepositSession) {
				s.Kind, s.InvitationID = store.DepositorExternal, inv.ID
			},
			"malformed source": func(s *store.DepositSession) { s.ReplyToTransferID = "trf_x" },
			"source not a transfer": func(s *store.DepositSession) {
				s.ReplyToTransferID = id.New(id.RecipientLink)
			},
			"malformed link":     func(s *store.DepositSession) { s.RecipientLinkID = "rcl_x" },
			"link not a link id": func(s *store.DepositSession) { s.RecipientLinkID = id.New(id.Transfer) },
		}
		for name, mutate := range invalid {
			x := newReplySession(t, src.ID, links[0].ID)
			mutate(&x)
			wantErr(t, "Create(bad "+name+")", repo.Create(ctx, a.ID, x), store.ErrInvalid)
		}

		// Cascade: deleting the recipient link (recipient erasure) deletes
		// the sessions it verified; deleting the source transfer row deletes
		// the remaining reply sessions.
		s2 := newReplySession(t, src.ID, links[1].ID)
		if err := repo.Create(ctx, a.ID, s2); err != nil {
			t.Fatalf("Create(second link): %v", err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if _, err := db.RecipientLinks().DestroyRecipientKeyTx(ctx, tx, src.ID, rcptBob); err != nil {
				return err
			}
			return db.Transfers().RemoveRecipientTx(ctx, tx, src.ID, rcptBob)
		})
		if err != nil {
			t.Fatalf("RemoveRecipientTx: %v", err)
		}
		_, err = repo.GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		wantErr(t, "GetByTokenHash(link removed)", err, store.ErrNotFound)
		if _, err := repo.GetByTokenHash(ctx, a.ID, s2.TokenHash, fixedNow); err != nil {
			t.Fatalf("GetByTokenHash(other link) = %v", err)
		}
		// A reply transfer outlives its source (no foreign key).
		reply := mustTransfer(t, db, a.ID, newReply(src.ID))
		eraseFileKeys(t, db, a.ID, src)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if _, err := db.RecipientLinks().DestroyKeysTx(ctx, tx, src.ID); err != nil {
				return err
			}
			return db.Transfers().DeleteTx(ctx, tx, src.ID)
		})
		if err != nil {
			t.Fatalf("DeleteTx(source): %v", err)
		}
		_, err = repo.GetByTokenHash(ctx, a.ID, s2.TokenHash, fixedNow)
		wantErr(t, "GetByTokenHash(source deleted)", err, store.ErrNotFound)
		if got, err := db.Transfers().Get(ctx, a.ID, reply.ID); err != nil || got.ReplyToTransferID != src.ID {
			t.Errorf("reply after its source was deleted = %+v, %v", got.Transfer, err)
		}
		// B's own reply sessions are untouched.
		if err := repo.Create(ctx, b.ID, newReplySession(t, srcB.ID, linksB[0].ID)); err != nil {
			t.Errorf("Create(reply of B): %v", err)
		}
	})
}

// TestDepositSessionsCountLiveReply: only the live (neither ended nor
// expired) reply sessions of the link count, in the tenant of the
// transaction only.
func TestDepositSessionsCountLiveReply(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.DepositSessions()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		src, links, _ := availablePerRecipient(t, db, a.ID, nil)
		srcB, linksB, _ := availablePerRecipient(t, db, b.ID, nil)
		count := func(tid tenant.ID, linkID string, now time.Time) int {
			t.Helper()
			var n int
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				n, err = repo.CountLiveReplyTx(ctx, tx, linkID, now)
				return err
			})
			if err != nil {
				t.Fatalf("CountLiveReplyTx: %v", err)
			}
			return n
		}
		if n := count(a.ID, links[0].ID, fixedNow); n != 0 {
			t.Fatalf("empty count = %d", n)
		}
		live := newReplySession(t, src.ID, links[0].ID)
		ended := newReplySession(t, src.ID, links[0].ID)
		short := newReplySession(t, src.ID, links[0].ID)
		short.ExpiresAt = fixedNow.Add(time.Hour)
		for _, s := range []store.DepositSession{live, ended, short, newReplySession(t, src.ID, links[1].ID)} {
			if err := repo.Create(ctx, a.ID, s); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
		// Sessions of other kinds and of another tenant never count.
		if err := repo.Create(ctx, a.ID, newSession(t, replier)); err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(ctx, b.ID, newReplySession(t, srcB.ID, linksB[0].ID)); err != nil {
			t.Fatal(err)
		}
		if n := count(a.ID, links[0].ID, fixedNow); n != 3 {
			t.Fatalf("count = %d, want 3", n)
		}
		if err := repo.End(ctx, a.ID, ended.TokenHash, fixedNow); err != nil {
			t.Fatal(err)
		}
		if n := count(a.ID, links[0].ID, fixedNow); n != 2 {
			t.Fatalf("count after End = %d, want 2", n)
		}
		if n := count(a.ID, links[0].ID, short.ExpiresAt); n != 1 {
			t.Fatalf("count at the expiry of one = %d, want 1", n)
		}
		// Isolation: B counts nothing on A's link, A nothing on B's.
		if n := count(b.ID, links[0].ID, fixedNow); n != 0 {
			t.Fatalf("count of A's link from B = %d", n)
		}
		if n := count(a.ID, linksB[0].ID, fixedNow); n != 0 {
			t.Fatalf("count of B's link from A = %d", n)
		}
	})
}

func TestTransfersReply(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		src := mustTransfer(t, db, a.ID, newTransfer())
		srcB := mustTransfer(t, db, b.ID, newTransfer())

		// Round trip, through every read path of a transfer.
		tr := newReply(src.ID)
		tr.IdempotencyKey = "reply-key"
		d := mustTransfer(t, db, a.ID, tr)
		if d.SenderKind != store.DepositorReply || d.ReplyToTransferID != src.ID || d.InvitationID != "" || d.APITokenID != "" {
			t.Fatalf("Get(reply) = %+v", d.Transfer)
		}
		if src.ReplyToTransferID != "" {
			t.Errorf("source ReplyToTransferID = %q", src.ReplyToTransferID)
		}
		if got, err := transfers.GetByIdempotencyKey(ctx, a.ID, replier, "reply-key", msNow); err != nil ||
			got.ReplyToTransferID != src.ID {
			t.Errorf("GetByIdempotencyKey = %+v, %v", got.Transfer, err)
		}

		// Ownership: only a reply depositor of the same source owns it.
		owner := store.Depositor{Email: replier, Kind: store.DepositorReply, ReplyToTransferID: src.ID}
		if !owner.Owns(d.Transfer) {
			t.Error("the reply depositor does not own its transfer")
		}
		for name, dep := range map[string]store.Depositor{
			"other source":   {Email: replier, Kind: store.DepositorReply, ReplyToTransferID: id.New(id.Transfer)},
			"internal":       {Email: replier, Kind: store.DepositorInternal},
			"internal claim": {Email: replier, Kind: store.DepositorInternal, ReplyToTransferID: src.ID},
		} {
			if dep.Owns(d.Transfer) {
				t.Errorf("%s owns the reply", name)
			}
		}

		// The source must exist in the tenant (no foreign key).
		for name, srcID := range map[string]string{"source of B": srcB.ID, "missing source": id.New(id.Transfer)} {
			f := newFile(t, db, a.ID, "x", 1)
			err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
				return transfers.CreateTx(ctx, tx, newReply(srcID), []string{"alice@entity-a.example.com"},
					[]store.TransferFile{f})
			})
			wantErr(t, "CreateTx("+name+")", err, store.ErrNotFound)
		}
		if _, err := transfers.Get(ctx, b.ID, d.ID); err == nil {
			t.Error("B reads A's reply")
		}

		// Invariants.
		inv := mustInvitation(t, db, a.ID)
		invalid := map[string]func(*store.Transfer){
			"reply without source":   func(tr *store.Transfer) { tr.ReplyToTransferID = "" },
			"reply with invitation":  func(tr *store.Transfer) { tr.InvitationID = inv.ID },
			"reply with api token":   func(tr *store.Transfer) { tr.APITokenID = id.New(id.APIToken) },
			"internal with source":   func(tr *store.Transfer) { tr.SenderKind = store.DepositorInternal },
			"external with source":   func(tr *store.Transfer) { tr.SenderKind, tr.InvitationID = store.DepositorExternal, inv.ID },
			"malformed source":       func(tr *store.Transfer) { tr.ReplyToTransferID = "trf_x" },
			"source not a transfer":  func(tr *store.Transfer) { tr.ReplyToTransferID = id.New(id.Invitation) },
			"reply answering itself": func(tr *store.Transfer) { tr.ReplyToTransferID = tr.ID },
		}
		for name, mutate := range invalid {
			tr := newReply(src.ID)
			mutate(&tr)
			f := newFile(t, db, a.ID, "x", 1)
			err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
				return transfers.CreateTx(ctx, tx, tr, []string{"alice@entity-a.example.com"}, []store.TransferFile{f})
			})
			wantErr(t, "CreateTx(bad "+name+")", err, store.ErrInvalid)
		}
	})
}
