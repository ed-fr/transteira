package isolation_test

import (
	"bytes"
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// linkedTransfer is an available per-recipient transfer with its links.
type linkedTransfer struct {
	store.TransferDetails
	links []store.RecipientLink
}

// perRecipientTransfer stores an available per-recipient transfer of tid,
// with recipient verification and the "delete after the first download"
// option, one link per recipient (two recipients), and a claimed archive
// download through its first link.
func perRecipientTransfer(t *testing.T, db *store.DB, tid tenant.ID) linkedTransfer {
	t.Helper()
	ctx := t.Context()
	tr := store.Transfer{
		ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal,
		ExpiryDays: 7, DeleteAfterFirstDownload: true, LinkMode: store.LinkModePerRecipient, RecipientVerification: true,
	}
	fl := newTransferFile(t, db, tid)
	fl.SHA256, fl.CiphertextSize, fl.UploadedAt = shaTransfer, 80, epoch
	tokens := []store.LinkToken{
		{Hash: downloadHash(t), KeyID: newSecretKey(t, db, tid)},
		{Hash: downloadHash(t), KeyID: newSecretKey(t, db, tid)},
	}
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	var links []store.RecipientLink
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		rcpts := []string{"bob@partner.example.net", "carol@partner.example.net"}
		if err := db.Transfers().CreateTx(ctx, tx, tr, rcpts, []store.TransferFile{fl}); err != nil {
			return err
		}
		if err := db.Transfers().FinalizeTx(ctx, tx, tr.ID, epoch); err != nil {
			return err
		}
		if links, err = db.Transfers().MarkAvailableLinksTx(ctx, tx, tr.ID, tokens, epoch); err != nil {
			return err
		}
		return db.RecipientLinks().ClaimTx(ctx, tx, links[0].ID, "", epoch)
	})
	if err != nil {
		t.Fatalf("per-recipient transfer: %v", err)
	}
	d, err := db.Transfers().Get(ctx, tid, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	return linkedTransfer{TransferDetails: d, links: links}
}

// TestRecipientLinksIsolation attacks A's recipient links from tenant B:
// B never resolves, reads, verifies, claims, completes, reminds or erases
// A's links, never counts A's codes, never attaches a code to them, and
// every attempt reads as a plain not-found (or an empty result). The
// reminder sweep returns identifiers only.
func TestRecipientLinksIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		la := perRecipientTransfer(t, db, a.ID)
		perRecipientTransfer(t, db, b.ID) // B has links of its own
		links, transfers := db.RecipientLinks(), db.Transfers()
		linkA := la.links[0]
		sb, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		inB := func(fn func(tx *store.ScopedTx) error) error { return sb.Tx(ctx, fn) }
		now := epoch.Add(time.Hour)

		// Lookups.
		_, err = links.GetByTokenHash(ctx, b.ID, linkA.TokenHash)
		assertNotFound(t, "GetByTokenHash", err)
		_, err = transfers.GetByDownloadTokenHash(ctx, b.ID, linkA.TokenHash)
		assertNotFound(t, "GetByDownloadTokenHash(link token)", err)
		assertNotFound(t, "GetTx", inB(func(tx *store.ScopedTx) error { _, err := links.GetTx(ctx, tx, linkA.ID); return err }))
		if got, err := links.ListByTransfer(ctx, b.ID, la.ID); err != nil || len(got) != 0 {
			t.Errorf("ListByTransfer(A from B) = %+v, %v", got, err)
		}
		if got, err := links.TrackingByTransfer(ctx, b.ID, la.ID); err != nil || len(got) != 0 {
			t.Errorf("TrackingByTransfer(A from B) = %+v, %v", got, err)
		}
		_ = inB(func(tx *store.ScopedTx) error {
			if got, err := links.ReminderTargetsTx(ctx, tx, la.ID); err != nil || len(got) != 0 {
				t.Errorf("ReminderTargetsTx(A from B) = %+v, %v", got, err)
			}
			return nil
		})

		// Writes.
		assertNotFound(t, "MarkVerifiedTx", inB(func(tx *store.ScopedTx) error { return links.MarkVerifiedTx(ctx, tx, linkA.ID, now) }))
		assertNotFound(t, "ClaimTx", inB(func(tx *store.ScopedTx) error { return links.ClaimTx(ctx, tx, linkA.ID, "", now) }))
		assertNotFound(t, "ClaimTx(file)", inB(func(tx *store.ScopedTx) error { return links.ClaimTx(ctx, tx, linkA.ID, la.Files[0].ID, now) }))
		assertNotFound(t, "CompleteItemTx", inB(func(tx *store.ScopedTx) error {
			_, err := links.CompleteItemTx(ctx, tx, linkA.ID, "", now)
			return err
		}))
		assertNotFound(t, "CompleteTx", inB(func(tx *store.ScopedTx) error { _, err := links.CompleteTx(ctx, tx, linkA.ID, now); return err }))
		assertNotFound(t, "MarkReminderSentTx", inB(func(tx *store.ScopedTx) error {
			return links.MarkReminderSentTx(ctx, tx, []string{linkA.ID}, now)
		}))
		assertNotFound(t, "ResetReminderSent", links.ResetReminderSent(ctx, b.ID, la.ID, []string{linkA.ID}, now))
		assertNotFound(t, "MarkExpiryReminderTx", inB(func(tx *store.ScopedTx) error { return transfers.MarkExpiryReminderTx(ctx, tx, la.ID, now) }))
		assertNotFound(t, "MarkFirstDownloadTx", inB(func(tx *store.ScopedTx) error {
			_, err := transfers.MarkFirstDownloadTx(ctx, tx, la.ID, now, now)
			return err
		}))
		tokensB := []store.LinkToken{{Hash: downloadHash(t), KeyID: newSecretKey(t, db, b.ID)}, {Hash: downloadHash(t), KeyID: newSecretKey(t, db, b.ID)}}
		assertNotFound(t, "CreateTx", inB(func(tx *store.ScopedTx) error { _, err := links.CreateTx(ctx, tx, la.ID, tokensB, now); return err }))
		assertNotFound(t, "MarkAvailableLinksTx", inB(func(tx *store.ScopedTx) error {
			_, err := transfers.MarkAvailableLinksTx(ctx, tx, la.ID, tokensB, now)
			return err
		}))
		// A's link token key cannot seal a link of B.
		scanningB := store.Transfer{
			ID: id.New(id.Transfer), SenderEmail: "alice@entity-b.example.org", SenderKind: store.DepositorInternal,
			ExpiryDays: 7, LinkMode: store.LinkModePerRecipient,
		}
		flB := newTransferFile(t, db, b.ID)
		flB.SHA256, flB.CiphertextSize, flB.UploadedAt = shaTransfer, 80, epoch
		if err := inB(func(tx *store.ScopedTx) error {
			if err := transfers.CreateTx(ctx, tx, scanningB, []string{"dan@partner.example.net"}, []store.TransferFile{flB}); err != nil {
				return err
			}
			return transfers.FinalizeTx(ctx, tx, scanningB.ID, epoch)
		}); err != nil {
			t.Fatal(err)
		}
		stolen := []store.LinkToken{{Hash: downloadHash(t), KeyID: la.links[1].TokenKeyID}}
		assertNotFound(t, "MarkAvailableLinksTx(key of A)", inB(func(tx *store.ScopedTx) error {
			_, err := transfers.MarkAvailableLinksTx(ctx, tx, scanningB.ID, stolen, now)
			return err
		}))
		assertNotFound(t, "CreateTx(key of A)", inB(func(tx *store.ScopedTx) error {
			_, err := links.CreateTx(ctx, tx, scanningB.ID, stolen, now)
			return err
		}))

		// Erasure from B destroys nothing of A.
		_ = inB(func(tx *store.ScopedTx) error {
			if n, err := links.DestroyKeysTx(ctx, tx, la.ID); err != nil || n != 0 {
				t.Errorf("DestroyKeysTx(A from B) = %d, %v", n, err)
			}
			if done, err := links.DestroyRecipientKeyTx(ctx, tx, la.ID, "bob@partner.example.net"); err != nil || done {
				t.Errorf("DestroyRecipientKeyTx(A from B) = %v, %v", done, err)
			}
			return nil
		})

		// Verification codes: B can neither attach a code to A's link nor
		// count A's codes.
		ch := store.Challenge{
			ID: "vch_" + "abcdefghijklmnopqrstuv", Email: "bob@partner.example.net", CodeMAC: bytes.Repeat([]byte{1}, 32),
			AttemptsRemaining: 2, ClientIP: netip.MustParseAddr("192.0.2.7"), ExpiresAt: epoch.Add(time.Hour),
			Purpose: store.ChallengeRecipient, RecipientLinkID: linkA.ID, RecipientIntent: store.IntentDownload,
		}
		assertNotFound(t, "Challenges.Create(link of A)", db.Challenges().Create(ctx, b.ID, ch))
		if err := db.Challenges().Create(ctx, a.ID, ch); err != nil {
			t.Fatalf("Challenges.Create(A): %v", err)
		}
		if n, err := db.Challenges().CountByLinkSince(ctx, b.ID, linkA.ID, epoch); err != nil || n != 0 {
			t.Errorf("CountByLinkSince(A from B) = %d, %v", n, err)
		}

		// A is intact.
		got, err := links.ListByTransfer(ctx, a.ID, la.ID)
		if err != nil || len(got) != 2 {
			t.Fatalf("ListByTransfer(A) = %+v, %v", got, err)
		}
		for i, l := range got {
			if l.TokenKeyID == "" || !l.VerifiedAt.IsZero() || !l.CompletedAt.IsZero() || !l.ReminderSentAt.IsZero() {
				t.Errorf("link %d of A changed: %+v", i, l)
			}
		}
		if got[0].DownloadCount != 1 || got[1].DownloadCount != 0 {
			t.Errorf("A's download counts changed: %d, %d", got[0].DownloadCount, got[1].DownloadCount)
		}
		if n, err := db.Challenges().CountByLinkSince(ctx, a.ID, linkA.ID, epoch); err != nil || n != 1 {
			t.Errorf("CountByLinkSince(A) = %d, %v", n, err)
		}
		if d, err := transfers.Get(ctx, a.ID, la.ID); err != nil || !d.FirstDownloadedAt.IsZero() || !d.ExpiryReminderAt.IsZero() {
			t.Errorf("A's transfer changed: %+v, %v", d.Transfer, err)
		}

		// The reminder sweep returns identifiers of both tenants only.
		due, err := links.DueReminders(ctx, la.ExpiresAt.Add(-time.Hour), store.SweepPage{Limit: store.ReminderSweepLimit})
		if err != nil || len(due) != 2 {
			t.Errorf("DueReminders = %+v, %v", due, err)
		}
	})
}

// TestRLSRecipientLinks checks on PostgreSQL that raw SQL in the scope of
// tenant A neither sees, changes nor adds recipient links or download
// tracking rows of tenant B.
func TestRLSRecipientLinks(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a, b := string(f.a.ID), string(f.b.ID)
	la := perRecipientTransfer(t, f.db, f.a.ID)
	lb := perRecipientTransfer(t, f.db, f.b.ID)
	linkB := lb.links[0].ID

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM recipient_links WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM recipient_links WHERE id = $1`, []any{linkB}, 0},
			{`SELECT count(*) FROM recipient_links WHERE token_hash = $1`, []any{lb.links[0].TokenHash}, 0},
			{`SELECT count(*) FROM recipient_links`, nil, len(la.links)},
			{`SELECT count(*) FROM recipient_downloads WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM recipient_downloads WHERE recipient_link_id = $1`, []any{linkB}, 0},
			{`SELECT count(*) FROM recipient_downloads`, nil, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE recipient_links SET completed_at = 1, first_downloaded_at = 1, last_downloaded_at = 1 WHERE id = $1`, []any{linkB}},
			{`UPDATE recipient_links SET token_key_id = NULL WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM recipient_links WHERE tenant_id = $1`, []any{b}},
			{`UPDATE recipient_downloads SET count = 99 WHERE recipient_link_id = $1`, []any{linkB}},
			{`DELETE FROM recipient_downloads WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows of B", s.stmt, n)
			}
		}
		return nil
	})

	for _, v := range []struct {
		name string
		stmt string
		args []any
	}{
		{"insert link for B", `INSERT INTO recipient_links (id, tenant_id, transfer_id, position, token_hash, created_at)
			VALUES ($1, $2, $3, 1, $4, 0)`, []any{id.New(id.RecipientLink), b, lb.ID, bytes.Repeat([]byte{9}, 32)}},
		{"insert tracking for B", `INSERT INTO recipient_downloads (tenant_id, recipient_link_id, item, first_at, last_at)
			VALUES ($1, $2, 'archive', 0, 0)`, []any{b, linkB}},
		{"move A's links to B", `UPDATE recipient_links SET tenant_id = $1`, []any{b}},
		{"move A's tracking to B", `UPDATE recipient_downloads SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}

	// B is intact.
	got, err := f.db.RecipientLinks().TrackingByTransfer(ctx, f.b.ID, lb.ID)
	if err != nil || len(got) != 2 || got[0].LinkID != linkB || len(got[0].Downloads) != 1 || got[0].Downloads[0].Count != 1 ||
		!got[0].CompletedAt.IsZero() {
		t.Errorf("B's tracking = %+v, %v", got, err)
	}
	if l, err := f.db.RecipientLinks().ListByTransfer(ctx, f.b.ID, lb.ID); err != nil || len(l) != 2 || l[0].TokenKeyID == "" {
		t.Errorf("B's links = %+v, %v", l, err)
	}
}
