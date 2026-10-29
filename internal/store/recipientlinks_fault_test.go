package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// linkFixture is a transferFixture with, in addition, an available
// per-recipient transfer (delete after the first download, one recipient,
// one complete file) whose link has one claimed archive download, and a
// scanning per-recipient transfer with a sealed token ready for its link.
type linkFixture struct {
	*transferFixture
	avail    Transfer
	link     RecipientLink
	fileID   string
	scanning Transfer
	token    LinkToken
}

// newLinkFixture builds a linkFixture.
func newLinkFixture(t *testing.T) *linkFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	f := &linkFixture{transferFixture: newTransferFixture(t)}
	scanning := func(deleteOpt bool) (Transfer, string) {
		trf := Transfer{
			ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 7,
			LinkMode: LinkModePerRecipient, DeleteAfterFirstDownload: deleteOpt,
		}
		fl := f.newFile(ctx, t)
		fl.SHA256, fl.CiphertextSize, fl.UploadedAt = faultSHA, 1, now
		if err := f.create(ctx, trf, fl); err != nil {
			t.Fatal(err)
		}
		if err := f.tx(ctx, func(tx *ScopedTx) error { return f.db.Transfers().FinalizeTx(ctx, tx, trf.ID, now) }); err != nil {
			t.Fatal(err)
		}
		return trf, fl.ID
	}
	newToken := func(seed string) LinkToken {
		key := id.New(id.WrappedKey)
		if err := f.db.WrappedKeys().Create(ctx, f.tid, WrappedKey{ID: key, Purpose: KeyPurposeSecret, KeyID: testMK1, Blob: []byte("s")}); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(seed + key))
		return LinkToken{Hash: h[:], KeyID: key}
	}
	f.avail, f.fileID = scanning(true)
	tok := newToken("a")
	err := f.tx(ctx, func(tx *ScopedTx) error {
		ls, err := f.db.Transfers().MarkAvailableLinksTx(ctx, tx, f.avail.ID, []LinkToken{tok}, now)
		if err != nil {
			return err
		}
		f.link = ls[0]
		return f.db.RecipientLinks().ClaimTx(ctx, tx, f.link.ID, "", now)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.scanning, _ = scanning(false)
	f.token = newToken("s")
	return f
}

// TestRecipientLinkDriverFaults injects a driver failure into each
// statement of the recipient links and of the per-recipient paths of the
// transfers, and checks that it surfaces as an error.
func TestRecipientLinkDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	links := func(f *linkFixture) *RecipientLinks { return f.db.RecipientLinks() }
	inTx := func(f *linkFixture, fn func(tx *ScopedTx) error) func() error {
		return func() error { return f.tx(ctx, fn) }
	}
	markLinks := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			_, err := f.db.Transfers().MarkAvailableLinksTx(ctx, tx, f.scanning.ID, []LinkToken{f.token}, now)
			return err
		})
	}
	createLinks := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			_, err := links(f).CreateTx(ctx, tx, f.scanning.ID, []LinkToken{f.token}, now)
			return err
		})
	}
	markShared := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			return f.db.Transfers().MarkAvailableTx(ctx, tx, f.scanning.ID, f.token.Hash, f.token.KeyID, now)
		})
	}
	firstDownload := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			_, err := f.db.Transfers().MarkFirstDownloadTx(ctx, tx, f.avail.ID, now, now.Add(time.Hour))
			return err
		})
	}
	claim := func(f *linkFixture, fileID string) func() error {
		return inTx(f, func(tx *ScopedTx) error { return links(f).ClaimTx(ctx, tx, f.link.ID, fileID, now) })
	}
	completeItem := func(f *linkFixture, fileID string) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			_, err := links(f).CompleteItemTx(ctx, tx, f.link.ID, fileID, now)
			return err
		})
	}
	complete := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { _, err := links(f).CompleteTx(ctx, tx, f.link.ID, now); return err })
	}
	destroy := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { _, err := links(f).DestroyKeysTx(ctx, tx, f.avail.ID); return err })
	}
	destroyRecipient := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			_, err := links(f).DestroyRecipientKeyTx(ctx, tx, f.avail.ID, "bob@b.example.org")
			return err
		})
	}
	listTx := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { _, err := links(f).ListByTransferTx(ctx, tx, f.avail.ID); return err })
	}
	trackingTx := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { _, err := links(f).TrackingByTransferTx(ctx, tx, f.avail.ID); return err })
	}
	targets := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { _, err := links(f).ReminderTargetsTx(ctx, tx, f.avail.ID); return err })
	}
	markSent := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { return links(f).MarkReminderSentTx(ctx, tx, []string{f.link.ID}, now) })
	}
	markReminder := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { return f.db.Transfers().MarkExpiryReminderTx(ctx, tx, f.avail.ID, now) })
	}
	resetReminder := func(f *linkFixture) func() error {
		return func() error { return links(f).ResetReminderSent(ctx, f.tid, f.avail.ID, []string{f.link.ID}, now) }
	}
	twice := func(fn func() error) func() error {
		if err := fn(); err != nil {
			panic(err)
		}
		return fn
	}
	challenge := func(f *linkFixture) func() error {
		return func() error {
			return f.db.Challenges().Create(ctx, f.tid, Challenge{
				ID: "vch_" + "0123456789abcdefghijkl", Email: "bob@b.example.org", CodeMAC: []byte{1},
				AttemptsRemaining: 1, ClientIP: fixtureIP, ExpiresAt: time.Now().Add(time.Minute),
				Purpose: ChallengeRecipient, RecipientLinkID: f.link.ID, RecipientIntent: IntentDownload,
			})
		}
	}
	const (
		getTransfer = "extension_count, extended_at FROM transfers WHERE tenant_id = ? AND id = ?"
		joinLinks   = "FROM recipient_links l JOIN"
	)
	steps := []struct {
		name, op, match string
		run             func(f *linkFixture) func() error
	}{
		{"mark links", faultExec, "SET status = 'available', available_at", markLinks},
		{"mark links probe", faultQuery, getTransfer, func(f *linkFixture) func() error {
			return inTx(f, func(tx *ScopedTx) error {
				_, err := f.db.Transfers().MarkAvailableLinksTx(ctx, tx, f.avail.ID, []LinkToken{f.token}, now)
				return err
			})
		}},
		{"shared probe", faultQuery, getTransfer, markShared},
		{"count recipients", faultQuery, "SELECT count(*) FROM transfer_recipients", markLinks},
		{"check token key", faultQuery, "FROM wrapped_keys WHERE tenant_id", markLinks},
		{"insert link", faultExec, "INSERT INTO recipient_links", markLinks},
		{"list created", faultQuery, joinLinks, markLinks},
		{"create read", faultQuery, getTransfer, createLinks},
		{"first download read", faultQuery, getTransfer, firstDownload},
		{"first link download", faultExec, "AND link_mode = 'per_recipient'", firstDownload},
		{"delete after links", faultExec, "SET delete_after = COALESCE", firstDownload},
		{"get by token", faultQuery, joinLinks, func(f *linkFixture) func() error {
			return func() error { _, err := links(f).GetByTokenHash(ctx, f.tid, f.link.TokenHash); return err }
		}},
		{"get", faultQuery, joinLinks, func(f *linkFixture) func() error {
			return inTx(f, func(tx *ScopedTx) error { _, err := links(f).GetTx(ctx, tx, f.link.ID); return err })
		}},
		{"list", faultQuery, joinLinks, listTx},
		{"list scan", faultScanNil, joinLinks, listTx},
		{"verify", faultExec, "SET verified_at", func(f *linkFixture) func() error {
			return inTx(f, func(tx *ScopedTx) error { return links(f).MarkVerifiedTx(ctx, tx, f.link.ID, now) })
		}},
		{"claim link", faultExec, "first_downloaded_at = COALESCE(first_downloaded_at, ?)", func(f *linkFixture) func() error { return claim(f, "") }},
		{"claim bump", faultExec, "UPDATE recipient_downloads SET count", func(f *linkFixture) func() error { return claim(f, "") }},
		{"claim bump rows", faultRows, "UPDATE recipient_downloads SET count", func(f *linkFixture) func() error { return claim(f, "") }},
		{"claim insert", faultExec, "INSERT INTO recipient_downloads", func(f *linkFixture) func() error { return claim(f, f.fileID) }},
		{"complete item", faultExec, "WHERE tenant_id = ? AND recipient_link_id = ? AND item = ? AND completed_at IS NULL", func(f *linkFixture) func() error { return completeItem(f, "") }},
		{"complete item probe", faultQuery, "SELECT count(*) FROM recipient_downloads", func(f *linkFixture) func() error { return completeItem(f, f.fileID) }},
		{"complete read", faultQuery, joinLinks, complete},
		{"complete link", faultExec, "UPDATE recipient_links SET completed_at", complete},
		{"complete count", faultQuery, "AND completed_at IS NULL", complete},
		{"destroy list", faultQuery, "SELECT token_key_id FROM recipient_links", destroy},
		{"destroy key", faultExec, "DELETE FROM wrapped_keys", destroy},
		{"destroy recipient list", faultQuery, joinLinks, destroyRecipient},
		{"tracking links", faultQuery, joinLinks, trackingTx},
		{"tracking downloads", faultQuery, "WHERE tenant_id = ? AND recipient_link_id = ? ORDER BY first_at", trackingTx},
		{"tracking downloads scan", faultScanNil, "WHERE tenant_id = ? AND recipient_link_id = ? ORDER BY first_at", trackingTx},
		{"tracking read", faultQuery, joinLinks, func(f *linkFixture) func() error {
			return func() error { _, err := links(f).TrackingByTransfer(ctx, f.tid, f.avail.ID); return err }
		}},
		{"reminder targets", faultQuery, joinLinks, targets},
		{"reminder sent", faultExec, "SET reminder_sent_at = ?", markSent},
		{"reminder sent probe", faultQuery, "SELECT count(*) FROM recipient_links WHERE tenant_id = ? AND id", func(f *linkFixture) func() error { return twice(markSent(f)) }},
		{"reminder reset", faultExec, "SET reminder_sent_at = NULL", resetReminder},
		{"reminder reset transfer", faultExec, "SET expiry_reminder_at = NULL", resetReminder},
		{"expiry reminder", faultExec, "SET expiry_reminder_at = ?", markReminder},
		{"expiry reminder probe", faultQuery, "SELECT count(*) FROM transfers WHERE tenant_id = ? AND id", func(f *linkFixture) func() error { return twice(markReminder(f)) }},
		{"due reminders", faultQuery, "AND expires_at <= ? AND expires_at > ?", func(f *linkFixture) func() error {
			return func() error {
				_, err := links(f).DueReminders(ctx, now, SweepPage{Limit: 1})
				return err
			}
		}},
		{"challenge link", faultQuery, joinLinks, challenge},
		{"link transfers", faultQuery, "SELECT id, transfer_id FROM recipient_links", func(f *linkFixture) func() error {
			return func() error { _, err := links(f).TransfersByLink(ctx, f.tid); return err }
		}},
		{"link transfers scan", faultScanNil, "SELECT id, transfer_id FROM recipient_links", func(f *linkFixture) func() error {
			return func() error { _, err := links(f).TransfersByLink(ctx, f.tid); return err }
		}},
		{"latest link challenge", faultQuery, "ORDER BY created_at DESC, id DESC", func(f *linkFixture) func() error {
			return func() error { _, err := f.db.Challenges().LatestByLink(ctx, f.tid, f.link.ID); return err }
		}},
		{"count link challenges", faultQuery, "recipient_link_id = ? AND created_at", func(f *linkFixture) func() error {
			return inTx(f, func(tx *ScopedTx) error {
				_, err := f.db.Challenges().CountByLinkSinceTx(ctx, tx, f.link.ID, now)
				return err
			})
		}},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newLinkFixture(t)
			run := s.run(f)
			f.plan.add(s.op, s.match, 0)
			if err := run(); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestLinkTransfersLimit lowers MaxReconcileRows to reach ErrTooManyRows
// in TransfersByLink.
func TestLinkTransfersLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newLinkFixture(t)
	f.db.reconcileRows = 0
	if _, err := f.db.RecipientLinks().TransfersByLink(ctx, f.tid); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("TransfersByLink above the limit = %v", err)
	}
	f.db.reconcileRows = 1
	if got, err := f.db.RecipientLinks().TransfersByLink(ctx, f.tid); err != nil || len(got) != 1 || got[f.link.ID] != f.avail.ID {
		t.Errorf("TransfersByLink at the limit = %v, %v", got, err)
	}
}

// TestFirstDownloadReReadFault fails the second read of a shared transfer
// by MarkFirstDownloadTx, after its conditional update matched nothing:
// the error surfaces.
func TestFirstDownloadReReadFault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	f.plan.add(faultQuery, "extension_count, extended_at FROM transfers WHERE tenant_id = ? AND id = ?", 1)
	err := f.tx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.Transfers().MarkFirstDownloadTx(ctx, tx, f.trf.ID, time.Now(), time.Time{})
		return err
	})
	if err == nil {
		t.Fatal("no error with an injected fault on the second read")
	}
}
