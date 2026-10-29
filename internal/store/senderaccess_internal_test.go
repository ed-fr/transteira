package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSenderAccessDriverFaults injects a driver failure into each
// statement of "my transfers" (the SenderAccess repository and the sender
// view of the transfers) and checks that it surfaces as an error.
func TestSenderAccessDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	mac := bytes.Repeat([]byte{3}, AddressMACSize)
	hash := sha256.Sum256([]byte("session"))
	sa := func(f *linkFixture) *SenderAccess { return f.db.SenderAccess() }
	inTx := func(f *linkFixture, fn func(tx *ScopedTx) error) func() error {
		return func() error { return f.tx(ctx, fn) }
	}
	record := func(f *linkFixture) func() error {
		return func() error { _, err := sa(f).RecordRequest(ctx, f.tid, mac, fixtureIP, now); return err }
	}
	endSession := func(f *linkFixture) func() error {
		err := f.tx(ctx, func(tx *ScopedTx) error {
			_, err := sa(f).CreateSessionTx(ctx, tx, hash[:], fixtureEmail, now, now.Add(time.Hour))
			return err
		})
		if err != nil {
			panic(err)
		}
		return func() error { return sa(f).EndSession(ctx, f.tid, hash[:], now) }
	}
	deleteByEmail := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error { _, err := sa(f).DeleteByEmailTx(ctx, tx, fixtureEmail); return err })
	}
	list := func(f *linkFixture) func() error {
		return func() error { _, err := f.db.Transfers().ListBySender(ctx, f.tid, fixtureEmail, "", 0); return err }
	}
	get := func(f *linkFixture) func() error {
		return func() error { _, err := f.db.Transfers().GetBySender(ctx, f.tid, f.avail.ID, fixtureEmail); return err }
	}
	extend := func(f *linkFixture) func() error {
		return inTx(f, func(tx *ScopedTx) error {
			_, err := f.db.Transfers().ExtendTx(ctx, tx, f.avail.ID, fixtureEmail, now.Add(30*24*time.Hour), now)
			return err
		})
	}
	const sessionList = "api_token_id IS NULL AND status IN"
	steps := []struct {
		name, op, match string
		run             func(f *linkFixture) func() error
	}{
		{"count by address", faultQuery, "access_link_requests WHERE tenant_id = ? AND address_mac", record},
		{"count by ip", faultQuery, "access_link_requests WHERE tenant_id = ? AND client_ip", record},
		{"insert request", faultExec, "INSERT INTO access_link_requests", record},
		{"end session", faultExec, "UPDATE sender_sessions SET ended_at", endSession},
		{"delete links by address", faultExec, "DELETE FROM sender_access_links WHERE tenant_id = ? AND email", deleteByEmail},
		{"delete sessions by address", faultExec, "DELETE FROM sender_sessions WHERE tenant_id = ? AND email", deleteByEmail},
		{"delete requests by mac", faultExec, "DELETE FROM access_link_requests WHERE tenant_id = ? AND address_mac", func(f *linkFixture) func() error {
			return inTx(f, func(tx *ScopedTx) error { _, err := sa(f).DeleteRequestsByMACTx(ctx, tx, mac); return err })
		}},
		{"list", faultQuery, sessionList, list},
		{"list scan", faultScanNil, sessionList, list},
		{"list recipients", faultQuery, "SELECT email FROM transfer_recipients", list},
		{"list downloaded", faultQuery, "first_downloaded_at IS NOT NULL", list},
		{"get downloaded", faultQuery, "first_downloaded_at IS NOT NULL", get},
		{"get tracking", faultQuery, "FROM recipient_links l JOIN", get},
		{"extend", faultExec, "extension_count = extension_count + 1", extend},
		{"extend links", faultExec, "SET reminder_sent_at = NULL WHERE tenant_id = ? AND transfer_id = ?", extend},
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

// TestApplyExtensionStale applies an extension checked against a row that
// changed since it was read: the guarded update matches nothing, and the
// extension is refused as not extendable.
func TestApplyExtensionStale(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newLinkFixture(t)
	now := time.Now()
	err := f.tx(ctx, func(tx *ScopedTx) error {
		tr, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, f.avail.ID))
		if err != nil {
			return err
		}
		// Pretend it was read expiring now: it really expires in 7 days
		// (as if extended meanwhile), so an extension to an hour from now
		// matches no row.
		tr.ExpiresAt = now
		_, err = applyExtension(ctx, tx, tr, now.Add(time.Hour), now)
		return err
	})
	if !errors.Is(err, ErrNotExtendable) {
		t.Fatalf("stale extension = %v, want ErrNotExtendable", err)
	}
	d, err := f.db.Transfers().Get(ctx, f.tid, f.avail.ID)
	if err != nil || d.ExtensionCount != 0 {
		t.Errorf("stale extension changed the transfer: %+v, %v", d.Transfer, err)
	}
}

// TestRecordRequestLockFailure checks that a failing tenant lock
// (PostgreSQL only) aborts the record of an access link request.
func TestRecordRequestLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	_, err := f.db.SenderAccess().RecordRequest(ctx, f.tid, bytes.Repeat([]byte{1}, AddressMACSize), fixtureIP, time.Now())
	if err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("RecordRequest with a failing lock = %v", err)
	}
}
