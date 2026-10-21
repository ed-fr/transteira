package store

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// makeAvailable makes a transfer available and returns its ID: the
// fixture's transfer, or a new one with the "delete after the first
// download" option when deleteOpt is set. Its file is completed and clean.
func (f *transferFixture) makeAvailable(ctx context.Context, t *testing.T, deleteOpt bool) string {
	t.Helper()
	trf := f.trf
	fl := f.file
	if deleteOpt {
		trf = Transfer{ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 1, DeleteAfterFirstDownload: true}
		fl = f.newFile(ctx, t)
		if err := f.create(ctx, trf, fl); err != nil {
			t.Fatal(err)
		}
	}
	tokenKey := id.New(id.WrappedKey)
	if err := f.db.WrappedKeys().Create(ctx, f.tid, WrappedKey{ID: tokenKey, Purpose: KeyPurposeSecret, KeyID: testMK1, Blob: []byte("t")}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err := f.tx(ctx, func(tx *ScopedTx) error {
		if err := completeUpload(ctx, tx, fl.ID, faultSHA, 1, now); err != nil {
			return err
		}
		if err := setStatus(ctx, tx, trf.ID, TransferUploading, TransferScanning, now); err != nil {
			return err
		}
		if err := setScanResult(ctx, tx, fl.ID, ScanClean, "", now); err != nil {
			return err
		}
		return markAvailable(ctx, tx, trf.ID, hashOf(trf.ID), tokenKey, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return trf.ID
}

// TestDownloadDriverFaults injects a driver failure into each statement of
// the download bookkeeping and checks that it surfaces as an error.
func TestDownloadDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	keys := []FailureKey{TransferFailureKey(id.New(id.Transfer)), IPFailureKey(netip.MustParseAddr("192.0.2.1"))}
	firstDownload := func(t *testing.T, f *transferFixture, deleteOpt bool) func() error {
		trfID := f.makeAvailable(ctx, t, deleteOpt)
		var deleteAfter time.Time
		if deleteOpt {
			deleteAfter = now.Add(time.Minute)
		}
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.Transfers().MarkFirstDownloadTx(ctx, tx, trfID, now, deleteAfter)
				return err
			})
		}
	}
	// probeFirst marks the fixture's uploading transfer, which probes it.
	probeFirst := func(_ *testing.T, f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.Transfers().MarkFirstDownloadTx(ctx, tx, f.trf.ID, now, time.Time{})
				return err
			})
		}
	}
	markDeleted := func(_ *testing.T, f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { return f.db.Transfers().MarkDeletedTx(ctx, tx, f.trf.ID) })
		}
	}
	markDeletedKeyless := func(t *testing.T, f *transferFixture) func() error {
		if err := f.db.WrappedKeys().Delete(ctx, f.tid, f.file.DEKKeyID); err != nil {
			t.Fatal(err)
		}
		return markDeleted(t, f)
	}
	due := func(t *testing.T, f *transferFixture) func() error {
		trfID := f.makeAvailable(ctx, t, true)
		if err := f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.Transfers().MarkFirstDownloadTx(ctx, tx, trfID, now, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return func() error { _, err := f.db.Transfers().DueDeletions(ctx, now, SweepPage{Limit: 1}); return err }
	}
	failures := func(op string) func(*testing.T, *transferFixture) func() error {
		return func(t *testing.T, f *transferFixture) func() error {
			pf := f.db.PasswordFailures()
			// A first failure creates the rows, so that a second one
			// updates them.
			if err := f.tx(ctx, func(tx *ScopedTx) error { _, err := pf.RecordFailureTx(ctx, tx, keys, now); return err }); err != nil {
				t.Fatal(err)
			}
			return func() error {
				return f.tx(ctx, func(tx *ScopedTx) error {
					switch op {
					case "check":
						_, err := pf.CheckTx(ctx, tx, keys, now)
						return err
					case "reset":
						return pf.ResetTx(ctx, tx, keys)
					case "refund":
						return pf.RefundTx(ctx, tx, keys, now)
					}
					_, err := pf.RecordFailureTx(ctx, tx, keys, now)
					return err
				})
			}
		}
	}
	freshFailure := func(_ *testing.T, f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error {
				_, err := f.db.PasswordFailures().RecordFailureTx(ctx, tx, keys, now)
				return err
			})
		}
	}

	steps := []struct {
		name, op, match string
		run             func(*testing.T, *transferFixture) func() error
	}{
		{"first download", faultExec, "AND NOT delete_after_first_download", func(t *testing.T, f *transferFixture) func() error { return firstDownload(t, f, false) }},
		{"first download rows", faultRows, "AND NOT delete_after_first_download", func(t *testing.T, f *transferFixture) func() error { return firstDownload(t, f, false) }},
		{"first download delete", faultExec, "SET first_downloaded_at = ?, delete_after", func(t *testing.T, f *transferFixture) func() error { return firstDownload(t, f, true) }},
		{"first download probe", faultQuery, "FROM transfers WHERE tenant_id = ? AND id", probeFirst},
		{"mark deleted keyed files", faultQuery, "dek_key_id IS NOT NULL", markDeleted},
		{"mark deleted", faultExec, "SET status = 'deleted'", markDeletedKeyless},
		{"mark deleted probe", faultQuery, "FROM transfers WHERE tenant_id = ? AND id", markDeletedKeyless},
		{"due deletions", faultQuery, "ORDER BY delete_after", due},
		{"due deletions scan", faultScanNil, "ORDER BY delete_after", due},
		{"check failures", faultQuery, "FROM password_failures", failures("check")},
		{"record read", faultQuery, "FROM password_failures", failures("record")},
		{"record update", faultExec, "UPDATE password_failures", failures("record")},
		{"record insert", faultExec, "INSERT INTO password_failures", freshFailure},
		{"reset", faultExec, "DELETE FROM password_failures", failures("reset")},
		{"refund read", faultQuery, "FROM password_failures", failures("refund")},
		{"refund update", faultExec, "UPDATE password_failures", failures("refund")},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newTransferFixture(t)
			run := s.run(t, f)
			f.plan.add(s.op, s.match, 0)
			if err := run(); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestPasswordFailuresLockFailure checks that a failing tenant lock
// (PostgreSQL only) aborts every password failure operation.
func TestPasswordFailuresLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	pf := f.db.PasswordFailures()
	keys := []FailureKey{TransferFailureKey(f.trf.ID)}
	for name, fn := range map[string]func(*ScopedTx) error{
		"CheckTx":         func(tx *ScopedTx) error { _, err := pf.CheckTx(ctx, tx, keys, time.Now()); return err },
		"RecordFailureTx": func(tx *ScopedTx) error { _, err := pf.RecordFailureTx(ctx, tx, keys, time.Now()); return err },
		"ResetTx":         func(tx *ScopedTx) error { return pf.ResetTx(ctx, tx, keys) },
		"RefundTx":        func(tx *ScopedTx) error { return pf.RefundTx(ctx, tx, keys, time.Now()) },
	} {
		if err := f.tx(ctx, fn); err == nil || !strings.Contains(err.Error(), "lock tenant") {
			t.Errorf("%s with a failing lock = %v", name, err)
		}
	}
}
