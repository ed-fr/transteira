package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// transferFixture is a fault-injecting database holding a tenant and an
// uploading transfer with one incomplete file.
type transferFixture struct {
	db   *DB
	plan *faultPlan
	tid  tenant.ID
	trf  Transfer
	file TransferFile
}

// faultSHA is a well-formed SHA-256 of the fault tests.
const faultSHA = "2222222222222222222222222222222222222222222222222222222222222222"

// newTransferFixture builds a transferFixture.
func newTransferFixture(t *testing.T) *transferFixture {
	t.Helper()
	ctx := context.Background()
	db, plan := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	f := &transferFixture{db: db, plan: plan, tid: tn.ID}
	f.trf = Transfer{ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 1}
	f.file = f.newFile(ctx, t)
	if err := f.create(ctx, f.trf, f.file); err != nil {
		t.Fatal(err)
	}
	return f
}

// newFile returns a valid incomplete file with a new data key.
func (f *transferFixture) newFile(ctx context.Context, t *testing.T) TransferFile {
	t.Helper()
	key := id.New(id.WrappedKey)
	if err := f.db.WrappedKeys().Create(ctx, f.tid, WrappedKey{ID: key, Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	upl, _ := id.NewUploadToken()
	return TransferFile{ID: id.New(id.File), Name: "f", Size: 5, DEKKeyID: key, StorageName: hex.EncodeToString([]byte(rand.Text())[:16]), UploadID: upl}
}

// create stores a transfer with one recipient and file fl.
func (f *transferFixture) create(ctx context.Context, trf Transfer, fl TransferFile) error {
	return f.tx(ctx, func(tx *ScopedTx) error {
		return f.db.Transfers().CreateTx(ctx, tx, trf, []string{"bob@b.example.org"}, []TransferFile{fl})
	})
}

// tx runs fn in a scoped transaction of the fixture's tenant.
func (f *transferFixture) tx(ctx context.Context, fn func(*ScopedTx) error) error {
	s, err := f.db.Scoped(f.tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, fn)
}

// TestTransferDriverFaults injects a driver failure into each statement of
// the transfer repositories and checks that it surfaces as an error.
func TestTransferDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	createNew := func(t *testing.T, f *transferFixture, key string) func() error {
		trf := Transfer{ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 1, IdempotencyKey: key}
		fl := f.newFile(ctx, t)
		return func() error { return f.create(ctx, trf, fl) }
	}
	get := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.Transfers().Get(ctx, f.tid, f.trf.ID); return err }
	}
	used := func(f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { _, err := f.db.Transfers().UsedBytesTx(ctx, tx); return err })
		}
	}
	setStatus := func(f *transferFixture, from, to TransferStatus) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { return f.db.Transfers().SetStatusTx(ctx, tx, f.trf.ID, from, to, now) })
		}
	}
	deleteTransfer := func(f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { return f.db.Transfers().DeleteTx(ctx, tx, f.trf.ID) })
		}
	}
	byUpload := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.TransferFiles().GetByUploadID(ctx, f.tid, f.file.UploadID); return err }
	}
	complete := func(f *transferFixture) func() error {
		return func() error { return f.db.TransferFiles().CompleteUpload(ctx, f.tid, f.file.ID, faultSHA, 1, now) }
	}
	completeTwice := func(f *transferFixture) func() error {
		if err := complete(f)(); err != nil {
			panic(err)
		}
		return complete(f)
	}
	// eraseFile destroys the file's key, then (in a second transaction)
	// deletes the file.
	eraseFile := func(f *transferFixture) func() error {
		if err := f.db.WrappedKeys().Delete(ctx, f.tid, f.file.DEKKeyID); err != nil {
			panic(err)
		}
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { return f.db.TransferFiles().DeleteTx(ctx, tx, f.file.ID) })
		}
	}
	deleteKeyed := func(f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { return f.db.TransferFiles().DeleteTx(ctx, tx, f.file.ID) })
		}
	}
	eraseTransfer := func(f *transferFixture) func() error {
		if err := f.db.WrappedKeys().Delete(ctx, f.tid, f.file.DEKKeyID); err != nil {
			panic(err)
		}
		return deleteTransfer(f)
	}

	steps := []struct {
		name, op, match string
		run             func(*testing.T, *transferFixture) func() error
	}{
		{"release key", faultExec, "SET idempotency_key = NULL", func(t *testing.T, f *transferFixture) func() error { return createNew(t, f, "k") }},
		{"insert transfer", faultExec, "INSERT INTO transfers", func(t *testing.T, f *transferFixture) func() error { return createNew(t, f, "") }},
		{"insert recipient", faultExec, "INSERT INTO transfer_recipients", func(t *testing.T, f *transferFixture) func() error { return createNew(t, f, "") }},
		{"check key", faultQuery, "FROM wrapped_keys WHERE tenant_id", func(t *testing.T, f *transferFixture) func() error { return createNew(t, f, "") }},
		{"insert file", faultExec, "INSERT INTO transfer_files", func(t *testing.T, f *transferFixture) func() error { return createNew(t, f, "") }},
		{"get transfer scan", faultScanNil, "expires_at FROM transfers", func(_ *testing.T, f *transferFixture) func() error { return get(f) }},
		{"list recipients", faultQuery, "FROM transfer_recipients", func(_ *testing.T, f *transferFixture) func() error { return get(f) }},
		{"scan recipients", faultScanNil, "FROM transfer_recipients", func(_ *testing.T, f *transferFixture) func() error { return get(f) }},
		{"list files", faultQuery, "scan_status FROM transfer_files WHERE tenant_id = ? AND transfer_id", func(_ *testing.T, f *transferFixture) func() error { return get(f) }},
		{"scan files", faultScanNil, "scan_status FROM transfer_files WHERE tenant_id = ? AND transfer_id", func(_ *testing.T, f *transferFixture) func() error { return get(f) }},
		{"used bytes", faultQuery, "sum(total_bytes)", func(_ *testing.T, f *transferFixture) func() error { return used(f) }},
		{"finalize", faultExec, "SET status = 'scanning'", func(_ *testing.T, f *transferFixture) func() error {
			return setStatus(f, TransferUploading, TransferScanning)
		}},
		{"finalize rows", faultRows, "SET status = 'scanning'", func(_ *testing.T, f *transferFixture) func() error {
			return setStatus(f, TransferUploading, TransferScanning)
		}},
		{"set status", faultExec, "SET status = ?", func(_ *testing.T, f *transferFixture) func() error {
			return setStatus(f, TransferUploading, TransferDeleted)
		}},
		{"status probe", faultQuery, "SELECT count(*) FROM transfers", func(_ *testing.T, f *transferFixture) func() error {
			return setStatus(f, TransferAvailable, TransferExpired)
		}},
		{"count keyed files", faultQuery, "dek_key_id IS NOT NULL", func(_ *testing.T, f *transferFixture) func() error { return deleteTransfer(f) }},
		{"delete transfer", faultExec, "DELETE FROM transfers", func(_ *testing.T, f *transferFixture) func() error { return eraseTransfer(f) }},
		{"delete transfer rows", faultRows, "DELETE FROM transfers", func(_ *testing.T, f *transferFixture) func() error { return eraseTransfer(f) }},
		{"upload file", faultQuery, "FROM transfer_files WHERE tenant_id = ? AND upload_id", func(_ *testing.T, f *transferFixture) func() error { return byUpload(f) }},
		{"upload transfer", faultQuery, "FROM transfers WHERE tenant_id = ? AND id", func(_ *testing.T, f *transferFixture) func() error { return byUpload(f) }},
		{"complete", faultExec, "SET sha256 = ?", func(_ *testing.T, f *transferFixture) func() error { return complete(f) }},
		{"complete rows", faultRows, "SET sha256 = ?", func(_ *testing.T, f *transferFixture) func() error { return complete(f) }},
		{"file probe", faultQuery, "SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND id", func(_ *testing.T, f *transferFixture) func() error {
			return completeTwice(f)
		}},
		{"delete file", faultQuery, "DELETE FROM transfer_files", func(_ *testing.T, f *transferFixture) func() error { return eraseFile(f) }},
		{"delete file probe", faultQuery, "SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND id", func(_ *testing.T, f *transferFixture) func() error {
			return deleteKeyed(f)
		}},
		{"shrink transfer", faultExec, "SET total_bytes = total_bytes", func(_ *testing.T, f *transferFixture) func() error { return eraseFile(f) }},
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

// TestUsedBytesLockFailure checks that a failing tenant lock (PostgreSQL
// only) aborts the quota sum.
func TestUsedBytesLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	err := f.tx(ctx, func(tx *ScopedTx) error { _, err := f.db.Transfers().UsedBytesTx(ctx, tx); return err })
	if err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("UsedBytesTx with a failing lock = %v", err)
	}
}
