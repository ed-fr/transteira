package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// cleanupEvery runs every task of the lifecycle sweeper but the backup
// every 50 ms (CLAUDE.md section 20): the tests age the rows and files they
// need with SQL and file times, then wait for the running server to act.
func cleanupEvery(lo *lifecycle.Options) {
	lo.Interval, lo.AbandonedInterval = 50*time.Millisecond, 50*time.Millisecond
	lo.PurgeInterval, lo.OrphansInterval = 50*time.Millisecond, 50*time.Millisecond
}

// countSystem returns the integer result of the query q, run outside any
// tenant scope.
func countSystem(t *testing.T, e storetest.Engine, q string) int {
	t.Helper()
	driver := "sqlite"
	if e.Driver == config.DriverPostgres {
		driver = "pgx"
	}
	raw, err := sql.Open(driver, e.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	ctx := context.Background()
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if e.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', 'on', true)`); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// usedBytes returns the quota used by the tenant tid.
func (d *depositEnv) usedBytes(t *testing.T, tid tenant.ID) int64 {
	t.Helper()
	s, err := d.db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		n, err = d.db.Transfers().UsedBytesTx(context.Background(), tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// openTenantB gives tenant B the SMTP settings of tenant A and returns an
// internal depositor of B with an open session.
func openTenantB(t *testing.T, d *depositEnv) *depositor {
	t.Helper()
	err := d.db.SMTPSettings().Put(context.Background(), d.tenantB.ID, store.SMTPConfig{
		Host: d.mp.host, Port: d.mp.port, Security: store.SMTPSecurityNone,
		FromAddress: "noreply@" + domainB, FromName: nameB,
	})
	if err != nil {
		t.Fatalf("put SMTP settings of B: %v", err)
	}
	bob := &depositor{d: d, host: hostB, ip: insideB}
	bob.openSession(t, uniqueEmail(t, "bob", domainB), "")
	return bob
}

// expectIntactB checks that the transfer trfID of tenant B is still
// available, with its keys and its files.
func expectIntactB(t *testing.T, d *depositEnv, trfID string) {
	t.Helper()
	ctx := context.Background()
	tr, err := d.db.Transfers().Get(ctx, d.tenantB.ID, trfID)
	if err != nil || tr.Status != store.TransferAvailable || tr.DownloadTokenKeyID == "" {
		t.Fatalf("transfer of B: %s, %v", tr.Status, err)
	}
	for _, f := range tr.Files {
		if _, err := d.db.WrappedKeys().Get(ctx, d.tenantB.ID, f.DEKKeyID); err != nil {
			t.Fatalf("data key of B: %v", err)
		}
		if !exists(t, filepath.Join(d.cfg.DataDir, string(d.tenantB.ID), f.StorageName+encSuffix)) {
			t.Fatal("file of B removed")
		}
	}
}

// TestCleanupExpiredTransfer: past its expiry, a transfer is erased by the
// running server (keys destroyed, files and download state removed, status
// expired, quota released) and its link answers 410; 30 days after, its row
// is deleted and the link answers 404. Tenant B is never touched.
func TestCleanupExpiredTransfer(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{lifecycle: cleanupEvery})
		bob := openTenantB(t, d)
		alice, _ := internalSession(t, d, "alice")
		content := []byte("expiring content")
		tr, token := alice.availableTransfer(t, transferCreate{},
			uploadedFile{"a.txt", content}, uploadedFile{"b.txt", []byte("second file")})
		trB, _ := bob.availableTransfer(t, transferCreate{}, uploadedFile{"b.txt", []byte("content of B")})
		r := d.newRecipient(7)
		expectFile(t, "a", r.get(t, filePath(token, tr.Files[0].ID), nil), "a.txt", content)
		eventually(t, "download state written", func() bool { return exists(t, statePath(d, tr.ID)) })
		before := d.transferRow(t, tr.ID)
		if d.usedBytes(t, d.tenantA.ID) == 0 {
			t.Fatal("no quota used before the expiry")
		}

		execSystem(t, e, "UPDATE transfers SET expires_at = "+strconv.FormatInt(nowMillis(-time.Second), 10)+
			" WHERE id = '"+tr.ID+"'")
		eventually(t, "transfer expired by the cleanup", func() bool {
			return d.transferRow(t, tr.ID).Status == store.TransferExpired
		})
		after := d.transferRow(t, tr.ID)
		if after.DownloadTokenKeyID != "" || after.EndedAt.IsZero() {
			t.Errorf("expired row: token key %q, ended at %v", after.DownloadTokenKeyID, after.EndedAt)
		}
		d.expectKeyDestroyed(t, before.DownloadTokenKeyID)
		for _, f := range before.Files {
			d.expectKeyDestroyed(t, f.DEKKeyID)
			expectNoFileOnDisk(t, "the encrypted file", d.encPath(f.StorageName))
		}
		expectNoFileOnDisk(t, "the download state", statePath(d, tr.ID))
		if got := d.usedBytes(t, d.tenantA.ID); got != 0 {
			t.Errorf("quota used after the expiry = %d, want 0", got)
		}
		expectGone(t, "page of the expired transfer", r.page(t, token))
		expectIntactB(t, d, trB.ID)

		execSystem(t, e, "UPDATE transfers SET ended_at = "+
			strconv.FormatInt(nowMillis(-lifecycle.EndedRetention-time.Minute), 10)+" WHERE id = '"+tr.ID+"'")
		eventually(t, "row deleted after the retention", func() bool {
			_, err := d.db.Transfers().Get(context.Background(), d.tenantA.ID, tr.ID)
			return errors.Is(err, store.ErrNotFound)
		})
		if resp := r.page(t, token); resp.status != http.StatusNotFound {
			t.Errorf("page after the retention: %d, want 404", resp.status)
		}
		expectIntactB(t, d, trB.ID)
	})
}

// TestCleanupAbandonedUpload: an upload abandoned past its TTL is expired by
// the running server: its quota reservation is released, its encrypted
// files and checkpoints are removed and its keys destroyed.
func TestCleanupAbandonedUpload(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{lifecycle: cleanupEvery})
		alice, _ := internalSession(t, d, "alice")
		done, partial := []byte("complete file"), seededBytes(t, 3, 64<<10)
		tr := alice.mustCreate(t, transferCreate{
			Recipients: []string{uniqueEmail(t, "rcpt", "example.net")}, ExpiryDays: 7,
			Files: []fileDecl{{Name: "done.txt", Size: int64(len(done))}, {Name: "partial.bin", Size: int64(len(partial))}},
		})
		alice.upload(t, tr.Files[0].UploadURL, done)
		alice.mustPatch(t, tr.Files[1].UploadURL, 0, partial[:len(partial)/2])
		files := d.files(t, tr.ID)
		ckpt := d.ckptPath(files[1].StorageName)
		if !exists(t, ckpt) || d.usedBytes(t, d.tenantA.ID) != int64(len(done)+len(partial)) {
			t.Fatalf("before: checkpoint %v, quota %d", exists(t, ckpt), d.usedBytes(t, d.tenantA.ID))
		}

		// Two days old, the last activity 25 hours ago (TT_UPLOAD_TTL 24 h).
		old := strconv.FormatInt(nowMillis(-48*time.Hour), 10)
		idle := time.Now().Add(-25 * time.Hour)
		if err := os.Chtimes(ckpt, idle, idle); err != nil {
			t.Fatal(err)
		}
		execSystem(t, e,
			"UPDATE transfer_files SET uploaded_at = "+old+" WHERE transfer_id = '"+tr.ID+"' AND uploaded_at IS NOT NULL",
			"UPDATE transfers SET created_at = "+old+" WHERE id = '"+tr.ID+"'")
		eventually(t, "abandoned upload expired by the cleanup", func() bool {
			return d.transferRow(t, tr.ID).Status == store.TransferExpired
		})
		if got := d.usedBytes(t, d.tenantA.ID); got != 0 {
			t.Errorf("quota used after the cleanup = %d, want 0", got)
		}
		for _, f := range files {
			d.expectKeyDestroyed(t, f.DEKKeyID)
			expectNoFileOnDisk(t, "the encrypted file", d.encPath(f.StorageName))
			expectNoFileOnDisk(t, "the checkpoint", d.ckptPath(f.StorageName))
		}
		if resp := alice.head(t, tr.Files[1].UploadURL); resp.status != http.StatusNotFound {
			t.Errorf("HEAD of the abandoned upload: %d, want 404", resp.status)
		}
	})
}

// TestCleanupRowPurges: each row purge applies at a high level (the store
// tests cover the exact boundaries): stale rows go, live ones stay, and a
// purge of tenant A never touches the rows of tenant B, even under the
// same key.
func TestCleanupRowPurges(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{lifecycle: cleanupEvery})
		alice, aliceEmail := internalSession(t, d, "alice")
		guest, kept := uniqueEmail(t, "guest", externalDomain), uniqueEmail(t, "kept", externalDomain)
		for _, g := range []string{guest, kept} {
			if resp := alice.invite(t, `{"email":"`+g+`"}`, alice.withCSRF()); resp.status != http.StatusCreated {
				t.Fatalf("createInvitation: %d %s", resp.status, resp.body)
			}
		}
		// Opened later: its challenge, session and address stay.
		_, carolEmail := internalSession(t, d, "carol")
		a, b := string(d.tenantA.ID), string(d.tenantB.ID)
		ms := func(d time.Duration) string { return strconv.FormatInt(nowMillis(d), 10) }
		months := func(n, days int) string {
			return strconv.FormatInt(time.Now().AddDate(-n/12, -n%12, days).UnixMilli(), 10)
		}
		execSystem(t, e,
			"UPDATE verification_challenges SET created_at = "+ms(-2*time.Hour)+" WHERE email = '"+aliceEmail+"'",
			"UPDATE deposit_sessions SET expires_at = "+ms(-time.Second)+" WHERE email = '"+aliceEmail+"'",
			"UPDATE verified_addresses SET last_used_at = "+months(12, -1)+" WHERE email = '"+aliceEmail+"'",
			"UPDATE verified_addresses SET last_used_at = "+months(12, 1)+" WHERE email = '"+carolEmail+"'",
			"UPDATE invitations SET created_at = "+ms(-2*time.Hour)+", expires_at = "+ms(-time.Second)+
				" WHERE email = '"+guest+"'",
			"INSERT INTO password_failures (tenant_id, scope, key, fail_1) VALUES ('"+a+"', 'ip', 'k1', "+ms(-time.Hour)+")",
			"INSERT INTO password_failures (tenant_id, scope, key, fail_1) VALUES ('"+a+"', 'ip', 'k2', "+ms(0)+")",
			"INSERT INTO password_failures (tenant_id, scope, key, fail_1) VALUES ('"+b+"', 'ip', 'k1', "+ms(0)+")",
		)
		count := func(table, where string) int {
			return countSystem(t, e, "SELECT count(*) FROM "+table+" WHERE "+where)
		}
		eventually(t, "stale rows purged", func() bool {
			return count("verification_challenges", "email = '"+aliceEmail+"'") == 0 &&
				count("deposit_sessions", "email = '"+aliceEmail+"'") == 0 &&
				count("verified_addresses", "email = '"+aliceEmail+"'") == 0 &&
				count("invitations", "email = '"+guest+"'") == 0 &&
				count("password_failures", "tenant_id = '"+a+"' AND key = 'k1'") == 0
		})
		for _, c := range []struct{ table, where string }{
			{"verification_challenges", "email = '" + carolEmail + "'"},
			{"deposit_sessions", "email = '" + carolEmail + "'"},
			{"verified_addresses", "email = '" + carolEmail + "'"},
			{"invitations", "email = '" + kept + "'"},
			{"password_failures", "tenant_id = '" + a + "' AND key = 'k2'"},
			{"password_failures", "tenant_id = '" + b + "' AND key = 'k1'"},
		} {
			if count(c.table, c.where) != 1 {
				t.Errorf("%s where %s: purged, want kept", c.table, c.where)
			}
		}
	})
}

// TestCleanupOrphans: the files the database proves orphaned are removed
// once older than 24 hours; fresh files, referenced files, unknown entries
// and the files of another tenant are kept.
func TestCleanupOrphans(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d, _ := startScanDeposit(t, e, serverOptions{lifecycle: cleanupEvery})
		alice, _ := internalSession(t, d, "alice")
		tr, _ := alice.availableTransfer(t, transferCreate{}, uploadedFile{"a.txt", []byte("referenced")})
		ref := d.encPath(d.files(t, tr.ID)[0].StorageName)
		old, fresh := time.Now().Add(-25*time.Hour), time.Now().Add(-23*time.Hour)
		dirB := filepath.Join(d.cfg.DataDir, string(d.tenantB.ID))
		write := func(dir, file string, mod time.Time) string {
			t.Helper()
			p := filepath.Join(dir, file)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(p, mod, mod); err != nil {
				t.Fatal(err)
			}
			return p
		}
		if err := os.Chtimes(ref, old, old); err != nil {
			t.Fatal(err)
		}
		orphan := storage.NewName()
		removed := []string{
			write(d.tenantDir(), orphan+encSuffix, old),
			write(d.tenantDir(), storage.NewName()+ckptSuffix, old),
			write(d.tenantDir(), storage.NewName()+".dlstate", old),
			write(d.tenantDir(), storage.NewName()+".dlstate.0123456789abcdef.tmp", old),
		}
		keptFiles := []string{
			ref,
			write(d.tenantDir(), storage.NewName()+encSuffix, fresh),
			write(d.tenantDir(), "notes.txt", old),
			// The same name in tenant B, fresh: B is reconciled on its own.
			write(dirB, orphan+encSuffix, fresh),
		}
		eventually(t, "orphans removed", func() bool {
			for _, p := range removed {
				if exists(t, p) {
					return false
				}
			}
			return true
		})
		for _, p := range keptFiles {
			if !exists(t, p) {
				t.Errorf("%s removed", filepath.Base(p))
			}
		}
	})
}

// TestCleanupBackup: with SQLite, the nightly copy is written at
// TT_BACKUP_TIME (moved five seconds ahead), reopens and passes quick_check,
// and the rotation keeps TT_BACKUP_KEEP copies; with PostgreSQL the task
// is left to the dedicated container, which the log says once.
func TestCleanupBackup(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		if e.Driver == config.DriverPostgres {
			s := startServer(t, e, serverOptions{})
			select {
			case <-s.appLog.wait("backups are made by the dedicated PostgreSQL container"):
			case <-time.After(waitTimeout):
				t.Fatalf("no PostgreSQL backup notice:\n%s", s.appLog)
			}
			return
		}
		now := time.Now().UTC()
		at := now.Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)) + 5*time.Second
		s := startServer(t, e, serverOptions{lifecycle: func(lo *lifecycle.Options) {
			lo.BackupTime, lo.BackupKeep = at%(24*time.Hour), 2
			// The older copies are created before the first run.
			for _, f := range []string{
				"transteira-20200101T000000Z.db", "transteira-20210101T000000Z.db", ".transteira-20200101T000000Z.db.tmp",
			} {
				if err := os.MkdirAll(lo.BackupDir, 0o700); err != nil {
					t.Error(err)
				}
				if err := os.WriteFile(filepath.Join(lo.BackupDir, f), nil, 0o600); err != nil {
					t.Error(err)
				}
			}
		}})
		dir := s.cfg.BackupDir
		var names []string
		eventually(t, "database copy written and rotated", func() bool {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			names = names[:0]
			for _, en := range entries {
				names = append(names, en.Name())
			}
			slices.Sort(names)
			return len(names) == 2 && names[0] == "transteira-20210101T000000Z.db"
		})
		latest := filepath.Join(dir, names[1])
		if !backupName.MatchString(names[1]) {
			t.Fatalf("copy name %q", names[1])
		}
		db, err := sql.Open("sqlite", latest+"?_pragma=query_only(1)")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		var check string
		var tenants int
		if err := db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
			t.Fatalf("quick_check of the copy = %q, %v", check, err)
		}
		if err := db.QueryRow("SELECT count(*) FROM tenants").Scan(&tenants); err != nil || tenants != 2 {
			t.Fatalf("tenants in the copy = %d, %v", tenants, err)
		}
	})
}

// backupName is the name of a database copy.
var backupName = regexp.MustCompile(`^transteira-\d{8}T\d{6}Z\.db$`)
