package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// v1Tables are the tables holding V1 data that the V1.1 migrations rebuild
// or alter, directly or as children of a rebuilt table.
var v1Tables = []string{
	"tenants", "wrapped_keys", "master_keys", "api_tokens", "invitations", "transfers", "transfer_recipients",
	"transfer_files", "verification_challenges", "deposit_sessions", "tenant_email_templates", "system_secrets",
	"admins", "admin_sessions",
}

// rawExecArgs runs q with args in a system transaction on the write pool,
// rewriting the placeholders for PostgreSQL.
func rawExecArgs(ctx context.Context, t *testing.T, db *DB, q string, args ...any) error {
	t.Helper()
	if db.dialect.numbered {
		q = rebindNumbered(q)
	}
	return db.runTx(ctx, db.write, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	})
}

// rawInt returns the integer read by q in a system transaction.
func rawInt(ctx context.Context, t *testing.T, db *DB, q string) int64 {
	t.Helper()
	var n int64
	err := db.runTx(ctx, db.write, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, q).Scan(&n)
	})
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// seedV1 fills a database at 0013 with V1 data in two tenants: keys,
// tokens, invitations, transfers in several states with recipients and
// files, codes, sessions, a mail template, and a super admin whose TOTP
// secret is a system secret with an open session.
func seedV1(ctx context.Context, t *testing.T, db *DB, a, b tenant.ID) {
	t.Helper()
	h := func(c byte) []byte { return bytes.Repeat([]byte{c}, 32) }
	name := func(c string) string { return strings.Repeat(c, 32) }
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO master_keys (id, status, created_at) VALUES ('mk_0000000000000001', 'active', 1)`, nil},
		{`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES ('mk_0000000000000002', 'retired', 1, 2)`, nil},
		{
			`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES (?, ?, ?, 'mk_0000000000000001', ?, 1)`,
			[]any{"key_f1", string(a), "dek", []byte("sealed")},
		},
		{
			`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES (?, ?, ?, 'mk_0000000000000001', ?, 1)`,
			[]any{"key_f2", string(a), "dek", []byte("sealed")},
		},
		{
			`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES (?, ?, ?, 'mk_0000000000000001', ?, 1)`,
			[]any{"key_dl", string(a), "secret", []byte("sealed")},
		},
		{`INSERT INTO api_tokens (id, tenant_id, name, prefix, token_hash, allowed_cidrs, created_by, created_at)
			VALUES ('tok_a', ?, 'ci', 'tt_Ab', ?, '[]', 'root', 1)`, []any{string(a), h(1)}},
		{`INSERT INTO invitations (id, tenant_id, token_hash, email, invited_by, created_at, expires_at)
			VALUES ('inv_a', ?, ?, 'guest@example.org', 'alice@a.example.com', 1, 9)`, []any{string(a), h(2)}},
		// An available transfer with its shared link, already downloaded.
		{`INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days, password_hash,
			delete_after_first_download, total_bytes, created_at, finalized_at, expires_at, download_token_hash,
			download_token_key_id, available_at, first_downloaded_at, delete_after, sender_ip, download_count)
			VALUES ('trf_a1', ?, 'available', 'alice@a.example.com', 'internal', 7, '$argon2id$x', ?, 30, 1, 2, 3,
			?, 'key_dl', 2, 2, 3, '192.0.2.1', 2)`, []any{string(a), true, h(3)}},
		{`INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, invitation_id, expiry_days,
			delete_after_first_download, total_bytes, created_at)
			VALUES ('trf_a2', ?, 'uploading', 'guest@example.org', 'external', 'inv_a', 1, ?, 0, 1)`, []any{string(a), false}},
		{
			`INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, idempotency_key, created_at, finalized_at, expires_at, ended_at, api_token_id)
			VALUES ('trf_a3', ?, 'expired', 'alice@a.example.com', 'internal', 30, ?, 5, 'k1', 1, 2, 3, 4, 'tok_a')`,
			[]any{string(a), false},
		},
		{`INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, created_at, finalized_at, expires_at)
			VALUES ('trf_b1', ?, 'scanning', 'bob@b.example.com', 'internal', 1, ?, 7, 1, 2, 3)`, []any{string(b), false}},
		{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_a1', 0, 'r0@example.org')`, []any{string(a)}},
		{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_a1', 1, 'r1@example.org')`, []any{string(a)}},
		{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_a2', 0, 'alice@a.example.com')`, []any{string(a)}},
		{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_b1', 0, 'r@example.org')`, []any{string(b)}},
		{
			`INSERT INTO transfer_files (id, tenant_id, transfer_id, position, name, size, sha256, dek_key_id, storage_name,
			upload_id, ciphertext_size, uploaded_at, scan_status, scanned_at)
			VALUES ('fil_a1', ?, 'trf_a1', 0, 'a.pdf', 10, ?, 'key_f1', ?, 'upl_a1', 50, 2, 'clean', 2)`,
			[]any{string(a), strings.Repeat("a", 64), name("1")},
		},
		{
			`INSERT INTO transfer_files (id, tenant_id, transfer_id, position, name, size, sha256, dek_key_id, storage_name,
			upload_id, ciphertext_size, uploaded_at, scan_status, scanned_at, scan_attempts)
			VALUES ('fil_a2', ?, 'trf_a1', 1, 'b.iso', 20, ?, 'key_f2', ?, 'upl_a2', 60, 2, 'not_scanned_too_large', 2, 1)`,
			[]any{string(a), strings.Repeat("b", 64), name("2")},
		},
		{`INSERT INTO transfer_files (id, tenant_id, transfer_id, position, name, size, storage_name, upload_id)
			VALUES ('fil_b1', ?, 'trf_b1', 0, 'c.txt', 7, ?, 'upl_b1')`, []any{string(b), name("3")}},
		{
			`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining, invitation_id,
			client_ip, created_at, expires_at) VALUES ('vch_a1', ?, 'guest@example.org', ?, 2, 'inv_a', '198.51.100.1', 1, 2)`,
			[]any{string(a), h(4)},
		},
		{
			`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining,
			client_ip, created_at, expires_at) VALUES ('vch_b1', ?, 'bob@b.example.com', ?, 1, '192.0.2.9', 1, 2)`,
			[]any{string(b), h(5)},
		},
		{`INSERT INTO deposit_sessions (id, tenant_id, token_hash, email, kind, created_at, expires_at)
			VALUES ('dps_a1', ?, ?, 'alice@a.example.com', 'internal', 1, 2)`, []any{string(a), h(6)}},
		{`INSERT INTO deposit_sessions (id, tenant_id, token_hash, email, kind, invitation_id, created_at, expires_at, ended_at)
			VALUES ('dps_a2', ?, ?, 'guest@example.org', 'external', 'inv_a', 1, 2, 2)`, []any{string(a), h(7)}},
		{`INSERT INTO tenant_email_templates (tenant_id, template_key, language, subject, body_html, body_text, updated_at, updated_by)
			VALUES (?, 'invitation', 'fr', 'Invitation', '<p>x</p>', 'x', 1, 'root')`, []any{string(a)}},
		{
			`INSERT INTO system_secrets (id, purpose, key_id, blob, created_at) VALUES ('sec_1', 'admin-totp', 'mk_0000000000000001', ?, 1)`,
			[]any{[]byte("sealed")},
		},
		{`INSERT INTO admins (id, username, email, role, password_hash, totp_secret_id, totp_enabled, require_totp, created_at, updated_at)
			VALUES ('adm_1', 'root', 'root@example.com', 'super_admin', '$argon2id$x', 'sec_1', ?, ?, 1, 1)`, []any{true, true}},
		{`INSERT INTO admin_sessions (id, token_hash, admin_id, state, created_at, last_seen_at, expires_at)
			VALUES ('ads_1', ?, 'adm_1', 'authenticated', 1, 1, 2)`, []any{h(8)}},
	}
	for _, s := range stmts {
		if err := rawExecArgs(ctx, t, db, s.q, s.args...); err != nil {
			t.Fatalf("seed V1 data: %v\n%s", err, s.q)
		}
	}
}

// rowCounts returns the row count of every table of v1Tables.
func rowCounts(ctx context.Context, t *testing.T, db *DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, tb := range v1Tables {
		out[tb] = rawInt(ctx, t, db, `SELECT count(*) FROM `+tb)
	}
	return out
}

// TestMigrationV11Upgrade applies the V1.1 migrations (0014 to 0020) on a
// database at 0013 holding V1 data: no row is lost (in particular no
// cascade from the rebuilt transfers and system_secrets tables), the
// columns keep their values, the backfills are right, the foreign keys,
// indexes and triggers still work, and the widened checks accept the V1.1
// values.
func TestMigrationV11Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 13)
		if n, err := db.Migrate(ctx); err != nil || n != 13 {
			t.Fatalf("Migrate to 0013 = %d, %v", n, err)
		}
		a := createLegacyTenant(ctx, t, db, "a.example.com", 100)
		b := createLegacyTenant(ctx, t, db, "b.example.com", 100)
		seedV1(ctx, t, db, a, b)
		before := rowCounts(ctx, t, db)

		db.migrationsFS = migrationFiles
		if n, err := db.Migrate(ctx); err != nil || n != 7 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		if after := rowCounts(ctx, t, db); !mapsEqualInt(before, after) {
			t.Fatalf("row counts changed by the V1.1 migrations:\nbefore %v\nafter  %v", before, after)
		}
		if e.Driver == "sqlite" {
			checkSQLiteIntegrity(ctx, t, db)
		}

		check := func(what, q string, want int64) {
			t.Helper()
			if got := rawInt(ctx, t, db, q); got != want {
				t.Errorf("%s: %s = %d, want %d", what, q, got, want)
			}
		}
		// Values kept by the rebuilds.
		check("transfer a1", `SELECT count(*) FROM transfers WHERE id = 'trf_a1' AND status = 'available'
			AND download_token_key_id = 'key_dl' AND available_at = 2 AND first_downloaded_at = 2 AND delete_after = 3
			AND sender_ip = '192.0.2.1' AND download_count = 2 AND password_hash = '$argon2id$x' AND expires_at = 3`, 1)
		check("transfer a2", `SELECT count(*) FROM transfers WHERE id = 'trf_a2' AND invitation_id = 'inv_a' AND sender_kind = 'external'`, 1)
		check("transfer a3", `SELECT count(*) FROM transfers WHERE id = 'trf_a3' AND api_token_id = 'tok_a' AND ended_at = 4 AND idempotency_key = 'k1'`, 1)
		check("files", `SELECT count(*) FROM transfer_files WHERE path = '' AND
			((id = 'fil_a1' AND scan_status = 'clean' AND scanned_at = 2 AND dek_key_id = 'key_f1' AND ciphertext_size = 50)
			OR (id = 'fil_a2' AND scan_status = 'not_scanned_too_large' AND scan_attempts = 1)
			OR (id = 'fil_b1' AND scan_status = 'pending' AND uploaded_at IS NULL))`, 3)
		check("admin TOTP secret", `SELECT count(*) FROM admins WHERE id = 'adm_1' AND totp_secret_id = 'sec_1'`, 1)
		check("sessions", `SELECT count(*) FROM deposit_sessions WHERE reply_to_transfer_id IS NULL AND recipient_link_id IS NULL
			AND ((id = 'dps_a1' AND kind = 'internal') OR (id = 'dps_a2' AND kind = 'external' AND invitation_id = 'inv_a' AND ended_at = 2))`, 2)
		check("template", `SELECT count(*) FROM tenant_email_templates WHERE subject = 'Invitation' AND updated_by = 'root'`, 1)
		// Backfills and defaults.
		check("shared links", `SELECT count(*) FROM transfers WHERE link_mode = 'shared' AND extension_count = 0
			AND max_downloads IS NULL AND confidentiality_level IS NULL AND rule_expiry_days_mask IS NULL
			AND expiry_reminder_at IS NULL AND reply_to_transfer_id IS NULL`, 4)
		check("challenges", `SELECT count(*) FROM verification_challenges WHERE purpose = 'deposit'
			AND recipient_link_id IS NULL AND recipient_intent IS NULL`, 2)
		check("tenant flags", `SELECT count(*) FROM tenants WHERE antivirus_enabled AND NOT allow_remote_internal_deposit
			AND NOT allow_transfer_reply AND NOT webhook_include_addresses`, 2)
		check("levels", `SELECT count(*) FROM confidentiality_levels`, 6)
		for _, tid := range []tenant.ID{a, b} {
			w := ` WHERE tenant_id = '` + string(tid) + `'`
			check("default level", `SELECT count(*) FROM confidentiality_levels`+w+` AND is_default AND key = 'internal'
				AND position = 1 AND NOT require_password AND allowed_validity_days = 7`, 1)
			check("public level", `SELECT count(*) FROM confidentiality_levels`+w+` AND key = 'public' AND position = 0
				AND NOT is_default AND NOT internal_recipients_only AND labels = '{"fr":"Public","en":"Public"}'`, 1)
			check("confidential level", `SELECT count(*) FROM confidentiality_levels`+w+` AND key = 'confidential'
				AND position = 2 AND require_password AND require_recipient_verification AND internal_recipients_only
				AND allowed_validity_days = 3 AND NOT force_delete_after_download AND max_downloads_cap IS NULL`, 1)
			check("abuse settings", `SELECT count(*) FROM tenant_abuse_settings`+w+` AND max_invitations_per_inviter = 20
				AND max_daily_bytes_per_sender IS NULL AND unusual_volume_pct IS NULL AND office_start_minute IS NULL
				AND NOT block_on_exceed AND time_zone = 'UTC' AND office_weekdays = 31 AND updated_at = 0`, 1)
		}
		// V1 store code still creates shared transfers; a new row gets the
		// per-recipient default.
		if err := rawExecArgs(ctx, t, db, `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, created_at) VALUES ('trf_new', ?, 'uploading', 'x@a.example.com', 'internal_remote', 1, ?, 0, 1)`,
			string(a), false); err != nil {
			t.Fatalf("insert an internal_remote transfer: %v", err)
		}
		check("new default", `SELECT count(*) FROM transfers WHERE id = 'trf_new' AND link_mode = 'per_recipient'`, 1)

		v11Constraints(ctx, t, db, a)

		// The foreign keys of the children point to the rebuilt tables: a
		// deleted transfer still takes its recipients and files along, and
		// a system secret used by an admin cannot be deleted.
		if _, err := rawSystemExec(ctx, db, `DELETE FROM transfers WHERE id = 'trf_b1'`); err != nil {
			t.Fatalf("delete transfer: %v", err)
		}
		check("cascade recipients", `SELECT count(*) FROM transfer_recipients WHERE transfer_id = 'trf_b1'`, 0)
		check("cascade files", `SELECT count(*) FROM transfer_files WHERE transfer_id = 'trf_b1'`, 0)
		if _, err := rawSystemExec(ctx, db, `DELETE FROM system_secrets WHERE id = 'sec_1'`); err == nil {
			t.Error("a system secret referenced by an admin was deleted")
		}
		// The retired-key trigger of system_secrets survives the rebuild.
		if err := rawExecArgs(ctx, t, db, `INSERT INTO system_secrets (id, purpose, key_id, blob, created_at)
			VALUES ('sec_2', 'webhook', 'mk_0000000000000002', ?, 1)`, []byte("sealed")); err == nil {
			t.Error("a system secret sealed under a retired master key was accepted")
		}
	})
}

// v11Constraints checks a sample of the V1.1 checks and foreign keys on a
// migrated database holding seedV1 data in tenant a.
func v11Constraints(ctx context.Context, t *testing.T, db *DB, a tenant.ID) {
	t.Helper()
	tid := string(a)
	trf := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days, delete_after_first_download,
		total_bytes, created_at, finalized_at, expires_at, link_mode, download_token_hash, available_at, reply_to_transfer_id,
		max_downloads, extension_count, extended_at, confidentiality_level, confidentiality_label, rule_expiry_days_mask,
		rule_require_password, rule_require_recipient_verification, rule_internal_recipients_only,
		rule_force_delete_after_first_download, rule_max_downloads_cap) VALUES (?, ?, ?, 'x@a.example.com', ?, 1, ?, 0, 1, ?, ?,
		?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	type row struct {
		id, status, kind, mode string
		finalized, expires     any
		token                  any
		availableAt, replyTo   any
		maxDl                  any
		ext                    int
		extAt                  any
		level, label           any
		mask                   any
		flag                   any
		capDl                  any
	}
	ins := func(r row) error {
		return rawExecArgs(ctx, t, db, trf, r.id, tid, r.status, r.kind, false, r.finalized, r.expires, r.mode, r.token,
			r.availableAt, r.replyTo, r.maxDl, r.ext, r.extAt, r.level, r.label, r.mask, r.flag, r.flag, r.flag, r.flag, r.capDl)
	}
	accepted := map[string]row{
		"per-recipient available without token": {status: "available", kind: "internal", mode: "per_recipient", finalized: 1, expires: 2, availableAt: 2},
		"reply":                                 {status: "uploading", kind: "reply", mode: "per_recipient", replyTo: "trf_a1"},
		"level with rules":                      {status: "uploading", kind: "internal", mode: "per_recipient", level: "confidential", label: "{}", mask: 3, flag: true},
		"extension within 90 days":              {status: "scanning", kind: "internal", mode: "per_recipient", finalized: 1, expires: 7776000001, ext: 1, extAt: 5},
	}
	rejected := map[string]row{
		"unknown sender kind":                 {status: "uploading", kind: "robot", mode: "per_recipient"},
		"reply without source":                {status: "uploading", kind: "reply", mode: "per_recipient"},
		"source without reply":                {status: "uploading", kind: "internal", mode: "per_recipient", replyTo: "trf_a1"},
		"token on a per-recipient transfer":   {status: "uploading", kind: "internal", mode: "per_recipient", token: bytes.Repeat([]byte{9}, 32)},
		"shared available without token":      {status: "available", kind: "internal", mode: "shared", finalized: 1, expires: 2, availableAt: 2},
		"unknown link mode":                   {status: "uploading", kind: "internal", mode: "group"},
		"max downloads 0":                     {status: "uploading", kind: "internal", mode: "per_recipient", maxDl: 0},
		"max downloads 1001":                  {status: "uploading", kind: "internal", mode: "per_recipient", maxDl: 1001},
		"level without label":                 {status: "uploading", kind: "internal", mode: "per_recipient", level: "x", mask: 7, flag: true},
		"level without rules":                 {status: "uploading", kind: "internal", mode: "per_recipient", level: "x", label: "{}"},
		"rules without level":                 {status: "uploading", kind: "internal", mode: "per_recipient", mask: 7, flag: false},
		"download cap without level":          {status: "uploading", kind: "internal", mode: "per_recipient", capDl: 5},
		"extension without date":              {status: "scanning", kind: "internal", mode: "per_recipient", finalized: 1, expires: 2, ext: 1},
		"extension beyond 90 days":            {status: "scanning", kind: "internal", mode: "per_recipient", finalized: 1, expires: 7776000002, ext: 1, extAt: 5},
		"extension date without an extension": {status: "uploading", kind: "internal", mode: "per_recipient", extAt: 5},
	}
	n := 0
	for name, r := range accepted {
		n++
		r.id = "trf_ok" + string(rune('a'+n))
		if err := ins(r); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	for name, r := range rejected {
		n++
		r.id = "trf_ko" + string(rune('a'+n))
		if err := ins(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := rawExecArgs(ctx, t, db, `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
		delete_after_first_download, total_bytes, created_at, api_token_id, reply_to_transfer_id)
		VALUES ('trf_api', ?, 'uploading', 'x@a.example.com', 'reply', 1, ?, 0, 1, 'tok_a', 'trf_a1')`, tid, false); err == nil {
		t.Error("a reply created by an API token accepted")
	}
	// Deletion after the maximum number of downloads.
	if _, err := rawSystemExec(ctx, db, `UPDATE transfers SET max_downloads = 2, delete_after = 9 WHERE id = 'trf_a3'`); err == nil {
		t.Error("delete_after accepted below the maximum number of downloads")
	}
	if _, err := rawSystemExec(ctx, db, `UPDATE transfers SET max_downloads = 2, download_count = 2, delete_after = 9 WHERE id = 'trf_a3'`); err != nil {
		t.Errorf("delete_after at the maximum number of downloads: %v", err)
	}
	misc := map[string]struct {
		q    string
		args []any
		ok   bool
	}{
		"file scan disabled":          {`UPDATE transfer_files SET scan_status = 'not_scanned_disabled' WHERE id = 'fil_a1'`, nil, true},
		"file path":                   {`UPDATE transfer_files SET path = 'a/b' WHERE id = 'fil_a1'`, nil, true},
		"long file path":              {`UPDATE transfer_files SET path = ? WHERE id = 'fil_a1'`, []any{strings.Repeat("a", 1025)}, false},
		"remote session":              {`INSERT INTO deposit_sessions (id, tenant_id, token_hash, email, kind, created_at, expires_at) VALUES ('dps_r', ?, ?, 'a@a.example.com', 'internal_remote', 1, 2)`, []any{tid, bytes.Repeat([]byte{1}, 32)}, true},
		"reply session without link":  {`INSERT INTO deposit_sessions (id, tenant_id, token_hash, email, kind, reply_to_transfer_id, created_at, expires_at) VALUES ('dps_x', ?, ?, 'a@a.example.com', 'reply', 'trf_a1', 1, 2)`, []any{tid, bytes.Repeat([]byte{2}, 32)}, false},
		"recipient code without link": {`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining, client_ip, created_at, expires_at, purpose, recipient_intent) VALUES ('vch_x', ?, 'r0@example.org', ?, 2, '192.0.2.1', 1, 2, 'recipient', 'download')`, []any{tid, []byte{1}}, false},
		"deposit code with intent":    {`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining, client_ip, created_at, expires_at, recipient_intent) VALUES ('vch_y', ?, 'r0@example.org', ?, 2, '192.0.2.1', 1, 2, 'download')`, []any{tid, []byte{1}}, false},
		"unknown purpose":             {`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining, client_ip, created_at, expires_at, purpose) VALUES ('vch_z', ?, 'r0@example.org', ?, 2, '192.0.2.1', 1, 2, 'reply')`, []any{tid, []byte{1}}, false},
		"webhook secret":              {`INSERT INTO system_secrets (id, purpose, key_id, blob, created_at) VALUES ('sec_w', 'webhook', 'mk_0000000000000001', ?, 1)`, []any{[]byte("x")}, true},
		"unknown secret purpose":      {`INSERT INTO system_secrets (id, purpose, key_id, blob, created_at) VALUES ('sec_u', 'other', 'mk_0000000000000001', ?, 1)`, []any{[]byte("x")}, false},
		"second default level":        {`UPDATE confidentiality_levels SET is_default = ? WHERE tenant_id = ? AND key = 'public'`, []any{true, tid}, false},
		"V1.1 template":               {`INSERT INTO tenant_email_templates (tenant_id, template_key, language, subject, body_html, body_text, updated_at) VALUES (?, 'recipient-verification-code', 'en', 's', '', '', 1)`, []any{tid}, true},
	}
	for name, m := range misc {
		err := rawExecArgs(ctx, t, db, m.q, m.args...)
		if m.ok && err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
		if !m.ok && err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A recipient link follows its recipient, and its downloads follow it.
	if err := rawExecArgs(ctx, t, db, `INSERT INTO recipient_links (id, tenant_id, transfer_id, position, token_hash, created_at)
		VALUES ('rcl_1', ?, 'trf_a1', 1, ?, 1)`, tid, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatalf("insert recipient link: %v", err)
	}
	if err := rawExecArgs(ctx, t, db, `INSERT INTO recipient_downloads (tenant_id, recipient_link_id, item, first_at, last_at)
		VALUES (?, 'rcl_1', 'fil_a1', 1, 1)`, tid); err != nil {
		t.Fatalf("insert recipient download: %v", err)
	}
	if err := rawExecArgs(ctx, t, db, `INSERT INTO recipient_downloads (tenant_id, recipient_link_id, item, first_at, last_at)
		VALUES (?, 'rcl_1', 'xyz', 1, 1)`, tid); err == nil {
		t.Error("recipient download of an unknown item accepted")
	}
	if err := rawExecArgs(ctx, t, db, `INSERT INTO recipient_links (id, tenant_id, transfer_id, position, token_hash, created_at)
		VALUES ('rcl_2', ?, 'trf_a1', 5, ?, 1)`, tid, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Error("recipient link without recipient accepted")
	}
	if _, err := rawSystemExec(ctx, db, `DELETE FROM transfer_recipients WHERE transfer_id = 'trf_a1' AND position = 1`); err != nil {
		t.Fatalf("delete recipient: %v", err)
	}
	if n := rawInt(ctx, t, db, `SELECT count(*) FROM recipient_downloads`); n != 0 {
		t.Errorf("recipient downloads left after the recipient: %d", n)
	}
}

// checkSQLiteIntegrity runs the SQLite integrity and foreign key checks
// and verifies that the writer connection enforces foreign keys again and
// has no legacy ALTER TABLE behavior.
func checkSQLiteIntegrity(ctx context.Context, t *testing.T, db *DB) {
	t.Helper()
	var integrity string
	if err := db.write.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Errorf("integrity_check = %q, %v", integrity, err)
	}
	if n := rawInt(ctx, t, db, `SELECT count(*) FROM pragma_foreign_key_check`); n != 0 {
		t.Errorf("%d foreign key violations", n)
	}
	assertSQLiteConnState(ctx, t, db)
	// Every index of the rebuilt tables is back.
	rows, err := db.write.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL
		AND tbl_name IN ('transfers', 'transfer_files', 'deposit_sessions', 'system_secrets', 'verification_challenges')`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	_ = rows.Close()
	want := []string{
		"deposit_sessions_email_idx", "deposit_sessions_expires_idx", "deposit_sessions_reply_idx", "deposit_sessions_tenant_id_idx",
		"system_secrets_key_id_idx", "transfer_files_tenant_id_idx",
		"transfers_delete_after_idx", "transfers_download_token_global_idx", "transfers_download_token_idx",
		"transfers_download_token_key_idx", "transfers_ended_idx", "transfers_expiry_idx", "transfers_idempotency_idx",
		"transfers_invitation_idx", "transfers_rejected_idx", "transfers_reminder_idx", "transfers_scanning_idx",
		"transfers_sender_created_idx", "transfers_sender_status_idx", "transfers_status_idx", "transfers_tenant_created_idx",
		"transfers_token_idempotency_idx", "transfers_token_status_idx", "transfers_uploading_idx",
		"verification_challenges_created_idx", "verification_challenges_email_idx", "verification_challenges_ip_idx",
		"verification_challenges_link_idx",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("indexes of the rebuilt tables:\n got  %v\n want %v", got, want)
	}
	if n := rawInt(ctx, t, db, `SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'system_secrets'`); n != 2 {
		t.Errorf("system_secrets has %d triggers, want 2", n)
	}
}

// assertSQLiteConnState checks that the SQLite writer connection enforces
// foreign keys and uses the modern ALTER TABLE behavior.
func assertSQLiteConnState(ctx context.Context, t *testing.T, db *DB) {
	t.Helper()
	var fk, legacy int
	if err := db.write.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("writer connection foreign_keys = %d, %v; want 1", fk, err)
	}
	if err := db.write.QueryRowContext(ctx, `PRAGMA legacy_alter_table`).Scan(&legacy); err != nil || legacy != 0 {
		t.Errorf("writer connection legacy_alter_table = %d, %v; want 0", legacy, err)
	}
}

// mapsEqualInt compares two integer maps.
func mapsEqualInt(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// openFaultEmpty opens an unmigrated SQLite database through the fault
// driver, with the migrations of fsys.
func openFaultEmpty(ctx context.Context, t *testing.T, fsys fstest.MapFS) (*DB, *faultPlan) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fault.db")
	plan := &faultPlan{}
	faultPlans.Store(path, plan)
	t.Cleanup(func() { faultPlans.Delete(path) })
	db, err := openSQLite(ctx, faultDriverName, path, nil)
	if err != nil {
		t.Fatalf("openSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if fsys != nil {
		db.migrationsFS = fsys
	}
	return db, plan
}

// TestMigrationV11FailureKeepsData makes the recording of 0014 fail after
// its body ran (sqlite-fault driver): the whole migration rolls back, the
// V1 data is intact, and the writer connection enforces foreign keys again.
// The retry then applies 0014 to 0020.
func TestMigrationV11FailureKeepsData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFaultEmpty(ctx, t, migrationsUpTo(t, 13).(fstest.MapFS))
	if n, err := db.Migrate(ctx); err != nil || n != 13 {
		t.Fatalf("Migrate to 0013 = %d, %v", n, err)
	}
	a := createLegacyTenant(ctx, t, db, "a.example.com", 100)
	b := createLegacyTenant(ctx, t, db, "b.example.com", 100)
	seedV1(ctx, t, db, a, b)
	before := rowCounts(ctx, t, db)

	db.migrationsFS = migrationFiles
	plan.add(faultExec, "INSERT INTO schema_migrations", 0)
	if n, err := db.Migrate(ctx); !errors.Is(err, errInjected) || n != 0 {
		t.Fatalf("Migrate with a failing record = %d, %v", n, err)
	}
	plan.reset()
	assertSQLiteConnState(ctx, t, db)
	if after := rowCounts(ctx, t, db); !mapsEqualInt(before, after) {
		t.Fatalf("row counts changed by a failed migration:\nbefore %v\nafter  %v", before, after)
	}
	if n := rawInt(ctx, t, db, `SELECT count(*) FROM pragma_table_info('transfers') WHERE name = 'link_mode'`); n != 0 {
		t.Error("the failed 0014 left its columns behind")
	}
	if n, err := db.Migrate(ctx); err != nil || n != 7 {
		t.Fatalf("retry = %d, %v", n, err)
	}
	if after := rowCounts(ctx, t, db); !mapsEqualInt(before, after) {
		t.Fatalf("row counts changed by the retry:\nbefore %v\nafter  %v", before, after)
	}
	assertSQLiteConnState(ctx, t, db)
}

// fkMigrations is a minimal migration set: a parent and a child table.
func fkMigrations(extra ...string) fstest.MapFS {
	fsys := fstest.MapFS{
		"migrations/sqlite/0001_init.sql": {Data: []byte(`CREATE TABLE p (id TEXT NOT NULL PRIMARY KEY) STRICT;
CREATE TABLE c (id TEXT NOT NULL PRIMARY KEY, pid TEXT REFERENCES p (id) ON DELETE CASCADE) STRICT;
INSERT INTO p VALUES ('p1');
INSERT INTO c VALUES ('c1', 'p1');`)},
	}
	for i, body := range extra {
		fsys["migrations/sqlite/000"+string(rune('2'+i))+"_step.sql"] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

// TestMigrationForeignKeysSQLite covers the SQLite migration connection:
// foreign keys are off during a migration (a referenced table can be
// rebuilt without cascading), a migration leaving a violation behind is
// refused, and every failure leaves the writer connection enforcing
// foreign keys.
func TestMigrationForeignKeysSQLite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rebuild := `CREATE TABLE p_0002 (id TEXT NOT NULL PRIMARY KEY, v INTEGER NOT NULL DEFAULT 1) STRICT;
INSERT INTO p_0002 (id) SELECT id FROM p;
DROP TABLE p;
ALTER TABLE p_0002 RENAME TO p;`

	t.Run("rebuild of a referenced table", func(t *testing.T) {
		t.Parallel()
		db, _ := openFaultEmpty(ctx, t, fkMigrations(rebuild))
		if n, err := db.Migrate(ctx); err != nil || n != 2 {
			t.Fatalf("Migrate = %d, %v", n, err)
		}
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM c`); n != 1 {
			t.Errorf("child rows after the rebuild = %d, want 1", n)
		}
		if _, err := rawSystemExec(ctx, db, `DELETE FROM p`); err != nil {
			t.Fatal(err)
		}
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM c`); n != 0 {
			t.Errorf("the child does not reference the rebuilt table: %d rows left", n)
		}
		assertSQLiteConnState(ctx, t, db)
	})

	t.Run("violation", func(t *testing.T) {
		t.Parallel()
		db, _ := openFaultEmpty(ctx, t, fkMigrations(`INSERT INTO c VALUES ('c2', 'nobody');`))
		if n, err := db.Migrate(ctx); !errors.Is(err, errForeignKeys) || n != 1 {
			t.Fatalf("Migrate = %d, %v; want errForeignKeys after 1", n, err)
		}
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM c`); n != 1 {
			t.Errorf("the refused migration was committed: %d child rows", n)
		}
		assertSQLiteConnState(ctx, t, db)
	})

	t.Run("enforced connection", func(t *testing.T) {
		t.Parallel()
		db, _ := openFaultEmpty(ctx, t, fkMigrations())
		d := *db.dialect
		d.migrationFKOff = `PRAGMA foreign_keys = ON`
		db.dialect = &d
		if _, err := db.Migrate(ctx); !errors.Is(err, errForeignKeys) {
			t.Fatalf("Migrate on an enforcing connection = %v; want errForeignKeys", err)
		}
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM sqlite_master WHERE name = 'p'`); n != 0 {
			t.Error("a migration ran with foreign keys enforced")
		}
	})

	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		db, _ := openFaultEmpty(ctx, t, fkMigrations())
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := db.Migrate(cctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Migrate(canceled) = %v", err)
		}
	})

	faults := map[string]struct {
		op, match string
		applied   bool // the migration is committed despite the error
	}{
		"disable":     {faultExec, "PRAGMA foreign_keys = OFF", false},
		"disable ran": {faultExecRan, "PRAGMA foreign_keys = OFF", false},
		"begin":       {faultBegin, "", false},
		"state":       {faultQuery, "PRAGMA foreign_keys", false},
		"check":       {faultQuery, "pragma_foreign_key_check", false},
		"commit":      {faultCommit, "", false},
		"restore":     {faultExec, "PRAGMA foreign_keys = ON", true},
		"state value": {faultScanNil, "PRAGMA foreign_keys", false},
	}
	// Enforcement turned off by a statement reporting an error, and not
	// restored either: the connection is discarded, never pooled.
	t.Run("disable ran, restore fails", func(t *testing.T) {
		t.Parallel()
		db, plan := openFaultEmpty(ctx, t, fkMigrations())
		plan.add(faultExecRan, "PRAGMA foreign_keys = OFF", 0)
		plan.add(faultExec, "PRAGMA foreign_keys = ON", 0)
		if _, err := db.Migrate(ctx); !errors.Is(err, errInjected) {
			t.Fatalf("Migrate = %v; want the injected fault", err)
		}
		plan.reset()
		assertSQLiteConnState(ctx, t, db)
		if n, err := db.Migrate(ctx); err != nil || n != 1 {
			t.Errorf("retry = %d, %v", n, err)
		}
	})

	for name, f := range faults {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db, plan := openFaultEmpty(ctx, t, fkMigrations())
			plan.add(f.op, f.match, 0)
			if _, err := db.Migrate(ctx); err == nil {
				t.Fatal("Migrate succeeded despite the fault")
			}
			plan.reset()
			assertSQLiteConnState(ctx, t, db)
			if got := rawInt(ctx, t, db, `SELECT count(*) FROM sqlite_master WHERE name = 'p'`); (got == 1) != f.applied {
				t.Errorf("migration applied = %v, want %v", got == 1, f.applied)
			}
			if n, err := db.Migrate(ctx); err != nil || (n == 1) == f.applied {
				t.Errorf("retry = %d, %v", n, err)
			}
		})
	}
}

// TestLiveIndexesMatch checks that both engines end up with the same named
// indexes (those declared by CREATE INDEX, not the ones backing a primary
// key or a unique constraint), so that a SQLite table rebuild cannot lose
// one silently.
func TestLiveIndexesMatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sets := map[string][]string{}
	for _, e := range storetest.Engines(t) {
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("%s: Migrate: %v", e.Name, err)
		}
		q := `SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL`
		if e.Driver == "postgres" {
			q = `SELECT i.indexname::text FROM pg_indexes i WHERE i.schemaname = current_schema()
				AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conname = i.indexname
				AND c.connamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema()))`
		}
		err := db.runTx(ctx, db.read, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, q)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var n string
				if err := rows.Scan(&n); err != nil {
					return err
				}
				sets[e.Name] = append(sets[e.Name], n)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		slices.Sort(sets[e.Name])
		if len(sets[e.Name]) < 70 {
			t.Errorf("%s: found only %d indexes", e.Name, len(sets[e.Name]))
		}
	}
	if pg, ok := sets["postgres"]; ok && !slices.Equal(pg, sets["sqlite"]) {
		t.Errorf("indexes differ:\nsqlite   %v\npostgres %v", sets["sqlite"], pg)
	}
}
