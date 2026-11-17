package store

import (
	"bytes"
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// v23Secret is a raw secrets row of the V2.3 schema tests, an anonymous
// express secret unless changed.
type v23Secret struct {
	id, state, kind, delivery, duration string
	sender, apiTok, recipient           any
	receipt, express                    bool
	salt, iterations                    any
	created, activated, expires         any
	fileSize, metadata, storage         any
	uploaded, fileKey                   any
}

// insertV23Secret is the raw insert of a v23Secret (verifiers, sealed text
// and text key given by the caller).
const insertV23Secret = `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email, api_token_id,
	delivery, recipient_email, read_receipt, verifier, key_verifier, kdf_salt, kdf_iterations, text_sealed, text_key_id,
	duration_code, created_at, activated_at, expires_at, file_size, file_metadata, file_storage_name, file_uploaded_at,
	file_key_id, express) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// anonymousRow returns the row of a live anonymous express secret.
func anonymousRow(secID string) v23Secret {
	return v23Secret{
		id: secID, state: "active", kind: "anonymous", delivery: "link", duration: "1d", express: true,
		created: 10, activated: 10, expires: 20,
	}
}

// TestV23SchemaConstraints checks the guarantees the V2.3 migration
// (0036_express_secrets) enforces by itself, on both engines: the tenant
// and token defaults and bounds, the express profile of the secrets, the
// targets of the abuse reports, and that both SQLite rebuilds kept every
// index and foreign key (on PostgreSQL: the constraint names and the
// row-level security of the altered tables).
func TestV23SchemaConstraints(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		a := string(newTestTenant(ctx, t, db, "a.example.com"))
		newTestTenant(ctx, t, db, "b.example.com")
		exec := func(q string, args ...any) error { return rawExecArgs(ctx, t, db, q, args...) }
		mustExec := func(q string, args ...any) {
			t.Helper()
			if err := exec(q, args...); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		rejected := func(name, q string, args ...any) {
			t.Helper()
			if err := exec(q, args...); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		count := func(q string) int64 {
			t.Helper()
			return rawInt(ctx, t, db, q)
		}

		// Tenant settings: anonymous mode off, 10, 100 and 1 000.
		if n := count(`SELECT count(*) FROM tenants WHERE NOT express_enabled AND express_per_hour_ip = 10
			AND express_per_hour_token = 100 AND express_max_pending = 1000`); n != 2 {
			t.Errorf("tenants with the 2.3 defaults = %d, want 2", n)
		}
		for col, bounds := range map[string][2]int{
			"express_per_hour_ip": {1, 1000}, "express_per_hour_token": {1, 10000}, "express_max_pending": {1, 100000},
		} {
			q := `UPDATE tenants SET ` + col + ` = ? WHERE id = ?`
			mustExec(q, bounds[0], a)
			mustExec(q, bounds[1], a)
			rejected(col+" below its minimum", q, bounds[0]-1, a)
			rejected(col+" above its maximum", q, bounds[1]+1, a)
		}
		mustExec(`UPDATE tenants SET express_enabled = ? WHERE id = ?`, true, a)

		tok := func(c byte) []byte { return bytes.Repeat([]byte{c}, 32) }
		mustExec(`INSERT INTO master_keys (id, status, created_at) VALUES ('mk_0000000000000001', 'active', 1)`)
		wkey := `INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES (?, ?, 'dek', 'mk_0000000000000001', ?, 1)`
		for i := range 20 {
			mustExec(wkey, "key_"+string(rune('a'+i)), a, []byte("sealed"))
		}
		mustExec(`INSERT INTO api_tokens (id, tenant_id, name, prefix, token_hash, allowed_cidrs, created_by, created_at)
			VALUES ('tok_a', ?, 'ci', 'tt_Ab', ?, '[]', 'root', 1)`, a, tok(90))
		if n := count(`SELECT count(*) FROM api_tokens WHERE NOT express_allowed`); n != 1 {
			t.Errorf("tokens without the express opt-in = %d, want 1", n)
		}
		mustExec(`UPDATE api_tokens SET express_allowed = ? WHERE id = 'tok_a'`, true)

		next := byte(0)
		insert := func(r v23Secret) error {
			next++
			return exec(insertV23Secret, r.id, a, tok(next), r.state, r.kind, r.sender, r.apiTok, r.delivery, r.recipient,
				r.receipt, tok(1), tok(2), r.salt, r.iterations, []byte("sealed text"), "key_"+string(rune('a'+next-1)),
				r.duration, r.created, r.activated, r.expires, r.fileSize, r.metadata, r.storage, r.uploaded, r.fileKey,
				r.express)
		}
		if err := insert(anonymousRow("sec_1")); err != nil {
			t.Fatalf("anonymous express secret refused: %v", err)
		}
		byTok := anonymousRow("sec_2")
		byTok.kind, byTok.apiTok = "api_token", "tok_a"
		if err := insert(byTok); err != nil {
			t.Fatalf("token express secret refused: %v", err)
		}
		v21 := anonymousRow("sec_3")
		v21.kind, v21.sender, v21.express, v21.duration = "internal", "alice@a.example.com", false, "12h"
		if err := insert(v21); err != nil {
			t.Fatalf("2.1 secret refused: %v", err)
		}
		for name, mod := range map[string]func(*v23Secret){
			"anonymous 2.1 secret":         func(r *v23Secret) { r.express, r.sender = false, "x@example.org" },
			"2.1 secret without address":   func(r *v23Secret) { r.express, r.kind = false, "internal" },
			"express secret with address":  func(r *v23Secret) { r.sender = "x@example.org" },
			"express secret of a session":  func(r *v23Secret) { r.kind = "internal" },
			"express secret by e-mail":     func(r *v23Secret) { r.delivery, r.recipient = "email", "x@example.org" },
			"express secret with receipt":  func(r *v23Secret) { r.receipt = true },
			"express secret with a phrase": func(r *v23Secret) { r.salt, r.iterations = bytes.Repeat([]byte{7}, 16), 600000 },
			"express secret with a file": func(r *v23Secret) {
				r.fileSize, r.metadata, r.storage, r.uploaded, r.fileKey = 100, "bWV0YQ", strings.Repeat("ab", 16), 5, "key_t"
			},
			"express secret of 12 hours":    func(r *v23Secret) { r.duration = "12h" },
			"express secret of 30 days":     func(r *v23Secret) { r.duration = "30d" },
			"pending express secret":        func(r *v23Secret) { r.state, r.activated, r.expires = "pending", nil, nil },
			"express secret activated late": func(r *v23Secret) { r.activated = 11 },
			"unknown creator kind":          func(r *v23Secret) { r.kind = "drop_link" },
		} {
			r := anonymousRow("sec_x")
			mod(&r)
			if err := insert(r); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		// Tombstones keep the profile: the read and the expiry clear the
		// content, the activation stays.
		mustExec(`UPDATE secrets SET state = 'read', read_at = 15, ended_at = 15, end_reason = 'read', verifier = NULL,
			key_verifier = NULL, text_sealed = NULL, text_key_id = NULL WHERE id = 'sec_1'`)
		rejected("express tombstone losing its activation", `UPDATE secrets SET activated_at = NULL, expires_at = NULL
			WHERE id = 'sec_1'`)
		rejected("address given to an express tombstone", `UPDATE secrets SET sender_email = 'x@example.org' WHERE id = 'sec_1'`)

		// Abuse reports: one target; a report on a secret has no address,
		// no recipient link and no verified reporter.
		report := `INSERT INTO abuse_reports (id, tenant_id, transfer_id, recipient_link_id, sender_email, recipient_position,
			reporter_email, reporter_verified, reporter_ip, category, created_at, secret_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, '192.0.2.1', 'spam', 1, ?)`
		mustExec(report, "abr_1", a, nil, nil, nil, nil, nil, false, "sec_1")
		mustExec(report, "abr_2", a, "trf_1", nil, "alice@a.example.com", nil, nil, false, nil)
		rejected("report on two targets", report, "abr_3", a, "trf_1", nil, nil, nil, nil, false, "sec_1")
		rejected("report without target", report, "abr_3", a, nil, nil, nil, nil, nil, false, nil)
		rejected("secret report with an address", report, "abr_3", a, nil, nil, "x@example.org", nil, nil, false, "sec_1")
		rejected("transfer report without address", report, "abr_3", a, "trf_1", nil, nil, nil, nil, false, nil)
		rejected("secret report through a recipient link", report, "abr_3", a, nil, "rcl_1", nil, 0, nil, false, "sec_1")
		rejected("secret report of a verified reporter", report, "abr_3", a, nil, "rcl_1", nil, 0, "x@example.org", true, "sec_1")

		if e.Driver == "sqlite" {
			checkV23SQLiteRebuilds(ctx, t, db)
			return
		}
		checkV23PostgresSchema(ctx, t, db)
	})
}

// checkV23SQLiteRebuilds checks that the SQLite rebuilds of secrets and
// abuse_reports kept every index and foreign key, and the database its
// integrity.
func checkV23SQLiteRebuilds(ctx context.Context, t *testing.T, db *DB) {
	t.Helper()
	checkSQLiteIntegrity(ctx, t, db)
	strs := func(q string) []string {
		t.Helper()
		rows, err := db.write.QueryContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		slices.Sort(out)
		return out
	}
	indexes := strs(`SELECT name FROM pragma_index_list('secrets') WHERE origin = 'c'
		UNION ALL SELECT name FROM pragma_index_list('abuse_reports') WHERE origin = 'c'`)
	want := []string{
		"abuse_reports_ip_rate_idx", "abuse_reports_link_rate_idx", "abuse_reports_list_idx", "abuse_reports_reporter_idx",
		"abuse_reports_secret_rate_idx", "abuse_reports_sender_idx", "abuse_reports_shared_rate_idx",
		"secrets_ended_idx", "secrets_expiry_idx", "secrets_express_live_idx", "secrets_file_storage_idx", "secrets_grant_idx",
		"secrets_invitation_idx", "secrets_pending_idx", "secrets_recipient_idx", "secrets_sender_created_idx",
		"secrets_tenant_created_idx", "secrets_token_created_idx",
	}
	if !slices.Equal(indexes, want) {
		t.Errorf("indexes of the rebuilt tables:\n got  %v\n want %v", indexes, want)
	}
	// The UNIQUE constraints: token_hash, text_key_id, file_key_id and
	// (tenant_id, id) on secrets, (tenant_id, id) on abuse_reports.
	if n := len(strs(`SELECT name FROM pragma_index_list('secrets') WHERE origin = 'u'`)); n != 4 {
		t.Errorf("secrets has %d unique constraints, want 4", n)
	}
	if n := len(strs(`SELECT name FROM pragma_index_list('abuse_reports') WHERE origin = 'u'`)); n != 1 {
		t.Errorf("abuse_reports has %d unique constraints, want 1", n)
	}
	fks := strs(`SELECT "table" || ':' || "from" || ':' || coalesce(on_delete, '') FROM pragma_foreign_key_list('secrets')
		UNION ALL SELECT 'abuse_reports>' || "table" || ':' || "from" || ':' || on_delete FROM pragma_foreign_key_list('abuse_reports')`)
	wantFKs := []string{
		"abuse_reports>tenants:tenant_id:CASCADE",
		"api_tokens:api_token_id:NO ACTION", "api_tokens:tenant_id:NO ACTION",
		"invitations:invitation_id:NO ACTION", "invitations:tenant_id:NO ACTION",
		"tenants:tenant_id:CASCADE", "wrapped_keys:file_key_id:SET NULL", "wrapped_keys:text_key_id:SET NULL",
	}
	if !slices.Equal(fks, wantFKs) {
		t.Errorf("foreign keys of the rebuilt tables:\n got  %v\n want %v", fks, wantFKs)
	}
	// express is the last column of secrets, secret_id of abuse_reports.
	for table, last := range map[string]string{"secrets": "express", "abuse_reports": "secret_id"} {
		cols := strs(`SELECT name FROM pragma_table_info('` + table + `') WHERE cid = (SELECT max(cid) FROM pragma_table_info('` + table + `'))`)
		if !slices.Equal(cols, []string{last}) {
			t.Errorf("last column of %s = %v, want %s", table, cols, last)
		}
	}
}

// checkV23PostgresSchema checks the constraint names of migration 0036 and
// the row-level security of the altered tables (PostgreSQL).
func checkV23PostgresSchema(ctx context.Context, t *testing.T, db *DB) {
	t.Helper()
	var names []string
	err := db.runTx(ctx, db.read, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT conname::text FROM pg_constraint
			WHERE connamespace = current_schema()::regnamespace AND contype = 'c'`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			names = append(names, n)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"secrets_creator_kind_check", "secrets_sender_email_check", "secrets_express_sender_check",
		"secrets_anonymous_check", "secrets_express_kind_check", "secrets_express_profile_check",
		"secrets_express_duration_check", "secrets_express_active_check",
		"tenants_express_per_hour_ip_check", "tenants_express_per_hour_token_check", "tenants_express_max_pending_check",
		"abuse_reports_target_check", "abuse_reports_sender_check", "abuse_reports_secret_check",
	} {
		if !slices.Contains(names, want) {
			t.Errorf("constraint %s missing", want)
		}
	}
	if n := rawInt(ctx, t, db, `SELECT count(*) FROM pg_class WHERE relnamespace = current_schema()::regnamespace
		AND relname IN ('secrets', 'abuse_reports', 'api_tokens') AND relrowsecurity AND relforcerowsecurity`); n != 3 {
		t.Errorf("%d of the altered tenant tables keep a forced row-level security, want 3", n)
	}
}

// TestMigration0036Upgrade applies 0036_express_secrets on a database at
// 0035 holding tenants, an API token, secrets of every origin and abuse
// reports: every row is kept unchanged (none becomes express), the new
// columns take their defaults, and the store reads the rows back.
func TestMigration0036Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 35)
		if n, err := db.Migrate(ctx); err != nil || n != 35 {
			t.Fatalf("Migrate to 0035 = %d, %v", n, err)
		}
		exec := func(q string, args ...any) {
			t.Helper()
			if err := rawExecArgs(ctx, t, db, q, args...); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		tok := func(c byte) []byte { return bytes.Repeat([]byte{c}, 32) }
		ta, tb := id.New(id.Tenant), id.New(id.Tenant)
		for i, tid := range []string{ta, tb} {
			exec(`INSERT INTO tenants (id, name, fqdn, default_language, max_transfer_bytes, storage_quota_bytes,
				setup_state, created_at, updated_at) VALUES (?, 'Legacy', ?, 'fr', 1, 1000, 'active', 1, 1)`,
				tid, string(rune('a'+i))+".example.com")
		}
		exec(`INSERT INTO master_keys (id, status, created_at) VALUES ('mk_0000000000000001', 'active', 1)`)
		for _, k := range []string{"key_1", "key_2"} {
			exec(`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at)
				VALUES (?, ?, 'dek', 'mk_0000000000000001', ?, 1)`, k, ta, []byte("sealed"))
		}
		tokID := id.New(id.APIToken)
		exec(`INSERT INTO api_tokens (id, tenant_id, name, prefix, token_hash, allowed_cidrs, created_by, created_at)
			VALUES (?, ?, 'ci', 'tt_Ab', ?, '["0.0.0.0/0"]', 'root', 1)`, tokID, ta, tok(90))
		secret := `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email, api_token_id,
			delivery, verifier, key_verifier, text_sealed, text_key_id, duration_code, created_at, activated_at, expires_at,
			read_at, ended_at, end_reason) VALUES (?, ?, ?, ?, ?, 'alice@a.example.com', ?, 'link', ?, ?, ?, ?, '1d',
			1, 1, 99, ?, ?, ?)`
		live, byTok, read := id.New(id.Secret), id.New(id.Secret), id.New(id.Secret)
		exec(secret, live, ta, tok(1), "active", "internal", nil, tok(3), tok(4), []byte("sealed"), "key_1", nil, nil, nil)
		exec(secret, byTok, ta, tok(2), "active", "api_token", tokID, tok(3), tok(4), []byte("sealed"), "key_2", nil, nil, nil)
		exec(secret, read, ta, tok(5), "read", "internal", nil, nil, nil, nil, nil, 5, 5, "read")
		repID := id.New(id.AbuseReport)
		exec(`INSERT INTO abuse_reports (id, tenant_id, transfer_id, sender_email, reporter_ip, category, created_at)
			VALUES (?, ?, 'trf_1', 'alice@a.example.com', '192.0.2.1', 'spam', 1)`, repID, ta)
		counts := func() map[string]int64 {
			out := rowCounts(ctx, t, db)
			for _, tb := range []string{"secrets", "abuse_reports", "api_tokens", "wrapped_keys"} {
				out[tb] = rawInt(ctx, t, db, `SELECT count(*) FROM `+tb)
			}
			return out
		}
		before := counts()

		db.migrationsFS = migrationFiles
		if n, err := db.Migrate(ctx); err != nil || n != 1 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		if after := counts(); !mapsEqualInt(before, after) || after["secrets"] != 3 {
			t.Fatalf("row counts changed by 0036:\nbefore %v\nafter  %v", before, after)
		}
		if e.Driver == "sqlite" {
			checkV23SQLiteRebuilds(ctx, t, db)
		}
		check := func(what, q string, want int64) {
			t.Helper()
			if got := rawInt(ctx, t, db, q); got != want {
				t.Errorf("%s: %s = %d, want %d", what, q, got, want)
			}
		}
		check("tenant defaults", `SELECT count(*) FROM tenants WHERE NOT express_enabled AND express_per_hour_ip = 10
			AND express_per_hour_token = 100 AND express_max_pending = 1000`, 2)
		check("token opt-in", `SELECT count(*) FROM api_tokens WHERE NOT express_allowed`, 1)
		check("secrets kept", `SELECT count(*) FROM secrets WHERE NOT express AND sender_email = 'alice@a.example.com'`, 3)
		check("secret keys kept", `SELECT count(*) FROM secrets WHERE text_key_id IN ('key_1', 'key_2')`, 2)
		check("token of a secret kept", `SELECT count(*) FROM secrets WHERE api_token_id = '`+tokID+`'`, 1)
		check("report kept", `SELECT count(*) FROM abuse_reports WHERE transfer_id = 'trf_1'
			AND sender_email = 'alice@a.example.com' AND secret_id IS NULL`, 1)

		// The store reads the migrated rows.
		for secID, want := range map[string]SecretState{live: SecretActive, byTok: SecretActive, read: SecretRead} {
			s, err := db.Secrets(nil).Get(ctx, tenant.ID(ta), secID)
			if err != nil || s.State != want || s.Express || s.SenderEmail != "alice@a.example.com" {
				t.Errorf("Get(%s) = %+v, %v", secID, s, err)
			}
		}
		if r, err := db.AbuseReports().Get(ctx, tenant.ID(ta), repID); err != nil || r.TransferID != "trf_1" || r.SecretID != "" {
			t.Errorf("AbuseReports.Get = %+v, %v", r, err)
		}
		if tok, err := db.APITokens().Get(ctx, tenant.ID(ta), tokID); err != nil || tok.ExpressAllowed {
			t.Errorf("APITokens.Get = %+v, %v", tok, err)
		}
	})
}
