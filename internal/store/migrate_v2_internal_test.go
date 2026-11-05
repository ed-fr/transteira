package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestV2SchemaConstraints checks the guarantees the V2 migrations (0026 to
// 0029) enforce by themselves, on both engines: defaults reproducing 1.2,
// the instance-wide uniqueness of SSO domains, the session auth method,
// coalesced security events, a single active proof signing key, immutable
// proofs, and the drop link, link-only and end-to-end transfer invariants.
func TestV2SchemaConstraints(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		a := string(newTestTenant(ctx, t, db, "a.example.com"))
		b := string(newTestTenant(ctx, t, db, "b.example.com"))

		// Defaults: nothing new is allowed.
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM tenants WHERE NOT link_only_allowed AND e2e_policy = 'forbidden'`); n != 2 {
			t.Errorf("tenants with 1.2 defaults = %d, want 2", n)
		}
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM confidentiality_levels WHERE NOT link_only_allowed OR e2e_policy IS NOT NULL`); n != 0 {
			t.Errorf("levels without 1.2 defaults = %d, want 0", n)
		}

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

		// SSO: one tenant per domain, lower case only.
		for _, tn := range []string{a, b} {
			mustExec(`INSERT INTO tenant_sso_settings (tenant_id, issuer, client_id, created_at, updated_at)
				VALUES (?, 'https://login.example.com/x/v2.0', 'client', 1, 1)`, tn)
		}
		mustExec(`INSERT INTO sso_email_domains (domain, tenant_id) VALUES ('a.example.com', ?)`, a)
		rejected("domain routed twice", `INSERT INTO sso_email_domains (domain, tenant_id) VALUES ('a.example.com', ?)`, b)
		rejected("upper case domain", `INSERT INTO sso_email_domains (domain, tenant_id) VALUES ('B.example.com', ?)`, b)
		rejected("http issuer", `UPDATE tenant_sso_settings SET issuer = 'http://login.example.com/x' WHERE tenant_id = ?`, a)

		// Sessions: an SSO session names its issuer, client ID and MFA flag
		// (all three, for oidc only) and is authenticated.
		mustExec(`INSERT INTO admins (id, username, email, role, require_totp, totp_enabled, created_at, updated_at)
			VALUES ('adm_1', 'u', 'u@a.example.com', 'auditor', true, false, 0, 0)`)
		session := `INSERT INTO admin_sessions (id, token_hash, admin_id, state, created_at, last_seen_at, expires_at,
			state_expires_at, auth_method, sso_issuer, sso_client_id, sso_mfa) VALUES (?, ?, 'adm_1', ?, 0, 0, 10, ?, ?, ?, ?, ?)`
		iss := "https://login.example.com/x/v2.0"
		tok := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
		mustExec(session, "ses_1", tok(1), "authenticated", nil, "oidc", iss, "client", true)
		mustExec(session, "ses_2", tok(2), "totp_required", 5, "password", nil, nil, nil)
		mustExec(session, "ses_6", tok(6), "authenticated", nil, "oidc", iss, "client", false)
		rejected("oidc without issuer", session, "ses_3", tok(3), "authenticated", nil, "oidc", nil, "client", true)
		rejected("oidc without client ID", session, "ses_7", tok(7), "authenticated", nil, "oidc", iss, nil, true)
		rejected("oidc without MFA flag", session, "ses_8", tok(8), "authenticated", nil, "oidc", iss, "client", nil)
		rejected("password with issuer", session, "ses_4", tok(4), "authenticated", nil, "password", iss, nil, nil)
		rejected("password with client ID", session, "ses_9", tok(9), "authenticated", nil, "password", nil, "client", nil)
		rejected("password with MFA flag", session, "ses_10", tok(10), "authenticated", nil, "password", nil, nil, false)
		rejected("oidc before TOTP", session, "ses_5", tok(5), "totp_required", 5, "oidc", iss, "client", true)

		// Identities: keyed by (issuer, client ID, subject), one per
		// (account, issuer, client ID).
		identity := `INSERT INTO admin_identities (id, admin_id, issuer, client_id, subject, created_at) VALUES (?, ?, 'https://i.example.com', ?, ?, 0)`
		mustExec(`INSERT INTO admins (id, username, email, role, require_totp, totp_enabled, created_at, updated_at)
			VALUES ('adm_2', 'v', 'v@a.example.com', 'auditor', true, false, 0, 0)`)
		mustExec(identity, "aid_1", "adm_1", "app1", "s1")
		mustExec(identity, "aid_3", "adm_1", "app2", "s3")
		mustExec(identity, "aid_4", "adm_2", "app2", "s1")
		rejected("second identity per application", identity, "aid_2", "adm_1", "app1", "s2")
		rejected("subject pinned twice", identity, "aid_5", "adm_2", "app1", "s1")

		// SSO-only accounts: no local password, never a super admin.
		ssoOnly := `INSERT INTO admins (id, username, email, role, password_hash, require_totp, totp_enabled, sso_only, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, false, ?, 0, 0)`
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM admins WHERE sso_only`); n != 0 {
			t.Errorf("sso_only accounts by default = %d, want 0", n)
		}
		mustExec(ssoOnly, "adm_3", "w", "w@a.example.com", "auditor", nil, true, true)
		mustExec(ssoOnly, "adm_4", "x", "x@a.example.com", "delegated_admin", "$argon2id$x", true, false)
		rejected("sso_only with a password", ssoOnly, "adm_5", "y", "y@a.example.com", "auditor", "$argon2id$x", true, true)
		rejected("sso_only super admin", ssoOnly, "adm_6", "z", "z@a.example.com", "super_admin", nil, true, true)
		rejected("password on an sso_only account", `UPDATE admins SET password_hash = 'h' WHERE id = 'adm_3'`)
		rejected("sso_only on an account with a password", `UPDATE admins SET sso_only = true WHERE id = 'adm_4'`)

		// Security events: coalesced counters.
		event := `INSERT INTO security_events (id, at, tenant_id, event_type, occurrences, last_seen_at) VALUES (?, 10, ?, 'sso_failed', ?, ?)`
		mustExec(event, "sev_1", a, 3, 20)
		rejected("zero occurrences", event, "sev_2", a, 0, 20)
		rejected("last seen before first", event, "sev_3", nil, 1, 5)

		// Proof keys: one active key, which keeps its private key.
		mustExec(`INSERT INTO system_secrets (id, purpose, key_id, blob, created_at) VALUES ('sec_1', 'proof-signing', 'mk_0', ?, 0)`, []byte{1})
		key := `INSERT INTO proof_signing_keys (id, public_key, private_key_secret_id, created_at, retired_at) VALUES (?, ?, ?, 0, ?)`
		mustExec(key, "psk_1", bytes.Repeat([]byte{1}, 32), "sec_1", nil)
		rejected("second active key", key, "psk_2", bytes.Repeat([]byte{2}, 32), nil, nil)
		mustExec(key, "psk_3", bytes.Repeat([]byte{3}, 32), nil, 1)
		rejected("erasing the active private key", `DELETE FROM system_secrets WHERE id = 'sec_1'`)

		// Proofs: one row per fact, never updated.
		proof := `INSERT INTO transfer_proofs (id, tenant_id, transfer_id, kind, recipient_link_id, statement, signature, key_id, created_at, expires_at)
			VALUES (?, ?, 'trf_1', ?, ?, '{}', ?, 'psk_1', 1, 2)`
		sig := bytes.Repeat([]byte{9}, 64)
		mustExec(proof, "prf_1", a, "delivery", nil, sig)
		mustExec(proof, "prf_2", a, "delivery", "rcl_1", sig)
		rejected("second overall delivery", proof, "prf_3", a, "delivery", nil, sig)
		rejected("deposit for a recipient", proof, "prf_4", a, "deposit", "rcl_2", sig)
		rejected("proof update", `UPDATE transfer_proofs SET expires_at = 3 WHERE id = 'prf_1'`)
		mustExec(`DELETE FROM transfer_proofs WHERE id = 'prf_1'`)

		// Drop links (recipients: a JSON array) and transfers.
		link := `INSERT INTO drop_links (id, tenant_id, token_hash, label, recipients, validity_days, created_by, created_at, updated_at)
			VALUES (?, ?, ?, 'Docs', ?, 7, 'adm_1', 0, 0)`
		mustExec(link, "drl_1", a, tok(7), `["x@a.example.com"]`)
		rejected("recipients not JSON", link, "drl_2", a, tok(8), `["x@a.example.com"`)
		rejected("recipients not an array", link, "drl_3", a, tok(9), `{"x":1}`)
		transfer := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, created_at, link_mode, link_only, e2e, drop_link_id, message, e2e_message)
			VALUES (?, ?, 'uploading', 's@example.org', ?, 7, false, 0, 0, ?, ?, ?, ?, ?, ?)`
		mustExec(transfer, "trf_1", a, "drop_link", "per_recipient", false, false, "drl_1", "", nil)
		mustExec(transfer, "trf_2", a, "internal", "shared", true, true, nil, "", "ZW5j")
		rejected("drop link of another tenant", transfer, "trf_3", b, "drop_link", "per_recipient", false, false, "drl_1", "", nil)
		rejected("drop link kind without link", transfer, "trf_4", a, "drop_link", "per_recipient", false, false, nil, "", nil)
		rejected("link-only per recipient", transfer, "trf_5", a, "internal", "per_recipient", true, false, nil, "", nil)
		rejected("encrypted message without e2e", transfer, "trf_6", a, "internal", "per_recipient", false, false, nil, "", "ZW5j")
		rejected("plaintext message with e2e", transfer, "trf_7", a, "internal", "per_recipient", false, true, nil, "hello", nil)
		rejected("e2e through a drop link", transfer, "trf_8", a, "drop_link", "per_recipient", false, true, "drl_1", "", nil)

		// Files: the E2E scan status needs the encrypted metadata.
		file := `INSERT INTO transfer_files (id, tenant_id, transfer_id, position, name, size, storage_name, upload_id,
			scan_status, scanned_at, e2e_metadata) VALUES (?, ?, 'trf_2', ?, 'file-1.tte2', 1, ?, ?, 'not_scanned_e2e', 1, ?)`
		mustExec(file, "fil_1", a, 0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "upl_1", "bWV0YQ")
		rejected("e2e status without metadata", file, "fil_2", a, 1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "upl_2", nil)

		// Deposit sessions bound to a drop link.
		dsession := `INSERT INTO deposit_sessions (id, tenant_id, token_hash, email, kind, created_at, expires_at, drop_link_id)
			VALUES (?, ?, ?, 'd@example.org', 'drop_link', 0, 1, ?)`
		mustExec(dsession, "dps_1", a, bytes.Repeat([]byte{1}, 32), "drl_1")
		rejected("drop link session without link", dsession, "dps_2", a, bytes.Repeat([]byte{2}, 32), nil)
	})
}

// TestMigration0030Upgrade applies 0030_network_review on a database at
// 0029: the existing tenants that have network rules count as reviewed (at
// their last modification), those without any rule stay unreviewed, so
// that no existing tenant sees its setup checklist change (T-307).
func TestMigration0030Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 29)
		if n, err := db.Migrate(ctx); err != nil || n != 29 {
			t.Fatalf("Migrate to 0029 = %d, %v", n, err)
		}
		// Tenants of the 0029 schema: with a range only, a domain only,
		// both, and no rule.
		tenants := map[string]int64{"ten_cidr": 11, "ten_domain": 12, "ten_both": 13, "ten_none": 14}
		for tid, updated := range tenants {
			if err := rawExecArgs(ctx, t, db, `INSERT INTO tenants (id, name, fqdn, default_language, max_transfer_bytes,
				storage_quota_bytes, setup_state, created_at, updated_at) VALUES (?, 'Legacy', ?, 'fr', 1, 1000, 'setup', 1, ?)`,
				tid, tid[len("ten_"):]+".example.com", updated); err != nil {
				t.Fatal(err)
			}
		}
		rules := [][3]string{
			{"ten_cidr", "cidr", "10.0.0.0/8"},
			{"ten_domain", "domain", "a.example.com"},
			{"ten_both", "cidr", "10.0.0.0/8"},
			{"ten_both", "domain", "a.example.com"},
		}
		for _, r := range rules {
			if err := rawExecArgs(ctx, t, db, `INSERT INTO tenant_network_rules (tenant_id, kind, value) VALUES (?, ?, ?)`,
				r[0], r[1], r[2]); err != nil {
				t.Fatal(err)
			}
		}

		db.migrationsFS = migrationFiles
		if n, err := db.Migrate(ctx); err != nil || n != 1 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		for tid, want := range map[string]int64{"ten_cidr": 11, "ten_domain": 12, "ten_both": 13} {
			if got := rawInt(ctx, t, db, `SELECT network_reviewed_at FROM tenants WHERE id = '`+tid+`'`); got != want {
				t.Errorf("%s: network_reviewed_at = %d, want %d", tid, got, want)
			}
		}
		if n := rawInt(ctx, t, db, `SELECT count(*) FROM tenants WHERE network_reviewed_at IS NULL`); n != 1 {
			t.Errorf("tenants without review = %d, want 1 (ten_none)", n)
		}
		if e.Driver == "sqlite" {
			checkSQLiteIntegrity(ctx, t, db)
		}
	})
}
