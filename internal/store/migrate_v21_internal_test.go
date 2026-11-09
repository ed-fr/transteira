package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestV21SchemaConstraints checks the guarantees the V2.1 migration
// (0033_secrets) enforces by itself, on both engines: the tenant settings
// defaults and bounds, and the one-time secret invariants (origin,
// delivery, passphrase parameters, no content outside pending and active,
// file and grant, lifecycle, tenant-bound foreign keys, key erasure).
func TestV21SchemaConstraints(t *testing.T) {
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

		// Tenant settings: the module is on by default, with three
		// durations, files of 10 MiB and e-mail delivery.
		if n := count(`SELECT count(*) FROM tenants WHERE secrets_enabled AND secret_durations = '1h,1d,7d'
			AND secret_default_duration IS NULL AND secret_file_allowed AND secret_file_max_bytes = 10485760
			AND secret_email_allowed`); n != 2 {
			t.Errorf("tenants with the 2.1 defaults = %d, want 2", n)
		}
		setting := `UPDATE tenants SET secret_durations = ?, secret_default_duration = ? WHERE id = ?`
		mustExec(setting, "1h,12h,1d,3d,7d,30d", "30d", a)
		mustExec(setting, "12h", nil, a)
		for name, d := range map[string]string{
			"empty list": "", "unknown code": "1h,2d", "duplicate code": "1h,1h", "trailing comma": "1h,",
			"leading comma": ",1h", "spaces": "1h, 1d", "upper case": "1H",
		} {
			rejected("durations "+name, setting, d, nil, a)
		}
		rejected("default not offered", setting, "1h,1d", "7d", a)
		rejected("unknown default", setting, "1h,1d", "2d", a)
		size := `UPDATE tenants SET secret_file_max_bytes = ? WHERE id = ?`
		mustExec(size, 1048576, a)
		mustExec(size, 26214400, a)
		rejected("file limit below 1 MiB", size, 1048575, a)
		rejected("file limit above 25 MiB", size, 26214401, a)

		// Secrets. Columns: id, tenant, token hash, state, creator kind,
		// API token, invitation, delivery, recipient, verifier, salt,
		// iterations, sealed text, activation and expiry.
		tok := func(c byte) []byte { return bytes.Repeat([]byte{c}, 32) }
		salt := bytes.Repeat([]byte{7}, 16)
		mustExec(`INSERT INTO master_keys (id, status, created_at) VALUES ('mk_0000000000000001', 'active', 1)`)
		wkey := `INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at) VALUES (?, ?, 'dek', 'mk_0000000000000001', ?, 1)`
		for _, k := range []string{"key_t1", "key_t2", "key_t3", "key_t4", "key_f1", "key_t9", "key_x"} {
			mustExec(wkey, k, a, []byte("sealed"))
		}
		mustExec(wkey, "key_tb", b, []byte("sealed"))
		mustExec(`INSERT INTO api_tokens (id, tenant_id, name, prefix, token_hash, allowed_cidrs, created_by, created_at)
			VALUES ('tok_a', ?, 'ci', 'tt_Ab', ?, '[]', 'root', 1)`, a, tok(90))
		mustExec(`INSERT INTO invitations (id, tenant_id, token_hash, email, invited_by, created_at, expires_at)
			VALUES ('inv_a', ?, ?, 'guest@example.org', 'alice@a.example.com', 1, 9)`, a, tok(91))

		secret := `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email, api_token_id,
			invitation_id, delivery, recipient_email, verifier, kdf_salt, kdf_iterations, text_sealed, text_key_id,
			duration_code, created_at, activated_at, expires_at, key_verifier) VALUES (?, ?, ?, ?, ?, 'alice@a.example.com', ?, ?, ?, ?,
			?, ?, ?, ?, ?, '1d', 1, ?, ?, ?)`
		text := []byte("sealed text")
		ok := func(id string, h byte, state, kind string, apiTok, inv any, delivery string, recipient any,
			s any, iter any, key any, act any, exp any,
		) []any {
			return []any{id, a, tok(h), state, kind, apiTok, inv, delivery, recipient, tok(1), s, iter, text, key, act, exp, tok(2)}
		}
		mustExec(secret, ok("sec_1", 1, "active", "internal", nil, nil, "link", nil, nil, nil, "key_t1", 10, 20)...)
		mustExec(secret, ok("sec_2", 2, "pending", "external", nil, "inv_a", "email", "alice@a.example.com", salt, 600000, "key_t2", nil, nil)...)
		mustExec(secret, ok("sec_3", 3, "active", "api_token", "tok_a", nil, "link", nil, nil, nil, "key_t3", 10, 20)...)
		mustExec(secret, ok("sec_4", 4, "active", "internal_remote", nil, nil, "email", "bob@example.org", nil, nil, "key_t4", 10, 20)...)

		// Token hashes are unique on the whole instance.
		rejected("token hash reused", secret, ok("sec_5", 1, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("short token hash", secret, append([]any{"sec_5", a, []byte{1}}, ok("", 0, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)[3:]...)...)
		// Origin.
		rejected("unknown state", secret, ok("sec_5", 5, "open", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("unknown creator kind", secret, ok("sec_5", 5, "active", "drop_link", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("external without invitation", secret, ok("sec_5", 5, "active", "external", nil, nil, "email", "x@a.example.com", nil, nil, "key_x", 10, 20)...)
		rejected("invitation of an internal", secret, ok("sec_5", 5, "active", "internal", nil, "inv_a", "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("external by link", secret, ok("sec_5", 5, "active", "external", nil, "inv_a", "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("api_token kind without token", secret, ok("sec_5", 5, "active", "api_token", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("token of a session", secret, ok("sec_5", 5, "active", "internal", "tok_a", nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		bArgs := ok("sec_5", 5, "active", "api_token", "tok_a", nil, "link", nil, nil, nil, "key_x", 10, 20)
		bArgs[1] = b
		rejected("API token of another tenant", secret, bArgs...)
		bArgs = ok("sec_5", 5, "pending", "external", nil, "inv_a", "email", "alice@a.example.com", nil, nil, "key_x", nil, nil)
		bArgs[1] = b
		rejected("invitation of another tenant", secret, bArgs...)
		// Delivery.
		rejected("email without recipient", secret, ok("sec_5", 5, "active", "internal", nil, nil, "email", nil, nil, nil, "key_x", 10, 20)...)
		rejected("link with recipient", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", "x@example.org", nil, nil, "key_x", 10, 20)...)
		rejected("unknown delivery", secret, ok("sec_5", 5, "active", "internal", nil, nil, "sms", nil, nil, nil, "key_x", 10, 20)...)
		// Passphrase parameters.
		rejected("salt without iterations", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, salt, nil, "key_x", 10, 20)...)
		rejected("iterations without salt", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, 600000, "key_x", 10, 20)...)
		rejected("other iteration count", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, salt, 100000, "key_x", 10, 20)...)
		rejected("short salt", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, []byte{1}, 600000, "key_x", 10, 20)...)
		short := ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)
		short[9] = []byte{1}
		rejected("short verifier", secret, short...)
		short = ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)
		short[16] = []byte{1}
		rejected("short key verifier", secret, short...)
		short[16] = nil
		rejected("live without key verifier", secret, short...)
		rejected("live without text key", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, nil, nil, 10, 20)...)
		rejected("pending without text key", secret, ok("sec_5", 5, "pending", "internal", nil, nil, "link", nil, nil, nil, nil, nil, nil)...)
		// Lifecycle.
		rejected("active without activation", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", nil, nil)...)
		rejected("pending with activation", secret, ok("sec_5", 5, "pending", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("expiry before activation", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", 20, 10)...)
		rejected("activation without expiry", secret, ok("sec_5", 5, "active", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, nil)...)
		rejected("tombstone with content", secret, ok("sec_5", 5, "expired", "internal", nil, nil, "link", nil, nil, nil, "key_x", 10, 20)...)
		rejected("unknown duration", `UPDATE secrets SET duration_code = '2d' WHERE id = 'sec_1'`)
		rejected("active without text", `UPDATE secrets SET text_sealed = NULL WHERE id = 'sec_1'`)
		rejected("active without verifier", `UPDATE secrets SET verifier = NULL WHERE id = 'sec_1'`)
		rejected("active without key verifier", `UPDATE secrets SET key_verifier = NULL WHERE id = 'sec_1'`)
		rejected("active without text key", `UPDATE secrets SET text_key_id = NULL WHERE id = 'sec_1'`)
		// A live secret's key cannot be destroyed under it (the deletion
		// paths delete the row first, then destroy its keys).
		rejected("key of a live secret destroyed", `DELETE FROM wrapped_keys WHERE id = 'key_t4'`)
		rejected("ended while active", `UPDATE secrets SET ended_at = 30, end_reason = 'read' WHERE id = 'sec_1'`)

		// Reveal: the tombstone drops the text, its key and the verifier in
		// the same statement; leaving any of them is refused.
		rejected("read keeping the text", `UPDATE secrets SET state = 'read', read_at = 30, ended_at = 30, end_reason = 'read',
			verifier = NULL, key_verifier = NULL WHERE id = 'sec_1'`)
		rejected("read keeping the key", `UPDATE secrets SET state = 'read', read_at = 30, ended_at = 30, end_reason = 'read',
			verifier = NULL, key_verifier = NULL, text_sealed = NULL WHERE id = 'sec_1'`)
		rejected("read without read_at", `UPDATE secrets SET state = 'read', ended_at = 30, end_reason = 'read',
			verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL WHERE id = 'sec_1'`)
		rejected("read with another reason", `UPDATE secrets SET state = 'read', read_at = 30, ended_at = 30, end_reason = 'expired',
			verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL WHERE id = 'sec_1'`)
		reveal := `UPDATE secrets SET state = 'read', read_at = 30, ended_at = 30, end_reason = 'read',
			verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL WHERE id = 'sec_1' AND state = 'active'`
		mustExec(reveal)
		mustExec(`DELETE FROM wrapped_keys WHERE id = 'key_t1'`)
		// Receipt: only when asked, only for an ended secret.
		rejected("receipt not asked", `UPDATE secrets SET receipt_sent_at = 31 WHERE id = 'sec_1'`)
		mustExec(`UPDATE secrets SET read_receipt = ?, receipt_sent_at = 31 WHERE id = 'sec_1'`, true)
		rejected("receipt before the end", `UPDATE secrets SET read_receipt = ?, receipt_sent_at = 31 WHERE id = 'sec_3'`, true)

		// Deletion of a pending secret: no activation, end reason names the
		// actor.
		rejected("deleted with a read reason", `UPDATE secrets SET state = 'deleted', ended_at = 5, end_reason = 'read',
			verifier = NULL, key_verifier = NULL, kdf_salt = NULL, kdf_iterations = NULL, text_sealed = NULL,
			text_key_id = NULL WHERE id = 'sec_2'`)
		// No passphrase oracle in a tombstone: the KDF parameters go too.
		rejected("tombstone keeping the passphrase parameters", `UPDATE secrets SET state = 'deleted', ended_at = 5,
			end_reason = 'deleted_by_admin', verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL
			WHERE id = 'sec_2'`)
		rejected("tombstone keeping the key verifier", `UPDATE secrets SET state = 'deleted', ended_at = 5,
			end_reason = 'deleted_by_admin', verifier = NULL, kdf_salt = NULL, kdf_iterations = NULL, text_sealed = NULL,
			text_key_id = NULL WHERE id = 'sec_2'`)
		mustExec(`UPDATE secrets SET state = 'deleted', ended_at = 5, end_reason = 'deleted_by_admin',
			verifier = NULL, key_verifier = NULL, kdf_salt = NULL, kdf_iterations = NULL, text_sealed = NULL,
			text_key_id = NULL WHERE id = 'sec_2'`)

		// Proof failures: a reveal claims a slot before comparing
		// (failed_proofs + 1 while below 5), so the claimed fifth slot is
		// allowed in 'active' inside its transaction; it is then either
		// released by a successful reveal or turned into 'locked'.
		claim := `UPDATE secrets SET failed_proofs = failed_proofs + 1
			WHERE id = 'sec_3' AND state = 'active' AND failed_proofs < 5`
		for range 4 {
			mustExec(claim)
		}
		rejected("six failures", `UPDATE secrets SET failed_proofs = 6 WHERE id = 'sec_3'`)
		rejected("negative failures", `UPDATE secrets SET failed_proofs = -1 WHERE id = 'sec_3'`)
		rejected("locked before five", `UPDATE secrets SET state = 'locked', ended_at = 12, end_reason = 'locked',
			verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL WHERE id = 'sec_3'`)
		mustExec(claim) // the fifth slot, claimed while active
		if n := count(`SELECT count(*) FROM secrets WHERE id = 'sec_3' AND failed_proofs = 5 AND state = 'active'`); n != 1 {
			t.Error("the fifth slot was not claimed")
		}
		rejected("read keeping the fifth slot", `UPDATE secrets SET state = 'read', read_at = 12, ended_at = 12,
			end_reason = 'read', verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL
			WHERE id = 'sec_3'`)
		// A success releases the slot as part of the reveal; here the
		// fifth wrong proof keeps it and locks.
		mustExec(`UPDATE secrets SET state = 'locked', ended_at = 12, end_reason = 'locked',
			verifier = NULL, key_verifier = NULL, text_sealed = NULL, text_key_id = NULL WHERE id = 'sec_3'`)
		mustExec(claim) // matches nothing: the secret is no longer active
		if n := count(`SELECT count(*) FROM secrets WHERE id = 'sec_3' AND failed_proofs = 5`); n != 1 {
			t.Error("a claim changed a locked secret")
		}

		// File: size, metadata and storage name together; uploaded before
		// activation; kept after the reveal only with a pending grant.
		fileSecret := `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email, delivery, verifier,
			key_verifier, text_sealed, text_key_id, duration_code, created_at, file_size, file_metadata, file_storage_name,
			file_key_id) VALUES (?, ?, ?, 'pending', 'internal', 'alice@a.example.com', 'link', ?, ?, ?, ?, '1h', 1, ?, ?, ?, ?)`
		name := func(c string) string { return string(bytes.Repeat([]byte(c), 32)) }
		mustExec(fileSecret, "sec_f", a, tok(20), tok(1), tok(2), text, "key_t9", 100, "bWV0YQ", name("a"), "key_f1")
		// A key row belongs to one secret only.
		rejected("text key shared", `UPDATE secrets SET text_key_id = 'key_t9' WHERE id = 'sec_4'`)
		rejected("file without metadata", fileSecret, "sec_g", a, tok(21), tok(1), tok(2), text, "key_x", 100, nil, name("b"), nil)
		rejected("file without storage", fileSecret, "sec_g", a, tok(21), tok(1), tok(2), text, "key_x", 100, "bWV0YQ", nil, nil)
		rejected("metadata without file", fileSecret, "sec_g", a, tok(21), tok(1), tok(2), text, "key_x", nil, "bWV0YQ", nil, nil)
		rejected("file above 25 MiB", fileSecret, "sec_g", a, tok(21), tok(1), tok(2), text, "key_x", 26214401, "bWV0YQ", name("b"), nil)
		rejected("bad storage name", fileSecret, "sec_g", a, tok(21), tok(1), tok(2), text, "key_x", 100, "bWV0YQ", "short", nil)
		rejected("storage name reused", fileSecret, "sec_g", a, tok(21), tok(1), tok(2), text, "key_x", 100, "bWV0YQ", name("a"), nil)
		mustExec(fileSecret, "sec_h", b, tok(22), tok(1), tok(2), text, "key_tb", 100, "bWV0YQ", name("a"), nil)
		// A complete upload of a live secret needs its file key.
		rejected("uploaded without file key", `UPDATE secrets SET file_uploaded_at = 5 WHERE id = 'sec_h'`)
		rejected("grant while pending", `UPDATE secrets SET file_grant_hash = ?, file_grant_expires_at = 99 WHERE id = 'sec_f'`, tok(30))
		rejected("activated before the upload", `UPDATE secrets SET state = 'active', activated_at = 10, expires_at = 20 WHERE id = 'sec_f'`)
		mustExec(`UPDATE secrets SET file_uploaded_at = 5, state = 'active', activated_at = 10, expires_at = 20 WHERE id = 'sec_f'`)
		fileReveal := `UPDATE secrets SET state = 'read', read_at = 30, ended_at = 30, end_reason = 'read', verifier = NULL, key_verifier = NULL,
			text_sealed = NULL, text_key_id = NULL, file_metadata = NULL, file_grant_hash = ?, file_grant_expires_at = ?
			WHERE id = 'sec_f'`
		rejected("read file without grant", fileReveal, nil, nil)
		rejected("grant without expiry", fileReveal, tok(30), nil)
		rejected("short grant", fileReveal, []byte{1}, 99)
		mustExec(fileReveal, tok(30), 99)
		// Download complete (or grant expired): file, key and grant go.
		rejected("grant dropped, file kept", `UPDATE secrets SET file_grant_hash = NULL, file_grant_expires_at = NULL,
			file_downloaded_at = 40 WHERE id = 'sec_f'`)
		mustExec(`UPDATE secrets SET file_grant_hash = NULL, file_grant_expires_at = NULL, file_storage_name = NULL,
			file_key_id = NULL, file_downloaded_at = 40 WHERE id = 'sec_f'`)
		if n := count(`SELECT count(*) FROM secrets WHERE id = 'sec_f' AND file_size = 100`); n != 1 {
			t.Error("the file size of the tombstone is gone")
		}
		rejected("downloaded while active", `UPDATE secrets SET file_downloaded_at = 40 WHERE id = 'sec_4'`)

		// Destroying a wrapped key nulls the reference (cryptographic
		// erasure leaves no dangling key ID).
		mustExec(`DELETE FROM wrapped_keys WHERE id = 'key_f1'`)
		if n := count(`SELECT count(*) FROM wrapped_keys WHERE id IN ('key_t1', 'key_t2', 'key_f1')`); n != 1 {
			t.Errorf("wrapped keys left = %d, want 1 (key_t2, dropped from its secret)", n)
		}

		// The invitation and the token cannot go while a secret references
		// them; the tenant takes its secrets along.
		rejected("invitation of a secret deleted", `DELETE FROM invitations WHERE id = 'inv_a'`)
		mustExec(`DELETE FROM tenants WHERE id = ?`, b)
		if n := count(`SELECT count(*) FROM secrets WHERE id = 'sec_h'`); n != 0 {
			t.Error("the secret of a deleted tenant survived")
		}
	})
}
