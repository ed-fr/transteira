package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newTestTenant creates a tenant through Tenants.Create.
func newTestTenant(ctx context.Context, t *testing.T, db *DB, fqdn string) tenant.ID {
	t.Helper()
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "T", FQDN: fqdn, DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatalf("create tenant %s: %v", fqdn, err)
	}
	return tn.ID
}

// TestRecipientLinkKeyGuards checks the crypto-erase guard of the recipient
// links (T-110), on both engines: neither a transfer nor a recipient can be
// deleted while a recipient link concerned keeps its sealed token, since
// the cascade would leave the key behind; once the key is destroyed, the
// deletion cascades to the link and its verification codes. It also checks
// that a verification code cannot reference the link of another tenant
// (composite foreign key).
func TestRecipientLinkKeyGuards(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		a := newTestTenant(ctx, t, db, "a.example.com")
		b := newTestTenant(ctx, t, db, "b.example.com")
		h := func(c byte) []byte { return bytes.Repeat([]byte{c}, 32) }
		seed := []struct {
			q    string
			args []any
		}{
			{`INSERT INTO master_keys (id, status, created_at) VALUES ('mk_0000000000000001', 'active', 1)`, nil},
			{`INSERT INTO wrapped_keys (id, tenant_id, purpose, key_id, blob, created_at)
				VALUES ('key_l0', ?, 'secret', 'mk_0000000000000001', ?, 1)`, []any{string(a), []byte("sealed")}},
			{`INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
				delete_after_first_download, total_bytes, created_at)
				VALUES ('trf_x', ?, 'uploading', 'alice@a.example.com', 'internal', 1, ?, 0, 1)`, []any{string(a), false}},
			{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_x', 0, 'r0@example.org')`, []any{string(a)}},
			{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_x', 1, 'r1@example.org')`, []any{string(a)}},
			{`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, 'trf_x', 2, 'r2@example.org')`, []any{string(a)}},
			{`INSERT INTO recipient_links (id, tenant_id, transfer_id, position, token_hash, token_key_id, created_at)
				VALUES ('rcl_0', ?, 'trf_x', 0, ?, 'key_l0', 1)`, []any{string(a), h(1)}},
			{`INSERT INTO recipient_links (id, tenant_id, transfer_id, position, token_hash, created_at)
				VALUES ('rcl_1', ?, 'trf_x', 1, ?, 1)`, []any{string(a), h(2)}},
			{`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining, client_ip,
				created_at, expires_at, purpose, recipient_link_id, recipient_intent)
				VALUES ('vch_0', ?, 'r0@example.org', ?, 2, '192.0.2.1', 1, 2, 'recipient', 'rcl_0', 'download')`, []any{string(a), h(3)}},
			{`INSERT INTO verification_challenges (id, tenant_id, email, code_mac, attempts_remaining, client_ip,
				created_at, expires_at, purpose, recipient_link_id, recipient_intent)
				VALUES ('vch_1', ?, 'r1@example.org', ?, 2, '192.0.2.1', 1, 2, 'recipient', 'rcl_1', 'reply')`, []any{string(a), h(4)}},
		}
		for _, s := range seed {
			if err := rawExecArgs(ctx, t, db, s.q, s.args...); err != nil {
				t.Fatalf("seed: %v\n%s", err, s.q)
			}
		}
		// The composite foreign key: a code of tenant b cannot point to a
		// link of tenant a.
		if err := rawExecArgs(ctx, t, db, `INSERT INTO verification_challenges (id, tenant_id, email, code_mac,
			attempts_remaining, client_ip, created_at, expires_at, purpose, recipient_link_id, recipient_intent)
			VALUES ('vch_b', ?, 'r0@example.org', ?, 2, '192.0.2.1', 1, 2, 'recipient', 'rcl_0', 'download')`,
			string(b), h(5)); err == nil {
			t.Error("a verification code referencing the link of another tenant was accepted")
		}

		sc, err := db.Scoped(a)
		if err != nil {
			t.Fatal(err)
		}
		inTx := func(fn func(tx *ScopedTx) error) error { return sc.Tx(ctx, fn) }
		removeRecipient := func(email string) error {
			return inTx(func(tx *ScopedTx) error { return db.Transfers().RemoveRecipientTx(ctx, tx, "trf_x", email) })
		}
		deleteTransfer := func() error {
			return inTx(func(tx *ScopedTx) error { return db.Transfers().DeleteTx(ctx, tx, "trf_x") })
		}
		count := func(q string) int64 { return rawInt(ctx, t, db, q) }

		if err := removeRecipient("r0@example.org"); !errors.Is(err, ErrKeysRemain) {
			t.Errorf("RemoveRecipientTx(link with key) = %v, want ErrKeysRemain", err)
		}
		if err := removeRecipient("nobody@example.org"); !errors.Is(err, ErrNotFound) {
			t.Errorf("RemoveRecipientTx(unknown) = %v, want ErrNotFound", err)
		}
		if err := deleteTransfer(); !errors.Is(err, ErrKeysRemain) {
			t.Errorf("DeleteTx(link with key) = %v, want ErrKeysRemain", err)
		}
		if n := count(`SELECT count(*) FROM recipient_links WHERE id = 'rcl_0' AND token_key_id = 'key_l0'`); n != 1 {
			t.Fatalf("the refused deletions removed the link: %d", n)
		}
		// A recipient without link, and one whose link has no key, go.
		if err := removeRecipient("r2@example.org"); err != nil {
			t.Errorf("RemoveRecipientTx(no link): %v", err)
		}
		if err := removeRecipient("r1@example.org"); err != nil {
			t.Errorf("RemoveRecipientTx(link without key): %v", err)
		}
		if n := count(`SELECT count(*) FROM recipient_links WHERE id = 'rcl_1'`) +
			count(`SELECT count(*) FROM verification_challenges WHERE id = 'vch_1'`); n != 0 {
			t.Errorf("link or code left after its recipient: %d", n)
		}
		// Keys first, then the transfer, which takes the link and its code.
		if err := inTx(func(tx *ScopedTx) error { return db.WrappedKeys().DeleteTx(ctx, tx, "key_l0") }); err != nil {
			t.Fatalf("delete the link key: %v", err)
		}
		if err := deleteTransfer(); err != nil {
			t.Fatalf("DeleteTx(keys destroyed): %v", err)
		}
		if n := count(`SELECT count(*) FROM recipient_links`) + count(`SELECT count(*) FROM verification_challenges`) +
			count(`SELECT count(*) FROM transfer_recipients`); n != 0 {
			t.Errorf("%d rows left after the transfer", n)
		}
	})
}

// TestTenantCreateSeeds checks, on both engines, that Tenants.Create seeds
// the same default configuration rows as the 0016 and 0017 backfills did
// for an existing tenant, and that deleting the new tenant takes them
// along.
func TestTenantCreateSeeds(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 15)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate to 0015: %v", err)
		}
		legacy := createLegacyTenant(ctx, t, db, "legacy.example.com", 1)
		db.migrationsFS = migrationFiles
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		fresh := newTestTenant(ctx, t, db, "fresh.example.com")

		same := func(what, q string, want int64) {
			t.Helper()
			if db.dialect.numbered {
				q = rebindNumbered(q)
			}
			var n int64
			err := db.runTx(ctx, db.read, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx, q, string(legacy), string(fresh)).Scan(&n)
			})
			if err != nil || n != want {
				t.Errorf("%s: %d matching rows, %v; want %d", what, n, err, want)
			}
		}
		same("levels", `SELECT count(*) FROM confidentiality_levels x JOIN confidentiality_levels y
			ON y.key = x.key AND y.position = x.position AND y.labels = x.labels AND y.descriptions = x.descriptions
			AND y.is_default = x.is_default AND y.require_recipient_verification = x.require_recipient_verification
			AND y.require_password = x.require_password AND y.allowed_validity_days = x.allowed_validity_days
			AND y.internal_recipients_only = x.internal_recipients_only
			AND y.force_delete_after_download = x.force_delete_after_download
			AND y.max_downloads_cap IS NOT DISTINCT FROM x.max_downloads_cap
			AND y.updated_at = x.updated_at AND y.updated_by = x.updated_by
			WHERE x.tenant_id = ? AND y.tenant_id = ?`, int64(len(defaultConfidentialityLevels)))
		same("abuse settings", `SELECT count(*) FROM tenant_abuse_settings x JOIN tenant_abuse_settings y
			ON y.max_daily_bytes_per_sender IS NOT DISTINCT FROM x.max_daily_bytes_per_sender
			AND y.max_daily_transfers_per_sender IS NOT DISTINCT FROM x.max_daily_transfers_per_sender
			AND y.max_recipients_per_transfer IS NOT DISTINCT FROM x.max_recipients_per_transfer
			AND y.block_on_exceed = x.block_on_exceed
			AND y.unusual_volume_pct IS NOT DISTINCT FROM x.unusual_volume_pct
			AND y.unusual_min_history_days = x.unusual_min_history_days
			AND y.large_external_transfer_bytes IS NOT DISTINCT FROM x.large_external_transfer_bytes
			AND y.office_start_minute IS NOT DISTINCT FROM x.office_start_minute
			AND y.office_end_minute IS NOT DISTINCT FROM x.office_end_minute
			AND y.office_weekdays = x.office_weekdays AND y.time_zone = x.time_zone
			AND y.max_invitations_per_inviter = x.max_invitations_per_inviter
			AND y.external_max_daily_bytes IS NOT DISTINCT FROM x.external_max_daily_bytes
			AND y.external_max_daily_deposits IS NOT DISTINCT FROM x.external_max_daily_deposits
			AND y.updated_at = x.updated_at AND y.updated_by = x.updated_by
			WHERE x.tenant_id = ? AND y.tenant_id = ?`, 1)
		for _, tb := range []string{"confidentiality_levels", "tenant_abuse_settings"} {
			for _, tid := range []tenant.ID{legacy, fresh} {
				want := int64(1)
				if tb == "confidentiality_levels" {
					want = int64(len(defaultConfidentialityLevels))
				}
				if n := rawInt(ctx, t, db, `SELECT count(*) FROM `+tb+` WHERE tenant_id = '`+string(tid)+`'`); n != want {
					t.Errorf("%s rows of %s = %d, want %d", tb, tid, n, want)
				}
			}
		}

		if err := db.Tenants().Delete(ctx, fresh); err != nil {
			t.Fatalf("delete the new tenant: %v", err)
		}
		for _, tb := range []string{"confidentiality_levels", "tenant_abuse_settings"} {
			if n := rawInt(ctx, t, db, `SELECT count(*) FROM `+tb+` WHERE tenant_id = '`+string(fresh)+`'`); n != 0 {
				t.Errorf("%d %s rows left after the tenant", n, tb)
			}
		}
	})
}

// TestTenantCreateSeedFaults makes each seed insert fail (sqlite-fault
// driver): the creation fails and leaves no tenant behind.
func TestTenantCreateSeedFaults(t *testing.T) {
	t.Parallel()
	for _, match := range []string{"INSERT INTO confidentiality_levels", "INSERT INTO tenant_abuse_settings"} {
		t.Run(match, func(t *testing.T) {
			t.Parallel()
			db, plan := openFault(t)
			ctx := context.Background()
			plan.add(faultExec, match, 0)
			if _, err := db.Tenants().Create(ctx, &tenant.Tenant{
				Name: "T", FQDN: "t.example.com", DefaultLanguage: "fr",
				MaxTransferBytes: 1, StorageQuotaBytes: 1,
			}); !errors.Is(err, errInjected) {
				t.Fatalf("Create = %v, want the injected fault", err)
			}
			plan.reset()
			if n := rawInt(ctx, t, db, `SELECT count(*) FROM tenants`); n != 0 {
				t.Errorf("%d tenants left by a failed creation", n)
			}
		})
	}
}
