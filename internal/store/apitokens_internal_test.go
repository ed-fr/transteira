package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestAPITokenDriverFaults reaches the error paths of the API token
// repository that a healthy database never takes, and the decoding of a
// corrupted allowed_cidrs column.
func TestAPITokenDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, TokenHashSize)
	tok, err := db.APITokens().Create(ctx, tn.ID, APIToken{
		ID: id.New(id.APIToken), Name: "n", Prefix: "tt_AbCd", TokenHash: hash,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens := db.APITokens()
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"list query", faultQuery, "FROM api_tokens WHERE tenant_id = ? ORDER BY", func() error { _, err := tokens.List(ctx, tn.ID); return err }},
		{"list scan", faultScanNil, "FROM api_tokens WHERE tenant_id = ? ORDER BY", func() error { _, err := tokens.List(ctx, tn.ID); return err }},
		{"update exec", faultExec, "UPDATE api_tokens SET name", func() error {
			_, err := tokens.Update(ctx, tn.ID, tok.ID, APITokenUpdate{Name: "x"})
			return err
		}},
		{"update rows", faultRows, "UPDATE api_tokens SET name", func() error {
			_, err := tokens.Update(ctx, tn.ID, tok.ID, APITokenUpdate{Name: "x"})
			return err
		}},
		{"update probe", faultQuery, "SELECT count(*) FROM api_tokens", func() error {
			_, err := tokens.Update(ctx, tn.ID, id.New(id.APIToken), APITokenUpdate{Name: "x"})
			return err
		}},
		{"revoke exec", faultExec, "SET revoked_at", func() error { _, _, err := tokens.Revoke(ctx, tn.ID, tok.ID, time.Time{}); return err }},
		{"revoke rows", faultRows, "SET revoked_at", func() error { _, _, err := tokens.Revoke(ctx, tn.ID, tok.ID, time.Time{}); return err }},
	} {
		plan.reset()
		plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	plan.reset()

	// A corrupted allowed_cidrs column is reported, never half-decoded.
	for _, doc := range []string{`not json`, `["not a prefix"]`} {
		if _, err := rawSystemExec(ctx, db, `UPDATE api_tokens SET allowed_cidrs = '`+doc+`'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tokens.Get(ctx, tn.ID, tok.ID); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get with allowed_cidrs %q = %v, want a decoding error", doc, err)
		}
	}
	if _, err := rawSystemExec(ctx, db, `UPDATE api_tokens SET allowed_cidrs = '["192.0.2.0/24"]'`); err != nil {
		t.Fatal(err)
	}
	// A corrupted allowed_senders column too; the JSON null reads empty.
	if _, err := rawSystemExec(ctx, db, `UPDATE api_tokens SET allowed_senders = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Get(ctx, tn.ID, tok.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get with a corrupted allowed_senders = %v, want a decoding error", err)
	}
	if _, err := rawSystemExec(ctx, db, `UPDATE api_tokens SET allowed_senders = 'null'`); err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Get(ctx, tn.ID, tok.ID); err != nil || got.AllowedSenders == nil || len(got.AllowedSenders) != 0 {
		t.Errorf("Get with allowed_senders null = %#v, %v", got.AllowedSenders, err)
	}
}

// TestMigration0011Upgrade applies 0011_api_tokens on a database at 0010
// holding a transfer with an idempotency key: the transfer reads as created
// by a deposit session, its key still identifies it and still refuses a
// second transfer of the same sender, and the token hash keeps its size.
func TestMigration0011Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 10)
		if n, err := db.Migrate(ctx); err != nil || n != 10 {
			t.Fatalf("Migrate to 0010 = %d, %v", n, err)
		}
		a := createLegacyTenant(ctx, t, db, "a.example.com", 5)
		trfID := id.New(id.Transfer)
		q := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, idempotency_key, created_at)
			VALUES ('` + trfID + `', '` + string(a) + `', 'uploading', 'alice@a.example.com', 'internal', 7, false, 0, 'k1', 1)`
		if _, err := rawSystemExec(ctx, db, q); err != nil {
			t.Fatalf("insert legacy transfer: %v", err)
		}
		db.migrationsFS = migrationFiles
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		d, err := db.Transfers().GetByIdempotencyKey(ctx, a, "alice@a.example.com", "k1", time.Time{})
		if err != nil || d.ID != trfID || d.APITokenID != "" {
			t.Fatalf("legacy transfer after 0011 = %+v, %v", d.Transfer, err)
		}
		dup := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, idempotency_key, created_at)
			VALUES ('` + id.New(id.Transfer) + `', '` + string(a) + `', 'uploading', 'alice@a.example.com', 'internal', 7, false, 0, 'k1', 2)`
		if _, err := rawSystemExec(ctx, db, dup); err == nil {
			t.Error("second session transfer with the same key accepted")
		}
		short := `INSERT INTO api_tokens (id, tenant_id, name, prefix, token_hash, allowed_cidrs, created_by, created_at)
			VALUES ('` + id.New(id.APIToken) + `', '` + string(a) + `', 'n', 'p', X'01', '[]', 'admin', 0)`
		if e.Driver == "postgres" {
			short = strings.Replace(short, "X'01'", `'\x01'::bytea`, 1)
		}
		if _, err := rawSystemExec(ctx, db, short); err == nil {
			t.Error("token hash of 1 byte accepted")
		}
		// A tenant whose token created transfers is deleted with both.
		tok, err := db.APITokens().Create(ctx, a, APIToken{
			ID: id.New(id.APIToken), Name: "n", Prefix: "tt_AbCd", TokenHash: make([]byte, TokenHashSize),
			AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, CreatedBy: "admin",
		})
		if err != nil {
			t.Fatal(err)
		}
		byToken := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
			delete_after_first_download, total_bytes, idempotency_key, created_at, api_token_id)
			VALUES ('` + id.New(id.Transfer) + `', '` + string(a) + `', 'uploading', 'alice@a.example.com', 'internal', 7, false, 0, 'k1', 3, '` + tok.ID + `')`
		if _, err := rawSystemExec(ctx, db, byToken); err != nil {
			t.Fatalf("token transfer with a session key: %v", err)
		}
		if _, err := rawSystemExec(ctx, db, `DELETE FROM api_tokens WHERE id = '`+tok.ID+`'`); err == nil {
			t.Error("token referenced by a transfer deleted")
		}
		if _, err := rawSystemExec(ctx, db, `DELETE FROM tenants WHERE id = '`+string(a)+`'`); err != nil {
			t.Errorf("delete a tenant with token transfers: %v", err)
		}
	})
}
