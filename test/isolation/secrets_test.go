package isolation_test

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// secretFixture is a one-time secret of a tenant with its proofs.
type secretFixture struct {
	created         store.CreatedSecret
	keyProof, proof [32]byte
}

// secretNow is the clock of the secret cases.
var secretNow = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

// createSecret stores an active link secret of tid sent by sender through
// the real vault.
func createSecret(t *testing.T, repo *store.Secrets, tid tenant.ID, sender string) secretFixture {
	t.Helper()
	var f secretFixture
	_, _ = rand.Read(f.keyProof[:])
	_, _ = rand.Read(f.proof[:])
	kv, v := sha256.Sum256(f.keyProof[:]), sha256.Sum256(f.proof[:])
	cs, err := repo.Create(t.Context(), tid, store.CreateSecret{
		CreatorKind: store.SecretCreatorInternal, SenderEmail: sender, Delivery: store.SecretDeliveryLink,
		Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("sealed-text_", 5),
		Duration: tenant.SecretDuration1d, Now: secretNow,
	})
	if err != nil {
		t.Fatalf("Secrets.Create(%s): %v", tid, err)
	}
	f.created = cs
	return f
}

// newSecretsRepo returns the secret repository of db over a real vault.
func newSecretsRepo(t *testing.T, db *store.DB) *store.Secrets {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, "K1"), nil)
	if err != nil {
		t.Fatalf("masterkey.New: %v", err)
	}
	return db.Secrets(masterkey.NewVault(db, kr, nil))
}

// TestSecretsIsolation attacks A's one-time secret from tenant B through
// every repository method: B never reads, finds by token, reveals, deletes,
// lists, counts, erases or purges it, and A's secret stays readable.
func TestSecretsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		repo := newSecretsRepo(t, f.db)
		const sender = "alice@entity-a.example.com"
		sa := createSecret(t, repo, f.a.ID, sender)
		sb := createSecret(t, repo, f.b.ID, sender)
		secA := sa.created.Secret

		_, err := repo.Get(ctx, f.b.ID, secA.ID)
		assertNotFound(t, "Get", err)
		_, err = repo.StatusByToken(ctx, f.b.ID, sa.created.Token, store.ExpressGate{}, secretNow)
		assertNotFound(t, "StatusByToken", err)
		_, err = repo.Reveal(ctx, f.b.ID, sa.created.Token, store.ExpressGate{}, sa.keyProof, sa.proof, secretNow)
		assertNotFound(t, "Reveal", err)
		_, err = repo.DeleteByAdmin(ctx, f.b.ID, secA.ID, secretNow)
		assertNotFound(t, "DeleteByAdmin", err)
		_, err = repo.DeleteByCreator(ctx, f.b.ID, secA.ID, store.SecretActor{Email: sender}, secretNow)
		assertNotFound(t, "DeleteByCreator", err)
		for name, list := range map[string]func() (store.Page[store.Secret], error){
			"ListByTenant": func() (store.Page[store.Secret], error) {
				return repo.ListByTenant(ctx, f.b.ID, store.SecretListOptions{})
			},
			"ListBySender": func() (store.Page[store.Secret], error) {
				return repo.ListBySender(ctx, f.b.ID, sender, store.SecretListOptions{})
			},
			"ListFiltered": func() (store.Page[store.Secret], error) {
				return repo.ListFiltered(ctx, f.b.ID, store.SecretFilter{State: store.SecretActive, Sender: sender}, store.SecretListOptions{})
			},
		} {
			page, err := list()
			if err != nil || len(page.Items) != 1 || page.Items[0].ID != sb.created.Secret.ID {
				t.Errorf("%s(B) = %+v, %v; want B's secret only", name, page.Items, err)
			}
		}
		if n, err := repo.CountByAddress(ctx, f.b.ID, sender); err != nil || n != 1 {
			t.Errorf("CountByAddress(B) = %d, %v", n, err)
		}
		// B erases its own secrets: A's stays.
		if rep, err := repo.DeleteByAddress(ctx, f.b.ID, sender); err != nil || rep.Deleted != 1 {
			t.Errorf("DeleteByAddress(B) = %+v, %v", rep, err)
		}
		if _, err := repo.DeleteTenant(ctx, f.b.ID); err != nil {
			t.Errorf("DeleteTenant(B): %v", err)
		}
		if n, err := repo.PurgeTombstones(ctx, f.b.ID, secretNow.Add(1000*time.Hour)); err != nil || n != 0 {
			t.Errorf("PurgeTombstones(B) = %d, %v", n, err)
		}
		// A's text key cannot be opened nor destroyed from B either.
		vault := masterkey.NewVault(f.db, mustKeyring(t), nil)
		sc, err := f.db.Scoped(f.b.ID)
		if err != nil {
			t.Fatal(err)
		}
		keysA := secretKeyIDs(t, e, f.a.ID, secA.ID)
		_ = sc.Tx(ctx, func(tx *store.ScopedTx) error {
			for _, k := range keysA {
				if _, err := vault.OpenTx(ctx, tx, crypto.PurposeDEK, k); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("OpenTx of A's key from B = %v", err)
				}
			}
			return nil
		})

		rev, err := repo.Reveal(ctx, f.a.ID, sa.created.Token, store.ExpressGate{}, sa.keyProof, sa.proof, secretNow)
		if err != nil || rev.SealedText != strings.Repeat("sealed-text_", 5) {
			t.Fatalf("A's reveal after the attacks = %+v, %v", rev, err)
		}
	})
}

// mustKeyring returns the keyring of the secret cases.
func mustKeyring(t *testing.T) *masterkey.Keyring {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, "K1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// secretKeyIDs returns the text key ID of the secret secID of tenant tid,
// read with a raw connection (in the scope of tid on PostgreSQL).
func secretKeyIDs(t *testing.T, e storetest.Engine, tid tenant.ID, secID string) []string {
	t.Helper()
	raw := rawDB(t, e)
	q, scope := `SELECT text_key_id FROM secrets WHERE id = ?`, (*string)(nil)
	if e.Driver == "postgres" {
		s := string(tid)
		q, scope = `SELECT text_key_id FROM secrets WHERE id = $1`, &s
	}
	var k sql.NullString
	err := inTenantTx(t.Context(), t, raw, scope, func(tx *sql.Tx) error {
		return tx.QueryRowContext(t.Context(), q, secID).Scan(&k)
	})
	if err != nil || !k.Valid {
		t.Fatalf("read the text key of %s: %v", secID, err)
	}
	return []string{k.String}
}

// TestRLSSecretsCrossTenantRawSQL bypasses the application layer: a raw
// transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT statements
// at B's secret. Row-level security alone must stop them.
func TestRLSSecretsCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	repo := newSecretsRepo(t, f.db)
	secA := createSecret(t, repo, f.a.ID, "alice@entity-a.example.com")
	secB := createSecret(t, repo, f.b.ID, "bob@entity-b.example.org")
	a, b := string(f.a.ID), string(f.b.ID)
	bID, bHash := secB.created.Secret.ID, id.HashToken(secB.created.Token)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM secrets WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM secrets`, nil, 1},
			{`SELECT count(*) FROM secrets WHERE id = $1`, []any{bID}, 0},
			{`SELECT count(*) FROM secrets WHERE token_hash = $1`, []any{bHash}, 0},
			{`SELECT count(*) FROM secrets WHERE true OR tenant_id = $1`, []any{b}, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE secrets SET failed_proofs = failed_proofs + 1 WHERE id = $1`, []any{bID}},
			{`UPDATE secrets SET duration_code = '30d' WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM secrets WHERE id = $1`, []any{bID}},
			{`DELETE FROM secrets WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows", s.stmt, n)
			}
		}
		return nil
	})
	for _, v := range []struct {
		name, stmt string
		args       []any
	}{
		{
			"insert a secret for B", `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email,
			delivery, verifier, key_verifier, text_sealed, text_key_id, duration_code, created_at)
			SELECT $1, $2, $3, 'pending', 'internal', 'x@example.net', 'link', verifier, key_verifier, text_sealed,
			NULL, '1h', 0 FROM secrets WHERE id = $4`,
			[]any{id.New(id.Secret), b, id.HashToken("tts_insert"), secA.created.Secret.ID},
		},
		{"move A's secret to B", `UPDATE secrets SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != pgInsufficientPrivilege {
				t.Errorf("%s: err = %v, want SQLSTATE %s", v.name, err, pgInsufficientPrivilege)
			}
		})
	}
	// Both secrets are intact.
	for _, s := range []struct {
		tid tenant.ID
		f   secretFixture
	}{{f.a.ID, secA}, {f.b.ID, secB}} {
		if _, err := repo.Reveal(ctx, s.tid, s.f.created.Token, store.ExpressGate{}, s.f.keyProof, s.f.proof, secretNow); err != nil {
			t.Errorf("reveal after the attacks: %v", err)
		}
	}
}

// createExpress stores an express secret of tid (anonymous when tokID is
// "") through the real vault.
func createExpress(t *testing.T, repo *store.Secrets, tid tenant.ID, tokID string) secretFixture {
	t.Helper()
	var f secretFixture
	_, _ = rand.Read(f.keyProof[:])
	_, _ = rand.Read(f.proof[:])
	kv, v := sha256.Sum256(f.keyProof[:]), sha256.Sum256(f.proof[:])
	cs, err := repo.CreateExpress(t.Context(), tid, store.CreateExpressSecret{
		APITokenID: tokID, Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("sealed-text_", 5),
		Duration: tenant.SecretDuration1d, Now: secretNow,
	})
	if err != nil {
		t.Fatalf("Secrets.CreateExpress(%s): %v", tid, err)
	}
	f.created = cs
	return f
}

// TestExpressSecretsIsolation attacks A's express secrets, settings and
// token from tenant B through every store method of the express secrets
// (since 2.3): B never creates with A's token, reads, reveals, looks up,
// purges or reports A's express secrets, the settings, caps and limits of
// one tenant never apply to the other, and A's secrets stay readable.
func TestExpressSecretsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		repo := newSecretsRepo(t, f.db)
		open := tenant.ExpressSettings{Enabled: true, PerHourPerIP: 10, PerHourPerToken: 1, MaxPending: 1}
		for _, tid := range []tenant.ID{f.a.ID, f.b.ID} {
			if _, err := f.db.Tenants().SetExpressSettings(ctx, tid, open); err != nil {
				t.Fatalf("SetExpressSettings(%s): %v", tid, err)
			}
		}
		tokA := createAPIToken(t, f.db, f.a.ID, "a")
		allowed := true
		if _, err := f.db.APITokens().Update(ctx, f.b.ID, tokA.ID, store.APITokenUpdate{ExpressAllowed: &allowed}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("allow A's token from B = %v", err)
		}
		if _, err := f.db.APITokens().Update(ctx, f.a.ID, tokA.ID, store.APITokenUpdate{ExpressAllowed: &allowed}); err != nil {
			t.Fatal(err)
		}

		// A fills its cap (1) and its token its hourly limit (1); B keeps
		// its own.
		anonA := createExpress(t, repo, f.a.ID, "")
		byTokA := createExpress(t, repo, f.a.ID, tokA.ID)
		anonB := createExpress(t, repo, f.b.ID, "")
		in := store.CreateExpressSecret{
			Verifier: make([]byte, 32), KeyVerifier: make([]byte, 32),
			SealedText: strings.Repeat("sealed-text_", 5), Duration: tenant.SecretDuration1h, Now: secretNow,
		}
		if _, err := repo.CreateExpress(ctx, f.a.ID, in); !errors.Is(err, store.ErrExpressLimit) {
			t.Errorf("A over its cap = %v", err)
		}
		in.APITokenID = tokA.ID
		if _, err := repo.CreateExpress(ctx, f.b.ID, in); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CreateExpress in B with A's token = %v, want ErrNotFound", err)
		}
		// B closes its anonymous mode: A's stay open.
		if _, err := f.db.Tenants().SetExpressSettings(ctx, f.b.ID, tenant.DefaultExpressSettings()); err != nil {
			t.Fatal(err)
		}
		if got, err := f.db.Tenants().Get(ctx, f.a.ID); err != nil || got.Express != open {
			t.Errorf("A's express settings after B's change = %+v, %v", got.Express, err)
		}

		// Recipient side, with and without the kill switch.
		for _, gate := range []store.ExpressGate{{}, {KillSwitch: true}} {
			for _, s := range []secretFixture{anonA, byTokA} {
				_, err := repo.StatusByToken(ctx, f.b.ID, s.created.Token, gate, secretNow)
				assertNotFound(t, "StatusByToken(A's express) from B", err)
				_, err = repo.Reveal(ctx, f.b.ID, s.created.Token, gate, s.keyProof, s.proof, secretNow)
				assertNotFound(t, "Reveal(A's express) from B", err)
			}
		}
		// Administration side.
		_, err := repo.LookupByToken(ctx, f.b.ID, anonA.created.Token)
		assertNotFound(t, "LookupByToken(A's link) from B", err)
		_, err = repo.DeleteByAdmin(ctx, f.b.ID, anonA.created.Secret.ID, secretNow)
		assertNotFound(t, "DeleteByAdmin(A's express) from B", err)
		if n, err := repo.PurgeAnonymousExpress(ctx, f.b.ID, secretNow); err != nil || n != 1 {
			t.Errorf("PurgeAnonymousExpress(B) = %d, %v; want B's secret only", n, err)
		}
		page, err := repo.ListFiltered(ctx, f.b.ID, store.SecretFilter{}, store.SecretListOptions{})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != anonB.created.Secret.ID {
			t.Errorf("ListFiltered(B) = %+v, %v", page.Items, err)
		}
		// Abuse reports name a secret of their own tenant only.
		reports := f.db.AbuseReports()
		rep := store.AbuseReport{
			SecretID: anonA.created.Secret.ID, ReporterIP: netip.MustParseAddr("192.0.2.9"),
			Category: store.AbuseCategoryPhishing,
		}
		_, err = reports.Create(ctx, f.b.ID, rep, store.DefaultAbuseReportLimits(), secretNow)
		assertNotFound(t, "report on A's express secret from B", err)
		repA, err := reports.Create(ctx, f.a.ID, rep, store.DefaultAbuseReportLimits(), secretNow)
		if err != nil {
			t.Fatalf("report on A's express secret from A: %v", err)
		}
		_, err = reports.Get(ctx, f.b.ID, repA.ID)
		assertNotFound(t, "Get(A's secret report) from B", err)
		if list, err := reports.List(ctx, f.b.ID, "", 0, ""); err != nil || len(list.Items) != 0 {
			t.Errorf("List(B) = %+v, %v", list.Items, err)
		}

		// A's express secrets are intact and readable.
		for _, s := range []secretFixture{anonA, byTokA} {
			rev, err := repo.Reveal(ctx, f.a.ID, s.created.Token, store.ExpressGate{}, s.keyProof, s.proof, secretNow)
			if err != nil || rev.SealedText != strings.Repeat("sealed-text_", 5) {
				t.Errorf("A's reveal after the attacks = %+v, %v", rev, err)
			}
		}
	})
}

// TestRLSExpressCrossTenantRawSQL (PostgreSQL, since 2.3): under tenant
// A's scope, raw SQL never sees, counts, purges, prolongs nor deletes B's
// express secrets, B's abuse reports on them or B's API tokens (whose
// express opt-in it cannot set), and cannot insert an anonymous express
// secret or a report for B nor move A's express secret to B (row-level
// security, threat model T-390). B's secret, report and token are intact
// afterwards.
func TestRLSExpressCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	repo := newSecretsRepo(t, f.db)
	open := tenant.ExpressSettings{Enabled: true, PerHourPerIP: 10, PerHourPerToken: 100, MaxPending: 1000}
	for _, tid := range []tenant.ID{f.a.ID, f.b.ID} {
		if _, err := f.db.Tenants().SetExpressSettings(ctx, tid, open); err != nil {
			t.Fatalf("SetExpressSettings(%s): %v", tid, err)
		}
	}
	tokB := createAPIToken(t, f.db, f.b.ID, "b")
	expA := createExpress(t, repo, f.a.ID, "")
	expB := createExpress(t, repo, f.b.ID, "")
	repB, err := f.db.AbuseReports().Create(ctx, f.b.ID, store.AbuseReport{
		SecretID: expB.created.Secret.ID, ReporterIP: netip.MustParseAddr("192.0.2.9"), Category: store.AbuseCategoryPhishing,
	}, store.DefaultAbuseReportLimits(), secretNow)
	if err != nil {
		t.Fatalf("report on B's express secret: %v", err)
	}
	a, b := string(f.a.ID), string(f.b.ID)
	bID := expB.created.Secret.ID

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM secrets WHERE express`, nil, 1},
			{`SELECT count(*) FROM secrets WHERE express AND tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM secrets WHERE id = $1`, []any{bID}, 0},
			{`SELECT count(*) FROM secrets WHERE token_hash = $1`, []any{id.HashToken(expB.created.Token)}, 0},
			{`SELECT count(*) FROM abuse_reports`, nil, 0},
			{`SELECT count(*) FROM abuse_reports WHERE secret_id = $1`, []any{bID}, 0},
			{`SELECT count(*) FROM api_tokens WHERE id = $1`, []any{tokB.ID}, 0},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE secrets SET expires_at = expires_at + 86400000 WHERE express AND tenant_id = $1`, []any{b}},
			{`DELETE FROM secrets WHERE id = $1`, []any{bID}},
			{`UPDATE abuse_reports SET note = 'hidden' WHERE secret_id = $1`, []any{bID}},
			{`DELETE FROM abuse_reports WHERE id = $1`, []any{repB.ID}},
			{`UPDATE api_tokens SET express_allowed = true WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows", s.stmt, n)
			}
		}
		return nil
	})
	for _, v := range []struct {
		name, stmt string
		args       []any
	}{
		{
			"insert an anonymous express secret for B", `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind,
			sender_email, delivery, verifier, key_verifier, text_sealed, text_key_id, duration_code, created_at, express)
			SELECT $1, $2, $3, 'active', 'anonymous', NULL, 'link', verifier, key_verifier, text_sealed, NULL, '1h', 0, true
			FROM secrets WHERE id = $4`,
			[]any{id.New(id.Secret), b, id.HashToken("tts_insert"), expA.created.Secret.ID},
		},
		{
			"insert a report on B's express secret", `INSERT INTO abuse_reports (id, tenant_id, secret_id, reporter_ip, category,
			created_at) VALUES ($1, $2, $3, '192.0.2.9', 'phishing', 0)`,
			[]any{"abr_forged", b, bID},
		},
		{"move A's express secret to B", `UPDATE secrets SET tenant_id = $1 WHERE express`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != pgInsufficientPrivilege {
				t.Errorf("%s: err = %v, want SQLSTATE %s", v.name, err, pgInsufficientPrivilege)
			}
		})
	}
	// B's secret, report and token are intact.
	if _, err := f.db.AbuseReports().Get(ctx, f.b.ID, repB.ID); err != nil {
		t.Errorf("B's report after the attacks: %v", err)
	}
	if tok, err := f.db.APITokens().Get(ctx, f.b.ID, tokB.ID); err != nil || tok.ExpressAllowed {
		t.Errorf("B's token after the attacks = %+v, %v", tok, err)
	}
	for _, s := range []struct {
		tid tenant.ID
		f   secretFixture
	}{{f.a.ID, expA}, {f.b.ID, expB}} {
		if _, err := repo.Reveal(ctx, s.tid, s.f.created.Token, store.ExpressGate{}, s.f.keyProof, s.f.proof, secretNow); err != nil {
			t.Errorf("reveal after the attacks: %v", err)
		}
	}
}
