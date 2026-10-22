package store

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestRebindNumbered(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"", ""},
		{"SELECT 1", "SELECT 1"},
		{"SELECT ?", "SELECT $1"},
		{"a = ? AND b = ?", "a = $1 AND b = $2"},
		{"x = '?' AND y = ?", "x = '?' AND y = $1"},
		{"x = 'it''s ?' AND y = ?", "x = 'it''s ?' AND y = $1"},
		{`"col?" = ?`, `"col?" = $1`},
		{`"a""?" = ?`, `"a""?" = $1`},
		{"-- why?\nx = ?", "-- why?\nx = $1"},
		{"x = ? -- trailing?", "x = $1 -- trailing?"},
		{"/* ? */ x = ?", "/* ? */ x = $1"},
		{"x = ? /* unterminated ?", "x = $1 /* unterminated ?"},
		{"x = 'unterminated ?", "x = 'unterminated ?"},
		{"a-b = ?", "a-b = $1"},
		{"a/b = ?", "a/b = $1"},
		{"?,?,?,?,?,?,?,?,?,?", "$1,$2,$3,$4,$5,$6,$7,$8,$9,$10"},
	}
	for _, tt := range tests {
		if got := rebindNumbered(tt.in); got != tt.want {
			t.Errorf("rebindNumbered(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLexSQL(t *testing.T) {
	t.Parallel()
	toks, ok := lexSQL("SELECT a.b, 'x''y', \"q\" FROM t WHERE c = ? -- c\n/* d */;")
	if !ok {
		t.Fatal("lexSQL reported an unterminated statement")
	}
	var got []string
	for _, tk := range toks {
		got = append(got, tk.text)
	}
	want := "SELECT|a.b|,|'x''y'|,|\"q\"|FROM|t|WHERE|c|=|?|;"
	if strings.Join(got, "|") != want {
		t.Errorf("tokens = %q, want %q", strings.Join(got, "|"), want)
	}
	for _, s := range []string{"'abc", `"abc`, "/* abc", "a = 'x' /*"} {
		if _, ok := lexSQL(s); ok {
			t.Errorf("lexSQL(%q) ok = true, want false", s)
		}
	}
	if _, ok := lexSQL("x -- comment without newline"); !ok {
		t.Error("a trailing line comment must be accepted")
	}
}

func TestValidateTenantQuery(t *testing.T) {
	t.Parallel()
	valid := []struct {
		q    string
		slot int
		n    int
	}{
		{"SELECT a FROM t WHERE tenant_id = ?", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ?;", 0, 1},
		{"select a from t where TENANT_ID = ? and b = ?", 0, 2},
		{"SELECT a FROM t x WHERE x.tenant_id = ? AND (b = ? OR c = ?) ORDER BY a LIMIT ?", 0, 4},
		{"SELECT a FROM t AS x WHERE x.tenant_id = ?", 0, 1},
		{"SELECT a FROM t WHERE t.tenant_id = ?", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ? ORDER BY a", 0, 1},
		{"SELECT count(*) FROM t WHERE tenant_id = ? GROUP BY a", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ? LIMIT 1", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ? AND b = '?' AND c = 'OR'", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ? AND b IN (?, 'x', 3) AND c NOT IN (1)", 0, 2},
		{"SELECT a FROM t WHERE b = ? AND tenant_id = ?", 1, 2},
		{"SELECT a, ? FROM t WHERE (b = ? OR c = ?) AND tenant_id = ? AND d = ? LIMIT ?", 3, 6},
		{"SELECT max(a) FILTER (WHERE b) FROM t WHERE tenant_id = ?", 0, 1},
		{"DELETE FROM t WHERE tenant_id = ?", 0, 1},
		{"DELETE FROM t WHERE tenant_id = ? AND id = ?", 0, 2},
		{"DELETE FROM t WHERE id = ? AND tenant_id = ?", 1, 2},
		{"DELETE FROM t x WHERE x.tenant_id = ?", 0, 1},
		{"UPDATE t SET a = 1 WHERE tenant_id = ? AND id = ?", 0, 2},
		{"UPDATE t SET a = ?, b = ? WHERE tenant_id = ? AND id = ?", 2, 4},
		{"UPDATE t SET a = lower(?) WHERE id = ? AND tenant_id = ?", 2, 3},
		{"UPDATE t AS x SET a = ? WHERE x.tenant_id = ?", 1, 2},
		{"INSERT INTO t (tenant_id, a, b) VALUES (?, ?, ?)", 0, 3},
		{"INSERT INTO t (tenant_id) VALUES (?)", 0, 1},
		{"INSERT INTO t (tenant_id, a) VALUES (?, lower(?))", 0, 2},
		{"INSERT INTO t (a, tenant_id) VALUES (?, ?)", 1, 2},
		{"INSERT INTO t (id, a, tenant_id, b) VALUES (?, coalesce(?, ?), ?, 'x')", 3, 4},
		{"INSERT INTO t (a, b, tenant_id) VALUES (1, 'z', ?)", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ? -- comment ?", 0, 1},
		{"SELECT a FROM t WHERE tenant_id = ? /* comment ? */", 0, 1},
	}
	for _, tt := range valid {
		slot, n, err := validateTenantQuery(tt.q, true)
		if err != nil || slot != tt.slot || n != tt.n {
			t.Errorf("validateTenantQuery(%q) = %d, %d, %v; want %d, %d, nil", tt.q, slot, n, err, tt.slot, tt.n)
		}
	}
	invalid := []struct {
		q    string
		want error
	}{
		{"", errQueryEmpty},
		{";", errQueryEmpty},
		{"-- only a comment", errQueryEmpty},
		{"SELECT 'unterminated", errQueryUnterminated},
		{"SELECT a FROM t WHERE tenant_id = ? /* a /* nested */ */", errQueryUnterminated},
		{"SELECT a FROM t WHERE tenant_id = ?; DELETE FROM t", errQueryMulti},
		{"SELECT a FROM t WHERE tenant_id = $1", errQueryBindSyntax},
		{"SELECT a FROM t WHERE tenant_id = :tid", errQueryBindSyntax},
		{"SELECT a FROM t WHERE tenant_id = @tid", errQueryBindSyntax},
		{"SELECT a::text FROM t WHERE tenant_id = ?", errQueryBindSyntax},
		{"SELECT a FROM t WHERE a <> ?5 AND tenant_id = ?", errQueryBindSyntax},
		{"SELECT a FROM t WHERE tenant_id = ?1", errQueryBindSyntax},
		{"SELECT a FROM t WHERE tenant_id = ? AND b = #name", errQueryBindSyntax},
		{`UPDATE t SET "tenant_id" = ? WHERE tenant_id = ? AND id = ?`, errQueryQuotedIdent},
		{"UPDATE t SET `tenant_id` = ? WHERE tenant_id = ? AND id = ?", errQueryQuotedIdent},
		{"UPDATE t SET [tenant_id] = ? WHERE tenant_id = ? AND id = ?", errQueryQuotedIdent},
		{`SELECT a FROM "t" WHERE tenant_id = ?`, errQueryQuotedIdent},
		{`SELECT a FROM t WHERE tenant_id = ? AND b = E'\x27'`, errQueryLiteralPrefix},
		{"SELECT a FROM t WHERE tenant_id = ? AND b = U&'x'", errQueryLiteralPrefix},
		{"SELECT a FROM t WHERE tenant_id = ? AND b = X'00'", errQueryLiteralPrefix},
		{"SELECT set_config('x', ?, true) FROM t WHERE tenant_id = ?", errQueryForbidden},
		{"SELECT a FROM t WHERE tenant_id = ? AND current_setting('x') = ''", errQueryForbidden},
		{"SELECT pg_sleep(1) FROM t WHERE tenant_id = ?", errQueryForbidden},
		{"SELECT a FROM pg_catalog.pg_class WHERE tenant_id = ?", errQueryForbidden},
		{"SELECT a FROM t WHERE tenant_id = ? AND b = 'app.tenant_id'", errQueryForbidden},
		{"WITH x AS (SELECT 1) SELECT a FROM t WHERE tenant_id = ?", errQueryVerb},
		{"PRAGMA foo", errQueryVerb},
		{"SELECT a FROM t WHERE tenant_id = ? OR 1 = 1", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE tenant_id = ? or b = ?", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE tenant_id = ? UNION SELECT a FROM t", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE tenant_id = ? INTERSECT SELECT a FROM t", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE tenant_id = ? EXCEPT SELECT a FROM t", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE tenant_id = ? AND (b = 1", errQueryParens},
		{"SELECT a FROM t WHERE tenant_id = ? ) OR ( 1 = 1", errQueryParens},
		{"SELECT a FROM t WHERE tenant_id = ? AND x BETWEEN 1 AND 2", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE x BETWEEN 1 AND tenant_id = ?", errQueryTopLevelOr},
		{"SELECT a FROM t WHERE CASE WHEN b AND tenant_id = ? AND c THEN 1 END = 1", errQueryTopLevelOr},
		// Single-table rule.
		{"SELECT a FROM t", errQuerySingleTable},
		{"SELECT ?", errQuerySingleTable},
		{"SELECT a FROM t, u WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM t x, u WHERE x.tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM t JOIN u ON u.x = t.x WHERE t.tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM t NATURAL LEFT OUTER JOIN u WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM (SELECT 'x' AS tenant_id, a FROM u) WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT (SELECT b FROM u) FROM t WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM t WHERE tenant_id = ? AND x IN (SELECT y FROM u)", errQuerySingleTable},
		{"SELECT a INTO x FROM t WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT substring(a FROM 2) FROM t WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT f(a FROM b) WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM t AS WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT a FROM", errQuerySingleTable},
		{"DELETE FROM t USING u WHERE tenant_id = ?", errQuerySingleTable},
		{"DELETE t WHERE tenant_id = ?", errQuerySingleTable},
		{"DELETE FROM t, u WHERE tenant_id = ?", errQuerySingleTable},
		{"UPDATE t SET a = 1 FROM u WHERE tenant_id = ?", errQuerySingleTable},
		{"UPDATE t, u SET a = 1 WHERE tenant_id = ?", errQuerySingleTable},
		{"UPDATE t SET a = (SELECT b FROM u) WHERE tenant_id = ?", errQuerySingleTable},
		{"INSERT INTO t (tenant_id, a) SELECT ?, a FROM u", errQuerySingleTable},
		{"SELECT count(*) FROM blocklist_entries WHERE tenant_id = ? AND (?, 'domain', ?) IN tenant_network_rules", errQuerySingleTable},
		{"SELECT a FROM t WHERE tenant_id = ? AND b NOT IN u", errQuerySingleTable},
		{"SELECT a FROM t WHERE tenant_id = ? AND b IN", errQuerySingleTable},
		{"SELECT a FROM t WHERE tenant_id = ? AND b IN (TABLE u)", errQuerySingleTable},
		{"SELECT a FROM t WHERE tenant_id = ? AND (b, c) IN (VALUES (1, 2))", errQuerySingleTable},
		{"SELECT a FROM t WHERE tenant_id = ? AND EXISTS (TABLE u)", errQuerySingleTable},
		{"SELECT a AS tenant_id FROM t WHERE tenant_id = ?", errQuerySingleTable},
		{"SELECT id || 'x' tenant_id FROM tenants WHERE tenant_id = ?", errQueryTenantColumn},
		{"SELECT tenant_id FROM t WHERE tenant_id = ?", errQueryTenantColumn},
		{"SELECT a FROM t WHERE tenant_id = ? ORDER BY tenant_id", errQueryTenantColumn},
		{"SELECT a FROM t WHERE tenant_id = ? AND lower(tenant_id) = b", errQueryTenantColumn},
		{"DELETE FROM t WHERE tenant_id = ? AND tenant_id IS NOT NULL", errQueryTenantColumn},
		{"UPDATE blocklist_entries SET comment = ((?, 'cidr', '10.0.0.0/8') IN tenant_network_rules) WHERE tenant_id = ?", errQuerySingleTable},
		{"INSERT INTO t (a, tenant_id) VALUES ((? IN u), ?)", errQuerySingleTable},
		{"INSERT INTO t (a, tenant_id) VALUES ((SELECT 1), ?) VALUES", errQuerySingleTable},
		{"INSERT INTO t (tenant_id, a) VALUES (?, substring(? FROM 2))", errQuerySingleTable},
		{"INSERT INTO t (a, tenant_id) VALUES ((SELECT b FROM u), ?)", errQuerySingleTable},
		{"SELECT a FROM t x WHERE u.tenant_id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE x.tenant_id = ?", errQueryNoTenant},
		// Tenant slot rule.
		{"SELECT a FROM t WHERE tenant_id = ? AND tenant_id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE b = ? AND NOT tenant_id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE b = ? AND tenant_id = ? IS NULL", errQueryNoTenant},
		{"SELECT a FROM t WHERE (b = ? OR tenant_id = ?)", errQueryNoTenant},
		{"SELECT a FROM t WHERE b = ? AND (c = 1 OR tenant_id = ?)", errQueryNoTenant},
		{"SELECT count(*) FROM t WHERE b = 1 GROUP BY a HAVING count(*) > 1 AND tenant_id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE tenant_id <> ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE tenant_id = ? + 0", errQueryNoTenant},
		{"SELECT a FROM t WHERE tenant_id = ? IS NOT NULL", errQueryNoTenant},
		{"SELECT a FROM t WHERE tenant_id = ? = 0", errQueryNoTenant},
		{"SELECT a FROM t WHERE tenant_id = ? COLLATE nocase", errQueryNoTenant},
		{"SELECT a FROM t WHERE other_tenant_id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE 'tenant_id' = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE (tenant_id = ?)", errQueryNoTenant},
		{"UPDATE t SET tenant_id = ? WHERE tenant_id = ?", errQueryNoTenant},
		{"UPDATE t SET tenant_id = ? WHERE id = ?", errQueryNoTenant},
		{"UPDATE t SET tenant_id = 'x' WHERE tenant_id = ?", errQueryNoTenant},
		{"UPDATE t SET a = ? WHERE id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE b = ? WHERE tenant_id = ?", errQueryNoTenant},
		{"SELECT a FROM t WHERE tenant_id = ? WHERE c = 1", errQueryNoTenant},
		// INSERT shape.
		{"INSERT INTO t (tenant_id, a) VALUES (? || ?, ?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, a) VALUES (?", errQueryParens},
		{"INSERT INTO t (tenant_id, a, tenant_id) VALUES (?, ?, ?)", errQueryInsertShape},
		{"INSERT INTO t (a, tenant_id) VALUES (?, ? || 'x')", errQueryInsertShape},
		{"INSERT INTO t (a, tenant_id) VALUES (?)", errQueryInsertShape},
		{"INSERT INTO t (a, t.tenant_id) VALUES (?, ?)", errQueryInsertShape},
		{"INSERT INTO t (a, tenant_id) VALUES (tenant_id, ?)", errQueryInsertShape},
		{"INSERT INTO t (a b, tenant_id) VALUES (?, ?)", errQueryInsertShape},
		{"INSERT INTO t (a) VALUES (?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, a) VALUES (?, (?)) RETURNING a", errQueryInsertShape},
		{"INSERT t (tenant_id) VALUES (?)", errQueryInsertShape},
		{"INSERT INTO t VALUES (?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, a) VALUES ('x', ?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, a) VALUES (?, ?), (?, ?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, a) VALUES (?, ?) ON CONFLICT DO NOTHING", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, a) VALUES (?, ?) RETURNING a", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, ?) VALUES (?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id, f(a)) VALUES (?)", errQueryInsertShape},
		{"INSERT INTO t (tenant_id", errQueryParens},
		{"INSERT INTO", errQueryInsertShape},
		{"INSERT INTO t (tenant_id) VALUES", errQueryInsertShape},
	}
	for _, tt := range invalid {
		if _, _, err := validateTenantQuery(tt.q, true); !errors.Is(err, tt.want) {
			t.Errorf("validateTenantQuery(%q) = %v, want %v", tt.q, err, tt.want)
		}
	}

	// Reviewed queries: the single-table rule is lifted, the others are not.
	reviewedValid := []struct {
		q    string
		slot int
	}{
		{"SELECT a FROM t JOIN u ON u.x = t.x AND u.y = ? WHERE t.tenant_id = ?", 1},
		{"SELECT a FROM t WHERE x IN (SELECT y FROM u WHERE z = ?) AND tenant_id = ?", 1},
		{"SELECT a FROM t WHERE u.tenant_id = ?", 0},
	}
	for _, tt := range reviewedValid {
		if slot, _, err := validateTenantQuery(tt.q, false); err != nil || slot != tt.slot {
			t.Errorf("reviewed %q = %d, %v; want %d", tt.q, slot, err, tt.slot)
		}
	}
	reviewedInvalid := []struct {
		q    string
		want error
	}{
		{"SELECT a FROM t WHERE tenant_id = ? AND x IN (SELECT y FROM u WHERE tenant_id = ?)", errQueryNoTenant},
		{"SELECT a FROM t WHERE x IN (SELECT y FROM u WHERE tenant_id = ?)", errQueryNoTenant},
		{"SELECT a FROM t JOIN u ON u.tenant_id = ? WHERE tenant_id = ?", errQueryNoTenant},
		{"UPDATE t SET a = (SELECT b FROM u WHERE tenant_id = ?) WHERE id = ?", errQueryNoTenant},
		{"INSERT INTO t (a, tenant_id) VALUES ((SELECT tenant_id FROM u), ?)", errQueryInsertShape},
		{`UPDATE t SET "tenant_id" = ? WHERE tenant_id = ?`, errQueryQuotedIdent},
	}
	for _, tt := range reviewedInvalid {
		if _, _, err := validateTenantQuery(tt.q, false); !errors.Is(err, tt.want) {
			t.Errorf("reviewed %q = %v, want %v", tt.q, err, tt.want)
		}
	}
}

func TestValidateSystemQuery(t *testing.T) {
	t.Parallel()
	if n, err := validateSystemQuery("SELECT a FROM t WHERE b = ? AND c = ?", "because"); err != nil || n != 2 {
		t.Errorf("valid system query = %d, %v", n, err)
	}
	tests := []struct {
		q, reason string
		want      error
	}{
		{"SELECT 1", "  ", errQueryNoReason},
		{"SELECT 1; SELECT 2", "r", errQueryMulti},
		{`SELECT "a" FROM t`, "r", errQueryQuotedIdent},
		{"SELECT a FROM t WHERE b = ?2", "r", errQueryBindSyntax},
		{"SELECT set_config('app.system_scope', 'on', true)", "r", errQueryForbidden},
		{"SELECT a FROM pg_roles", "r", errQueryForbidden},
		{"SELECT E'x'", "r", errQueryLiteralPrefix},
		{"SELECT 1 /* /* */", "r", errQueryUnterminated},
	}
	for _, tt := range tests {
		if _, err := validateSystemQuery(tt.q, tt.reason); !errors.Is(err, tt.want) {
			t.Errorf("validateSystemQuery(%q) = %v, want %v", tt.q, err, tt.want)
		}
	}
}

func TestQueryConstructorsPanic(t *testing.T) {
	t.Parallel()
	before := len(registeredQueries())
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		f()
	}
	mustPanic("tenantQuery", func() { tenantQuery("SELECT a FROM t") })
	mustPanic("tenantQuery multi-table", func() { tenantQuery("SELECT a FROM t JOIN u ON u.x = t.x WHERE t.tenant_id = ?") })
	mustPanic("reviewedTenantQuery without reason", func() { reviewedTenantQuery("SELECT a FROM t WHERE tenant_id = ?", " ") })
	mustPanic("reviewedTenantQuery invalid", func() { reviewedTenantQuery("SELECT a FROM t", "reviewed") })
	mustPanic("systemQuery", func() { systemQuery("SELECT 1", "") })
	if after := len(registeredQueries()); after != before {
		t.Errorf("rejected queries were registered: %d -> %d", before, after)
	}
}

// qTestReviewed is declared by the tests only, to exercise the reviewed
// escape hatch.
var qTestReviewed = reviewedTenantQuery(
	`SELECT r.value FROM tenant_network_rules r JOIN tenants t ON t.id = r.tenant_id WHERE r.tenant_id = ?`,
	"test only: exercises reviewedTenantQuery")

// TestRegistryTenantQueries re-validates every registered tenant query and
// checks its recorded slot, placeholder count and PostgreSQL form.
func TestRegistryTenantQueries(t *testing.T) {
	t.Parallel()
	n := 0
	for _, q := range registeredQueries() {
		if q.kind != kindTenant {
			continue
		}
		n++
		slot, count, err := validateTenantQuery(q.text, !q.reviewed)
		if err != nil || slot != q.slot || count != q.placeholders {
			t.Errorf("registered tenant query %q: slot %d, count %d, %v; recorded %d, %d", q.text, slot, count, err, q.slot, q.placeholders)
		}
		if (q.reason != "") != q.reviewed {
			t.Errorf("tenant query %q: reason %q, reviewed %v", q.text, q.reason, q.reviewed)
		}
		if q.numbered != rebindNumbered(q.text) {
			t.Errorf("tenant query %q has an inconsistent PostgreSQL form %q", q.text, q.numbered)
		}
		param := fmt.Sprintf(`\$%d\b`, q.slot+1)
		if !regexp.MustCompile(`(?i)(tenant_id\s*=\s*` + param + `|VALUES\s*\(.*` + param + `)`).MatchString(q.numbered) {
			t.Errorf("tenant query %q does not bind the tenant at its slot: %q", q.text, q.numbered)
		}
	}
	if n == 0 {
		t.Fatal("no tenant query registered")
	}
}

// normalizeSQL collapses whitespace so that the allowlists below are
// insensitive to indentation.
func normalizeSQL(s string) string { return strings.Join(strings.Fields(s), " ") }

// tenantAllowlist pins every single-table tenant query (normalized SQL) with
// its tenant slot. Adding or changing a tenant query requires a visible
// update of this list.
var tenantAllowlist = map[string]int{
	`SELECT kind, value FROM tenant_network_rules WHERE tenant_id = ?`:                                                         0,
	`DELETE FROM tenant_network_rules WHERE tenant_id = ?`:                                                                     0,
	`INSERT INTO tenant_network_rules (tenant_id, kind, value) VALUES (?, ?, ?)`:                                               0,
	`INSERT INTO blocklist_entries (tenant_id, id, kind, value, comment, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`: 0,
	`SELECT ` + blockColumns + ` FROM blocklist_entries WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ?`:                    0,
	`SELECT ` + blockColumns + ` FROM blocklist_entries WHERE tenant_id = ? AND kind = ? AND id > ? ORDER BY id LIMIT ?`:       0,
	`DELETE FROM blocklist_entries WHERE tenant_id = ? AND id = ?`:                                                             0,
	`SELECT ` + blockColumns + ` FROM blocklist_entries WHERE tenant_id = ? AND ( (kind = 'email' AND value = ?) ` +
		`OR (kind = 'sha256' AND value = ?) OR (kind = 'domain' AND (value = ? OR ? LIKE ('%.' || value))) ) ORDER BY id`: 0,
	`INSERT INTO wrapped_keys (tenant_id, id, purpose, key_id, blob, created_at) VALUES (?, ?, ?, ?, ?, ?)`: 0,
	`SELECT ` + wrappedKeyColumns + ` FROM wrapped_keys WHERE tenant_id = ? AND id = ?`:                     0,
	`DELETE FROM wrapped_keys WHERE tenant_id = ? AND id = ?`:                                               0,
	// SMTP settings.
	`SELECT ` + smtpColumns + ` FROM tenant_smtp_settings WHERE tenant_id = ?`: 0,
	`UPDATE tenant_smtp_settings SET host = ?, port = ?, security = ?, username = ?, password_key_id = ?, ` +
		`from_address = ?, from_name = ?, updated_at = ? WHERE tenant_id = ?`: 8,
	`INSERT INTO tenant_smtp_settings (tenant_id, host, port, security, username, password_key_id, ` +
		`from_address, from_name, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	// Verification challenges.
	`INSERT INTO verification_challenges (tenant_id, id, email, code_mac, attempts_remaining, invitation_id, ` +
		`client_ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	`SELECT ` + challengeColumns + ` FROM verification_challenges WHERE tenant_id = ? AND id = ?`:            0,
	`SELECT count(*) FROM verification_challenges WHERE tenant_id = ? AND email = ? AND created_at >= ?`:     0,
	`SELECT count(*) FROM verification_challenges WHERE tenant_id = ? AND client_ip = ? AND created_at >= ?`: 0,
	`DELETE FROM verification_challenges WHERE tenant_id = ? AND id = ?`:                                     0,
	`UPDATE verification_challenges SET attempts_remaining = attempts_remaining - 1 ` +
		`WHERE tenant_id = ? AND id = ? AND attempts_remaining > 0 AND consumed_at IS NULL AND expires_at > ? ` +
		`RETURNING attempts_remaining`: 0,
	`UPDATE verification_challenges SET consumed_at = ? ` +
		`WHERE tenant_id = ? AND id = ? AND attempts_remaining > 0 AND consumed_at IS NULL AND expires_at > ?`: 1,
	// Verified addresses.
	`SELECT ` + verifiedColumns + ` FROM verified_addresses WHERE tenant_id = ? AND email = ?`:        0,
	`SELECT last_used_at, recognition_salt FROM verified_addresses WHERE tenant_id = ? AND email = ?`: 0,
	`UPDATE verified_addresses SET last_used_at = ? WHERE tenant_id = ? AND email = ?`:                1,
	`UPDATE verified_addresses SET last_used_at = ?, internal_verified_at = COALESCE(internal_verified_at, ?), ` +
		`internal_verified_ip = COALESCE(internal_verified_ip, ?) WHERE tenant_id = ? AND email = ?`: 3,
	`UPDATE verified_addresses SET first_verified_at = ?, first_verified_ip = ?, internal_verified_at = ?, ` +
		`internal_verified_ip = ?, recognition_salt = ?, last_used_at = ? WHERE tenant_id = ? AND email = ?`: 6,
	`INSERT INTO verified_addresses (tenant_id, email, first_verified_at, first_verified_ip, ` +
		`internal_verified_at, internal_verified_ip, recognition_salt, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	`UPDATE verified_addresses SET recognition_salt = ? WHERE tenant_id = ? AND email = ?`: 1,
	// Deposit sessions.
	`INSERT INTO deposit_sessions (tenant_id, id, token_hash, email, kind, invitation_id, created_at, expires_at) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	`SELECT ` + sessionColumns + ` FROM deposit_sessions ` +
		`WHERE tenant_id = ? AND token_hash = ? AND ended_at IS NULL AND expires_at > ?`: 0,
	`UPDATE deposit_sessions SET ended_at = ? ` +
		`WHERE tenant_id = ? AND token_hash = ? AND ended_at IS NULL AND expires_at > ?`: 1,
	// Invitations.
	`INSERT INTO invitations (tenant_id, id, token_hash, email, invited_by, message, language, created_at, expires_at) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	`SELECT ` + invitationColumns + ` FROM invitations WHERE tenant_id = ? AND id = ?`:         0,
	`SELECT ` + invitationColumns + ` FROM invitations WHERE tenant_id = ? AND token_hash = ?`: 0,
	`UPDATE invitations SET last_used_at = ?, expires_at = (CASE WHEN expires_at < ? THEN ? ELSE expires_at END) ` +
		`WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL AND expires_at > ?`: 3,
	`SELECT count(*) FROM invitations WHERE tenant_id = ? AND invited_by = ? AND created_at >= ?`: 0,
	`DELETE FROM invitations WHERE tenant_id = ? AND id = ?`:                                      0,
	`UPDATE invitations SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`: 1,
	// Transfers and recipients.
	`INSERT INTO transfers (tenant_id, id, status, sender_email, sender_kind, invitation_id, message, language, ` +
		`expiry_days, password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint, ` +
		`created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	`UPDATE transfers SET idempotency_key = NULL ` +
		`WHERE tenant_id = ? AND sender_email = ? AND idempotency_key = ? AND created_at < ?`: 0,
	`SELECT ` + transferColumns + ` FROM transfers WHERE tenant_id = ? AND id = ?`: 0,
	`SELECT ` + transferColumns + ` FROM transfers ` +
		`WHERE tenant_id = ? AND sender_email = ? AND idempotency_key = ? AND created_at >= ?`: 0,
	`SELECT count(*) FROM transfers WHERE tenant_id = ? AND id = ?`: 0,
	`SELECT count(*) FROM transfers ` +
		`WHERE tenant_id = ? AND sender_email = ? AND status = 'uploading' AND created_at >= ?`: 0,
	`SELECT ` + transferColumns + ` FROM transfers ` +
		`WHERE tenant_id = ? AND sender_email = ? AND status = 'uploading' AND created_at >= ? ` +
		`ORDER BY created_at DESC, id DESC LIMIT ?`: 0,
	`SELECT CAST(COALESCE(sum(total_bytes), 0) AS BIGINT) FROM transfers ` +
		`WHERE tenant_id = ? AND status IN ('uploading', 'scanning', 'available')`: 0,
	`UPDATE transfers SET status = ?, ended_at = COALESCE(ended_at, ?) WHERE tenant_id = ? AND id = ? AND status = ? ` +
		`AND download_token_key_id IS NULL`: 2,
	`UPDATE transfers SET status = 'scanning', finalized_at = ?, expires_at = ? + expiry_days * CAST(86400000 AS BIGINT) ` +
		`WHERE tenant_id = ? AND id = ? AND status = 'uploading'`: 2,
	`UPDATE transfers SET total_bytes = total_bytes - ? WHERE tenant_id = ? AND id = ?`:               1,
	`DELETE FROM transfers WHERE tenant_id = ? AND id = ? AND download_token_key_id IS NULL`:          0,
	`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, ?, ?, ?)`:   0,
	`SELECT email FROM transfer_recipients WHERE tenant_id = ? AND transfer_id = ? ORDER BY position`: 0,
	// Transfer files.
	`INSERT INTO transfer_files (tenant_id, id, transfer_id, position, name, size, media_type, expected_sha256, ` +
		`sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`: 0,
	`SELECT ` + fileColumns + ` FROM transfer_files WHERE tenant_id = ? AND transfer_id = ? ORDER BY position`: 0,
	`SELECT ` + fileColumns + ` FROM transfer_files WHERE tenant_id = ? AND upload_id = ?`:                     0,
	`SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND id = ?`:                                       0,
	`SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND transfer_id = ? AND dek_key_id IS NOT NULL`:   0,
	`UPDATE transfer_files SET sha256 = ?, ciphertext_size = ?, uploaded_at = ? ` +
		`WHERE tenant_id = ? AND id = ? AND uploaded_at IS NULL`: 3,
	`UPDATE transfer_files SET dek_key_id = ?, storage_name = ? ` +
		`WHERE tenant_id = ? AND id = ? AND uploaded_at IS NULL`: 2,
	`DELETE FROM transfer_files WHERE tenant_id = ? AND id = ? AND dek_key_id IS NULL RETURNING transfer_id, size`: 0,
	// Antivirus analysis and download links.
	`UPDATE transfers SET status = 'available', download_token_hash = ?, download_token_key_id = ?, available_at = ?, ` +
		`expires_at = ? + expiry_days * CAST(86400000 AS BIGINT) WHERE tenant_id = ? AND id = ? AND status = 'scanning'`: 4,
	`SELECT ` + transferColumns + ` FROM transfers WHERE tenant_id = ? AND download_token_hash = ?`: 0,
	`UPDATE transfer_files SET scan_status = 'scanning' ` +
		`WHERE tenant_id = ? AND id = ? AND uploaded_at IS NOT NULL AND scan_status IN ('pending', 'scanning')`: 0,
	`UPDATE transfer_files SET scan_status = ?, scan_signature = ?, scanned_at = ? ` +
		`WHERE tenant_id = ? AND id = ? AND uploaded_at IS NOT NULL AND scan_status IN ('pending', 'scanning')`: 3,
	`UPDATE transfer_files SET scan_attempts = scan_attempts + 1 ` +
		`WHERE tenant_id = ? AND id = ? AND scan_status IN ('pending', 'scanning') RETURNING scan_attempts`: 0,
	// First download and deletion after it.
	`UPDATE transfers SET first_downloaded_at = ? WHERE tenant_id = ? AND id = ? AND status = 'available' ` +
		`AND first_downloaded_at IS NULL AND NOT delete_after_first_download`: 1,
	`UPDATE transfers SET first_downloaded_at = ?, delete_after = ? WHERE tenant_id = ? AND id = ? ` +
		`AND status = 'available' AND first_downloaded_at IS NULL AND delete_after_first_download`: 2,
	`UPDATE transfers SET status = 'deleted', ended_at = ? ` +
		`WHERE tenant_id = ? AND id = ? AND status = 'available' AND download_token_key_id IS NULL`: 1,
	// Transfer password failures.
	`SELECT fail_1, fail_2, fail_3, locked_until FROM password_failures WHERE tenant_id = ? AND scope = ? AND key = ?`: 0,
	`INSERT INTO password_failures (tenant_id, scope, key, fail_1, fail_2, fail_3, locked_until) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?)`: 0,
	`UPDATE password_failures SET fail_1 = ?, fail_2 = ?, fail_3 = ?, locked_until = ? ` +
		`WHERE tenant_id = ? AND scope = ? AND key = ?`: 4,
	`DELETE FROM password_failures WHERE tenant_id = ? AND scope = ? AND key = ?`: 0,
	// Periodic cleanup (cleanup.go): expiry, purges and disk reconciliation.
	`UPDATE transfers SET status = 'expired', ended_at = ? WHERE tenant_id = ? AND id = ? ` +
		`AND status IN ('uploading', 'scanning', 'available') AND download_token_key_id IS NULL`: 1,
	`SELECT id FROM transfers WHERE tenant_id = ? AND status IN ('rejected', 'expired', 'deleted') AND ended_at <= ? ` +
		`ORDER BY ended_at, id LIMIT ?`: 0,
	`SELECT id FROM transfers WHERE tenant_id = ? AND status = ? ORDER BY id LIMIT ?`:                               0,
	`SELECT id, status FROM transfers WHERE tenant_id = ? LIMIT ?`:                                                  0,
	`SELECT storage_name, id, transfer_id, dek_key_id, uploaded_at FROM transfer_files WHERE tenant_id = ? LIMIT ?`: 0,
	`SELECT count(*) FROM transfers WHERE tenant_id = ? AND invitation_id = ?`:                                      0,
	`DELETE FROM verified_addresses WHERE tenant_id = ? AND email = ? AND last_used_at = ?`:                         0,
	`DELETE FROM deposit_sessions WHERE tenant_id = ? AND id = ? AND (ended_at IS NOT NULL OR expires_at <= ?)`:     0,
	`SELECT id FROM verification_challenges WHERE tenant_id = ? AND (consumed_at IS NOT NULL OR expires_at <= ?) ` +
		`AND created_at < ? AND id > ? ORDER BY id LIMIT ?`: 0,
	`DELETE FROM verification_challenges WHERE tenant_id = ? AND id = ? AND (consumed_at IS NOT NULL OR expires_at <= ?) ` +
		`AND created_at < ?`: 0,
	`SELECT id FROM deposit_sessions WHERE tenant_id = ? AND (ended_at IS NOT NULL OR expires_at <= ?) AND id > ? ` +
		`ORDER BY id LIMIT ?`: 0,
	`SELECT key FROM password_failures WHERE tenant_id = ? AND scope = ? AND COALESCE(fail_1, 0) <= ? ` +
		`AND COALESCE(fail_2, 0) <= ? AND COALESCE(fail_3, 0) <= ? AND COALESCE(locked_until, 0) <= ? AND key > ? ` +
		`ORDER BY key LIMIT ?`: 0,
	`DELETE FROM password_failures WHERE tenant_id = ? AND scope = ? AND key = ? AND COALESCE(fail_1, 0) <= ? ` +
		`AND COALESCE(fail_2, 0) <= ? AND COALESCE(fail_3, 0) <= ? AND COALESCE(locked_until, 0) <= ?`: 0,
	`SELECT email, last_used_at FROM verified_addresses WHERE tenant_id = ? AND last_used_at <= ? AND email > ? ` +
		`ORDER BY email LIMIT ?`: 0,
	`SELECT id FROM invitations WHERE tenant_id = ? AND (revoked_at IS NOT NULL OR expires_at <= ?) AND created_at < ? ` +
		`AND id > ? ORDER BY id LIMIT ?`: 0,
	`DELETE FROM invitations WHERE tenant_id = ? AND id = ? AND (revoked_at IS NOT NULL OR expires_at <= ?) ` +
		`AND created_at < ?`: 0,
	`INSERT INTO audit_events (id, at, tenant_id, actor_kind, actor, ip, action, object_kind, object_id, details) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`: 2,
	`SELECT id, at, actor_kind, actor, ip, action, object_kind, object_id, details FROM audit_events WHERE tenant_id = ? ` +
		`AND at >= ? AND at <= ? AND (? = '' OR action = ?) AND (? = '' OR actor = ?) AND (at, id) < (?, ?) ` +
		`ORDER BY at DESC, id DESC LIMIT ?`: 0,
	// Declared by the tests (internal_test.go).
	`INSERT INTO tenant_network_rules (kind, value, tenant_id) VALUES (?, ?, ?)`:               2,
	`SELECT count(*) FROM tenant_network_rules WHERE kind = ? AND value = ? AND tenant_id = ?`: 2,
	`DELETE FROM tenant_network_rules WHERE value = ? AND tenant_id = ? AND kind = ?`:          1,
}

// reviewedAllowlist pins every reviewed (multi-table) tenant query with its
// review reason. Each entry needs a security review.
var reviewedAllowlist = map[string]string{
	// Declared by the tests (above).
	`SELECT r.value FROM tenant_network_rules r JOIN tenants t ON t.id = r.tenant_id WHERE r.tenant_id = ?`: "test only: exercises reviewedTenantQuery",
}

func TestRegistryTenantQueriesAllowlist(t *testing.T) {
	t.Parallel()
	gotTenant, gotReviewed := map[string]int{}, map[string]string{}
	for _, q := range registeredQueries() {
		key := normalizeSQL(q.text)
		switch {
		case q.kind == kindTenant && q.reviewed:
			gotReviewed[key] = q.reason
		case q.kind == kindTenant:
			if _, dup := gotTenant[key]; dup {
				t.Errorf("tenant query declared twice: %q", key)
			}
			gotTenant[key] = q.slot
		}
	}
	for k, slot := range gotTenant {
		if want, ok := tenantAllowlist[k]; !ok || want != slot {
			t.Errorf("tenant query not in the allowlist (or slot %d differs): %q", slot, k)
		}
	}
	for k := range tenantAllowlist {
		if _, ok := gotTenant[k]; !ok {
			t.Errorf("allowlisted tenant query is not registered: %q", k)
		}
	}
	for k, reason := range gotReviewed {
		if want, ok := reviewedAllowlist[k]; !ok || want != reason {
			t.Errorf("reviewed tenant query not in the allowlist: %q (reason %q)", k, reason)
		}
	}
	for k := range reviewedAllowlist {
		if _, ok := gotReviewed[k]; !ok {
			t.Errorf("allowlisted reviewed query is not registered: %q", k)
		}
	}
	if qTestReviewed.tenant == nil || !qTestReviewed.tenant.reviewed {
		t.Error("qTestReviewed is not marked as reviewed")
	}
}

// systemAllowlist pins every statement allowed to cross tenants, with its
// reason. Adding a system query requires a conscious update of this list
// (and a security review).
var systemAllowlist = map[string]string{
	`CREATE TABLE IF NOT EXISTS schema_migrations ( version BIGINT NOT NULL PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at BIGINT NOT NULL )`: "schema migrations: create the bookkeeping table",
	`SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`:                                                                           "schema migrations: read the applied versions",
	`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`:                                                                      "schema migrations: record an applied version",
	`INSERT INTO tenants (` + tenantColumns + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`:                                                                                  reasonTenantAdmin,
	`SELECT ` + tenantColumns + ` FROM tenants WHERE id = ?`:                                                                                                       reasonTenantAdmin,
	`SELECT ` + tenantColumns + ` FROM tenants WHERE fqdn = ?`:                                                                                                     reasonTenantResolve,
	`SELECT ` + tenantColumns + ` FROM tenants WHERE id > ? ORDER BY id LIMIT ?`:                                                                                   reasonTenantAdmin,
	`UPDATE tenants SET name = ?, fqdn = ?, default_language = ?, max_transfer_bytes = ?, storage_quota_bytes = ?, updated_at = ? WHERE id = ?`:                    reasonTenantAdmin,
	`DELETE FROM tenants WHERE id = ?`: reasonTenantAdmin,
	// Master keys (startup check and rotation).
	`SELECT key_id FROM wrapped_keys UNION SELECT key_id FROM system_secrets ORDER BY key_id`:                                                     reasonKeyCheck,
	`SELECT (SELECT count(*) FROM wrapped_keys WHERE key_id = ?) + (SELECT count(*) FROM system_secrets WHERE key_id = ?)`:                        reasonKeyRotation,
	`SELECT tenant_id, ` + wrappedKeyColumns + ` FROM wrapped_keys WHERE key_id = ? ORDER BY id LIMIT ?`:                                          reasonKeyRotation,
	`UPDATE wrapped_keys SET blob = ?, key_id = ? WHERE id = ? AND key_id = ?`:                                                                    reasonKeyRotation,
	`SELECT id, status, created_at, retired_at FROM master_keys ORDER BY created_at, id`:                                                          reasonKeyCheck,
	`SELECT id FROM master_keys WHERE status = 'active'`:                                                                                          reasonKeyCheck,
	`SELECT count(*) FROM master_keys`:                                                                                                            reasonKeyCheck,
	`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES (?, 'active', ?, NULL)`:                                                  reasonKeyCheck,
	`UPDATE master_keys SET status = 'retired', retired_at = ? WHERE status = 'active' AND id <> ?`:                                               reasonKeyRotation,
	`SELECT status FROM master_keys WHERE id = ?`:                                                                                                 reasonKeyRotation,
	`INSERT INTO master_keys (id, status, created_at) VALUES (?, 'active', ?)`:                                                                    reasonKeyRotation,
	`INSERT INTO key_rotations (id, from_key_id, to_key_id, status, total_keys, rewrapped_keys, started_at) VALUES (?, ?, ?, 'running', ?, 0, ?)`: reasonKeyRotation,
	`SELECT ` + rotationColumns + ` FROM key_rotations WHERE id = ?`:                                                                              reasonKeyRotation,
	`SELECT ` + rotationColumns + ` FROM key_rotations WHERE status = 'running'`:                                                                  reasonKeyRotation,
	`SELECT ` + rotationColumns + ` FROM key_rotations ORDER BY started_at DESC, id DESC LIMIT 1`:                                                 reasonKeyRotation,
	`UPDATE key_rotations SET rewrapped_keys = rewrapped_keys + ? WHERE id = ? AND status = 'running' AND from_key_id = ? AND to_key_id = ?`:      reasonKeyRotation,
	`UPDATE key_rotations SET status = ?, completed_at = ?, error = ? WHERE id = ? AND status = 'running'`:                                        reasonKeyRotation,
	// Antivirus worker start-up sweep (identifiers only).
	`SELECT tenant_id, id FROM transfers WHERE status = 'scanning' ORDER BY finalized_at, id LIMIT ?`: reasonAntivirusSweep,
	// Deletion after the first download (identifiers only).
	`SELECT tenant_id, id, delete_after FROM transfers WHERE delete_after IS NOT NULL AND delete_after <= ? ` +
		`AND status = 'available' AND (delete_after, tenant_id, id) > (?, ?, ?) ` +
		`ORDER BY delete_after, tenant_id, id LIMIT ?`: reasonDeleteAfterDownload,
	// Periodic cleanup (identifiers only).
	`SELECT tenant_id, id, due_at FROM ( ` +
		`SELECT tenant_id, id, expires_at AS due_at FROM transfers WHERE status = 'available' AND expires_at <= ? ` +
		`UNION ALL ` +
		`SELECT tenant_id, id, finalized_at + ? AS due_at FROM transfers WHERE status = 'scanning' AND finalized_at <= ? ` +
		`) d WHERE (due_at, tenant_id, id) > (?, ?, ?) ORDER BY due_at, tenant_id, id LIMIT ?`: reasonExpirySweep,
	`SELECT tenant_id, id, ended FROM ( ` +
		`SELECT t.tenant_id, t.id, COALESCE(t.ended_at, 0) AS ended FROM transfers t ` +
		`WHERE t.status = 'rejected' AND EXISTS (SELECT 1 FROM transfer_files f ` +
		`WHERE f.tenant_id = t.tenant_id AND f.transfer_id = t.id AND f.dek_key_id IS NOT NULL) ` +
		`) r WHERE (ended, tenant_id, id) > (?, ?, ?) ORDER BY ended, tenant_id, id LIMIT ?`: reasonExpirySweep,
	`SELECT tenant_id, id, created_at FROM transfers WHERE status = 'uploading' AND created_at <= ? ` +
		`AND (created_at, tenant_id, id) > (?, ?, ?) ORDER BY created_at, tenant_id, id LIMIT ?`: reasonAbandonedSweep,
	`SELECT id FROM tenants ORDER BY id`: reasonCleanupTenants,
	// Administration (0008_admin): system tables, no tenant.
	`DELETE FROM admin_tenants WHERE admin_id = ?`:                  reasonAdminAccounts,
	`DELETE FROM admins WHERE id = ?`:                               reasonAdminAccounts,
	`INSERT INTO admin_tenants (admin_id, tenant_id) VALUES (?, ?)`: reasonAdminAccounts,
	`INSERT INTO admins (id, username, email, role, password_hash, require_totp, disabled, language, created_at, updated_at, credentials_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`: reasonAdminAccounts,
	`SELECT admin_id, tenant_id FROM admin_tenants WHERE admin_id > ? AND admin_id <= ? ORDER BY admin_id, tenant_id`:                                                                          reasonAdminAccounts,
	`SELECT count(*) FROM admins`: reasonAdminAccounts,
	`SELECT count(*) FROM admins WHERE role = 'super_admin' AND disabled = false AND password_hash IS NOT NULL AND totp_enabled = true`:                                                                                                                                      reasonAdminAccounts,
	`SELECT id, username, email, role, password_hash, totp_secret_id, totp_enabled, totp_last_counter, pending_totp_secret_id, require_totp, disabled, language, created_at, updated_at, last_login_at, credentials_changed_at FROM admins WHERE id = ?`:                     reasonAdminAccounts,
	`SELECT id, username, email, role, password_hash, totp_secret_id, totp_enabled, totp_last_counter, pending_totp_secret_id, require_totp, disabled, language, created_at, updated_at, last_login_at, credentials_changed_at FROM admins WHERE id > ? ORDER BY id LIMIT ?`: reasonAdminAccounts,
	`SELECT id, username, email, role, password_hash, totp_secret_id, totp_enabled, totp_last_counter, pending_totp_secret_id, require_totp, disabled, language, created_at, updated_at, last_login_at, credentials_changed_at FROM admins WHERE username = ?`:               reasonAdminAccounts,
	`SELECT tenant_id FROM admin_tenants WHERE admin_id = ? ORDER BY tenant_id`:                                                                                                                                                    reasonAdminAccounts,
	`UPDATE admins SET email = ?, role = ?, require_totp = ?, disabled = ?, language = ?, updated_at = ? WHERE id = ?`:                                                                                                             reasonAdminAccounts,
	`UPDATE admins SET last_login_at = ? WHERE id = ?`:                                                                                                                                                                             reasonAdminAccounts,
	`UPDATE admins SET password_hash = ?, credentials_changed_at = ?, updated_at = ? WHERE id = ?`:                                                                                                                                 reasonAdminAccounts,
	`UPDATE admins SET pending_totp_secret_id = ?, updated_at = ? WHERE id = ?`:                                                                                                                                                    reasonAdminAccounts,
	`UPDATE admins SET totp_last_counter = ? WHERE id = ? AND totp_enabled = true AND (totp_last_counter IS NULL OR totp_last_counter < ?)`:                                                                                        reasonAdminAccounts,
	`UPDATE admins SET totp_secret_id = NULL, pending_totp_secret_id = NULL, totp_enabled = false, totp_last_counter = NULL, credentials_changed_at = ?, updated_at = ? WHERE id = ?`:                                              reasonAdminAccounts,
	`UPDATE admins SET totp_secret_id = pending_totp_secret_id, pending_totp_secret_id = NULL, totp_enabled = true, totp_last_counter = ?, credentials_changed_at = ?, updated_at = ? WHERE id = ? AND pending_totp_secret_id = ?`: reasonAdminAccounts,
	`DELETE FROM admin_activations WHERE admin_id = ?`:                                                                                                                                                                             reasonAdminAuth,
	`DELETE FROM admin_activations WHERE id IN (SELECT id FROM admin_activations WHERE used_at IS NOT NULL OR expires_at <= ? ORDER BY id LIMIT ?)`:                                                                                reasonAdminAuth,
	`DELETE FROM admin_login_failures WHERE (scope, key) IN (SELECT scope, key FROM admin_login_failures WHERE COALESCE(last_failure_at, 0) <= ? AND COALESCE(locked_until, 0) <= ? ORDER BY scope, key LIMIT ?)`:                  reasonAdminAuth,
	`DELETE FROM admin_login_failures WHERE scope = ? AND key = ?`:                                                                                                                                                                 reasonAdminAuth,
	`DELETE FROM admin_recovery_codes WHERE admin_id = ?`:                                                                                                                                                                          reasonAdminAuth,
	`DELETE FROM admin_sessions WHERE admin_id = ? AND id <> ?`:                                                                                                                                                                    reasonAdminAuth,
	`DELETE FROM admin_sessions WHERE id = ?`:                                                                                                                                                                                      reasonAdminAuth,
	`DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions WHERE expires_at <= ? OR last_seen_at <= ? OR state_expires_at <= ? ORDER BY id LIMIT ?)`:                                                               reasonAdminAuth,
	`INSERT INTO admin_activations (id, admin_id, token_hash, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)`:                                                                                                       reasonAdminAuth,
	`INSERT INTO admin_login_failures (scope, key, failures, last_failure_at, locked_until) VALUES (?, ?, ?, ?, ?)`:                                                                                                                reasonAdminAuth,
	`INSERT INTO admin_recovery_codes (admin_id, code_hash, used_at) VALUES (?, ?, NULL)`:                                                                                                                                          reasonAdminAuth,
	`INSERT INTO admin_sessions (id, token_hash, admin_id, state, created_at, last_seen_at, expires_at, state_expires_at, totp_failures, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`:                                         reasonAdminAuth,
	`SELECT count(*) FROM admin_recovery_codes WHERE admin_id = ? AND used_at IS NULL`:                                                                                                                                             reasonAdminAuth,
	`SELECT failures, locked_until FROM admin_login_failures WHERE scope = ? AND key = ?`:                                                                                                                                          reasonAdminAuth,
	`SELECT id, token_hash, admin_id, state, created_at, last_seen_at, expires_at, state_expires_at, totp_failures, client_ip FROM admin_sessions WHERE token_hash = ? AND expires_at > ? AND last_seen_at > ? AND (state_expires_at IS NULL OR state_expires_at > ?)`: reasonAdminAuth,
	`UPDATE admin_activations SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING admin_id`:                                                                                                                                          reasonAdminAuth,
	`UPDATE admin_login_failures SET failures = ?, last_failure_at = ?, locked_until = ? WHERE scope = ? AND key = ?`:                                                                                                                                                  reasonAdminAuth,
	`UPDATE admin_recovery_codes SET used_at = ? WHERE admin_id = ? AND code_hash = ? AND used_at IS NULL`:                                                                                                                                                             reasonAdminAuth,
	`UPDATE admin_sessions SET last_seen_at = ? WHERE id = ? AND expires_at > ? AND last_seen_at > ? AND (state_expires_at IS NULL OR state_expires_at > ?)`:                                                                                                           reasonAdminAuth,
	`UPDATE admin_sessions SET token_hash = ?, state = ?, state_expires_at = ?, totp_failures = 0, last_seen_at = ? WHERE id = ? AND token_hash = ? AND expires_at > ? AND last_seen_at > ? AND (state_expires_at IS NULL OR state_expires_at > ?)`:                    reasonAdminAuth,
	`UPDATE admin_sessions SET totp_failures = totp_failures + 1 WHERE id = ? RETURNING totp_failures`:                                                                                                                                                                 reasonAdminAuth,
	`DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE at < ? ORDER BY at, id LIMIT ?)`:                                                                                                                                                          reasonAudit,
	`INSERT INTO audit_events (id, at, tenant_id, actor_kind, actor, ip, action, object_kind, object_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`:                                                                                                               reasonAudit,
	`SELECT tenant_id, id, at, actor_kind, actor, ip, action, object_kind, object_id, details FROM audit_events WHERE at >= ? AND at <= ? AND (? = '' OR action = ?) AND (? = '' OR actor = ?) AND (at, id) < (?, ?) ORDER BY at DESC, id DESC LIMIT ?`:                reasonAudit,
	`SELECT id, purpose, key_id, blob, created_at FROM system_secrets WHERE key_id = ? ORDER BY id LIMIT ?`:                                                                                                                                                            reasonKeyRotation,
	`UPDATE system_secrets SET blob = ?, key_id = ? WHERE id = ? AND key_id = ?`:                                                                                                                                                                                       reasonKeyRotation,
	`DELETE FROM system_secrets WHERE id = ?`:                                                   reasonSystemSecrets,
	`INSERT INTO system_secrets (id, purpose, key_id, blob, created_at) VALUES (?, ?, ?, ?, ?)`: reasonSystemSecrets,
	`SELECT id, purpose, key_id, blob, created_at FROM system_secrets WHERE id = ?`:             reasonSystemSecrets,
}

func TestRegistrySystemQueriesAllowlist(t *testing.T) {
	t.Parallel()
	got := map[string]string{}
	for _, q := range registeredQueries() {
		if q.kind != kindSystem {
			continue
		}
		key := normalizeSQL(q.text)
		if _, dup := got[key]; dup {
			t.Errorf("system query declared twice: %q", key)
		}
		got[key] = q.reason
	}
	for k, reason := range got {
		want, ok := systemAllowlist[k]
		switch {
		case !ok:
			t.Errorf("system query not in the allowlist: %q (reason %q)", k, reason)
		case want != reason:
			t.Errorf("system query %q: reason %q, allowlist says %q", k, reason, want)
		}
	}
	for k := range systemAllowlist {
		if _, ok := got[k]; !ok {
			t.Errorf("allowlisted system query is not registered: %q", k)
		}
	}
}

func TestQuerySQL(t *testing.T) {
	t.Parallel()
	q := &query{text: "a = ?", numbered: "a = $1"}
	if got := q.sql(sqliteDialect); got != "a = ?" {
		t.Errorf("sqlite form = %q", got)
	}
	if got := q.sql(postgresDialect); got != "a = $1" {
		t.Errorf("postgres form = %q", got)
	}
}

// FuzzRebindNumbered checks that the rewriter never panics, only replaces
// placeholders, and numbers them consecutively.
func FuzzRebindNumbered(f *testing.F) {
	for _, s := range []string{"", "?", "a = ? AND b = '?'", `"x?" = ?`, "-- ?\n?", "/* ? */ ?", "'", "/*"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := rebindNumbered(s)
		toks, _ := lexSQL(s)
		n := 0
		for _, tk := range toks {
			if tk.kind == tokPlaceholder {
				n++
			}
		}
		if strings.Count(out, "$") < n {
			t.Fatalf("rebindNumbered(%q) = %q: expected %d numbered placeholders", s, out, n)
		}
		if n == 0 && out != s {
			t.Fatalf("rebindNumbered(%q) changed a statement without placeholders: %q", s, out)
		}
	})
}

// FuzzValidateTenantQuery checks that the validator never panics and that
// every accepted single-table statement has a single tenant slot at the
// recorded index, one table, and none of the forbidden tokens.
func FuzzValidateTenantQuery(f *testing.F) {
	for _, s := range validatorSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		slot, count, err := validateTenantQuery(s, true)
		if err != nil {
			return
		}
		toks, ok := lexSQL(s)
		if !ok {
			t.Fatalf("accepted an unterminated statement: %q", s)
		}
		at, n, depth, slots := -1, 0, 0, 0
		for i, tk := range toks {
			if isSlot(toks, i) {
				slots++
			}
			switch {
			case tk.kind == tokQuotedIdent, tk.is("JOIN"), tk.is("USING"), tk.is("SELECT") && i > 0:
				t.Fatalf("accepted %q with %s", s, tk.text)
			case tk.is("("):
				depth++
			case tk.is(")"):
				depth--
			case depth == 0 && (tk.is("OR") || tk.is("UNION") || tk.is("CASE") || tk.is("BETWEEN")):
				t.Fatalf("accepted %q with a top-level %s", s, tk.text)
			case tk.kind == tokPlaceholder:
				if i+1 < len(toks) && toks[i+1].pos == tk.end() && toks[i+1].kind == tokWord {
					t.Fatalf("accepted %q with a numbered placeholder", s)
				}
				if n == slot {
					at = i
				}
				n++
			}
		}
		if n != count {
			t.Fatalf("accepted %q: %d placeholders, recorded %d", s, n, count)
		}
		if at < 2 || at+1 > len(toks) {
			t.Fatalf("accepted %q: slot %d is not a placeholder", s, slot)
		}
		if toks[0].is("INSERT") {
			if slots != 0 || (!toks[at-1].is("(") && !toks[at-1].is(",")) ||
				at+1 >= len(toks) || (!toks[at+1].is(",") && !toks[at+1].is(")")) {
				t.Fatalf("accepted %q: tenant value is not a bare placeholder", s)
			}
			return
		}
		if slots != 1 || !toks[at-1].is("=") || !isTenantColumn(toks[at-2]) || at < 3 ||
			(!toks[at-3].is("WHERE") && !toks[at-3].is("AND")) || !endsPredicate(toks, at+1) {
			t.Fatalf("accepted %q: slot %d is not a single top-level tenant_id = ? conjunct", s, slot)
		}
	})
}

// validatorSeeds are the seed inputs of the validator fuzzers.
var validatorSeeds = []string{
	"SELECT a FROM t WHERE tenant_id = ?",
	"INSERT INTO t (tenant_id, a) VALUES (?, ?)",
	"DELETE FROM t WHERE tenant_id = ? AND id = ?",
	"UPDATE t SET a = ?, b = ? WHERE tenant_id = ? AND id = ?",
	"SELECT a FROM t WHERE tenant_id = ? OR 1=1",
	"INSERT INTO t (tenant_id) VALUES (?), (?)",
	`UPDATE t SET "tenant_id" = ? WHERE tenant_id = ? AND id = ?`,
	"SELECT a FROM t WHERE a <> ?5 AND tenant_id = ?",
	"SELECT a FROM t, u WHERE tenant_id = ?",
	"SELECT count(*) FROM blocklist_entries WHERE tenant_id = ? AND (?, 'domain', ?) IN tenant_network_rules",
	"UPDATE blocklist_entries SET comment = ((?, 'cidr', '10.0.0.0/8') IN tenant_network_rules) WHERE tenant_id = ?",
	"SELECT a FROM t WHERE tenant_id = ? AND b IN (TABLE u)",
	"SELECT id || 'x' tenant_id FROM tenants WHERE tenant_id = ?",
	"(((", ")))", "'", "?",
}
