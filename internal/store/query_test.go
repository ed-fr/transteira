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
