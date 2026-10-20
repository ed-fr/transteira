package store

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// tenantColumn is the column carrying the owning tenant in every
// tenant-scoped table.
const tenantColumn = "tenant_id"

// Errors reported by the query validators. They are only ever seen at
// package initialization (as panics) and in tests.
var (
	errQueryEmpty         = errors.New("statement is empty")
	errQueryUnterminated  = errors.New("unterminated or nested string, identifier or comment")
	errQueryMulti         = errors.New("multiple statements are not allowed")
	errQueryBindSyntax    = errors.New("only bare ? placeholders are allowed ($n, ?NNN, :name, @name and #name are forbidden)")
	errQueryQuotedIdent   = errors.New("quoted identifiers (\"x\", `x`, [x]) are forbidden")
	errQueryLiteralPrefix = errors.New("prefixed string literals (E'', U&'', X''...) are forbidden")
	errQueryForbidden     = errors.New("set_config, current_setting, pg_* names and 'app.*' literals are forbidden")
	errQueryVerb          = errors.New("statement must start with SELECT, INSERT, UPDATE or DELETE")
	errQueryTopLevelOr    = errors.New("OR, UNION, INTERSECT, EXCEPT, CASE and BETWEEN are forbidden outside parentheses")
	errQueryParens        = errors.New("unbalanced parentheses")
	errQuerySingleTable   = errors.New("tenant queries must read or write a single table: no JOIN, USING, subquery, " +
		"second table or UPDATE ... FROM (use reviewedTenantQuery)")
	errQueryNoTenant     = errors.New("statement needs exactly one tenant_id = ? slot, as a conjunct of the top-level WHERE")
	errQueryInsertShape  = errors.New("INSERT must be INSERT INTO t (..., tenant_id, ...) VALUES (..., ?, ...) with a single row and no other clause")
	errQueryNoReason     = errors.New("system and reviewed queries need a non-empty reason")
	errQueryUnregistered = errors.New("store: query was not declared with tenantQuery or systemQuery, or has the wrong kind for this executor")
	errQueryArgCount     = errors.New("store: wrong number of arguments for the query")
)

// TenantQuery is an SQL statement restricted to one tenant. It can only be
// declared inside this package, with tenantQuery (or reviewedTenantQuery),
// which validates at package initialization that the statement has exactly
// one tenant slot ("tenant_id = ?" in the top-level WHERE, or the tenant_id
// value of an INSERT) and records its position. Only a [ScopedTx] executes
// it, binding the tenant at that position itself: callers never pass the
// tenant ID as an SQL argument.
//
// TenantQuery and SystemQuery have different field names on purpose: their
// underlying types differ, so neither converts to the other.
type TenantQuery struct {
	tenant *query
}

// SystemQuery is an SQL statement that is not restricted to one tenant
// (tenant administration, host resolution, schema migrations...). It can
// only be declared inside this package, with systemQuery, together with the
// reason it needs to cross tenants. Only a [SystemTx] executes it.
type SystemQuery struct {
	system *query
}

// queryKind distinguishes the two families of registered statements.
type queryKind string

// Query families.
const (
	kindTenant queryKind = "tenant"
	kindSystem queryKind = "system"
)

// query is a validated statement in both placeholder syntaxes.
type query struct {
	kind queryKind
	// text is the statement with "?" placeholders, as declared (SQLite).
	text string
	// numbered is the statement with "$n" placeholders (PostgreSQL).
	numbered string
	// reason explains why a system query crosses tenants, or why a reviewed
	// tenant query may touch several tables ("" otherwise).
	reason string
	// reviewed marks a tenant query exempted from the single-table rule
	// after a security review (reviewedTenantQuery).
	reviewed bool
	// slot is the index, among the placeholders, of the tenant slot of a
	// tenant query (unused for system queries).
	slot int
	// placeholders is the number of "?" in the statement.
	placeholders int
}

// sql returns the statement in the syntax of dialect d.
func (q *query) sql(d *dialect) string {
	if d.numbered {
		return q.numbered
	}
	return q.text
}

// registry holds every statement declared by the package, so that tests can
// check them all.
var registry struct {
	mu      sync.Mutex
	queries []*query
}

// register records q, already validated, in the registry.
func register(q *query) *query {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.queries = append(registry.queries, q)
	return q
}

// registeredQueries returns a copy of the registry.
func registeredQueries() []*query {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return append([]*query(nil), registry.queries...)
}

// tenantQuery declares a single-table tenant-scoped statement. It panics,
// aborting the program at start-up, when the statement does not satisfy
// validateTenantQuery.
func tenantQuery(sql string) TenantQuery {
	slot, n, err := validateTenantQuery(sql, true)
	if err != nil {
		panic(fmt.Sprintf("store: invalid tenant query %q: %v", sql, err))
	}
	return TenantQuery{tenant: register(&query{
		kind: kindTenant, text: sql, numbered: rebindNumbered(sql), slot: slot, placeholders: n,
	})}
}

// reviewedTenantQuery declares a tenant-scoped statement exempted from the
// single-table rule (joins, subqueries...), every other rule still
// applying. Each use requires a security review, recorded in reason, and is
// pinned by an allowlist test: the tenant slot only constrains the target
// table, so every other table the statement reads must be filtered too.
func reviewedTenantQuery(sql, reason string) TenantQuery {
	if strings.TrimSpace(reason) == "" {
		panic(fmt.Sprintf("store: invalid reviewed tenant query %q: %v", sql, errQueryNoReason))
	}
	slot, n, err := validateTenantQuery(sql, false)
	if err != nil {
		panic(fmt.Sprintf("store: invalid reviewed tenant query %q: %v", sql, err))
	}
	return TenantQuery{tenant: register(&query{
		kind: kindTenant, text: sql, numbered: rebindNumbered(sql), slot: slot, placeholders: n,
		reason: reason, reviewed: true,
	})}
}

// systemQuery declares a statement that crosses tenants, with the reason it
// needs to. It panics when the reason is empty or the statement breaks the
// rules shared by every registered statement (see baseTokens).
func systemQuery(sql, reason string) SystemQuery {
	n, err := validateSystemQuery(sql, reason)
	if err != nil {
		panic(fmt.Sprintf("store: invalid system query %q: %v", sql, err))
	}
	return SystemQuery{system: register(&query{
		kind: kindSystem, text: sql, numbered: rebindNumbered(sql), reason: reason, placeholders: n,
	})}
}

// isForbiddenWord reports whether an identifier names the settings used by
// the row-level security policies or the PostgreSQL catalog: set_config,
// current_setting, or any dotted part starting with "pg_".
func isForbiddenWord(w string) bool {
	for _, part := range strings.Split(strings.ToLower(w), ".") {
		if part == "set_config" || part == "current_setting" || strings.HasPrefix(part, "pg_") {
			return true
		}
	}
	return false
}

// baseTokens lexes sql and applies the checks shared by every registered
// statement: one terminated statement without nested comments (a trailing
// semicolon is dropped); bare "?" as the only binding syntax; no quoted
// identifier, which could hide tenant_id from the validator; no prefixed
// string literal; no access to the row-level security settings or to the
// PostgreSQL catalog. It returns the tokens and the number of placeholders.
func baseTokens(sql string) ([]token, int, error) {
	toks, ok := lexSQL(sql)
	if !ok {
		return nil, 0, errQueryUnterminated
	}
	if n := len(toks); n > 0 && toks[n-1].is(";") {
		toks = toks[:n-1]
	}
	if len(toks) == 0 {
		return nil, 0, errQueryEmpty
	}
	placeholders := 0
	for i, t := range toks {
		adjacentPrev := i > 0 && toks[i-1].end() == t.pos
		switch {
		case t.is(";"):
			return nil, 0, errQueryMulti
		case t.kind == tokWord && strings.Contains(t.text, "$"), t.is(":"), t.is("@"), t.is("#"),
			t.kind == tokWord && adjacentPrev && toks[i-1].kind == tokPlaceholder:
			return nil, 0, errQueryBindSyntax
		case t.kind == tokQuotedIdent, t.is("`"), t.is("["), t.is("]"):
			return nil, 0, errQueryQuotedIdent
		case t.kind == tokString && adjacentPrev && (toks[i-1].kind == tokWord || toks[i-1].is("&")):
			return nil, 0, errQueryLiteralPrefix
		case t.kind == tokString && strings.HasPrefix(strings.ToLower(t.text), "'app."),
			t.kind == tokWord && isForbiddenWord(t.text):
			return nil, 0, errQueryForbidden
		case t.kind == tokPlaceholder:
			placeholders++
		}
	}
	return toks, placeholders, nil
}

// validateSystemQuery checks a system statement and its reason, and returns
// its number of placeholders.
func validateSystemQuery(sql, reason string) (int, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, errQueryNoReason
	}
	_, n, err := baseTokens(sql)
	return n, err
}

// validateTenantQuery checks that sql cannot read or write outside the
// tenant bound to its single tenant slot, and returns the position of that
// slot among the statement's placeholders (0 for the first "?") and the
// number of placeholders:
//
//   - the rules shared by every registered statement (see baseTokens);
//   - a single SELECT, INSERT, UPDATE or DELETE statement;
//   - no OR, UNION, INTERSECT or EXCEPT outside parentheses, so that no
//     alternative branch can escape the tenant predicate, and no CASE or
//     BETWEEN outside parentheses, whose own AND could absorb it;
//   - when singleTable is true, a single table (see checkSingleTable), and
//     a qualified tenant column must name that table or its alias;
//   - SELECT, UPDATE and DELETE: exactly one "tenant_id = ?" in the whole
//     statement, a conjunct of the top-level WHERE clause: preceded by
//     WHERE or AND, followed by nothing, AND, ORDER, GROUP or LIMIT, with no
//     other clause keyword in between. An UPDATE never names tenant_id
//     before its WHERE, so it cannot move rows to another tenant;
//   - INSERT: exactly "INSERT INTO t (c1, ..., tenant_id, ...) VALUES (v1,
//     ..., ?, ...)": tenant_id appears once, unqualified, in the column
//     list, and its value is a bare placeholder; one row, nothing after the
//     values list.
//
// The validator is deliberately conservative: it rejects some harmless
// statements, never the reverse for the shapes above. PostgreSQL row-level
// security backs this check up.
func validateTenantQuery(sql string, singleTable bool) (slot, placeholders int, err error) {
	toks, placeholders, err := baseTokens(sql)
	if err != nil {
		return 0, 0, err
	}
	depth := 0
	for _, t := range toks {
		switch {
		case t.is("("):
			depth++
		case t.is(")"):
			depth--
			if depth < 0 {
				return 0, 0, errQueryParens
			}
		case depth == 0 && (t.is("OR") || t.is("UNION") || t.is("INTERSECT") || t.is("EXCEPT") ||
			t.is("CASE") || t.is("BETWEEN")):
			return 0, 0, errQueryTopLevelOr
		}
	}
	if depth != 0 {
		return 0, 0, errQueryParens
	}
	if !toks[0].is("INSERT") && !toks[0].is("SELECT") && !toks[0].is("UPDATE") && !toks[0].is("DELETE") {
		return 0, 0, errQueryVerb
	}
	var names []string // target table and alias, lower case
	if singleTable {
		if names, err = checkSingleTable(toks); err != nil {
			return 0, 0, err
		}
	}
	if toks[0].is("INSERT") {
		slot, err = validateTenantInsert(toks)
	} else {
		slot, err = validateTenantWhere(toks, names)
	}
	return slot, placeholders, err
}

// checkSingleTable enforces the single-table rule and returns the target
// table name and alias (lower case, alias possibly ""): no SELECT other than
// the statement's own (no subquery, derived table or INSERT ... SELECT), no
// JOIN, USING, NATURAL or SELECT ... INTO, and the target written as
// "FROM t [[AS] a] WHERE" (SELECT, DELETE) or "UPDATE t [[AS] a] SET", and
// no FROM in an UPDATE or INSERT.
func checkSingleTable(toks []token) ([]string, error) {
	froms, values := 0, 0
	for i, t := range toks {
		switch {
		case t.is("SELECT") && i > 0, t.is("JOIN"), t.is("USING"), t.is("NATURAL"),
			t.is("INTO") && !toks[0].is("INSERT"),
			// TABLE x, VALUES (...) and EXISTS introduce subqueries without
			// SELECT; "expr IN t" (SQLite) reads table t: IN must open a list.
			t.is("TABLE"), t.is("EXISTS"),
			t.is("IN") && (i+1 >= len(toks) || !toks[i+1].is("(")),
			// An alias named tenant_id could stand for another value.
			t.is("AS") && i+1 < len(toks) && isTenantColumn(toks[i+1]):
			return nil, errQuerySingleTable
		case t.is("VALUES"):
			values++
		case t.is("FROM"):
			froms++
		}
	}
	// VALUES is only allowed as the values list of an INSERT.
	if (toks[0].is("INSERT") && values > 1) || (!toks[0].is("INSERT") && values != 0) {
		return nil, errQuerySingleTable
	}
	switch {
	case toks[0].is("INSERT"):
		// The shape itself is checked by validateTenantInsert; an INSERT
		// slot is never qualified, so no name is needed.
		if froms != 0 {
			return nil, errQuerySingleTable
		}
		return nil, nil
	case toks[0].is("UPDATE"):
		if froms != 0 {
			return nil, errQuerySingleTable
		}
		return parseTarget(toks, 1, "SET")
	case toks[0].is("DELETE"):
		if froms != 1 || len(toks) < 2 || !toks[1].is("FROM") {
			return nil, errQuerySingleTable
		}
		return parseTarget(toks, 2, "WHERE")
	}
	// SELECT: the single FROM must be at depth 0 (not inside a function
	// call such as substring(x FROM 2)).
	depth := 0
	for i, t := range toks {
		switch {
		case t.is("("):
			depth++
		case t.is(")"):
			depth--
		case t.is("FROM") && depth == 0 && froms == 1:
			return parseTarget(toks, i+1, "WHERE")
		}
	}
	return nil, errQuerySingleTable
}

// parseTarget reads "table [[AS] alias] terminator" at toks[i:] and returns
// the lower-case table name and alias.
func parseTarget(toks []token, i int, terminator string) ([]string, error) {
	if i >= len(toks) || toks[i].kind != tokWord {
		return nil, errQuerySingleTable
	}
	names := []string{strings.ToLower(toks[i].text)}
	j := i + 1
	as := j < len(toks) && toks[j].is("AS")
	if as {
		j++
	}
	if j < len(toks) && toks[j].kind == tokWord && (as || !toks[j].is(terminator)) {
		names = append(names, strings.ToLower(toks[j].text))
		j++
	}
	if j >= len(toks) || !toks[j].is(terminator) {
		return nil, errQuerySingleTable
	}
	return names, nil
}

// isTenantColumn reports whether t names the tenant column, optionally
// qualified by a table name or alias.
func isTenantColumn(t token) bool {
	if t.kind != tokWord {
		return false
	}
	name := strings.ToLower(t.text)
	return name == tenantColumn || strings.HasSuffix(name, "."+tenantColumn)
}

// qualifierMatches reports whether the tenant column token t is unqualified
// or qualified by one of names (target table and alias). An empty names
// list (reviewed query) accepts any qualifier.
func qualifierMatches(t token, names []string) bool {
	q, ok := strings.CutSuffix(strings.ToLower(t.text), "."+tenantColumn)
	if !ok || len(names) == 0 {
		return true
	}
	for _, n := range names {
		if q == n {
			return true
		}
	}
	return false
}

// isSlot reports whether toks[i:] starts with "tenant_id = ?".
func isSlot(toks []token, i int) bool {
	return i+2 < len(toks) && isTenantColumn(toks[i]) && toks[i+1].is("=") && toks[i+2].kind == tokPlaceholder
}

// isClauseKeyword reports whether t starts a clause that may follow WHERE.
func isClauseKeyword(t token) bool {
	for _, kw := range []string{"GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "RETURNING", "WINDOW"} {
		if t.is(kw) {
			return true
		}
	}
	return false
}

// endsPredicate reports whether the token at index i (if any) ends the
// "tenant_id = ?" predicate: end of statement, AND (which binds less tightly
// than comparisons), or a clause keyword. Anything else, such as
// "= ? IS NOT NULL" or "= ? = 0", could turn the predicate into one that
// matches other tenants.
func endsPredicate(toks []token, i int) bool {
	if i >= len(toks) {
		return true
	}
	for _, kw := range []string{"AND", "ORDER", "GROUP", "LIMIT"} {
		if toks[i].is(kw) {
			return true
		}
	}
	return false
}

// validateTenantWhere checks the SELECT / UPDATE / DELETE rule and returns
// the placeholder index of the tenant slot. names lists the target table
// and alias the slot may be qualified with (empty: any).
func validateTenantWhere(toks []token, names []string) (int, error) {
	var (
		where        = -1 // index of the top-level WHERE
		clauseAfter  = -1 // index of the first top-level clause after WHERE
		slotAt       = -1 // token index of the tenant slot
		slot         = 0  // placeholder index of the tenant slot
		placeholders = 0
		depth        = 0
	)
	for i, t := range toks {
		if isSlot(toks, i) {
			if slotAt >= 0 || depth != 0 {
				return 0, errQueryNoTenant // second slot, or slot in a subquery
			}
			slotAt, slot = i, placeholders
		}
		switch {
		case t.is("("):
			depth++
		case t.is(")"):
			depth--
		case t.kind == tokPlaceholder:
			placeholders++
		case depth == 0 && t.is("WHERE"):
			if where >= 0 {
				return 0, errQueryNoTenant
			}
			where = i
		case depth == 0 && where >= 0 && clauseAfter < 0 && isClauseKeyword(t):
			clauseAfter = i
		case where < 0 && toks[0].is("UPDATE") && isTenantColumn(t):
			return 0, errQueryNoTenant // tenant_id in the SET clause
		}
	}
	switch {
	case slotAt < 0, where < 0, slotAt < where, clauseAfter >= 0 && clauseAfter < slotAt,
		!toks[slotAt-1].is("WHERE") && !toks[slotAt-1].is("AND"), !endsPredicate(toks, slotAt+3),
		!qualifierMatches(toks[slotAt], names):
		return 0, errQueryNoTenant
	}
	return slot, nil
}

// validateTenantInsert checks the INSERT rule. Tokens: INSERT INTO name (
// columns ) VALUES ( values ) and nothing else. It returns the placeholder
// index of the tenant value.
func validateTenantInsert(toks []token) (int, error) {
	if len(toks) < 4 || !toks[1].is("INTO") || toks[2].kind != tokWord || !toks[3].is("(") {
		return 0, errQueryInsertShape
	}
	// Column list: unqualified words separated by commas.
	tenantCol, ncols := -1, 0
	i := 4
	for ; i < len(toks) && !toks[i].is(")"); i++ {
		t := toks[i]
		if (i-4)%2 == 1 {
			if !t.is(",") {
				return 0, errQueryInsertShape
			}
			continue
		}
		if t.kind != tokWord || strings.Contains(t.text, ".") {
			return 0, errQueryInsertShape
		}
		if isTenantColumn(t) {
			if tenantCol >= 0 {
				return 0, errQueryInsertShape
			}
			tenantCol = ncols
		}
		ncols++
	}
	if tenantCol < 0 || i+2 >= len(toks) || !toks[i+1].is("VALUES") || !toks[i+2].is("(") {
		return 0, errQueryInsertShape
	}
	// Values tuple, split at depth-1 commas; it must end the statement.
	var (
		values [][]token
		cur    []token
		before []int // placeholders preceding each value
		seen   int
		depth  int
	)
	for j := i + 2; j < len(toks); j++ {
		t := toks[j]
		switch {
		case t.is("(") && depth == 0:
			depth++
			before = append(before, seen)
			continue
		case t.is("("):
			depth++
		case t.is(")") && depth == 1:
			depth--
			values = append(values, cur)
			if j != len(toks)-1 {
				return 0, errQueryInsertShape // second row or trailing clause
			}
			continue
		case t.is(")"):
			depth--
		case t.is(",") && depth == 1:
			values = append(values, cur)
			cur = nil
			before = append(before, seen)
			continue
		case isTenantColumn(t):
			return 0, errQueryInsertShape // tenant_id read inside a value
		case t.kind == tokPlaceholder:
			seen++
		}
		cur = append(cur, t)
	}
	if len(values) != ncols {
		return 0, errQueryInsertShape
	}
	if v := values[tenantCol]; len(v) != 1 || v[0].kind != tokPlaceholder {
		return 0, errQueryInsertShape
	}
	return before[tenantCol], nil
}
