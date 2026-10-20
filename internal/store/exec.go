package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Scoped executes tenant queries for one tenant. Obtain it with [DB.Scoped].
//
// Every operation runs in a transaction. On PostgreSQL the transaction first
// sets app.tenant_id (transaction-local), which the row-level security
// policies compare with the tenant_id of each row: even a faulty statement
// cannot reach another tenant's rows.
type Scoped struct {
	db  *DB
	tid tenant.ID
}

// Scoped returns an executor bound to tenant tid. It rejects an empty or
// malformed ID.
func (db *DB) Scoped(tid tenant.ID) (*Scoped, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return &Scoped{db: db, tid: tid}, nil
}

// Tenant returns the tenant the executor is bound to.
func (s *Scoped) Tenant() tenant.ID { return s.tid }

// Tx runs fn in a read-write transaction, committed when fn returns nil and
// rolled back otherwise. fn must not start another transaction: with SQLite
// the single writer connection is held until fn returns, so nesting would
// deadlock.
func (s *Scoped) Tx(ctx context.Context, fn func(*ScopedTx) error) error {
	return s.run(ctx, s.db.write, fn)
}

// ReadTx runs fn in a transaction meant for reads. With SQLite it uses the
// read-only pool, so that reads never wait for the writer.
func (s *Scoped) ReadTx(ctx context.Context, fn func(*ScopedTx) error) error {
	return s.run(ctx, s.db.read, fn)
}

// run executes fn in a tenant-scoped transaction on pool.
func (s *Scoped) run(ctx context.Context, pool *sql.DB, fn func(*ScopedTx) error) error {
	return s.db.runTx(ctx, pool, s.db.dialect.scopeTenant, []any{string(s.tid)}, func(tx *sql.Tx) error {
		return fn(&ScopedTx{tx: tx, tid: s.tid, dialect: s.db.dialect})
	})
}

// ScopedTx is a transaction bound to one tenant. It accepts only
// [TenantQuery] statements and binds the tenant ID at their tenant slot:
// callers pass the other arguments only, in statement order. It must not be used after the
// function it was given to returns.
type ScopedTx struct {
	tx      *sql.Tx
	tid     tenant.ID
	dialect *dialect
}

// prepare checks that q is a registered tenant query and returns its SQL text and its full argument list: the
// caller's arguments with the tenant ID inserted at the tenant slot. It
// fails unless the caller passed exactly one argument per placeholder other
// than the tenant slot.
func (t *ScopedTx) prepare(q TenantQuery, args []any) (string, []any, error) {
	tq := q.tenant
	if tq == nil || tq.kind != kindTenant {
		return "", nil, errQueryUnregistered
	}
	if len(args)+1 != tq.placeholders {
		return "", nil, errQueryArgCount
	}
	full := make([]any, 0, len(args)+1)
	full = append(full, args[:tq.slot]...)
	full = append(full, string(t.tid))
	full = append(full, args[tq.slot:]...)
	return tq.sql(t.dialect), full, nil
}

// lock serializes the current transaction with every other transaction of
// the same tenant that calls lock, until it ends. It is a no-op on SQLite,
// whose write transactions are serialized anyway.
func (t *ScopedTx) lock(ctx context.Context) error {
	if t.dialect.lockTenant == "" {
		return nil
	}
	if _, err := t.tx.ExecContext(ctx, t.dialect.lockTenant, string(t.tid)); err != nil {
		return wrap("lock tenant", err)
	}
	return nil
}

// Exec runs a statement that returns no rows.
func (t *ScopedTx) Exec(ctx context.Context, q TenantQuery, args ...any) (sql.Result, error) {
	text, full, err := t.prepare(q, args)
	if err != nil {
		return nil, err
	}
	return t.tx.ExecContext(ctx, text, full...)
}

// Query runs a statement returning rows. The caller must close the rows
// before the transaction function returns.
func (t *ScopedTx) Query(ctx context.Context, q TenantQuery, args ...any) (*sql.Rows, error) {
	text, full, err := t.prepare(q, args)
	if err != nil {
		return nil, err
	}
	return t.tx.QueryContext(ctx, text, full...)
}

// QueryRow runs a statement expected to return at most one row.
func (t *ScopedTx) QueryRow(ctx context.Context, q TenantQuery, args ...any) *Row {
	text, full, err := t.prepare(q, args)
	if err != nil {
		return &Row{err: err}
	}
	return &Row{row: t.tx.QueryRowContext(ctx, text, full...)}
}

// System executes system queries, which are not restricted to a tenant.
// Obtain it with [DB.System].
type System struct {
	db     *DB
	reason string
}

// System returns an executor for system queries. reason explains the
// operation (for example "resolve tenant by host") and is logged at info
// level with every transaction (the audit log proper comes with the audit
// package). It rejects an empty reason.
func (db *DB) System(reason string) (*System, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, invalid("system scope needs a reason")
	}
	return &System{db: db, reason: reason}, nil
}

// Tx runs fn in a read-write transaction, committed when fn returns nil and
// rolled back otherwise. As with [Scoped.Tx], fn must not start another
// transaction.
func (s *System) Tx(ctx context.Context, fn func(*SystemTx) error) error {
	return s.run(ctx, s.db.write, fn)
}

// ReadTx runs fn in a transaction meant for reads (read-only pool with
// SQLite).
func (s *System) ReadTx(ctx context.Context, fn func(*SystemTx) error) error {
	return s.run(ctx, s.db.read, fn)
}

// run executes fn in a system transaction on pool.
func (s *System) run(ctx context.Context, pool *sql.DB, fn func(*SystemTx) error) error {
	s.db.logger.InfoContext(ctx, "store: system scope", "reason", s.reason)
	return s.db.runTx(ctx, pool, s.db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		return fn(&SystemTx{tx: tx, dialect: s.db.dialect})
	})
}

// SystemTx is a system transaction. It accepts only [SystemQuery]
// statements. It must not be used after the function it was given to
// returns.
type SystemTx struct {
	tx      *sql.Tx
	dialect *dialect
}

// prepare checks that q is a registered system query taking exactly
// len(args) arguments and returns its SQL text.
func (t *SystemTx) prepare(q SystemQuery, args []any) (string, error) {
	if q.system == nil || q.system.kind != kindSystem {
		return "", errQueryUnregistered
	}
	if len(args) != q.system.placeholders {
		return "", errQueryArgCount
	}
	return q.system.sql(t.dialect), nil
}

// Exec runs a statement that returns no rows.
func (t *SystemTx) Exec(ctx context.Context, q SystemQuery, args ...any) (sql.Result, error) {
	text, err := t.prepare(q, args)
	if err != nil {
		return nil, err
	}
	return t.tx.ExecContext(ctx, text, args...)
}

// Query runs a statement returning rows. The caller must close the rows
// before the transaction function returns.
func (t *SystemTx) Query(ctx context.Context, q SystemQuery, args ...any) (*sql.Rows, error) {
	text, err := t.prepare(q, args)
	if err != nil {
		return nil, err
	}
	return t.tx.QueryContext(ctx, text, args...)
}

// QueryRow runs a statement expected to return at most one row.
func (t *SystemTx) QueryRow(ctx context.Context, q SystemQuery, args ...any) *Row {
	text, err := t.prepare(q, args)
	if err != nil {
		return &Row{err: err}
	}
	return &Row{row: t.tx.QueryRowContext(ctx, text, args...)}
}

// Row is the result of QueryRow.
type Row struct {
	row *sql.Row
	err error
}

// Scan copies the columns of the row into dest. It returns ErrNotFound when
// the statement returned no row.
func (r *Row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	err := r.row.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// runTx begins a transaction on pool, runs the scope statement (if any) with
// scopeArgs, then fn, and commits. The transaction is rolled back when any
// step fails or fn panics. Errors from fn are returned unchanged.
func (db *DB) runTx(ctx context.Context, pool *sql.DB, scope string, scopeArgs []any, fn func(*sql.Tx) error) (err error) {
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin transaction", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if scope != "" {
		if _, err := tx.ExecContext(ctx, scope, scopeArgs...); err != nil {
			return wrap("set transaction scope", err)
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	committed = true
	if err := tx.Commit(); err != nil {
		return wrap("commit", err)
	}
	return nil
}
