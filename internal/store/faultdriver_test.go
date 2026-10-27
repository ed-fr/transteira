package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

// faultDriverName is the database/sql name of the fault-injecting driver: a
// wrapper around the SQLite driver that fails chosen operations, so that the
// tests reach the error paths a healthy database never takes.
const faultDriverName = "sqlite-fault"

func init() {
	sql.Register(faultDriverName, &faultDriver{base: &sqlite.Driver{}})
}

// errInjected is the error returned by injected faults.
var errInjected = errors.New("injected fault")

// Fault operations.
const (
	faultOpen    = "open"          // driver Open; match against the DSN
	faultBegin   = "begin"         // BeginTx
	faultCommit  = "commit"        // Commit
	faultExec    = "exec"          // ExecContext; match against the SQL
	faultExecRan = "exec-ran"      // ExecContext fails after running; match the SQL
	faultQuery   = "query"         // QueryContext; match against the SQL
	faultNext    = "next"          // Rows.Next; match against the SQL
	faultScanNil = "scan-nil"      // Rows.Next returns NULL columns; match the SQL
	faultRows    = "rows-affected" // Result.RowsAffected; match the SQL
)

// faultRule fails the matching calls of op after letting `after` of them
// through.
type faultRule struct {
	op    string
	match string
	after int
	seen  int
}

// faultPlan is the set of rules of one database file.
type faultPlan struct {
	mu    sync.Mutex
	rules []*faultRule
}

// add installs a rule.
func (p *faultPlan) add(op, match string, after int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = append(p.rules, &faultRule{op: op, match: match, after: after})
}

// reset removes every rule.
func (p *faultPlan) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = nil
}

// fail reports whether the call (op, text) must fail.
func (p *faultPlan) fail(op, text string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.rules {
		if r.op != op || !strings.Contains(text, r.match) {
			continue
		}
		r.seen++
		if r.seen > r.after {
			return true
		}
	}
	return false
}

// check returns errInjected when the call must fail.
func (p *faultPlan) check(op, text string) error {
	if p.fail(op, text) {
		return errInjected
	}
	return nil
}

// faultPlans maps a database path to its plan.
var faultPlans sync.Map

// faultDriver wraps the SQLite driver.
type faultDriver struct{ base driver.Driver }

// Open opens a connection and attaches the plan registered for its path.
func (d *faultDriver) Open(name string) (driver.Conn, error) {
	path, _, _ := strings.Cut(name, "?")
	v, _ := faultPlans.LoadOrStore(path, &faultPlan{})
	plan := v.(*faultPlan)
	if err := plan.check(faultOpen, name); err != nil {
		return nil, err
	}
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &faultConn{base: c, plan: plan}, nil
}

// faultConn wraps a SQLite connection.
type faultConn struct {
	base driver.Conn
	plan *faultPlan
}

func (c *faultConn) Prepare(q string) (driver.Stmt, error) { return c.base.Prepare(q) }
func (c *faultConn) Close() error                          { return c.base.Close() }
func (c *faultConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := c.plan.check(faultBegin, ""); err != nil {
		return nil, err
	}
	tx, err := c.base.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &faultTx{base: tx, plan: c.plan}, nil
}

func (c *faultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.plan.check(faultExec, q); err != nil {
		return nil, err
	}
	res, err := c.base.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err != nil {
		return nil, err
	}
	if err := c.plan.check(faultExecRan, q); err != nil {
		return nil, err
	}
	return &faultResult{base: res, plan: c.plan, q: q}, nil
}

func (c *faultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.plan.check(faultQuery, q); err != nil {
		return nil, err
	}
	rows, err := c.base.(driver.QueryerContext).QueryContext(ctx, q, args)
	if err != nil {
		return nil, err
	}
	return &faultRowsT{base: rows, plan: c.plan, q: q}, nil
}

// faultTx wraps a transaction.
type faultTx struct {
	base driver.Tx
	plan *faultPlan
}

func (t *faultTx) Commit() error {
	if err := t.plan.check(faultCommit, ""); err != nil {
		_ = t.base.Rollback()
		return err
	}
	return t.base.Commit()
}

func (t *faultTx) Rollback() error { return t.base.Rollback() }

// faultResult wraps an exec result.
type faultResult struct {
	base driver.Result
	plan *faultPlan
	q    string
}

func (r *faultResult) LastInsertId() (int64, error) { return r.base.LastInsertId() }
func (r *faultResult) RowsAffected() (int64, error) {
	if err := r.plan.check(faultRows, r.q); err != nil {
		return 0, err
	}
	return r.base.RowsAffected()
}

// faultRowsT wraps a result set.
type faultRowsT struct {
	base driver.Rows
	plan *faultPlan
	q    string
}

func (r *faultRowsT) Columns() []string { return r.base.Columns() }
func (r *faultRowsT) Close() error      { return r.base.Close() }
func (r *faultRowsT) Next(dest []driver.Value) error {
	if err := r.plan.check(faultNext, r.q); err != nil {
		return err
	}
	if err := r.base.Next(dest); err != nil {
		return err
	}
	if r.plan.fail(faultScanNil, r.q) {
		for i := range dest {
			dest[i] = nil
		}
	}
	return nil
}

// openFault opens a migrated SQLite database through the fault driver and
// returns it with its fault plan.
func openFault(t *testing.T, opts ...Option) (*DB, *faultPlan) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fault.db")
	plan := &faultPlan{}
	faultPlans.Store(path, plan)
	t.Cleanup(func() { faultPlans.Delete(path) })
	db, err := openSQLite(context.Background(), faultDriverName, path, opts)
	if err != nil {
		t.Fatalf("openSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db, plan
}
