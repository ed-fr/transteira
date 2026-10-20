package isolation_test

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// invalidTenantIDs returns malformed tenant IDs derived from a valid one.
func invalidTenantIDs(valid tenant.ID) []tenant.ID {
	s := string(valid)
	return []tenant.ID{
		"",
		tenant.ID(strings.ToLower(s)),
		tenant.ID(s + " "),
		tenant.ID(" " + s),
		tenant.ID(s[:len(s)-1]),
		tenant.ID(s + "0"),
		tenant.ID("blk_" + s[len("ten_"):]),
		tenant.ID(s + "' OR '1'='1"),
		tenant.ID(s + "%"),
		"%",
		tenant.ID(id.New(id.Blocklist)),
	}
}

// TestExecutorRejectsInvalidTenant checks that no executor or repository
// method accepts a zero or malformed tenant ID, and that rejecting it
// changes nothing.
func TestExecutorRejectsInvalidTenant(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)

		for _, bad := range invalidTenantIDs(f.a.ID) {
			if s, err := f.db.Scoped(bad); !errors.Is(err, store.ErrInvalid) || s != nil {
				t.Errorf("Scoped(%q) = %v, %v; want nil, ErrInvalid", bad, s, err)
			}
			ops := map[string]func() error{
				"NetworkRules.Get": func() error { _, err := f.db.NetworkRules().Get(ctx, bad); return err },
				"NetworkRules.Replace": func() error {
					_, err := f.db.NetworkRules().Replace(ctx, bad, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, nil)
					return err
				},
				"Blocklist.List":   func() error { _, err := f.db.Blocklist().List(ctx, bad, store.BlocklistFilter{}); return err },
				"Blocklist.Match":  func() error { _, err := f.db.Blocklist().Match(ctx, bad, "spam-b@example.net", ""); return err },
				"Blocklist.Delete": func() error { return f.db.Blocklist().Delete(ctx, bad, f.blockB[0].ID) },
				"Blocklist.Create": func() error {
					_, err := f.db.Blocklist().Create(ctx, bad, store.BlocklistEntry{Kind: store.BlockEmail, Value: "x@example.net"})
					return err
				},
			}
			for name, op := range ops {
				if err := op(); !errors.Is(err, store.ErrInvalid) {
					t.Errorf("%s(%q) err = %v, want ErrInvalid", name, bad, err)
				}
			}
		}
		f.assertAIntact(ctx, t)
		f.assertBIntact(ctx, t)
	})
}

// TestExecutorMisuse covers the misuse of the executors available outside
// the store package.
//
// Executing a system query on a scoped transaction (or the reverse) is
// meant to be a compile-time error: ScopedTx accepts only store.TenantQuery
// and SystemTx only store.SystemQuery, and no registered query is exported.
// Callers outside the package can only build zero-value queries, which the
// executors reject at run time. Argument-count checks (too few arguments
// before the tenant slot) need a registered query, which only the store's
// internal tests can declare; they are covered there
// (internal/store/internal_test.go).
func TestExecutorMisuse(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)

		s, err := f.db.Scoped(f.a.ID)
		if err != nil || s.Tenant() != f.a.ID {
			t.Fatalf("Scoped(A) = %v, %v", s, err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			if _, err := tx.Exec(ctx, store.TenantQuery{}, string(f.b.ID)); err == nil {
				t.Error("ScopedTx.Exec(zero query) succeeded")
			}
			rows, err := tx.Query(ctx, store.TenantQuery{}, string(f.b.ID))
			if err == nil {
				_ = rows.Close()
				t.Error("ScopedTx.Query(zero query) succeeded")
			}
			if err := tx.QueryRow(ctx, store.TenantQuery{}).Scan(); err == nil {
				t.Error("ScopedTx.QueryRow(zero query) succeeded")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Scoped.Tx: %v", err)
		}

		for _, reason := range []string{"", " ", "\t\n"} {
			if sys, err := f.db.System(reason); !errors.Is(err, store.ErrInvalid) || sys != nil {
				t.Errorf("System(%q) = %v, %v; want nil, ErrInvalid", reason, sys, err)
			}
		}
		sys, err := f.db.System("isolation test")
		if err != nil {
			t.Fatal(err)
		}
		err = sys.ReadTx(ctx, func(tx *store.SystemTx) error {
			if _, err := tx.Exec(ctx, store.SystemQuery{}); err == nil {
				t.Error("SystemTx.Exec(zero query) succeeded")
			}
			rows, err := tx.Query(ctx, store.SystemQuery{})
			if err == nil {
				_ = rows.Close()
				t.Error("SystemTx.Query(zero query) succeeded")
			}
			if err := tx.QueryRow(ctx, store.SystemQuery{}).Scan(); err == nil {
				t.Error("SystemTx.QueryRow(zero query) succeeded")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("System.ReadTx: %v", err)
		}

		// A function error rolls back the scoped transaction and is
		// returned unchanged.
		sentinel := errors.New("boom")
		if err := s.Tx(ctx, func(*store.ScopedTx) error { return sentinel }); !errors.Is(err, sentinel) {
			t.Errorf("Scoped.Tx error = %v, want the function's error", err)
		}
		f.assertAIntact(ctx, t)
		f.assertBIntact(ctx, t)
	})
}

// TestQueryKindsAreNotInterchangeable checks the type-level barrier between
// tenant and system queries: store.TenantQuery and store.SystemQuery have
// distinct underlying types, so neither converts to the other (not even
// explicitly), and each executor accepts only its own kind. The executors
// additionally check the query kind at run time (covered by the store's
// internal tests, since registered queries are not exported).
func TestQueryKindsAreNotInterchangeable(t *testing.T) {
	t.Parallel()
	tq := reflect.TypeFor[store.TenantQuery]()
	sq := reflect.TypeFor[store.SystemQuery]()
	if sq.ConvertibleTo(tq) || tq.ConvertibleTo(sq) {
		t.Errorf("store.SystemQuery and store.TenantQuery must not be convertible into each other: " +
			"a system query could then be run by the tenant-scoped executor")
	}
	// The executor signatures themselves are distinct.
	execS, _ := reflect.TypeFor[*store.ScopedTx]().MethodByName("Exec")
	execY, _ := reflect.TypeFor[*store.SystemTx]().MethodByName("Exec")
	if execS.Type.In(2) != tq || execY.Type.In(2) != sq {
		t.Errorf("unexpected executor signatures: %v / %v", execS.Type, execY.Type)
	}
}
