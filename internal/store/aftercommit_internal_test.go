package store

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestAfterCommit checks that the hooks of a transaction run in
// registration order once it committed, and never when it is rolled back,
// on both engines and for both executors.
func TestAfterCommit(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		a, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		scoped, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		system := db.systemScope("test after commit")
		boom := errors.New("boom")

		var calls []string
		hook := func(name string) func() { return func() { calls = append(calls, name) } }

		// Committed tenant transaction: the hooks run in order, after the
		// commit (the write is visible to them), and a nil hook is ignored.
		var visible bool
		err = scoped.Tx(ctx, func(tx *ScopedTx) error {
			if _, err := tx.Exec(ctx, qRuleInsert, ruleKindDomain, "x.example.com"); err != nil {
				return err
			}
			tx.AfterCommit(hook("s1"))
			tx.AfterCommit(nil)
			tx.AfterCommit(func() {
				set, err := db.NetworkRules().Get(ctx, a.ID)
				visible = err == nil && len(set.Domains) == 1
				calls = append(calls, "s2")
			})
			if len(calls) != 0 {
				t.Error("a hook ran before the commit")
			}
			return nil
		})
		if err != nil || !slices.Equal(calls, []string{"s1", "s2"}) || !visible {
			t.Fatalf("committed tenant Tx: err=%v calls=%v visible=%v", err, calls, visible)
		}

		// Rolled back by an error or a panic: no hook runs.
		calls = nil
		err = scoped.Tx(ctx, func(tx *ScopedTx) error {
			tx.AfterCommit(hook("rolled back"))
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("Tx err = %v", err)
		}
		func() {
			defer func() { _ = recover() }()
			_ = scoped.Tx(ctx, func(tx *ScopedTx) error {
				tx.AfterCommit(hook("panicked"))
				panic("boom")
			})
		}()
		err = system.Tx(ctx, func(tx *SystemTx) error {
			tx.AfterCommit(hook("rolled back"))
			return boom
		})
		if !errors.Is(err, boom) || len(calls) != 0 {
			t.Fatalf("rolled back: err=%v calls=%v", err, calls)
		}

		// Committed system and read transactions.
		err = system.Tx(ctx, func(tx *SystemTx) error {
			tx.AfterCommit(hook("y1"))
			tx.AfterCommit(nil)
			tx.AfterCommit(hook("y2"))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = system.ReadTx(ctx, func(tx *SystemTx) error {
			tx.AfterCommit(hook("yr"))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = scoped.ReadTx(ctx, func(tx *ScopedTx) error {
			tx.AfterCommit(hook("sr"))
			return nil
		})
		if err != nil || !slices.Equal(calls, []string{"y1", "y2", "yr", "sr"}) {
			t.Fatalf("committed system and read Tx: err=%v calls=%v", err, calls)
		}
	})
}

// TestAfterCommitNotRunOnFailedCommit makes the commit itself fail: the
// hooks registered during the transaction do not run.
func TestAfterCommitNotRunOnFailedCommit(t *testing.T) {
	t.Parallel()
	db, plan := openFault(t)
	ctx := context.Background()
	ran := false
	plan.add(faultCommit, "", 0)
	err := db.systemScope("test failed commit").Tx(ctx, func(tx *SystemTx) error {
		tx.AfterCommit(func() { ran = true })
		return nil
	})
	if err == nil || ran {
		t.Fatalf("failed commit: err=%v ran=%v", err, ran)
	}
}

// TestAfterCommitWithoutHooks checks that a transaction built without
// hooks (the migration transactions) drops a hook instead of panicking.
func TestAfterCommitWithoutHooks(t *testing.T) {
	t.Parallel()
	ran := false
	(&SystemTx{}).AfterCommit(func() { ran = true })
	(&ScopedTx{}).AfterCommit(func() { ran = true })
	if ran {
		t.Fatal("a hook ran on a transaction without hooks")
	}
}
