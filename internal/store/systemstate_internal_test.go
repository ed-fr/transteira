package store

import (
	"context"
	"errors"
	"testing"
)

// TestSystemStateDriverFaults reaches the error paths of the system state
// repository that a healthy database never takes.
func TestSystemStateDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	repo := db.SystemState()
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"get", faultQuery, "FROM system_state WHERE key", func() error {
			_, err := repo.Get(ctx, SystemStateUpdateCheck)
			return err
		}},
		{"put", faultExec, "INSERT INTO system_state", func() error {
			return repo.Put(ctx, SystemStateUpdateCheck, []byte(`{}`))
		}},
	} {
		plan.reset()
		plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
}
