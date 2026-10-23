package app

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/keyrotation"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// chanWaiter is a rotationWaiter over a channel.
type chanWaiter chan struct{}

func (c chanWaiter) Done() <-chan struct{} { return c }

func TestWaitRotation(t *testing.T) {
	t.Parallel()
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	idle := make(chanWaiter)
	close(idle)
	waitRotation(context.Background(), idle, logger)
	if logs.String() != "" {
		t.Errorf("logs without a running worker = %s", logs)
	}
	running := make(chanWaiter)
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(running)
	}()
	waitRotation(context.Background(), running, logger)
	if !strings.Contains(logs.String(), "waiting for the master key rotation to stop") {
		t.Errorf("logs = %s", logs)
	}
}

// TestRunWarnsInterruptedRotation checks the start-up warning about an
// interrupted rotation between the configured keys, which is not resumed
// automatically, and the rotation options hook.
func TestRunWarnsInterruptedRotation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		cfg := testConfig(t, e)
		prepare(t, cfg)
		cfg.MasterKeyNewFile = writeMasterKey(t)
		c := *cfg
		db, err := store.Open(ctx, &c)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		kr, err := masterkey.Load(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer kr.Close()
		if _, err := masterkey.Check(ctx, db, kr, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
		rot, err := masterkey.StartRotation(ctx, db, kr, time.Now())
		if err != nil {
			t.Fatal(err)
		}

		edited := false
		run := *cfg
		s := start(t, &run, WithRotationOptions(func(o *keyrotation.Options) {
			edited = o.Logger != nil
			o.Rotation.BatchSize = 1
		}))
		if code, _ := s.get(t, "/healthz", "x"); code == 0 {
			t.Fatal("no answer")
		}
		if err := s.stop(t); err != nil {
			t.Fatal(err)
		}
		if !edited {
			t.Error("WithRotationOptions was not applied")
		}
		if logs := s.logs.String(); !strings.Contains(logs, "an interrupted master key rotation is waiting") ||
			!strings.Contains(logs, rot.ID) {
			t.Errorf("logs = %s", logs)
		}
		// Not resumed automatically.
		got, err := db.KeyRotations().Get(ctx, rot.ID)
		if err != nil || got.Status != store.RotationRunning || got.RewrappedKeys != 0 {
			t.Errorf("rotation after the start = %+v, %v", got, err)
		}
	})
}
