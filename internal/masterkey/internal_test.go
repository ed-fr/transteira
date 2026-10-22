package masterkey

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestNewDEKRandomFailure covers a failure of the random source, which only
// a broken platform can produce.
func TestNewDEKRandomFailure(t *testing.T) {
	boom := errors.New("no entropy")
	orig := generateDEK
	generateDEK = func() ([]byte, error) { return nil, boom }
	t.Cleanup(func() { generateDEK = orig })
	v := &Vault{kr: &Keyring{current: &crypto.MasterKey{}}}
	if _, _, err := v.NewDEK(context.Background(), tenant.ID("x")); !errors.Is(err, boom) {
		t.Errorf("NewDEK = %v", err)
	}
}

// TestWrapSystemKeyFailure covers a wrapping failure of WrapSystem, which
// only an unusable master key can produce.
func TestWrapSystemKeyFailure(t *testing.T) {
	v := &Vault{kr: &Keyring{current: &crypto.MasterKey{}}}
	if _, err := v.WrapSystem(crypto.PurposeAdminTOTP, []byte("x")); !errors.Is(err, crypto.ErrKeyUnavailable) {
		t.Errorf("WrapSystem = %v", err)
	}
}

// TestScrub covers the outcomes of the post-deletion scrub: a busy WAL is a
// warning, any other failure an error (Vault.Scrub) or a warning (after a
// rotation).
func TestScrub(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	busy := func(context.Context) error { return store.ErrScrubBusy }
	broken := func(context.Context) error { return errors.New("disk I/O error") }

	v := &Vault{logger: logger, scrub: busy}
	if err := v.Scrub(ctx); err != nil || !strings.Contains(logs.String(), "may remain in the database WAL") {
		t.Errorf("Scrub(busy) = %v, logs %s", err, logs.String())
	}
	v.scrub = broken
	if err := v.Scrub(ctx); err == nil || !strings.Contains(err.Error(), "disk I/O error") {
		t.Errorf("Scrub(broken) = %v", err)
	}
	logs.Reset()
	scrubWarn(ctx, broken, logger)
	if !strings.Contains(logs.String(), "could not scrub") {
		t.Errorf("scrubWarn logs %s", logs.String())
	}
}
