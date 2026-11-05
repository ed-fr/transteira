package proof

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestSignerCreatesOnce(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := t.Context()
		if k := ev.keys(); len(k) != 0 {
			t.Fatalf("keys before use = %+v", k)
		}
		// Concurrent first uses, from this signer and from another process.
		other := NewSigner(ev.db, ev.vault, ev.rec, ev.clock.Now, nil)
		var wg sync.WaitGroup
		ids := make([]string, 8)
		errs := make([]error, 8)
		for i := range ids {
			wg.Go(func() {
				s := ev.signer
				if i%2 == 1 {
					s = other
				}
				sealer, err := s.Prepare(ctx)
				if err == nil {
					ids[i] = sealer.KeyID()
				}
				errs[i] = err
			})
		}
		wg.Wait()
		keys := ev.keys()
		if len(keys) != 1 || !keys[0].RetiredAt.IsZero() || len(keys[0].PublicKey) != ed25519.PublicKeySize ||
			!keys[0].CreatedAt.Equal(testStart) {
			t.Fatalf("keys = %+v", keys)
		}
		for i := range ids {
			if errs[i] != nil || ids[i] != keys[0].KeyID {
				t.Errorf("Prepare #%d = %s, %v", i, ids[i], errs[i])
			}
		}
		created := ev.auditEvents("", audit.ActionProofKeyCreated)
		if len(created) != 1 || created[0].TenantID != "" || created[0].ActorKind != store.ActorSystem ||
			created[0].ObjectKind != audit.ObjectProofKey || created[0].ObjectID != keys[0].KeyID {
			t.Errorf("proof_key.created events = %+v", created)
		}
		// The private key is a sealed system secret, never the raw seed.
		k, err := ev.db.ProofKeys().Get(ctx, keys[0].KeyID)
		if err != nil {
			t.Fatal(err)
		}
		sec, err := ev.db.SystemSecrets().Get(ctx, k.PrivateKeySecretID)
		if err != nil || sec.Purpose != store.SecretPurposeProofSigning {
			t.Errorf("secret = %+v, %v", sec, err)
		}
		// Sealers sign with the same key and hold their own copy.
		s1, s2 := ev.prepare(), ev.prepare()
		if s1.KeyID() != s2.KeyID() || &s1.priv[0] == &s2.priv[0] || &s1.priv[0] == &ev.signer.cached.priv[0] {
			t.Error("sealers share the cached key")
		}
		msg := []byte("statement")
		if !ed25519.Verify(keys[0].PublicKey, msg, ed25519.Sign(s1.priv, msg)) {
			t.Error("sealer key does not match the published key")
		}
	})
}

func TestSignerRetire(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := t.Context()
		if _, err := ev.signer.Retire(ctx, CLIActor); !errors.Is(err, ErrNoActiveKey) {
			t.Errorf("Retire(no key) = %v", err)
		}
		first := ev.prepare()
		cached := ev.signer.cached.priv

		// The command line retires the key from another process.
		ev.clock.Advance(time.Hour)
		cli := NewSigner(ev.db, ev.vault, ev.rec, ev.clock.Now, nil)
		retired, err := cli.Retire(ctx, CLIActor)
		if err != nil || retired.ID != first.KeyID() || !retired.RetiredAt.Equal(testStart.Add(time.Hour)) || retired.PrivateKeySecretID != "" {
			t.Fatalf("Retire = %+v, %v", retired, err)
		}
		events := ev.auditEvents("", audit.ActionProofKeyRetired)
		if len(events) != 1 || events[0].Actor != "cli" || events[0].ActorKind != store.ActorSystem || events[0].ObjectID != retired.ID {
			t.Errorf("proof_key.retired events = %+v", events)
		}

		// The next write uses a new key: the retired one never signs again,
		// and its cached copy is zeroed.
		ev.clock.Advance(time.Minute)
		second := ev.prepare()
		if second.KeyID() == first.KeyID() {
			t.Fatal("retired key used again")
		}
		for _, b := range cached {
			if b != 0 {
				t.Fatal("cached private key of the retired key not zeroed")
			}
		}
		keys := ev.keys()
		if len(keys) != 2 || keys[0].KeyID != second.KeyID() || !keys[0].RetiredAt.IsZero() ||
			keys[1].KeyID != first.KeyID() || !keys[1].RetiredAt.Equal(retired.RetiredAt) {
			t.Errorf("keys = %+v", keys)
		}

		// Retiring through the signer that holds the key clears its cache.
		if _, err := ev.signer.Retire(ctx, Actor{Kind: store.ActorAdmin, Name: "root", IP: clientIP}); err != nil {
			t.Fatal(err)
		}
		if ev.signer.cached != nil {
			t.Error("cache kept after retirement")
		}
		if third := ev.prepare(); third.KeyID() == second.KeyID() {
			t.Error("retired key used again")
		}
		if n := len(ev.auditEvents("", audit.ActionProofKeyCreated)); n != 3 {
			t.Errorf("%d keys created, want 3", n)
		}
	})
}

func TestSignerFaults(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := t.Context()
	newSigner := func(v Vault, rec SystemAuditor) *Signer { return NewSigner(ev.db, v, rec, ev.clock.Now, nil) }

	// Key generation, sealing and audit failures store nothing.
	s := newSigner(ev.vault, ev.rec)
	s.rand = failingReader{}
	if _, err := s.Prepare(ctx); err == nil {
		t.Error("Prepare with a failing random source succeeded")
	}
	if _, err := newSigner(&faultVault{Vault: ev.vault, wrapErr: errBoom}, ev.rec).Prepare(ctx); !errors.Is(err, errBoom) {
		t.Errorf("Prepare(seal fails) = %v", err)
	}
	if _, err := newSigner(ev.vault, faultAudit{}).Prepare(ctx); !errors.Is(err, errBoom) {
		t.Errorf("Prepare(audit fails) = %v", err)
	}
	if k := ev.keys(); len(k) != 0 {
		t.Fatalf("keys after failures = %+v", k)
	}

	// Another process creates the key while this one seals its own: the
	// insert conflicts, and the key of the other process is opened.
	winner := newSigner(ev.vault, ev.rec)
	var won *Sealer
	racer := newSigner(&faultVault{Vault: ev.vault, beforeWrap: func() {
		if won == nil {
			var err error
			if won, err = winner.Prepare(ctx); err != nil {
				t.Errorf("winner Prepare = %v", err)
			}
		}
	}}, ev.rec)
	got, err := racer.Prepare(ctx)
	if err != nil || won == nil || got.KeyID() != won.KeyID() || len(ev.keys()) != 1 {
		t.Fatalf("racing Prepare = %v, %v", got, err)
	}

	// Opening failures: the secret does not open, or holds another key.
	if _, err := newSigner(&faultVault{Vault: ev.vault, openErr: errBoom}, ev.rec).Prepare(ctx); !errors.Is(err, errBoom) {
		t.Errorf("Prepare(open fails) = %v", err)
	}
	for _, seed := range [][]byte{make([]byte, 5), make([]byte, ed25519.SeedSize)} {
		if _, err := newSigner(&faultVault{Vault: ev.vault, openSeed: seed}, ev.rec).Prepare(ctx); !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("Prepare(wrong seed) = %v", err)
		}
	}
	// The key is retired between its read and its opening, every time:
	// the bounded retries give up.
	if _, err := newSigner(&faultVault{Vault: ev.vault, openErr: store.ErrNotFound}, ev.rec).Prepare(ctx); !errors.Is(err, store.ErrConflict) {
		t.Errorf("Prepare(secret always gone) = %v", err)
	}
	// A key whose private part is already gone is not opened.
	if _, err := s.open(ctx, store.ProofKey{ID: "psk_x"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("open(retired) = %v", err)
	}

	// Audit failure of a retirement: the key stays active.
	if _, err := newSigner(ev.vault, faultAudit{}).Retire(ctx, CLIActor); !errors.Is(err, errBoom) {
		t.Errorf("Retire(audit fails) = %v", err)
	}
	if k := ev.keys(); len(k) != 1 || !k[0].RetiredAt.IsZero() {
		t.Errorf("keys = %+v", k)
	}

	// Database failures.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Prepare(canceled); err == nil {
		t.Error("Prepare(canceled) succeeded")
	}
	if _, err := s.Retire(canceled, CLIActor); err == nil || errors.Is(err, ErrNoActiveKey) {
		t.Errorf("Retire(canceled) = %v", err)
	}
	if _, err := s.Keys(canceled); err == nil {
		t.Error("Keys(canceled) succeeded")
	}
	if _, err := s.create(canceled); err == nil {
		t.Error("create(canceled) succeeded")
	}
}

func TestNewSignerDefaults(t *testing.T) {
	t.Parallel()
	s := NewSigner(nil, nil, nil, nil, nil)
	if s.clock == nil || s.logger == nil || s.rand == nil {
		t.Errorf("defaults = %+v", s)
	}
	svc := NewService(nil, s, nil, nil, nil, WithRateLimit(0, 0))
	if svc.clock == nil || svc.logger == nil || svc.perMinute != DefaultRatePerMinute || svc.burst != DefaultBurst {
		t.Errorf("service defaults = %+v", svc)
	}
	if got := NewService(nil, s, nil, nil, nil, WithRateLimit(1, 2)); got.perMinute != 1 || got.burst != 2 {
		t.Errorf("WithRateLimit = %d/%d", got.perMinute, got.burst)
	}
}

func TestRetireScrubFailureKeepsRetirement(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ev.prepare()
	ev.signer.scrub = func(context.Context) error { return store.ErrScrubBusy }
	k, err := ev.signer.Retire(t.Context(), CLIActor)
	if err != nil || k.ID == "" {
		t.Fatalf("Retire = %+v, %v", k, err)
	}
	if !strings.Contains(ev.logs.String(), "scrub after proof key retirement failed") {
		t.Errorf("logs = %q", ev.logs.String())
	}
}
