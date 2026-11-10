package stats

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/metrics/metricstate"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestSecretsCreatedStats checks the one-time secrets created of the
// statistics, on both engines: per tenant over each period, and per row of
// the global view, each tenant counting only its own.
func TestSecretsCreatedStats(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
		ev := newEnv(t, e, now)
		ev.svc.measure = func(string) (uint64, uint64, error) { return 10, 5, nil }
		a, b := ev.tenant(1000), ev.tenant(1000)
		ev.add(a, day(2026, 11, 10), store.UsageCounts{SecretsCreated: 3, Transfers: 1})
		ev.add(a, day(2026, 11, 4), store.UsageCounts{SecretsCreated: 2}) // 7d: first day
		ev.add(a, day(2026, 9, 1), store.UsageCounts{SecretsCreated: 4})  // 12m only
		ev.add(b, day(2026, 11, 10), store.UsageCounts{SecretsCreated: 7})
		ctx := context.Background()
		for per, want := range map[Period]int64{Period7Days: 5, Period30Days: 5, Period12Months: 9} {
			s, err := ev.svc.TenantStats(ctx, principal(store.RoleDelegatedAdmin, a.ID), a.ID, per)
			if err != nil || s.SecretsCreated != want || s.Transfers != 1 {
				t.Errorf("%s: secrets created %d, transfers %d, want %d: %v", per, s.SecretsCreated, s.Transfers, want, err)
			}
		}
		g, err := ev.svc.GlobalStats(ctx, principal(store.RoleSuperAdmin), Period30Days)
		if err != nil {
			t.Fatal(err)
		}
		got := map[tenant.ID]int64{}
		for _, r := range g.Tenants {
			got[r.TenantID] = r.SecretsCreated
		}
		if got[a.ID] != 5 || got[b.ID] != 7 || len(got) != 2 {
			t.Errorf("global rows %v", got)
		}
	})
}

// secretProofs is a key proof and a proof with their verifiers.
type secretProofs struct{ key, proof [32]byte }

func newSecretProofs() secretProofs {
	var p secretProofs
	_, _ = rand.Read(p.key[:])
	_, _ = rand.Read(p.proof[:])
	return p
}

func (p secretProofs) input(now time.Time) store.CreateSecret {
	kv, v := sha256.Sum256(p.key[:]), sha256.Sum256(p.proof[:])
	return store.CreateSecret{
		CreatorKind: store.SecretCreatorInternal, SenderEmail: "alice@entity-a.example.com", Delivery: store.SecretDeliveryLink,
		Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("TTE2sealed-text_", 4), Duration: tenant.SecretDuration1d,
		Now: now,
	}
}

// TestInstanceStateSecrets checks the one-time secret figures of the
// supervision on real secrets, on both engines: created, read and locked
// during the last 24 hours, and the bytes of the stored files, per tenant.
func TestInstanceStateSecrets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
		ev := newEnv(t, e, now)
		ev.svc.measure = func(string) (uint64, uint64, error) { return 10, 5, nil }
		a, b := ev.tenant(1<<40), ev.tenant(1<<40)
		ctx := context.Background()
		kr, err := masterkey.New(masterkeytest.Key(t, "stats"), nil)
		if err != nil {
			t.Fatal(err)
		}
		repo := ev.db.Secrets(masterkey.NewVault(ev.db, kr, nil))
		create := func(tid tenant.ID, c store.CreateSecret) store.CreatedSecret {
			t.Helper()
			cs, err := repo.Create(ctx, tid, c)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			return cs
		}

		// A: one read, one locked, one pending with a file, one active
		// created two days ago (not in the last 24 hours).
		p := newSecretProofs()
		read := create(a.ID, p.input(now.Add(-time.Hour)))
		if _, err := repo.Reveal(ctx, a.ID, read.Token, p.key, p.proof, now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		in := p.input(now.Add(-time.Hour))
		in.KDFSalt = bytes.Repeat([]byte{7}, store.SecretKDFSaltLen)
		locked := create(a.ID, in)
		wrong := p.proof
		wrong[0] ^= 1
		for range store.SecretMaxFailedProofs {
			_, _ = repo.Reveal(ctx, a.ID, locked.Token, p.key, wrong, now.Add(-time.Minute))
		}
		if s, err := repo.Get(ctx, a.ID, locked.Secret.ID); err != nil || s.State != store.SecretLocked {
			t.Fatalf("locked = %+v, %v", s, err)
		}
		in = p.input(now.Add(-time.Minute))
		in.FileSize, in.FileMetadata, in.FileStorageName = 4096, "AQ"+strings.Repeat("A", 38), strings.Repeat("ab", 16)
		create(a.ID, in)
		create(a.ID, p.input(now.Add(-48*time.Hour)))
		// B: one active secret.
		create(b.ID, p.input(now.Add(-time.Hour)))

		s, err := ev.svc.InstanceState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]metricstate.TenantState{}
		for _, ts := range s.Tenants {
			byID[ts.ID] = ts
		}
		ta, tb := byID[string(a.ID)], byID[string(b.ID)]
		if ta.SecretsCreatedLast24h != 3 || ta.SecretsReadLast24h != 1 || ta.SecretsLockedLast24h != 1 || ta.SecretFileBytes != 4096 {
			t.Errorf("tenant A %+v", ta)
		}
		if ta.StorageUsedBytes != 4096 {
			t.Errorf("tenant A storage %d, want the secret file", ta.StorageUsedBytes)
		}
		if tb.SecretsCreatedLast24h != 1 || tb.SecretsReadLast24h != 0 || tb.SecretsLockedLast24h != 0 || tb.SecretFileBytes != 0 {
			t.Errorf("tenant B %+v", tb)
		}
		if !slices.IsSortedFunc(s.Tenants, func(x, y metricstate.TenantState) int { return strings.Compare(x.ID, y.ID) }) {
			t.Error("tenants not sorted")
		}
	})
}
