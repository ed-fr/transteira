package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// expressInput returns a valid anonymous express secret of one day.
func (f *secretFixture) expressInput(p proofs) CreateExpressSecret {
	kv, v := p.verifiers()
	return CreateExpressSecret{Verifier: v, KeyVerifier: kv, SealedText: sealedText, Duration: tenant.SecretDuration1d, Now: f.now}
}

// createExpress stores an express secret or fails the test.
func (f *secretFixture) createExpress(ctx context.Context, t *testing.T, tid tenant.ID, c CreateExpressSecret) CreatedSecret {
	t.Helper()
	cs, err := f.repo.CreateExpress(ctx, tid, c)
	if err != nil {
		t.Fatalf("CreateExpress: %v", err)
	}
	return cs
}

// setExpress writes the express settings of tid: the defaults changed by
// mod.
func (f *secretFixture) setExpress(t *testing.T, tid tenant.ID, mod func(*tenant.ExpressSettings)) {
	t.Helper()
	s := tenant.DefaultExpressSettings()
	mod(&s)
	if _, err := f.db.Tenants().SetExpressSettings(context.Background(), tid, s); err != nil {
		t.Errorf("SetExpressSettings: %v", err)
	}
}

// enableExpress turns the anonymous mode of tid on or off, the limits at
// their defaults.
func enableExpress(on bool) func(*tenant.ExpressSettings) {
	return func(s *tenant.ExpressSettings) { s.Enabled = on }
}

// expressToken creates a usable API token of tid allowed for the express
// secrets and returns its ID.
func (f *secretFixture) expressToken(t *testing.T, tid tenant.ID) string {
	t.Helper()
	tokID := f.apiToken(t, tid)
	allowed := true
	tok, err := f.db.APITokens().Update(context.Background(), tid, tokID, APITokenUpdate{ExpressAllowed: &allowed})
	if err != nil || !tok.ExpressAllowed {
		t.Fatalf("allow the token for express secrets: %+v, %v", tok, err)
	}
	return tokID
}

// failedProofs reads the failure counter of secret secID.
func (f *secretFixture) failedProofs(t *testing.T, secID string) int64 {
	t.Helper()
	return rawInt(context.Background(), t, f.db, `SELECT failed_proofs FROM secrets WHERE id = '`+secID+`'`)
}

// TestSecretsCreateExpress covers the creation of the express secrets:
// the anonymous mode, the stored profile, the inputs, the API tokens and
// the tenant states, on both engines.
func TestSecretsCreateExpress(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		in := f.expressInput(p)

		// Off by default: refused, nothing stored.
		if _, err := f.repo.CreateExpress(ctx, f.a, in); !errors.Is(err, ErrExpressDisabled) || !errors.Is(err, ErrSecretPolicy) {
			t.Fatalf("anonymous creation by default: %v", err)
		}
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM secrets`); n != 0 {
			t.Fatalf("%d secrets stored by a refused creation", n)
		}
		f.assertNoOrphanKeys(t, "refused creation")

		f.setExpress(t, f.a, enableExpress(true))
		cs := f.createExpress(ctx, t, f.a, in)
		s := cs.Secret
		if !s.Express || !s.Anonymous() || s.CreatorKind != SecretCreatorAnonymous || s.SenderEmail != "" ||
			s.APITokenID != "" || s.InvitationID != "" || s.State != SecretActive || s.Delivery != SecretDeliveryLink ||
			s.RecipientEmail != "" || s.ReadReceipt || s.HasPassphrase() || s.FileSize != 0 || s.TenantID != f.a ||
			!s.CreatedAt.Equal(f.now) || !s.ActivatedAt.Equal(f.now) || !s.ExpiresAt.Equal(f.now.Add(24*time.Hour)) ||
			s.Duration != tenant.SecretDuration1d || !id.SecretTokenValid(cs.Token) || !id.Valid(id.Secret, s.ID) {
			t.Fatalf("express secret = %+v (token %q)", s, cs.Token)
		}
		st, err := f.repo.StatusByToken(ctx, f.a, cs.Token, ExpressGate{}, f.now)
		if err != nil || st.ID != s.ID || !st.Express || !st.Anonymous() || st.State != SecretActive {
			t.Fatalf("StatusByToken = %+v, %v", st, err)
		}
		out, err := f.repo.Reveal(ctx, f.a, cs.Token, ExpressGate{}, p.key, p.proof, f.now)
		if err != nil || out.SealedText != sealedText || out.Secret.State != SecretRead || !out.Secret.Express ||
			out.FileGrant != "" {
			t.Fatalf("Reveal = %+v, %v", out, err)
		}
		f.assertNoOrphanKeys(t, "revealed")

		// The durations are fixed: 1h, 1d and 7d only.
		for _, d := range tenant.AllSecretDurations() {
			c := f.expressInput(newProofs())
			c.Duration = d
			created, err := f.repo.CreateExpress(ctx, f.a, c)
			switch {
			case d.ExpressDuration() && (err != nil || !created.Secret.ExpiresAt.Equal(f.now.Add(d.Duration()))):
				t.Errorf("duration %s: %+v, %v", d, created.Secret, err)
			case !d.ExpressDuration() && !errors.Is(err, ErrInvalid):
				t.Errorf("duration %s accepted: %v", d, err)
			}
		}
		for name, mod := range map[string]func(*CreateExpressSecret){
			"short verifier":     func(c *CreateExpressSecret) { c.Verifier = c.Verifier[:5] },
			"short key verifier": func(c *CreateExpressSecret) { c.KeyVerifier = nil },
			"short sealed text":  func(c *CreateExpressSecret) { c.SealedText = "x" },
			"not base64url":      func(c *CreateExpressSecret) { c.SealedText = strings.Repeat("!", 64) },
			"sealed text long":   func(c *CreateExpressSecret) { c.SealedText = strings.Repeat("a", MaxSecretSealedTextLen+1) },
			"no duration":        func(c *CreateExpressSecret) { c.Duration = "" },
		} {
			c := f.expressInput(newProofs())
			mod(&c)
			if _, err := f.repo.CreateExpress(ctx, f.a, c); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}

		// API tokens, while the anonymous mode is off: a token allowed for
		// the express secrets creates them; an unknown, foreign, revoked
		// or expired token is unusable (and so unknown); a token without
		// the opt-in is refused.
		f.setExpress(t, f.a, enableExpress(false))
		tc := f.expressInput(newProofs())
		unusable := func(err error) bool { return errors.Is(err, ErrExpressTokenUnusable) && errors.Is(err, ErrNotFound) }
		for name, tokID := range map[string]string{
			"unknown token":      id.New(id.APIToken),
			"token of B":         f.expressToken(t, f.b),
			"malformed token id": "tok_x",
		} {
			tc.APITokenID = tokID
			if _, err := f.repo.CreateExpress(ctx, f.a, tc); !unusable(err) {
				t.Errorf("%s: %v", name, err)
			}
		}
		tc.APITokenID = f.apiToken(t, f.a)
		if _, err := f.repo.CreateExpress(ctx, f.a, tc); !errors.Is(err, ErrExpressTokenNotAllowed) || !errors.Is(err, ErrSecretPolicy) {
			t.Errorf("token without the opt-in: %v", err)
		}
		tok := f.expressToken(t, f.a)
		tc.APITokenID = tok
		byTok, err := f.repo.CreateExpress(ctx, f.a, tc)
		if err != nil || byTok.Secret.CreatorKind != SecretCreatorAPIToken || byTok.Secret.APITokenID != tok ||
			byTok.Secret.SenderEmail != "" || !byTok.Secret.Express || byTok.Secret.Anonymous() ||
			byTok.Secret.State != SecretActive {
			t.Fatalf("token creation = %+v, %v", byTok.Secret, err)
		}
		if _, _, err := f.db.APITokens().Revoke(ctx, f.a, tok, f.now); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.CreateExpress(ctx, f.a, tc); !unusable(err) {
			t.Errorf("revoked token: %v", err)
		}
		expired := id.New(id.APIToken)
		hash := sha256.Sum256([]byte(expired))
		_, err = f.db.APITokens().Create(ctx, f.a, APIToken{
			ID: expired, Name: "old", Prefix: "tt_Ex", TokenHash: hash[:], CreatedBy: "root", CreatedAt: f.now.Add(-time.Hour),
			ExpiresAt: f.now.Add(-time.Minute), ExpressAllowed: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("::/0")},
		})
		if err != nil {
			t.Fatal(err)
		}
		tc.APITokenID = expired
		if _, err := f.repo.CreateExpress(ctx, f.a, tc); !unusable(err) {
			t.Errorf("expired token: %v", err)
		}
		f.assertNoOrphanKeys(t, "token creations")

		// Tenant states: in setup, being deleted.
		setup, err := f.db.Tenants().Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateSetup, Name: "S",
			FQDN: "s.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.setExpress(t, setup.ID, enableExpress(true))
		if _, err := f.repo.CreateExpress(ctx, setup.ID, f.expressInput(newProofs())); !errors.Is(err, ErrTenantInSetup) {
			t.Errorf("tenant in setup: %v", err)
		}
		f.setExpress(t, f.b, enableExpress(true))
		if err := f.db.Tenants().SetStatus(ctx, f.b, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.CreateExpress(ctx, f.b, f.expressInput(newProofs())); !errors.Is(err, ErrNotFound) ||
			errors.Is(err, ErrExpressTokenUnusable) {
			t.Errorf("tenant being deleted: %v", err)
		}
		if _, err := f.repo.CreateExpress(ctx, tenant.ID(id.New(id.Tenant)), f.expressInput(newProofs())); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown tenant: %v", err)
		}
		f.assertNoOrphanKeys(t, "tenant states")
		if _, err := f.db.Secrets(nil).CreateExpress(ctx, f.a, in); !errors.Is(err, errSecretNoKeys) {
			t.Errorf("without key vault: %v", err)
		}
	})
}

// TestSecretsExpressLimits checks the tenant cap of the live express
// secrets (anonymous creations only), the hourly limit of a token, and
// that the express secrets stay out of the 2.1 limits of the token.
func TestSecretsExpressLimits(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.setExpress(t, f.a, func(s *tenant.ExpressSettings) { s.Enabled, s.MaxPending, s.PerHourPerToken = true, 3, 2 })
		f.setExpress(t, f.b, func(s *tenant.ExpressSettings) { s.Enabled, s.MaxPending = true, 1 })
		tok := f.expressToken(t, f.a)
		create := func(tid tenant.ID, tokID string, at time.Time, d tenant.SecretDuration) (CreatedSecret, error) {
			c := f.expressInput(newProofs())
			c.APITokenID, c.Now, c.Duration = tokID, at, d
			return f.repo.CreateExpress(ctx, tid, c)
		}
		must := func(cs CreatedSecret, err error) CreatedSecret {
			t.Helper()
			if err != nil {
				t.Fatalf("CreateExpress: %v", err)
			}
			return cs
		}

		// Two anonymous secrets of an hour and one token secret fill the
		// cap: the next anonymous one is refused, the token ones still
		// pass (the count goes over the cap).
		must(create(f.a, "", f.now, tenant.SecretDuration1h))
		must(create(f.a, "", f.now, tenant.SecretDuration1h))
		must(create(f.a, tok, f.now, tenant.SecretDuration7d))
		if _, err := create(f.a, "", f.now, tenant.SecretDuration1d); !errors.Is(err, ErrExpressLimit) || !errors.Is(err, ErrLimitReached) {
			t.Fatalf("anonymous creation at the cap: %v", err)
		}
		must(create(f.a, tok, f.now.Add(time.Minute), tenant.SecretDuration7d))

		// The token reached its hourly limit: the wait runs until its
		// oldest creation leaves the window.
		_, err := create(f.a, tok, f.now.Add(2*time.Minute), tenant.SecretDuration1h)
		var rate *ExpressTokenRateError
		if !errors.As(err, &rate) || rate.RetryAfter != 58*time.Minute || !errors.Is(err, ErrExpressTokenRate) ||
			!errors.Is(err, ErrLimitReached) || !strings.Contains(err.Error(), "58m0s") {
			t.Fatalf("token over its hourly limit: %v", err)
		}
		// Another token has its own limit; the other tenant its own cap.
		must(create(f.a, f.expressToken(t, f.a), f.now.Add(2*time.Minute), tenant.SecretDuration1h))
		must(create(f.b, "", f.now, tenant.SecretDuration1h))
		if _, err := create(f.b, "", f.now, tenant.SecretDuration1h); !errors.Is(err, ErrExpressLimit) {
			t.Errorf("cap of B: %v", err)
		}

		// One hour later the anonymous secrets of an hour are no longer
		// live (even unswept) and the first token creation left the
		// window.
		later := f.now.Add(time.Hour)
		must(create(f.a, tok, later, tenant.SecretDuration1h))
		if _, err := create(f.a, tok, later, tenant.SecretDuration1h); !errors.As(err, &rate) || rate.RetryAfter != time.Minute {
			t.Errorf("token limit one hour later: %v", err)
		}
		// Live: the two 7-day token secrets, the one of the second token
		// and the one just created: 4, over the cap.
		if _, err := create(f.a, "", later, tenant.SecretDuration1h); !errors.Is(err, ErrExpressLimit) {
			t.Errorf("anonymous creation over the cap: %v", err)
		}
		f.setExpress(t, f.a, func(s *tenant.ExpressSettings) { s.Enabled, s.MaxPending, s.PerHourPerToken = true, 10, 2 })
		must(create(f.a, "", later, tenant.SecretDuration1h))

		// The express secrets of a token never count in its 2.1 limits.
		f.setExpress(t, f.a, func(s *tenant.ExpressSettings) { s.PerHourPerToken = tenant.MaxExpressPerHourPerToken })
		heavy := f.expressToken(t, f.a)
		for range SecretMaxOpen {
			must(create(f.a, heavy, later, tenant.SecretDuration1d))
		}
		in := f.input(newProofs())
		in.CreatorKind, in.APITokenID, in.Now = SecretCreatorAPIToken, heavy, later
		if _, err := f.repo.Create(ctx, f.a, in); err != nil {
			t.Errorf("2.1 secret of a token holding %d express secrets: %v", SecretMaxOpen, err)
		}
		f.assertNoOrphanKeys(t, "limits")
	})
}

// TestSecretsExpressGate checks the read gate of the express secrets: the
// instance kill switch closes every express secret, the anonymous mode of
// the tenant closes the anonymous ones, an unknown token stays unknown, a
// 2.1 secret is never closed, and nothing is consumed.
func TestSecretsExpressGate(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.setExpress(t, f.a, enableExpress(true))
		pa, pt, p2 := newProofs(), newProofs(), newProofs()
		anon := f.createExpress(ctx, t, f.a, f.expressInput(pa))
		tc := f.expressInput(pt)
		tc.APITokenID = f.expressToken(t, f.a)
		byTok := f.createExpress(ctx, t, f.a, tc)
		v21 := f.create(ctx, t, f.a, f.input(p2))
		kill := ExpressGate{KillSwitch: true}
		wrong := newProofs()
		closed := func(what string, err error) {
			t.Helper()
			if !errors.Is(err, ErrExpressClosed) {
				t.Errorf("%s: %v, want closed", what, err)
			}
		}

		// Kill switch: every express secret, status and reveal, even with
		// wrong proofs; nothing counted.
		for name, c := range map[string]CreatedSecret{"anonymous": anon, "token": byTok} {
			_, err := f.repo.StatusByToken(ctx, f.a, c.Token, kill, f.now)
			closed(name+" status", err)
			_, err = f.repo.Reveal(ctx, f.a, c.Token, kill, wrong.key, wrong.proof, f.now)
			closed(name+" reveal", err)
			if n := f.failedProofs(t, c.Secret.ID); n != 0 {
				t.Errorf("%s: %d failures counted while closed", name, n)
			}
		}
		if st, err := f.repo.StatusByToken(ctx, f.a, v21.Token, kill, f.now); err != nil || st.Express || st.Anonymous() {
			t.Errorf("2.1 secret under the kill switch = %+v, %v", st, err)
		}
		// An unknown token, or a token of another tenant, is unknown first.
		unknown, err := id.NewSecretToken()
		if err != nil {
			t.Fatal(err)
		}
		for name, try := range map[string]func() error{
			"unknown status": func() error { _, err := f.repo.StatusByToken(ctx, f.a, unknown, kill, f.now); return err },
			"unknown reveal": func() error {
				_, err := f.repo.Reveal(ctx, f.a, unknown, kill, pa.key, pa.proof, f.now)
				return err
			},
			"other tenant status": func() error { _, err := f.repo.StatusByToken(ctx, f.b, anon.Token, kill, f.now); return err },
			"other tenant reveal": func() error {
				_, err := f.repo.Reveal(ctx, f.b, anon.Token, kill, pa.key, pa.proof, f.now)
				return err
			},
		} {
			if err := try(); !errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpressClosed) {
				t.Errorf("%s: %v, want not found", name, err)
			}
		}

		// The anonymous mode of the tenant closes the anonymous secrets
		// only.
		f.setExpress(t, f.a, enableExpress(false))
		_, err = f.repo.StatusByToken(ctx, f.a, anon.Token, ExpressGate{}, f.now)
		closed("anonymous status, mode off", err)
		_, err = f.repo.Reveal(ctx, f.a, anon.Token, ExpressGate{}, pa.key, pa.proof, f.now)
		closed("anonymous reveal, mode off", err)
		if st, err := f.repo.StatusByToken(ctx, f.a, byTok.Token, ExpressGate{}, f.now); err != nil || !st.Express || st.Anonymous() {
			t.Errorf("token secret, mode off = %+v, %v", st, err)
		}
		if n := f.failedProofs(t, anon.Secret.ID); n != 0 {
			t.Errorf("%d failures counted while closed", n)
		}

		// Reopened: the same link works, once.
		f.setExpress(t, f.a, enableExpress(true))
		if out, err := f.repo.Reveal(ctx, f.a, anon.Token, ExpressGate{}, pa.key, pa.proof, f.now); err != nil || out.SealedText != sealedText {
			t.Fatalf("reveal after reopening = %+v, %v", out, err)
		}
		// A tombstone is closed as well while the service is.
		_, err = f.repo.StatusByToken(ctx, f.a, anon.Token, kill, f.now)
		closed("tombstone status", err)
		if st, err := f.repo.StatusByToken(ctx, f.a, anon.Token, ExpressGate{}, f.now); err != nil || st.State != SecretRead {
			t.Errorf("tombstone status, open = %+v, %v", st, err)
		}

		// Closed between the key proof check and the claim of a reveal:
		// refused in the write transaction, nothing written.
		late := f.createExpress(ctx, t, f.a, f.expressInput(pa))
		claimHooks.Store(late.Secret.ID, func() { f.setExpress(t, f.a, enableExpress(false)) })
		_, err = f.repo.Reveal(ctx, f.a, late.Token, ExpressGate{}, pa.key, pa.proof, f.now)
		claimHooks.Delete(late.Secret.ID)
		closed("closed during the reveal", err)
		if s, err := f.repo.Get(ctx, f.a, late.Secret.ID); err != nil || s.State != SecretActive || s.FailedProofs != 0 {
			t.Errorf("secret closed during the reveal = %+v, %v", s, err)
		}
	})
}

// TestSecretsExpressAdmin checks the administration paths on express
// secrets: the lookup by link, the lists, the address operations that
// never match them, the admin deletion and the lifecycle sweeps.
func TestSecretsExpressAdmin(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.setExpress(t, f.a, enableExpress(true))
		anon := f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		pending := f.create(ctx, t, f.a, withFile(f.input(newProofs()), 100))
		v21 := f.create(ctx, t, f.a, f.input(newProofs()))

		// Lookup: any state, as stored, metadata only, in the tenant.
		for name, c := range map[string]CreatedSecret{"express": anon, "pending": pending, "2.1": v21} {
			s, err := f.db.Secrets(nil).LookupByToken(ctx, f.a, c.Token)
			if err != nil || s.ID != c.Secret.ID || s.State != c.Secret.State || s.Express != c.Secret.Express {
				t.Errorf("LookupByToken(%s) = %+v, %v", name, s, err)
			}
		}
		if s, err := f.repo.LookupByToken(ctx, f.a, anon.Token); err != nil || !s.Express || !s.Anonymous() {
			t.Errorf("LookupByToken(express) = %+v, %v", s, err)
		}
		// Past its expiry it is still found, as stored (no expiry applied).
		if s, err := f.repo.LookupByToken(ctx, f.a, anon.Token); err != nil || s.State != SecretActive {
			t.Errorf("LookupByToken past expiry = %+v, %v", s, err)
		}
		unknown, _ := id.NewSecretToken()
		for name, try := range map[string]func() error{
			"malformed": func() error { _, err := f.repo.LookupByToken(ctx, f.a, "tts_x"); return err },
			"unknown":   func() error { _, err := f.repo.LookupByToken(ctx, f.a, unknown); return err },
			"tenant B":  func() error { _, err := f.repo.LookupByToken(ctx, f.b, anon.Token); return err },
		} {
			if err := try(); !errors.Is(err, ErrNotFound) {
				t.Errorf("lookup %s: %v", name, err)
			}
		}

		// The admin list shows the express secret; the address filters,
		// the "my transfers" list and the data-subject operations never
		// match it.
		page, err := f.repo.ListFiltered(ctx, f.a, SecretFilter{}, SecretListOptions{})
		if err != nil || len(page.Items) != 3 {
			t.Fatalf("ListFiltered = %+v, %v", page.Items, err)
		}
		express := 0
		for _, s := range page.Items {
			if s.Express {
				express++
			}
		}
		if express != 1 {
			t.Errorf("%d express secrets listed, want 1", express)
		}
		page, err = f.repo.ListFiltered(ctx, f.a, SecretFilter{State: SecretActive, Sender: "alice@a.example.com"}, SecretListOptions{})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != v21.Secret.ID {
			t.Errorf("ListFiltered(sender) = %+v, %v", page.Items, err)
		}
		page, err = f.repo.ListBySender(ctx, f.a, "alice@a.example.com", SecretListOptions{})
		if err != nil || len(page.Items) != 2 {
			t.Errorf("ListBySender = %+v, %v", page.Items, err)
		}
		if n, err := f.repo.CountByAddress(ctx, f.a, "alice@a.example.com"); err != nil || n != 2 {
			t.Errorf("CountByAddress = %d, %v", n, err)
		}
		erased, err := f.repo.DeleteByAddress(ctx, f.a, "alice@a.example.com")
		if err != nil || erased.Deleted != 2 {
			t.Fatalf("DeleteByAddress = %+v, %v", erased, err)
		}
		if s, err := f.repo.Get(ctx, f.a, anon.Secret.ID); err != nil || s.State != SecretActive {
			t.Errorf("express secret after the erasure of an address = %+v, %v", s, err)
		}

		// The admin deletion ends it like any secret.
		ended, err := f.repo.DeleteByAdmin(ctx, f.a, anon.Secret.ID, f.now)
		if err != nil || ended.Secret.State != SecretDeleted || ended.Secret.EndReason != SecretEndDeletedByAdmin ||
			!ended.Secret.Express || ended.RemovedFile != "" {
			t.Fatalf("DeleteByAdmin = %+v, %v", ended, err)
		}
		// The expiry sweep and the tombstone purge.
		swept := f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		out, _, err := f.repo.ExpireDue(ctx, f.now.Add(25*time.Hour), SecretSweepLimit)
		if err != nil || len(out) != 1 || out[0].Secret.ID != swept.Secret.ID || out[0].Secret.State != SecretExpired ||
			!out[0].Secret.Express {
			t.Fatalf("ExpireDue = %+v, %v", out, err)
		}
		if n, err := f.repo.PurgeTombstones(ctx, f.a, f.now.Add(SecretTombstoneRetention+26*time.Hour)); err != nil || n != 2 {
			t.Errorf("PurgeTombstones = %d, %v", n, err)
		}
		f.assertNoOrphanKeys(t, "admin paths")
	})
}

// TestSecretsPurgeAnonymousExpress checks the purge of the live anonymous
// express secrets of a tenant, in batches: tokens, 2.1 secrets,
// tombstones and the other tenant are left alone; the keys are destroyed.
func TestSecretsPurgeAnonymousExpress(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.setExpress(t, f.a, enableExpress(true))
		f.setExpress(t, f.b, enableExpress(true))
		r := f.db.Secrets(f.keys)
		r.expressPurgeBatch = 2
		var live []CreatedSecret
		for range 5 {
			live = append(live, f.createExpress(ctx, t, f.a, f.expressInput(newProofs())))
		}
		p := newProofs()
		read := f.createExpress(ctx, t, f.a, f.expressInput(p))
		if _, err := f.repo.Reveal(ctx, f.a, read.Token, ExpressGate{}, p.key, p.proof, f.now); err != nil {
			t.Fatal(err)
		}
		tc := f.expressInput(newProofs())
		tc.APITokenID = f.expressToken(t, f.a)
		byTok := f.createExpress(ctx, t, f.a, tc)
		v21 := f.create(ctx, t, f.a, f.input(newProofs()))
		other := f.createExpress(ctx, t, f.b, f.expressInput(newProofs()))

		destroyed := f.keys.destroyed.Load()
		at := f.now.Add(time.Minute)
		if n, err := r.PurgeAnonymousExpress(ctx, f.a, at); err != nil || n != 5 {
			t.Fatalf("PurgeAnonymousExpress = %d, %v", n, err)
		}
		if d := f.keys.destroyed.Load() - destroyed; d != 5 {
			t.Errorf("%d keys destroyed, want 5", d)
		}
		for _, c := range live {
			s, err := f.repo.Get(ctx, f.a, c.Secret.ID)
			if err != nil || s.State != SecretDeleted || s.EndReason != SecretEndDeletedByAdmin || !s.EndedAt.Equal(at) {
				t.Errorf("purged secret = %+v, %v", s, err)
			}
			st, err := f.repo.StatusByToken(ctx, f.a, c.Token, ExpressGate{}, at)
			if err != nil || st.State != SecretDeleted || st.EndReason != SecretEndDeletedByAdmin {
				t.Errorf("status of a purged secret = %+v, %v", st, err)
			}
		}
		for name, c := range map[string]struct {
			tid   tenant.ID
			id    string
			state SecretState
		}{
			"tombstone": {f.a, read.Secret.ID, SecretRead}, "token": {f.a, byTok.Secret.ID, SecretActive},
			"2.1": {f.a, v21.Secret.ID, SecretActive}, "tenant B": {f.b, other.Secret.ID, SecretActive},
		} {
			if s, err := f.repo.Get(ctx, c.tid, c.id); err != nil || s.State != c.state {
				t.Errorf("%s after the purge = %+v, %v", name, s, err)
			}
		}
		f.assertNoOrphanKeys(t, "purge")
		// Idempotent; a full last batch takes one more empty round.
		if n, err := r.PurgeAnonymousExpress(ctx, f.a, at); err != nil || n != 0 {
			t.Errorf("second purge = %d, %v", n, err)
		}
		for range 2 {
			f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		}
		if n, err := r.PurgeAnonymousExpress(ctx, f.a, at); err != nil || n != 2 {
			t.Errorf("purge of a full batch = %d, %v", n, err)
		}
		if n, err := f.db.Secrets(nil).PurgeAnonymousExpress(ctx, f.a, at); !errors.Is(err, errSecretNoKeys) || n != 0 {
			t.Errorf("without key vault = %d, %v", n, err)
		}
	})
}

// TestSecretsPurgeAnonymousExpressRace checks that a purge whose listed
// secrets are ended before its updates (a reveal and the expiry task, on
// PostgreSQL in their own transactions committed while the batch is open,
// READ COMMITTED; on SQLite, whose writer is serialized, inside the batch)
// skips them, ends the others and fails nothing; the keys stay destroyed
// once each.
func TestSecretsPurgeAnonymousExpressRace(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.setExpress(t, f.a, enableExpress(true))
		p := newProofs()
		revealed := f.createExpress(ctx, t, f.a, f.expressInput(p))
		short := f.expressInput(newProofs())
		short.Duration = tenant.SecretDuration1h
		expiring := f.createExpress(ctx, t, f.a, short)
		purged := f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		at := f.now.Add(2 * time.Hour) // the 1h secret is past its expiry, still active

		r := f.db.Secrets(f.keys)
		calls := 0
		r.expressPurgeHook = func(ctx context.Context, tx *ScopedTx, listed []secretRow) error {
			if calls++; calls > 1 {
				return nil
			}
			if len(listed) != 3 {
				t.Errorf("listed %d secrets, want 3", len(listed))
			}
			if e.Driver == "postgres" {
				if _, err := f.repo.Reveal(ctx, f.a, revealed.Token, ExpressGate{}, p.key, p.proof, at); err != nil {
					return err
				}
				out, _, err := f.repo.ExpireDue(ctx, at, SecretSweepLimit)
				if err != nil || len(out) != 1 || out[0].Secret.ID != expiring.Secret.ID {
					t.Errorf("concurrent expiry = %+v, %v", out, err)
				}
				return err
			}
			for _, row := range listed {
				q, args := qSecretExpire, []any{toMillis(at), row.ID, toMillis(at)}
				switch row.ID {
				case purged.Secret.ID:
					continue
				case revealed.Secret.ID:
					q, args = qSecretMarkDeleted, []any{toMillis(at), string(SecretEndDeletedByAdmin), row.ID}
				}
				if err := execOne(ctx, tx, q, args...); err != nil {
					return err
				}
				if err := r.destroyKeys(ctx, tx, row.keyIDs()); err != nil {
					return err
				}
			}
			return nil
		}
		destroyed := f.keys.destroyed.Load()
		if n, err := r.PurgeAnonymousExpress(ctx, f.a, at); err != nil || n != 1 {
			t.Fatalf("PurgeAnonymousExpress = %d, %v", n, err)
		}
		if d := f.keys.destroyed.Load() - destroyed; d != 3 {
			t.Errorf("%d keys destroyed, want 3 (one per secret)", d)
		}
		want := map[string]SecretState{revealed.Secret.ID: SecretRead, expiring.Secret.ID: SecretExpired, purged.Secret.ID: SecretDeleted}
		if e.Driver != "postgres" {
			want[revealed.Secret.ID] = SecretDeleted
		}
		for secID, state := range want {
			if s, err := f.repo.Get(ctx, f.a, secID); err != nil || s.State != state {
				t.Errorf("%s = %+v, %v, want %s", secID, s.State, err, state)
			}
		}
		if s, _ := f.repo.Get(ctx, f.a, purged.Secret.ID); s.EndReason != SecretEndDeletedByAdmin || !s.EndedAt.Equal(at) {
			t.Errorf("purged = %+v", s)
		}
		f.assertNoOrphanKeys(t, "purge race")

		// A failing hook fails the batch: nothing more is ended.
		f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		r.expressPurgeHook = func(context.Context, *ScopedTx, []secretRow) error { return errInjected }
		if n, err := r.PurgeAnonymousExpress(ctx, f.a, at); !errors.Is(err, errInjected) || n != 0 {
			t.Errorf("failing hook = %d, %v", n, err)
		}
	})
}

// TestSecretsExpressFaults covers the failure paths of the express
// secrets on SQLite.
func TestSecretsExpressFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := newSecretFixtureDB(t, db)
	f.setExpress(t, f.a, func(s *tenant.ExpressSettings) { s.Enabled = true })
	tok := f.expressToken(t, f.a)

	// Creation.
	r := f.db.Secrets(f.keys)
	r.newToken = func() (string, error) { return "", errInjected }
	if _, err := r.CreateExpress(ctx, f.a, f.expressInput(newProofs())); !errors.Is(err, errInjected) {
		t.Errorf("token failure: %v", err)
	}
	newID := f.db.newID
	f.db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	if _, err := f.repo.CreateExpress(ctx, f.a, f.expressInput(newProofs())); !errors.Is(err, errInjected) {
		t.Errorf("id failure: %v", err)
	}
	f.db.newID = newID
	f.keys.shortKey = true
	if _, err := f.repo.CreateExpress(ctx, f.a, f.expressInput(newProofs())); err == nil {
		t.Error("short data key accepted")
	}
	f.keys.shortKey = false
	f.keys.newErr = errInjected
	if _, err := f.repo.CreateExpress(ctx, f.a, f.expressInput(newProofs())); !errors.Is(err, errInjected) {
		t.Errorf("data key failure: %v", err)
	}
	f.keys.newErr = nil
	withToken := f.expressInput(newProofs())
	withToken.APITokenID = tok
	for _, s := range []struct {
		match string
		in    CreateExpressSecret
	}{
		{"FROM api_tokens WHERE tenant_id = ? AND id = ?", withToken},
		{"INSERT INTO secrets", f.expressInput(newProofs())},
		{"n.express_max_pending", f.expressInput(newProofs())},
		{"AND express AND state = 'active' AND expires_at > ?", f.expressInput(newProofs())},
		{"min(created_at)", withToken},
		{"FROM secrets WHERE tenant_id = ? AND id = ?", f.expressInput(newProofs())},
	} {
		plan.add(faultQuery, s.match, 0)
		plan.add(faultExec, s.match, 0)
		if _, err := f.repo.CreateExpress(ctx, f.a, s.in); !errors.Is(err, errInjected) {
			t.Errorf("fault %q: %v", s.match, err)
		}
		plan.reset()
	}
	d := *f.db.dialect
	saved := f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	if _, err := f.repo.CreateExpress(ctx, f.a, f.expressInput(newProofs())); err == nil {
		t.Error("creation with a failing tenant lock succeeded")
	}
	f.db.dialect = saved
	f.assertNoOrphanKeys(t, "creation faults")

	// The read gate, in the status and in both steps of a reveal.
	p := newProofs()
	cs := f.createExpress(ctx, t, f.a, f.expressInput(p))
	plan.add(faultQuery, "s.express, s.creator_kind", 0)
	if _, err := f.repo.StatusByToken(ctx, f.a, cs.Token, ExpressGate{}, f.now); !errors.Is(err, errInjected) {
		t.Errorf("gate fault in the status: %v", err)
	}
	for after := range 2 {
		plan.reset()
		plan.add(faultQuery, "s.express, s.creator_kind", after)
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, ExpressGate{}, p.key, p.proof, f.now); !errors.Is(err, errInjected) {
			t.Errorf("gate fault in step %d of the reveal: %v", after+1, err)
		}
	}
	plan.reset()

	// The purge: the list, the end of a secret, the key, and a failure
	// after a committed batch.
	r = f.db.Secrets(f.keys)
	r.expressPurgeBatch = 1
	for _, s := range []struct{ op, match string }{
		{faultQuery, "creator_kind = 'anonymous'"},
		{faultExec, "SET state = 'deleted'"},
	} {
		plan.add(s.op, s.match, 0)
		if n, err := r.PurgeAnonymousExpress(ctx, f.a, f.now); !errors.Is(err, errInjected) || n != 0 {
			t.Errorf("purge fault %q = %d, %v", s.match, n, err)
		}
		plan.reset()
	}
	f.keys.dstrErr = errInjected
	if n, err := r.PurgeAnonymousExpress(ctx, f.a, f.now); !errors.Is(err, errInjected) || n != 0 {
		t.Errorf("purge key fault = %d, %v", n, err)
	}
	f.keys.dstrErr = nil
	f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
	plan.add(faultQuery, "creator_kind = 'anonymous'", 1)
	if n, err := r.PurgeAnonymousExpress(ctx, f.a, f.now); !errors.Is(err, errInjected) || n != 1 {
		t.Errorf("purge failing after a batch = %d, %v", n, err)
	}
	plan.reset()
	if n, err := r.PurgeAnonymousExpress(ctx, f.a, f.now); err != nil || n != 1 {
		t.Errorf("purge resumed = %d, %v", n, err)
	}
	f.assertNoOrphanKeys(t, "purge faults")
}
