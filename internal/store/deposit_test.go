package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// msNow is fixedNow at the precision of the stored timestamps.
var msNow = fixedNow.Truncate(time.Millisecond)

// badTenants are tenant IDs every repository method rejects with
// ErrInvalid.
var badTenants = []tenant.ID{"", "bogus"}

// tokenHash returns the SHA-256 of a token, as callers compute it.
func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// newToken returns a public token with 128 bits of entropy.
func newToken(t *testing.T, prefix string) string {
	t.Helper()
	tok, err := id.NewToken(prefix, id.MinTokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// wantErr fails the test unless err matches target.
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("%s: err = %v, want %v", what, err, target)
	}
}

// inTx runs fn in a scoped transaction of tid.
func inTx(t *testing.T, db *store.DB, tid tenant.ID, fn func(*store.ScopedTx) error) error {
	t.Helper()
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	return s.Tx(context.Background(), fn)
}

// inTxCtx is inTx with the caller's context, for use inside closures.
func inTxCtx(ctx context.Context, t *testing.T, db *store.DB, tid tenant.ID, fn func(*store.ScopedTx) error) error {
	t.Helper()
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	return s.Tx(ctx, fn)
}

// mustSecret stores a wrapped secret for tid and returns its ID.
func mustSecret(t *testing.T, db *store.DB, tid tenant.ID, purpose string) string {
	t.Helper()
	k := newWrappedKey(mk1, "sealed")
	k.Purpose = purpose
	return mustCreateKey(t, db, tid, k).ID
}

// newInvitation returns a valid invitation of an external address.
func newInvitation(t *testing.T) store.Invitation {
	t.Helper()
	return store.Invitation{
		ID: id.New(id.Invitation), TokenHash: tokenHash(newToken(t, "inv")),
		Email: "Bob@Partner.Example.org", InvitedBy: "Alice@Entity-A.example.com",
		Message: "Please send the signed contract.\nThanks.", Language: "en",
	}
}

// mustInvitation stores a new invitation for tid.
func mustInvitation(t *testing.T, db *store.DB, tid tenant.ID) store.Invitation {
	t.Helper()
	inv := newInvitation(t)
	if err := db.Invitations().Create(context.Background(), tid, inv); err != nil {
		t.Fatalf("Create invitation: %v", err)
	}
	return inv
}

func TestSMTPSettings(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SMTPSettings()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		if _, err := repo.Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(none) = %v", err)
		}
		relay := store.SMTPConfig{Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: " NoReply@Entity-A.Example.com "}
		if err := repo.Put(ctx, a.ID, relay); err != nil {
			t.Fatalf("Put(relay): %v", err)
		}
		want := relay
		want.FromAddress, want.UpdatedAt = "noreply@entity-a.example.com", msNow
		if got, err := repo.Get(ctx, a.ID); err != nil || got != want {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, want)
		}

		// Replace with an authenticated server and a password secret.
		secret := mustSecret(t, db, a.ID, store.KeyPurposeSecret)
		at := time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC)
		auth := store.SMTPConfig{
			Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: "mailer",
			PasswordKeyID: secret, FromAddress: "noreply@entity-a.example.com", FromName: "Entity A", UpdatedAt: at,
		}
		if err := repo.Put(ctx, a.ID, auth); err != nil {
			t.Fatalf("Put(auth): %v", err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got != auth {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, auth)
		}

		// The password key must be a secret of the same tenant.
		bad := auth
		bad.PasswordKeyID = mustSecret(t, db, a.ID, store.KeyPurposeDEK)
		wantErr(t, "Put(dek key)", repo.Put(ctx, a.ID, bad), store.ErrInvalid)
		bad.PasswordKeyID = mustSecret(t, db, b.ID, store.KeyPurposeSecret)
		wantErr(t, "Put(key of another tenant)", repo.Put(ctx, a.ID, bad), store.ErrNotFound)
		bad.PasswordKeyID = id.New(id.WrappedKey)
		wantErr(t, "Put(missing key)", repo.Put(ctx, a.ID, bad), store.ErrNotFound)

		// Isolation: B has its own settings and never sees A's.
		if _, err := repo.Get(ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(B) = %v", err)
		}
		tls := store.SMTPConfig{Host: "10.0.0.25", Port: 465, Security: store.SMTPSecurityTLS, FromAddress: "noreply@entity-b.example.com"}
		if err := repo.Put(ctx, b.ID, tls); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got != auth {
			t.Errorf("A's settings changed: %+v, %v", got, err)
		}

		// Rotate the password in one transaction: new secret, settings,
		// erasure of the previous secret.
		newSecret := mustSecret(t, db, a.ID, store.KeyPurposeSecret)
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			cur, err := repo.GetTx(ctx, tx)
			if err != nil {
				return err
			}
			next := cur
			next.PasswordKeyID = newSecret
			if err := repo.PutTx(ctx, tx, next); err != nil {
				return err
			}
			return db.WrappedKeys().DeleteTx(ctx, tx, cur.PasswordKeyID)
		})
		if err != nil {
			t.Fatalf("password rotation: %v", err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got.PasswordKeyID != newSecret {
			t.Errorf("after rotation: %+v, %v", got, err)
		}
		if _, err := db.WrappedKeys().Get(ctx, a.ID, secret); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("previous secret not erased: %v", err)
		}
		// Erasing the secret leaves the settings without password.
		if err := db.WrappedKeys().Delete(ctx, a.ID, newSecret); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got.PasswordKeyID != "" || got.Username != "mailer" {
			t.Errorf("after secret erasure: %+v, %v", got, err)
		}

		// Errors.
		c := newTenant(t, db, "transfer.entity-c.example.com")
		err = inTx(t, db, c.ID, func(tx *store.ScopedTx) error { _, err := repo.GetTx(ctx, tx); return err })
		wantErr(t, "GetTx(none)", err, store.ErrNotFound)
		err = inTx(t, db, c.ID, func(tx *store.ScopedTx) error { return repo.PutTx(ctx, tx, store.SMTPConfig{}) })
		wantErr(t, "PutTx(invalid)", err, store.ErrInvalid)
		wantErr(t, "Put(missing tenant)", repo.Put(ctx, tenant.ID(id.New(id.Tenant)), relay), store.ErrNotFound)
		for _, tid := range badTenants {
			_, err := repo.Get(ctx, tid)
			wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "Put(bad tenant)", repo.Put(ctx, tid, relay), store.ErrInvalid)
		}
		invalid := map[string]func(*store.SMTPConfig){
			"security":        func(s *store.SMTPConfig) { s.Security = "ssl" },
			"empty host":      func(s *store.SMTPConfig) { s.Host = "" },
			"long host":       func(s *store.SMTPConfig) { s.Host = strings.Repeat("a", 254) },
			"host chars":      func(s *store.SMTPConfig) { s.Host = "smtp.example.com\r\n" },
			"port zero":       func(s *store.SMTPConfig) { s.Port = 0 },
			"port high":       func(s *store.SMTPConfig) { s.Port = 65536 },
			"username length": func(s *store.SMTPConfig) { s.Username = strings.Repeat("u", 321) },
			"username bytes":  func(s *store.SMTPConfig) { s.Username = strings.Repeat("ü", 161) },
			"password alone":  func(s *store.SMTPConfig) { s.Username, s.PasswordKeyID = "", id.New(id.WrappedKey) },
			"auth in clear":   func(s *store.SMTPConfig) { s.Security = store.SMTPSecurityNone },
			"from name sep":   func(s *store.SMTPConfig) { s.FromName = "Entity\xe2\x80\xa8A" },
			"from quoted":     func(s *store.SMTPConfig) { s.FromAddress = `"no reply"@example.com` },
			"from display":    func(s *store.SMTPConfig) { s.FromAddress = "Entity <noreply@example.com>" },
			"from ip literal": func(s *store.SMTPConfig) { s.FromAddress = "noreply@[192.0.2.1]" },
			"from one label":  func(s *store.SMTPConfig) { s.FromAddress = "noreply@localhost" },
			"from idn":        func(s *store.SMTPConfig) { s.FromAddress = "noreply@bücher.example" },
			"from utf8 local": func(s *store.SMTPConfig) { s.FromAddress = "jöhn@example.com" },
			"from dots":       func(s *store.SMTPConfig) { s.FromAddress = "no..reply@example.com" },
			"from hyphen":     func(s *store.SMTPConfig) { s.FromAddress = "noreply@-example.com" },
			"from local len":  func(s *store.SMTPConfig) { s.FromAddress = strings.Repeat("a", 65) + "@example.com" },
			"from label len":  func(s *store.SMTPConfig) { s.FromAddress = "a@" + strings.Repeat("b", 64) + ".com" },
			"from total len":  func(s *store.SMTPConfig) { s.FromAddress = "a@" + strings.Repeat("b.", 126) + "com" },
			"from comment":    func(s *store.SMTPConfig) { s.FromAddress = "noreply@example.com (x)" },
			"from tab":        func(s *store.SMTPConfig) { s.FromAddress = "no\treply@example.com" },
			"from punycode":   func(s *store.SMTPConfig) { s.FromAddress = "user@xn--a.example.com" },
			"username ctrl":   func(s *store.SMTPConfig) { s.Username = "a\nb" },
			"from name":       func(s *store.SMTPConfig) { s.FromName = "Entity\r\nBcc: x@example.com" },
			"from name utf8":  func(s *store.SMTPConfig) { s.FromName = "\xff" },
			"password key":    func(s *store.SMTPConfig) { s.PasswordKeyID = id.New(id.Blocklist) },
			"from address":    func(s *store.SMTPConfig) { s.FromAddress = "not-an-address" },
		}
		for name, mutate := range invalid {
			cfg := auth
			cfg.PasswordKeyID = ""
			mutate(&cfg)
			wantErr(t, "Put(bad "+name+")", repo.Put(ctx, c.ID, cfg), store.ErrInvalid)
		}
		edge := store.SMTPConfig{
			Host: strings.Repeat("a", 253), Port: 65535, Security: store.SMTPSecurityTLS,
			Username: strings.Repeat("u", 320), FromAddress: "a.b+c@example.com", FromName: strings.Repeat("é", 100),
		}
		if err := repo.Put(ctx, c.ID, edge); err != nil {
			t.Errorf("Put(limits) = %v", err)
		}
	})
}

// newChallenge returns a valid challenge of email from ip, expiring in 15
// minutes.
func newChallenge(t *testing.T, email string, ip netip.Addr) store.Challenge {
	t.Helper()
	return store.Challenge{
		ID: newToken(t, "vch"), Email: email, CodeMAC: bytes.Repeat([]byte{7}, 32),
		AttemptsRemaining: store.MaxChallengeAttempts, ClientIP: ip, ExpiresAt: fixedNow.Add(15 * time.Minute),
	}
}

// Client IPs of the tests.
var (
	ipA = netip.MustParseAddr("10.0.0.1")
	ipB = netip.MustParseAddr("2001:db8::1")
)

func TestChallenges(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Challenges()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		c := newChallenge(t, "Alice@Entity-A.Example.com", ipA)
		if err := repo.Create(ctx, a.ID, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.Get(ctx, a.ID, c.ID)
		if err != nil || got.ID != c.ID || got.Email != "alice@entity-a.example.com" || !bytes.Equal(got.CodeMAC, c.CodeMAC) ||
			got.AttemptsRemaining != 2 || got.InvitationID != "" || got.ClientIP != ipA || !got.CreatedAt.Equal(msNow) ||
			!got.ExpiresAt.Equal(c.ExpiresAt.Truncate(time.Millisecond)) || !got.ConsumedAt.IsZero() || !got.Open(fixedNow) {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if got.Open(c.ExpiresAt) {
			t.Error("a challenge is open at its expiry")
		}

		// Rate-limit counts, per address and per IP, over a sliding window.
		mapped := newChallenge(t, "alice@entity-a.example.com", netip.MustParseAddr("::ffff:10.0.0.1"))
		mapped.CreatedAt = fixedNow.Add(-30 * time.Minute)
		other := newChallenge(t, "carol@entity-a.example.com", ipB)
		old := newChallenge(t, "alice@entity-a.example.com", ipA)
		old.CreatedAt = fixedNow.Add(-2 * time.Hour)
		for _, ch := range []store.Challenge{mapped, other, old} {
			if err := repo.Create(ctx, a.ID, ch); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := repo.Get(ctx, a.ID, mapped.ID); err != nil || got.ClientIP != ipA {
			t.Errorf("mapped IP stored as %v, %v", got.ClientIP, err)
		}
		hourAgo := fixedNow.Add(-time.Hour)
		counts := []struct {
			name string
			run  func(tenant.ID) (int, error)
			want int
		}{
			{"email", func(tid tenant.ID) (int, error) {
				return repo.CountSince(ctx, tid, "ALICE@entity-a.example.com", hourAgo)
			}, 2},
			{"email all", func(tid tenant.ID) (int, error) {
				return repo.CountSince(ctx, tid, "alice@entity-a.example.com", old.CreatedAt)
			}, 3},
			{"email now", func(tid tenant.ID) (int, error) {
				return repo.CountSince(ctx, tid, "alice@entity-a.example.com", fixedNow)
			}, 1},
			{"ip", func(tid tenant.ID) (int, error) { return repo.CountByIPSince(ctx, tid, ipA, hourAgo) }, 2},
			{"ip mapped", func(tid tenant.ID) (int, error) {
				return repo.CountByIPSince(ctx, tid, netip.MustParseAddr("::ffff:10.0.0.1"), hourAgo)
			}, 2},
			{"ip v6", func(tid tenant.ID) (int, error) { return repo.CountByIPSince(ctx, tid, ipB, hourAgo) }, 1},
		}
		for _, tc := range counts {
			if n, err := tc.run(a.ID); err != nil || n != tc.want {
				t.Errorf("count %s = %d, %v; want %d", tc.name, n, err, tc.want)
			}
			// Isolation: B never counts A's challenges.
			if n, err := tc.run(b.ID); err != nil || n != 0 {
				t.Errorf("count %s for B = %d, %v; want 0", tc.name, n, err)
			}
		}

		// Isolation: B can neither read, spend nor consume A's challenge.
		_, err = repo.Get(ctx, b.ID, c.ID)
		wantErr(t, "Get from B", err, store.ErrNotFound)
		_, err = repo.DecrementAttempt(ctx, b.ID, c.ID, fixedNow)
		wantErr(t, "DecrementAttempt from B", err, store.ErrNotFound)
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error { return repo.ConsumeTx(ctx, tx, c.ID, fixedNow) })
		wantErr(t, "ConsumeTx from B", err, store.ErrNotFound)
		if got, err := repo.Get(ctx, a.ID, c.ID); err != nil || got.AttemptsRemaining != 2 || !got.ConsumedAt.IsZero() {
			t.Errorf("A's challenge changed: %+v, %v", got, err)
		}

		// Wrong codes: 2, then 1, then dead.
		for want := 1; want >= 0; want-- {
			if n, err := repo.DecrementAttempt(ctx, a.ID, c.ID, fixedNow); err != nil || n != want {
				t.Fatalf("DecrementAttempt = %d, %v; want %d", n, err, want)
			}
		}
		_, err = repo.DecrementAttempt(ctx, a.ID, c.ID, fixedNow)
		wantErr(t, "DecrementAttempt(exhausted)", err, store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.ConsumeTx(ctx, tx, c.ID, fixedNow) })
		wantErr(t, "ConsumeTx(exhausted)", err, store.ErrNotFound)
		if got, err := repo.Get(ctx, a.ID, c.ID); err != nil || got.AttemptsRemaining != 0 || got.Open(fixedNow) {
			t.Errorf("exhausted challenge = %+v, %v", got, err)
		}

		// Expiry closes the challenge.
		_, err = repo.DecrementAttempt(ctx, a.ID, other.ID, other.ExpiresAt)
		wantErr(t, "DecrementAttempt(expired)", err, store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.ConsumeTx(ctx, tx, other.ID, other.ExpiresAt) })
		wantErr(t, "ConsumeTx(expired)", err, store.ErrNotFound)

		// The right code consumes the challenge, once.
		consumeAt := msNow.Add(time.Minute)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.ConsumeTx(ctx, tx, other.ID, consumeAt) }); err != nil {
			t.Fatalf("ConsumeTx: %v", err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.ConsumeTx(ctx, tx, other.ID, consumeAt) })
		wantErr(t, "ConsumeTx twice", err, store.ErrNotFound)
		_, err = repo.DecrementAttempt(ctx, a.ID, other.ID, consumeAt)
		wantErr(t, "DecrementAttempt(consumed)", err, store.ErrNotFound)
		if got, err := repo.Get(ctx, a.ID, other.ID); err != nil || !got.ConsumedAt.Equal(consumeAt) || got.Open(consumeAt) {
			t.Errorf("consumed challenge = %+v, %v", got, err)
		}

		// Invitation references stay within the tenant.
		invA, invB := mustInvitation(t, db, a.ID), mustInvitation(t, db, b.ID)
		withInv := newChallenge(t, "bob@partner.example.org", ipB)
		withInv.InvitationID = invA.ID
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.CreateTx(ctx, tx, withInv) }); err != nil {
			t.Fatalf("CreateTx(invitation): %v", err)
		}
		if got, err := repo.Get(ctx, a.ID, withInv.ID); err != nil || got.InvitationID != invA.ID {
			t.Errorf("Get(invitation) = %+v, %v", got, err)
		}
		for name, invID := range map[string]string{"invitation of B": invB.ID, "missing invitation": id.New(id.Invitation)} {
			ch := newChallenge(t, "bob@partner.example.org", ipB)
			ch.InvitationID = invID
			wantErr(t, "Create("+name+")", repo.Create(ctx, a.ID, ch), store.ErrNotFound)
		}

		// Errors.
		wantErr(t, "Create(duplicate)", repo.Create(ctx, b.ID, c), store.ErrConflict)
		wantErr(t, "Create(missing tenant)", repo.Create(ctx, tenant.ID(id.New(id.Tenant)), newChallenge(t, "a@example.com", ipA)), store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.CreateTx(ctx, tx, store.Challenge{}) })
		wantErr(t, "CreateTx(invalid)", err, store.ErrInvalid)
		_, err = repo.CountSince(ctx, a.ID, "nope", hourAgo)
		wantErr(t, "CountSince(bad email)", err, store.ErrInvalid)
		_, err = repo.CountByIPSince(ctx, a.ID, netip.Addr{}, hourAgo)
		wantErr(t, "CountByIPSince(zero ip)", err, store.ErrInvalid)
		for _, tid := range badTenants {
			wantErr(t, "Create(bad tenant)", repo.Create(ctx, tid, newChallenge(t, "a@example.com", ipA)), store.ErrInvalid)
			_, err := repo.Get(ctx, tid, c.ID)
			wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
			_, err = repo.CountSince(ctx, tid, "a@example.com", hourAgo)
			wantErr(t, "CountSince(bad tenant)", err, store.ErrInvalid)
			_, err = repo.CountByIPSince(ctx, tid, ipA, hourAgo)
			wantErr(t, "CountByIPSince(bad tenant)", err, store.ErrInvalid)
			_, err = repo.DecrementAttempt(ctx, tid, c.ID, fixedNow)
			wantErr(t, "DecrementAttempt(bad tenant)", err, store.ErrInvalid)
		}
		invalid := map[string]func(*store.Challenge){
			"email":         func(c *store.Challenge) { c.Email = "nope" },
			"ip":            func(c *store.Challenge) { c.ClientIP = netip.Addr{} },
			"id prefix":     func(c *store.Challenge) { c.ID = "vxx_" + strings.Repeat("a", 22) },
			"id short":      func(c *store.Challenge) { c.ID = "vch_" + strings.Repeat("a", 21) },
			"id long":       func(c *store.Challenge) { c.ID = "vch_" + strings.Repeat("a", 44) },
			"empty mac":     func(c *store.Challenge) { c.CodeMAC = nil },
			"long mac":      func(c *store.Challenge) { c.CodeMAC = make([]byte, store.MaxMACBytes+1) },
			"no attempts":   func(c *store.Challenge) { c.AttemptsRemaining = 0 },
			"many attempts": func(c *store.Challenge) { c.AttemptsRemaining = 3 },
			"invitation":    func(c *store.Challenge) { c.InvitationID = id.New(id.Blocklist) },
			"expiry":        func(c *store.Challenge) { c.ExpiresAt = fixedNow },
			"consumed":      func(c *store.Challenge) { c.ConsumedAt = fixedNow },
		}
		for name, mutate := range invalid {
			ch := newChallenge(t, "a@example.com", ipA)
			mutate(&ch)
			wantErr(t, "Create(bad "+name+")", repo.Create(ctx, a.ID, ch), store.ErrInvalid)
		}
		edge := newChallenge(t, "a@example.com", ipA)
		edge.ID, edge.CodeMAC, edge.AttemptsRemaining = "vch_"+strings.Repeat("Z", 43), make([]byte, store.MaxMACBytes), 1
		if err := repo.Create(ctx, a.ID, edge); err != nil {
			t.Errorf("Create(limits) = %v", err)
		}
	})
}

func TestVerifiedAddresses(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.VerifiedAddresses()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		const email = "alice@entity-a.example.com"
		var salt, zero [store.RecognitionSaltSize]byte // salt: returned by the last upsert
		upsert := func(tid tenant.ID, v store.VerifiedAddress) error {
			t.Helper()
			return inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				salt, err = repo.UpsertTx(ctx, tx, v)
				return err
			})
		}

		if _, err := repo.Get(ctx, a.ID, email); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(unverified) = %v", err)
		}
		// First verification from outside (an invitation): no internal
		// verification yet.
		first := store.VerifiedAddress{Email: "Alice@Entity-A.example.com", FirstVerifiedIP: ipB}
		if err := upsert(a.ID, first); err != nil {
			t.Fatalf("UpsertTx(first): %v", err)
		}
		want := store.VerifiedAddress{Email: email, FirstVerifiedAt: msNow, FirstVerifiedIP: ipB, LastUsedAt: msNow, RecognitionSalt: salt}
		if salt == zero {
			t.Error("no recognition salt drawn")
		}
		if got, err := repo.Get(ctx, a.ID, "ALICE@entity-a.example.com"); err != nil || got != want {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, want)
		}
		if !want.Active(msNow) || !want.Active(msNow.AddDate(1, 0, 0).Add(-time.Millisecond)) || want.Active(msNow.AddDate(1, 0, 0)) {
			t.Error("Active does not span exactly 12 months")
		}

		// A second verification, internal this time, keeps the first
		// verification details and records the internal one.
		later := msNow.Add(time.Hour)
		internal := store.VerifiedAddress{
			Email: email, FirstVerifiedAt: later, FirstVerifiedIP: netip.MustParseAddr("::ffff:10.0.0.1"),
			InternalVerifiedAt: later, InternalVerifiedIP: netip.MustParseAddr("::ffff:10.0.0.1"), LastUsedAt: later,
		}
		if err := upsert(a.ID, internal); err != nil {
			t.Fatalf("UpsertTx(internal): %v", err)
		}
		want.LastUsedAt, want.InternalVerifiedAt, want.InternalVerifiedIP = later, later, ipA
		if salt != want.RecognitionSalt {
			t.Error("a re-verification changed the recognition salt")
		}
		if got, err := repo.Get(ctx, a.ID, email); err != nil || got != want {
			t.Errorf("Get after internal verification = %+v, %v; want %+v", got, err, want)
		}
		// A later internal verification does not move the internal details.
		later2 := later.Add(time.Hour)
		again := internal
		again.FirstVerifiedAt, again.InternalVerifiedAt, again.LastUsedAt = later2, later2, later2
		if err := upsert(a.ID, again); err != nil {
			t.Fatalf("UpsertTx(again): %v", err)
		}
		want.LastUsedAt = later2
		if got, err := repo.Get(ctx, a.ID, email); err != nil || got != want {
			t.Errorf("Get after re-verification = %+v, %v; want %+v", got, err, want)
		}

		// Uses.
		use := later2.Add(time.Hour)
		if err := repo.Touch(ctx, a.ID, email, use); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		use2 := use.Add(time.Hour)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, email, use2) }); err != nil {
			t.Fatalf("TouchTx: %v", err)
		}
		if got, err := repo.Get(ctx, a.ID, email); err != nil || !got.LastUsedAt.Equal(use2) || !got.FirstVerifiedAt.Equal(msNow) {
			t.Errorf("Get after uses = %+v, %v", got, err)
		}
		// GetTx reads the same row inside the caller's transaction, scoped
		// to its tenant.
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			got, err := repo.GetTx(ctx, tx, "ALICE@entity-a.example.com")
			if err != nil || !got.LastUsedAt.Equal(use2) || got.Email != email {
				t.Errorf("GetTx = %+v, %v", got, err)
			}
			_, err = repo.GetTx(ctx, tx, "not an address")
			wantErr(t, "GetTx(malformed)", err, store.ErrInvalid)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			_, err := repo.GetTx(ctx, tx, email)
			wantErr(t, "GetTx(other tenant)", err, store.ErrNotFound)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// Isolation: the address is not verified for B, which cannot touch it.
		_, err = repo.Get(ctx, b.ID, email)
		wantErr(t, "Get from B", err, store.ErrNotFound)
		wantErr(t, "Touch from B", repo.Touch(ctx, b.ID, email, use2.Add(time.Hour)), store.ErrNotFound)
		if got, err := repo.Get(ctx, a.ID, email); err != nil || !got.LastUsedAt.Equal(use2) {
			t.Errorf("A's address changed: %+v, %v", got, err)
		}
		// B verifies the same address independently.
		external := store.VerifiedAddress{Email: email, FirstVerifiedAt: use2, FirstVerifiedIP: ipB}
		if err := upsert(b.ID, external); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, b.ID, email); err != nil || !got.InternalVerifiedAt.IsZero() || got.InternalVerifiedIP.IsValid() ||
			got.FirstVerifiedIP != ipB || !got.LastUsedAt.Equal(use2) {
			t.Errorf("Get(B) = %+v, %v", got, err)
		}
		if salt == want.RecognitionSalt {
			t.Error("B's address shares A's recognition salt")
		}

		// After 12 months without use, a new verification starts over: every
		// first-verification field is overwritten, the internal ones cleared.
		reborn := use2.AddDate(1, 0, 0)
		renew := store.VerifiedAddress{Email: email, FirstVerifiedAt: reborn, FirstVerifiedIP: ipB, LastUsedAt: reborn}
		if err := upsert(a.ID, renew); err != nil {
			t.Fatalf("UpsertTx(expired): %v", err)
		}
		if salt == want.RecognitionSalt || salt == zero {
			t.Error("a verification after expiry kept the recognition salt")
		}
		renew.RecognitionSalt = salt
		if got, err := repo.Get(ctx, a.ID, email); err != nil || got != renew {
			t.Errorf("Get after expiry = %+v, %v; want %+v", got, err, renew)
		}
		// And an internal one after expiry records the internal details anew.
		reborn2 := reborn.AddDate(1, 0, 1)
		renew2 := store.VerifiedAddress{
			Email: email, FirstVerifiedAt: reborn2, FirstVerifiedIP: ipA,
			InternalVerifiedAt: reborn2, InternalVerifiedIP: ipA,
		}
		if err := upsert(a.ID, renew2); err != nil {
			t.Fatalf("UpsertTx(expired, internal): %v", err)
		}
		renew2.LastUsedAt = reborn2
		if salt == renew.RecognitionSalt {
			t.Error("a verification after expiry kept the recognition salt")
		}
		renew2.RecognitionSalt = salt
		if got, err := repo.Get(ctx, a.ID, email); err != nil || got != renew2 {
			t.Errorf("Get after expiry (internal) = %+v, %v; want %+v", got, err, renew2)
		}

		// ResetRecognition draws a new salt and changes nothing else.
		if err := repo.ResetRecognition(ctx, a.ID, "ALICE@entity-a.example.com"); err != nil {
			t.Fatalf("ResetRecognition: %v", err)
		}
		got, err := repo.Get(ctx, a.ID, email)
		reset := renew2
		reset.RecognitionSalt = got.RecognitionSalt
		if err != nil || got.RecognitionSalt == renew2.RecognitionSalt || got.RecognitionSalt == zero || got != reset {
			t.Errorf("Get after ResetRecognition = %+v, %v", got, err)
		}
		wantErr(t, "ResetRecognition(unverified)", repo.ResetRecognition(ctx, a.ID, "carol@entity-a.example.com"), store.ErrNotFound)
		wantErr(t, "ResetRecognition from B", repo.ResetRecognition(ctx, b.ID, "carol@entity-a.example.com"), store.ErrNotFound)
		wantErr(t, "ResetRecognition(bad email)", repo.ResetRecognition(ctx, a.ID, "nope"), store.ErrInvalid)
		for _, tid := range badTenants {
			wantErr(t, "ResetRecognition(bad tenant)", repo.ResetRecognition(ctx, tid, email), store.ErrInvalid)
		}

		// Errors.
		wantErr(t, "Touch(unverified)", repo.Touch(ctx, a.ID, "carol@entity-a.example.com", use), store.ErrNotFound)
		wantErr(t, "Touch(bad email)", repo.Touch(ctx, a.ID, "nope", use), store.ErrInvalid)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, "nope", use) })
		wantErr(t, "TouchTx(bad email)", err, store.ErrInvalid)
		_, err = repo.Get(ctx, a.ID, "nope")
		wantErr(t, "Get(bad email)", err, store.ErrInvalid)
		for name, v := range map[string]store.VerifiedAddress{
			"email":            {Email: "nope", FirstVerifiedIP: ipA},
			"ip":               {Email: email},
			"internal ip only": {Email: email, FirstVerifiedIP: ipA, InternalVerifiedIP: ipA},
			"internal at only": {Email: email, FirstVerifiedIP: ipA, InternalVerifiedAt: msNow},
		} {
			wantErr(t, "UpsertTx(bad "+name+")", upsert(a.ID, v), store.ErrInvalid)
		}
		wantErr(t, "UpsertTx(missing tenant)", upsert(tenant.ID(id.New(id.Tenant)), first), store.ErrNotFound)
		for _, tid := range badTenants {
			_, err := repo.Get(ctx, tid, email)
			wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "Touch(bad tenant)", repo.Touch(ctx, tid, email, use), store.ErrInvalid)
		}
	})
}

// newSession returns a valid internal deposit session expiring in 4 hours.
func newSession(t *testing.T, email string) store.DepositSession {
	t.Helper()
	return store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: tokenHash(newToken(t, "ds")), Email: email,
		Kind: store.DepositorInternal, ExpiresAt: fixedNow.Add(4 * time.Hour),
	}
}

func TestDepositSessions(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.DepositSessions()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		s := newSession(t, "Alice@Entity-A.example.com")
		if err := repo.Create(ctx, a.ID, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		if err != nil || got.ID != s.ID || !bytes.Equal(got.TokenHash, s.TokenHash) || got.Email != "alice@entity-a.example.com" ||
			got.Kind != store.DepositorInternal || got.InvitationID != "" || !got.CreatedAt.Equal(msNow) ||
			!got.ExpiresAt.Equal(s.ExpiresAt.Truncate(time.Millisecond)) || !got.EndedAt.IsZero() {
			t.Fatalf("GetByTokenHash = %+v, %v", got, err)
		}
		_, err = repo.GetByTokenHash(ctx, a.ID, s.TokenHash, s.ExpiresAt)
		wantErr(t, "GetByTokenHash(expired)", err, store.ErrNotFound)
		_, err = repo.GetByTokenHash(ctx, a.ID, tokenHash("unknown"), fixedNow)
		wantErr(t, "GetByTokenHash(unknown)", err, store.ErrNotFound)

		// Isolation: A's cookie is worthless under B, which cannot end it.
		_, err = repo.GetByTokenHash(ctx, b.ID, s.TokenHash, fixedNow)
		wantErr(t, "GetByTokenHash from B", err, store.ErrNotFound)
		wantErr(t, "End from B", repo.End(ctx, b.ID, s.TokenHash, fixedNow), store.ErrNotFound)
		if _, err := repo.GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow); err != nil {
			t.Errorf("A's session was ended by B: %v", err)
		}

		// External sessions reference an invitation of the same tenant.
		invA, invB := mustInvitation(t, db, a.ID), mustInvitation(t, db, b.ID)
		ext := newSession(t, "bob@partner.example.org")
		ext.Kind, ext.InvitationID, ext.CreatedAt = store.DepositorExternal, invA.ID, fixedNow.Add(-time.Minute)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.CreateTx(ctx, tx, ext) }); err != nil {
			t.Fatalf("CreateTx(external): %v", err)
		}
		if got, err := repo.GetByTokenHash(ctx, a.ID, ext.TokenHash, fixedNow); err != nil || got.Kind != store.DepositorExternal ||
			got.InvitationID != invA.ID || !got.CreatedAt.Equal(ext.CreatedAt.Truncate(time.Millisecond)) {
			t.Errorf("GetByTokenHash(external) = %+v, %v", got, err)
		}
		for name, invID := range map[string]string{"invitation of B": invB.ID, "missing invitation": id.New(id.Invitation)} {
			x := newSession(t, "bob@partner.example.org")
			x.Kind, x.InvitationID = store.DepositorExternal, invID
			wantErr(t, "Create("+name+")", repo.Create(ctx, a.ID, x), store.ErrNotFound)
		}

		// End.
		if err := repo.End(ctx, a.ID, s.TokenHash, fixedNow); err != nil {
			t.Fatalf("End: %v", err)
		}
		wantErr(t, "End twice", repo.End(ctx, a.ID, s.TokenHash, fixedNow), store.ErrNotFound)
		_, err = repo.GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		wantErr(t, "GetByTokenHash(ended)", err, store.ErrNotFound)
		wantErr(t, "End(expired)", repo.End(ctx, a.ID, ext.TokenHash, ext.ExpiresAt), store.ErrNotFound)

		// Errors.
		dup := newSession(t, "alice@entity-a.example.com")
		dup.TokenHash = s.TokenHash
		wantErr(t, "Create(duplicate hash)", repo.Create(ctx, a.ID, dup), store.ErrConflict)
		wantErr(t, "Create(missing tenant)", repo.Create(ctx, tenant.ID(id.New(id.Tenant)), newSession(t, "a@example.com")), store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.CreateTx(ctx, tx, store.DepositSession{}) })
		wantErr(t, "CreateTx(invalid)", err, store.ErrInvalid)
		_, err = repo.GetByTokenHash(ctx, a.ID, s.TokenHash[:16], fixedNow)
		wantErr(t, "GetByTokenHash(short hash)", err, store.ErrInvalid)
		wantErr(t, "End(short hash)", repo.End(ctx, a.ID, nil, fixedNow), store.ErrInvalid)
		for _, tid := range badTenants {
			wantErr(t, "Create(bad tenant)", repo.Create(ctx, tid, newSession(t, "a@example.com")), store.ErrInvalid)
			_, err := repo.GetByTokenHash(ctx, tid, s.TokenHash, fixedNow)
			wantErr(t, "GetByTokenHash(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "End(bad tenant)", repo.End(ctx, tid, s.TokenHash, fixedNow), store.ErrInvalid)
		}
		invalid := map[string]func(*store.DepositSession){
			"email":               func(s *store.DepositSession) { s.Email = "nope" },
			"id":                  func(s *store.DepositSession) { s.ID = id.New(id.Invitation) },
			"hash":                func(s *store.DepositSession) { s.TokenHash = make([]byte, 31) },
			"kind":                func(s *store.DepositSession) { s.Kind = "robot" },
			"external no inv":     func(s *store.DepositSession) { s.Kind = store.DepositorExternal },
			"internal with inv":   func(s *store.DepositSession) { s.InvitationID = invA.ID },
			"malformed inv":       func(s *store.DepositSession) { s.Kind, s.InvitationID = store.DepositorExternal, "inv_x" },
			"expiry":              func(s *store.DepositSession) { s.ExpiresAt = fixedNow },
			"ended":               func(s *store.DepositSession) { s.EndedAt = fixedNow },
			"expiry before start": func(s *store.DepositSession) { s.CreatedAt = s.ExpiresAt.Add(time.Second) },
		}
		for name, mutate := range invalid {
			x := newSession(t, "a@example.com")
			mutate(&x)
			wantErr(t, "Create(bad "+name+")", repo.Create(ctx, a.ID, x), store.ErrInvalid)
		}
	})
}

func TestInvitations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Invitations()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		inv := mustInvitation(t, db, a.ID)
		want := inv
		want.Email, want.InvitedBy = "bob@partner.example.org", "alice@entity-a.example.com"
		want.CreatedAt, want.ExpiresAt = msNow, store.InvitationExpiry(msNow)
		got, err := repo.Get(ctx, a.ID, inv.ID)
		if err != nil || !sameInvitation(got, want) || !got.Active(fixedNow) {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, want)
		}
		if got, err := repo.GetByTokenHash(ctx, a.ID, inv.TokenHash); err != nil || !sameInvitation(got, want) {
			t.Fatalf("GetByTokenHash = %+v, %v; want %+v", got, err, want)
		}
		if !want.ExpiresAt.Equal(time.Date(2027, 10, 19, 12, 30, 45, 123_000_000, time.UTC)) {
			t.Errorf("default expiry = %v", want.ExpiresAt)
		}
		_, err = repo.GetByTokenHash(ctx, a.ID, tokenHash("unknown"))
		wantErr(t, "GetByTokenHash(unknown)", err, store.ErrNotFound)

		// Isolation: B can neither read, use nor revoke A's invitation.
		_, err = repo.Get(ctx, b.ID, inv.ID)
		wantErr(t, "Get from B", err, store.ErrNotFound)
		_, err = repo.GetByTokenHash(ctx, b.ID, inv.TokenHash)
		wantErr(t, "GetByTokenHash from B", err, store.ErrNotFound)
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, inv.ID, fixedNow) })
		wantErr(t, "TouchTx from B", err, store.ErrNotFound)
		wantErr(t, "Revoke from B", repo.Revoke(ctx, b.ID, inv.ID, fixedNow), store.ErrNotFound)
		if got, err := repo.Get(ctx, a.ID, inv.ID); err != nil || !sameInvitation(got, want) {
			t.Errorf("A's invitation changed: %+v, %v", got, err)
		}

		// A use moves the expiry to 12 months after the use.
		use := fixedNow.AddDate(0, 3, 0)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, inv.ID, use) }); err != nil {
			t.Fatalf("TouchTx: %v", err)
		}
		want.LastUsedAt, want.ExpiresAt = use.Truncate(time.Millisecond), store.InvitationExpiry(use).Truncate(time.Millisecond)
		if got, err := repo.Get(ctx, a.ID, inv.ID); err != nil || !sameInvitation(got, want) {
			t.Errorf("Get after use = %+v, %v; want %+v", got, err, want)
		}
		// A later expiry set at creation is never shortened.
		long := newInvitation(t)
		long.CreatedAt, long.ExpiresAt, long.Language, long.Message = fixedNow, fixedNow.AddDate(2, 0, 0), "", ""
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if err := repo.CreateTx(ctx, tx, long); err != nil {
				return err
			}
			return repo.TouchTx(ctx, tx, long.ID, use)
		}); err != nil {
			t.Fatalf("CreateTx + TouchTx: %v", err)
		}
		if got, err := repo.Get(ctx, a.ID, long.ID); err != nil || !got.ExpiresAt.Equal(long.ExpiresAt.Truncate(time.Millisecond)) ||
			!got.LastUsedAt.Equal(use.Truncate(time.Millisecond)) || got.Language != "" || got.Message != "" {
			t.Errorf("Get(long) = %+v, %v", got, err)
		}
		// Expired invitations cannot be used.
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, long.ID, long.ExpiresAt) })
		wantErr(t, "TouchTx(expired)", err, store.ErrNotFound)

		// Revocation.
		revokeAt := use.Add(time.Hour)
		if err := repo.Revoke(ctx, a.ID, inv.ID, revokeAt); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		wantErr(t, "Revoke twice", repo.Revoke(ctx, a.ID, inv.ID, revokeAt), store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.TouchTx(ctx, tx, inv.ID, revokeAt) })
		wantErr(t, "TouchTx(revoked)", err, store.ErrNotFound)
		if got, err := repo.GetByTokenHash(ctx, a.ID, inv.TokenHash); err != nil || !got.RevokedAt.Equal(revokeAt.Truncate(time.Millisecond)) || got.Active(revokeAt) {
			t.Errorf("revoked invitation = %+v, %v", got, err)
		}

		// Errors.
		wantErr(t, "Create(duplicate id)", repo.Create(ctx, b.ID, inv), store.ErrConflict)
		dup := newInvitation(t)
		dup.TokenHash = inv.TokenHash
		wantErr(t, "Create(duplicate hash)", repo.Create(ctx, a.ID, dup), store.ErrConflict)
		wantErr(t, "Create(missing tenant)", repo.Create(ctx, tenant.ID(id.New(id.Tenant)), newInvitation(t)), store.ErrNotFound)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return repo.CreateTx(ctx, tx, store.Invitation{}) })
		wantErr(t, "CreateTx(invalid)", err, store.ErrInvalid)
		_, err = repo.GetByTokenHash(ctx, a.ID, []byte("short"))
		wantErr(t, "GetByTokenHash(short hash)", err, store.ErrInvalid)
		for _, tid := range badTenants {
			wantErr(t, "Create(bad tenant)", repo.Create(ctx, tid, newInvitation(t)), store.ErrInvalid)
			_, err := repo.Get(ctx, tid, inv.ID)
			wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
			_, err = repo.GetByTokenHash(ctx, tid, inv.TokenHash)
			wantErr(t, "GetByTokenHash(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "Revoke(bad tenant)", repo.Revoke(ctx, tid, inv.ID, fixedNow), store.ErrInvalid)
		}
		invalid := map[string]func(*store.Invitation){
			"email":      func(i *store.Invitation) { i.Email = "nope" },
			"invited by": func(i *store.Invitation) { i.InvitedBy = "nope" },
			"id":         func(i *store.Invitation) { i.ID = "inv_9sK2mQ7xL0aZ4vR8tYb3nC6dE1fG5hJ" },
			"hash":       func(i *store.Invitation) { i.TokenHash = nil },
			"message":    func(i *store.Invitation) { i.Message = strings.Repeat("m", 2001) },
			"utf8":       func(i *store.Invitation) { i.Message = "\xff" },
			"language":   func(i *store.Invitation) { i.Language = "de" },
			"expiry":     func(i *store.Invitation) { i.CreatedAt, i.ExpiresAt = fixedNow, fixedNow },
			"used":       func(i *store.Invitation) { i.LastUsedAt = fixedNow },
			"revoked":    func(i *store.Invitation) { i.RevokedAt = fixedNow },
		}
		for name, mutate := range invalid {
			x := newInvitation(t)
			mutate(&x)
			wantErr(t, "Create(bad "+name+")", repo.Create(ctx, a.ID, x), store.ErrInvalid)
		}
		edge := newInvitation(t)
		edge.Message = strings.Repeat("é", 2000)
		if err := repo.Create(ctx, a.ID, edge); err != nil {
			t.Errorf("Create(limits) = %v", err)
		}
	})
}

// sameInvitation compares two invitations field by field.
func sameInvitation(a, b store.Invitation) bool {
	return a.ID == b.ID && bytes.Equal(a.TokenHash, b.TokenHash) && a.Email == b.Email && a.InvitedBy == b.InvitedBy &&
		a.Message == b.Message && a.Language == b.Language && a.CreatedAt.Equal(b.CreatedAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt) && a.LastUsedAt.Equal(b.LastUsedAt) && a.RevokedAt.Equal(b.RevokedAt)
}

// TestDepositTablesCascade checks that a tenant with deposit rows of every
// kind can be deleted: the foreign keys cascade.
func TestDepositTablesCascade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		inv := mustInvitation(t, db, a.ID)
		ch := newChallenge(t, "bob@partner.example.org", ipA)
		ch.InvitationID = inv.ID
		s := newSession(t, "bob@partner.example.org")
		s.Kind, s.InvitationID = store.DepositorExternal, inv.ID
		v := store.VerifiedAddress{Email: "bob@partner.example.org", FirstVerifiedIP: ipA}
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if err := db.Challenges().CreateTx(ctx, tx, ch); err != nil {
				return err
			}
			if _, err := db.VerifiedAddresses().UpsertTx(ctx, tx, v); err != nil {
				return err
			}
			return db.DepositSessions().CreateTx(ctx, tx, s)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SMTPSettings().Put(ctx, a.ID, store.SMTPConfig{Host: "relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "a@example.com"}); err != nil {
			t.Fatal(err)
		}
		if err := db.Tenants().Delete(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		// The tenant ID is gone: every lookup reports ErrNotFound.
		_, err = db.Invitations().Get(ctx, a.ID, inv.ID)
		wantErr(t, "invitation after tenant deletion", err, store.ErrNotFound)
		_, err = db.Challenges().Get(ctx, a.ID, ch.ID)
		wantErr(t, "challenge after tenant deletion", err, store.ErrNotFound)
		_, err = db.VerifiedAddresses().Get(ctx, a.ID, v.Email)
		wantErr(t, "verified address after tenant deletion", err, store.ErrNotFound)
		_, err = db.DepositSessions().GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		wantErr(t, "session after tenant deletion", err, store.ErrNotFound)
		_, err = db.SMTPSettings().Get(ctx, a.ID)
		wantErr(t, "smtp settings after tenant deletion", err, store.ErrNotFound)
	})
}

// TestRateLimitCountsTx checks the counts used inside the write transaction
// that enforces the rate limits, the challenge deletion and the per-inviter
// count, with their tenant isolation.
func TestRateLimitCountsTx(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		challenges, invitations := db.Challenges(), db.Invitations()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		hourAgo := fixedNow.Add(-time.Hour)

		c1 := newChallenge(t, "alice@entity-a.example.com", ipA)
		c2 := newChallenge(t, "carol@entity-a.example.com", ipA)
		old := newChallenge(t, "alice@entity-a.example.com", ipA)
		old.CreatedAt = fixedNow.Add(-2 * time.Hour)
		for _, c := range []store.Challenge{c1, c2, old} {
			if err := challenges.Create(ctx, a.ID, c); err != nil {
				t.Fatal(err)
			}
		}
		counts := func(tid tenant.ID) (byEmail, byIP int, err error) {
			t.Helper()
			err = inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				if byEmail, err = challenges.CountSinceTx(ctx, tx, "ALICE@entity-a.example.com", hourAgo); err != nil {
					return err
				}
				byIP, err = challenges.CountByIPSinceTx(ctx, tx, netip.MustParseAddr("::ffff:10.0.0.1"), hourAgo)
				return err
			})
			return byEmail, byIP, err
		}
		if byEmail, byIP, err := counts(a.ID); err != nil || byEmail != 1 || byIP != 2 {
			t.Errorf("counts(A) = %d, %d, %v; want 1, 2", byEmail, byIP, err)
		}
		if byEmail, byIP, err := counts(b.ID); err != nil || byEmail != 0 || byIP != 0 {
			t.Errorf("counts(B) = %d, %d, %v; want 0, 0", byEmail, byIP, err)
		}

		// Delete: B cannot delete A's challenge; A can, once.
		wantErr(t, "Delete from B", challenges.Delete(ctx, b.ID, c1.ID), store.ErrNotFound)
		if err := challenges.Delete(ctx, a.ID, c1.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		wantErr(t, "Delete twice", challenges.Delete(ctx, a.ID, c1.ID), store.ErrNotFound)
		if _, err := challenges.Get(ctx, a.ID, c1.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deleted) = %v", err)
		}
		if byEmail, byIP, err := counts(a.ID); err != nil || byEmail != 0 || byIP != 1 {
			t.Errorf("counts(A) after delete = %d, %d, %v; want 0, 1", byEmail, byIP, err)
		}

		// Per-inviter count: every state counts, by creation time.
		const inviter = "alice@entity-a.example.com"
		recent, revoked, older := newInvitation(t), newInvitation(t), newInvitation(t)
		older.CreatedAt = fixedNow.Add(-2 * time.Hour)
		other := newInvitation(t)
		other.InvitedBy = "dave@entity-a.example.com"
		for _, inv := range []store.Invitation{recent, revoked, older, other} {
			if err := invitations.Create(ctx, a.ID, inv); err != nil {
				t.Fatal(err)
			}
		}
		if err := invitations.Revoke(ctx, a.ID, revoked.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		inviterCount := func(tid tenant.ID, who string) (int, error) {
			t.Helper()
			var n int
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				n, err = invitations.CountByInviterSinceTx(ctx, tx, who, hourAgo)
				return err
			})
			return n, err
		}
		if n, err := inviterCount(a.ID, "Alice@Entity-A.example.com"); err != nil || n != 2 {
			t.Errorf("CountByInviterSinceTx(A) = %d, %v; want 2", n, err)
		}
		if n, err := inviterCount(b.ID, inviter); err != nil || n != 0 {
			t.Errorf("CountByInviterSinceTx(B) = %d, %v; want 0", n, err)
		}

		// Errors.
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := challenges.CountSinceTx(ctx, tx, "nope", hourAgo)
			return err
		})
		wantErr(t, "CountSinceTx(bad email)", err, store.ErrInvalid)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := challenges.CountByIPSinceTx(ctx, tx, netip.Addr{}, hourAgo)
			return err
		})
		wantErr(t, "CountByIPSinceTx(zero ip)", err, store.ErrInvalid)
		_, err = inviterCount(a.ID, "nope")
		wantErr(t, "CountByInviterSinceTx(bad email)", err, store.ErrInvalid)
		for _, tid := range badTenants {
			wantErr(t, "Delete(bad tenant)", challenges.Delete(ctx, tid, c2.ID), store.ErrInvalid)
			wantErr(t, "Invitations.Delete(bad tenant)", invitations.Delete(ctx, tid, recent.ID), store.ErrInvalid)
		}

		// Deleting an invitation removes it, and its challenges, from the
		// count and the tables; B cannot delete A's.
		withInv := newChallenge(t, "bob@partner.example.org", ipB)
		withInv.InvitationID = recent.ID
		if err := challenges.Create(ctx, a.ID, withInv); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "Invitations.Delete from B", invitations.Delete(ctx, b.ID, recent.ID), store.ErrNotFound)
		if err := invitations.Delete(ctx, a.ID, recent.ID); err != nil {
			t.Fatalf("Invitations.Delete: %v", err)
		}
		wantErr(t, "Invitations.Delete twice", invitations.Delete(ctx, a.ID, recent.ID), store.ErrNotFound)
		if _, err := challenges.Get(ctx, a.ID, withInv.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("challenge of a deleted invitation = %v", err)
		}
		if n, err := inviterCount(a.ID, inviter); err != nil || n != 1 {
			t.Errorf("CountByInviterSinceTx after delete = %d, %v; want 1", n, err)
		}
	})
}
