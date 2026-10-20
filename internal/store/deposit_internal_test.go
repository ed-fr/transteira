package store

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// depositFixture is a fault-injecting database holding a tenant with SMTP
// settings (with a password secret), an invitation, an open challenge, a
// verified address and a deposit session.
type depositFixture struct {
	db      *DB
	plan    *faultPlan
	tid     tenant.ID
	secret  string
	inv     Invitation
	chID    string
	session []byte
}

// Values of the deposit fixture.
const fixtureEmail = "alice@a.example.com"

var fixtureIP = netip.MustParseAddr("10.0.0.1")

// newDepositFixture builds a depositFixture.
func newDepositFixture(t *testing.T) *depositFixture {
	t.Helper()
	ctx := context.Background()
	db, plan := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	f := &depositFixture{db: db, plan: plan, tid: tn.ID, secret: id.New(id.WrappedKey)}
	if err := db.WrappedKeys().Create(ctx, f.tid, WrappedKey{ID: f.secret, Purpose: KeyPurposeSecret, KeyID: testMK1, Blob: []byte("s")}); err != nil {
		t.Fatal(err)
	}
	if err := db.SMTPSettings().Put(ctx, f.tid, f.smtp()); err != nil {
		t.Fatal(err)
	}
	f.inv = Invitation{ID: id.New(id.Invitation), TokenHash: hashOf("inv"), Email: "bob@b.example.org", InvitedBy: fixtureEmail}
	if err := db.Invitations().Create(ctx, f.tid, f.inv); err != nil {
		t.Fatal(err)
	}
	f.chID, _ = id.NewToken(id.ChallengeTokenPrefix, id.MinTokenBytes)
	if err := db.Challenges().Create(ctx, f.tid, f.challenge(f.chID)); err != nil {
		t.Fatal(err)
	}
	f.session = hashOf("ds")
	if err := f.tx(ctx, func(tx *ScopedTx) error {
		if _, err := db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: fixtureEmail, FirstVerifiedIP: fixtureIP}); err != nil {
			return err
		}
		return db.DepositSessions().CreateTx(ctx, tx, f.depositSession(f.session))
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// hashOf returns the SHA-256 of s.
func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// smtp returns the fixture's SMTP settings.
func (f *depositFixture) smtp() SMTPConfig {
	return SMTPConfig{
		Host: "smtp.example.com", Port: 587, Security: SMTPSecuritySTARTTLS, Username: "u",
		PasswordKeyID: f.secret, FromAddress: fixtureEmail,
	}
}

// challenge returns a valid open challenge chID.
func (f *depositFixture) challenge(chID string) Challenge {
	return Challenge{
		ID: chID, Email: fixtureEmail, CodeMAC: []byte("mac"), AttemptsRemaining: 2,
		ClientIP: fixtureIP, ExpiresAt: time.Now().Add(time.Hour),
	}
}

// depositSession returns a valid internal session for the token hash.
func (f *depositFixture) depositSession(hash []byte) DepositSession {
	return DepositSession{
		ID: id.New(id.DepositSession), TokenHash: hash, Email: fixtureEmail,
		Kind: DepositorInternal, ExpiresAt: time.Now().Add(time.Hour),
	}
}

// tx runs fn in a scoped transaction of the fixture's tenant.
func (f *depositFixture) tx(ctx context.Context, fn func(*ScopedTx) error) error {
	s, err := f.db.Scoped(f.tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, fn)
}

// TestDepositDriverFaults injects a driver failure into each statement of
// the deposit repositories and checks that it surfaces as an error.
func TestDepositDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	smtpGet := func(f *depositFixture) error { _, err := f.db.SMTPSettings().Get(ctx, f.tid); return err }
	smtpGetTx := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error { _, err := f.db.SMTPSettings().GetTx(ctx, tx); return err })
	}
	smtpPut := func(f *depositFixture) error { return f.db.SMTPSettings().Put(ctx, f.tid, f.smtp()) }
	smtpPutTx := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error { return f.db.SMTPSettings().PutTx(ctx, tx, f.smtp()) })
	}
	smtpInsert := func(f *depositFixture) error {
		tn, err := f.db.Tenants().Create(ctx, &tenant.Tenant{Name: "B", FQDN: "b.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			return nil // reported as "no error": the step fails
		}
		c := f.smtp()
		c.PasswordKeyID = ""
		return f.db.SMTPSettings().Put(ctx, tn.ID, c)
	}
	chCreate := func(f *depositFixture) error {
		chID, _ := id.NewToken(id.ChallengeTokenPrefix, id.MinTokenBytes)
		return f.db.Challenges().Create(ctx, f.tid, f.challenge(chID))
	}
	chGet := func(f *depositFixture) error { _, err := f.db.Challenges().Get(ctx, f.tid, f.chID); return err }
	chCount := func(f *depositFixture) error {
		_, err := f.db.Challenges().CountSince(ctx, f.tid, fixtureEmail, now.Add(-time.Hour))
		return err
	}
	chCountIP := func(f *depositFixture) error {
		_, err := f.db.Challenges().CountByIPSince(ctx, f.tid, fixtureIP, now.Add(-time.Hour))
		return err
	}
	chCountTx := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.Challenges().CountSinceTx(ctx, tx, fixtureEmail, now.Add(-time.Hour))
			return err
		})
	}
	chCountIPTx := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.Challenges().CountByIPSinceTx(ctx, tx, fixtureIP, now.Add(-time.Hour))
			return err
		})
	}
	chDelete := func(f *depositFixture) error { return f.db.Challenges().Delete(ctx, f.tid, f.chID) }
	chDecrement := func(f *depositFixture) error {
		_, err := f.db.Challenges().DecrementAttempt(ctx, f.tid, f.chID, now)
		return err
	}
	chConsume := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error { return f.db.Challenges().ConsumeTx(ctx, tx, f.chID, now) })
	}
	vaGet := func(f *depositFixture) error {
		_, err := f.db.VerifiedAddresses().Get(ctx, f.tid, fixtureEmail)
		return err
	}
	vaTouch := func(f *depositFixture) error { return f.db.VerifiedAddresses().Touch(ctx, f.tid, fixtureEmail, now) }
	vaUpsert := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: fixtureEmail, FirstVerifiedIP: fixtureIP, LastUsedAt: now})
			return err
		})
	}
	vaInsert := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: "new@a.example.com", FirstVerifiedIP: fixtureIP})
			return err
		})
	}
	vaReset := func(f *depositFixture) error {
		later := time.Now().AddDate(2, 0, 0)
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: fixtureEmail, FirstVerifiedIP: fixtureIP, FirstVerifiedAt: later})
			return err
		})
	}
	vaResetSalt := func(f *depositFixture) error {
		return f.db.VerifiedAddresses().ResetRecognition(ctx, f.tid, fixtureEmail)
	}
	dsCreate := func(f *depositFixture) error {
		return f.db.DepositSessions().Create(ctx, f.tid, f.depositSession(hashOf("other")))
	}
	dsGet := func(f *depositFixture) error {
		_, err := f.db.DepositSessions().GetByTokenHash(ctx, f.tid, f.session, now)
		return err
	}
	dsEnd := func(f *depositFixture) error { return f.db.DepositSessions().End(ctx, f.tid, f.session, now) }
	invCreate := func(f *depositFixture) error {
		return f.db.Invitations().Create(ctx, f.tid, Invitation{ID: id.New(id.Invitation), TokenHash: hashOf("inv2"), Email: "c@c.example.org", InvitedBy: fixtureEmail})
	}
	invGet := func(f *depositFixture) error { _, err := f.db.Invitations().Get(ctx, f.tid, f.inv.ID); return err }
	invGetHash := func(f *depositFixture) error {
		_, err := f.db.Invitations().GetByTokenHash(ctx, f.tid, f.inv.TokenHash)
		return err
	}
	invTouch := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error { return f.db.Invitations().TouchTx(ctx, tx, f.inv.ID, now) })
	}
	invRevoke := func(f *depositFixture) error { return f.db.Invitations().Revoke(ctx, f.tid, f.inv.ID, now) }
	invDelete := func(f *depositFixture) error { return f.db.Invitations().Delete(ctx, f.tid, f.inv.ID) }
	invCount := func(f *depositFixture) error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.Invitations().CountByInviterSinceTx(ctx, tx, fixtureEmail, now.Add(-time.Hour))
			return err
		})
	}

	steps := []struct {
		name, op, match string
		run             func(*depositFixture) error
	}{
		{"smtp get", faultQuery, "FROM tenant_smtp_settings", smtpGet},
		{"smtp get scan", faultScanNil, "FROM tenant_smtp_settings", smtpGet},
		{"smtp get tx", faultQuery, "FROM tenant_smtp_settings", smtpGetTx},
		{"smtp key check", faultQuery, "FROM wrapped_keys WHERE tenant_id", smtpPut},
		{"smtp update", faultExec, "UPDATE tenant_smtp_settings", smtpPut},
		{"smtp update rows", faultRows, "UPDATE tenant_smtp_settings", smtpPutTx},
		{"smtp insert", faultExec, "INSERT INTO tenant_smtp_settings", smtpInsert},
		{"challenge create", faultExec, "INSERT INTO verification_challenges", chCreate},
		{"challenge get", faultQuery, "FROM verification_challenges WHERE tenant_id = ? AND id", chGet},
		{"challenge get scan", faultScanNil, "FROM verification_challenges WHERE tenant_id = ? AND id", chGet},
		{"challenge count", faultQuery, "AND email = ?", chCount},
		{"challenge count ip", faultQuery, "AND client_ip = ?", chCountIP},
		{"challenge count tx", faultQuery, "AND email = ?", chCountTx},
		{"challenge count ip tx", faultQuery, "AND client_ip = ?", chCountIPTx},
		{"challenge delete", faultExec, "DELETE FROM verification_challenges", chDelete},
		{"challenge delete rows", faultRows, "DELETE FROM verification_challenges", chDelete},
		{"challenge decrement", faultQuery, "SET attempts_remaining", chDecrement},
		{"challenge consume", faultExec, "SET consumed_at", chConsume},
		{"challenge consume rows", faultRows, "SET consumed_at", chConsume},
		{"verified get", faultQuery, "FROM verified_addresses", vaGet},
		{"verified get scan", faultScanNil, "FROM verified_addresses", vaGet},
		{"verified touch", faultExec, "UPDATE verified_addresses", vaTouch},
		{"verified touch rows", faultRows, "UPDATE verified_addresses", vaTouch},
		{"verified upsert", faultExec, "UPDATE verified_addresses", vaUpsert},
		{"verified insert", faultExec, "INSERT INTO verified_addresses", vaInsert},
		{"verified upsert read", faultQuery, "SELECT last_used_at", vaUpsert},
		{"verified reset", faultExec, "SET first_verified_at", vaReset},
		{"verified reset salt", faultExec, "SET recognition_salt", vaResetSalt},
		{"session create", faultExec, "INSERT INTO deposit_sessions", dsCreate},
		{"session get", faultQuery, "FROM deposit_sessions", dsGet},
		{"session get scan", faultScanNil, "FROM deposit_sessions", dsGet},
		{"session end", faultExec, "UPDATE deposit_sessions", dsEnd},
		{"session end rows", faultRows, "UPDATE deposit_sessions", dsEnd},
		{"invitation create", faultExec, "INSERT INTO invitations", invCreate},
		{"invitation get", faultQuery, "FROM invitations WHERE tenant_id = ? AND id", invGet},
		{"invitation get scan", faultScanNil, "FROM invitations WHERE tenant_id = ? AND id", invGet},
		{"invitation get hash", faultQuery, "AND token_hash = ?", invGetHash},
		{"invitation touch", faultExec, "SET last_used_at", invTouch},
		{"invitation touch rows", faultRows, "SET last_used_at", invTouch},
		{"invitation revoke", faultExec, "SET revoked_at", invRevoke},
		{"invitation revoke rows", faultRows, "SET revoked_at", invRevoke},
		{"invitation count", faultQuery, "AND invited_by = ?", invCount},
		{"invitation delete", faultExec, "DELETE FROM invitations", invDelete},
		{"invitation delete rows", faultRows, "DELETE FROM invitations", invDelete},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newDepositFixture(t)
			f.plan.add(s.op, s.match, 0)
			if err := s.run(f); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestUpsertLockFailure checks that a failing tenant lock (PostgreSQL only)
// aborts the upserts.
func TestUpsertLockFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDepositFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	if err := f.db.SMTPSettings().Put(ctx, f.tid, f.smtp()); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Put with a failing lock = %v", err)
	}
	err := f.tx(ctx, func(tx *ScopedTx) error {
		_, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: fixtureEmail, FirstVerifiedIP: fixtureIP})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("UpsertTx with a failing lock = %v", err)
	}
	since := time.Now().Add(-time.Hour)
	for name, count := range map[string]func(*ScopedTx) (int, error){
		"CountSinceTx": func(tx *ScopedTx) (int, error) { return f.db.Challenges().CountSinceTx(ctx, tx, fixtureEmail, since) },
		"CountByIPSinceTx": func(tx *ScopedTx) (int, error) {
			return f.db.Challenges().CountByIPSinceTx(ctx, tx, fixtureIP, since)
		},
		"CountByInviterSinceTx": func(tx *ScopedTx) (int, error) {
			return f.db.Invitations().CountByInviterSinceTx(ctx, tx, fixtureEmail, since)
		},
	} {
		err := f.tx(ctx, func(tx *ScopedTx) error { _, err := count(tx); return err })
		if err == nil || !strings.Contains(err.Error(), "lock tenant") {
			t.Errorf("%s with a failing lock = %v", name, err)
		}
	}
}
