package deposit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/vcode"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	s := New(nil, nil, nil, nil, nil, Options{})
	if s.sessionTTL != DefaultSessionTTL || s.clock == nil || s.logger == nil || s.render == nil || s.rand == nil {
		t.Errorf("defaults not applied: %+v", s)
	}
	if d := time.Since(s.now()); d < 0 || d > time.Minute {
		t.Errorf("default clock is off by %v", d)
	}
}

func TestErrorTypes(t *testing.T) {
	t.Parallel()
	checks := []struct {
		err    error
		target error
		text   string
	}{
		{invalid(FieldEmail), ErrInvalid, "deposit: invalid /email"},
		{&RateLimitError{RetryAfter: time.Minute}, ErrRateLimited, "deposit: rate limited, retry after 1m0s"},
		{&WrongCodeError{Remaining: 1}, ErrWrongCode, "deposit: wrong verification code, 1 attempt(s) remaining"},
	}
	for _, c := range checks {
		if !errors.Is(c.err, c.target) || c.err.Error() != c.text || errors.Is(c.err, ErrForbidden) {
			t.Errorf("%T: Is/Error mismatch: %q", c.err, c.err.Error())
		}
	}
}

func TestParseEmail(t *testing.T) {
	t.Parallel()
	got, err := parseEmail(" Alice@Entity-A.Example.com ")
	if err != nil || got.mailbox != "Alice@entity-a.example.com" || got.normalized != aliceNorm {
		t.Errorf("parseEmail = %+v, %v", got, err)
	}
	// Accepted by mail.ParseAddress, refused by the store normalization.
	for _, bad := range []string{"user@192.0.2.1", "user@example.123", "user@xn--a.example.com"} {
		_, err := parseEmail(bad)
		wantInvalid(t, "parseEmail", err, FieldEmail)
	}
}

// seqReader returns the given 32-bit values, big-endian, then fails.
type seqReader struct{ vals []uint32 }

func (r *seqReader) Read(p []byte) (int, error) {
	if len(r.vals) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	binary.BigEndian.PutUint32(p[:4], r.vals[0])
	r.vals = r.vals[1:]
	return 4, nil
}

func TestNewCode(t *testing.T) {
	t.Parallel()
	if vcode.RejectAtOrAbove%vcode.Space != 0 || vcode.RejectAtOrAbove > 1<<32 || (1<<32)-vcode.RejectAtOrAbove >= vcode.Space {
		t.Fatalf("rejection bound %d is not the largest multiple of %d", int64(vcode.RejectAtOrAbove), vcode.Space)
	}
	s := &Service{}
	// Values in the incomplete last block are rejected, the next is used.
	s.rand = &seqReader{vals: []uint32{0xFFFFFFFF, vcode.RejectAtOrAbove, vcode.RejectAtOrAbove - 1}}
	if code, err := s.newCode(); err != nil || code != "999999" {
		t.Errorf("newCode after rejections: err %v, value ok %v", err, code == "999999")
	}
	s.rand = &seqReader{vals: []uint32{7}}
	if code, err := s.newCode(); err != nil || code != "000007" {
		t.Errorf("newCode zero-padding: err %v, value ok %v", err, code == "000007")
	}
	s.rand = &seqReader{}
	if _, err := s.newCode(); err == nil {
		t.Error("newCode with a failing source succeeded")
	}

	// Uniformity: every digit position is evenly spread over 0-9. With
	// 100000 codes, each bucket expects 10000 (standard deviation ~95).
	s = New(nil, nil, nil, nil, nil, Options{})
	const n = 100000
	var counts [CodeDigits][10]int
	for range n {
		code, err := s.newCode()
		if err != nil || !validCode(code) {
			t.Fatal("newCode returned an error or a malformed code")
		}
		for i := range CodeDigits {
			counts[i][code[i]-'0']++
		}
	}
	for pos := range counts {
		for d, c := range counts[pos] {
			if c < n/10-600 || c > n/10+600 {
				t.Errorf("digit %d at position %d appears %d times, want about %d", d, pos, c, n/10)
			}
		}
	}
}

// failKeys fails MAC and VerifyMAC on demand; with only set, they fail for
// that purpose only.
type failKeys struct {
	Keys
	mac, verify bool
	only        crypto.MACPurpose
}

func (k failKeys) MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error) {
	if k.mac && (k.only == "" || k.only == p) {
		return nil, errFault
	}
	return k.Keys.MAC(p, parts...)
}

func (k failKeys) VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error) {
	if k.verify && (k.only == "" || k.only == p) {
		return false, errFault
	}
	return k.Keys.VerifyMAC(p, mac, parts...)
}

// failSecrets always fails.
type failSecrets struct{}

func (failSecrets) Open(context.Context, tenant.ID, crypto.Purpose, string) ([]byte, error) {
	return nil, errFault
}

// failLog always fails.
type failLog struct{}

func (failLog) Log(securitylog.Event) error { return errFault }

func TestCheckCSRF(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		s := ev.mustSession(t, ev.a, internalIP, alice, "")
		other := ev.mustSession(t, ev.a, internalIP, alice, "")
		for _, tc := range []struct {
			what, token, header string
			want                bool
		}{
			{"valid", s.Token, s.CSRFToken, true},
			{"other session", other.Token, s.CSRFToken, false},
			{"no prefix", s.Token, strings.TrimPrefix(s.CSRFToken, CSRFPrefix), false},
			{"bad base64", s.Token, CSRFPrefix + "!!!", false},
			{"truncated", s.Token, s.CSRFToken[:len(s.CSRFToken)-2], false},
			{"empty header", s.Token, "", false},
			{"empty token", "", s.CSRFToken, false},
		} {
			if got := ev.svc.CheckCSRF(tc.token, tc.header); got != tc.want {
				t.Errorf("CheckCSRF(%s) = %v, want %v", tc.what, got, tc.want)
			}
		}
		ev.svc.keys = failKeys{Keys: ev.svc.keys, verify: true}
		if ev.svc.CheckCSRF(s.Token, s.CSRFToken) {
			t.Error("CheckCSRF with failing keys = true")
		}
	})
}

// faultRepo wraps a repo and fails the operations named in fails.
type faultRepo struct {
	repo
	fails map[string]error
}

func (f faultRepo) fail(op string) error { return f.fails[op] }

func (f faultRepo) blocked(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	if err := f.fail("blocked"); err != nil {
		return false, err
	}
	return f.repo.blocked(ctx, tid, email)
}

func (f faultRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	if err := f.fail("networkRules"); err != nil {
		return store.NetworkRuleSet{}, err
	}
	return f.repo.networkRules(ctx, tid)
}

func (f faultRepo) invitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	if err := f.fail("invitation"); err != nil {
		return store.Invitation{}, err
	}
	return f.repo.invitation(ctx, tid, invID)
}

func (f faultRepo) invitationByHash(ctx context.Context, tid tenant.ID, hash []byte) (store.Invitation, error) {
	if err := f.fail("invitationByHash"); err != nil {
		return store.Invitation{}, err
	}
	return f.repo.invitationByHash(ctx, tid, hash)
}

func (f faultRepo) verified(ctx context.Context, tid tenant.ID, email string) (store.VerifiedAddress, error) {
	if err := f.fail("verified"); err != nil {
		return store.VerifiedAddress{}, err
	}
	return f.repo.verified(ctx, tid, email)
}

func (f faultRepo) deleteChallenge(ctx context.Context, tid tenant.ID, chID string) error {
	if err := f.fail("deleteChallenge"); err != nil {
		return err
	}
	return f.repo.deleteChallenge(ctx, tid, chID)
}

func (f faultRepo) deleteInvitation(ctx context.Context, tid tenant.ID, invID string) error {
	if err := f.fail("deleteInvitation"); err != nil {
		return err
	}
	return f.repo.deleteInvitation(ctx, tid, invID)
}

func (f faultRepo) challenge(ctx context.Context, tid tenant.ID, chID string) (store.Challenge, error) {
	if err := f.fail("challenge"); err != nil {
		return store.Challenge{}, err
	}
	return f.repo.challenge(ctx, tid, chID)
}

func (f faultRepo) decrementAttempt(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error) {
	if err := f.fail("decrementAttempt"); err != nil {
		return 0, err
	}
	return f.repo.decrementAttempt(ctx, tid, chID, now)
}

func (f faultRepo) smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	if err := f.fail("smtp"); err != nil {
		return store.SMTPConfig{}, err
	}
	return f.repo.smtp(ctx, tid)
}

func (f faultRepo) session(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.DepositSession, error) {
	if err := f.fail("session"); err != nil {
		return store.DepositSession{}, err
	}
	return f.repo.session(ctx, tid, hash, now)
}

func (f faultRepo) endSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error {
	if err := f.fail("endSession"); err != nil {
		return err
	}
	return f.repo.endSession(ctx, tid, hash, now)
}

func (f faultRepo) tx(ctx context.Context, tid tenant.ID, fn func(txRepo) error) error {
	return f.repo.tx(ctx, tid, func(tx txRepo) error { return fn(faultTx{txRepo: tx, f: f}) })
}

// faultTx wraps a txRepo and fails the operations named in the faultRepo.
type faultTx struct {
	txRepo
	f faultRepo
}

func (t faultTx) countByEmail(ctx context.Context, email string, since time.Time) (int, error) {
	if err := t.f.fail("countByEmail"); err != nil {
		return 0, err
	}
	return t.txRepo.countByEmail(ctx, email, since)
}

func (t faultTx) countByIP(ctx context.Context, ip netip.Addr, since time.Time) (int, error) {
	if err := t.f.fail("countByIP"); err != nil {
		return 0, err
	}
	return t.txRepo.countByIP(ctx, ip, since)
}

func (t faultTx) countInvitations(ctx context.Context, inviter string, since time.Time) (int, error) {
	if err := t.f.fail("countInvitations"); err != nil {
		return 0, err
	}
	return t.txRepo.countInvitations(ctx, inviter, since)
}

func (t faultTx) createChallenge(ctx context.Context, c store.Challenge) error {
	if err := t.f.fail("createChallenge"); err != nil {
		return err
	}
	return t.txRepo.createChallenge(ctx, c)
}

func (t faultTx) consumeChallenge(ctx context.Context, chID string, now time.Time) error {
	if err := t.f.fail("consumeChallenge"); err != nil {
		return err
	}
	return t.txRepo.consumeChallenge(ctx, chID, now)
}

func (t faultTx) upsertVerified(ctx context.Context, v store.VerifiedAddress) ([store.RecognitionSaltSize]byte, error) {
	if err := t.f.fail("upsertVerified"); err != nil {
		return [store.RecognitionSaltSize]byte{}, err
	}
	return t.txRepo.upsertVerified(ctx, v)
}

func (t faultTx) touchVerified(ctx context.Context, email string, now time.Time) error {
	if err := t.f.fail("touchVerified"); err != nil {
		return err
	}
	return t.txRepo.touchVerified(ctx, email, now)
}

func (t faultTx) createSession(ctx context.Context, s store.DepositSession) error {
	if err := t.f.fail("createSession"); err != nil {
		return err
	}
	return t.txRepo.createSession(ctx, s)
}

func (t faultTx) touchInvitation(ctx context.Context, invID string, now time.Time) error {
	if err := t.f.fail("touchInvitation"); err != nil {
		return err
	}
	return t.txRepo.touchInvitation(ctx, invID, now)
}

func (t faultTx) createInvitation(ctx context.Context, inv store.Invitation) error {
	if err := t.f.fail("createInvitation"); err != nil {
		return err
	}
	return t.txRepo.createInvitation(ctx, inv)
}

// TestFaults injects a failure at every step and checks that it surfaces
// as an internal error (no sentinel), or as the documented sentinel.
func TestFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		real := ev.svc.repo
		realKeys := ev.svc.keys

		// Fixtures: a verified internal user with a session, an invitation
		// whose invitee is verified, and a pending challenge of each kind.
		sess := ev.mustSession(t, ev.a, internalIP, alice, "")
		_, invToken := ev.mustInvite(t, bob)
		extSess := ev.mustSession(t, ev.a, externalIP, bob, invToken)
		_, invToken2 := ev.mustInvite(t, "carl@partner.example.org")
		chInt := ev.mustChallenge(t, ev.a, internalIP, "dan@entity-a.example.com", "")
		codeInt := codeOf(t, ev.queue.last(t))
		chExt := ev.mustChallenge(t, ev.a, externalIP, "carl@partner.example.org", invToken2)
		codeExt := codeOf(t, ev.queue.last(t))

		startInt := func() error {
			_, err := ev.svc.Start(ctx, ev.a, internalIP, "", "erin@entity-a.example.com", "", "")
			return err
		}
		startVerified := func() error { _, err := ev.svc.Start(ctx, ev.a, internalIP, "", alice, "", ev.known); return err }
		startInvited := func() error { _, err := ev.svc.Start(ctx, ev.a, externalIP, "", bob, invToken, ""); return err }
		confirmInt := func() error { _, err := ev.svc.Confirm(ctx, ev.a, internalIP, chInt.ID, codeInt, ""); return err }
		confirmWrong := func() error {
			_, err := ev.svc.Confirm(ctx, ev.a, internalIP, chInt.ID, wrongCodeFor(codeInt), "")
			return err
		}
		confirmExt := func() error { _, err := ev.svc.Confirm(ctx, ev.a, externalIP, chExt.ID, codeExt, ""); return err }
		session := func() error { _, err := ev.svc.Session(ctx, ev.a, sess.Token); return err }
		extSession := func() error { _, err := ev.svc.Session(ctx, ev.a, extSess.Token); return err }
		end := func() error { return ev.svc.End(ctx, ev.a, sess.Token) }
		invite := func() error {
			_, err := ev.svc.Invite(ctx, ev.a, sess.SessionInfo, internalIP, "", "fay@partner.example.org", "", "")
			return err
		}
		public := func() error { _, err := ev.svc.PublicInvitation(ctx, ev.a, invToken); return err }

		type step struct {
			name string
			call func() error
			want error // nil: an internal error, matching no sentinel
		}
		repoFaults := map[string][]step{
			"blocked":          {{"Start", startInt, nil}},
			"networkRules":     {{"Start", startInt, nil}},
			"invitationByHash": {{"Start", startInvited, nil}, {"PublicInvitation", public, nil}},
			"invitation":       {{"Session", extSession, nil}, {"Confirm", confirmExt, nil}},
			"verified":         {{"Start", startVerified, nil}},
			"countByEmail":     {{"Start", startInt, nil}},
			"countByIP":        {{"Start", startInt, nil}},
			"smtp":             {{"Start", startInt, nil}, {"Invite", invite, nil}},
			"challenge":        {{"Confirm", confirmInt, nil}},
			"decrementAttempt": {{"Confirm", confirmWrong, nil}},
			"session":          {{"Session", session, nil}},
			"endSession":       {{"End", end, nil}},
			"createChallenge":  {{"Start", startInt, nil}},
			"touchVerified":    {{"Start", startVerified, nil}},
			"consumeChallenge": {{"Confirm", confirmInt, nil}},
			"upsertVerified":   {{"Confirm", confirmInt, nil}},
			"createSession":    {{"Start", startVerified, nil}},
			"touchInvitation":  {{"Confirm", confirmExt, nil}},
			"countInvitations": {{"Invite", invite, nil}},
			"createInvitation": {{"Invite", invite, nil}},
		}
		for op, steps := range repoFaults {
			ev.svc.repo = faultRepo{repo: real, fails: map[string]error{op: errFault}}
			for _, st := range steps {
				err := st.call()
				if !errors.Is(err, errFault) || isSentinel(err) {
					t.Errorf("%s with %s failing: err = %v, want an internal error", st.name, op, err)
				}
			}
		}

		// store.ErrNotFound at the conditional steps means a concurrent
		// change: the documented sentinels.
		notFound := map[string]step{
			"decrementAttempt": {"Confirm", confirmWrong, ErrChallengeGone},
			"consumeChallenge": {"Confirm", confirmInt, ErrChallengeGone},
			"touchInvitation":  {"Confirm", confirmExt, ErrInvitationGone},
			"invitation":       {"Session", extSession, ErrUnauthenticated},
		}
		for op, st := range notFound {
			ev.svc.repo = faultRepo{repo: real, fails: map[string]error{op: store.ErrNotFound}}
			wantErr(t, st.name+" with "+op+" not found", st.call(), st.want)
		}
		ev.svc.repo = real

		// Random sources and keys.
		for _, prefix := range []string{id.ChallengeTokenPrefix, id.SessionTokenPrefix, id.InvitationTokenPrefix} {
			ev.svc.newToken = func(p string, n int) (string, error) {
				if p == prefix {
					return "", errFault
				}
				return id.NewToken(p, n)
			}
			for _, call := range []func() error{startInt, startVerified, invite} {
				if err := call(); err != nil && !errors.Is(err, errFault) {
					t.Errorf("newToken(%s) failing: unexpected %v", prefix, err)
				}
			}
		}
		ev.svc.newToken = id.NewToken
		for _, p := range []id.Prefix{id.DepositSession, id.Invitation} {
			ev.svc.newID = func(q id.Prefix) (string, error) {
				if q == p {
					return "", errFault
				}
				return id.New(q), nil
			}
			call := startVerified
			if p == id.Invitation {
				call = invite
			}
			wantErr(t, "newID("+string(p)+") failing", call(), errFault)
		}
		ev.svc.newID = func(q id.Prefix) (string, error) { return id.New(q), nil }
		ev.svc.rand = &seqReader{}
		wantErr(t, "Start with a failing random source", startInt(), io.ErrUnexpectedEOF)
		ev.svc.rand = rand.Reader

		ev.svc.keys = failKeys{Keys: realKeys, mac: true}
		wantErr(t, "Start with failing MAC", startInt(), errFault)
		wantErr(t, "Start(verified) with failing MAC", startVerified(), errFault)
		wantErr(t, "Session with failing MAC", session(), errFault)
		ev.svc.keys = failKeys{Keys: realKeys, mac: true, only: crypto.MACPurposeCSRF}
		wantErr(t, "Start(verified) with failing CSRF MAC", startVerified(), errFault)
		ev.svc.keys = failKeys{Keys: realKeys, verify: true}
		wantErr(t, "Confirm with failing VerifyMAC", confirmInt(), errFault)
		wantErr(t, "Start(verified) with failing VerifyMAC", startVerified(), errFault)
		ev.svc.keys = realKeys

		// Mail.
		ev.svc.secrets = failSecrets{}
		wantErr(t, "Start with failing vault", startInt(), errFault)
		ev.svc.secrets = ev.vault
		realRender := ev.svc.render
		ev.svc.render = func(context.Context, mail.OverrideLookup, string, string, string, any) (mail.Message, error) {
			return mail.Message{}, errFault
		}
		wantErr(t, "Start with failing render", startInt(), errFault)
		ev.svc.render = realRender
		for _, tc := range []struct {
			err, want error
		}{
			{mail.ErrQueueClosed, ErrMailUnavailable},
			{mail.ErrInvalidSettings, ErrMailUnavailable},
			{mail.ErrCircuitOpen, ErrMailUnavailable},
			{errFault, errFault},
		} {
			ev.queue.setErr(tc.err)
			wantErr(t, "Start with queue error", startInt(), tc.want)
			wantErr(t, "Invite with queue error", invite(), tc.want)
		}
		// The compensation of a refused mail is best effort: its failure is
		// logged and the request answers the queue error.
		var compLogs bytes.Buffer
		ev.svc.logger = slog.New(slog.NewTextHandler(&compLogs, nil))
		ev.svc.repo = faultRepo{repo: real, fails: map[string]error{"deleteChallenge": errFault, "deleteInvitation": errFault}}
		wantErr(t, "Start with queue error, failing delete", startInt(), errFault)
		wantErr(t, "Invite with queue error, failing delete", invite(), errFault)
		ev.svc.repo, ev.svc.logger = real, slog.New(slog.DiscardHandler)
		if !strings.Contains(compLogs.String(), "discarding an unsent verification challenge failed") ||
			!strings.Contains(compLogs.String(), "deleting an unsent invitation failed") {
			t.Errorf("compensation failures not reported: %s", compLogs.String())
		}
		ev.queue.setErr(nil)
		_, err := ev.svc.Start(ctx, ev.c, internalIP, "", alice, "", "")
		wantErr(t, "Start on a tenant without smtp", err, ErrMailUnavailable)

		// A failing security log never fails the request.
		var logs bytes.Buffer
		ev.svc.seclog, ev.svc.logger = failLog{}, slog.New(slog.NewTextHandler(&logs, nil))
		_, err = ev.svc.Start(ctx, ev.a, externalIP, "", alice, "", "")
		wantErr(t, "Start refused with a failing security log", err, ErrForbidden)
		if !strings.Contains(logs.String(), "security log write failed") || !strings.Contains(logs.String(), "deposit_refused") {
			t.Errorf("the security log failure was not reported: %s", logs.String())
		}

		// The real repository refuses a malformed tenant ID in tx.
		err = storeRepo{db: ev.db}.tx(ctx, "bogus", func(txRepo) error { return nil })
		wantErr(t, "tx(bad tenant)", err, store.ErrInvalid)

		// Sanity: everything works again with the real dependencies.
		if err := startInt(); err != nil {
			t.Errorf("Start after the faults: %v", err)
		}
	})
}

// isSentinel reports whether err matches one of the service sentinels.
func isSentinel(err error) bool {
	for _, s := range []error{
		ErrInvalid, ErrForbidden, ErrInvitationGone, ErrRateLimited, ErrMailUnavailable,
		ErrNotFound, ErrChallengeGone, ErrWrongCode, ErrUnauthenticated,
	} {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}
