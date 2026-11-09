package secret

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/tte2"
)

const carol = "carol@customer.example.net"

// linkHalves returns a valid secret token and fragment key.
func linkHalves(t *testing.T) (token, key string) {
	t.Helper()
	token, err := id.NewSecretToken()
	if err != nil {
		t.Fatal(err)
	}
	k, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ = tte2.EncodeKey(k)
	return token, key
}

// pendingMail is a pending e-mail secret of alice, from a deposit session.
func pendingMail() store.Secret {
	return store.Secret{
		ID: id.New(id.Secret), TenantID: testTenant.ID, State: store.SecretPending, CreatorKind: store.SecretCreatorInternal,
		SenderEmail: alice, Delivery: store.SecretDeliveryEmail, RecipientEmail: carol, Duration: tenant.SecretDuration1h,
		ReadReceipt: true, CreatedAt: testNow.Add(-time.Minute),
	}
}

func TestSend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	token, key := linkHalves(t)
	e := newEnv(t)
	sec := pendingMail()
	e.repo.got = sec
	act := sec
	act.State, act.ActivatedAt, act.ExpiresAt = store.SecretActive, testNow, testNow.Add(time.Hour)
	e.repo.activated = act

	out, err := e.svc.Send(ctx, testTenant, internalSender(), sec.ID, token, key)
	if err != nil || out.State != store.SecretActive {
		t.Fatalf("Send = %+v, %v", out, err)
	}
	// The link is built on the registered FQDN, with the token and the key.
	if want := "https://" + testTenant.FQDN + "/s/" + token + "#k=" + key; !slices.Equal(e.notifier.links, []string{want}) {
		t.Errorf("links = %v, want %s", e.notifier.links, want)
	}
	if v := e.notifier.views[0]; v.RecipientEmail != carol || !v.ExpiresAt.Equal(testNow.Add(time.Hour)) || v.SenderEmail != alice {
		t.Errorf("view = %+v", v)
	}
	if e.repo.gotToken != token || !e.repo.gotNow.Equal(testNow) || e.repo.gotActor.Email != alice ||
		e.repo.gotActor.Kind != store.SecretCreatorInternal {
		t.Errorf("activation: token %q, now %v, actor %+v", e.repo.gotToken, e.repo.gotNow, e.repo.gotActor)
	}
	if got := e.mailer.templates(); !slices.Equal(got, []string{mail.TemplateSecretNotification}) {
		t.Errorf("mails = %v", got)
	}
	if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionSecretSent}) {
		t.Fatalf("audit = %v", got)
	}
	ev := e.audit.events[0]
	if ev.ActorKind != store.ActorDepositor || ev.Actor != alice || ev.ObjectID != sec.ID || ev.IP != internalIP ||
		ev.Details["delivery"] != "email" || ev.Details["recipientDomain"] != "customer.example.net" {
		t.Errorf("sent event = %+v", ev)
	}
	// Neither the token nor the key reaches the audit or the security log.
	for _, x := range []string{token, key} {
		if strings.Contains(stringify(e.audit.events), x) || len(e.seclog.events) != 0 {
			t.Error("the token or the key reached the logs")
		}
	}

	// An API token is the actor of its own send.
	tokID := id.New(id.APIToken)
	byToken := transfer.Sender{Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: tokID}, ClientIP: internalIP}
	e.repo.got.CreatorKind, e.repo.got.APITokenID = store.SecretCreatorAPIToken, tokID
	if _, err := e.svc.Send(ctx, testTenant, byToken, sec.ID, token, key); err != nil {
		t.Fatal(err)
	}
	if ev := e.audit.events[1]; ev.ActorKind != store.ActorAPIToken || ev.Actor != tokID {
		t.Errorf("token event = %+v", ev)
	}
}

// stringify renders audit events for a substring check.
func stringify(evs []audit.Event) string {
	var b strings.Builder
	for _, ev := range evs {
		b.WriteString(ev.Actor + " " + ev.ObjectID + " ")
		for k, v := range ev.Details {
			b.WriteString(k + "=")
			if s, ok := v.(string); ok {
				b.WriteString(s)
			}
			b.WriteString(" ")
		}
	}
	return b.String()
}

func TestSendRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	token, key := linkHalves(t)
	tests := []struct {
		name   string
		sender transfer.Sender
		token  string
		key    string
		setup  func(*env)
		check  func(error) bool
		built  bool
	}{
		{
			"reply",
			transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorReply}},
			token, key, nil,
			func(err error) bool { return errors.Is(err, ErrNotFound) }, false,
		},
		{
			"unknown", internalSender(), token, key, func(e *env) { e.repo.getErr = store.ErrNotFound },
			func(err error) bool { return errors.Is(err, ErrNotFound) }, false,
		},
		{
			"read failure", internalSender(), token, key, func(e *env) { e.repo.getErr = errBoom },
			func(err error) bool { return errors.Is(err, errBoom) }, false,
		},
		{
			"another creator", internalSender(), token, key, func(e *env) { e.repo.got.SenderEmail = bob },
			func(err error) bool { return errors.Is(err, ErrNotFound) }, false,
		},
		{
			"another kind", internalSender(), token, key, func(e *env) { e.repo.got.CreatorKind = store.SecretCreatorExternal },
			func(err error) bool { return errors.Is(err, ErrNotFound) }, false,
		},
		{
			"link delivery", internalSender(), token, key, func(e *env) { e.repo.got.Delivery, e.repo.got.RecipientEmail = store.SecretDeliveryLink, "" },
			func(err error) bool { return errors.Is(err, ErrConflict) }, false,
		},
		{
			"active", internalSender(), token, key, func(e *env) { e.repo.got.State = store.SecretActive },
			func(err error) bool { return errors.Is(err, ErrConflict) }, false,
		},
		{
			"file missing", internalSender(), token, key, func(e *env) { e.repo.got.FileSize = 100 },
			func(err error) bool { return errors.Is(err, ErrConflict) }, false,
		},
		{
			"no SMTP", internalSender(), token, key, func(e *env) { e.notifier.notifErr = notify.ErrNoSMTP },
			func(err error) bool { return errors.Is(err, ErrMailUnavailable) }, true,
		},
		{
			"render failure", internalSender(), token, key, func(e *env) { e.notifier.notifErr = errBoom },
			func(err error) bool { return errors.Is(err, errBoom) }, true,
		},
		{
			"race", internalSender(), token, key, func(e *env) { e.repo.activateErr = store.ErrSecretState },
			func(err error) bool { return errors.Is(err, ErrConflict) }, true,
		},
		{
			"wrong token", internalSender(), token, key, func(e *env) { e.repo.activateErr = store.ErrNotFound },
			func(err error) bool { return errors.Is(err, ErrNotFound) }, true,
		},
		{
			"activation failure", internalSender(), token, key, func(e *env) { e.repo.activateErr = errBoom },
			func(err error) bool { return errors.Is(err, errBoom) }, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.repo.got = pendingMail()
			if tt.setup != nil {
				tt.setup(e)
			}
			_, err := e.svc.Send(ctx, testTenant, tt.sender, e.repo.got.ID, tt.token, tt.key)
			if !tt.check(err) {
				t.Fatalf("err = %v", err)
			}
			if got := len(e.notifier.links) > 0; got != tt.built {
				t.Errorf("mail built = %v, want %v", got, tt.built)
			}
			if len(e.mailer.sent) != 0 || len(e.audit.events) != 0 || len(e.seclog.events) != 0 {
				t.Errorf("refused send queued %d mails, audited %v, logged %v", len(e.mailer.sent), e.audit.actions(), e.seclog.types())
			}
			// Without SMTP settings, nothing is activated.
			if tt.name == "no SMTP" && e.repo.gotToken != "" {
				t.Error("activated without SMTP settings")
			}
			if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), key)) {
				t.Errorf("error %q holds the token or the key", err)
			}
		})
	}
}

func TestSendValidation(t *testing.T) {
	t.Parallel()
	token, key := linkHalves(t)
	e := newEnv(t)
	for _, tt := range []struct {
		token, key string
		want       []string
	}{
		{"", "", []string{"/secretToken required", "/fragmentKey required"}},
		{"tts_short", key[:42], []string{"/secretToken invalid-format", "/fragmentKey invalid-format"}},
		{"ttd_" + token[4:], key[:42] + "B", []string{"/secretToken invalid-format", "/fragmentKey invalid-format"}},
	} {
		_, err := e.svc.Send(context.Background(), testTenant, internalSender(), "sec_x", tt.token, tt.key)
		if got := fieldsOf(t, err); !slices.Equal(got, tt.want) {
			t.Errorf("Send(%q, %q) fields = %v, want %v", tt.token, tt.key, got, tt.want)
		}
	}
	if e.repo.gets != 0 {
		t.Error("a malformed request reached the store")
	}
}

// emailRequest is a valid e-mail creation request of s to recipient.
func emailRequest(s sealed, recipient string) CreateRequest {
	req := s.request()
	req.Delivery, req.Recipient = DeliveryEmail, ptr(recipient)
	return req
}

func TestCreateRecipientRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "the secret", "")
	tokID := id.New(id.APIToken)
	byToken := transfer.Sender{Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: tokID}, ClientIP: internalIP}

	// Allowed: created, the recipient checked against both lists.
	e := newEnv(t)
	e.dir.rules = store.RecipientRuleSet{Allowed: []string{"customer.example.net"}}
	if _, err := e.svc.Create(ctx, testTenant, internalSender(), emailRequest(s, " Carol@Customer.example.net")); err != nil {
		t.Fatal(err)
	}
	if e.dir.gotEmail != carol || e.repo.gotCreate.RecipientEmail != carol {
		t.Errorf("checked %q, stored %q", e.dir.gotEmail, e.repo.gotCreate.RecipientEmail)
	}

	for _, tt := range []struct {
		name   string
		sender transfer.Sender
		setup  func(*fakeDirectory)
		reason string
		actor  string
		origin string
	}{
		{"blocklist", internalSender(), func(d *fakeDirectory) { d.blocked = true }, reasonBlocklist, alice, originInternal},
		{"denied domain", internalSender(), func(d *fakeDirectory) { d.rules.Denied = []string{"example.net"} }, reasonDomainRules, alice, originInternal},
		{"outside the allow list", byToken, func(d *fakeDirectory) { d.rules.Allowed = []string{"entity-a.example.com"} }, reasonDomainRules, tokID, originAPI},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			tt.setup(e.dir)
			req := emailRequest(s, carol)
			if tt.sender.APITokenID != "" {
				req.SenderEmail = ptr(alice)
			}
			if _, err := e.svc.Create(ctx, testTenant, tt.sender, req); !errors.Is(err, ErrRecipientRefused) {
				t.Fatalf("err = %v", err)
			}
			if e.repo.gotCreate.SealedText != "" {
				t.Error("a refused secret reached the store")
			}
			if len(e.seclog.events) != 0 {
				t.Errorf("security log = %v, want nothing (a policy refusal)", e.seclog.types())
			}
			if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionTransferRecipientRefused}) {
				t.Fatalf("audit = %v", got)
			}
			ev := e.audit.events[0]
			domains, _ := ev.Details["domains"].([]string)
			if ev.Actor != tt.actor || ev.ObjectKind != audit.ObjectTenant || ev.ObjectID != testTenant.ID.String() ||
				!slices.Equal(domains, []string{"customer.example.net"}) || ev.Details["reason"] != tt.reason ||
				ev.Details["origin"] != tt.origin || ev.Details["object"] != audit.ObjectSecret {
				t.Errorf("refusal event = %+v", ev)
			}
		})
	}

	// The lookups fail: the creation fails, nothing created.
	e = newEnv(t)
	e.dir.blockedErr = errBoom
	if _, err := e.svc.Create(ctx, testTenant, internalSender(), emailRequest(s, carol)); !errors.Is(err, errBoom) {
		t.Errorf("blocklist failure: %v", err)
	}
	e.dir.blockedErr, e.dir.rulesErr = nil, errBoom
	if _, err := e.svc.Create(ctx, testTenant, internalSender(), emailRequest(s, carol)); !errors.Is(err, errBoom) {
		t.Errorf("rules failure: %v", err)
	}

	// An invited external has no free choice: its recipient (forced to its
	// inviter by the store) is not checked; a link secret has none.
	e = newEnv(t)
	e.dir.blocked = true
	external := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: id.New(id.Invitation)}}
	if _, err := e.svc.Create(ctx, testTenant, external, emailRequest(s, carol)); err != nil {
		t.Errorf("external: %v", err)
	}
	if _, err := e.svc.Create(ctx, testTenant, internalSender(), s.request()); err != nil {
		t.Errorf("link: %v", err)
	}
	if e.dir.gotEmail != "" {
		t.Errorf("recipient %q checked", e.dir.gotEmail)
	}
}

func TestReadReceipts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "the secret", "")
	ended := testNow.Add(-time.Second)
	tomb := func(receipt bool) store.Secret {
		sec := pendingMail()
		sec.State, sec.ReadReceipt, sec.ReadAt, sec.EndedAt = store.SecretRead, receipt, ended, ended
		return sec
	}

	t.Run("read", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.repo.revealed, e.repo.marked = store.RevealedSecret{Secret: tomb(true), SealedText: s.text}, true
		if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", s.keyProof, s.proof); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(e.notifier.outcomes, []string{mail.SecretOutcomeRead}) || !e.notifier.ats[0].Equal(ended) ||
			!slices.Equal(e.mailer.templates(), []string{mail.TemplateSecretReceipt}) || e.repo.marks != 1 {
			t.Errorf("outcomes %v at %v, mails %v, marks %d", e.notifier.outcomes, e.notifier.ats, e.mailer.templates(), e.repo.marks)
		}
	})
	t.Run("not marked", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.repo.revealed = store.RevealedSecret{Secret: tomb(true), SealedText: s.text}
		if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", s.keyProof, s.proof); err != nil {
			t.Fatal(err)
		}
		if len(e.mailer.sent) != 0 || e.repo.marks != 1 {
			t.Errorf("a receipt marked elsewhere was sent again (%d mails)", len(e.mailer.sent))
		}
	})
	t.Run("failures", func(t *testing.T) {
		t.Parallel()
		for name, setup := range map[string]func(*env){
			"mark":   func(e *env) { e.repo.markErr = errBoom },
			"SMTP":   func(e *env) { e.notifier.receiptErr = notify.ErrNoSMTP },
			"render": func(e *env) { e.notifier.receiptErr = errBoom },
		} {
			e := newEnv(t)
			e.repo.revealed, e.repo.marked = store.RevealedSecret{Secret: tomb(true), SealedText: s.text}, true
			setup(e)
			if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", s.keyProof, s.proof); err != nil {
				t.Fatalf("%s: a receipt failure failed the reveal: %v", name, err)
			}
			if len(e.mailer.sent) != 0 {
				t.Errorf("%s: mail queued", name)
			}
			if name != "mark" && e.repo.marks != 0 {
				t.Errorf("%s: receipt marked although not built", name)
			}
		}
	})
	t.Run("not asked", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.repo.revealed, e.repo.marked = store.RevealedSecret{Secret: tomb(false), SealedText: s.text}, true
		if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", s.keyProof, s.proof); err != nil {
			t.Fatal(err)
		}
		if len(e.notifier.outcomes) != 0 || e.repo.marks != 0 {
			t.Error("receipt sent without being asked")
		}
	})
	t.Run("locked", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		locked := tomb(true)
		locked.State = store.SecretLocked
		e.repo.got, e.repo.marked = locked, true
		e.repo.revealErr = &store.SecretProofError{ID: locked.ID}
		var gone *GoneError
		if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", s.keyProof, s.proof); !errors.As(err, &gone) {
			t.Fatal(err)
		}
		if e.repo.gotSecID != locked.ID || !slices.Equal(e.notifier.outcomes, []string{mail.SecretOutcomeLocked}) ||
			len(e.mailer.sent) != 1 {
			t.Errorf("read %s, outcomes %v, %d mails", e.repo.gotSecID, e.notifier.outcomes, len(e.mailer.sent))
		}
		// The tombstone cannot be read: no receipt, the answer unchanged.
		e = newEnv(t)
		e.repo.getErr, e.repo.revealErr = errBoom, &store.SecretProofError{ID: locked.ID}
		if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", s.keyProof, s.proof); !errors.As(err, &gone) {
			t.Fatal(err)
		}
		if len(e.notifier.outcomes) != 0 {
			t.Error("receipt built without the tombstone")
		}
	})
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.repo.marked = true
		exp := tomb(true)
		exp.State, exp.ReadAt = store.SecretExpired, time.Time{}
		e.svc.Expired(ctx, store.EndedSecret{Secret: exp})
		if !slices.Equal(e.notifier.outcomes, []string{mail.SecretOutcomeExpired}) || !e.notifier.ats[0].Equal(ended) ||
			len(e.mailer.sent) != 1 {
			t.Errorf("outcomes %v, %d mails", e.notifier.outcomes, len(e.mailer.sent))
		}
		// Without receipt nothing is read; a tenant that cannot be read
		// sends nothing.
		e = newEnv(t)
		e.dir.tenantErr = errBoom
		e.svc.Expired(ctx, store.EndedSecret{Secret: exp})
		exp.ReadReceipt = false
		e.svc.Expired(ctx, store.EndedSecret{Secret: exp})
		if len(e.notifier.outcomes) != 0 || e.repo.marks != 0 {
			t.Error("receipt sent")
		}
	})
}

func TestAbuseOnActivation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "the secret", "")
	e := newEnv(t)
	// A link secret without file is active at once.
	if _, err := e.svc.Create(ctx, testTenant, internalSender(), s.request()); err != nil {
		t.Fatal(err)
	}
	// An e-mail secret stays pending: nothing yet.
	e.repo.created = store.CreatedSecret{Token: "tts_tok", Secret: pendingMail()}
	if _, err := e.svc.Create(ctx, testTenant, internalSender(), emailRequest(s, carol)); err != nil {
		t.Fatal(err)
	}
	if len(e.abuse.facts) != 1 {
		t.Fatalf("facts after the creations = %+v", e.abuse.facts)
	}
	f := e.abuse.facts[0]
	if f.Kind != store.DepositorInternal || f.SenderEmail != alice || f.Recipients != nil || f.Bytes != 0 || f.TransferID != "" || f.ClientIP != internalIP ||
		!f.At.Equal(testNow) {
		t.Errorf("link facts = %+v", f)
	}
	// The upload of a link secret activates it; of an e-mail one, not.
	link := store.Secret{
		ID: id.New(id.Secret), State: store.SecretActive, CreatorKind: store.SecretCreatorInternalRemote,
		SenderEmail: alice, Delivery: store.SecretDeliveryLink, ActivatedAt: testNow,
	}
	e.repo.uploaded = link
	if _, err := e.svc.UploadFile(ctx, testTenant, internalSender(), link.ID, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	e.repo.uploaded = pendingMail()
	if _, err := e.svc.UploadFile(ctx, testTenant, internalSender(), link.ID, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if len(e.abuse.facts) != 2 || e.abuse.facts[1].Kind != store.DepositorInternalRemote || e.abuse.facts[1].SenderEmail != alice {
		t.Fatalf("facts after the uploads = %+v", e.abuse.facts)
	}
	// The send activates an e-mail secret: its recipient is counted.
	token, key := linkHalves(t)
	e.repo.got = pendingMail()
	act := e.repo.got
	act.State, act.ActivatedAt, act.CreatorKind = store.SecretActive, testNow, store.SecretCreatorExternal
	e.repo.activated = act
	if _, err := e.svc.Send(ctx, testTenant, internalSender(), act.ID, token, key); err != nil {
		t.Fatal(err)
	}
	if len(e.abuse.facts) != 3 || !slices.Equal(e.abuse.facts[2].Recipients, []string{carol}) ||
		e.abuse.facts[2].Kind != store.DepositorExternal {
		t.Errorf("facts after the send = %+v", e.abuse.facts)
	}
	if depositorKind(store.SecretCreatorAPIToken) != store.DepositorInternal {
		t.Error("an API token deposits as an internal sender")
	}
}

// TestSendRecipientRules applies the recipient rules again at the send:
// a rule added after the creation refuses it, nothing is built nor
// activated, and the recipient of an invited external is not checked.
func TestSendRecipientRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	token, key := linkHalves(t)
	for _, tt := range []struct {
		name   string
		setup  func(*fakeDirectory)
		reason string
	}{
		{"blocklist", func(d *fakeDirectory) { d.blocked = true }, reasonBlocklist},
		{"denied domain", func(d *fakeDirectory) { d.rules.Denied = []string{"customer.example.net"} }, reasonDomainRules},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.repo.got = pendingMail()
			tt.setup(e.dir)
			if _, err := e.svc.Send(ctx, testTenant, internalSender(), e.repo.got.ID, token, key); !errors.Is(err, ErrRecipientRefused) {
				t.Fatalf("err = %v", err)
			}
			if e.dir.gotEmail != carol || len(e.notifier.links) != 0 || e.repo.gotToken != "" || len(e.mailer.sent) != 0 {
				t.Errorf("checked %q, built %d, activated %q, sent %d", e.dir.gotEmail, len(e.notifier.links), e.repo.gotToken, len(e.mailer.sent))
			}
			if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionTransferRecipientRefused}) ||
				e.audit.events[0].Details["reason"] != tt.reason || e.audit.events[0].Actor != alice {
				t.Errorf("audit = %v, %+v", got, e.audit.events)
			}
		})
	}
	// A lookup failure fails the send.
	e := newEnv(t)
	e.repo.got = pendingMail()
	e.dir.rulesErr = errBoom
	if _, err := e.svc.Send(ctx, testTenant, internalSender(), e.repo.got.ID, token, key); !errors.Is(err, errBoom) {
		t.Errorf("rules failure: %v", err)
	}
	// An invited external: its recipient is its inviter, not checked.
	e = newEnv(t)
	sec := pendingMail()
	sec.CreatorKind, sec.SenderEmail, sec.RecipientEmail = store.SecretCreatorExternal, bob, alice
	e.repo.got, e.repo.activated = sec, sec
	e.dir.blocked = true
	external := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: id.New(id.Invitation)}}
	if _, err := e.svc.Send(ctx, testTenant, external, sec.ID, token, key); err != nil {
		t.Errorf("external: %v", err)
	}
	if e.dir.gotEmail != "" {
		t.Errorf("recipient %q checked for an external", e.dir.gotEmail)
	}
}
