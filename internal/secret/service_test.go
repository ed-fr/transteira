package secret

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/tte2"
)

func TestNew(t *testing.T) {
	t.Parallel()
	full := Deps{
		Secrets: &fakeRepo{}, Creators: &fakeCreators{}, Scrubber: &fakeScrubber{}, Files: &fakeFiles{}, SecurityLog: &fakeSeclog{},
		Directory: &fakeDirectory{}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
	}
	for name, mutate := range map[string]func(*Deps){
		"directory": func(d *Deps) { d.Directory = nil },
		"notifier":  func(d *Deps) { d.Notifier = nil },
		"mailer":    func(d *Deps) { d.Mailer = nil },
		"secrets":   func(d *Deps) { d.Secrets = nil },
		"creators":  func(d *Deps) { d.Creators = nil },
		"scrubber":  func(d *Deps) { d.Scrubber = nil },
		"files":     func(d *Deps) { d.Files = nil },
		"seclog":    func(d *Deps) { d.SecurityLog = nil },
	} {
		d := full
		mutate(&d)
		if _, err := New(d, Options{}); !errors.Is(err, errMissingDeps) {
			t.Errorf("without %s: %v", name, err)
		}
	}
	s, err := New(full, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.now == nil || s.logger == nil || s.requests == nil || s.failures == nil || s.audit != nil {
		t.Errorf("defaults not set: %+v", s)
	}
}

func TestClientKey(t *testing.T) {
	t.Parallel()
	for ip, want := range map[string]string{
		"":                 "invalid",
		"192.0.2.7":        "192.0.2.7",
		"::ffff:192.0.2.7": "192.0.2.7",
		"2001:db8:1:2::9":  "2001:db8:1:2::/64",
	} {
		var addr netip.Addr
		if ip != "" {
			addr = netip.MustParseAddr(ip)
		}
		if got := clientKey(addr); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", ip, got, want)
		}
	}
}

// TestBestEffortFailures checks that the failures of the security log, the
// audit, the file removal and the scrub never fail a request.
func TestBestEffortFailures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seclog.err, e.audit.err, e.files.err, e.scrubber.err = errBoom, errBoom, errBoom, errBoom
	e.svc.logger = slog.New(slog.DiscardHandler)
	e.repo.statusErr = store.ErrNotFound
	if _, err := e.svc.Status(context.Background(), testTenant, internalIP, "tts_x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status: %v", err)
	}
	e.repo.ended = store.EndedSecret{Secret: store.Secret{SenderEmail: alice}, RemovedFile: strings.Repeat("a", 32)}
	if err := e.svc.DeleteMine(context.Background(), testTenant, alice, internalIP, "sec_x"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(e.files.removed) != 1 || e.scrubber.calls != 1 || len(e.audit.events) != 1 || len(e.seclog.events) != 1 {
		t.Errorf("removed %v, scrubs %d, audit %v, seclog %v", e.files.removed, e.scrubber.calls, e.audit.events, e.seclog.events)
	}
	// Without an audit recorder nothing is recorded.
	e.svc.audit = nil
	e.svc.record(context.Background(), testTenant, audit.Event{Action: audit.ActionSecretDeleted})
}

func TestCreate(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	e := newEnv(t)
	req := s.request()
	req.ReadReceipt = true
	out, err := e.svc.Create(context.Background(), testTenant, internalSender(), req)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID == "" || out.Token != "tts_tok" || out.State != store.SecretActive || !out.ExpiresAt.Equal(testNow.Add(24*time.Hour)) {
		t.Errorf("created = %+v", out)
	}
	c := e.repo.gotCreate
	if c.CreatorKind != store.SecretCreatorInternal || c.SenderEmail != alice || c.Delivery != store.SecretDeliveryLink ||
		c.Duration != tenant.SecretDuration1d || c.SealedText != s.text || !c.ReadReceipt || c.KDFSalt != nil ||
		tte2.EncodeProof(c.Verifier) != s.verifier || tte2.EncodeProof(c.KeyVerifier) != s.keyVerifier || !c.Now.Equal(testNow) {
		t.Errorf("store input = %+v", c)
	}
	if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionSecretCreated}) {
		t.Fatalf("audit = %v", got)
	}
	ev := e.audit.events[0]
	if ev.ActorKind != store.ActorDepositor || ev.Actor != alice || ev.ObjectKind != audit.ObjectSecret || ev.ObjectID != out.ID ||
		ev.IP != internalIP || ev.Details["delivery"] != "link" || ev.Details["hasFile"] != false || ev.Details["creatorKind"] != "internal" {
		t.Errorf("audit event = %+v", ev)
	}
}

func TestCreateWithPassphrase(t *testing.T) {
	t.Parallel()
	s, d := seal(t, "the secret", "correct horse")
	e := newEnv(t)
	req := s.request()
	req.Passphrase = &Passphrase{KDF: d.KDF, Iterations: d.Iterations, Salt: d.EncodedSalt()}
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), req); err != nil {
		t.Fatal(err)
	}
	if string(e.repo.gotCreate.KDFSalt) != string(d.Salt) {
		t.Errorf("salt = %x, want %x", e.repo.gotCreate.KDFSalt, d.Salt)
	}
}

func TestCreateByAPIToken(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	e := newEnv(t)
	tokID := id.New(id.APIToken)
	sender := transfer.Sender{Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: tokID}, ClientIP: internalIP}
	req := s.request()
	// Without senderEmail, refused before the eligibility check.
	if _, err := e.svc.Create(context.Background(), testTenant, sender, req); !slices.Equal(fieldsOf(t, err), []string{"/senderEmail required"}) {
		t.Fatalf("no sender: %v", err)
	}
	if e.creators.calls != 0 {
		t.Error("eligibility checked before the validation of a token request")
	}
	req.SenderEmail = ptr(" Alice@Entity-A.example.com ")
	out, err := e.svc.Create(context.Background(), testTenant, sender, req)
	if err != nil {
		t.Fatal(err)
	}
	if e.creators.sender.Email != alice || e.repo.gotCreate.CreatorKind != store.SecretCreatorAPIToken || e.repo.gotCreate.APITokenID != tokID {
		t.Errorf("sender %+v, store input %+v", e.creators.sender, e.repo.gotCreate)
	}
	if got := e.audit.actions(); !slices.Equal(got, []audit.Action{audit.ActionSecretCreated, audit.ActionAPITokenUsed}) {
		t.Fatalf("audit = %v", got)
	}
	if ev := e.audit.events[0]; ev.ActorKind != store.ActorAPIToken || ev.Actor != tokID {
		t.Errorf("created event = %+v", ev)
	}
	if ev := e.audit.events[1]; ev.ActorKind != store.ActorDepositor || ev.Actor != alice || ev.ObjectKind != audit.ObjectAPIToken ||
		ev.ObjectID != tokID || ev.Details["objectId"] != out.ID {
		t.Errorf("token event = %+v", ev)
	}
}

func TestCreateCreators(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	inv := id.New(id.Invitation)
	remote := transfer.Sender{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternalRemote}}
	external := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: inv}}
	reply := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorReply}}
	drop := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorDropLink}}

	e := newEnv(t)
	if _, err := e.svc.Create(context.Background(), testTenant, remote, s.request()); err != nil || e.repo.gotCreate.CreatorKind != store.SecretCreatorInternalRemote {
		t.Errorf("remote: %v, %+v", err, e.repo.gotCreate)
	}
	for name, sender := range map[string]transfer.Sender{"reply": reply, "drop link": drop} {
		if _, err := e.svc.Create(context.Background(), testTenant, sender, s.request()); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An invited external must use the e-mail delivery.
	_, err := e.svc.Create(context.Background(), testTenant, external, s.request())
	if !slices.Equal(fieldsOf(t, err), []string{"/delivery not-allowed"}) {
		t.Errorf("external link: %v", err)
	}
	mail := s.request()
	mail.Delivery, mail.Recipient = DeliveryEmail, ptr(alice)
	if _, err := e.svc.Create(context.Background(), testTenant, external, mail); err != nil ||
		e.repo.gotCreate.Delivery != store.SecretDeliveryEmail || e.repo.gotCreate.CreatorKind != store.SecretCreatorExternal {
		t.Errorf("external e-mail: %v, %+v", err, e.repo.gotCreate)
	}
	noMail := *testTenant
	noMail.Secrets.EmailAllowed = false
	if _, err := e.svc.Create(context.Background(), &noMail, external, s.request()); !errors.Is(err, ErrEmailNotAllowed) {
		t.Errorf("external without e-mail delivery: %v", err)
	}
	if creatorKind(external) != store.SecretCreatorExternal {
		t.Error("external kind")
	}
	withSender := s.request()
	withSender.SenderEmail = ptr(alice)
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), withSender); !slices.Equal(fieldsOf(t, err), []string{"/senderEmail not-allowed"}) {
		t.Errorf("session with senderEmail: %v", err)
	}
	e.creators.err = transfer.ErrForbidden
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), s.request()); !errors.Is(err, ErrForbidden) {
		t.Errorf("not eligible: %v", err)
	}
	e.creators.err = errBoom
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), s.request()); !errors.Is(err, errBoom) {
		t.Errorf("eligibility failure: %v", err)
	}
}

func TestCreateExternalInvitation(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	inv := id.New(id.Invitation)
	external := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: inv}}
	// The store input of an external creator carries its invitation (the
	// input is built directly, without the settings check).
	e := newEnv(t)
	in := e.svc.storeInput(external, bob, plan{delivery: store.SecretDeliveryEmail}, s.request())
	if in.InvitationID != inv || in.CreatorKind != store.SecretCreatorExternal || in.APITokenID != "" {
		t.Errorf("store input = %+v", in)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	long := strings.Repeat("A", store.MaxSecretSealedTextLen+1)
	tests := []struct {
		name   string
		mutate func(*CreateRequest)
		token  bool
		want   []string
	}{
		{"empty", func(r *CreateRequest) { *r = CreateRequest{} }, false, []string{
			"/encryptedText required", "/verifier required", "/keyVerifier required", "/expiresIn required", "/delivery required",
		}},
		{"text too long", func(r *CreateRequest) { r.EncryptedText = long }, false, []string{"/encryptedText too-long"}},
		{"text too short", func(r *CreateRequest) { r.EncryptedText = "AQ" }, false, []string{"/encryptedText invalid-format"}},
		{"text alphabet", func(r *CreateRequest) { r.EncryptedText = strings.Repeat("A=", 30) }, false, []string{"/encryptedText invalid-format"}},
		{"verifiers", func(r *CreateRequest) { r.Verifier, r.KeyVerifier = strings.ToUpper(s.verifier), "ab" }, false, []string{
			"/verifier invalid-format", "/keyVerifier invalid-format",
		}},
		{"passphrase", func(r *CreateRequest) { r.Passphrase = &Passphrase{KDF: "argon2id", Iterations: 1, Salt: "x"} }, false, []string{
			"/passphrase/kdf not-allowed", "/passphrase/iterations not-allowed", "/passphrase/salt invalid-format",
		}},
		{"duration", func(r *CreateRequest) { r.ExpiresIn = "2d" }, false, []string{"/expiresIn not-allowed"}},
		{"delivery", func(r *CreateRequest) { r.Delivery = "sms" }, false, []string{"/delivery not-allowed"}},
		{"link recipient", func(r *CreateRequest) { r.Recipient = ptr(alice) }, false, []string{"/recipient not-allowed"}},
		{"mail without recipient", func(r *CreateRequest) { r.Delivery = DeliveryEmail }, false, []string{"/recipient required"}},
		{"mail empty recipient", func(r *CreateRequest) { r.Delivery, r.Recipient = DeliveryEmail, ptr("") }, false, []string{"/recipient required"}},
		{"mail bad recipient", func(r *CreateRequest) { r.Delivery, r.Recipient = DeliveryEmail, ptr("Bob <bob@x.example>") }, false, []string{"/recipient invalid-email"}},
		{"file", func(r *CreateRequest) { r.File = &File{Size: 47} }, false, []string{"/file/size not-allowed", "/file/encryptedMetadata required"}},
		{"file too large", func(r *CreateRequest) {
			r.File = &File{Size: MaxFileSize + 1, EncryptedMetadata: strings.Repeat("A", MaxFileMetadataLen+1)}
		}, false, []string{
			"/file/size not-allowed", "/file/encryptedMetadata too-long",
		}},
		{"file metadata alphabet", func(r *CreateRequest) { r.File = &File{Size: 48, EncryptedMetadata: "a+b"} }, false, []string{"/file/encryptedMetadata invalid-format"}},
		{"session sender", func(r *CreateRequest) { r.SenderEmail = ptr(alice) }, false, []string{"/senderEmail not-allowed"}},
		{"token empty sender", func(r *CreateRequest) { r.SenderEmail = ptr("") }, true, []string{"/senderEmail required"}},
		{"token bad sender", func(r *CreateRequest) { r.SenderEmail = ptr("alice@[192.0.2.1]") }, true, []string{"/senderEmail invalid-email"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := s.request()
			tt.mutate(&req)
			_, err := validate(req, tt.token)
			if got := fieldsOf(t, err); !slices.Equal(got, tt.want) {
				t.Errorf("fields = %v, want %v", got, tt.want)
			}
		})
	}
	// A valid e-mail request.
	req := s.request()
	req.Delivery, req.Recipient = DeliveryEmail, ptr("Carol@Customer.example.NET")
	p, err := validate(req, false)
	if err != nil || p.recipient != "carol@customer.example.net" || p.delivery != store.SecretDeliveryEmail {
		t.Errorf("e-mail plan = %+v, %v", p, err)
	}
	// Allowed values are listed.
	req = s.request()
	req.ExpiresIn = "2d"
	_, err = validate(req, false)
	var v *ValidationError
	if !errors.As(err, &v) || len(v.Fields[0].Allowed) != 6 {
		t.Errorf("allowed durations: %+v", err)
	}
}

func TestCheckFraming(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	empty, _ := seal(t, "", "")
	odd, _ := seal(t, "the secret!", "")
	meta := tte2Metadata(t)
	tests := []struct {
		name string
		req  CreateRequest
		want []string
	}{
		{"version byte", CreateRequest{EncryptedText: "B" + s.text[1:]}, []string{"/encryptedText invalid-format"}},
		// 40 bytes: 54 characters, whose last one has unused bits.
		{"not canonical", CreateRequest{EncryptedText: odd.text[:len(odd.text)-1] + "_"}, []string{"/encryptedText invalid-format"}},
		{"empty text without file", CreateRequest{EncryptedText: empty.text}, []string{"/encryptedText invalid-format"}},
		{"bad metadata", CreateRequest{EncryptedText: s.text, File: &File{EncryptedMetadata: "BQ" + meta[2:]}}, []string{"/file/encryptedMetadata invalid-format"}},
	}
	for _, tt := range tests {
		if got := fieldsOf(t, checkFraming(tt.req)); !slices.Equal(got, tt.want) {
			t.Errorf("%s: fields = %v, want %v", tt.name, got, tt.want)
		}
	}
	for name, req := range map[string]CreateRequest{
		"text":                 {EncryptedText: s.text},
		"empty text with file": {EncryptedText: empty.text, File: &File{EncryptedMetadata: meta}},
	} {
		if err := checkFraming(req); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Through Create: the framing comes after the validation.
	e := newEnv(t)
	req := s.request()
	req.EncryptedText = "B" + s.text[1:]
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), req); !slices.Equal(fieldsOf(t, err), []string{"/encryptedText invalid-format"}) {
		t.Errorf("create: %v", err)
	}
	var f *FormatError
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), req); !errors.As(err, &f) {
		t.Errorf("create: %v, want a *FormatError", err)
	}
}

// tte2Metadata returns a valid sealed file metadata.
func tte2Metadata(t *testing.T) string {
	t.Helper()
	key, _ := tte2.NewKey()
	m, err := tte2.SealMetadata(key, 0, tte2.Metadata{Index: 0, Count: 1, Name: "a.txt", Type: "text/plain", Size: 1, SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCheckSettings(t *testing.T) {
	t.Parallel()
	link := plan{duration: tenant.SecretDuration1d, delivery: store.SecretDeliveryLink}
	mail := plan{duration: tenant.SecretDuration1d, delivery: store.SecretDeliveryEmail}
	withSalt := mail
	withSalt.salt = make([]byte, 16)
	file := CreateRequest{File: &File{Size: 2 << 20}}
	big := CreateRequest{File: &File{Size: tenant.DefaultSecretFileBytes + 1}}
	internal := store.SecretCreatorInternal
	set := func(mutate func(*tenant.SecretSettings)) tenant.SecretSettings {
		s := tenant.DefaultSecretSettings()
		mutate(&s)
		return s
	}
	same := func(*tenant.SecretSettings) {}
	tests := []struct {
		name string
		set  tenant.SecretSettings
		kind store.SecretCreatorKind
		p    plan
		req  CreateRequest
		want error
	}{
		{"disabled", set(func(s *tenant.SecretSettings) { s.Enabled = false }), internal, link, CreateRequest{}, ErrDisabled},
		{"e-mail off", set(func(s *tenant.SecretSettings) { s.EmailAllowed = false }), internal, mail, CreateRequest{}, ErrEmailNotAllowed},
		{"passphrase required", set(func(s *tenant.SecretSettings) { s.EmailRequiresPassphrase = true }), internal, mail, CreateRequest{}, ErrPassphraseRequired},
		{"file off", set(func(s *tenant.SecretSettings) { s.FileAllowed = false }), internal, link, file, ErrFileNotAllowed},
	}
	for _, tt := range tests {
		if err := checkSettings(tt.set, tt.kind, tt.p, tt.req); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
	var d *DurationError
	if err := checkSettings(set(same), internal, plan{duration: tenant.SecretDuration30d, delivery: store.SecretDeliveryLink}, CreateRequest{}); !errors.As(err, &d) ||
		!slices.Equal(d.Allowed, []string{"1h", "1d", "7d"}) {
		t.Errorf("duration: %v", err)
	}
	var tooLarge *FileTooLargeError
	if err := checkSettings(set(same), internal, link, big); !errors.As(err, &tooLarge) || tooLarge.MaxBytes != tenant.DefaultSecretFileBytes {
		t.Errorf("file too large: %v", err)
	}
	for name, c := range map[string]struct {
		p   plan
		req CreateRequest
	}{
		"e-mail": {withSalt, CreateRequest{}},
		"file":   {link, file},
	} {
		if err := checkSettings(set(func(s *tenant.SecretSettings) { s.EmailRequiresPassphrase = true }), internal, c.p, c.req); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkSettings(set(same), internal, link, CreateRequest{}); err != nil {
		t.Errorf("link: %v", err)
	}
	// Through Create, a store refusal is mapped.
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	off := *testTenant
	off.Secrets.Enabled = false
	if _, err := e.svc.Create(context.Background(), &off, internalSender(), s.request()); !errors.Is(err, ErrDisabled) {
		t.Errorf("create disabled: %v", err)
	}
}

func TestCreateStoreErrors(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "the secret", "")
	var (
		limit    *LimitError
		duration *DurationError
		tooLarge *FileTooLargeError
	)
	tests := []struct {
		err   error
		check func(error) bool
	}{
		{store.ErrSecretOpenLimit, func(err error) bool { return errors.As(err, &limit) && limit.RetryAfter == 0 }},
		{store.ErrSecretDailyLimit, func(err error) bool { return errors.As(err, &limit) && limit.RetryAfter == DailyLimitRetryAfter }},
		{store.ErrSecretsDisabled, func(err error) bool { return errors.Is(err, ErrDisabled) }},
		{store.ErrSecretDurationNotOffered, func(err error) bool { return errors.As(err, &duration) && len(duration.Allowed) == 3 }},
		{store.ErrSecretEmailNotAllowed, func(err error) bool { return errors.Is(err, ErrEmailNotAllowed) }},
		{store.ErrSecretPassphraseRequired, func(err error) bool { return errors.Is(err, ErrPassphraseRequired) }},
		{store.ErrSecretFileNotAllowed, func(err error) bool { return errors.Is(err, ErrFileNotAllowed) }},
		{store.ErrSecretFileTooLarge, func(err error) bool {
			return errors.As(err, &tooLarge) && tooLarge.MaxBytes == tenant.DefaultSecretFileBytes
		}},
		{store.ErrSecretQuotaExceeded, func(err error) bool { return errors.Is(err, ErrQuotaExceeded) }},
		{store.ErrNotFound, func(err error) bool { return errors.Is(err, ErrForbidden) }},
		{errBoom, func(err error) bool { return errors.Is(err, errBoom) }},
	}
	for _, tt := range tests {
		e := newEnv(t)
		e.repo.createErr = tt.err
		_, err := e.svc.Create(context.Background(), testTenant, internalSender(), s.request())
		if !tt.check(err) {
			t.Errorf("store %v: got %v", tt.err, err)
		}
		if len(e.audit.events) != 0 {
			t.Errorf("store %v: audited %v", tt.err, e.audit.actions())
		}
	}
}

func TestErrorsText(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		&ValidationError{}, &FormatError{}, &DurationError{}, &FileTooLargeError{}, &LimitError{}, &RateLimitError{},
		&GoneError{Reason: ReasonRead}, &ProofError{},
	} {
		if !strings.HasPrefix(err.Error(), "secret: ") {
			t.Errorf("%T: %q", err, err.Error())
		}
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	salt := make([]byte, 16)
	e.repo.status = store.Secret{
		ID: "sec_1", State: store.SecretActive, ExpiresAt: testNow.Add(time.Hour), KDFSalt: salt, KDFIterations: 600000, FileSize: 4096,
	}
	st, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok")
	if err != nil {
		t.Fatal(err)
	}
	if !st.ExpiresAt.Equal(testNow.Add(time.Hour)) || st.FileSize != 4096 || st.Passphrase == nil ||
		*st.Passphrase != (Passphrase{KDF: tte2.PassphraseKDF, Iterations: 600000, Salt: "AAAAAAAAAAAAAAAAAAAAAA"}) {
		t.Errorf("status = %+v", st)
	}
	e.repo.status.KDFSalt = nil
	if st, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok"); err != nil || st.Passphrase != nil {
		t.Errorf("without passphrase: %+v, %v", st, err)
	}
	// Tombstones: the reason of each.
	for reason, want := range map[store.SecretEndReason]string{
		store.SecretEndRead: ReasonRead, store.SecretEndExpired: ReasonExpired, store.SecretEndLocked: ReasonLocked,
		store.SecretEndDeletedByCreator: ReasonDeleted, store.SecretEndDeletedByAdmin: ReasonDeleted,
	} {
		e.repo.status = store.Secret{State: store.SecretRead, EndReason: reason}
		var g *GoneError
		if _, err := e.svc.Status(ctx, testTenant, internalIP, "tts_tok"); !errors.As(err, &g) || g.Reason != want {
			t.Errorf("%s: %v, want gone %s", reason, err, want)
		}
	}
	// Unknown: logged and counted; pending: neither.
	e.repo.statusErr = store.ErrNotFound
	if _, err := e.svc.Status(ctx, testTenant, internalIP, "tts_x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	e.repo.statusErr = store.ErrSecretPending
	if _, err := e.svc.Status(ctx, testTenant, internalIP, "tts_x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("pending: %v", err)
	}
	if got := e.seclog.types(); !slices.Equal(got, []string{"secret_invalid"}) || e.failures.fails != 1 {
		t.Errorf("security log %v, failures %d", got, e.failures.fails)
	}
	if ev := e.seclog.events[0]; ev.IP != internalIP || ev.Tenant != testTenant.FQDN || ev.TenantID != string(testTenant.ID) {
		t.Errorf("event = %+v", ev)
	}
	e.repo.statusErr = errBoom
	if _, err := e.svc.Status(ctx, testTenant, internalIP, "tts_x"); !errors.Is(err, errBoom) {
		t.Errorf("store failure: %v", err)
	}
}

func TestLinkLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	var rl *RateLimitError
	e.requests.refuse = true
	if _, err := e.svc.Status(ctx, testTenant, internalIP, "tts_x"); !errors.As(err, &rl) || rl.RetryAfter != 3*time.Second {
		t.Errorf("rate: %v", err)
	}
	e.requests.refuse, e.failures.lock = false, true
	if _, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_x", "", ""); !errors.As(err, &rl) || rl.RetryAfter != time.Minute {
		t.Errorf("lockout: %v", err)
	}
	want := []string{"rate_limited scope=" + ScopeLinkIP, "rate_limited scope=" + ScopeLink}
	if got := e.seclog.types(); !slices.Equal(got, want) {
		t.Errorf("security log = %v, want %v", got, want)
	}
}

// TestDefaultLinkLimits checks the default limiters: the request rate,
// then the lockout after LinkFailureLimit unknown tokens.
func TestDefaultLinkLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{statusErr: store.ErrNotFound}
	seclog := &fakeSeclog{}
	now := testNow
	svc, err := New(Deps{
		Secrets: repo, Creators: &fakeCreators{}, Scrubber: &fakeScrubber{}, Files: &fakeFiles{}, SecurityLog: seclog,
		Directory: &fakeDirectory{}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
	}, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var rl *RateLimitError
	for i := range LinkFailureLimit {
		if _, err := svc.Status(ctx, testTenant, internalIP, "tts_x"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if _, err := svc.Status(ctx, testTenant, internalIP, "tts_x"); !errors.As(err, &rl) {
		t.Fatalf("after %d failures: %v", LinkFailureLimit, err)
	}
	other := netip.MustParseAddr("192.0.2.9")
	repo.statusErr = store.ErrSecretPending
	for range LinkRequestsPerMinute {
		if _, err := svc.Status(ctx, testTenant, other, "tts_x"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("pending: %v", err)
		}
	}
	if _, err := svc.Status(ctx, testTenant, other, "tts_x"); !errors.As(err, &rl) {
		t.Fatalf("over the rate: %v", err)
	}
}

func TestReveal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	e.repo.revealed = store.RevealedSecret{Secret: store.Secret{ID: "sec_1", State: store.SecretRead}, SealedText: s.text}
	out, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_tok", s.keyProof, s.proof)
	if err != nil {
		t.Fatal(err)
	}
	if out.EncryptedText != s.text || out.EncryptedMetadata != "" {
		t.Errorf("revealed = %+v", out)
	}
	if tte2.EncodeProof(e.repo.gotKey[:]) != s.keyProof || tte2.EncodeProof(e.repo.gotProof[:]) != s.proof {
		t.Error("proofs not passed to the store")
	}
	if e.scrubber.calls != 1 || !slices.Equal(e.audit.actions(), []audit.Action{audit.ActionSecretRevealed}) {
		t.Errorf("scrubs %d, audit %v", e.scrubber.calls, e.audit.actions())
	}
	if ev := e.audit.events[0]; ev.ActorKind != store.ActorRecipient || ev.Actor != linkActor || ev.ObjectID != "sec_1" || ev.Details != nil {
		t.Errorf("audit event = %+v", ev)
	}
	// Malformed proofs.
	if got := fieldsOf(t, mustErr(e.svc.Reveal(ctx, testTenant, internalIP, "tts_tok", "", strings.ToUpper(s.proof)))); !slices.Equal(got,
		[]string{"/keyProof required", "/proof invalid-format"}) {
		t.Errorf("fields = %v", got)
	}
}

func mustErr(_ Revealed, err error) error { return err }

func TestRevealErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := seal(t, "x", "")
	var (
		gone  *GoneError
		proof *ProofError
	)
	tests := []struct {
		name    string
		err     error
		check   func(error) bool
		seclog  []string
		fails   int
		actions []audit.Action
	}{
		{"unknown", store.ErrNotFound, func(err error) bool { return errors.Is(err, ErrNotFound) }, []string{"secret_invalid"}, 1, nil},
		{"pending", store.ErrSecretPending, func(err error) bool { return errors.Is(err, ErrNotFound) }, nil, 0, nil},
		{"gone", &store.SecretGoneError{Reason: store.SecretEndDeletedByAdmin}, func(err error) bool {
			return errors.As(err, &gone) && gone.Reason == ReasonDeleted
		}, nil, 0, nil},
		{"key", store.ErrSecretKeyProof, func(err error) bool { return errors.As(err, &proof) && !proof.Counted }, []string{"secret_proof_invalid reason=key"}, 1, nil},
		{"passphrase", &store.SecretProofError{ID: "sec_1", Remaining: 3}, func(err error) bool {
			return errors.As(err, &proof) && proof.Counted && proof.Remaining == 3
		}, []string{"secret_proof_invalid reason=passphrase"}, 1, nil},
		{"locked", &store.SecretProofError{ID: "sec_1", RemovedFile: "f1"}, func(err error) bool {
			return errors.As(err, &gone) && gone.Reason == ReasonLocked
		}, []string{"secret_proof_invalid reason=passphrase"}, 1, []audit.Action{audit.ActionSecretLocked}},
		{"store", errBoom, func(err error) bool { return errors.Is(err, errBoom) }, nil, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.repo.revealErr = tt.err
			_, err := e.svc.Reveal(ctx, testTenant, internalIP, "tts_tok", s.keyProof, s.proof)
			if !tt.check(err) {
				t.Fatalf("err = %v", err)
			}
			if got := e.seclog.types(); !slices.Equal(got, tt.seclog) && (len(got) != 0 || len(tt.seclog) != 0) {
				t.Errorf("security log = %v, want %v", got, tt.seclog)
			}
			if e.failures.fails != tt.fails {
				t.Errorf("failures = %d, want %d", e.failures.fails, tt.fails)
			}
			if got := e.audit.actions(); !slices.Equal(got, tt.actions) && (len(got) != 0 || len(tt.actions) != 0) {
				t.Errorf("audit = %v, want %v", got, tt.actions)
			}
			if tt.name == "locked" && (e.scrubber.calls != 1 || e.audit.events[0].ObjectID != "sec_1" ||
				!slices.Equal(e.files.removed, []string{"f1"})) {
				t.Errorf("locked: scrubs %d, event %+v, removed %v", e.scrubber.calls, e.audit.events[0], e.files.removed)
			}
		})
	}
}

func TestListMine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	e.repo.page = store.Page[store.Secret]{Items: []store.Secret{{ID: "sec_1"}}, NextCursor: "c2"}
	page, err := e.svc.ListMine(ctx, testTenant, alice, "c1", 7)
	if err != nil || len(page.Items) != 1 || page.NextCursor != "c2" || e.repo.gotOpts != (store.SecretListOptions{Cursor: "c1", Limit: 7}) {
		t.Errorf("page = %+v, %v, opts %+v", page, err, e.repo.gotOpts)
	}
	e.repo.listErr = store.ErrInvalid
	if _, err := e.svc.ListMine(ctx, testTenant, alice, "bad", 0); !slices.Equal(fieldsOf(t, err), []string{"cursor invalid-format"}) {
		t.Errorf("bad cursor: %v", err)
	}
	e.repo.listErr = errBoom
	if _, err := e.svc.ListMine(ctx, testTenant, alice, "", 0); !errors.Is(err, errBoom) {
		t.Errorf("store failure: %v", err)
	}
}

func TestDeleteMine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	e.repo.ended = store.EndedSecret{Secret: store.Secret{ID: "sec_1", SenderEmail: alice}}
	if err := e.svc.DeleteMine(ctx, testTenant, "Alice@entity-a.example.com", internalIP, "sec_1"); err != nil {
		t.Fatal(err)
	}
	if e.repo.gotActor != (store.SecretActor{Email: "Alice@entity-a.example.com"}) {
		t.Errorf("actor = %+v", e.repo.gotActor)
	}
	if len(e.files.removed) != 0 || e.scrubber.calls != 1 {
		t.Errorf("removed %v, scrubs %d", e.files.removed, e.scrubber.calls)
	}
	if ev := e.audit.events[0]; ev.Action != audit.ActionSecretDeleted || ev.ActorKind != store.ActorDepositor || ev.Actor != alice ||
		ev.ObjectKind != audit.ObjectSecret || ev.ObjectID != "sec_1" || ev.IP != internalIP {
		t.Errorf("audit event = %+v", ev)
	}
	for err, want := range map[error]error{
		&store.SecretGoneError{Reason: store.SecretEndRead}: nil,
		store.ErrNotFound: ErrNotFound,
		errBoom:           errBoom,
	} {
		e := newEnv(t)
		e.repo.deleteErr = err
		if got := e.svc.DeleteMine(ctx, testTenant, alice, internalIP, "sec_1"); !errors.Is(got, want) || (want == nil && got != nil) {
			t.Errorf("%v: got %v, want %v", err, got, want)
		}
		if len(e.audit.events) != 0 || e.scrubber.calls != 0 {
			t.Errorf("%v: audited or scrubbed", err)
		}
	}
}
