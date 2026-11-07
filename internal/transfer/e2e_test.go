package transfer

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// meta returns a canonical base64url value standing for an encrypted
// metadata or message (the server never decrypts them).
// meta returns a value with the framing of a sealed blob (version 1, a
// zero nonce, s and a zero tag): the server checks the framing, never the
// encryption, which it cannot open.
func meta(s string) string {
	b := append(append([]byte{1}, make([]byte, tte2.NonceSize)...), s...)
	return base64.RawURLEncoding.EncodeToString(append(b, make([]byte, tte2.TagSize)...))
}

// e2eRequest is an end-to-end encrypted request of two files (100 bytes
// and the smallest TTE2 stream) with an encrypted message.
func e2eRequest() CreateRequest {
	return CreateRequest{
		Recipients: []string{dave}, ExpiryDays: 7, EndToEndEncrypted: true, EncryptedMessage: meta("message"),
		Files: []FileDeclaration{
			{Name: "file-1.tte2", Size: 100, EncryptedMetadata: meta("metadata 1")},
			{Name: "file-2.tte2", Size: tte2.MinFileSize, EncryptedMetadata: meta("metadata 2")},
		},
	}
}

// setE2E sets the end-to-end encryption policy of tn in the database (the
// in-memory tn keeps its value: the service reads the current one).
func (ev *env) setE2E(t *testing.T, tn *tenant.Tenant, p tenant.E2EPolicy) {
	t.Helper()
	if _, err := ev.db.Tenants().SetE2EPolicy(context.Background(), tn.ID, p); err != nil {
		t.Fatal(err)
	}
}

func TestE2EFileName(t *testing.T) {
	t.Parallel()
	if got := E2EFileName(0); got != "file-1.tte2" {
		t.Errorf("E2EFileName(0) = %q", got)
	}
	if got := E2EFileName(41); got != "file-42.tte2" {
		t.Errorf("E2EFileName(41) = %q", got)
	}
}

func TestValidBase64URL(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"AA": true, meta("x"): true, "A": false, "AB": false, "a+b": false, "a/bc": false, "AA==": false,
		"AA\nAA": false, "AAAA\r": false, "": true,
	} {
		if got := validBase64URL(s); got != want {
			t.Errorf("validBase64URL(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestValidateE2E checks every rule of an end-to-end encrypted request,
// and the refusal of the encrypted members on a plain one.
func TestValidateE2E(t *testing.T) {
	t.Parallel()
	s := &Service{maxRecipients: 3}
	sender := internalSender()
	long := strings.Repeat("A", store.MaxE2EMetadataLen+1)
	longMsg := strings.Repeat("A", store.MaxE2EMessageLen+1)
	sum := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		edit func(r *CreateRequest)
		want []FieldError
	}{
		{"valid", func(*CreateRequest) {}, nil},
		{"without message", func(r *CreateRequest) { r.EncryptedMessage = "" }, nil},
		{"password and ciphertext hash", func(r *CreateRequest) {
			pw := "pw"
			r.Password, r.Files[0].ExpectedSHA256 = &pw, strings.ToUpper(sum)
		}, nil},
		{
			"metadata missing", func(r *CreateRequest) { r.Files[1].EncryptedMetadata = "" },
			[]FieldError{{Pointer: "/files/1/encryptedMetadata", Code: CodeRequired}},
		},
		{
			"metadata too long", func(r *CreateRequest) { r.Files[0].EncryptedMetadata = long },
			[]FieldError{{Pointer: "/files/0/encryptedMetadata", Code: CodeTooLong}},
		},
		{
			"metadata alphabet", func(r *CreateRequest) { r.Files[0].EncryptedMetadata = "ab+c" },
			[]FieldError{{Pointer: "/files/0/encryptedMetadata", Code: CodeInvalidFormat}},
		},
		{
			"metadata not canonical", func(r *CreateRequest) { r.Files[0].EncryptedMetadata = "AB" },
			[]FieldError{{Pointer: "/files/0/encryptedMetadata", Code: CodeInvalidFormat}},
		},
		{
			"real name", func(r *CreateRequest) { r.Files[0].Name = "plans.pdf" },
			[]FieldError{{Pointer: "/files/0/name", Code: CodeNotAllowed}},
		},
		{
			"names out of order", func(r *CreateRequest) { r.Files[0].Name, r.Files[1].Name = "file-2.tte2", "file-1.tte2" },
			[]FieldError{{Pointer: "/files/0/name", Code: CodeNotAllowed}, {Pointer: "/files/1/name", Code: CodeNotAllowed}},
		},
		{
			"path", func(r *CreateRequest) { r.Files[1].Path = "docs" },
			[]FieldError{{Pointer: "/files/1/path", Code: CodeNotAllowed}},
		},
		{
			"media type", func(r *CreateRequest) { r.Files[0].MediaType = "application/pdf" },
			[]FieldError{{Pointer: "/files/0/mediaType", Code: CodeNotAllowed}},
		},
		{
			"below the smallest stream", func(r *CreateRequest) { r.Files[1].Size = tte2.MinFileSize - 1 },
			[]FieldError{{Pointer: "/files/1/size", Code: CodeInvalidFormat}},
		},
		{
			"empty file", func(r *CreateRequest) { r.Files[1].Size = 0 },
			[]FieldError{{Pointer: "/files/1/size", Code: CodeInvalidFormat}},
		},
		{
			"negative size", func(r *CreateRequest) { r.Files[1].Size = -1 },
			[]FieldError{{Pointer: "/files/1/size", Code: CodeInvalidFormat}},
		},
		{
			"bad ciphertext hash", func(r *CreateRequest) { r.Files[0].ExpectedSHA256 = "abc" },
			[]FieldError{{Pointer: "/files/0/expectedSha256", Code: CodeInvalidFormat}},
		},
		{
			"plaintext message", func(r *CreateRequest) { r.Message = "hello" },
			[]FieldError{{Pointer: FieldMessage, Code: CodeNotAllowed}},
		},
		{
			"blank plaintext message", func(r *CreateRequest) { r.Message = " " },
			[]FieldError{{Pointer: FieldMessage, Code: CodeNotAllowed}},
		},
		{
			"metadata not a sealed blob", func(r *CreateRequest) {
				r.Files[0].EncryptedMetadata = base64.RawURLEncoding.EncodeToString(make([]byte, 40)) // version 0
			},
			[]FieldError{{Pointer: "/files/0/encryptedMetadata", Code: CodeInvalidFormat}},
		},
		{
			"message too short for a sealed blob", func(r *CreateRequest) { r.EncryptedMessage = "AQID" },
			[]FieldError{{Pointer: FieldEncryptedMessage, Code: CodeInvalidFormat}},
		},
		{
			"message too long", func(r *CreateRequest) { r.EncryptedMessage = longMsg },
			[]FieldError{{Pointer: FieldEncryptedMessage, Code: CodeTooLong}},
		},
		{
			"message alphabet", func(r *CreateRequest) { r.EncryptedMessage = "a b" },
			[]FieldError{{Pointer: FieldEncryptedMessage, Code: CodeInvalidFormat}},
		},
		{"every file field", func(r *CreateRequest) {
			r.Files[0] = FileDeclaration{Name: "x", Path: "a", Size: 1, MediaType: "text/plain", ExpectedSHA256: "z"}
		}, []FieldError{
			{Pointer: "/files/0/name", Code: CodeNotAllowed},
			{Pointer: "/files/0/path", Code: CodeNotAllowed},
			{Pointer: "/files/0/size", Code: CodeInvalidFormat},
			{Pointer: "/files/0/mediaType", Code: CodeNotAllowed},
			{Pointer: "/files/0/expectedSha256", Code: CodeInvalidFormat},
			{Pointer: "/files/0/encryptedMetadata", Code: CodeRequired},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := e2eRequest()
			tc.edit(&req)
			p, err := s.validate(req, sender, "")
			if tc.want == nil {
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				if p.message != "" || p.e2eMessage != req.EncryptedMessage || len(p.files) != 2 {
					t.Fatalf("plan = %+v", p)
				}
				for i, f := range p.files {
					if f.Name != E2EFileName(i) || f.E2EMetadata != req.Files[i].EncryptedMetadata || f.Path != "" || f.MediaType != "" {
						t.Errorf("file %d = %+v", i, f)
					}
				}
				if p.files[0].ExpectedSHA256 != strings.ToLower(req.Files[0].ExpectedSHA256) {
					t.Errorf("expected sha256 = %q", p.files[0].ExpectedSHA256)
				}
				return
			}
			wantFields(t, err, tc.want)
		})
	}
	// On a plain request, the encrypted members are refused.
	plain := request()
	plain.EncryptedMessage = meta("m")
	plain.Files[1].EncryptedMetadata = meta("x")
	_, err := s.validate(plain, sender, "")
	wantFields(t, err, []FieldError{
		{Pointer: FieldEncryptedMessage, Code: CodeNotAllowed}, {Pointer: "/files/1/encryptedMetadata", Code: CodeNotAllowed},
	})
	// A plain request keeps its names and message; nothing is encrypted.
	p, err := s.validate(request(), sender, "")
	if err != nil || p.e2eMessage != "" || p.files[0].E2EMetadata != "" || p.files[0].Name != "plans.pdf" {
		t.Errorf("plain plan = %+v, %v", p, err)
	}
}

// TestFingerprintE2E checks that the end-to-end members change the
// fingerprint, and that a plain request keeps the one it had.
func TestFingerprintE2E(t *testing.T) {
	t.Parallel()
	s := &Service{maxRecipients: 3}
	fp := func(req CreateRequest) string {
		t.Helper()
		p, err := s.validate(req, internalSender(), "")
		if err != nil {
			t.Fatal(err)
		}
		return fingerprint(p, req)
	}
	base := fp(e2eRequest())
	if fp(e2eRequest()) != base {
		t.Error("fingerprint not stable")
	}
	msg := e2eRequest()
	msg.EncryptedMessage = meta("other")
	noMsg := e2eRequest()
	noMsg.EncryptedMessage = ""
	md := e2eRequest()
	md.Files[1].EncryptedMetadata = meta("other")
	for name, req := range map[string]CreateRequest{"message": msg, "no message": noMsg, "metadata": md} {
		if fp(req) == base {
			t.Errorf("%s: same fingerprint", name)
		}
	}
	// The plain form of the same files differs by the flag alone.
	plain := e2eRequest()
	plain.EndToEndEncrypted, plain.EncryptedMessage = false, ""
	for i := range plain.Files {
		plain.Files[i].EncryptedMetadata = ""
	}
	if fp(plain) == base {
		t.Error("plain request with the same fingerprint")
	}
}

// TestCreateE2E creates an end-to-end encrypted transfer: stored with its
// flag, encrypted message and metadata, shown to the sender, audited with
// endToEndEncrypted; a password is accepted, a level that requires one
// still requires it, and the idempotency key covers the encrypted members.
func TestCreateE2E(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		ev.withHooks(spy)

		// Forbidden by default.
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), e2eRequest(), ""); !errors.Is(err, ErrE2EForbidden) {
			t.Fatalf("default policy: %v", err)
		}
		ev.setE2E(t, ev.a, tenant.E2EAllowed)
		req := e2eRequest()
		pw := "secret"
		req.Password = &pw
		d := ev.mustCreate(t, internalSender(), req)
		if !d.E2E || d.EncryptedMessage != req.EncryptedMessage || d.Message != "" || !d.PasswordProtected || len(d.Files) != 2 {
			t.Fatalf("details = %+v", d)
		}
		for i, f := range d.Files {
			if f.Name != E2EFileName(i) || f.EncryptedMetadata != req.Files[i].EncryptedMetadata {
				t.Errorf("file %d = %+v", i, f)
			}
		}
		got, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || !got.E2E || got.E2EMessage != req.EncryptedMessage || got.Message != "" ||
			got.Files[1].E2EMetadata != req.Files[1].EncryptedMetadata {
			t.Fatalf("stored = %+v, %v", got.Transfer, err)
		}
		events, _, errs := spy.snapshot()
		if len(errs) != 0 || len(events) != 1 || events[0].Details["endToEndEncrypted"] != true {
			t.Errorf("audit = %+v %v", events, errs)
		}
		// A plain transfer has no flag in its event.
		plain := ev.mustCreate(t, internalSender(), request())
		if plain.E2E || plain.EncryptedMessage != "" || plain.Files[0].EncryptedMetadata != "" {
			t.Errorf("plain details = %+v", plain)
		}
		events, _, _ = spy.snapshot()
		if _, ok := events[1].Details["endToEndEncrypted"]; ok {
			t.Errorf("plain audit = %+v", events[1])
		}
		// Validation errors come before the policy.
		bad := e2eRequest()
		bad.Message = "plain"
		_, err = ev.svc.Create(ctx, ev.a, internalSender(), bad, "")
		wantFields(t, err, []FieldError{{Pointer: FieldMessage, Code: CodeNotAllowed}})

		// The idempotency key covers the encrypted members.
		first, err := ev.svc.Create(ctx, ev.a, internalSender(), e2eRequest(), "e2e-key")
		if err != nil {
			t.Fatal(err)
		}
		again, err := ev.svc.Create(ctx, ev.a, internalSender(), e2eRequest(), "e2e-key")
		if err != nil || again.ID != first.ID {
			t.Errorf("replay = %v, %v", again.ID, err)
		}
		other := e2eRequest()
		other.Files[0].EncryptedMetadata = meta("other")
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), other, "e2e-key"); !errors.Is(err, ErrIdempotencyMismatch) {
			t.Errorf("other metadata: %v", err)
		}

		// A level that requires a password requires it for an encrypted
		// transfer too (the key in the link does not replace it).
		ev.setLevels(t, ev.a, strictLevels())
		secret := e2eRequest()
		secret.ConfidentialityLevel, secret.ExpiryDays, secret.Recipients = "secret", 1, []string{carol}
		_, err = ev.svc.Create(ctx, ev.a, internalSender(), secret, "")
		if f := ruleFields(t, err, ErrConfidentialityRule); !reflect.DeepEqual(f, []FieldError{{Pointer: FieldPassword, Code: CodeRequired}}) {
			t.Errorf("secret without password: %+v", f)
		}
		secret.Password = &pw
		if d := ev.mustCreate(t, internalSender(), secret); !d.E2E || !d.DeleteAfterFirstDownload {
			t.Errorf("secret with password = %+v", d)
		}
		// Tenant B keeps its own (default) policy.
		if _, err := ev.svc.Create(ctx, ev.b, internalSender(), e2eRequest(), ""); !errors.Is(err, ErrE2EForbidden) {
			t.Errorf("tenant B: %v", err)
		}
	})
}

// TestCreateE2EPolicyMatrix crosses the tenant policy, the level policy
// and the request: the tenant decides when it forbids or requires, the
// level when the tenant allows.
func TestCreateE2EPolicyMatrix(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		pol := func(p tenant.E2EPolicy) *tenant.E2EPolicy { return &p }
		levelPolicies := []*tenant.E2EPolicy{nil, pol(tenant.E2EForbidden), pol(tenant.E2EAllowed), pol(tenant.E2ERequired)}
		for _, tp := range []tenant.E2EPolicy{tenant.E2EForbidden, tenant.E2EAllowed, tenant.E2ERequired} {
			ev.setE2E(t, ev.a, tp)
			for _, lp := range levelPolicies {
				levels := strictLevels()
				levels[0].E2EPolicy = lp
				ev.setLevels(t, ev.a, levels)
				effective := tp
				if tp == tenant.E2EAllowed && lp != nil {
					effective = *lp
				}
				for _, encrypted := range []bool{false, true} {
					req := request()
					if encrypted {
						req = e2eRequest()
					}
					_, err := ev.svc.Create(ctx, ev.a, internalSender(), req, "")
					var want error
					switch {
					case effective == tenant.E2EForbidden && encrypted:
						want = ErrE2EForbidden
					case effective == tenant.E2ERequired && !encrypted:
						want = ErrE2ERequired
					}
					if (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
						t.Errorf("tenant %s, level %v, encrypted %v: err = %v, want %v", tp, lp, encrypted, err, want)
					}
				}
			}
		}
	})
}

// TestCreateE2EDepositors lets every depositor encrypt except a drop link
// one, refused whatever the policy, and unable to deposit at a level that
// requires encryption.
func TestCreateE2EDepositors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, orig := replyEnv(t, e)
		ev.a.AllowTransferReply = true // kept by the update below
		ev.allowRemote(t, ev.a, true)
		ev.verify(t, ev.a, alice, true)
		ev.setLevels(t, ev.a, strictLevels())
		tok := ev.newToken(t, ev.a)
		l := ev.dropLink(t, ev.a)
		ev.setE2E(t, ev.a, tenant.E2EAllowed)

		tokenReq := e2eRequest()
		tokenReq.SenderEmail = carol
		for name, tc := range map[string]struct {
			sender Sender
			req    CreateRequest
		}{
			"internal":  {internalSender(), e2eRequest()},
			"remote":    {remoteSender(), e2eRequest()},
			"api token": {tokenSender(tok), tokenReq},
			"external":  {ev.external(), e2eRequest()},
			"reply":     {replySender(dave, orig), e2eRequest()},
		} {
			d, err := ev.svc.Create(ctx, ev.a, tc.sender, tc.req, "")
			if err != nil || !d.E2E {
				t.Errorf("%s: %+v, %v", name, d, err)
			}
		}
		dropE2E := e2eRequest()
		dropE2E.Recipients = nil
		for _, p := range []tenant.E2EPolicy{tenant.E2EForbidden, tenant.E2EAllowed, tenant.E2ERequired} {
			ev.setE2E(t, ev.a, p)
			if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropE2E, ""); !errors.Is(err, ErrE2EForbidden) {
				t.Errorf("drop link, policy %s: %v", p, err)
			}
		}
		// Required: a drop link depositor cannot deposit at all.
		if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropRequest(), ""); !errors.Is(err, ErrE2ERequired) {
			t.Errorf("drop link, required, plain: %v", err)
		}
		ev.setE2E(t, ev.a, tenant.E2EAllowed)
		if _, err := ev.svc.Create(ctx, ev.a, ev.dropSender(t, l), dropRequest(), ""); err != nil {
			t.Errorf("drop link, allowed, plain: %v", err)
		}
	})
}

// TestCreateE2ETenantRead covers the tenant read of the policies.
func TestCreateE2ETenantRead(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.setE2E(t, ev.a, tenant.E2EAllowed)
	f := ev.faults()
	// The first read is the policies' one (an internal sender reads no
	// tenant for its eligibility).
	f.fail["tenant"] = errFault
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), e2eRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("tenant read: %v", err)
	}
	f.fail["tenant"] = store.ErrNotFound
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), e2eRequest(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("tenant gone: %v", err)
	}
	// The second read is the one of the limits.
	f.fail["tenant"], f.skip["tenant"] = errFault, 1
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), e2eRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("limits read: %v", err)
	}
}

// e2eUploaded creates an end-to-end encrypted transfer of A and completes
// its uploads with sum.
func (ev *env) e2eUploaded(t *testing.T, sum string) Details {
	t.Helper()
	d := ev.mustCreate(t, internalSender(), e2eRequest())
	ev.complete(t, d.ID, sum)
	return d
}

// TestFinalizeE2E finalizes an end-to-end encrypted transfer: its files get
// not_scanned_e2e whatever the antivirus switch, each audited with reason
// e2e, the worker is told so that it concludes the transfer, and the
// blocklist of file hashes does not apply.
func TestFinalizeE2E(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.setE2E(t, ev.a, tenant.E2EAllowed)
		for _, tc := range []struct {
			name         string
			tenantSwitch bool
			engineNone   bool
		}{{"antivirus effective", true, false}, {"tenant switch off", false, false}, {"engine none", true, true}} {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				spy := &auditSpy{writer: audit.New(ev.db)}
				ev.withHooks(spy)
				ev.svc.avDisabled = tc.engineNone
				tn, err := ev.db.Tenants().SetAntivirusEnabled(ctx, ev.a.ID, tc.tenantSwitch)
				if err != nil {
					t.Fatal(err)
				}
				d := ev.e2eUploaded(t, "")
				got, err := ev.svc.Finalize(ctx, tn, internalSender(), d.ID)
				if err != nil {
					t.Fatalf("Finalize: %v", err)
				}
				if got.Status != store.TransferScanning || !got.E2E {
					t.Fatalf("finalized = %+v", got)
				}
				for _, f := range got.Files {
					if f.ScanStatus != store.ScanNotScannedE2E {
						t.Errorf("file %s status %q", f.ID, f.ScanStatus)
					}
				}
				ev.mu.Lock()
				told := slices.Contains(ev.finalized, string(ev.a.ID)+"/"+d.ID)
				ev.mu.Unlock()
				if !told {
					t.Error("the worker was not told to conclude the transfer")
				}
				events, _, errs := spy.snapshot()
				var reasons []any
				for _, ev := range events {
					if ev.Action == audit.ActionFileNotScanned {
						reasons = append(reasons, ev.Details["reason"])
					}
				}
				if len(errs) != 0 || !reflect.DeepEqual(reasons, []any{audit.NotScannedE2E, audit.NotScannedE2E}) {
					t.Errorf("not scanned reasons %v (errors %v)", reasons, errs)
				}
			})
		}
		ev.svc.avDisabled = false
		if _, err := ev.db.Tenants().SetAntivirusEnabled(ctx, ev.a.ID, true); err != nil {
			t.Fatal(err)
		}

		// The hash of a ciphertext is not checked against the blocklist.
		sum := strings.Repeat("cd", 32)
		ev.block(t, ev.a, store.BlockSHA256, sum)
		d := ev.e2eUploaded(t, sum)
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); err != nil {
			t.Errorf("E2E with a blocked hash: %v", err)
		}
		plain := ev.mustCreate(t, internalSender(), request())
		ev.complete(t, plain.ID, sum)
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), plain.ID); !errors.Is(err, ErrBlockedFile) {
			t.Errorf("plain with a blocked hash: %v", err)
		}
		// The address blocklist still applies.
		ev.block(t, ev.a, store.BlockEmail, alice)
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), e2eRequest(), ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("blocked sender: %v", err)
		}
	})
}

// TestFinalizeE2EFault covers a failing E2E finalization: nothing changes.
func TestFinalizeE2EFault(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.setE2E(t, ev.a, tenant.E2EAllowed)
	d := ev.e2eUploaded(t, "")
	f := ev.faults()
	f.fail["finalizeE2E"] = errFault
	if _, err := ev.svc.Finalize(context.Background(), ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
		t.Fatalf("Finalize: %v", err)
	}
	got, err := ev.db.Transfers().Get(context.Background(), ev.a.ID, d.ID)
	if err != nil || got.Status != store.TransferUploading || got.Files[0].ScanStatus != store.ScanPending {
		t.Errorf("after the fault: %+v, %v", got.Transfer, err)
	}
}
