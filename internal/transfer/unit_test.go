package transfer

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/filename"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	s := New(nil, nil, nil, nil, Options{MaxRecipients: 1000})
	if s.maxRecipients != store.MaxTransferRecipients || s.maxOpen != DefaultMaxOpenTransfers ||
		s.uploadMaxAge != upload.DefaultMaxAge || s.logger == nil {
		t.Errorf("service = %+v", s)
	}
	if _, ok := s.hasher.(*crypto.PasswordHasher); !ok {
		t.Errorf("hasher = %T", s.hasher)
	}
	if s.now().IsZero() || s.now().Location() != time.UTC {
		t.Error("clock not set")
	}
	s.onFinalized(tenant.ID("ten_x"), "trf_x") // the default does nothing
	if s = New(nil, nil, nil, nil, Options{}); s.maxRecipients != DefaultMaxRecipients {
		t.Errorf("max recipients = %d", s.maxRecipients)
	}
}

// TestDuplicatedConstants checks the limits that several packages declare
// separately (the store cannot import the packages that own them).
func TestDuplicatedConstants(t *testing.T) {
	t.Parallel()
	ttl, err := time.ParseDuration(config.DefaultUploadTTL)
	if err != nil {
		t.Fatal(err)
	}
	maxAge, err := time.ParseDuration(config.DefaultUploadMaxAge)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"storage.NameLen", storage.NameLen, store.StorageNameLen},
		{"filename.MaxBytes", filename.MaxBytes, store.MaxFileNameBytes},
		{"upload.DefaultUploadTTL", upload.DefaultUploadTTL, ttl},
		{"upload.DefaultMaxAge", upload.DefaultMaxAge, maxAge},
		{"config.DefaultMaxRecipients", config.DefaultMaxRecipients, strconv.Itoa(DefaultMaxRecipients)},
		{"config.DefaultMaxOpenTransfers", config.DefaultMaxOpenTransfers, strconv.Itoa(DefaultMaxOpenTransfers)},
		{"password bytes", MaxPasswordRunes*4 <= crypto.MaxPasswordSize, true},
		{"tenant limit fits", tenant.MaxTransferLimit > 0, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestDefaultHasher creates a password-protected transfer with the real
// argon2id hasher once.
func TestDefaultHasher(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.svc.hasher = New(nil, nil, nil, nil, Options{}).hasher
	pw := "correct horse"
	req := request()
	req.Password = &pw
	d := ev.mustCreate(t, internalSender(), req)
	stored, err := ev.db.Transfers().Get(context.Background(), ev.a.ID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := crypto.VerifyPassword(stored.PasswordHash, []byte(pw)); !ok || err != nil {
		t.Errorf("VerifyPassword = %v, %v", ok, err)
	}
}

func TestErrorTypes(t *testing.T) {
	t.Parallel()
	verr := &ValidationError{Fields: []FieldError{{FieldMessage, CodeTooLong}, {"/files/0/name", CodeInvalidFileName}}}
	if got := verr.Error(); got != "transfer: invalid request: /message (too-long), /files/0/name (invalid-file-name)" {
		t.Errorf("ValidationError = %q", got)
	}
	tl := &TooLargeError{MaxTransferBytes: 42}
	if !strings.Contains(tl.Error(), "42") || !errors.Is(tl, ErrTooLarge) || errors.Is(tl, ErrInvalid) {
		t.Errorf("TooLargeError = %q", tl.Error())
	}
	fe := &FilesError{Kind: ErrIncomplete, FileIDs: []string{"a", "b"}}
	if fe.Error() != "transfer: upload incomplete: 2 file(s)" || !errors.Is(fe, ErrIncomplete) || errors.Is(fe, ErrChecksumMismatch) {
		t.Errorf("FilesError = %q", fe.Error())
	}
	rl := &RateLimitError{RetryAfter: time.Hour}
	if !strings.Contains(rl.Error(), "1h0m0s") || !errors.Is(rl, ErrRateLimited) || errors.Is(rl, ErrConflict) {
		t.Errorf("RateLimitError = %q", rl.Error())
	}
	if errors.Is(verr, ErrTooLarge) {
		t.Error("ValidationError matches ErrTooLarge")
	}
	if !errors.Is(ErrIdempotencyMismatch, ErrConflict) || !errors.Is(ErrBusy, ErrConflict) {
		t.Error("ErrIdempotencyMismatch and ErrBusy must match ErrConflict")
	}
}

func TestStoreError(t *testing.T) {
	t.Parallel()
	cases := map[error]error{
		store.ErrNotFound: ErrNotFound, store.ErrConflict: ErrConflict, errFault: errFault,
	}
	for in, want := range cases {
		if got := storeError("op", in); !errors.Is(got, want) {
			t.Errorf("storeError(%v) = %v", in, got)
		}
	}
}

func TestStoreRepoInvalidTenant(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	err := ev.svc.repo.tx(context.Background(), tenant.ID("ten_bad"), func(txRepo) error { return nil })
	if !errors.Is(err, store.ErrInvalid) {
		t.Errorf("err = %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	t.Parallel()
	pw := "secret"
	base := plan{
		recipients: []string{"b@x.example.com", "a@x.example.com"}, message: "m",
		files: []store.TransferFile{{Name: "f", Size: 1, MediaType: "t", ExpectedSHA256: "h"}},
	}
	req := CreateRequest{ExpiryDays: 7}
	want := fingerprint(base, req)
	if len(want) != 64 || strings.Trim(want, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint = %q", want)
	}
	// The order of the recipients and the password value do not matter.
	same := base
	same.recipients = []string{"a@x.example.com", "b@x.example.com"}
	if fingerprint(same, req) != want {
		t.Error("recipient order changes the fingerprint")
	}
	withPw, otherPw := base, base
	withPw.password, otherPw.password = []byte(pw), []byte("other")
	if fingerprint(withPw, req) != fingerprint(otherPw, req) || fingerprint(withPw, req) == want {
		t.Error("the presence of a password must count, not its value")
	}
	changes := []func(p *plan, r *CreateRequest){
		func(p *plan, _ *CreateRequest) { p.message = "n" },
		func(_ *plan, r *CreateRequest) { r.ExpiryDays = 1 },
		func(_ *plan, r *CreateRequest) { r.DeleteAfterFirstDownload = true },
		func(_ *plan, r *CreateRequest) { r.Language = "fr" },
		func(p *plan, _ *CreateRequest) { p.recipients = []string{"a@x.example.com"} },
		func(p *plan, _ *CreateRequest) {
			p.files = []store.TransferFile{{Name: "f", Size: 2, MediaType: "t", ExpectedSHA256: "h"}}
		},
	}
	for i, change := range changes {
		p, r := base, req
		change(&p, &r)
		if fingerprint(p, r) == want {
			t.Errorf("change %d does not change the fingerprint", i)
		}
	}
}

// The upload engine and the vault implement the interfaces of the service.
var (
	_ Uploads  = (*upload.Engine)(nil)
	_ DataKeys = (*masterkey.Vault)(nil)
)
