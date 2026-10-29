package download

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/vcode"
)

// notFoundRepo knows no download token; any other method panics (the nil
// embedded repo), which would reveal a lookup past the token checks.
type notFoundRepo struct{ repo }

func (notFoundRepo) linkByToken(context.Context, tenant.ID, []byte) (store.RecipientLink, error) {
	return store.RecipientLink{}, store.ErrNotFound
}

func (notFoundRepo) byToken(context.Context, tenant.ID, []byte) (store.TransferDetails, error) {
	return store.TransferDetails{}, store.ErrNotFound
}

// fuzzService returns a service over a real keyring and notFoundRepo.
func fuzzService(f *testing.F) *Service {
	kr, err := masterkey.New(masterkeytest.Key(f, "download-fuzz"), nil)
	if err != nil {
		f.Fatal(err)
	}
	return &Service{repo: notFoundRepo{}, keys: kr, clock: time.Now}
}

// FuzzVerificationCookie checks that any verification cookie value parses
// without panic into at most GrantMaxEntries entries that round-trip, and
// that a forged value never verifies a link.
func FuzzVerificationCookie(f *testing.F) {
	s := fuzzService(f)
	tid, link := tenant.ID("ten_01JA0000000000000000000000"), "rcl_01JA0000000000000000000000"
	// A fixed clock, so that every fuzzing process mints the same entry.
	now := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
	valid, err := s.add(verificationSpec, "", tid, link, now)
	if err != nil {
		f.Fatal(err)
	}
	entry := grantEncoding.EncodeToString(bytes.Repeat([]byte{7}, grantRawLen))
	for _, seed := range []string{
		"", VerificationCookiePrefix, valid, valid + "." + entry, VerificationCookiePrefix + entry,
		GrantCookiePrefix + strings.TrimPrefix(valid, VerificationCookiePrefix), "rv_*.**",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		entries := parseVerifications(raw)
		if len(entries) > GrantMaxEntries {
			t.Fatalf("%d entries", len(entries))
		}
		parts := make([]string, 0, len(entries))
		for _, e := range entries {
			parts = append(parts, grantEncoding.EncodeToString(e))
		}
		if len(entries) > 0 {
			again := parseVerifications(VerificationCookiePrefix + strings.Join(parts, grantSep))
			if !slices.EqualFunc(again, entries, bytes.Equal) {
				t.Fatalf("round trip %x, want %x", again, entries)
			}
		}
		ok, err := s.holds(verificationSpec, raw, tid, link, now)
		if err != nil {
			t.Fatal(err)
		}
		if ok && !strings.Contains(raw, strings.TrimPrefix(valid, VerificationCookiePrefix)) {
			t.Fatalf("forged cookie %q verifies", raw)
		}
		// Never for another link or tenant.
		if ok, _ := s.holds(verificationSpec, raw, tid, "rcl_01JB0000000000000000000000", now); ok {
			t.Fatal("entry valid for another link")
		}
		if ok, _ := s.holds(verificationSpec, raw, "ten_01JB0000000000000000000000", link, now); ok {
			t.Fatal("entry valid for another tenant")
		}
	})
}

// FuzzVerificationInputs checks the input checks of the verification
// operations on any token, code and cookie: a malformed code is
// ErrInvalidCode before anything else, and an unknown token is ErrNotFound
// for every operation, without any other lookup.
func FuzzVerificationInputs(f *testing.F) {
	s := fuzzService(f)
	tn := &tenant.Tenant{ID: "ten_01JA0000000000000000000000", FQDN: hostA, DefaultLanguage: "en"}
	for _, seed := range [][3]string{
		{"dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf", "123456", ""},
		{"dl_", "12345", "rv_"},
		{"", "١٢٣٤٥٦", "rv_x.y"},
		{"dl_" + strings.Repeat("a", 43), "000000", strings.Repeat("rv_", 400)},
		{"rcl_01JA0000000000000000000000", " 12345", "\x00"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, token, code, cookie string) {
		ctx := context.Background()
		_, err := s.ConfirmVerification(ctx, tn, token, ipOne, code, cookie)
		validCode := len(code) == vcode.Digits && strings.Trim(code, "0123456789") == ""
		switch {
		case !validCode && !errors.Is(err, ErrInvalidCode):
			t.Fatalf("code %q: %v", code, err)
		case validCode && !errors.Is(err, ErrNotFound):
			t.Fatalf("token %q, code %q: %v", token, code, err)
		}
		if _, err := s.StartVerification(ctx, tn, token, ipOne, false, cookie, cookie); !errors.Is(err, ErrNotFound) {
			t.Fatalf("start %q: %v", token, err)
		}
		if _, err := s.Resolve(ctx, tn, token, Cookies{Grant: cookie, Verification: cookie}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("resolve %q: %v", token, err)
		}
		if !utf8.ValidString(code) && validCode {
			t.Fatal("a code that is not UTF-8 passed")
		}
	})
}

// FuzzMaskEmail checks that a masked address keeps the domain and at most
// the first character of the local part.
func FuzzMaskEmail(f *testing.F) {
	for _, seed := range []string{"carol@customer.example.net", "@x", "x", "élodie@example.com", "\xff@x", "a@b@c"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, addr string) {
		got := MaskEmail(addr)
		local, domain, ok := strings.Cut(addr, "@")
		switch {
		case !ok && got != maskedLocal:
			t.Fatalf("MaskEmail(%q) = %q", addr, got)
		case ok && !strings.HasSuffix(got, maskedLocal+"@"+domain):
			t.Fatalf("MaskEmail(%q) = %q", addr, got)
		case ok && len(got)-len(maskedLocal+"@"+domain) > utf8.UTFMax:
			t.Fatalf("MaskEmail(%q) = %q keeps more than one character", addr, got)
		case ok:
			r, size := utf8.DecodeRuneInString(local)
			if want := maskedLocal + "@" + domain; got != want && (size == 0 || got != local[:size]+want || r == utf8.RuneError) {
				t.Fatalf("MaskEmail(%q) = %q keeps more than the first character", addr, got)
			}
		}
	})
}
