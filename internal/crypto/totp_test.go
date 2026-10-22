package crypto

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the HMAC-SHA1 seed of RFC 4226 Appendix D and RFC 6238
// Appendix B.
var rfcSecret = []byte(vectorTOTPSecret)

func TestTOTPCodeRFC4226(t *testing.T) {
	t.Parallel()
	// RFC 4226 Appendix D: HOTP values for counters 0 to 9.
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for c, w := range want {
		if got := TOTPCode(rfcSecret, uint64(c)); got != w {
			t.Errorf("HOTP(%d) = %s, want %s", c, got, w)
		}
	}
}

func TestTOTPRFC6238(t *testing.T) {
	t.Parallel()
	for _, v := range rfc6238SHA1 {
		now := time.Unix(v.Time, 0)
		if got := TOTPCode(rfcSecret, TOTPCounter(now)); got != v.Code {
			t.Errorf("TOTP at %d = %s, want %s", v.Time, got, v.Code)
		}
		c, ok := VerifyTOTP(rfcSecret, v.Code, now, 0, false)
		if !ok || c != uint64(v.Time)/TOTPPeriod {
			t.Errorf("VerifyTOTP at %d = %d, %v", v.Time, c, ok)
		}
	}
}

func TestTOTPCounter(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		sec  int64
		want uint64
	}{{0, 0}, {29, 0}, {30, 1}, {59, 1}, {60, 2}, {1111111109, 37037036}, {-1, 0}, {-1 << 40, 0}} {
		if got := TOTPCounter(time.Unix(tc.sec, 0)); got != tc.want {
			t.Errorf("TOTPCounter(%d) = %d, want %d", tc.sec, got, tc.want)
		}
	}
	// Sub-second precision and time zones do not matter.
	at := time.Date(2026, 1, 1, 0, 0, 29, 999_999_999, time.FixedZone("x", 3600))
	if TOTPCounter(at) != uint64(at.Unix())/30 {
		t.Fatal("counter depends on more than the Unix second")
	}
}

func TestGenerateTOTPSecret(t *testing.T) {
	a, err := GenerateTOTPSecret()
	if err != nil || len(a) != TOTPSecretSize {
		t.Fatalf("GenerateTOTPSecret = %d bytes, %v", len(a), err)
	}
	b, err := GenerateTOTPSecret()
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("two TOTP secrets are equal")
	}
	setRand(t, errReader{})
	if s, err := GenerateTOTPSecret(); !errors.Is(err, errBoom) || s != nil {
		t.Fatalf("rand failure: %x, %v", s, err)
	}
}

func TestEncodeTOTPSecret(t *testing.T) {
	t.Parallel()
	if got := EncodeTOTPSecret(rfcSecret); got != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("EncodeTOTPSecret = %s", got)
	}
	// No padding, even when the length is not a multiple of 5.
	if got := EncodeTOTPSecret([]byte{0xff}); got != "74" {
		t.Fatalf("EncodeTOTPSecret(0xff) = %s", got)
	}
	if EncodeTOTPSecret(nil) != "" {
		t.Fatal("empty secret encoding")
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	t.Parallel()
	const step = uint64(50_000_000)
	base := time.Unix(int64(step)*TOTPPeriod, 0) // first second of step
	for _, tc := range []struct {
		counter uint64
		ok      bool
	}{
		{step - 2, false}, {step - 1, true}, {step, true}, {step + 1, true}, {step + 2, false},
	} {
		code := TOTPCode(rfcSecret, tc.counter)
		c, ok := VerifyTOTP(rfcSecret, code, base, 0, false)
		if ok != tc.ok || (ok && c != tc.counter) {
			t.Errorf("counter %d: got %d, %v; want ok=%v", tc.counter, c, ok, tc.ok)
		}
	}
	// Edges of a step: the last second of step still accepts step+1, and the
	// first second of step+1 no longer accepts step-1.
	last := base.Add(TOTPPeriod*time.Second - time.Nanosecond)
	if _, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, step+1), last, 0, false); !ok {
		t.Error("next step refused at the end of the current one")
	}
	if _, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, step-1), base.Add(TOTPPeriod*time.Second), 0, false); ok {
		t.Error("step-1 accepted from step+1")
	}
	// Wrong secret.
	if _, ok := VerifyTOTP([]byte("another secret"), TOTPCode(rfcSecret, step), base, 0, false); ok {
		t.Error("code of another secret accepted")
	}
}

func TestVerifyTOTPEpoch(t *testing.T) {
	t.Parallel()
	// At step 0 there is no previous step; before the epoch, step 0 applies.
	for _, now := range []time.Time{time.Unix(0, 0), time.Unix(-100, 0)} {
		for _, tc := range []struct {
			counter uint64
			ok      bool
		}{{0, true}, {1, true}, {2, false}, {^uint64(0), false}} {
			c, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, tc.counter), now, 0, false)
			if ok != tc.ok || (ok && c != tc.counter) {
				t.Errorf("%v counter %d: %d, %v", now, tc.counter, c, ok)
			}
		}
	}
}

func TestVerifyTOTPReplay(t *testing.T) {
	t.Parallel()
	const step = uint64(60_000_000)
	now := time.Unix(int64(step)*TOTPPeriod+10, 0)
	code := TOTPCode(rfcSecret, step)
	c, ok := VerifyTOTP(rfcSecret, code, now, 0, false)
	if !ok || c != step {
		t.Fatalf("first use: %d, %v", c, ok)
	}
	// The same code again is a replay.
	if _, ok := VerifyTOTP(rfcSecret, code, now, c, true); ok {
		t.Fatal("replayed code accepted")
	}
	// An older code is refused once a newer one was used.
	if _, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, step-1), now, c, true); ok {
		t.Fatal("older code accepted after a newer one")
	}
	// A newer code is accepted.
	if c2, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, step+1), now, c, true); !ok || c2 != step+1 {
		t.Fatalf("newer code: %d, %v", c2, ok)
	}
	// haveLast false ignores lastCounter, so lastCounter 0 is not "step 0
	// used": a code of step 0 is accepted at the epoch.
	if _, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, 0), time.Unix(0, 0), 0, false); !ok {
		t.Fatal("step 0 refused without a last counter")
	}
	if _, ok := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, 0), time.Unix(0, 0), 0, true); ok {
		t.Fatal("step 0 accepted after step 0")
	}
	// A last counter in the future (clock moved back) refuses everything.
	if _, ok := VerifyTOTP(rfcSecret, code, now, step+5, true); ok {
		t.Fatal("code accepted before the last counter")
	}
}

// findCollision returns a secret whose codes for two of the three steps around
// step are equal, the second one being later.
func findCollision(t *testing.T, step uint64) []byte {
	t.Helper()
	for i := range 20_000_000 {
		s := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		if TOTPCode(s, step-1) == TOTPCode(s, step+1) {
			return s
		}
	}
	t.Skip("no collision found")
	return nil
}

func TestVerifyTOTPLatestMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("searches for a code collision")
	}
	t.Parallel()
	const step = uint64(7)
	s := findCollision(t, step)
	now := time.Unix(int64(step)*TOTPPeriod, 0)
	code := TOTPCode(s, step-1)
	if c, ok := VerifyTOTP(s, code, now, 0, false); !ok || c != step+1 {
		t.Fatalf("collision: got %d, %v, want the latest step %d", c, ok, step+1)
	}
	// A last counter between the two matching steps keeps the later one.
	if c, ok := VerifyTOTP(s, code, now, step, true); !ok || c != step+1 {
		t.Fatalf("collision after last counter: %d, %v", c, ok)
	}
}

func TestVerifyTOTPMalformed(t *testing.T) {
	t.Parallel()
	now := time.Unix(1111111111, 0)
	good := TOTPCode(rfcSecret, TOTPCounter(now))
	if _, ok := VerifyTOTP(rfcSecret, good, now, 0, false); !ok {
		t.Fatal("good code refused")
	}
	for _, code := range []string{
		"", "12345", "1234567", good + " ", " " + good, good[:5] + "a", "-12345", "+12345",
		"１２３４５６", "12 456", "0x1234", good + "\x00", "abcdef",
	} {
		if c, ok := VerifyTOTP(rfcSecret, code, now, 0, false); ok || c != 0 {
			t.Errorf("malformed code %q accepted", code)
		}
	}
	if _, ok := VerifyTOTP(nil, good, now, 0, false); ok {
		t.Error("empty secret accepted")
	}
	if _, ok := VerifyTOTP([]byte{}, TOTPCode(nil, TOTPCounter(now)), now, 0, false); ok {
		t.Error("empty secret accepted with its own code")
	}
}

func TestTOTPURI(t *testing.T) {
	t.Parallel()
	got := TOTPURI("TransTeira", "alice@entity-a.example.com", rfcSecret)
	want := "otpauth://totp/TransTeira:alice%40entity-a.example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" + // gitleaks:allow (RFC 6238 test secret)
		"&issuer=TransTeira&algorithm=SHA1&digits=6&period=30"
	if got != want {
		t.Fatalf("TOTPURI =\n%s\nwant\n%s", got, want)
	}

	// Special characters cannot break the label separator nor the query.
	issuer := "Entity A: Transfer & Co/?#é+%"
	account := "bob smith:admin@x=y&z"
	got = TOTPURI(issuer, account, rfcSecret)
	wantLabel := "Entity%20A%3A%20Transfer%20%26%20Co%2F%3F%23%C3%A9%2B%25:bob%20smith%3Aadmin%40x%3Dy%26z"
	if !strings.HasPrefix(got, "otpauth://totp/"+wantLabel+"?") {
		t.Fatalf("escaped label: %s", got)
	}
	if strings.Count(got, ":") != 2 || strings.Count(got, "?") != 1 || strings.Contains(got, " ") ||
		strings.Contains(got, "+") || strings.Contains(got, "#") {
		t.Fatalf("unescaped separator in %s", got)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("scheme/host: %s %s", u.Scheme, u.Host)
	}
	// The only literal colon of the escaped label is the separator.
	rawIssuer, rawAccount, found := strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), ":")
	gotIssuer, err1 := url.PathUnescape(rawIssuer)
	gotAccount, err2 := url.PathUnescape(rawAccount)
	if !found || err1 != nil || err2 != nil || gotIssuer != issuer || gotAccount != account {
		t.Fatalf("label decodes to %q, %q", gotIssuer, gotAccount)
	}
	q := u.Query()
	if q.Get("secret") != EncodeTOTPSecret(rfcSecret) || q.Get("issuer") != issuer ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" || len(q) != 5 {
		t.Fatalf("query: %v", q)
	}
}

func TestEscapeURIComponent(t *testing.T) {
	t.Parallel()
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	esc := escapeURIComponent(string(all))
	dec, err := url.PathUnescape(esc)
	if err != nil || dec != string(all) {
		t.Fatalf("round trip: %v", err)
	}
	for i := range len(esc) {
		c := esc[i]
		if c != '%' && !strings.ContainsRune(uriUnreserved, rune(c)) {
			t.Fatalf("byte %q left unescaped", c)
		}
	}
	if escapeURIComponent("aZ09-._~") != "aZ09-._~" {
		t.Fatal("unreserved bytes escaped")
	}
}
