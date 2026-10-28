package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWrapRoundTrip(t *testing.T) {
	k := testKey(t)
	for _, p := range []Purpose{PurposeDEK, PurposeSecret, PurposeAdminTOTP, PurposeWebhook} {
		for _, pt := range [][]byte{nil, {}, []byte("smtp-password"), testDEK(7), bytes.Repeat([]byte{1}, 4096)} {
			blob, err := k.Wrap(p, "ten_a", "wk_1", pt)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if len(blob) != envelopeOverhead+len(pt) || blob[0] != envelopeVersion {
				t.Fatalf("blob framing: len=%d version=%d", len(blob), blob[0])
			}
			got, err := k.Unwrap(p, "ten_a", "wk_1", blob)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("Unwrap = %x, %v", got, err)
			}
			if len(pt) >= 8 && bytes.Contains(blob, pt) {
				t.Fatal("plaintext visible in blob")
			}
		}
	}
}

func TestUnwrapMismatch(t *testing.T) {
	k := testKey(t)
	dek := testDEK(3)
	blob, err := k.Wrap(PurposeDEK, "ten_a", "wk_1", dek)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", maxBindingLen+1)
	cases := map[string]struct {
		k      *MasterKey
		p      Purpose
		tenant string
		row    string
		blob   []byte
	}{
		"other tenant":     {k, PurposeDEK, "ten_b", "wk_1", blob},
		"other row":        {k, PurposeDEK, "ten_a", "wk_2", blob},
		"purpose swap":     {k, PurposeSecret, "ten_a", "wk_1", blob},
		"webhook purpose":  {k, PurposeWebhook, "ten_a", "wk_1", blob},
		"unknown purpose":  {k, Purpose("file"), "ten_a", "wk_1", blob},
		"empty purpose":    {k, Purpose(""), "ten_a", "wk_1", blob},
		"other master key": {otherKey(t), PurposeDEK, "ten_a", "wk_1", blob},
		"shifted fields":   {k, PurposeDEK, "ten_aw", "k_1", blob},
		"swapped fields":   {k, PurposeDEK, "wk_1", "ten_a", blob},
		"empty tenant":     {k, PurposeDEK, "", "wk_1", blob},
		"empty row":        {k, PurposeDEK, "ten_a", "", blob},
		"long tenant":      {k, PurposeDEK, long, "wk_1", blob},
		"nil blob":         {k, PurposeDEK, "ten_a", "wk_1", nil},
		"short blob":       {k, PurposeDEK, "ten_a", "wk_1", blob[:envelopeOverhead-1]},
		"truncated blob":   {k, PurposeDEK, "ten_a", "wk_1", blob[:len(blob)-1]},
		"extended blob":    {k, PurposeDEK, "ten_a", "wk_1", append(append([]byte(nil), blob...), 0)},
		"bad version":      {k, PurposeDEK, "ten_a", "wk_1", append([]byte{2}, blob[1:]...)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := c.k.Unwrap(c.p, c.tenant, c.row, c.blob)
			if !errors.Is(err, ErrUnwrap) || got != nil {
				t.Fatalf("Unwrap = %x, %v; want ErrUnwrap", got, err)
			}
			if err.Error() != ErrUnwrap.Error() {
				t.Fatalf("error not opaque: %v", err)
			}
		})
	}

	// Every single bit flip is detected.
	for i := range blob {
		for bit := range 8 {
			mod := append([]byte(nil), blob...)
			mod[i] ^= 1 << bit
			if _, err := k.Unwrap(PurposeDEK, "ten_a", "wk_1", mod); !errors.Is(err, ErrUnwrap) {
				t.Fatalf("flip byte %d bit %d accepted", i, bit)
			}
		}
	}

	// A nil key reports unavailability.
	if _, err := (*MasterKey)(nil).Unwrap(PurposeDEK, "ten_a", "wk_1", blob); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("nil key Unwrap: %v", err)
	}
}

func TestWrapErrors(t *testing.T) {
	k := testKey(t)
	long := strings.Repeat("x", maxBindingLen+1)
	if _, err := k.Wrap(Purpose("file"), "ten_a", "wk_1", nil); !errors.Is(err, ErrUnknownPurpose) {
		t.Fatalf("unknown purpose: %v", err)
	}
	for _, ids := range [][2]string{{"", "wk_1"}, {"ten_a", ""}, {long, "wk_1"}, {"ten_a", long}} {
		if _, err := k.Wrap(PurposeDEK, ids[0], ids[1], nil); !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("binding %q: %v", ids, err)
		}
	}
	if _, err := k.Wrap(PurposeDEK, strings.Repeat("x", maxBindingLen), "wk_1", nil); err != nil {
		t.Fatalf("maximal binding refused: %v", err)
	}
	if _, err := (*MasterKey)(nil).Wrap(PurposeDEK, "ten_a", "wk_1", nil); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("nil key: %v", err)
	}
	setRand(t, errReader{})
	if _, err := k.Wrap(PurposeDEK, "ten_a", "wk_1", nil); !errors.Is(err, errBoom) {
		t.Fatalf("rand failure: %v", err)
	}
}

func TestPurposeKeysDiffer(t *testing.T) {
	k := testKey(t)
	// Same nonce, same AAD apart from the purpose: the per-purpose keys must
	// differ, which the AAD alone would not show. Seal directly.
	nonce := make([]byte, nonceSize)
	seen := map[string]Purpose{}
	for _, p := range purposes {
		ct := string(k.m.wrap[p].Seal(nil, nonce, []byte("x"), nil))
		if other, dup := seen[ct]; dup {
			t.Fatalf("purposes %s and %s share a wrapping key", p, other)
		}
		seen[ct] = p
	}
}

func TestGenerateDEK(t *testing.T) {
	a, err := GenerateDEK()
	if err != nil || len(a) != DEKSize {
		t.Fatalf("GenerateDEK = %d bytes, %v", len(a), err)
	}
	b, err := GenerateDEK()
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("two DEKs are equal")
	}
	setRand(t, errReader{})
	if _, err := GenerateDEK(); !errors.Is(err, errBoom) {
		t.Fatalf("rand failure: %v", err)
	}
}

func TestNewAEADPanicsOnBadKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	newAEAD(make([]byte, 16))
}

func TestEnvelopeNonceUniqueness(t *testing.T) {
	k := testKey(t)
	seen := make(map[string]bool)
	for range 5000 {
		blob, err := k.Wrap(PurposeDEK, "ten_a", "wk_1", testDEK(0))
		if err != nil {
			t.Fatal(err)
		}
		n := string(blob[1 : 1+nonceSize])
		if seen[n] {
			t.Fatal("duplicate envelope nonce")
		}
		seen[n] = true
	}
}
