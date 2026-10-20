package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// passwordVector is the hash of "correct horse battery staple" with the real
// parameters and the salt 0x00..0x0f. vectors_password_external_test.go checks
// it against argon2.IDKey directly.
const passwordVector = "$argon2id$v=19$m=65536,t=3,p=1$AAECAwQFBgcICQoLDA0ODw$DRo8ZSPI8G5OCvnFFapbVEjP69aDjy1Sw9i2743cPC4"

// phcRe matches a PHC string with the fast test parameters.
var phcRe = regexp.MustCompile(`^\$argon2id\$v=19\$m=64,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

// setFastParams lowers the hashing parameters for the duration of the test.
func setFastParams(t testing.TB) {
	t.Helper()
	old := hashParams
	hashParams = argon2Params{memory: 64, time: 1, threads: 1, saltLen: Argon2SaltSize, keyLen: Argon2KeySize}
	t.Cleanup(func() { hashParams = old })
}

// setIDKey replaces the argon2id function for the duration of the test.
func setIDKey(t testing.TB, f func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte) {
	t.Helper()
	old := idKey
	idKey = f
	t.Cleanup(func() { idKey = old })
}

// fixedSalt returns a reader yielding 0x00..0x0f.
func fixedSalt() *bytes.Reader {
	b := make([]byte, Argon2SaltSize)
	for i := range b {
		b[i] = byte(i)
	}
	return bytes.NewReader(b)
}

func TestHashPasswordRealParameters(t *testing.T) {
	setRand(t, fixedSalt())
	got, err := HashPassword([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if got != passwordVector {
		t.Fatalf("HashPassword = %q, want %q", got, passwordVector)
	}
	ok, err := VerifyPassword(got, []byte("correct horse battery staple"))
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v; want true, nil", ok, err)
	}
	if NeedsRehash(got) {
		t.Fatal("NeedsRehash is true for a hash with the current parameters")
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	setFastParams(t)
	for _, pw := range [][]byte{[]byte("secret"), {}, []byte("pässwörd ✓"), bytes.Repeat([]byte{'x'}, MaxPasswordSize)} {
		enc, err := HashPassword(pw)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		if !phcRe.MatchString(enc) {
			t.Fatalf("unexpected encoding %q", enc)
		}
		ok, err := VerifyPassword(enc, pw)
		if err != nil || !ok {
			t.Fatalf("VerifyPassword(own hash) = %v, %v", ok, err)
		}
		wrong := []byte("x")
		if len(pw) > 0 {
			wrong = append([]byte(nil), pw...)
			wrong[0] ^= 1
		}
		ok, err = VerifyPassword(enc, wrong)
		if err != nil || ok {
			t.Fatalf("VerifyPassword(wrong password) = %v, %v; want false, nil", ok, err)
		}
	}
}

func TestHashPasswordSaltsDiffer(t *testing.T) {
	setFastParams(t)
	a, _ := HashPassword([]byte("same"))
	b, _ := HashPassword([]byte("same"))
	if a == b {
		t.Fatal("two hashes of the same password are equal")
	}
}

func TestWrongPassword(t *testing.T) {
	setFastParams(t)
	enc, _ := HashPassword([]byte("secret"))
	for _, pw := range []string{"Secret", "secret ", "", "secre"} {
		ok, err := VerifyPassword(enc, []byte(pw))
		if err != nil || ok {
			t.Fatalf("VerifyPassword(%q) = %v, %v; want false, nil", pw, ok, err)
		}
	}
}

func TestHashPasswordErrors(t *testing.T) {
	setFastParams(t)
	if _, err := HashPassword(make([]byte, MaxPasswordSize+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("too long: err = %v", err)
	}
	setRand(t, errReader{})
	if _, err := HashPassword([]byte("x")); !errors.Is(err, errBoom) {
		t.Fatalf("rand failure: err = %v", err)
	}
}

func TestVerifyPasswordTooLong(t *testing.T) {
	setIDKey(t, func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
		t.Fatal("a too long password must not be hashed")
		return nil
	})
	ok, err := VerifyPassword(passwordVector, make([]byte, MaxPasswordSize+1))
	if ok || !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("VerifyPassword = %v, %v", ok, err)
	}
}

// salt8, salt64, key16 and key64 are base64 strings of the boundary sizes.
var (
	salt8  = b64.EncodeToString(make([]byte, 8))
	salt7  = b64.EncodeToString(make([]byte, 7))
	salt64 = b64.EncodeToString(make([]byte, 64))
	salt65 = b64.EncodeToString(make([]byte, 65))
	key16  = b64.EncodeToString(make([]byte, 16))
	key15  = b64.EncodeToString(make([]byte, 15))
	key64  = b64.EncodeToString(make([]byte, 64))
	key65  = b64.EncodeToString(make([]byte, 65))
	salt16 = "AAECAwQFBgcICQoLDA0ODw"
	key32  = "DRo8ZSPI8G5OCvnFFapbVEjP69aDjy1Sw9i2743cPC4" // gitleaks:allow
)

// enc builds a PHC string from its variable segments.
func enc(params, salt, key string) string {
	return "$argon2id$v=19$" + params + "$" + salt + "$" + key
}

func TestVerifyPasswordMalformed(t *testing.T) {
	setIDKey(t, func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
		t.Fatal("a malformed hash must not be hashed")
		return nil
	})
	good := "m=65536,t=3,p=1"
	cases := map[string]string{
		"empty":             "",
		"too long":          strings.Repeat("$", maxEncodedHashLen+1),
		"argon2i":           "$argon2i$v=19$" + good + "$" + salt16 + "$" + key32,
		"argon2d":           "$argon2d$v=19$" + good + "$" + salt16 + "$" + key32,
		"bcrypt":            "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
		"no leading dollar": "argon2id$v=19$" + good + "$" + salt16 + "$" + key32,
		"version 16":        "$argon2id$v=16$" + good + "$" + salt16 + "$" + key32,
		"no version":        "$argon2id$" + good + "$" + salt16 + "$" + key32,
		"version 019":       "$argon2id$v=019$" + good + "$" + salt16 + "$" + key32,
		"extra segment":     enc(good, salt16, key32) + "$",
		"extra segment 2":   enc(good, salt16, key32) + "$AAAA",
		"missing hash":      "$argon2id$v=19$" + good + "$" + salt16,
		"params order":      enc("t=3,m=65536,p=1", salt16, key32),
		"params missing":    enc("m=65536,t=3", salt16, key32),
		"params extra":      enc("m=65536,t=3,p=1,k=1", salt16, key32),
		"params keyid":      enc("m=65536,t=3,p=1,keyid=AA", salt16, key32),
		"params spaces":     enc("m=65536, t=3,p=1", salt16, key32),
		"m empty":           enc("m=,t=3,p=1", salt16, key32),
		"m sign":            enc("m=+65536,t=3,p=1", salt16, key32),
		"m negative":        enc("m=-1,t=3,p=1", salt16, key32),
		"m leading zero":    enc("m=065536,t=3,p=1", salt16, key32),
		"m hex":             enc("m=0x10000,t=3,p=1", salt16, key32),
		"m huge":            enc("m=4294967295,t=3,p=1", salt16, key32),
		"m overflow":        enc("m=99999999999999999999,t=3,p=1", salt16, key32),
		"m above bound":     enc("m=262145,t=3,p=1", salt16, key32),
		"m below lanes":     enc("m=31,t=1,p=4", salt16, key32),
		"m zero":            enc("m=0,t=3,p=1", salt16, key32),
		"t zero":            enc("m=65536,t=0,p=1", salt16, key32),
		"t huge":            enc("m=65536,t=4294967295,p=1", salt16, key32),
		"t above bound":     enc("m=65536,t=11,p=1", salt16, key32),
		"p zero":            enc("m=65536,t=3,p=0", salt16, key32),
		"p above bound":     enc("m=65536,t=3,p=5", salt16, key32),
		"p huge":            enc("m=65536,t=3,p=255", salt16, key32),
		"uppercase M":       enc("M=65536,t=3,p=1", salt16, key32),
		"salt padded":       enc(good, salt16+"==", key32),
		"salt url alphabet": enc(good, "AAECAwQFBgcICQoLDA0OD_", key32),
		"salt bad char":     enc(good, "AAECAwQFBgcICQoLDA0OD!", key32),
		"salt non canon":    enc(good, "AAECAwQFBgcICQoLDA0ODx", key32),
		"salt empty":        enc(good, "", key32),
		"salt too short":    enc(good, salt7, key32),
		"salt too long":     enc(good, salt65, key32),
		"hash too short":    enc(good, salt16, key15),
		"hash too long":     enc(good, salt16, key65),
		"hash bad base64":   enc(good, salt16, key32[:42]+"*"),
		"hash newline":      enc(good, salt16, key32+"\n"),
		"hash empty":        enc(good, salt16, ""),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword(e, []byte("correct horse battery staple"))
			if ok || !errors.Is(err, ErrMalformedHash) {
				t.Fatalf("VerifyPassword(%q) = %v, %v; want false, ErrMalformedHash", e, ok, err)
			}
			if !NeedsRehash(e) {
				t.Fatalf("NeedsRehash(%q) = false for a malformed hash", e)
			}
		})
	}
}

func TestVerifyPasswordBoundsAccepted(t *testing.T) {
	type call struct {
		saltLen, keyLen  int
		tm, mem, threads uint32
	}
	var got call
	setIDKey(t, func(_, salt []byte, tm, mem uint32, threads uint8, keyLen uint32) []byte {
		got = call{len(salt), int(keyLen), tm, mem, uint32(threads)}
		return make([]byte, keyLen)
	})
	cases := []struct {
		enc  string
		want call
	}{
		{enc("m=262144,t=10,p=4", salt64, key64), call{64, 64, 10, 262144, 4}},
		{enc("m=8,t=1,p=1", salt8, key16), call{8, 16, 1, 8, 1}},
		{enc("m=32,t=1,p=4", salt8, key16), call{8, 16, 1, 32, 4}},
	}
	for _, c := range cases {
		ok, err := VerifyPassword(c.enc, []byte("pw"))
		if err != nil || !ok {
			t.Fatalf("VerifyPassword(%q) = %v, %v", c.enc, ok, err)
		}
		if got != c.want {
			t.Fatalf("idKey called with %+v, want %+v", got, c.want)
		}
		if !NeedsRehash(c.enc) {
			t.Fatalf("NeedsRehash(%q) = false", c.enc)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	if NeedsRehash(passwordVector) {
		t.Fatal("current parameters need a rehash")
	}
	for _, e := range []string{
		enc("m=65536,t=2,p=1", salt16, key32),
		enc("m=32768,t=3,p=1", salt16, key32),
		enc("m=65536,t=3,p=2", salt16, key32),
		enc("m=65536,t=3,p=1", salt8, key32),
		enc("m=65536,t=3,p=1", salt16, key16),
		"garbage",
	} {
		if !NeedsRehash(e) {
			t.Fatalf("NeedsRehash(%q) = false", e)
		}
	}
}

func TestPasswordHasher(t *testing.T) {
	setFastParams(t)
	h := NewPasswordHasher(2)
	ctx := t.Context()
	e, err := h.HashPassword(ctx, []byte("pw"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := h.VerifyPassword(ctx, e, []byte("pw"))
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v", ok, err)
	}
	ok, err = h.VerifyPassword(ctx, e, []byte("other"))
	if err != nil || ok {
		t.Fatalf("VerifyPassword(wrong) = %v, %v", ok, err)
	}
	if h.NeedsRehash(e) {
		t.Fatal("NeedsRehash is true for the current (test) parameters")
	}
	if cap(NewPasswordHasher(0).slots) != 1 || cap(NewPasswordHasher(-3).slots) != 1 {
		t.Fatal("maxConcurrent below 1 must mean 1")
	}
}

func TestPasswordHasherBoundsConcurrency(t *testing.T) {
	setFastParams(t)
	const limit = 2
	var running, peak atomic.Int32
	release := make(chan struct{})
	setIDKey(t, func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		running.Add(-1)
		return make([]byte, Argon2KeySize)
	})
	h := NewPasswordHasher(limit)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if _, err := h.HashPassword(context.Background(), []byte("pw")); err != nil {
				t.Errorf("HashPassword: %v", err)
			}
		})
	}
	// Wait until the slots are full, then let everything finish.
	for running.Load() < limit {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if p := peak.Load(); p != limit {
		t.Fatalf("peak concurrency = %d, want %d", p, limit)
	}
}

func TestPasswordHasherContext(t *testing.T) {
	setFastParams(t)
	h := NewPasswordHasher(1)
	h.slots <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := h.HashPassword(ctx, []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Fatalf("HashPassword: err = %v", err)
	}
	if ok, err := h.VerifyPassword(ctx, passwordVector, []byte("pw")); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyPassword = %v, %v", ok, err)
	}
	// A malformed hash is rejected without waiting for a slot.
	if ok, err := h.VerifyPassword(t.Context(), "bad", []byte("pw")); ok || !errors.Is(err, ErrMalformedHash) {
		t.Fatalf("VerifyPassword(malformed) = %v, %v", ok, err)
	}
}

func FuzzVerifyPassword(f *testing.F) {
	setFastParams(f)
	f.Add(passwordVector, []byte("correct horse battery staple"))
	f.Add(enc("m=262144,t=10,p=4", salt64, key64), []byte{})
	f.Add(enc("m=4294967295,t=4294967295,p=255", salt16, key32), []byte("x"))
	f.Add("$argon2id$v=19$m=64,t=1,p=1$"+salt16+"$"+key32+"$", []byte("x"))
	f.Add("$argon2i$v=19$m=64,t=1,p=1$AAAA$AAAA", []byte("x"))
	f.Add("", []byte(nil))
	setIDKey(f, func(_, salt []byte, tm, mem uint32, threads uint8, keyLen uint32) []byte {
		if mem > MaxArgon2Memory || mem < 8*uint32(threads) || tm < 1 || tm > MaxArgon2Time ||
			threads < 1 || threads > MaxArgon2Threads ||
			len(salt) < MinArgon2SaltSize || len(salt) > MaxArgon2SaltSize ||
			keyLen < MinArgon2KeySize || keyLen > MaxArgon2KeySize {
			panic(fmt.Sprintf("idKey called out of bounds: m=%d t=%d p=%d salt=%d key=%d", mem, tm, threads, len(salt), keyLen))
		}
		return make([]byte, keyLen)
	})
	f.Fuzz(func(t *testing.T, encoded string, password []byte) {
		ok, err := VerifyPassword(encoded, password)
		if err != nil && ok {
			t.Fatal("ok with an error")
		}
		if err != nil && !errors.Is(err, ErrMalformedHash) && !errors.Is(err, ErrPasswordTooLong) {
			t.Fatalf("unexpected error %v", err)
		}
		if errors.Is(err, ErrMalformedHash) && !NeedsRehash(encoded) {
			t.Fatal("malformed hash does not need a rehash")
		}
	})
}
