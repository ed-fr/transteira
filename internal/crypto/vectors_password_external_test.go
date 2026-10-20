package crypto_test

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/ed-fr/transteira/internal/crypto"
)

// TestPasswordVectorExternal recomputes the fixed-salt reference hash with
// argon2.IDKey directly, independently of the package's encoder, and checks
// that the package verifies it with the documented parameters.
func TestPasswordVectorExternal(t *testing.T) {
	const password = "correct horse battery staple"
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	want := "$argon2id$v=19$m=65536,t=3,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key)
	const frozen = "$argon2id$v=19$m=65536,t=3,p=1$AAECAwQFBgcICQoLDA0ODw$DRo8ZSPI8G5OCvnFFapbVEjP69aDjy1Sw9i2743cPC4"
	if want != frozen {
		t.Fatalf("recomputed vector %q, frozen %q", want, frozen)
	}
	if crypto.Argon2Memory != 64*1024 || crypto.Argon2Time != 3 || crypto.Argon2Threads != 1 ||
		crypto.Argon2SaltSize != 16 || crypto.Argon2KeySize != 32 {
		t.Fatal("documented parameters changed: update the vector")
	}
	ok, err := crypto.VerifyPassword(want, []byte(password))
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v", ok, err)
	}
	if ok, _ := crypto.VerifyPassword(want, []byte(password+"!")); ok {
		t.Fatal("wrong password accepted")
	}
	if crypto.NeedsRehash(want) {
		t.Fatal("NeedsRehash true for the current parameters")
	}
}
