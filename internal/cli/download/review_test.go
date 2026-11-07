package download

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// count returns how many logged requests start with prefix.
func count(log []string, prefix string) int {
	n := 0
	for _, l := range log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// TestDowngradeRefused fails closed when a key is held for a transfer the
// server serves unencrypted, before any further request.
func TestDowngradeRefused(t *testing.T) {
	for name, o := range map[string]Options{
		"link key": {Link: Link{Token: testToken, Key: testKey}},
		"key file": {Link: Link{Token: testToken}, KeyProvided: true, Key: func() (string, error) { return testKey, nil }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
			f.password = "pw"
			o.Password = func() (string, error) { t.Error("password asked"); return "pw", nil }
			res, out, err := run(t, f, o)
			if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "serves this transfer unencrypted") {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), testKey) || res != nil {
				t.Errorf("err = %v, res = %+v", err, res)
			}
			if got := f.log(); len(got) != 1 {
				t.Errorf("requests = %v", got)
			}
			if got := listDir(t, out); len(got) != 0 {
				t.Errorf("files = %v", got)
			}
		})
	}
}

// TestDowngradeAfterUnlock refuses a transfer announced encrypted while
// locked and served unencrypted once unlocked.
func TestDowngradeAfterUnlock(t *testing.T) {
	key, enc := newKey(t)
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{[]byte("x")})
	f.password = "pw"
	f.hook = func(_ int, r *http.Request) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/unlock") {
			f.e2e = false // f.mu is held by the handler
		}
		return 0, ""
	}
	_, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}, Password: func() (string, error) { return "pw", nil }})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
	if got := count(f.log(), "GET "+apiPrefix+testToken+"/files/"); got != 0 {
		t.Errorf("%d file requests", got)
	}
	if got := listDir(t, out); len(got) != 0 {
		t.Errorf("files = %v", got)
	}
}

// TestE2EPrivateModes writes decrypted files readable by the owner only.
func TestE2EPrivateModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	key, enc := newKey(t)
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{[]byte("secret")})
	_, out, err := run(t, f, Options{Link: Link{Token: testToken, Key: enc}})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(out, "a.bin"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", fi, err)
	}
}

// TestPasswordOnce stops at the first wrong password: a password file
// must not burn the other attempts.
func TestPasswordOnce(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.password = "right"
	calls := 0
	_, _, err := run(t, f, Options{PasswordOnce: true, Password: func() (string, error) { calls++; return "wrong", nil }})
	if !errors.Is(err, ErrWrongPassword) || calls != 1 {
		t.Fatalf("err = %v after %d calls", err, calls)
	}
	if got := count(f.log(), "POST "+apiPrefix+testToken+"/unlock"); got != 1 {
		t.Errorf("%d unlock requests", got)
	}
	// The right password still opens the transfer at the first attempt.
	if _, _, err := run(t, f, Options{PasswordOnce: true, Password: func() (string, error) { return "right", nil }}); err != nil {
		t.Fatal(err)
	}
}

// TestCodeOnce stops at the first wrong or malformed code.
func TestCodeOnce(t *testing.T) {
	confirm := "POST " + apiPrefix + testToken + "/verification/confirm"
	for code, sent := range map[string]int{"999999": 1, "abc": 0} {
		f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
		f.code = "123456"
		calls := 0
		_, _, err := run(t, f, Options{CodeOnce: true, Code: func(string) (string, error) { calls++; return code, nil }})
		if !errors.Is(err, ErrVerification) || calls != 1 {
			t.Fatalf("%s: err = %v after %d calls", code, err, calls)
		}
		if got := count(f.log(), confirm); got != sent {
			t.Errorf("%s: %d confirmations", code, got)
		}
	}
}

// TestRetryProgressResets keeps resuming when the failure that brings new
// bytes is the last one the limit allows: the progress counts first.
func TestRetryProgressResets(t *testing.T) {
	data := pattern("retry", 10_000)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	files := 0
	f.hook = func(_ int, r *http.Request) (int, string) {
		if !strings.Contains(r.URL.Path, "/files/") {
			return 0, ""
		}
		files++
		switch {
		case files < client.DefaultMaxAttempts:
			f.cut["fil_a"] = 0 // headers only: no progress
		case files == client.DefaultMaxAttempts:
			f.cut["fil_a"] = 1 // one new byte, then cut
		}
		return 0, ""
	}
	_, out, err := run(t, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), data) || files != client.DefaultMaxAttempts+1 {
		t.Errorf("content differs or %d file requests", files)
	}
}
