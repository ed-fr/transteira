package apidocs

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"
)

// TestVendoredChecksums checks that the vendored files are the ones
// recorded in README.md (its "SHA-256" rows): the embedded Scalar bundle and
// its license, so that a tampered or silently updated file fails the checks.
func TestVendoredChecksums(t *testing.T) {
	t.Parallel()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	license, err := os.ReadFile("LICENSE.scalar")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"scalar.js": ScalarJS, "LICENSE.scalar": license} {
		// The README row: | `<name>` SHA-256 | `<hex>` |
		re := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(name) + "` SHA-256 \\| `([0-9a-f]{64})` \\|\\r?$")
		m := re.FindSubmatch(readme)
		if m == nil {
			t.Errorf("no %s SHA-256 row in README.md", name)
			continue
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != string(m[1]) {
			t.Errorf("%s SHA-256 %s, README.md records %s", name, got, m[1])
		}
	}
}
