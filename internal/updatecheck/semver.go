package updatecheck

import (
	"strings"

	"github.com/ed-fr/transteira/internal/version"
)

// MaxVersionLength bounds a version read from GitHub or from the cache,
// in bytes (a leading "v" of a tag included).
const MaxVersionLength = 64

// semver is a parsed SemVer 2.0 version (build metadata dropped: it has
// no precedence).
type semver struct {
	major, minor, patch int
	pre                 []string
}

// parseSemver parses s, a strict SemVer 2.0 version without a leading "v"
// of at most MaxVersionLength bytes.
func parseSemver(s string) (semver, bool) {
	if len(s) > MaxVersionLength {
		return semver{}, false
	}
	major, minor, patch, pre, err := version.ParseSemver(s)
	if err != nil {
		return semver{}, false
	}
	v := semver{major: major, minor: minor, patch: patch}
	if pre != "" {
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// StableVersion reports whether s is a strict SemVer 2.0 version of at
// most MaxVersionLength bytes, without a pre-release suffix: the only
// versions announced as a release. Build metadata is accepted.
func StableVersion(s string) bool {
	v, ok := parseSemver(s)
	return ok && len(v.pre) == 0
}

// Compare compares the SemVer 2.0 versions a and b by precedence: -1 when
// a < b, 0 when equal (build metadata ignored), +1 when a > b. ok is false
// when either is not a strict SemVer of at most MaxVersionLength bytes;
// the result is then 0.
func Compare(a, b string) (result int, ok bool) {
	va, okA := parseSemver(a)
	vb, okB := parseSemver(b)
	if !okA || !okB {
		return 0, false
	}
	return compareSemver(va, vb), true
}

// compareSemver compares two parsed versions by SemVer 2.0 precedence
// (semver.org, rule 11).
func compareSemver(a, b semver) int {
	for _, c := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if r := compareInt(c[0], c[1]); r != 0 {
			return r
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1 // a release is greater than its pre-releases
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if r := compareIdentifier(a.pre[i], b.pre[i]); r != 0 {
			return r
		}
	}
	return compareInt(len(a.pre), len(b.pre))
}

// compareIdentifier compares two pre-release identifiers: numeric ones
// numerically (any length: SemVer forbids their leading zeros, so the
// longer is the greater), numeric before alphanumeric, alphanumeric ones
// in ASCII order.
func compareIdentifier(a, b string) int {
	numA, numB := numeric(a), numeric(b)
	switch {
	case numA && numB:
		if r := compareInt(len(a), len(b)); r != 0 {
			return r
		}
		return strings.Compare(a, b)
	case numA:
		return -1
	case numB:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// numeric reports whether s is a non-empty string of ASCII digits.
func numeric(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareInt returns -1, 0 or +1 as a is less than, equal to or greater
// than b.
func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// Newer reports whether latest is strictly greater than current. It is
// false when either is not a valid version, or when latest is not a
// stable version ([StableVersion]).
func Newer(latest, current string) bool {
	if !StableVersion(latest) {
		return false
	}
	r, ok := Compare(latest, current)
	return ok && r > 0
}
