// Package version exposes the build version of TransTeira.
//
// The values are injected at build time with -ldflags, for example:
//
//	go build -ldflags "-X github.com/ed-fr/transteira/internal/version.Version=1.2.3 \
//	  -X github.com/ed-fr/transteira/internal/version.Commit=3f9c2ab \
//	  -X github.com/ed-fr/transteira/internal/version.Date=2026-10-19T16:00:00Z"
//
// When they are left at their defaults, the module and VCS information
// embedded by the Go toolchain (runtime/debug.ReadBuildInfo) is used instead.
package version

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// Default values used when nothing is injected at build time.
const (
	defaultVersion = "0.0.0-dev"
	unknown        = "unknown"
	shortCommitLen = 7
)

// Version is the SemVer 2.0 version of the application, without a leading "v".
// It is set at build time with -ldflags "-X .../internal/version.Version=...".
var Version = defaultVersion

// Commit is the VCS revision the binary was built from.
// It is set at build time with -ldflags "-X .../internal/version.Commit=...".
var Commit = unknown

// Date is the build timestamp (RFC 3339, UTC).
// It is set at build time with -ldflags "-X .../internal/version.Date=...".
var Date = unknown

// readBuildInfo is the build-info reader, replaceable in tests.
var readBuildInfo = debug.ReadBuildInfo

// Info describes the build of the running binary. The JSON field names match
// the OpenAPI VersionInfo schema where both define them (version, commit).
type Info struct {
	// Version is the SemVer of the application.
	Version string `json:"version"`
	// Commit is the VCS revision, suffixed with "-dirty" for modified trees.
	Commit string `json:"commit"`
	// Date is the build or commit timestamp.
	Date string `json:"date"`
	// GoVersion is the Go toolchain used to build the binary.
	GoVersion string `json:"goVersion"`
}

// Get returns the build information of the running binary, falling back to
// the information embedded by the Go toolchain for values left at defaults.
func Get() Info {
	return resolve(Version, Commit, Date, readBuildInfo)
}

// resolve merges injected values with the build info returned by read.
func resolve(v, commit, date string, read func() (*debug.BuildInfo, bool)) Info {
	info := Info{Version: v, Commit: commit, Date: date, GoVersion: runtime.Version()}
	bi, ok := read()
	if !ok || bi == nil {
		return info
	}
	if bi.GoVersion != "" {
		info.GoVersion = bi.GoVersion
	}
	if info.Version == defaultVersion {
		if mv := strings.TrimPrefix(bi.Main.Version, "v"); IsValid(mv) {
			info.Version = mv
		}
	}
	var revision, vcsTime string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if info.Commit == unknown && revision != "" {
		info.Commit = revision
		if modified {
			info.Commit += "-dirty"
		}
	}
	if info.Date == unknown && vcsTime != "" {
		info.Date = vcsTime
	}
	return info
}

// String formats the build information on one line, for example
// "transteira 1.2.3 (commit 3f9c2ab, built 2026-10-19T16:00:00Z, go1.27.2)".
func (i Info) String() string {
	return fmt.Sprintf("transteira %s (commit %s, built %s, %s)",
		i.Version, shortCommit(i.Commit), i.Date, i.GoVersion)
}

// shortCommit abbreviates a full revision, keeping any "-dirty" suffix.
func shortCommit(c string) string {
	rev, dirty := strings.CutSuffix(c, "-dirty")
	if len(rev) > shortCommitLen && rev != unknown {
		rev = rev[:shortCommitLen]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// semverRe is the official SemVer 2.0 regular expression (semver.org).
var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// ErrInvalidSemver is returned when a string is not a valid SemVer 2.0 version.
var ErrInvalidSemver = errors.New("version: invalid SemVer 2.0 string")

// ParseSemver parses s as a SemVer 2.0 version (without a leading "v") and
// returns its numeric components and pre-release identifier. Build metadata
// is validated but not returned.
func ParseSemver(s string) (major, minor, patch int, pre string, err error) {
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, "", fmt.Errorf("%w: %q", ErrInvalidSemver, s)
	}
	nums := [3]int{}
	for i := range nums {
		n, convErr := strconv.Atoi(m[i+1])
		if convErr != nil {
			return 0, 0, 0, "", fmt.Errorf("%w: %q: %w", ErrInvalidSemver, s, convErr)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], m[4], nil
}

// IsValid reports whether s is a valid SemVer 2.0 version.
func IsValid(s string) bool {
	_, _, _, _, err := ParseSemver(s)
	return err == nil
}

// Valid reports whether the injected Version is a valid SemVer 2.0 version.
func Valid() bool {
	return IsValid(Version)
}
