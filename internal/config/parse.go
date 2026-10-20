package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// maxHostnameLength is the maximum length of a DNS name in text form.
const maxHostnameLength = 253

// ipv4MappedBits is the length of the ::ffff:0:0/96 IPv4-mapped IPv6 prefix.
const ipv4MappedBits = 96

// maxLabelLength is the maximum length of a single DNS label.
const maxLabelLength = 63

// splitList splits a comma-separated list, trims each item and drops empty
// items (so that "a, b," and "a,b" are equivalent).
func splitList(raw string) []string {
	var items []string
	for item := range strings.SplitSeq(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// parsePrefixes parses a comma-separated list of CIDR prefixes or bare IP
// addresses. A bare address becomes a single-host prefix (/32 or /128).
// Prefixes with host bits set (e.g. 10.0.0.1/8) are rejected because they
// usually reveal a typo whose silent correction would widen the trust.
// IPv6 zones are rejected. IPv4-mapped IPv6 addresses and prefixes (e.g.
// ::ffff:10.0.0.0/104) are converted to their IPv4 equivalent (10.0.0.0/8),
// since client addresses are unmapped before matching. A mapped prefix shorter
// than /96 has no IPv4 equivalent; it is rejected by the host bits check.
func parsePrefixes(raw string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range splitList(raw) {
		p, err := parsePrefix(item)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// parsePrefix parses a single CIDR prefix or bare IP address.
func parsePrefix(item string) (netip.Prefix, error) {
	if !strings.Contains(item, "/") {
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid IP address or CIDR prefix", item)
		}
		if addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q: IPv6 zones are not allowed", item)
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(item)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid IP address or CIDR prefix", item)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("%q has host bits set (did you mean %s?)", item, p.Masked())
	}
	// A masked prefix shorter than /96 cannot keep the ::ffff: marker, so a
	// mapped prefix reaching this point always has at least 96 bits.
	if p.Addr().Is4In6() {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-ipv4MappedBits), nil
	}
	return p, nil
}

// parseBool parses a boolean accepting true/false/1/0, case-insensitively.
func parseBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%q is not a boolean (use true, false, 1 or 0)", raw)
	}
}

// parseDuration parses a Go duration (e.g. "90m", "24h") and checks that it
// lies within [lowest, highest].
func parseDuration(raw string, lowest, highest time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid duration (examples: 15m, 4h, 168h)", raw)
	}
	if d < lowest || d > highest {
		return 0, fmt.Errorf("%s is out of range [%s, %s]", d, lowest, highest)
	}
	return d, nil
}

// parseInt parses a decimal integer and checks that it lies within
// [lowest, highest].
func parseInt(raw string, lowest, highest int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid integer", raw)
	}
	if n < lowest || n > highest {
		return 0, fmt.Errorf("%d is out of range [%d, %d]", n, lowest, highest)
	}
	return n, nil
}

// validHostname reports whether name is a syntactically valid lowercase DNS
// name made of LDH labels (letters, digits, hyphens). IP literals are rejected.
func validHostname(name string) bool {
	if name == "" || len(name) > maxHostnameLength {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > maxLabelLength {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// parseHosts parses a comma-separated list of FQDNs. Names are lowercased,
// a single trailing dot is removed and duplicates are dropped.
func parseHosts(raw string) ([]string, error) {
	var hosts []string
	seen := make(map[string]bool)
	for _, item := range splitList(raw) {
		name := strings.TrimSuffix(strings.ToLower(item), ".")
		if !validHostname(name) {
			return nil, fmt.Errorf("%q is not a valid host name", item)
		}
		if !seen[name] {
			seen[name] = true
			hosts = append(hosts, name)
		}
	}
	return hosts, nil
}

// parsePort parses a TCP port number in [1, 65535].
func parsePort(raw string) error {
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("port %q must be a number between 1 and 65535", raw)
	}
	return nil
}

// validateHostPort checks a "host:port" address. When hostRequired is false
// the host may be empty (listen on all interfaces).
func validateHostPort(raw string, hostRequired bool) error {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return fmt.Errorf("%q is not a host:port address", raw)
	}
	if err := parsePort(port); err != nil {
		return err
	}
	switch {
	case host == "":
		if hostRequired {
			return fmt.Errorf("%q has no host", raw)
		}
	case validHostname(strings.ToLower(host)):
	default:
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Zone() != "" {
			return fmt.Errorf("%q has an invalid host", raw)
		}
	}
	return nil
}

// sqliteDir returns the directory of the SQLite database file designated by
// dsn, which is either a plain path or a "file:" URI with optional query
// parameters. It returns false for in-memory or relative databases.
func sqliteDir(dsn string) (string, bool) {
	path, _, _ := strings.Cut(strings.TrimPrefix(dsn, "file:"), "?")
	if strings.HasPrefix(path, "///") {
		path = path[2:] // file:///abs: empty URI authority
	}
	if path == "" || path == ":memory:" || !isAbsPath(path) || strings.ContainsRune(path, 0) {
		return "", false
	}
	return filepath.Dir(filepath.Clean(path)), true
}

// errNotAbsolute is returned by checkAbsPath for relative paths.
var errNotAbsolute = errors.New("must be an absolute path")

// isAbsPath reports whether p is absolute. Besides filepath.IsAbs, a path
// starting with "/" is accepted on every platform: TransTeira targets Linux
// containers, and accepting "/var/lib/..." on Windows keeps the defaults and
// the tests portable (Windows treats such paths as rooted on the current
// drive).
func isAbsPath(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/")
}

// checkAbsPath validates a filesystem path and returns its cleaned form.
func checkAbsPath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", errors.New("must not contain NUL bytes")
	}
	if !isAbsPath(p) {
		return "", errNotAbsolute
	}
	return filepath.Clean(p), nil
}

// caseInsensitivePaths reports whether paths must be compared without regard
// to case (Windows filesystems are case-insensitive by default).
var caseInsensitivePaths = runtime.GOOS == "windows"

// normalizePath returns a cleaned path suitable for comparisons.
func normalizePath(p string) string {
	p = filepath.Clean(p)
	if caseInsensitivePaths {
		p = strings.ToLower(p)
	}
	return p
}

// samePath reports whether a and b designate the same path after cleaning
// (case-insensitively on Windows). Symbolic links are not resolved.
func samePath(a, b string) bool {
	return normalizePath(a) == normalizePath(b)
}

// pathWithin reports whether child is dir itself or located below dir, after
// cleaning (case-insensitively on Windows). The separator is appended to dir
// before the prefix test so that "/data2/key" is not considered inside
// "/data". Symbolic links are not resolved.
func pathWithin(child, dir string) bool {
	c, d := normalizePath(child), normalizePath(dir)
	if c == d {
		return true
	}
	if !strings.HasSuffix(d, string(filepath.Separator)) {
		d += string(filepath.Separator)
	}
	return strings.HasPrefix(c, d)
}
