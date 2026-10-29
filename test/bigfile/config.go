// Package bigfile is the automated large-file test of CLAUDE.md section
// 24.2: a file of 20 GiB generated on the fly is deposited with an API
// token through tus and the reference Caddy of the production stack, the
// upload is cut in the middle of a PATCH and resumed from the offset the
// server reports, then the file is downloaded entirely and once more with a
// cut and a Range resume; every SHA-256 (expected, computed by the server,
// downloaded, resumed download) must match. Nothing is ever written to the
// client's disk: the content comes from test/internal/seeded.
//
// The scenario itself is TestBigFile, built only with the bigfile tag and
// driven by scripts/bigfile.sh (make bigfile), which starts the stack and
// sets the BIGFILE_* variables read by LoadConfig:
//
//	go test -tags bigfile -run TestBigFile -v -count=1 -timeout 4h ./test/bigfile
//
// The files of this package without the tag (configuration, name
// resolution, TOTP, cut plan, report) are unit tested by the ordinary test
// suite.
package bigfile

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Environment variables read by LoadConfig.
const (
	// EnvBaseURL is the tenant origin through Caddy, e.g.
	// https://transfer.bigfile.localhost:8443. Its host name becomes the FQDN
	// of the test tenant. Mandatory.
	EnvBaseURL = "BIGFILE_BASE_URL"
	// EnvAdminURL is the admin origin through Caddy (a host of
	// TT_ADMIN_HOSTS), e.g. https://admin.bigfile.localhost:8443. Mandatory.
	EnvAdminURL = "BIGFILE_ADMIN_URL"
	// EnvMailAPI is the HTTP API origin of the Mailpit that captures the mails
	// of the test tenant, e.g. http://127.0.0.1:18025. The recipient link is
	// read from the mail sent to the recipient (the API never returns it).
	// Mandatory.
	EnvMailAPI = "BIGFILE_MAIL_API"
	// EnvCAFile is a PEM file of the certificate authorities to trust (the
	// root of Caddy's internal CA). Optional: the system roots otherwise.
	EnvCAFile = "BIGFILE_CA_FILE"
	// EnvResolve maps host names to addresses, see ParseResolve. Optional.
	EnvResolve = "BIGFILE_RESOLVE"
	// EnvSetupToken is the first-run setup token printed by TransTeira in
	// its log. Mandatory.
	EnvSetupToken = "BIGFILE_SETUP_TOKEN"
	// EnvBytes is the size of the file in bytes, 20 GiB by default.
	EnvBytes = "BIGFILE_BYTES"
	// EnvChunk is the body size of one tus PATCH in bytes, 1 GiB by default.
	EnvChunk = "BIGFILE_CHUNK"
	// EnvCutAt is the fraction of the file after which the upload is cut,
	// 0.43 by default, off the 1 GiB chunk boundaries so the cut falls inside a PATCH.
	EnvCutAt = "BIGFILE_CUT_AT"
	// EnvDownloadCutAt is the fraction of the file after which the resumed
	// download is cut, 0.3 by default.
	EnvDownloadCutAt = "BIGFILE_DL_CUT_AT"
	// EnvSeed is the seed of the generated content, 20 by default.
	EnvSeed = "BIGFILE_SEED"
	// EnvReport is the path of the JSON report written at the end, pass or
	// fail. Optional: no report otherwise.
	EnvReport = "BIGFILE_REPORT"
	// EnvEngine labels the report with the database engine of the stack
	// (sqlite or postgres). Optional, informational.
	EnvEngine = "BIGFILE_ENGINE"
	// EnvClamAVMaxScanBytes mirrors TT_CLAMAV_MAX_SCAN_BYTES of the stack: a
	// larger file must end not_scanned_too_large, a smaller one clean.
	EnvClamAVMaxScanBytes = "BIGFILE_CLAMAV_MAX_SCAN_BYTES"
	// EnvScanTimeout bounds the wait from finalize to available (a real
	// clamd may scan a file up to its limit), 30 minutes by default.
	EnvScanTimeout = "BIGFILE_SCAN_TIMEOUT"
)

// Defaults and bounds of the configuration.
const (
	// MaxBytes is the per-transfer limit of TransTeira.
	MaxBytes = tenant.MaxTransferLimit
	// DefaultBytes is the size required by CLAUDE.md section 24.2.
	DefaultBytes = MaxBytes
	// MinBytes keeps the cut and the resumed download meaningful.
	MinBytes int64 = 1 << 20
	// DefaultChunk is the default PATCH body size.
	DefaultChunk int64 = 1 << 30
	// MinChunk is the smallest PATCH body size accepted.
	MinChunk int64 = 1 << 20
	// DefaultCutAt and DefaultDownloadCutAt are the default cut fractions.
	DefaultCutAt         = 0.43
	DefaultDownloadCutAt = 0.3
	// DefaultSeed is the default content seed.
	DefaultSeed uint64 = 20
	// DefaultClamAVMaxScanBytes is TransTeira's default TT_CLAMAV_MAX_SCAN_BYTES
	// (config.DefaultClamAVMaxScanBytes, a string there; a unit test keeps
	// both equal).
	DefaultClamAVMaxScanBytes int64 = 2 << 30
	// DefaultScanTimeout is the default bound of the wait for available.
	DefaultScanTimeout = 30 * time.Minute
)

// Config is the configuration of the large-file test.
type Config struct {
	BaseURL            *url.URL
	AdminURL           *url.URL
	MailAPI            *url.URL
	CAFile             string
	Resolve            map[string]string
	SetupToken         string
	Bytes              int64
	Chunk              int64
	CutAt              float64
	DownloadCutAt      float64
	Seed               uint64
	Report             string
	Engine             string
	ClamAVMaxScanBytes int64
	ScanTimeout        time.Duration
}

// LoadConfig reads the configuration from getenv (os.Getenv in the test)
// and returns every error found, joined.
func LoadConfig(getenv func(string) string) (Config, error) {
	var errs []error
	fail := func(name, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{name}, args...)...))
	}
	c := Config{
		CAFile:     getenv(EnvCAFile),
		SetupToken: getenv(EnvSetupToken),
		Report:     getenv(EnvReport),
		Engine:     getenv(EnvEngine),
	}
	origin := func(name string) *url.URL {
		v := getenv(name)
		if v == "" {
			fail(name, "not set")
			return nil
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			fail(name, "%q is not an https origin (https://host[:port])", v)
			return nil
		}
		u.Path = ""
		return u
	}
	c.BaseURL = origin(EnvBaseURL)
	c.AdminURL = origin(EnvAdminURL)
	if v := getenv(EnvMailAPI); v == "" {
		fail(EnvMailAPI, "not set")
	} else if u, err := url.Parse(v); err != nil || u.Scheme != "http" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		fail(EnvMailAPI, "%q is not an http origin (http://host[:port])", v)
	} else {
		u.Path = ""
		c.MailAPI = u
	}
	if c.SetupToken == "" {
		fail(EnvSetupToken, "not set")
	}
	var err error
	if c.Resolve, err = ParseResolve(getenv(EnvResolve)); err != nil {
		fail(EnvResolve, "%v", err)
	}
	size := func(name string, def, lo, hi int64) int64 {
		v := getenv(name)
		if v == "" {
			return def
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < lo || n > hi {
			fail(name, "%q: want a number of bytes in [%d, %d]", v, lo, hi)
			return def
		}
		return n
	}
	c.Bytes = size(EnvBytes, DefaultBytes, MinBytes, MaxBytes)
	c.Chunk = size(EnvChunk, DefaultChunk, MinChunk, MaxBytes)
	c.ClamAVMaxScanBytes = size(EnvClamAVMaxScanBytes, DefaultClamAVMaxScanBytes, 1, 1<<62)
	fraction := func(name string, def float64) float64 {
		v := getenv(name)
		if v == "" {
			return def
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || !(f > 0 && f < 1) {
			fail(name, "%q: want a fraction strictly between 0 and 1", v)
			return def
		}
		return f
	}
	c.CutAt = fraction(EnvCutAt, DefaultCutAt)
	c.DownloadCutAt = fraction(EnvDownloadCutAt, DefaultDownloadCutAt)
	c.Seed = DefaultSeed
	if v := getenv(EnvSeed); v != "" {
		if c.Seed, err = strconv.ParseUint(v, 10, 64); err != nil {
			fail(EnvSeed, "%q: want an unsigned integer", v)
		}
	}
	c.ScanTimeout = DefaultScanTimeout
	if v := getenv(EnvScanTimeout); v != "" {
		if c.ScanTimeout, err = time.ParseDuration(v); err != nil || c.ScanTimeout <= 0 {
			fail(EnvScanTimeout, "%q: want a positive Go duration (e.g. 30m)", v)
		}
	}
	return c, errors.Join(errs...)
}

// ExpectedScanStatus is the scan status the file must end with: above the
// ClamAV limit of the stack it is delivered unscanned, otherwise clamd
// scans it (random content is clean).
func (c Config) ExpectedScanStatus() string {
	if c.Bytes > c.ClamAVMaxScanBytes {
		return "not_scanned_too_large"
	}
	return "clean"
}

// TenantHost is the FQDN of the test tenant: the host name of BaseURL.
func (c Config) TenantHost() string { return strings.ToLower(c.BaseURL.Hostname()) }

// AdminHost is the host name of AdminURL.
func (c Config) AdminHost() string { return strings.ToLower(c.AdminURL.Hostname()) }
