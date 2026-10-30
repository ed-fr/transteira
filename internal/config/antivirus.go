package config

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Bounds of the ICAP and HTTP engine settings.
const (
	// minEngineMaxScanBytes and maxEngineMaxScanBytes bound
	// TT_ICAP_MAX_SCAN_BYTES and TT_AVHTTP_MAX_SCAN_BYTES (1 MiB to 20 GiB,
	// the largest transfer).
	minEngineMaxScanBytes = 1 << 20
	maxEngineMaxScanBytes = 20 << 30
	// maxMultipartFieldLen bounds TT_AVHTTP_MULTIPART_FIELD.
	maxMultipartFieldLen = 64
)

// Body modes of the HTTP antivirus engine (TT_AVHTTP_BODY).
const (
	AVHTTPBodyMultipart = "multipart"
	AVHTTPBodyRaw       = "raw"
)

// ICAPConfig configures the ICAP antivirus engine (TT_ANTIVIRUS_ENGINE=icap).
type ICAPConfig struct {
	// URL is the ICAP service: icap://host[:port]/service or icaps://...,
	// without credentials, query or fragment.
	URL string
	// CAFile is the path of the PEM file of the only CAs trusted for
	// icaps:// ("" for the system pool); CAPEM is its content.
	CAFile string
	CAPEM  []byte
	// InfectionHeaders are the header names whose presence means the
	// content is infected.
	InfectionHeaders []string
	// MaxScanBytes is the largest file size sent to the engine.
	MaxScanBytes int64
	// Timeout bounds the analysis of one file.
	Timeout time.Duration
}

// AVHTTPConfig configures the generic HTTP antivirus engine
// (TT_ANTIVIRUS_ENGINE=http). The verdict rules stay strings here; the
// application parses them (antivirus.ParseRule).
type AVHTTPConfig struct {
	// URL receives the content to analyze (http or https, no credentials).
	URL string
	// Method is POST or PUT.
	Method string
	// Body is AVHTTPBodyMultipart or AVHTTPBodyRaw.
	Body string
	// MultipartField names the part holding the content.
	MultipartField string
	// AuthHeader is an optional "Name: value" header line sent with every
	// request, read from TT_AVHTTP_AUTH_HEADER_FILE. It is never logged.
	AuthHeader Secret
	// CAFile is the path of the PEM file of the only CAs trusted for an
	// https URL ("" for the system pool); CAPEM is its content.
	CAFile string
	CAPEM  []byte
	// CleanRule and InfectedRule decide the verdict.
	CleanRule    string
	InfectedRule string
	// SignaturePointer is an optional RFC 6901 pointer to the signature
	// name in the JSON body.
	SignaturePointer string
	// HealthURL is an optional URL checked by the health probe.
	HealthURL string
	// MaxScanBytes is the largest file size sent to the engine.
	MaxScanBytes int64
	// Timeout bounds the analysis of one file.
	Timeout time.Duration
}

// icapVars and avhttpVars are the variables specific to each engine: set
// while another engine is selected, they are ignored with a warning.
var (
	icapVars = []string{
		EnvICAPURL, EnvICAPCAFile, EnvICAPInfectionHeaders, EnvICAPMaxScanBytes, EnvICAPTimeout,
	}
	avhttpVars = []string{
		EnvAVHTTPURL, EnvAVHTTPMethod, EnvAVHTTPBody, EnvAVHTTPMultipartField, EnvAVHTTPAuthHeaderFile,
		EnvAVHTTPCAFile, EnvAVHTTPCleanRule, EnvAVHTTPInfectedRule, EnvAVHTTPSignaturePointer,
		EnvAVHTTPHealthURL, EnvAVHTTPMaxScanBytes, EnvAVHTTPTimeout,
	}
)

// loadEngines reads the variables of the selected ICAP or HTTP engine and
// warns about those of an engine that is not selected.
func (l *loader) loadEngines(c *Config) {
	if c.AntivirusEngine != EngineICAP {
		l.warnIgnored(icapVars, EngineICAP, c.AntivirusEngine)
	}
	if c.AntivirusEngine != EngineHTTP {
		l.warnIgnored(avhttpVars, EngineHTTP, c.AntivirusEngine)
	}
	switch c.AntivirusEngine {
	case EngineICAP:
		l.loadICAP(c)
	case EngineHTTP:
		l.loadAVHTTP(c)
	}
}

// warnIgnored records a warning for each variable of names that is set.
func (l *loader) warnIgnored(names []string, owner, selected AntivirusEngine) {
	for _, name := range names {
		if l.get(name) != "" {
			l.warnings = append(l.warnings, fmt.Sprintf("%s is ignored: it configures the %s engine, but %s is %s",
				name, owner, EnvAntivirusEngine, selected))
		}
	}
}

// loadICAP reads the TT_ICAP_* variables.
func (l *loader) loadICAP(c *Config) {
	ic := ICAPConfig{}
	raw := l.get(EnvICAPURL)
	var scheme string
	if raw == "" {
		l.fail(EnvICAPURL, "is required when %s is %s", EnvAntivirusEngine, EngineICAP)
	} else if u, err := parseEngineURL(raw, "icap", "icaps"); err != nil {
		l.fail(EnvICAPURL, "%v", err)
	} else if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		l.fail(EnvICAPURL, "must not contain a query or a fragment")
	} else if p := u.EscapedPath(); p == "" || p == "/" {
		l.fail(EnvICAPURL, "must name the ICAP service (e.g. icap://icap:1344/avscan)")
	} else {
		ic.URL, scheme = raw, u.Scheme
	}
	ic.CAFile, ic.CAPEM = l.engineCAFile(EnvICAPCAFile, EnvICAPURL, scheme, "icaps")
	headers := splitList(l.getOr(EnvICAPInfectionHeaders, DefaultICAPInfectionHeaders))
	for _, h := range headers {
		if !isHeaderToken(h) {
			l.fail(EnvICAPInfectionHeaders, "%q is not a valid header name", h)
		}
	}
	if len(headers) == 0 {
		l.fail(EnvICAPInfectionHeaders, "must list at least one header name")
	}
	ic.InfectionHeaders = headers
	ic.MaxScanBytes = l.engineMaxScanBytes(EnvICAPMaxScanBytes, EngineICAP,
		"c-icap virus_scan MaxObjectSize, squidclamav maxsize")
	ic.Timeout = l.duration(EnvICAPTimeout, DefaultEngineTimeout, minClamAVTimeout, maxClamAVTimeout)
	c.ICAP = ic
}

// loadAVHTTP reads the TT_AVHTTP_* variables.
func (l *loader) loadAVHTTP(c *Config) {
	hc := AVHTTPConfig{}
	raw := l.get(EnvAVHTTPURL)
	var scheme string
	if raw == "" {
		l.fail(EnvAVHTTPURL, "is required when %s is %s", EnvAntivirusEngine, EngineHTTP)
	} else if u, err := parseEngineURL(raw, "http", "https"); err != nil {
		l.fail(EnvAVHTTPURL, "%v", err)
	} else {
		hc.URL, scheme = raw, u.Scheme
	}
	if health := l.get(EnvAVHTTPHealthURL); health != "" {
		if _, err := parseEngineURL(health, "http", "https"); err != nil {
			l.fail(EnvAVHTTPHealthURL, "%v", err)
		} else {
			hc.HealthURL = health
		}
	}
	hc.Method = strings.ToUpper(l.getOr(EnvAVHTTPMethod, DefaultAVHTTPMethod))
	if hc.Method != "POST" && hc.Method != "PUT" {
		l.fail(EnvAVHTTPMethod, "%q is not supported (use POST or PUT)", hc.Method)
	}
	hc.Body = strings.ToLower(l.getOr(EnvAVHTTPBody, DefaultAVHTTPBody))
	if hc.Body != AVHTTPBodyMultipart && hc.Body != AVHTTPBodyRaw {
		l.fail(EnvAVHTTPBody, "%q is not supported (use %s or %s)", hc.Body, AVHTTPBodyMultipart, AVHTTPBodyRaw)
	}
	hc.MultipartField = l.getOr(EnvAVHTTPMultipartField, DefaultAVHTTPMultipartField)
	if !validFieldName(hc.MultipartField) {
		l.fail(EnvAVHTTPMultipartField, "must be 1 to %d letters, digits, '.', '_' or '-'", maxMultipartFieldLen)
	}
	hc.AuthHeader = l.authHeaderFile(EnvAVHTTPAuthHeaderFile)
	if hc.AuthHeader.IsSet() && scheme == "http" {
		l.warnings = append(l.warnings, fmt.Sprintf("%s is sent in cleartext: %s uses http://; "+
			"use https://, or keep the engine on a trusted internal network only",
			EnvAVHTTPAuthHeaderFile, EnvAVHTTPURL))
	}
	hc.CAFile, hc.CAPEM = l.engineCAFile(EnvAVHTTPCAFile, EnvAVHTTPURL, scheme, "https")
	hc.CleanRule = l.get(EnvAVHTTPCleanRule)
	if hc.CleanRule == "" {
		l.fail(EnvAVHTTPCleanRule, "is required when %s is %s", EnvAntivirusEngine, EngineHTTP)
	} else if !hasPositiveJSONCondition(hc.CleanRule) {
		l.warnings = append(l.warnings, fmt.Sprintf("%s has no positive JSON condition (json:/pointer=value): "+
			"an error body returned with a matching status code would be read as clean; "+
			"add a condition on a field the engine sets only for a clean file, e.g. json:/infected=false",
			EnvAVHTTPCleanRule))
	}
	hc.InfectedRule = l.get(EnvAVHTTPInfectedRule)
	if hc.InfectedRule == "" {
		l.fail(EnvAVHTTPInfectedRule, "is required when %s is %s", EnvAntivirusEngine, EngineHTTP)
	}
	hc.SignaturePointer = l.get(EnvAVHTTPSignaturePointer)
	if hc.SignaturePointer != "" && !strings.HasPrefix(hc.SignaturePointer, "/") {
		l.fail(EnvAVHTTPSignaturePointer, "must be a JSON pointer starting with /")
	}
	hc.MaxScanBytes = l.engineMaxScanBytes(EnvAVHTTPMaxScanBytes, EngineHTTP,
		"e.g. the StreamMaxLength of the clamd behind clamav-rest")
	hc.Timeout = l.duration(EnvAVHTTPTimeout, DefaultEngineTimeout, minClamAVTimeout, maxClamAVTimeout)
	c.AVHTTP = hc
}

// engineMaxScanBytes reads the TT_*_MAX_SCAN_BYTES variable name of the
// ICAP or HTTP engine. It is required, without a default: such engines
// answer "clean" (ICAP 204, unchanged echo, 2xx) for an object above their
// own size limit without analyzing it, so the value must be chosen at most
// equal to that limit (limits names it for the engine), and larger files
// are then delivered marked not analyzed (too large) instead.
func (l *loader) engineMaxScanBytes(name string, engine AntivirusEngine, limits string) int64 {
	raw := l.get(name)
	if raw == "" {
		l.fail(name, "is required when %s is %s: set it at most to the engine's own size limit (%s), "+
			"since the engine reports a larger file clean without analyzing it; files above this value "+
			"are delivered marked not analyzed (too large)", EnvAntivirusEngine, engine, limits)
		return 0
	}
	n, err := parseInt64(raw, minEngineMaxScanBytes, maxEngineMaxScanBytes)
	if err != nil {
		l.fail(name, "%v", err)
	}
	return n
}

// hasPositiveJSONCondition reports whether the verdict rule has at least
// one json:<pointer>=<literal> condition (not "!="), following the grammar
// of antivirus.Rule: the pointer extends to the first "=", and a trailing
// "!" makes the operator "!=". The rule itself is validated by the
// application (antivirus.ParseRule).
func hasPositiveJSONCondition(rule string) bool {
	for _, part := range strings.Split(rule, "&&") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(part), "json:")
		if !ok {
			continue
		}
		if ptr, _, ok := strings.Cut(rest, "="); ok && !strings.HasSuffix(ptr, "!") {
			return true
		}
	}
	return false
}

// parseEngineURL parses the URL of an engine: one of the two schemes,
// a host, no credentials. The errors never quote the URL, which may carry
// secrets.
func parseEngineURL(raw, plain, secure string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, fmt.Errorf("is not a valid URL")
	case u.Scheme != plain && u.Scheme != secure:
		return nil, fmt.Errorf("must use the %s:// or %s:// scheme", plain, secure)
	case u.User != nil:
		return nil, fmt.Errorf("must not contain credentials")
	case u.Opaque != "" || u.Hostname() == "":
		return nil, fmt.Errorf("must name a host")
	}
	if p := u.Port(); p != "" {
		if err := parsePort(p); err != nil {
			return nil, fmt.Errorf("has an invalid port")
		}
	}
	return u, nil
}

// engineCAFile reads the CA file variable name of an engine, only allowed
// when the scheme of the engine URL (urlVar) is secure: an absolute path
// to a readable file holding at least one PEM certificate. It returns the
// cleaned path and the content, "" and nil when unset or invalid. An
// invalid or missing URL (scheme "") is reported by the URL variable.
func (l *loader) engineCAFile(name, urlVar, scheme, secure string) (string, []byte) {
	raw := l.get(name)
	if raw == "" {
		return "", nil
	}
	if scheme != "" && scheme != secure {
		l.fail(name, "is only allowed with a %s:// %s", secure, urlVar)
		return "", nil
	}
	path, err := checkAbsPath(raw)
	if err != nil {
		l.fail(name, "%q %v", raw, err)
		return "", nil
	}
	data, err := l.readFile(path)
	if err != nil {
		l.fail(name, "cannot read file: %v", err)
		return "", nil
	}
	if !x509.NewCertPool().AppendCertsFromPEM(data) {
		l.fail(name, "the file holds no PEM certificate")
		return "", nil
	}
	return path, data
}

// authHeaderFile reads the optional file of name holding one "Name: value"
// header line (trailing newline trimmed). Neither the line nor any part of
// it ever appears in a problem.
func (l *loader) authHeaderFile(name string) Secret {
	raw := l.get(name)
	if raw == "" {
		return Secret{}
	}
	path, err := checkAbsPath(raw)
	if err != nil {
		l.fail(name, "%v", err)
		return Secret{}
	}
	data, err := l.readFile(path)
	if err != nil {
		l.fail(name, "cannot read file: %v", err)
		return Secret{}
	}
	line := strings.TrimRight(string(data), "\r\n")
	if reason := checkAuthHeader(line); reason != "" {
		l.fail(name, "%s", reason)
		return Secret{}
	}
	return NewSecret(line)
}

// checkAuthHeader validates a "Name: value" header line and returns the
// problem, "" when valid. The reason never quotes the line.
func checkAuthHeader(line string) string {
	name, value, ok := strings.Cut(line, ":")
	switch {
	case !ok:
		return `the file must hold one "Name: value" header line`
	case !isHeaderToken(name):
		return "the header name in the file is not valid"
	}
	value = strings.Trim(value, " \t")
	if value == "" {
		return "the header value in the file is empty"
	}
	for i := range len(value) {
		if b := value[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return "the header line in the file holds a control character or several lines"
		}
	}
	return ""
}

// isHeaderToken reports whether s is a non-empty HTTP token (RFC 9110), as
// header names are.
func isHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if !isAlnumByte(b) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			return false
		}
	}
	return true
}

// validFieldName reports whether s is a safe multipart field name: 1 to
// maxMultipartFieldLen letters, digits, '.', '_' or '-'.
func validFieldName(s string) bool {
	if s == "" || len(s) > maxMultipartFieldLen {
		return false
	}
	for i := range len(s) {
		if b := s[i]; !isAlnumByte(b) && b != '.' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

// isAlnumByte reports whether b is an ASCII letter or digit.
func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
