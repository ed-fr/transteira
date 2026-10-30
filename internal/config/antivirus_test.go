package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Fictitious engine settings of the tests.
const (
	testICAPURL   = "icap://icap:1344/avscan"
	testAVHTTPURL = "https://scanner.example.com/api/v1/scan"
	testClean     = "status=200 && json:/infected=false"
	testInfected  = "status=200 && json:/infected=true"
	testAuthFile  = "/run/secrets/avhttp_auth"
	testAuthLine  = "Authorization: Bearer s3cr3t-t0ken"
	testMaxScan   = "2147483648"
)

// httpEngineVars returns the minimal valid variables of the http engine,
// with extra on top.
func httpEngineVars(extra map[string]string) map[string]string {
	m := map[string]string{
		EnvAntivirusEngine: "http", EnvAVHTTPURL: testAVHTTPURL,
		EnvAVHTTPCleanRule: testClean, EnvAVHTTPInfectedRule: testInfected, EnvAVHTTPMaxScanBytes: testMaxScan,
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// icapEngineVars returns the minimal valid variables of the icap engine,
// with extra on top.
func icapEngineVars(extra map[string]string) map[string]string {
	m := map[string]string{EnvAntivirusEngine: "icap", EnvICAPURL: testICAPURL, EnvICAPMaxScanBytes: testMaxScan}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// fakeFiles returns a WithReadFile option serving files, and an error for
// any other path.
func fakeFiles(files map[string]string) Option {
	return WithReadFile(func(name string) ([]byte, error) {
		for p, v := range files {
			if filepath.Clean(p) == name {
				return []byte(v), nil
			}
		}
		return nil, os.ErrNotExist
	})
}

func TestICAPDefaults(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, icapEngineVars(nil))
	want := []string{"X-Infection-Found", "X-Virus-ID", "X-Violations-Found"}
	if c.ICAP.URL != testICAPURL || !slices.Equal(c.ICAP.InfectionHeaders, want) || c.ICAP.MaxScanBytes != 2<<30 ||
		c.ICAP.Timeout != 10*time.Minute || c.ICAP.CAFile != "" || c.ICAP.CAPEM != nil {
		t.Errorf("ICAP = %+v", c.ICAP)
	}
	if c.AVHTTP.URL != "" || len(c.Warnings) != 0 {
		t.Errorf("AVHTTP = %+v, warnings %v", c.AVHTTP, c.Warnings)
	}
}

func TestICAPFull(t *testing.T) {
	t.Parallel()
	ca := writeTestCA(t, t.TempDir())
	c := mustLoad(t, icapEngineVars(map[string]string{
		EnvICAPURL: "icaps://icap.example.com:11344/srv_clamav", EnvICAPCAFile: ca,
		EnvICAPInfectionHeaders: " X-Virus-Name , X-Infection-Found", EnvICAPMaxScanBytes: "1048576",
		EnvICAPTimeout: "2h",
	}))
	if c.ICAP.URL != "icaps://icap.example.com:11344/srv_clamav" || c.ICAP.CAFile != ca || len(c.ICAP.CAPEM) == 0 ||
		!slices.Equal(c.ICAP.InfectionHeaders, []string{"X-Virus-Name", "X-Infection-Found"}) ||
		c.ICAP.MaxScanBytes != 1<<20 || c.ICAP.Timeout != 2*time.Hour {
		t.Errorf("ICAP = %+v", c.ICAP)
	}
}

func TestAVHTTPDefaults(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, httpEngineVars(nil))
	h := c.AVHTTP
	if h.URL != testAVHTTPURL || h.Method != "POST" || h.Body != AVHTTPBodyMultipart || h.MultipartField != "file" ||
		h.AuthHeader.IsSet() || h.CAPEM != nil || h.CleanRule != testClean || h.InfectedRule != testInfected ||
		h.SignaturePointer != "" || h.HealthURL != "" || h.MaxScanBytes != 2<<30 || h.Timeout != 10*time.Minute {
		t.Errorf("AVHTTP = %+v", h)
	}
	if c.ICAP.URL != "" {
		t.Errorf("ICAP = %+v", c.ICAP)
	}
}

func TestAVHTTPFull(t *testing.T) {
	t.Parallel()
	ca := writeTestCA(t, t.TempDir())
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	c := mustLoad(t, httpEngineVars(map[string]string{
		EnvAVHTTPMethod: "put", EnvAVHTTPBody: "RAW", EnvAVHTTPMultipartField: "upload.file_1",
		EnvAVHTTPAuthHeaderFile: testAuthFile, EnvAVHTTPCAFile: "/etc/ca.pem",
		EnvAVHTTPSignaturePointer: "/viruses/0", EnvAVHTTPHealthURL: "https://scanner.example.com/health",
		EnvAVHTTPMaxScanBytes: "21474836480", EnvAVHTTPTimeout: "10s",
	}), fakeFiles(map[string]string{testAuthFile: testAuthLine + "\r\n", "/etc/ca.pem": string(pem)}))
	h := c.AVHTTP
	if h.Method != "PUT" || h.Body != AVHTTPBodyRaw || h.MultipartField != "upload.file_1" ||
		h.AuthHeader.Reveal() != testAuthLine || h.CAFile != filepath.Clean("/etc/ca.pem") || string(h.CAPEM) != string(pem) ||
		h.SignaturePointer != "/viruses/0" || h.HealthURL != "https://scanner.example.com/health" ||
		h.MaxScanBytes != 20<<30 || h.Timeout != 10*time.Second {
		t.Errorf("AVHTTP = %+v", h)
	}
}

func TestEngineInvalid(t *testing.T) {
	t.Parallel()
	files := fakeFiles(map[string]string{
		"/etc/ca.pem":         "not a certificate",
		"/run/no-colon":       "Bearer s3cr3t-t0ken\n",
		"/run/bad-name":       "Auth orization: s3cr3t-t0ken",
		"/run/empty-value":    "X-Api-Key:   \n",
		"/run/two-lines":      "X-Api-Key: s3cr3t-t0ken\nX-Other: s3cr3t-t0ken",
		"/run/control":        "X-Api-Key: s3cr3t\x00t0ken",
		"/run/secrets/ca.pem": "unused",
		// Valid header files, refused only for their place in a volume.
		DefaultDataDir + "/avhttp_auth":   testAuthLine,
		DefaultBackupDir + "/avhttp_auth": testAuthLine,
	})
	tests := []struct {
		name string
		vars map[string]string
		want []string
	}{
		{"icap bad scheme", icapEngineVars(map[string]string{EnvICAPURL: "http://icap:1344/avscan"}), []string{EnvICAPURL}},
		{"icap credentials", icapEngineVars(map[string]string{EnvICAPURL: "icap://user:s3cr3t-t0ken@icap/avscan"}), []string{EnvICAPURL}},
		{"icap query", icapEngineVars(map[string]string{EnvICAPURL: "icap://icap/avscan?key=s3cr3t-t0ken"}), []string{EnvICAPURL}},
		{"icap fragment", icapEngineVars(map[string]string{EnvICAPURL: "icap://icap/avscan#x"}), []string{EnvICAPURL}},
		{"icap no service", icapEngineVars(map[string]string{EnvICAPURL: "icap://icap:1344/"}), []string{EnvICAPURL}},
		{"icap no host", icapEngineVars(map[string]string{EnvICAPURL: "icap:///avscan"}), []string{EnvICAPURL}},
		{"icap bad port", icapEngineVars(map[string]string{EnvICAPURL: "icap://icap:99999/avscan"}), []string{EnvICAPURL}},
		{"icap malformed", icapEngineVars(map[string]string{EnvICAPURL: "icap://ic ap/%zz"}), []string{EnvICAPURL}},
		{"icap CA with cleartext", icapEngineVars(map[string]string{EnvICAPCAFile: "/run/secrets/ca.pem"}), []string{EnvICAPCAFile}},
		{"icap CA relative", icapEngineVars(map[string]string{EnvICAPURL: "icaps://icap/avscan", EnvICAPCAFile: "ca.pem"}), []string{EnvICAPCAFile}},
		{"icap CA unreadable", icapEngineVars(map[string]string{EnvICAPURL: "icaps://icap/avscan", EnvICAPCAFile: "/nowhere.pem"}), []string{EnvICAPCAFile}},
		{"icap CA not PEM", icapEngineVars(map[string]string{EnvICAPURL: "icaps://icap/avscan", EnvICAPCAFile: "/etc/ca.pem"}), []string{EnvICAPCAFile}},
		{"icap bad header", icapEngineVars(map[string]string{EnvICAPInfectionHeaders: "X-Virus-ID,X Bad"}), []string{EnvICAPInfectionHeaders}},
		{"icap no header", icapEngineVars(map[string]string{EnvICAPInfectionHeaders: " , "}), []string{EnvICAPInfectionHeaders}},
		{"icap scan bytes too small", icapEngineVars(map[string]string{EnvICAPMaxScanBytes: "1048575"}), []string{EnvICAPMaxScanBytes}},
		{"icap scan bytes too big", icapEngineVars(map[string]string{EnvICAPMaxScanBytes: "21474836481"}), []string{EnvICAPMaxScanBytes}},
		{"icap scan bytes missing", icapEngineVars(map[string]string{EnvICAPMaxScanBytes: ""}), []string{EnvICAPMaxScanBytes}},
		{"icap timeout too short", icapEngineVars(map[string]string{EnvICAPTimeout: "9s"}), []string{EnvICAPTimeout}},
		{"http bad scheme", httpEngineVars(map[string]string{EnvAVHTTPURL: "ftp://scanner/scan"}), []string{EnvAVHTTPURL}},
		{"http credentials", httpEngineVars(map[string]string{EnvAVHTTPURL: "https://user:s3cr3t-t0ken@scanner/scan"}), []string{EnvAVHTTPURL}},
		{"http no host", httpEngineVars(map[string]string{EnvAVHTTPURL: "https:///scan"}), []string{EnvAVHTTPURL}},
		{"http health credentials", httpEngineVars(map[string]string{EnvAVHTTPHealthURL: "http://u:s3cr3t-t0ken@scanner/h"}), []string{EnvAVHTTPHealthURL}},
		{"http method", httpEngineVars(map[string]string{EnvAVHTTPMethod: "GET"}), []string{EnvAVHTTPMethod}},
		{"http body", httpEngineVars(map[string]string{EnvAVHTTPBody: "json"}), []string{EnvAVHTTPBody}},
		{"http field", httpEngineVars(map[string]string{EnvAVHTTPMultipartField: "file name"}), []string{EnvAVHTTPMultipartField}},
		{"http field too long", httpEngineVars(map[string]string{EnvAVHTTPMultipartField: strings.Repeat("f", 65)}), []string{EnvAVHTTPMultipartField}},
		{"http CA with cleartext", httpEngineVars(map[string]string{EnvAVHTTPURL: "http://scanner/scan", EnvAVHTTPCAFile: "/run/secrets/ca.pem"}), []string{EnvAVHTTPCAFile}},
		{"http CA not PEM", httpEngineVars(map[string]string{EnvAVHTTPCAFile: "/etc/ca.pem"}), []string{EnvAVHTTPCAFile}},
		{"http pointer", httpEngineVars(map[string]string{EnvAVHTTPSignaturePointer: "viruses/0"}), []string{EnvAVHTTPSignaturePointer}},
		{"http auth relative", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "auth"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth in data volume", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: DefaultDataDir + "/avhttp_auth"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth in backup volume", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: DefaultBackupDir + "/avhttp_auth"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth unreadable", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "/run/none"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth no colon", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "/run/no-colon"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth bad name", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "/run/bad-name"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth empty value", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "/run/empty-value"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth two lines", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "/run/two-lines"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http auth control", httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: "/run/control"}), []string{EnvAVHTTPAuthHeaderFile}},
		{"http scan bytes", httpEngineVars(map[string]string{EnvAVHTTPMaxScanBytes: "2G"}), []string{EnvAVHTTPMaxScanBytes}},
		{"http scan bytes missing", httpEngineVars(map[string]string{EnvAVHTTPMaxScanBytes: ""}), []string{EnvAVHTTPMaxScanBytes}},
		{"http timeout", httpEngineVars(map[string]string{EnvAVHTTPTimeout: "3h"}), []string{EnvAVHTTPTimeout}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verr := mustFail(t, tc.vars, files)
			var got []string
			for _, p := range verr.Problems {
				got = append(got, p.Variable)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("problems on %v, want %v\n%v", got, tc.want, verr)
			}
			// Neither the credentials of a URL nor the auth header line
			// ever appear in the error.
			if msg := verr.Error(); strings.Contains(msg, "s3cr3t") || strings.Contains(msg, "Bearer") {
				t.Fatalf("secret in error: %s", msg)
			}
		})
	}
}

func TestEngineWarnings(t *testing.T) {
	t.Parallel()
	// Variables of the engines not selected are ignored with a warning,
	// never validated, and the warning never quotes the value.
	c := mustLoad(t, map[string]string{
		EnvICAPURL: "icap://user:s3cr3t-t0ken@icap/avscan", EnvAVHTTPCleanRule: "nonsense", EnvAVHTTPAuthHeaderFile: "rel",
	})
	if c.ICAP.URL != "" || c.AVHTTP.CleanRule != "" || len(c.Warnings) != 3 {
		t.Fatalf("config %+v %+v, warnings %v", c.ICAP, c.AVHTTP, c.Warnings)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "s3cr3t") || !strings.Contains(w, "is ignored") || !strings.Contains(w, "TT_ANTIVIRUS_ENGINE is clamd") {
			t.Errorf("warning %q", w)
		}
	}
	if !strings.HasPrefix(c.Warnings[0], EnvICAPURL+" ") {
		t.Errorf("first warning %q", c.Warnings[0])
	}
	c = mustLoad(t, icapEngineVars(map[string]string{EnvAVHTTPURL: testAVHTTPURL}))
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "the http engine") {
		t.Fatalf("warnings %v", c.Warnings)
	}
	c = mustLoad(t, httpEngineVars(map[string]string{EnvICAPTimeout: "1m"}))
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "the icap engine") {
		t.Fatalf("warnings %v", c.Warnings)
	}
	if c := mustLoad(t, map[string]string{EnvAntivirusEngine: "none"}); c.Warnings != nil {
		t.Fatalf("warnings %v", c.Warnings)
	}
}

func TestEngineMaxScanBytesRequired(t *testing.T) {
	t.Parallel()
	// The error explains why there is no default: the engine reports a
	// larger file clean without analyzing it.
	for _, tc := range []struct {
		vars  map[string]string
		name  string
		limit string
	}{
		{icapEngineVars(map[string]string{EnvICAPMaxScanBytes: ""}), EnvICAPMaxScanBytes, "MaxObjectSize"},
		{httpEngineVars(map[string]string{EnvAVHTTPMaxScanBytes: ""}), EnvAVHTTPMaxScanBytes, "StreamMaxLength"},
	} {
		msg := mustFail(t, tc.vars).Error()
		if !strings.Contains(msg, tc.name+": is required") || !strings.Contains(msg, tc.limit) ||
			!strings.Contains(msg, "clean without analyzing") {
			t.Errorf("error = %s", msg)
		}
	}
}

func TestAVHTTPCleanRuleWarning(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rule string
		warn bool
	}{
		{testClean, false},
		{"json:/Status=\"OK\"", false},
		{"status=200", true},
		{"status=200-299 && json:/infected!=true", true},
		{"json:/viruses!=[] && json:/error!=null", true},
		{" json:/a!= 1 && json:/b = 2 ", false},
	} {
		c := mustLoad(t, httpEngineVars(map[string]string{EnvAVHTTPCleanRule: tc.rule}))
		got := len(c.Warnings) == 1 && strings.HasPrefix(c.Warnings[0], EnvAVHTTPCleanRule+" ") &&
			strings.Contains(c.Warnings[0], "read as clean")
		if got != tc.warn || (!tc.warn && len(c.Warnings) != 0) {
			t.Errorf("rule %q: warnings %v", tc.rule, c.Warnings)
		}
	}
}

func TestAVHTTPAuthHeaderCleartextWarning(t *testing.T) {
	t.Parallel()
	files := fakeFiles(map[string]string{testAuthFile: testAuthLine})
	c := mustLoad(t, httpEngineVars(map[string]string{
		EnvAVHTTPURL: "http://scanner/scan", EnvAVHTTPAuthHeaderFile: testAuthFile,
	}), files)
	if len(c.Warnings) != 1 || !strings.HasPrefix(c.Warnings[0], EnvAVHTTPAuthHeaderFile+" ") ||
		!strings.Contains(c.Warnings[0], "cleartext") || strings.Contains(c.Warnings[0], "s3cr3t") {
		t.Fatalf("warnings %v", c.Warnings)
	}
	// Over https, or without the header, no warning.
	if c := mustLoad(t, httpEngineVars(map[string]string{EnvAVHTTPAuthHeaderFile: testAuthFile}), files); len(c.Warnings) != 0 {
		t.Fatalf("https warnings %v", c.Warnings)
	}
	if c := mustLoad(t, httpEngineVars(map[string]string{EnvAVHTTPURL: "http://scanner/scan"})); len(c.Warnings) != 0 {
		t.Fatalf("no header warnings %v", c.Warnings)
	}
}

func TestEngineHelpers(t *testing.T) {
	t.Parallel()
	if isHeaderToken("") || !isHeaderToken("X-Virus-ID") || isHeaderToken("X:Y") {
		t.Error("isHeaderToken")
	}
	if validFieldName("") || !validFieldName("a.b_c-1") || validFieldName("a/b") {
		t.Error("validFieldName")
	}
	if checkAuthHeader("X-Api-Key: v\talue") != "" {
		t.Error("tab refused in the header value")
	}
	if _, err := parseEngineURL("https://scanner:0x/scan", "http", "https"); err == nil {
		t.Error("bad port accepted")
	}
}
