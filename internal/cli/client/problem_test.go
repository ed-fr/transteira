package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// problemOf builds a non-2xx answer and reads it with readProblem, which
// closes the body.
func problemOf(status int, contentType, body string, header map[string]string, now time.Time) *Problem {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	for k, v := range header {
		h.Set(k, v)
	}
	return readProblem(&http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}, now)
}

func TestReadProblem(t *testing.T) {
	now := time.Now()
	body := `{"type":"https://docs.example.com/errors/transfer-password-invalid","title":"Wrong password",
		"status":403,"detail":"Try again","instance":"req-instance","code":"transfer-password-invalid",
		"attemptsRemaining":2,"retryAfterSeconds":30,"maxTransferBytes":20000000000,
		"errors":[{"field":"/recipients/0","code":"invalid","message":"bad"}]}`
	p := problemOf(403, "application/problem+json", body, nil, now)
	if p.Status != 403 || p.Code != "transfer-password-invalid" || p.Title != "Wrong password" || p.Detail != "Try again" ||
		p.Type == "" || p.Instance != "req-instance" || p.RequestID != "req-instance" {
		t.Fatalf("members: %+v", p)
	}
	if p.AttemptsRemaining == nil || *p.AttemptsRemaining != 2 || p.RetryAfter != 30*time.Second {
		t.Fatalf("extensions: %+v", p)
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "/recipients/0" || p.Errors[0].Message != "bad" {
		t.Fatalf("errors: %+v", p.Errors)
	}
	if _, ok := p.Extensions["maxTransferBytes"]; !ok || p.Extensions["code"] != nil || len(p.Extensions) != 4 {
		t.Fatalf("raw extensions: %v", p.Extensions)
	}

	// The header wins over the body for the request id and Retry-After.
	p = problemOf(429, "application/problem+json", `{"instance":"i","retryAfterSeconds":30}`,
		map[string]string{"X-Request-Id": "hdr", "Retry-After": "5"}, now)
	if p.RequestID != "hdr" || p.RetryAfter != 5*time.Second {
		t.Fatalf("header precedence: %+v", p)
	}

	// tus: no body at all.
	p = problemOf(410, "", "", map[string]string{"Tus-Resumable": "1.0.0"}, now)
	if p.Status != 410 || p.Code != "" || p.Extensions != nil || p.Error() != "HTTP 410: Gone" {
		t.Fatalf("empty: %+v %q", p, p.Error())
	}

	// Bodies ignored: oversized, invalid JSON, not JSON, unreadable, odd members.
	big := `{"code":"x","detail":"` + strings.Repeat("a", MaxProblemBytes) + `"}`
	for name, c := range map[string][2]string{
		"oversized": {"application/problem+json", big},
		"invalid":   {"application/problem+json", `{"code":`},
		"html":      {"text/html", `{"code":"x"}`},
		"bad type":  {"application/problem+json; =", `{"code":"x"}`},
	} {
		if p := problemOf(400, c[0], c[1], nil, now); p.Code != "" || p.Status != 400 {
			t.Errorf("%s: %+v", name, p)
		}
	}
	unreadable := &http.Response{
		StatusCode: 500, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(errReader{}),
	}
	if p := readProblem(unreadable, now); p.Status != 500 || p.Code != "" {
		t.Errorf("unreadable: %+v", p)
	}
	p = problemOf(400, "application/json", `{"code":5,"attemptsRemaining":-1,"retryAfterSeconds":"x","errors":"no"}`, nil, now)
	if p.Code != "" || p.AttemptsRemaining != nil || p.RetryAfter != 0 || p.Errors != nil {
		t.Errorf("odd members: %+v", p)
	}
	// Huge retryAfterSeconds is capped.
	p = problemOf(503, "application/json", `{"retryAfterSeconds":99999999999}`, nil, now)
	if p.RetryAfter != 24*time.Hour {
		t.Errorf("cap: %v", p.RetryAfter)
	}
}

// errReader fails every read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

func TestProblemError(t *testing.T) {
	p := &Problem{
		Status: 401, Code: "invalid-credentials", Title: "Bad\x1b[31m token", Detail: "line1\nline2" + rlo,
		RequestID: "req-1", Method: "GET", Path: "/api/v1/transfers",
	}
	want := "GET /api/v1/transfers: HTTP 401 invalid-credentials: Bad�[31m token (line1 line2�) [request req-1]"
	if p.Error() != want {
		t.Fatalf("got %q\nwant %q", p.Error(), want)
	}
	if got := (&Problem{Status: 599}).Error(); got != "HTTP 599" {
		t.Fatalf("unknown status: %q", got)
	}
}

func TestRetryableStatus(t *testing.T) {
	for _, s := range []int{408, 429, 500, 502, 503, 504, 599} {
		if !(&Problem{Status: s}).Retryable() {
			t.Errorf("%d not retryable", s)
		}
	}
	for _, s := range []int{301, 302, 400, 401, 403, 404, 409, 410, 413, 422, 501, 507, 600} {
		if (&Problem{Status: s}).Retryable() {
			t.Errorf("%d retryable", s)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"0", 0, true},
		{" 120 ", 2 * time.Minute, true},
		{"86401", 24 * time.Hour, true},
		{"99999999999999999999999", 24 * time.Hour, true},
		{"12a", 0, false},
		{"-5", 0, false},
		{"1.5", 0, false},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second, true},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0, true},
		{now.Add(48 * time.Hour).Format(http.TimeFormat), 24 * time.Hour, true},
		{"Saturday, 07-Nov-26 10:01:00 GMT", time.Minute, true},
		{"tomorrow", 0, false},
	}
	for _, tc := range cases {
		d, ok := ParseRetryAfter(tc.in, now)
		if d != tc.want || ok != tc.ok {
			t.Errorf("%q: got %v %v, want %v %v", tc.in, d, ok, tc.want, tc.ok)
		}
	}
}

func FuzzRetryAfter(f *testing.F) {
	for _, s := range []string{"", "0", "120", "99999999999", "Sat, 07 Nov 2026 10:00:30 GMT", "x", "-1", "1e3"} {
		f.Add(s)
	}
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		d, ok := ParseRetryAfter(s, now)
		if d < 0 || d > 24*time.Hour || (!ok && d != 0) {
			t.Fatalf("%q: %v %v", s, d, ok)
		}
	})
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf":          "/api/v1/downloads/dl_Xk4L…",
		"/api/v1/uploads/upl_7Hq2Wm9Zx4Lp1Vb8Rt3Yk6Nd":             "/api/v1/uploads/upl_7Hq2…",
		"Bearer tt_" + strings.Repeat("A", 43):                     "Bearer tt_AAAA…",
		"https://transfer.example.com/d/dl_Xk4Lm9Qp2Zr7Vb1N#k=key": "https://transfer.example.com/d/dl_Xk4L…",
		"/x?code=123456":              "/x",
		"/api/v1/transfers/trf_short": "/api/v1/transfers/trf_short",
		"/a\x1b[2J":                   "/a�[2J",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
