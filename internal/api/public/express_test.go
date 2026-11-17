package public

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// expressBody is a well-formed creation body.
const expressBody = `{"encryptedText":"` + sealedFixture + `","verifier":"` + hex64 + `","keyVerifier":"` + hex64 + `","expiresIn":"1d"}`

// hex64 is a verifier of the right form.
const hex64 = "2efe6abcc112e614f12b2074e79d465dd5d572d0947646f62ddd9b0d01e3cfb1"

// expressCtx returns the context of an anonymous creation carrying raw as
// the body kept by CaptureRawBody.
func expressCtx(t *testing.T, raw string) context.Context {
	t.Helper()
	return context.WithValue(depositCtx(t, nil), rawBodyKey{}, []byte(raw))
}

func TestCreateExpressSecret(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	f := &fakeSecrets{created: secret.Created{ID: "sec_1", Token: "tts_t", State: store.SecretActive, ExpiresAt: expires}}
	srv := NewServer(WithSecrets(f))
	resp, err := srv.CreateExpressSecret(expressCtx(t, expressBody), gen.CreateExpressSecretRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.CreateExpressSecret201JSONResponse)
	if got.Body.Id != "sec_1" || got.Body.Token != "tts_t" || got.Body.State != "active" || got.Body.ExpiresAt == nil ||
		!got.Body.ExpiresAt.Equal(expires) || got.Headers.CacheControl == nil || *got.Headers.CacheControl != "no-store" {
		t.Errorf("response = %+v", got)
	}
	want := secret.ExpressCreateRequest{EncryptedText: sealedFixture, Verifier: hex64, KeyVerifier: hex64, ExpiresIn: "1d"}
	if !equalExpress(f.expressReq, want) {
		t.Errorf("request = %+v", f.expressReq)
	}
	if f.creator.ClientIP != clientIP || f.creator.APITokenID != "" || f.creator.ExpressAllowed {
		t.Errorf("anonymous creator = %+v", f.creator)
	}

	// With an API token: the token and its opt-in reach the service.
	ctx := middleware.WithAPIToken(expressCtx(t, expressBody), middleware.TokenPrincipal{TokenID: "tok_1", ExpressAllowed: true})
	if _, err := srv.CreateExpressSecret(ctx, gen.CreateExpressSecretRequestObject{}); err != nil {
		t.Fatal(err)
	}
	if f.creator.APITokenID != "tok_1" || !f.creator.ExpressAllowed || f.creator.ClientIP != clientIP {
		t.Errorf("token creator = %+v", f.creator)
	}

	// Members outside the schema are passed as pointers, in body order.
	body := strings.Replace(expressBody, `{`, `{"passphrase":{"kdf":"x"},"a/b~c":1,`, 1)
	if _, err := srv.CreateExpressSecret(expressCtx(t, body), gen.CreateExpressSecretRequestObject{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.expressReq.Extra, []string{"/passphrase", "/a~1b~0c"}) || f.expressReq.EncryptedText != sealedFixture {
		t.Errorf("extra = %+v", f.expressReq)
	}
}

// equalExpress compares two creation requests.
func equalExpress(a, b secret.ExpressCreateRequest) bool {
	return a.EncryptedText == b.EncryptedText && a.Verifier == b.Verifier && a.KeyVerifier == b.KeyVerifier &&
		a.ExpiresIn == b.ExpiresIn && slices.Equal(a.Extra, b.Extra)
}

func TestCreateExpressSecretErrors(t *testing.T) {
	t.Parallel()
	// Without the raw body (CaptureRawBody not installed): a wiring error.
	f := &fakeSecrets{}
	srv := NewServer(WithSecrets(f))
	if _, err := srv.CreateExpressSecret(depositCtx(t, nil), gen.CreateExpressSecretRequestObject{}); !errors.Is(err, errNoExpressBody) || f.callCount != 0 {
		t.Errorf("without raw body: %v, %d calls", err, f.callCount)
	}

	// A malformed body still reaches the service, which checks its
	// switches first, with an empty request.
	f.err = secret.ErrExpressDisabled
	_, err := srv.CreateExpressSecret(expressCtx(t, `{`), gen.CreateExpressSecretRequestObject{})
	wantProblem(t, err, problem.CodeExpressSecretsDisabled)
	if f.callCount != 1 || !equalExpress(f.expressReq, secret.ExpressCreateRequest{}) {
		t.Errorf("malformed body: %d calls, request %+v", f.callCount, f.expressReq)
	}
	// Its validation error names no field: the body is not a JSON object.
	f.err = &secret.ValidationError{Fields: []secret.FieldError{{Pointer: secret.FieldEncryptedText, Code: secret.CodeRequired}}}
	_, err = srv.CreateExpressSecret(expressCtx(t, `[1]`), gen.CreateExpressSecretRequestObject{})
	if p := problemOf(t, err, problem.CodeValidationFailed); len(p.Errors) != 0 {
		t.Errorf("malformed body: %+v", p.Errors)
	}
	// A well-formed body gets the fields of the service.
	_, err = srv.CreateExpressSecret(expressCtx(t, `{}`), gen.CreateExpressSecretRequestObject{})
	if p := problemOf(t, err, problem.CodeValidationFailed); len(p.Errors) != 1 || p.Errors[0].Field != secret.FieldEncryptedText {
		t.Errorf("well-formed body: %+v", p.Errors)
	}
	// The other errors of a malformed body are mapped as usual.
	f.err = &secret.RateLimitError{RetryAfter: time.Minute}
	_, err = srv.CreateExpressSecret(expressCtx(t, `x`), gen.CreateExpressSecretRequestObject{})
	if p := problemOf(t, err, problem.CodeRateLimited); p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 60 {
		t.Errorf("rate limited: %+v", p)
	}
	for _, c := range []struct {
		err  error
		code problem.Code
	}{
		{secret.ErrExpressTokenNotAllowed, problem.CodeExpressTokenNotAllowed},
		{fmt.Errorf("wrapped: %w", secret.ErrTokenInvalid), problem.CodeInvalidCredentials},
		{secret.ErrExpressLimit, problem.CodeExpressSecretLimitReached},
		{secret.ErrTenantInSetup, problem.CodeTenantInSetup},
		{&secret.FormatError{Fields: []secret.FieldError{{Pointer: secret.FieldEncryptedText, Code: secret.CodeInvalidFormat}}}, problem.CodeSecretFormatInvalid},
	} {
		f.err = c.err
		_, err := srv.CreateExpressSecret(expressCtx(t, expressBody), gen.CreateExpressSecretRequestObject{})
		wantProblem(t, err, c.code)
	}
}

func TestParseExpressBody(t *testing.T) {
	t.Parallel()
	many := `{`
	for i := range MaxExtraMembers + 3 {
		many += `"x` + strings.Repeat("y", i) + `":0,`
	}
	many += `"expiresIn":"1h"}`
	for _, c := range []struct {
		name, raw  string
		wellFormed bool
		want       secret.ExpressCreateRequest
	}{
		{"complete", expressBody, true, secret.ExpressCreateRequest{EncryptedText: sealedFixture, Verifier: hex64, KeyVerifier: hex64, ExpiresIn: "1d"}},
		{"empty object", `{}`, true, secret.ExpressCreateRequest{}},
		{"null reads as absent", `{"expiresIn":null}`, true, secret.ExpressCreateRequest{}},
		{"last duplicate wins", `{"expiresIn":"1h","expiresIn":"7d"}`, true, secret.ExpressCreateRequest{ExpiresIn: "7d"}},
		{"trailing data ignored", `{"expiresIn":"1h"} trailing`, true, secret.ExpressCreateRequest{ExpiresIn: "1h"}},
		{"nested extra", `{"file":{"size":1,"x":[1,2]},"delivery":"email"}`, true, secret.ExpressCreateRequest{Extra: []string{"/file", "/delivery"}}},
		{"empty name", `{"":1}`, true, secret.ExpressCreateRequest{Extra: []string{"/"}}},
		{"empty", ``, false, secret.ExpressCreateRequest{}},
		{"array", `[]`, false, secret.ExpressCreateRequest{}},
		{"string", `"x"`, false, secret.ExpressCreateRequest{}},
		{"wrong type", `{"expiresIn":7}`, false, secret.ExpressCreateRequest{}},
		{"truncated object", `{"expiresIn":"1h"`, false, secret.ExpressCreateRequest{}},
		{"truncated member", `{"expiresIn":`, false, secret.ExpressCreateRequest{}},
		{"bad key", `{1:2}`, false, secret.ExpressCreateRequest{}},
		{"wrong closing", `{"expiresIn":"1h"]`, false, secret.ExpressCreateRequest{}},
		{"bad value", `{"a":tru}`, false, secret.ExpressCreateRequest{}},
	} {
		got, ok := parseExpressBody([]byte(c.raw))
		if ok != c.wellFormed || !equalExpress(got, c.want) {
			t.Errorf("%s: %+v, %v", c.name, got, ok)
		}
	}
	// The extra members are bounded.
	got, ok := parseExpressBody([]byte(many))
	if !ok || len(got.Extra) != MaxExtraMembers || got.Extra[0] != "/x" || got.ExpiresIn != "1h" {
		t.Errorf("many extra members: %d, %+v", len(got.Extra), got)
	}
}

func TestCaptureRawBody(t *testing.T) {
	t.Parallel()
	var (
		raw     []byte
		kept    bool
		decoded string
	)
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		raw, kept = r.Context().Value(rawBodyKey{}).([]byte)
		b, err := io.ReadAll(r.Body)
		decoded = string(b)
		if err != nil {
			decoded = "error: " + err.Error()
		}
	})
	h := CaptureRawBody(next)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/express-secrets", strings.NewReader(`{"a":1}`))
	req.Pattern = ExpressRoute
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !kept || string(raw) != `{"a":1}` || decoded != `{}` {
		t.Errorf("express route: kept %v %q, decoder reads %q", kept, raw, decoded)
	}
	// Any other route passes untouched.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/secrets", strings.NewReader(`{"a":1}`))
	req.Pattern = http.MethodPost + " /api/v1/secrets"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if kept || decoded != `{"a":1}` {
		t.Errorf("other route: kept %v, decoder reads %q", kept, decoded)
	}
	// A read failure reaches the generated decoder.
	boom := errors.New("http: request body too large")
	req = httptest.NewRequest(http.MethodPost, "/api/v1/express-secrets", iotest.ErrReader(boom))
	req.Pattern = ExpressRoute
	h.ServeHTTP(httptest.NewRecorder(), req)
	if kept || decoded != "error: "+boom.Error() {
		t.Errorf("read failure: kept %v, decoder reads %q", kept, decoded)
	}
}

func TestReportSecretAbuse(t *testing.T) {
	t.Parallel()
	f := &fakeSecrets{}
	srv := NewServer(WithSecrets(f))
	msg := "Asks for my bank password."
	resp, err := srv.ReportSecretAbuse(depositCtx(t, nil), gen.ReportSecretAbuseRequestObject{
		SecretToken: "tts_tok", Body: &gen.AbuseReportCreate{Category: "phishing", Message: &msg},
	})
	if _, ok := resp.(gen.ReportSecretAbuse202Response); err != nil || !ok {
		t.Fatalf("report: %v, %T", err, resp)
	}
	if f.token != "tts_tok" || f.ip != clientIP || f.report.Category != "phishing" || f.report.Message != msg {
		t.Errorf("call = %+v", f)
	}
	// Without body, the service refuses the empty category.
	f.err = &secret.ValidationError{Fields: []secret.FieldError{{Pointer: secret.FieldCategory, Code: secret.CodeRequired}}}
	_, err = srv.ReportSecretAbuse(depositCtx(t, nil), gen.ReportSecretAbuseRequestObject{SecretToken: "tts_tok"})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != secret.FieldCategory || f.report != (secret.AbuseReportRequest{}) {
		t.Errorf("no body: %+v, %+v", p, f.report)
	}
	f.err = &secret.GoneError{Reason: secret.ReasonExpired}
	_, err = srv.ReportSecretAbuse(depositCtx(t, nil), gen.ReportSecretAbuseRequestObject{SecretToken: "tts_tok"})
	if p := problemOf(t, err, problem.CodeSecretGone); p.Reason != "expired" {
		t.Errorf("gone: %+v", p)
	}
}

func TestGetSecretLinkExpress(t *testing.T) {
	t.Parallel()
	f := &fakeSecrets{status: secret.Status{ExpiresAt: time.Now(), Express: true, Anonymous: true}}
	srv := NewServer(WithSecrets(f))
	for _, anonymous := range []bool{true, false} {
		f.status.Anonymous = anonymous
		resp, err := srv.GetSecretLink(depositCtx(t, nil), gen.GetSecretLinkRequestObject{SecretToken: "tts_tok"})
		if err != nil {
			t.Fatal(err)
		}
		b := resp.(gen.GetSecretLink200JSONResponse).Body
		if b.Express == nil || !*b.Express || b.Anonymous == nil || *b.Anonymous != anonymous || b.File != nil || b.Passphrase != nil {
			t.Errorf("express status = %+v", b)
		}
	}
	// A 2.1 secret has neither member.
	f.status = secret.Status{ExpiresAt: time.Now()}
	resp, _ := srv.GetSecretLink(depositCtx(t, nil), gen.GetSecretLinkRequestObject{SecretToken: "tts_tok"})
	raw, _ := json.Marshal(resp.(gen.GetSecretLink200JSONResponse).Body)
	if strings.Contains(string(raw), "express") || strings.Contains(string(raw), "anonymous") {
		t.Errorf("2.1 status = %s", raw)
	}
	// The read block of a closed service, on the status and the reveal.
	f.err = secret.ErrExpressDisabled
	_, err := srv.GetSecretLink(depositCtx(t, nil), gen.GetSecretLinkRequestObject{SecretToken: "tts_tok"})
	wantProblem(t, err, problem.CodeExpressSecretsDisabled)
	_, err = srv.RevealSecret(depositCtx(t, nil), gen.RevealSecretRequestObject{SecretToken: "tts_tok", Body: &gen.SecretReveal{}})
	wantProblem(t, err, problem.CodeExpressSecretsDisabled)
}

func TestExpressFeatures(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		enabled, killSwitch, want bool
	}{
		{true, false, true}, {false, false, false}, {true, true, false}, {false, true, false},
	} {
		srv := NewServer(WithExpressKillSwitch(c.killSwitch))
		got := srv.expressFeatures(&tenant.Tenant{Express: tenant.ExpressSettings{Enabled: c.enabled}})
		if got.Enabled != c.want || got.MaxChars != 10000 ||
			!slices.Equal(got.Durations, []gen.ExpressSecretDuration{"1h", "1d", "7d"}) {
			t.Errorf("tenant %v, kill switch %v: %+v", c.enabled, c.killSwitch, got)
		}
	}
}
