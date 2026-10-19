package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func ptr[T any](v T) *T { return &v }

func TestCatalogIsWellFormed(t *testing.T) {
	t.Parallel()
	for _, c := range Codes() {
		def, ok := Lookup(c)
		if !ok {
			t.Fatalf("Lookup(%q) not found", c)
		}
		if def.Status < 400 || def.Status > 599 {
			t.Errorf("%q: status %d out of range", c, def.Status)
		}
		if def.Title == "" {
			t.Errorf("%q: empty title", c)
		}
		if got := c.TypeURI(); got != TypeBaseURI+string(c) {
			t.Errorf("%q: TypeURI = %q", c, got)
		}
	}
	if _, ok := Lookup("no-such-code"); ok {
		t.Error("Lookup of unknown code succeeded")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code Code
		opts []Option
		want *Problem
	}{
		{
			name: "defaults",
			code: CodeQuotaExceeded,
			want: &Problem{
				Type:   TypeBaseURI + "quota-exceeded",
				Title:  "Storage quota reached",
				Status: http.StatusInsufficientStorage,
				Code:   CodeQuotaExceeded,
			},
		},
		{
			name: "unknown code becomes internal-error",
			code: "bogus",
			want: &Problem{
				Type:   TypeBaseURI + "internal-error",
				Title:  "Internal error",
				Status: http.StatusInternalServerError,
				Code:   CodeInternalError,
			},
		},
		{
			name: "all options",
			code: CodeValidationFailed,
			opts: []Option{
				WithTitle("Requete invalide"),
				WithDetail("detail"),
				WithInstance("req-1"),
				WithFieldErrors(FieldError{Field: "a", Code: "invalid"}),
				WithFieldErrors(FieldError{Field: "b", Code: "not-allowed", Allowed: []any{1, 7, 30}}),
				WithAttemptsRemaining(2),
				WithRetryAfter(1500 * time.Millisecond),
				WithMaxTransferBytes(21474836480),
				WithFiles("f1"),
				WithFiles("f2", "f3"),
			},
			want: &Problem{
				Type:     TypeBaseURI + "validation-failed",
				Title:    "Requete invalide",
				Status:   http.StatusBadRequest,
				Detail:   "detail",
				Instance: "req-1",
				Code:     CodeValidationFailed,
				Errors: []FieldError{
					{Field: "a", Code: "invalid"},
					{Field: "b", Code: "not-allowed", Allowed: []any{1, 7, 30}},
				},
				AttemptsRemaining: ptr(2),
				RetryAfterSeconds: ptr(2),
				MaxTransferBytes:  ptr(int64(21474836480)),
				Files:             []string{"f1", "f2", "f3"},
			},
		},
		{
			name: "empty title ignored and negatives clamped",
			code: CodeRateLimited,
			opts: []Option{WithTitle(""), WithAttemptsRemaining(-3), WithRetryAfter(-time.Second)},
			want: &Problem{
				Type:              TypeBaseURI + "rate-limited",
				Title:             "Too many requests",
				Status:            http.StatusTooManyRequests,
				Code:              CodeRateLimited,
				AttemptsRemaining: ptr(0),
				RetryAfterSeconds: ptr(0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := New(tt.code, tt.opts...)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestError(t *testing.T) {
	t.Parallel()
	p := New(CodeNotFound, WithDetail("secret detail"))
	if got, want := p.Error(), "not-found: Not found"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestFrom(t *testing.T) {
	t.Parallel()
	p := New(CodeTransferGone)
	var nilProblem *Problem
	tests := []struct {
		name     string
		err      error
		wantSame bool
	}{
		{"problem itself", p, true},
		{"wrapped problem", fmt.Errorf("handler: %w", p), true},
		{"joined problem", errors.Join(errors.New("x"), p), true},
		{"plain error", errors.New("db password=hunter2"), false},
		{"nil error", nil, false},
		{"typed nil problem", nilProblem, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := From(tt.err)
			if tt.wantSame {
				if got != p {
					t.Errorf("From() = %+v, want original problem", got)
				}
				return
			}
			want := New(CodeInternalError)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("From() = %+v, want %+v", got, want)
			}
			if tt.err != nil && strings.Contains(got.Detail+got.Title, "hunter2") {
				t.Error("From leaked error text")
			}
		})
	}
}

func TestWrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		p              *Problem
		wantStatus     int
		wantRetryAfter string
		wantBody       map[string]any
	}{
		{
			name:       "simple",
			p:          New(CodeNotFound),
			wantStatus: http.StatusNotFound,
			wantBody: map[string]any{
				"type": TypeBaseURI + "not-found", "title": "Not found",
				"status": float64(404), "code": "not-found",
			},
		},
		{
			name:           "rate limited with retry after",
			p:              New(CodeRateLimited, WithRetryAfter(30*time.Minute)),
			wantStatus:     http.StatusTooManyRequests,
			wantRetryAfter: "1800",
			wantBody: map[string]any{
				"type": TypeBaseURI + "rate-limited", "title": "Too many requests",
				"status": float64(429), "code": "rate-limited", "retryAfterSeconds": float64(1800),
			},
		},
		{
			name: "validation with field errors",
			p: New(CodeValidationFailed, WithFieldErrors(
				FieldError{Field: "expiryDays", Code: "not-allowed", Allowed: []any{1, 7, 30}},
			)),
			wantStatus: http.StatusBadRequest,
			wantBody: map[string]any{
				"type": TypeBaseURI + "validation-failed", "title": "Invalid request",
				"status": float64(400), "code": "validation-failed",
				"errors": []any{map[string]any{
					"field": "expiryDays", "code": "not-allowed",
					"allowed": []any{float64(1), float64(7), float64(30)},
				}},
			},
		},
		{
			name:       "nil problem",
			p:          nil,
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalErrorBody(),
		},
		{
			name: "invalid status is replaced",
			p: &Problem{
				Type: TypeBaseURI + "forbidden", Title: "x", Status: 200, Code: CodeForbidden,
				Detail: "secret", Instance: "req-9", RetryAfterSeconds: ptr(5),
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"type": TypeBaseURI + "internal-error", "title": "Internal error",
				"status": float64(500), "code": "internal-error", "instance": "req-9",
			},
		},
		{
			name:       "status above range is replaced",
			p:          &Problem{Status: 600, Code: CodeForbidden},
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalErrorBody(),
		},
		{
			name:       "status below range is replaced",
			p:          &Problem{Status: 399, Code: CodeForbidden},
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalErrorBody(),
		},
		{
			name: "encoding failure falls back",
			p: New(CodeValidationFailed, WithRetryAfter(time.Second), WithFieldErrors(
				FieldError{Field: "f", Code: "c", Allowed: []any{math.NaN()}},
			)),
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalErrorBody(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Length", "999")
			Write(rec, tt.p)
			res := rec.Result()
			defer func() { _ = res.Body.Close() }()

			if res.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			wantHeaders := map[string]string{
				"Content-Type":           ContentType,
				"X-Content-Type-Options": "nosniff",
				"Cache-Control":          "no-store",
				"Retry-After":            tt.wantRetryAfter,
				"Content-Length":         "",
			}
			for k, v := range wantHeaders {
				if got := res.Header.Get(k); got != v {
					t.Errorf("header %s = %q, want %q", k, got, v)
				}
			}
			var body map[string]any
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want %v", body, tt.wantBody)
			}
		})
	}
}

func TestWriteDoesNotMutateProblem(t *testing.T) {
	t.Parallel()
	for _, status := range []int{0, 200, 404, 600} {
		p := &Problem{Type: "t", Title: "x", Status: status, Code: CodeNotFound, Instance: "req-1"}
		want := *p
		Write(httptest.NewRecorder(), p)
		if !reflect.DeepEqual(*p, want) {
			t.Errorf("status %d: Write mutated problem: %+v, want %+v", status, *p, want)
		}
	}
}

func internalErrorBody() map[string]any {
	return map[string]any{
		"type": TypeBaseURI + "internal-error", "title": "Internal error",
		"status": float64(500), "code": "internal-error",
	}
}

func TestFallbackBodyMatchesNew(t *testing.T) {
	t.Parallel()
	want, err := json.Marshal(New(CodeInternalError))
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != fallbackBody {
		t.Errorf("fallbackBody = %s, want %s", fallbackBody, want)
	}
}

func FuzzWriteFromRoundTrip(f *testing.F) {
	for _, s := range []string{"", "plain", `quote " and \ backslash`, "<script>", "\x00\xff\xfe", "été 🚀", " "} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, detail, title string) {
		orig := New(CodeAlreadyExists, WithDetail(detail), WithTitle(title), WithInstance(detail))
		p := From(fmt.Errorf("wrap: %w", orig))
		if p != orig {
			t.Fatal("From lost the wrapped problem")
		}
		rec := httptest.NewRecorder()
		Write(rec, p)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d", rec.Code)
		}
		raw := rec.Body.Bytes()
		if !json.Valid(raw) {
			t.Fatalf("invalid JSON: %q", raw)
		}
		var got Problem
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Code != CodeAlreadyExists || got.Status != http.StatusConflict {
			t.Fatalf("round trip changed code/status: %+v", got)
		}
		if utf8.ValidString(detail) && got.Detail != detail {
			t.Fatalf("detail = %q, want %q", got.Detail, detail)
		}
	})
}
