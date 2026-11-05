package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFlowCookie(t *testing.T) {
	t.Parallel()
	const clearCookie = "flow=; Max-Age=0"
	applies := func(r *http.Request) bool { return r.URL.Path == "/cb" }
	var got string
	h := FlowCookie("flow", clearCookie, applies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = FlowCookieFrom(r.Context())
		switch r.URL.Query().Get("mode") {
		case "redirect":
			w.Header().Set("Set-Cookie", "session=x")
			w.WriteHeader(http.StatusSeeOther)
		case "write":
			_, _ = w.Write([]byte("x"))
			if w.(interface{ Unwrap() http.ResponseWriter }).Unwrap() == nil {
				t.Error("no unwrap")
			}
		}
	}))
	for _, tc := range []struct {
		target, cookie, want string
		cookies              []string
	}{
		{"/cb?mode=redirect", "v1", "v1", []string{"session=x", clearCookie}},
		{"/cb?mode=write", "", "", []string{clearCookie}},
		{"/cb", "v2", "v2", []string{clearCookie}},
		{"/other?mode=redirect", "v3", "", []string{"session=x"}},
	} {
		got = "unset"
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		if tc.cookie != "" {
			req.AddCookie(&http.Cookie{Name: "flow", Value: tc.cookie})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		want := tc.want
		if tc.target == "/other?mode=redirect" {
			want = ""
		}
		if got != want {
			t.Errorf("%s: cookie in context = %q, want %q", tc.target, got, want)
		}
		if c := rec.Header().Values("Set-Cookie"); len(c) != len(tc.cookies) || c[len(c)-1] != tc.cookies[len(tc.cookies)-1] || c[0] != tc.cookies[0] {
			t.Errorf("%s: Set-Cookie = %q, want %q", tc.target, c, tc.cookies)
		}
	}
	// Fetch metadata: only a top-level navigation presents the flow; the
	// cookie is still cleared.
	for _, tc := range []struct {
		mode, dest string
		passed     bool
	}{
		{"navigate", "document", true},
		{"navigate", "", true},
		{"", "document", true},
		{"no-cors", "image", false},
		{"cors", "empty", false},
		{"navigate", "iframe", false},
		{"", "script", false},
	} {
		got = "unset"
		req := httptest.NewRequest(http.MethodGet, "/cb", nil)
		req.AddCookie(&http.Cookie{Name: "flow", Value: "v4"})
		if tc.mode != "" {
			req.Header.Set("Sec-Fetch-Mode", tc.mode)
		}
		if tc.dest != "" {
			req.Header.Set("Sec-Fetch-Dest", tc.dest)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if (got == "v4") != tc.passed || (!tc.passed && got != "") {
			t.Errorf("mode %q dest %q: cookie in context = %q", tc.mode, tc.dest, got)
		}
		if c := rec.Header().Values("Set-Cookie"); len(c) != 1 || c[0] != clearCookie {
			t.Errorf("mode %q dest %q: Set-Cookie = %q", tc.mode, tc.dest, c)
		}
	}
	if FlowCookieFrom(httptest.NewRequest(http.MethodGet, "/", nil).Context()) != "" {
		t.Error("FlowCookieFrom without middleware")
	}
}
