package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Fictitious identifiers matching the patterns of api/openapi.yaml.
const (
	exampleTransferID = "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS"
	exampleUploadID   = "upl_7Hq2Wm9Zx4Lp1Vb8Rt3Yk6Nd"
	exampleTenantPath = "/api/v1/admin/tenants/ten_01JAB00000000000000ENT1TYA"
	oneMiB            = 1 << 20
)

// versionBody is the VersionInfo schema.
type versionBody struct {
	Version    string  `json:"version"`
	APIVersion string  `json:"apiVersion"`
	Commit     *string `json:"commit"`
}

// TestGetVersionUnderEachTenant checks getVersion under both tenants: same
// answer, no tenant data, no caching, security headers.
func TestGetVersionUnderEachTenant(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		var bodies [][]byte
		for _, tn := range []struct{ host, name, id string }{
			{hostA, nameA, string(s.tenantA.ID)}, {hostB, nameB, string(s.tenantB.ID)},
		} {
			resp := s.get(t, tn.host, "/api/v1/version")
			if resp.status != http.StatusOK {
				t.Fatalf("%s: status = %d; body %s", tn.host, resp.status, resp.body)
			}
			if ct := resp.header.Get("Content-Type"); ct != contentJSON {
				t.Errorf("Content-Type = %q, want %q", ct, contentJSON)
			}
			var v versionBody
			mustJSON(t, resp.body, &v)
			if v.Version == "" || v.APIVersion != "v1" {
				t.Errorf("version body = %s", resp.body)
			}
			for _, leak := range []string{hostA, hostB, nameA, nameB, string(s.tenantA.ID), string(s.tenantB.ID)} {
				if strings.Contains(string(resp.body), leak) {
					t.Errorf("getVersion under %s leaks %q", tn.host, leak)
				}
			}
			if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
			expectSecurityHeaders(t, "getVersion", resp.header)
			bodies = append(bodies, resp.body)
		}
		if !bytes.Equal(bodies[0], bodies[1]) {
			t.Errorf("getVersion differs between tenants: %s vs %s", bodies[0], bodies[1])
		}

		head := s.do(t, request{method: http.MethodHead, host: hostA, path: "/api/v1/version"})
		if head.status != http.StatusOK || len(head.body) != 0 {
			t.Errorf("HEAD version: status %d, %d body bytes; want 200 and no body", head.status, len(head.body))
		}
	})
}

// TestRequestID checks that every response carries a fresh X-Request-Id,
// that an incoming one is never echoed (T-101), and that problems use it as
// instance.
func TestRequestID(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		seen := map[string]bool{}
		for range 5 {
			resp := s.do(t, request{
				host: hostA, path: "/api/v1/does-not-exist",
				headers: http.Header{hdrRequestID: {"req_attacker\" ip=1.2.3.4"}},
			})
			p := expectProblem(t, resp, http.StatusNotFound, "not-found")
			if strings.Contains(p.Instance, "attacker") {
				t.Errorf("incoming X-Request-Id echoed: %q", p.Instance)
			}
			if seen[p.Instance] {
				t.Errorf("request identifier %q reused", p.Instance)
			}
			seen[p.Instance] = true
		}
		for _, path := range []string{"/healthz", "/api/openapi.yaml", "/api/v1/version"} {
			if rid := s.get(t, hostA, path).header.Get(hdrRequestID); !strings.HasPrefix(rid, "req_") {
				t.Errorf("%s: X-Request-Id = %q", path, rid)
			}
		}
	})
}

// TestUnimplementedAndUnknownRoutes checks the 404 and 405 problems.
func TestUnimplementedAndUnknownRoutes(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		for _, tc := range []struct {
			name   string
			req    request
			status int
			code   string
			allow  string
		}{
			{"stub GET", request{path: "/api/v1/transfers/" + exampleTransferID}, 404, "not-found", ""},
			{"stub POST with JSON body", request{method: http.MethodPost, path: "/api/v1/transfers", body: []byte(`{}`)}, 404, "not-found", ""},
			{"stub admin route", request{path: exampleTenantPath}, 404, "not-found", ""},
			{"unknown API route", request{path: "/api/v1/nope"}, 404, "not-found", ""},
			{"unknown API version", request{path: "/api/v2/version"}, 404, "not-found", ""},
			{"unknown root route", request{path: "/admin"}, 404, "not-found", ""},
			{"wrong method on version", request{method: http.MethodDelete, path: "/api/v1/version"}, 405, "method-not-allowed", "GET, HEAD"},
			{"wrong method on spec", request{method: http.MethodPost, path: "/api/openapi.yaml", body: []byte(`{}`)}, 405, "method-not-allowed", "GET, HEAD"},
			{"wrong method on healthz", request{method: http.MethodPut, path: "/healthz", body: []byte(`{}`)}, 405, "method-not-allowed", "GET, HEAD"},
			// Path patterns are not validated by the router: a malformed
			// identifier simply matches nothing.
			{"malformed identifier", request{path: "/api/v1/transfers/not-an-id"}, 404, "not-found", ""},
			{"invalid header parameter", request{
				method: http.MethodPatch, path: "/api/v1/uploads/" + exampleUploadID, body: []byte("x"),
				headers: http.Header{"Content-Type": {"application/offset+octet-stream"}, "Tus-Resumable": {"1.0.0"}, "Upload-Offset": {"abc"}},
			}, 400, "validation-failed", ""},
			{"missing required header", request{
				method: http.MethodPatch, path: "/api/v1/uploads/" + exampleUploadID, body: []byte("x"),
				headers: http.Header{"Content-Type": {"application/offset+octet-stream"}, "Tus-Resumable": {"1.0.0"}},
			}, 400, "validation-failed", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tc.req.host = hostA
				resp := s.do(t, tc.req)
				expectProblem(t, resp, tc.status, tc.code)
				expectSecurityHeaders(t, tc.name, resp.header)
				if tc.allow != "" && resp.header.Get("Allow") != tc.allow {
					t.Errorf("Allow = %q, want %q", resp.header.Get("Allow"), tc.allow)
				}
				if strings.HasPrefix(tc.req.path, "/api") && resp.header.Get("Cache-Control") != "no-store" {
					t.Errorf("Cache-Control = %q under /api, want no-store", resp.header.Get("Cache-Control"))
				}
			})
		}
	})
}

// TestJSONBodyLimit checks the 1 MiB limit of JSON endpoints (T-98, DoS):
// refused upfront on Content-Length, and when a chunked body crosses the
// limit; while the tus PATCH and the branding image upload are exempt.
func TestJSONBodyLimit(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})

		t.Run("10 MiB Content-Length", func(t *testing.T) {
			head := "POST /api/v1/deposit-sessions HTTP/1.1\r\nHost: " + hostA +
				"\r\nContent-Type: application/json\r\nContent-Length: " + fmt.Sprint(10*oneMiB) + "\r\n"
			// The answer must come before any byte of the body is sent.
			resp := s.raw(t, head, nil)
			expectProblem(t, resp, http.StatusRequestEntityTooLarge, "payload-too-large")
			expectSecurityHeaders(t, "413", resp.header)
		})

		t.Run("chunked body above 1 MiB", func(t *testing.T) {
			head := "POST /api/v1/deposit-sessions HTTP/1.1\r\nHost: " + hostA +
				"\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
			resp := s.raw(t, head, func(w io.Writer) {
				writeChunk(w, []byte(`{"email":"`))
				for range 12 { // 12 x 1 MiB of string content, more than enough
					if !writeChunk(w, bytes.Repeat([]byte("a"), oneMiB)) {
						return
					}
				}
				writeChunk(w, []byte(`"}`))
				_, _ = io.WriteString(w, "0\r\n\r\n")
			})
			expectProblem(t, resp, http.StatusRequestEntityTooLarge, "payload-too-large")
		})

		t.Run("Go client 10 MiB JSON", func(t *testing.T) {
			body := append(append([]byte(`{"email":"`), bytes.Repeat([]byte("a"), 10*oneMiB)...), `"}`...)
			resp, err := s.tryDo(t, request{method: http.MethodPost, host: hostA, path: "/api/v1/transfers", body: body})
			if err != nil {
				// The server answers 413 before reading the body and then
				// closes the connection; a client still sending may see the
				// reset before the answer (observed with Go on Windows).
				// The refusal itself is asserted on raw connections above.
				t.Logf("client saw a reset instead of the early 413: %v", err)
				return
			}
			expectProblem(t, resp, http.StatusRequestEntityTooLarge, "payload-too-large")
		})

		t.Run("just under the limit reaches the handler", func(t *testing.T) {
			// An unknown member: decoding succeeds and the stub answers.
			body := append(append([]byte(`{"padding":"`), bytes.Repeat([]byte("a"), oneMiB-20)...), `"}`...)
			resp := s.do(t, request{method: http.MethodPost, host: hostA, path: "/api/v1/transfers", body: body})
			expectProblem(t, resp, http.StatusNotFound, "not-found") // still a stub
		})

		t.Run("tus PATCH is exempt", func(t *testing.T) {
			// The stub never reads the body: a non-exempt route would answer
			// 413 at once from the announced length, as below for PATCH on a
			// tenant. The tus stub answers a bare 404 (tus responses have no
			// body).
			head := "PATCH /api/v1/uploads/" + exampleUploadID + " HTTP/1.1\r\nHost: " + hostA +
				"\r\nContent-Type: application/offset+octet-stream\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: 0" +
				"\r\nContent-Length: " + fmt.Sprint(10*oneMiB) + "\r\n"
			resp := s.raw(t, head, nil)
			if resp.status != http.StatusNotFound {
				t.Fatalf("PATCH of 10 MiB: status = %d, want 404 from the stub (not 413); body %s", resp.status, resp.body)
			}
		})

		t.Run("branding image upload has the image limit", func(t *testing.T) {
			brandingHead := func(n int) string {
				return "PUT " + exampleTenantPath + "/branding/logo HTTP/1.1\r\nHost: " + hostA +
					"\r\nContent-Type: image/png\r\nContent-Length: " + fmt.Sprint(n) + "\r\n"
			}
			// Above the JSON limit but within the 10 MiB image limit: reaches
			// the stub.
			resp := s.raw(t, brandingHead(10*oneMiB), nil)
			if resp.status == http.StatusRequestEntityTooLarge {
				t.Fatalf("branding upload of 10 MiB refused by the JSON limit: %s", resp.body)
			}
			expectProblem(t, resp, http.StatusNotFound, "not-found")
			// Above the image limit: refused upfront.
			expectProblem(t, s.raw(t, brandingHead(10*oneMiB+1), nil), http.StatusRequestEntityTooLarge, "payload-too-large")
		})

		t.Run("PATCH on another route is not exempt", func(t *testing.T) {
			head := "PATCH " + exampleTenantPath + " HTTP/1.1\r\nHost: " + hostA +
				"\r\nContent-Type: application/merge-patch+json\r\nContent-Length: " + fmt.Sprint(2*oneMiB) + "\r\n"
			expectProblem(t, s.raw(t, head, nil), http.StatusRequestEntityTooLarge, "payload-too-large")
		})
	})
}

// writeChunk writes one HTTP/1.1 chunk and reports whether it succeeded.
func writeChunk(w io.Writer, b []byte) bool {
	if _, err := fmt.Fprintf(w, "%x\r\n", len(b)); err != nil {
		return false
	}
	if _, err := w.Write(b); err != nil {
		return false
	}
	_, err := io.WriteString(w, "\r\n")
	return err == nil
}
