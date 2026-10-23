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
	exampleDownload   = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf"
	// exampleStubPOST is an administration operation (createTenant): under
	// a tenant host it answers 404 before any admin logic.
	exampleStubPOST   = "/api/v1/admin/tenants"
	exampleTenantPath = "/api/v1/admin/tenants/ten_01JAB00000000000000ENT1TYA"
	// exampleOpenPOST is an operation of the admin host served without a
	// session that reads a JSON body (adminLogin): an empty login answers
	// 401 invalid-credentials once the body is decoded.
	exampleOpenPOST = "/api/v1/admin/auth/login"
	oneMiB          = 1 << 20
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

// TestTusParameterErrors checks the parameter errors of the tus PATCH: no
// body, Tus-Resumable on the answer, 412 with Tus-Version for the protocol
// version, 400 for Upload-Offset.
func TestTusParameterErrors(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		for _, tc := range []struct {
			name   string
			header http.Header
			status int
		}{
			{"invalid Upload-Offset", http.Header{"Tus-Resumable": {"1.0.0"}, "Upload-Offset": {"abc"}}, http.StatusBadRequest},
			{"missing Upload-Offset", http.Header{"Tus-Resumable": {"1.0.0"}}, http.StatusBadRequest},
			{"missing Tus-Resumable", http.Header{"Upload-Offset": {"0"}}, http.StatusPreconditionFailed},
			{"unsupported Tus-Resumable", http.Header{"Tus-Resumable": {"0.2.2"}, "Upload-Offset": {"0"}}, http.StatusPreconditionFailed},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tc.header.Set("Content-Type", "application/offset+octet-stream")
				resp := s.do(t, request{
					method: http.MethodPatch, host: hostA, path: "/api/v1/uploads/" + exampleUploadID, body: []byte("x"), headers: tc.header,
				})
				if resp.status != tc.status || len(resp.body) != 0 || resp.header.Get("Tus-Resumable") != "1.0.0" {
					t.Errorf("status %d, body %q, Tus-Resumable %q; want %d without body", resp.status, resp.body,
						resp.header.Get("Tus-Resumable"), tc.status)
				}
				if tc.status == http.StatusPreconditionFailed && resp.header.Get("Tus-Version") != "1.0.0" {
					t.Errorf("412 without Tus-Version: %v", resp.header)
				}
				expectSecurityHeaders(t, tc.name, resp.header)
			})
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
			{"stub GET", request{path: exampleDownload}, 404, "not-found", ""},
			{"admin POST on a tenant host", request{method: http.MethodPost, path: exampleStubPOST, body: []byte(`{}`)}, 404, "not-found", ""},
			{"admin route on a tenant host", request{path: exampleTenantPath}, 404, "not-found", ""},
			{"admin stub on the admin host", request{host: adminHost, path: exampleTenantPath}, 401, "unauthenticated", ""},
			{"unknown API route", request{path: "/api/v1/nope"}, 404, "not-found", ""},
			{"unknown API version", request{path: "/api/v2/version"}, 404, "not-found", ""},
			{"unknown route under the api prefix", request{path: "/api/nope"}, 404, "not-found", ""},
			{"wrong method on version", request{method: http.MethodDelete, path: "/api/v1/version"}, 405, "method-not-allowed", "GET, HEAD"},
			{"wrong method on spec", request{method: http.MethodPost, path: "/api/openapi.yaml", body: []byte(`{}`)}, 405, "method-not-allowed", "GET, HEAD"},
			{"wrong method on healthz", request{method: http.MethodPut, path: "/healthz", body: []byte(`{}`)}, 405, "method-not-allowed", "GET, HEAD"},
			// Path patterns are not validated by the router: a malformed
			// identifier simply matches nothing.
			{"malformed identifier", request{path: "/api/v1/downloads/not-a-token"}, 404, "not-found", ""},
			{"invalid query parameter", request{host: adminHost, path: "/api/v1/admin/tenants?limit=abc"}, 400, "validation-failed", ""},
			{"tenant route on the admin host", request{host: adminHost, path: "/api/v1/tenant"}, 404, "not-found", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if tc.req.host == "" {
					tc.req.host = hostA
				}
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
			resp, err := s.tryDo(t, request{method: http.MethodPost, host: hostA, path: "/api/v1/deposit-sessions", body: body})
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
			// An unknown member: decoding succeeds and the empty login is
			// refused by the handler.
			body := append(append([]byte(`{"padding":"`), bytes.Repeat([]byte("a"), oneMiB-20)...), `"}`...)
			resp := s.do(t, request{method: http.MethodPost, host: adminHost, path: exampleOpenPOST, body: body})
			expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		})

		t.Run("tus PATCH is exempt", func(t *testing.T) {
			// A non-exempt route would answer 413 at once from the
			// announced length, as below for PATCH on a tenant. The tus
			// PATCH reaches the session check instead, which answers a bare
			// 401 (tus error responses have no body).
			head := "PATCH /api/v1/uploads/" + exampleUploadID + " HTTP/1.1\r\nHost: " + hostA +
				"\r\nContent-Type: application/offset+octet-stream\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: 0" +
				"\r\nContent-Length: " + fmt.Sprint(10*oneMiB) + "\r\n"
			resp := s.raw(t, head, nil)
			if resp.status != http.StatusUnauthorized || len(resp.body) != 0 {
				t.Fatalf("PATCH of 10 MiB: status = %d, want a bodyless 401 (not 413); body %s", resp.status, resp.body)
			}
		})

		// The image limit of the branding upload, an admin operation behind
		// the admin session, is covered by the httpserver tests
		// (TestBrandingBodyLimit) until the admin flows exist here.
		t.Run("an admin host operation has the JSON limit", func(t *testing.T) {
			head := "POST " + exampleOpenPOST + " HTTP/1.1\r\nHost: " + adminHost +
				"\r\nContent-Type: application/json\r\nContent-Length: " + fmt.Sprint(2*oneMiB) + "\r\n"
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
