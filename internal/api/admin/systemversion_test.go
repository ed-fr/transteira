package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/updatecheck"
	"github.com/ed-fr/transteira/internal/version"
)

// fakeUpdateCheck is an UpdateCheckService recording its calls.
type fakeUpdateCheck struct {
	status updatecheck.Status
	err    error
	calls  []string
}

func (f *fakeUpdateCheck) Status(_ context.Context, p adminauth.Principal) (updatecheck.Status, error) {
	f.calls = append(f.calls, "status:"+p.Admin.Username)
	return f.status, f.err
}

func (f *fakeUpdateCheck) CheckNow(_ context.Context, p adminauth.Principal) (updatecheck.Status, error) {
	f.calls = append(f.calls, "check:"+p.Admin.Username)
	return f.status, f.err
}

func updateServer(f *fakeUpdateCheck) *Server {
	s := NewServer(WithUpdateCheck(f))
	s.version = func() version.Info { return version.Info{Version: "1.2.0", Commit: "3f9c2ab"} }
	return s
}

// systemVersionCalls runs both operations on s with ctx.
func systemVersionCalls(ctx context.Context, s *Server) map[string]func() (any, error) {
	return map[string]func() (any, error){
		"GetSystemVersion": func() (any, error) {
			return s.GetSystemVersion(ctx, gen.GetSystemVersionRequestObject{})
		},
		"CheckSystemVersion": func() (any, error) {
			return s.CheckSystemVersion(ctx, gen.CheckSystemVersionRequestObject{})
		},
	}
}

func TestSystemVersion(t *testing.T) {
	t.Parallel()
	checked := time.Date(2026, 10, 31, 6, 0, 0, 0, time.FixedZone("CET", 3600))
	f := &fakeUpdateCheck{status: updatecheck.Status{
		Enabled: true, LatestVersion: "1.2.1", ReleaseURL: "https://github.com/ed-fr/transteira/releases/tag/v1.2.1",
		UpdateAvailable: true, CheckedAt: checked, LastError: updatecheck.CategoryNone,
	}}
	s := updateServer(f)
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	want := `{"commit":"3f9c2ab","updateCheck":{"checkedAt":"2026-10-31T05:00:00Z","enabled":true,"lastError":"none",` +
		`"latestVersion":"1.2.1","releaseUrl":"https://github.com/ed-fr/transteira/releases/tag/v1.2.1",` +
		`"updateAvailable":true},"version":"1.2.0"}`

	get, err := s.GetSystemVersion(ctx, gen.GetSystemVersionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := get.VisitGetSystemVersionResponse(rec); err != nil || rec.Code != 200 {
		t.Fatalf("visit = %d, %v", rec.Code, err)
	}
	expectJSON(t, rec.Body.Bytes(), want)

	check, err := s.CheckSystemVersion(ctx, gen.CheckSystemVersionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	if err := check.VisitCheckSystemVersionResponse(rec); err != nil || rec.Code != 200 {
		t.Fatalf("visit = %d, %v", rec.Code, err)
	}
	expectJSON(t, rec.Body.Bytes(), want)
	if !reflect.DeepEqual(f.calls, []string{"status:root", "check:root"}) {
		t.Errorf("calls %v", f.calls)
	}

	// Disabled, never checked, no commit: every nullable member is null,
	// never omitted.
	f.status = updatecheck.Status{LastError: updatecheck.CategoryNone}
	s.version = func() version.Info { return version.Info{Version: "1.2.0", Commit: unknownCommit} }
	get, err = s.GetSystemVersion(ctx, gen.GetSystemVersionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	if err := get.VisitGetSystemVersionResponse(rec); err != nil {
		t.Fatal(err)
	}
	expectJSON(t, rec.Body.Bytes(), `{"updateCheck":{"checkedAt":null,"enabled":false,"lastError":"none",`+
		`"latestVersion":null,"releaseUrl":null,"updateAvailable":false},"version":"1.2.0"}`)
}

// expectJSON compares two JSON documents.
func expectJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("invalid JSON %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("body %s, want %s", got, want)
	}
}

// A delegated admin gets 403 and a session not fully signed in 401,
// before the service is called.
func TestSystemVersionRoles(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		ctx  context.Context
		code problem.Code
	}{
		{ctxWith(store.SessionAuthenticated, delegated), problem.CodeForbidden},
		{ctxWith(store.SessionTOTPRequired, superRoot), problem.CodeUnauthenticated},
		{context.Background(), problem.CodeUnauthenticated},
	} {
		f := &fakeUpdateCheck{}
		for name, call := range systemVersionCalls(c.ctx, updateServer(f)) {
			_, err := call()
			if p := expectProblem(t, err, c.code); p.Code == "" {
				t.Error(name)
			}
		}
		if len(f.calls) != 0 {
			t.Errorf("the service was called: %v", f.calls)
		}
	}
}

func TestSystemVersionErrors(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	// Without the service: 500.
	for name, call := range systemVersionCalls(ctx, NewServer()) {
		if _, err := call(); !errors.Is(err, errNoUpdateCheck) {
			t.Errorf("%s without service = %v", name, err)
		}
	}
	// 409 when disabled, 429 with its delay, a role error of the service,
	// a store failure answered 500.
	_, err := updateServer(&fakeUpdateCheck{err: updatecheck.ErrDisabled}).CheckSystemVersion(ctx, gen.CheckSystemVersionRequestObject{})
	expectProblem(t, err, problem.CodeUpdateCheckDisabled)
	_, err = updateServer(&fakeUpdateCheck{err: &updatecheck.RateLimitError{RetryAfter: 41500 * time.Millisecond}}).
		CheckSystemVersion(ctx, gen.CheckSystemVersionRequestObject{})
	if p := expectProblem(t, err, problem.CodeRateLimited); p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 42 {
		t.Errorf("retry after %v", p.RetryAfterSeconds)
	}
	_, err = updateServer(&fakeUpdateCheck{err: adminauth.ErrForbidden}).GetSystemVersion(ctx, gen.GetSystemVersionRequestObject{})
	expectProblem(t, err, problem.CodeForbidden)
	boom := errors.New("database down")
	_, err = updateServer(&fakeUpdateCheck{err: boom}).GetSystemVersion(ctx, gen.GetSystemVersionRequestObject{})
	if !errors.Is(err, boom) {
		t.Errorf("GetSystemVersion(store failure) = %v", err)
	}
}
