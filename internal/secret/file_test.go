package secret

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// validGrant is a grant of the right shape.
var validGrant = "ttg_" + strings.Repeat("G", 43)

func TestActorOf(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		sender transfer.Sender
		want   store.SecretActor
		ok     bool
	}{
		"internal": {internalSender(), store.SecretActor{Email: alice, Kind: store.SecretCreatorInternal}, true},
		"token": {
			transfer.Sender{Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: "tok_1"}},
			store.SecretActor{APITokenID: "tok_1"},
			true,
		},
		"external": {
			transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: "inv_1"}},
			store.SecretActor{Email: bob, Kind: store.SecretCreatorExternal},
			true,
		},
		"reply":     {transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorReply}}, store.SecretActor{}, false},
		"drop link": {transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorDropLink}}, store.SecretActor{}, false},
	} {
		if got, ok := actorOf(c.sender); got != c.want || ok != c.ok {
			t.Errorf("%s: %+v, %v", name, got, ok)
		}
	}
}

func TestCreateWithFile(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "", "")
	meta := "AQ" + strings.Repeat("A", 38)
	var quota []bool
	e := newEnv(t)
	e.svc.onQuota = func(tid tenant.ID, refused bool) {
		if tid != testTenant.ID {
			t.Errorf("tenant %s", tid)
		}
		quota = append(quota, refused)
	}
	req := s.request()
	req.File = &File{Size: 2 << 20, EncryptedMetadata: meta}
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), req); err != nil {
		t.Fatal(err)
	}
	in := e.repo.gotCreate
	if in.FileSize != 2<<20 || in.FileMetadata != meta || !storage.ValidName(in.FileStorageName) {
		t.Errorf("store input = %+v", in)
	}
	e.repo.createErr = store.ErrSecretQuotaExceeded
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), req); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("quota: %v", err)
	}
	// Without file, the quota is not reported.
	e.repo.createErr = nil
	plain, _ := seal(t, "text", "")
	if _, err := e.svc.Create(context.Background(), testTenant, internalSender(), plain.request()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(quota, []bool{false, true}) {
		t.Errorf("quota calls = %v", quota)
	}
	// The default OnQuota does nothing.
	newEnv(t).svc.onQuota(testTenant.ID, true)
}

func TestUploadFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	e.repo.uploaded = store.Secret{ID: "sec_1", State: store.SecretActive}
	out, err := e.svc.UploadFile(ctx, testTenant, internalSender(), "sec_1", strings.NewReader("body"))
	if err != nil || out.ID != "sec_1" || string(e.repo.gotBody) != "body" || e.repo.gotSecID != "sec_1" ||
		e.repo.gotActor != (store.SecretActor{Email: alice, Kind: store.SecretCreatorInternal}) {
		t.Fatalf("upload = %+v, %v, repo %+v", out, err, e.repo.gotActor)
	}
	if e.scrubber.calls != 0 || len(e.audit.events) != 0 {
		t.Errorf("scrubs %d, audit %v", e.scrubber.calls, e.audit.actions())
	}
	reply := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorReply}}
	if _, err := e.svc.UploadFile(ctx, testTenant, reply, "sec_1", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("reply sender: %v", err)
	}
	var format *FormatError
	for _, c := range []struct {
		err   error
		check func(error) bool
		scrub bool
	}{
		{store.ErrSecretState, func(err error) bool { return errors.Is(err, ErrConflict) }, false},
		{store.ErrNotFound, func(err error) bool { return errors.Is(err, ErrNotFound) }, false},
		{errBoom, func(err error) bool { return errors.Is(err, errBoom) }, false},
		// After the key was created: the conflict of a secret changed
		// during the upload, a malformed body, a write failure.
		{errors.Join(store.ErrSecretState, store.ErrSecretUploadAborted), func(err error) bool { return errors.Is(err, ErrConflict) }, true},
		{errors.Join(store.ErrSecretFileFormat, store.ErrSecretUploadAborted), func(err error) bool {
			return errors.As(err, &format) && len(format.Fields) == 0
		}, true},
		{errors.Join(errBoom, store.ErrSecretUploadAborted), func(err error) bool { return errors.Is(err, errBoom) }, true},
	} {
		e := newEnv(t)
		e.repo.uploadErr = c.err
		_, err := e.svc.UploadFile(ctx, testTenant, internalSender(), "sec_1", strings.NewReader("x"))
		if !c.check(err) || (e.scrubber.calls == 1) != c.scrub {
			t.Errorf("%v: %v, scrubs %d", c.err, err, e.scrubber.calls)
		}
	}
}

func TestDownloadFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	e.repo.download = &store.SecretFileDownload{ID: "sec_1", Size: 4, Reader: strings.NewReader("data")}
	d, err := e.svc.DownloadFile(ctx, testTenant, internalIP, "tts_tok", validGrant)
	if err != nil || d.Size() != 4 || e.repo.gotGrant != validGrant {
		t.Fatalf("download = %+v, %v", d, err)
	}
	if e.streams.held != 1 || e.streams.gotID != "sec_1" {
		t.Errorf("stream slots: %+v", e.streams)
	}
	b, _ := io.ReadAll(d)
	if string(b) != "data" {
		t.Errorf("content %q", b)
	}
	_ = d.Close()
	if e.streams.held != 0 {
		t.Errorf("slots held after close: %d", e.streams.held)
	}
	// A concurrent download completed first: nothing more.
	d.Delivered(ctx)
	if e.scrubber.calls != 0 || len(e.audit.events) != 0 {
		t.Errorf("not completed: scrubs %d, audit %v", e.scrubber.calls, e.audit.actions())
	}
	// A failure is logged only.
	e.repo.completeEr = errBoom
	d.Delivered(ctx)
	if e.scrubber.calls != 0 || len(e.audit.events) != 0 {
		t.Errorf("failed completion: scrubs %d, audit %v", e.scrubber.calls, e.audit.actions())
	}
	// Completed: the file goes, the keys are scrubbed, the download
	// audited.
	e.repo.completeEr, e.repo.completeOK = nil, true
	e.repo.completed = store.EndedSecret{RemovedFile: "abc"}
	d.Delivered(ctx)
	if e.scrubber.calls != 1 || !slices.Equal(e.files.removed, []string{"abc"}) ||
		!slices.Equal(e.audit.actions(), []audit.Action{audit.ActionSecretFileDownloaded}) || e.repo.completes != 3 {
		t.Errorf("delivered: scrubs %d, files %v, audit %v", e.scrubber.calls, e.files.removed, e.audit.actions())
	}
	if ev := e.audit.events[0]; ev.ActorKind != store.ActorRecipient || ev.Actor != linkActor || ev.ObjectID != "sec_1" ||
		ev.IP != internalIP || ev.Details != nil {
		t.Errorf("audit event = %+v", ev)
	}
	if len(e.seclog.events) != 0 || e.failures.fails != 0 {
		t.Errorf("events %v, failures %d", e.seclog.types(), e.failures.fails)
	}
}

func TestDownloadFileErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var limited *RateLimitError
	tests := []struct {
		name   string
		grant  string
		setup  func(*env)
		check  func(error) bool
		seclog []string
		fails  int
	}{
		{
			"rate", validGrant, func(e *env) { e.requests.refuse = true },
			func(err error) bool { return errors.As(err, &limited) },
			[]string{"rate_limited scope=" + ScopeLinkIP},
			0,
		},
		{"malformed grant", "ttg_x", func(*env) {}, func(err error) bool { var v *ValidationError; return errors.As(err, &v) && len(v.Fields) == 1 }, nil, 0},
		{
			"wrong grant", validGrant, func(e *env) { e.repo.openErr = store.ErrSecretGrant },
			func(err error) bool { return errors.Is(err, ErrNotFound) }, nil, 0,
		},
		{
			"unknown", validGrant, func(e *env) { e.repo.openErr = store.ErrNotFound },
			func(err error) bool { return errors.Is(err, ErrNotFound) },
			[]string{"secret_invalid"},
			1,
		},
		{
			"pending", validGrant, func(e *env) { e.repo.openErr = store.ErrSecretPending },
			func(err error) bool { return errors.Is(err, ErrNotFound) }, nil, 0,
		},
		{
			"store", validGrant, func(e *env) { e.repo.openErr = errBoom },
			func(err error) bool { return errors.Is(err, errBoom) }, nil, 0,
		},
		{
			"too many streams", validGrant, func(e *env) {
				e.repo.download = &store.SecretFileDownload{ID: "sec_1", Reader: strings.NewReader("")}
				e.streams.err = &download.TooManyStreamsError{RetryAfter: download.StreamRetryAfter}
			},
			func(err error) bool {
				var l *RateLimitError
				return errors.As(err, &l) && l.RetryAfter == download.StreamRetryAfter
			}, nil, 0,
		},
		{
			"no client IP", validGrant, func(e *env) {
				e.repo.download = &store.SecretFileDownload{ID: "sec_1", Reader: strings.NewReader("")}
				e.streams.err = download.ErrNoClientIP
			},
			func(err error) bool { return errors.Is(err, download.ErrNoClientIP) }, nil, 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			tt.setup(e)
			_, err := e.svc.DownloadFile(ctx, testTenant, internalIP, "tts_tok", tt.grant)
			if !tt.check(err) {
				t.Errorf("err = %v", err)
			}
			if got := e.seclog.types(); !slices.Equal(got, tt.seclog) {
				t.Errorf("security log = %v, want %v", got, tt.seclog)
			}
			if e.failures.fails != tt.fails {
				t.Errorf("failures = %d, want %d", e.failures.fails, tt.fails)
			}
		})
	}
	e := newEnv(t)
	if got := fieldsOf(t, mustDownloadErr(e.svc.DownloadFile(ctx, testTenant, internalIP, "tts_tok", ""))); !slices.Equal(got,
		[]string{FieldGrant + " " + CodeInvalidFormat}) {
		t.Errorf("fields = %v", got)
	}
}

func mustDownloadErr(_ FileStream, err error) error { return err }

func TestRevealWithFile(t *testing.T) {
	t.Parallel()
	s, _ := seal(t, "x", "")
	e := newEnv(t)
	exp := testNow.Add(10 * time.Minute)
	e.repo.revealed = store.RevealedSecret{
		Secret: store.Secret{ID: "sec_1"}, SealedText: s.text, FileMetadata: "meta", FileGrant: validGrant, FileGrantExpiresAt: exp,
	}
	out, err := e.svc.Reveal(context.Background(), testTenant, internalIP, "tts_tok", s.keyProof, s.proof)
	if err != nil || out.FileGrant != validGrant || !out.FileGrantExpiresAt.Equal(exp) || out.EncryptedMetadata != "meta" {
		t.Fatalf("reveal = %+v, %v", out, err)
	}
}
