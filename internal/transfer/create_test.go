package transfer

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/upload"
)

func TestCreateInternal(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		pw := "correct horse"
		req := CreateRequest{
			Recipients: []string{" Dave@Customer.Example.NET ", "erin@customer.example.net"},
			Message:    "Hello\u200b\r\nworld\u202e\tok",
			ExpiryDays: 30, Password: &pw, DeleteAfterFirstDownload: true, Language: "fr",
			Files: []FileDeclaration{
				{Name: "cafe\u0301.txt", Size: 10, MediaType: "text/plain", ExpectedSHA256: strings.ToUpper(emptySHA)},
				{Name: "empty.bin", Size: 0},
			},
		}
		d, err := ev.svc.Create(ctx, ev.a, internalSender(), req, "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if d.Status != store.TransferUploading || d.SenderEmail != alice || d.ExpiryDays != 30 ||
			!d.PasswordProtected || !d.DeleteAfterFirstDownload || d.TotalBytes != 10 ||
			!d.CreatedAt.Equal(testStart) || !d.UploadExpiresAt.Equal(testStart.Add(uploadTTL)) ||
			!d.ExpiresAt.IsZero() || !d.FinalizedAt.IsZero() {
			t.Errorf("details = %+v", d)
		}
		if d.Message != "Hello\nworld\tok" {
			t.Errorf("message = %q", d.Message)
		}
		if !reflect.DeepEqual(d.Recipients, []string{dave, "erin@customer.example.net"}) {
			t.Errorf("recipients = %v", d.Recipients)
		}
		if len(d.Files) != 2 {
			t.Fatalf("files = %d", len(d.Files))
		}
		f0, f1 := d.Files[0], d.Files[1]
		if f0.Name != "caf\u00e9.txt" || f0.Size != 10 || f0.MediaType != "text/plain" || f0.SHA256 != "" ||
			f0.ScanStatus != store.ScanPending || f0.UploadOffset != 0 || !strings.HasPrefix(f0.UploadID, "upl_") {
			t.Errorf("file 0 = %+v", f0)
		}
		if f1.SHA256 != emptySHA || f1.UploadOffset != 0 || f1.UploadID == "" || f1.UploadID == f0.UploadID {
			t.Errorf("file 1 = %+v", f1)
		}
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Language != "fr" || stored.PasswordHash != "$fake$636f727265637420686f727365" ||
			stored.Files[0].ExpectedSHA256 != emptySHA || stored.Files[0].DEKKeyID == "" ||
			stored.Files[0].DEKKeyID == stored.Files[1].DEKKeyID || !stored.Files[1].Completed() {
			t.Errorf("stored = %+v", stored)
		}
		// The DEK handed to WriteEmpty is cleared after use.
		if len(ev.uploads.emptyDEKs) != 1 || strings.Trim(string(ev.uploads.emptyDEKs[0]), "\x00") != "" {
			t.Errorf("empty DEKs = %v", ev.uploads.emptyDEKs)
		}
		got, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, d) {
			t.Errorf("Get = %+v, want %+v", got, d)
		}
	})
}

func TestCreateExternalForcedRecipient(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		req := request()
		req.Recipients = []string{"not an address", dave, dave} // ignored (T-17)
		d, err := ev.svc.Create(context.Background(), ev.a, ev.external(), req, "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !reflect.DeepEqual(d.Recipients, []string{alice}) || d.SenderEmail != bob {
			t.Errorf("details = %+v", d)
		}
		stored, err := ev.db.Transfers().Get(context.Background(), ev.a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.SenderKind != store.DepositorExternal || stored.InvitationID != ev.inv.ID {
			t.Errorf("stored = %+v", stored.Transfer)
		}
	})
}

func TestCreateValidation(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	str := func(s string) *string { return &s }
	tooManyFiles := make([]FileDeclaration, MaxFiles+1)
	tests := []struct {
		name string
		key  string
		edit func(r *CreateRequest)
		want []FieldError
	}{
		{"idempotency key", "bad key", func(*CreateRequest) {}, []FieldError{{FieldIdempotencyKey, CodeInvalidFormat}}},
		{"idempotency key long", strings.Repeat("k", 65), func(*CreateRequest) {}, []FieldError{{FieldIdempotencyKey, CodeInvalidFormat}}},
		{"sender email", "", func(r *CreateRequest) { r.SenderEmail = alice }, []FieldError{{FieldSenderEmail, CodeNotAllowed}}},
		{"no recipients", "", func(r *CreateRequest) { r.Recipients = nil }, []FieldError{{FieldRecipients, CodeRequired}}},
		{"too many recipients", "", func(r *CreateRequest) {
			r.Recipients = []string{"a@x.example.com", "b@x.example.com", "c@x.example.com", "d@x.example.com"}
		}, []FieldError{{FieldRecipients, CodeTooMany}}},
		{"bad recipients", "", func(r *CreateRequest) {
			r.Recipients = []string{"Dave <dave@customer.example.net>", dave, "DAVE@customer.example.net"}
		}, []FieldError{{"/recipients/0", CodeInvalidEmail}, {"/recipients/2", CodeDuplicate}}},
		{
			"recipient ip literal", "", func(r *CreateRequest) { r.Recipients = []string{"x@sub.123"} },
			[]FieldError{{"/recipients/0", CodeInvalidEmail}},
		},
		{"message utf8", "", func(r *CreateRequest) { r.Message = "\xff" }, []FieldError{{FieldMessage, CodeInvalidFormat}}},
		{
			"message long", "", func(r *CreateRequest) { r.Message = strings.Repeat("\u00e9", MaxMessageRunes+1) },
			[]FieldError{{FieldMessage, CodeTooLong}},
		},
		{"expiry", "", func(r *CreateRequest) { r.ExpiryDays = 2 }, []FieldError{{FieldExpiryDays, CodeNotAllowed}}},
		{"password empty", "", func(r *CreateRequest) { r.Password = str("") }, []FieldError{{FieldPassword, CodeRequired}}},
		{
			"password long", "", func(r *CreateRequest) { r.Password = str(strings.Repeat("p", MaxPasswordRunes+1)) },
			[]FieldError{{FieldPassword, CodeTooLong}},
		},
		{"password utf8", "", func(r *CreateRequest) { r.Password = str("pw\xff") }, []FieldError{{FieldPassword, CodeInvalidFormat}}},
		{"language", "", func(r *CreateRequest) { r.Language = "de" }, []FieldError{{FieldLanguage, CodeNotAllowed}}},
		{"no files", "", func(r *CreateRequest) { r.Files = nil }, []FieldError{{FieldFiles, CodeRequired}}},
		{"too many files", "", func(r *CreateRequest) { r.Files = tooManyFiles }, []FieldError{{FieldFiles, CodeTooMany}}},
		{"file fields", "", func(r *CreateRequest) {
			r.Files = []FileDeclaration{
				{Name: "../etc", Size: -1, MediaType: "text/plain\r\nX: y", ExpectedSHA256: "abc"},
				{Name: "ok.txt", MediaType: strings.Repeat("m", MaxMediaTypeRunes+1), ExpectedSHA256: strings.Repeat("g", 64)},
				{Name: "CON.txt", MediaType: "\xff"},
			}
		}, []FieldError{
			{"/files/0/name", CodeInvalidFileName},
			{"/files/0/size", CodeInvalidFormat},
			{"/files/0/mediaType", CodeInvalidFormat},
			{"/files/0/expectedSha256", CodeInvalidFormat},
			{"/files/1/mediaType", CodeInvalidFormat},
			{"/files/1/expectedSha256", CodeInvalidFormat},
			{"/files/2/name", CodeInvalidFileName},
			{"/files/2/mediaType", CodeInvalidFormat},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := request()
			tc.edit(&req)
			_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, tc.key)
			var verr *ValidationError
			if !errors.As(err, &verr) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want a validation error", err)
			}
			if !reflect.DeepEqual(verr.Fields, tc.want) {
				t.Errorf("fields = %v, want %v", verr.Fields, tc.want)
			}
		})
	}
	// A message of exactly the limit after sanitization is accepted.
	req := request()
	req.Message = strings.Repeat("a", MaxMessageRunes) + "\u200b\u200b"
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, ""); err != nil {
		t.Errorf("message at the limit: %v", err)
	}
}

func TestCreateTooLarge(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		req := request()
		req.Files = []FileDeclaration{{Name: "a", Size: maxBytes - 1}, {Name: "b", Size: 1}}
		ev.mustCreate(t, internalSender(), req)
		for _, sizes := range [][]int64{{maxBytes, 1}, {math.MaxInt64, math.MaxInt64}} {
			req.Files = []FileDeclaration{{Name: "a", Size: sizes[0]}, {Name: "b", Size: sizes[1]}}
			_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, "")
			var tl *TooLargeError
			if !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || tl.MaxTransferBytes != maxBytes {
				t.Errorf("sizes %v: err = %v", sizes, err)
			}
		}
	})
}

func TestCreateQuota(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.setQuota(t, ev.a, 1000)
		req := request() // 300 bytes
		ev.mustCreate(t, internalSender(), req)
		ev.mustCreate(t, internalSender(), req)
		req.Files = []FileDeclaration{{Name: "rest", Size: 401}}
		if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, ""); !errors.Is(err, ErrQuotaExceeded) {
			t.Errorf("one byte over: err = %v", err)
		}
		req.Files = []FileDeclaration{{Name: "rest", Size: 400}}
		ev.mustCreate(t, internalSender(), req) // exactly at the quota
		if got := ev.usedBytes(t, ev.a); got != 1000 {
			t.Errorf("used = %d", got)
		}
		// Tenant B is not affected by the quota of A.
		if ev.usedBytes(t, ev.b) != 0 {
			t.Error("B uses storage")
		}
	})
}

func TestCreateQuotaConcurrent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.setQuota(t, ev.a, 5*300)
		const n = 10
		var (
			wg             sync.WaitGroup
			mu             sync.Mutex
			ok, overflowed int
		)
		for range n {
			wg.Go(func() {
				_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), request(), "")
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrQuotaExceeded):
					overflowed++
				default:
					t.Errorf("Create: %v", err)
				}
			})
		}
		wg.Wait()
		if ok != 5 || overflowed != n-5 {
			t.Errorf("ok = %d, quota errors = %d", ok, overflowed)
		}
		if got := ev.usedBytes(t, ev.a); got != 5*300 {
			t.Errorf("used = %d", got)
		}
	})
}

func TestCreateIdempotency(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		const key = "5f0c6c1e-8b7a-4a8e-9f0d-2c3b4a5d6e7f" // gitleaks:allow
		first, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), key)
		if err != nil {
			t.Fatal(err)
		}
		ev.uploads.offsets = map[string]int64{first.Files[0].ID: 0}
		replayed, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), key)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(replayed, first) {
			t.Errorf("replay = %+v, want %+v", replayed, first)
		}
		// The same key with another body is refused.
		changed := request()
		changed.ExpiryDays = 1
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), changed, key); !errors.Is(err, ErrIdempotencyMismatch) ||
			!errors.Is(err, ErrConflict) {
			t.Errorf("other body: err = %v", err)
		}
		// Another sender may use the same key.
		other := internalSender()
		other.Email = carol
		d, err := ev.svc.Create(ctx, ev.a, other, request(), key)
		if err != nil || d.ID == first.ID {
			t.Errorf("other sender: %v, %s", err, d.ID)
		}
		// The same address under another invitation conflicts.
		ext := ev.external()
		if _, err := ev.svc.Create(ctx, ev.a, ext, request(), key); err != nil {
			t.Fatal(err)
		}
		ext.InvitationID = ev.invite(t, ev.a, bob, carol).ID
		if _, err := ev.svc.Create(ctx, ev.a, ext, request(), key); !errors.Is(err, ErrConflict) {
			t.Errorf("other invitation: err = %v", err)
		}
		// After the retention, the key creates a new transfer.
		ev.clock.Advance(store.IdempotencyRetention + time.Second)
		later, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), key)
		if err != nil || later.ID == first.ID {
			t.Errorf("after retention: %v, %s", err, later.ID)
		}
	})
}

// TestCreateIdempotencyRace has a request wait in the password hasher,
// after its replay lookup, while a second request with the same key
// commits: the first one then gets the conflict of the store and returns
// the transfer of the second one.
func TestCreateIdempotencyRace(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		const key = "race-key"
		block := make(chan struct{})
		ev.hasher.entered, ev.hasher.block = make(chan struct{}), block
		pw := "secret"
		slow := request()
		slow.Password = &pw
		var (
			got  Details
			gerr error
			done = make(chan struct{})
		)
		go func() {
			defer close(done)
			got, gerr = ev.svc.Create(ctx, ev.a, internalSender(), slow, key)
		}()
		<-ev.hasher.entered
		fast, err := ev.svc.Create(ctx, ev.a, internalSender(), slow, key) // same body
		if err != nil {
			t.Fatal(err)
		}
		close(block)
		<-done
		if gerr != nil || got.ID != fast.ID || !got.PasswordProtected {
			t.Errorf("slow request = %+v, %v; want transfer %s", got, gerr, fast.ID)
		}

		// With a different body, the slow request gets the mismatch.
		block = make(chan struct{})
		ev.hasher.mu.Lock()
		ev.hasher.entered, ev.hasher.block = make(chan struct{}), block
		ev.hasher.mu.Unlock()
		done = make(chan struct{})
		go func() {
			defer close(done)
			_, gerr = ev.svc.Create(ctx, ev.a, internalSender(), slow, "race-key-2")
		}()
		<-ev.hasher.entered
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "race-key-2"); err != nil {
			t.Fatal(err)
		}
		close(block)
		<-done
		if !errors.Is(gerr, ErrIdempotencyMismatch) {
			t.Errorf("different body: err = %v", gerr)
		}
	})
}

func TestCreateFaults(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	pw := "pw"
	withPassword := request()
	withPassword.Password = &pw
	tests := []struct {
		name   string
		method string
		skip   int
		key    string
	}{
		{"blocklist", "blocked", 0, ""},
		{"tenant", "tenant", 0, ""},
		{"replay", "transferByKey", 0, "k"},
		{"used bytes", "usedBytes", 0, ""},
		{"open count", "countUploading", 0, ""},
		{"data key", "newDEK", 1, ""},
		{"insert", "createTransfer", 0, ""},
		{"insert with key", "createTransfer", 0, "k2"},
		{"read back", "transfer", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saved := ev.svc.repo
			defer func() { ev.svc.repo = saved }()
			r := ev.faults()
			r.fail[tc.method], r.skip[tc.method] = errFault, tc.skip
			if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), tc.key); !errors.Is(err, errFault) {
				t.Errorf("err = %v", err)
			}
		})
	}
	t.Run("network rules", func(t *testing.T) {
		saved := ev.svc.repo
		defer func() { ev.svc.repo = saved }()
		ev.faults().fail["networkRules"] = errFault
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, errFault) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("invitation", func(t *testing.T) {
		saved := ev.svc.repo
		defer func() { ev.svc.repo = saved }()
		ev.faults().fail["invitation"] = errFault
		if _, err := ev.svc.Create(ctx, ev.a, ev.external(), request(), ""); !errors.Is(err, errFault) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("conflict without replay", func(t *testing.T) {
		saved := ev.svc.repo
		defer func() { ev.svc.repo = saved }()
		ev.faults().fail["createTransfer"] = store.ErrConflict
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "k3"); !errors.Is(err, store.ErrConflict) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("hasher", func(t *testing.T) {
		ev.hasher.err = errFault
		defer func() { ev.hasher.err = nil }()
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), withPassword, ""); !errors.Is(err, errFault) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("replay offset", func(t *testing.T) {
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "k4"); err != nil {
			t.Fatal(err)
		}
		ev.uploads.offsetErr = errFault
		defer func() { ev.uploads.offsetErr = nil }()
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "k4"); !errors.Is(err, errFault) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("identifiers", func(t *testing.T) {
		saved, savedUpl := ev.svc.newID, ev.svc.newUploadID
		defer func() { ev.svc.newID, ev.svc.newUploadID = saved, savedUpl }()
		for _, n := range []int{0, 1} {
			calls := 0
			ev.svc.newID = func(p id.Prefix) (string, error) {
				if calls == n {
					return "", errFault
				}
				calls++
				return saved(p)
			}
			if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, errFault) {
				t.Errorf("newID failing at call %d: err = %v", n, err)
			}
		}
		ev.svc.newID = saved
		ev.svc.newUploadID = func() (string, error) { return "", errFault }
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, errFault) {
			t.Errorf("newUploadID: err = %v", err)
		}
	})
}

func TestCreateEmptyFileFailure(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	req := request()
	req.Files = []FileDeclaration{{Name: "empty", Size: 0}}
	ev.uploads.emptyErr = errFault
	d := ev.mustCreate(t, internalSender(), req)
	if d.Files[0].SHA256 != "" || d.Files[0].UploadID == "" {
		t.Errorf("file = %+v, want incomplete", d.Files[0])
	}
	ev.uploads.emptyErr = nil
	ev.faults().fail["completeUpload"] = errFault
	d = ev.mustCreate(t, internalSender(), req)
	if d.Files[0].SHA256 != "" {
		t.Errorf("file = %+v, want incomplete", d.Files[0])
	}
	if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrIncomplete) {
		t.Errorf("Finalize: %v", err)
	}
}

func TestCreateOpenTransferCap(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.svc.maxOpen = 2
		first := ev.mustCreate(t, internalSender(), request())
		ev.mustCreate(t, internalSender(), request())
		_, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "")
		var rl *RateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter != OpenTransfersRetryAfter {
			t.Fatalf("over the cap: err = %v", err)
		}
		ev.seclog.mu.Lock()
		last := ev.seclog.events[len(ev.seclog.events)-1]
		ev.seclog.mu.Unlock()
		if last.Type != securitylog.RateLimited || last.Fields[0].Value != "open_transfers" || last.IP != internalIP {
			t.Errorf("event = %+v", last)
		}
		// Another sender has its own allowance; a finalized transfer frees
		// a slot.
		other := internalSender()
		other.Email = carol
		ev.mustCreate(t, other, request())
		ev.complete(t, first.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), first.ID); err != nil {
			t.Fatal(err)
		}
		ev.mustCreate(t, internalSender(), request())

		// External senders are capped at MaxOpenTransfersExternal.
		for range MaxOpenTransfersExternal {
			ev.mustCreate(t, ev.external(), request())
		}
		if _, err := ev.svc.Create(ctx, ev.a, ev.external(), request(), ""); !errors.Is(err, ErrRateLimited) {
			t.Errorf("external over the cap: err = %v", err)
		}
	})
}

// TestCreateOpenTransferCapConcurrent checks that concurrent creations of
// one sender never exceed the cap: the count runs under the tenant lock.
func TestCreateOpenTransferCapConcurrent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.svc.maxOpen = 3
		const n = 10
		var (
			wg          sync.WaitGroup
			mu          sync.Mutex
			ok, limited int
		)
		for range n {
			wg.Go(func() {
				_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), request(), "")
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrRateLimited):
					limited++
				default:
					t.Errorf("Create: %v", err)
				}
			})
		}
		wg.Wait()
		if ok != 3 || limited != n-3 {
			t.Errorf("ok = %d, limited = %d", ok, limited)
		}
	})
}

// TestCreateOpenTransferCapExpired checks that transfers whose uploads
// expired no longer count against the cap.
func TestCreateOpenTransferCapExpired(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.svc.maxOpen = 2
		ev.mustCreate(t, internalSender(), request())
		ev.mustCreate(t, internalSender(), request())
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("at the cap: err = %v", err)
		}
		// Still active while their uploads are: recent activity.
		ev.clock.Advance(uploadTTL + time.Hour)
		ev.uploads.activity = ev.clock.Now().Add(-time.Minute)
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("active uploads: err = %v", err)
		}
		// Expired (no activity for longer than the TTL): ignored.
		ev.uploads.activity = time.Time{}
		ev.mustCreate(t, internalSender(), request())
		ev.mustCreate(t, internalSender(), request())
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("two new active transfers: err = %v", err)
		}

		// Failures while examining the transfers at the cap.
		saved := ev.svc.repo
		for _, method := range []string{"listUploading", "listFiles"} {
			r := ev.faults()
			r.fail[method] = errFault
			if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, errFault) {
				t.Errorf("%s failure: err = %v", method, err)
			}
			ev.svc.repo = saved
		}
		ev.uploads.actErr = errFault
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), ""); !errors.Is(err, errFault) {
			t.Errorf("activity failure: err = %v", err)
		}
		ev.uploads.actErr = nil

		// Older than the maximum age: not even counted, nor listed.
		ev.clock.Advance(upload.DefaultMaxAge + time.Second)
		ev.faults().fail["listUploading"] = errFault
		ev.mustCreate(t, internalSender(), request())
	})
}
