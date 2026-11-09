package public

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// sealedFixture is a sealed text the tests pass around; it must never
// appear outside the creation and the reveal.
const sealedFixture = "AQvm_LNcuMssDUaZI6WQ3iGRK4gIg8iiNhOpsnYu-dMoF2eTMvmbWpRI1yivl-6L03VwgcaRxEruSIQs7Q"

// fakeSecrets records its calls and answers with the configured values.
type fakeSecrets struct {
	err      error
	created  secret.Created
	status   secret.Status
	revealed secret.Revealed
	page     store.Page[store.Secret]

	sender    transfer.Sender
	req       secret.CreateRequest
	ip        netip.Addr
	token     string
	keyProof  string
	proof     string
	email     string
	cursor    string
	limit     int
	secretID  string
	callCount int
}

func (f *fakeSecrets) Create(_ context.Context, _ *tenant.Tenant, sender transfer.Sender, req secret.CreateRequest) (secret.Created, error) {
	f.callCount++
	f.sender, f.req = sender, req
	return f.created, f.err
}

func (f *fakeSecrets) Status(_ context.Context, _ *tenant.Tenant, ip netip.Addr, token string) (secret.Status, error) {
	f.callCount++
	f.ip, f.token = ip, token
	return f.status, f.err
}

func (f *fakeSecrets) Reveal(_ context.Context, _ *tenant.Tenant, ip netip.Addr, token, keyProof, proof string) (secret.Revealed, error) {
	f.callCount++
	f.ip, f.token, f.keyProof, f.proof = ip, token, keyProof, proof
	return f.revealed, f.err
}

func (f *fakeSecrets) ListMine(_ context.Context, _ *tenant.Tenant, email, cursor string, limit int) (store.Page[store.Secret], error) {
	f.callCount++
	f.email, f.cursor, f.limit = email, cursor, limit
	return f.page, f.err
}

func (f *fakeSecrets) DeleteMine(_ context.Context, _ *tenant.Tenant, email string, ip netip.Addr, secID string) error {
	f.callCount++
	f.email, f.ip, f.secretID = email, ip, secID
	return f.err
}

var clientIP = netip.MustParseAddr("192.0.2.7")

// secretCalls are the five operations, each with a context carrying the
// credential it needs.
func secretCalls(t *testing.T) map[string]func(*Server, context.Context) error {
	t.Helper()
	return map[string]func(*Server, context.Context) error{
		"create": func(s *Server, ctx context.Context) error {
			_, err := s.CreateSecret(ctx, gen.CreateSecretRequestObject{Body: &gen.SecretCreate{}})
			return err
		},
		"status": func(s *Server, ctx context.Context) error {
			_, err := s.GetSecretLink(ctx, gen.GetSecretLinkRequestObject{SecretToken: "tts_x"})
			return err
		},
		"reveal": func(s *Server, ctx context.Context) error {
			_, err := s.RevealSecret(ctx, gen.RevealSecretRequestObject{SecretToken: "tts_x", Body: &gen.SecretReveal{}})
			return err
		},
		"list": func(s *Server, ctx context.Context) error {
			_, err := s.ListMySecrets(ctx, gen.ListMySecretsRequestObject{})
			return err
		},
		"delete": func(s *Server, ctx context.Context) error {
			_, err := s.DeleteMySecret(ctx, gen.DeleteMySecretRequestObject{SecretId: "sec_x"})
			return err
		},
	}
}

func TestSecretOperationsRequireTenantAndService(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	for name, call := range secretCalls(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := NewServer(WithSecrets(&fakeSecrets{}))
			wantProblem(t, call(srv, context.Background()), problem.CodeUnknownTenant)
			if err := call(NewServer(), depositCtx(t, &info)); !errors.Is(err, errNoSecretService) {
				t.Errorf("without secret service: %v", err)
			}
		})
	}
	// The creator side needs a credential.
	srv := NewServer(WithSecrets(&fakeSecrets{}))
	calls := secretCalls(t)
	wantProblem(t, calls["create"](srv, depositCtx(t, nil)), problem.CodeUnauthenticated)
	wantProblem(t, calls["list"](srv, meCtx(t, false)), problem.CodeUnauthenticated)
	wantProblem(t, calls["delete"](srv, meCtx(t, false)), problem.CodeUnauthenticated)
}

func TestCreateSecret(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	expires := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	f := &fakeSecrets{created: secret.Created{ID: "sec_1", Token: "tts_tok", State: store.SecretActive, ExpiresAt: expires}}
	srv := NewServer(WithSecrets(f))
	recipient, sender := gen.Email("carol@customer.example.net"), gen.Email("alice@entity-a.example.com")
	resp, err := srv.CreateSecret(depositCtx(t, &info), gen.CreateSecretRequestObject{Body: &gen.SecretCreate{
		EncryptedText: sealedFixture, Verifier: "v", KeyVerifier: "kv", ExpiresIn: "1d", Delivery: "email",
		Recipient: &recipient, ReadReceipt: new(true), SenderEmail: &sender,
		Passphrase: &gen.SecretPassphrase{Kdf: "pbkdf2-sha256", Iterations: 600000, Salt: "fYFgqj_v4D4pjxFwzmjGvQ"},
		File:       &gen.SecretFileDeclaration{Size: 48, EncryptedMetadata: "AQ"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.CreateSecret201JSONResponse)
	if !ok || got.Id != "sec_1" || got.Token != "tts_tok" || got.State != "active" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("response %T %+v", resp, resp)
	}
	want := secret.CreateRequest{
		EncryptedText: sealedFixture, Verifier: "v", KeyVerifier: "kv", ExpiresIn: "1d", Delivery: "email",
		Recipient: &recipient, ReadReceipt: true, SenderEmail: &sender,
		Passphrase: &secret.Passphrase{KDF: "pbkdf2-sha256", Iterations: 600000, Salt: "fYFgqj_v4D4pjxFwzmjGvQ"},
		File:       &secret.File{Size: 48, EncryptedMetadata: "AQ"},
	}
	if f.req.EncryptedText != want.EncryptedText || *f.req.Recipient != *want.Recipient || !f.req.ReadReceipt ||
		*f.req.Passphrase != *want.Passphrase || *f.req.File != *want.File || *f.req.SenderEmail != *want.SenderEmail ||
		f.req.Delivery != want.Delivery || f.req.ExpiresIn != want.ExpiresIn || f.req.Verifier != "v" || f.req.KeyVerifier != "kv" {
		t.Errorf("request = %+v", f.req)
	}
	if f.sender.Email != info.Email || f.sender.Kind != store.DepositorInternal || f.sender.ClientIP != clientIP {
		t.Errorf("sender = %+v", f.sender)
	}
	// A pending secret has no expiry.
	f.created = secret.Created{ID: "sec_2", Token: "tts_2", State: store.SecretPending}
	resp, err = srv.CreateSecret(depositCtx(t, &info), gen.CreateSecretRequestObject{Body: &gen.SecretCreate{}})
	if got, ok := resp.(gen.CreateSecret201JSONResponse); err != nil || !ok || got.ExpiresAt != nil || got.State != "pending" {
		t.Errorf("pending: %+v, %v", resp, err)
	}
	// Without body.
	before := f.callCount
	_, err = srv.CreateSecret(depositCtx(t, &info), gen.CreateSecretRequestObject{})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != secret.FieldEncryptedText || f.callCount != before {
		t.Errorf("no body: %+v", p)
	}
}

func TestCreateSecretByAPIToken(t *testing.T) {
	t.Parallel()
	tokID := id.New(id.APIToken)
	ctx := middleware.WithAPIToken(depositCtx(t, nil), middleware.TokenPrincipal{TokenID: tokID, Name: "bot"})
	f := &fakeSecrets{created: secret.Created{ID: "sec_1", Token: "tts_tok", State: store.SecretActive}}
	if _, err := NewServer(WithSecrets(f)).CreateSecret(ctx, gen.CreateSecretRequestObject{Body: &gen.SecretCreate{}}); err != nil {
		t.Fatal(err)
	}
	if f.sender.APITokenID != tokID || f.sender.Kind != store.DepositorInternal {
		t.Errorf("sender = %+v", f.sender)
	}
}

func TestGetSecretLink(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 11, 10, 9, 0, 0, 0, time.FixedZone("x", 3600))
	f := &fakeSecrets{status: secret.Status{
		ExpiresAt: expires, FileSize: 2097200,
		Passphrase: &secret.Passphrase{KDF: "pbkdf2-sha256", Iterations: 600000, Salt: "fYFgqj_v4D4pjxFwzmjGvQ"},
	}}
	srv := NewServer(WithSecrets(f))
	resp, err := srv.GetSecretLink(depositCtx(t, nil), gen.GetSecretLinkRequestObject{SecretToken: "tts_tok"})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.GetSecretLink200JSONResponse)
	if got.Headers.CacheControl == nil || *got.Headers.CacheControl != "no-store" {
		t.Errorf("headers = %+v", got.Headers)
	}
	b := got.Body
	if b.State != "active" || !b.ExpiresAt.Equal(expires) || b.ExpiresAt.Location() != time.UTC || b.File == nil || b.File.Size != 2097200 ||
		b.Passphrase == nil || b.Passphrase.Salt != "fYFgqj_v4D4pjxFwzmjGvQ" || b.Passphrase.Iterations != 600000 || b.Passphrase.Kdf != "pbkdf2-sha256" {
		t.Errorf("body = %+v", b)
	}
	if f.token != "tts_tok" || f.ip != clientIP {
		t.Errorf("token %q, ip %v", f.token, f.ip)
	}
	// Without passphrase nor file: file is an explicit null.
	f.status = secret.Status{ExpiresAt: expires}
	resp, _ = srv.GetSecretLink(depositCtx(t, nil), gen.GetSecretLinkRequestObject{SecretToken: "tts_tok"})
	raw, _ := json.Marshal(resp.(gen.GetSecretLink200JSONResponse).Body)
	if !strings.Contains(string(raw), `"file":null`) || strings.Contains(string(raw), "passphrase") {
		t.Errorf("body = %s", raw)
	}
}

func TestRevealSecret(t *testing.T) {
	t.Parallel()
	f := &fakeSecrets{revealed: secret.Revealed{EncryptedText: sealedFixture}}
	srv := NewServer(WithSecrets(f))
	resp, err := srv.RevealSecret(depositCtx(t, nil), gen.RevealSecretRequestObject{
		SecretToken: "tts_tok", Body: &gen.SecretReveal{KeyProof: "kp", Proof: "p"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.RevealSecret200JSONResponse)
	if got.Body.EncryptedText != sealedFixture || got.Body.EncryptedMetadata != nil || got.Body.FileGrant != nil ||
		got.Headers.CacheControl == nil || *got.Headers.CacheControl != "no-store" {
		t.Errorf("response = %+v", got)
	}
	if f.token != "tts_tok" || f.keyProof != "kp" || f.proof != "p" || f.ip != clientIP {
		t.Errorf("call = %+v", f)
	}
	f.revealed.EncryptedMetadata = "AQmeta"
	resp, _ = srv.RevealSecret(depositCtx(t, nil), gen.RevealSecretRequestObject{SecretToken: "tts_tok", Body: &gen.SecretReveal{}})
	if m := resp.(gen.RevealSecret200JSONResponse).Body.EncryptedMetadata; m == nil || *m != "AQmeta" {
		t.Errorf("metadata = %v", m)
	}
	before := f.callCount
	_, err = srv.RevealSecret(depositCtx(t, nil), gen.RevealSecretRequestObject{SecretToken: "tts_tok"})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != secret.FieldKeyProof || f.callCount != before {
		t.Errorf("no body: %+v", p)
	}
}

func TestListMySecrets(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	f := &fakeSecrets{page: store.Page[store.Secret]{NextCursor: "c2", Items: []store.Secret{
		{
			ID: "sec_2", State: store.SecretDeleted, Delivery: store.SecretDeliveryEmail, RecipientEmail: "carol@customer.example.net",
			ReadReceipt: true, CreatedAt: at, EndedAt: at.Add(time.Minute), EndReason: store.SecretEndDeletedByCreator, FileSize: 4096,
		},
		{
			ID: "sec_1", State: store.SecretRead, Delivery: store.SecretDeliveryLink, CreatedAt: at, ActivatedAt: at,
			ExpiresAt: at.Add(time.Hour), ReadAt: at.Add(time.Minute), EndedAt: at.Add(time.Minute), EndReason: store.SecretEndRead,
		},
		{ID: "sec_0", State: store.SecretActive, Delivery: store.SecretDeliveryLink, CreatedAt: at, ExpiresAt: at.Add(time.Hour)},
	}}}
	limit, cursor := 3, "c1"
	resp, err := NewServer(WithSecrets(f)).ListMySecrets(meCtx(t, true), gen.ListMySecretsRequestObject{
		Params: gen.ListMySecretsParams{Limit: &limit, Cursor: &cursor},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.email != meInfo().Email || f.cursor != "c1" || f.limit != 3 {
		t.Errorf("call = %+v", f)
	}
	got := resp.(gen.ListMySecrets200JSONResponse)
	if got.NextCursor == nil || *got.NextCursor != "c2" || len(got.Items) != 3 {
		t.Fatalf("page = %+v", got)
	}
	del, read, active := got.Items[0], got.Items[1], got.Items[2]
	if del.Id != "sec_2" || del.State != "deleted" || del.Delivery != "email" || del.Recipient == nil || *del.Recipient != "carol@customer.example.net" ||
		!del.ReadReceipt || !del.HasFile || del.FileSize == nil || *del.FileSize != 4096 || del.EndReason == nil || *del.EndReason != "deleted" ||
		del.ExpiresAt != nil || del.ReadAt != nil || del.EndedAt == nil {
		t.Errorf("deleted = %+v", del)
	}
	if read.EndReason == nil || *read.EndReason != "read" || read.ReadAt == nil || read.HasFile || read.FileSize != nil || read.Recipient != nil {
		t.Errorf("read = %+v", read)
	}
	if active.EndReason != nil || active.EndedAt != nil || active.ExpiresAt == nil {
		t.Errorf("active = %+v", active)
	}
	f.page = store.Page[store.Secret]{}
	resp, _ = NewServer(WithSecrets(f)).ListMySecrets(meCtx(t, true), gen.ListMySecretsRequestObject{})
	if got := resp.(gen.ListMySecrets200JSONResponse); got.NextCursor != nil || len(got.Items) != 0 {
		t.Errorf("empty page = %+v", got)
	}
	f.err = &secret.ValidationError{Fields: []secret.FieldError{{Pointer: secret.FieldCursor, Code: secret.CodeInvalidFormat}}}
	_, err = NewServer(WithSecrets(f)).ListMySecrets(meCtx(t, true), gen.ListMySecretsRequestObject{})
	wantProblem(t, err, problem.CodeValidationFailed)
}

func TestDeleteMySecret(t *testing.T) {
	t.Parallel()
	f := &fakeSecrets{}
	resp, err := NewServer(WithSecrets(f)).DeleteMySecret(meCtx(t, true), gen.DeleteMySecretRequestObject{SecretId: "sec_1"})
	if _, ok := resp.(gen.DeleteMySecret204Response); err != nil || !ok {
		t.Fatalf("response %T, %v", resp, err)
	}
	if f.email != meInfo().Email || f.secretID != "sec_1" || f.ip != clientIP {
		t.Errorf("call = %+v", f)
	}
	f.err = secret.ErrNotFound
	_, err = NewServer(WithSecrets(f)).DeleteMySecret(meCtx(t, true), gen.DeleteMySecretRequestObject{SecretId: "sec_1"})
	wantProblem(t, err, problem.CodeNotFound)
}

func TestSecretErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err   error
		code  problem.Code
		check func(*problem.Problem) bool
	}{
		{
			&secret.ValidationError{Fields: []secret.FieldError{{Pointer: "/delivery", Code: "not-allowed", Allowed: []string{"link", "email"}}}},
			problem.CodeValidationFailed, func(p *problem.Problem) bool {
				return len(p.Errors) == 1 && p.Errors[0].Field == "/delivery" && slices.Equal(p.Errors[0].Allowed, []any{"link", "email"})
			},
		},
		{
			&secret.FormatError{Fields: []secret.FieldError{{Pointer: "/encryptedText", Code: "invalid-format"}}},
			problem.CodeSecretFormatInvalid, func(p *problem.Problem) bool { return p.Errors[0].Field == "/encryptedText" && p.Status == 400 },
		},
		{&secret.DurationError{Allowed: []string{"1h", "1d"}}, problem.CodeSecretDurationNotOffered, func(p *problem.Problem) bool {
			return p.Status == 422 && p.Errors[0].Field == "/expiresIn" && slices.Equal(p.Errors[0].Allowed, []any{"1h", "1d"})
		}},
		{&secret.FileTooLargeError{MaxBytes: 10}, problem.CodeSecretFileTooLarge, func(p *problem.Problem) bool {
			return p.Status == 413 && p.MaxTransferBytes != nil && *p.MaxTransferBytes == 10
		}},
		{&secret.LimitError{}, problem.CodeSecretLimitReached, func(p *problem.Problem) bool { return p.RetryAfterSeconds == nil }},
		{&secret.LimitError{RetryAfter: time.Hour}, problem.CodeSecretLimitReached, func(p *problem.Problem) bool {
			return p.RetryAfterSeconds != nil && *p.RetryAfterSeconds == 3600
		}},
		{&secret.RateLimitError{RetryAfter: time.Second}, problem.CodeRateLimited, func(p *problem.Problem) bool {
			return p.RetryAfterSeconds != nil && *p.RetryAfterSeconds == 1
		}},
		{&secret.GoneError{Reason: "read"}, problem.CodeSecretGone, func(p *problem.Problem) bool { return p.Reason == "read" && p.Status == 410 }},
		{&secret.ProofError{}, problem.CodeSecretProofInvalid, func(p *problem.Problem) bool { return p.AttemptsRemaining == nil }},
		{&secret.ProofError{Counted: true, Remaining: 4}, problem.CodeSecretProofInvalid, func(p *problem.Problem) bool {
			return p.AttemptsRemaining != nil && *p.AttemptsRemaining == 4
		}},
		{secret.ErrForbidden, problem.CodeDepositNotAllowed, nil},
		{secret.ErrNotFound, problem.CodeNotFound, nil},
		{secret.ErrDisabled, problem.CodeSecretsDisabled, nil},
		{secret.ErrEmailNotAllowed, problem.CodeSecretEmailNotAllowed, nil},
		{secret.ErrPassphraseRequired, problem.CodeSecretPassphraseRequired, nil},
		{secret.ErrFileNotAllowed, problem.CodeSecretFileNotAllowed, nil},
	}
	for _, tt := range tests {
		p := problemOf(t, secretError(tt.err), tt.code)
		if tt.check != nil && !tt.check(p) {
			t.Errorf("%v: problem %+v", tt.err, p)
		}
	}
	boom := errors.New("boom")
	if err := secretError(boom); !errors.Is(err, boom) {
		t.Errorf("unknown error = %v", err)
	}
	// Every operation maps the errors of the service.
	info := internalInfo()
	for name, call := range secretCalls(t) {
		ctx := depositCtx(t, &info)
		if name == "list" || name == "delete" {
			ctx = meCtx(t, true)
		}
		if err := call(NewServer(WithSecrets(&fakeSecrets{err: secret.ErrNotFound})), ctx); err == nil {
			t.Errorf("%s: no error", name)
		} else {
			wantProblem(t, err, problem.CodeNotFound)
		}
	}
}

// TestSecretAnswersHoldNothingSealed is the contract check of the data
// model (section 8, "Nothing sealed before the reveal"): in the
// specification, SecretStatus and every error answer of the public secret
// operations have no member that is, or refers to, a sealed value; and the
// answers the handlers render for each error of the service hold no sealed
// value either.
func TestSecretAnswersHoldNothingSealed(t *testing.T) {
	t.Parallel()
	doc, err := openapi3.NewLoader().LoadFromData(api.OpenAPISpec)
	if err != nil {
		t.Fatal(err)
	}
	status := doc.Components.Schemas["SecretStatus"]
	if status == nil {
		t.Fatal("no SecretStatus schema")
	}
	if path := sealedMember(status, "SecretStatus", map[*openapi3.Schema]bool{}); path != "" {
		t.Errorf("SecretStatus holds a sealed member at %s", path)
	}
	// The walker finds the sealed members of the reveal answer.
	if path := sealedMember(doc.Components.Schemas["SecretRevealed"], "SecretRevealed", map[*openapi3.Schema]bool{}); path == "" {
		t.Error("the walker misses the sealed members of SecretRevealed")
	}
	ops := map[string]string{
		"getSecretLink": "/secret-links/{secretToken}", "revealSecret": "/secret-links/{secretToken}/reveal",
		"createSecret": "/secrets", "listMySecrets": "/me/secrets", "deleteMySecret": "/me/secrets/{secretId}",
		"downloadSecretFile": "/secret-links/{secretToken}/file",
	}
	for opID, path := range ops {
		item := doc.Paths.Value(path)
		if item == nil {
			t.Fatalf("no path %s", path)
		}
		var op *openapi3.Operation
		for _, o := range item.Operations() {
			if o.OperationID == opID {
				op = o
			}
		}
		if op == nil {
			t.Fatalf("no operation %s", opID)
		}
		for code, resp := range op.Responses.Map() {
			success := strings.HasPrefix(code, "2")
			if success && opID != "getSecretLink" && opID != "listMySecrets" {
				continue // the creation answers the token, the reveal the sealed text: their purpose
			}
			for _, media := range resp.Value.Content {
				if media.Schema == nil {
					continue
				}
				if p := sealedMember(media.Schema, opID+" "+code, map[*openapi3.Schema]bool{}); p != "" {
					t.Errorf("%s %s holds a sealed member at %s", opID, code, p)
				}
			}
		}
	}
	// The rendered problems.
	errs := []error{
		&secret.ValidationError{Fields: []secret.FieldError{{Pointer: secret.FieldEncryptedText, Code: secret.CodeInvalidFormat}}},
		&secret.FormatError{Fields: []secret.FieldError{{Pointer: secret.FieldFileMetadata, Code: secret.CodeInvalidFormat}}},
		&secret.GoneError{Reason: secret.ReasonLocked}, &secret.ProofError{Counted: true, Remaining: 2}, secret.ErrNotFound,
		&secret.RateLimitError{RetryAfter: time.Minute},
	}
	for _, e := range errs {
		f := &fakeSecrets{err: e, status: secret.Status{ExpiresAt: time.Now()}}
		srv := NewServer(WithSecrets(f))
		_, err := srv.RevealSecret(depositCtx(t, nil), gen.RevealSecretRequestObject{
			SecretToken: "tts_tok", Body: &gen.SecretReveal{KeyProof: sealedFixture, Proof: sealedFixture},
		})
		raw, _ := json.Marshal(problem.From(err))
		if strings.Contains(string(raw), sealedFixture) || strings.Contains(string(raw), "tts_tok") {
			t.Errorf("%v renders %s", e, raw)
		}
	}
	raw, _ := json.Marshal(gen.SecretStatus{})
	for _, m := range sealedMembers {
		if strings.Contains(string(raw), `"`+m+`"`) {
			t.Errorf("gen.SecretStatus has the member %s", m)
		}
	}
}

// sealedMembers are the member names of sealed values and of what protects
// them.
var sealedMembers = []string{"encryptedText", "encryptedMetadata", "verifier", "keyVerifier", "keyProof", "proof", "token", "fileGrant"}

// sealedRefs are the schemas of the sealed values.
var sealedRefs = []string{"#/components/schemas/SecretSealedText", "#/components/schemas/EncryptedMetadata"}

// sealedMember returns the path of a member of s that is, or refers to, a
// sealed value, or "".
func sealedMember(s *openapi3.SchemaRef, path string, seen map[*openapi3.Schema]bool) string {
	if s == nil {
		return ""
	}
	if slices.Contains(sealedRefs, s.Ref) {
		return path
	}
	v := s.Value
	if v == nil || seen[v] {
		return ""
	}
	seen[v] = true
	for name, p := range v.Properties {
		if slices.Contains(sealedMembers, name) {
			return path + "/" + name
		}
		if r := sealedMember(p, path+"/"+name, seen); r != "" {
			return r
		}
	}
	for _, list := range [][]*openapi3.SchemaRef{v.AllOf, v.AnyOf, v.OneOf} {
		for _, sub := range list {
			if r := sealedMember(sub, path, seen); r != "" {
				return r
			}
		}
	}
	if r := sealedMember(v.Items, path+"[]", seen); r != "" {
		return r
	}
	if v.AdditionalProperties.Schema != nil {
		return sealedMember(v.AdditionalProperties.Schema, path+"{}", seen)
	}
	return ""
}
