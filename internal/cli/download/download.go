package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/safepath"
	"github.com/ed-fr/transteira/internal/filename"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Sentinel errors, to be tested with errors.Is. Errors from the server are
// wrapped [*client.Problem] values.
var (
	// ErrExists: a target file already exists and Options.Force is not set
	// (the same value as safepath.ErrExists).
	ErrExists = safepath.ErrExists
	// ErrIntegrity: a downloaded file does not match its SHA-256 or size,
	// a chunk of an end-to-end encrypted stream does not authenticate, or
	// the sealed metadata disagree with the file list (altered transfer).
	// The part file is removed.
	ErrIntegrity = errors.New("integrity check failed")
	// ErrWrongKey: no sealed metadata of the transfer opens with the key,
	// or the key is not a valid TTE2 key.
	ErrWrongKey = errors.New("wrong end-to-end key")
	// ErrKeyRequired: the transfer is end-to-end encrypted, the link has
	// no key and Options.Key is nil.
	ErrKeyRequired = errors.New("end-to-end key required")
	// ErrPasswordRequired: the transfer has a password and Options.Password
	// is nil or gave an empty password.
	ErrPasswordRequired = errors.New("password required")
	// ErrWrongPassword: the password was refused and no attempt is left.
	ErrWrongPassword = errors.New("wrong password")
	// ErrTransferLocked: too many wrong passwords; the message gives the
	// wait announced by the server.
	ErrTransferLocked = errors.New("transfer locked after too many wrong passwords")
	// ErrCodeRequired: the link needs a recipient verification and
	// Options.Code is nil.
	ErrCodeRequired = errors.New("verification code required")
	// ErrVerification: the recipient verification failed (code refused
	// with no attempt left, code invalidated, no code pending).
	ErrVerification = errors.New("recipient verification failed")
	// ErrArchiveE2E: Options.Archive was asked for an end-to-end encrypted
	// transfer, for which the server builds no archive.
	ErrArchiveE2E = errors.New("no server archive for an end-to-end encrypted transfer: download the files instead")
	// ErrNoMatch: an Options.Files filter matches no file of the transfer.
	ErrNoMatch = errors.New("no such file in the transfer")
)

// errWrongKeyFormat wraps ErrWrongKey for a key that is not 43 base64url
// characters.
var errWrongKeyFormat = fmt.Errorf("%w: the key must be 43 base64url characters", ErrWrongKey)

// Options describe one download.
type Options struct {
	// Link is the parsed link; its Origin, when set, must be the server of
	// the client.
	Link Link
	// Output is the target directory, "." by default; it is created when
	// missing.
	Output string
	// Files keeps only the files whose identifier, name or relative path
	// (as written) is in the list; empty means every file. Each entry must
	// match a file ([ErrNoMatch]).
	Files []string
	// Archive downloads the server ZIP archive instead of the files (not
	// for an end-to-end encrypted transfer, nor with Files).
	Archive bool
	// Force replaces existing files.
	Force bool
	// Password returns the transfer password; it is called only when the
	// transfer is locked, again after a wrong password while attempts
	// remain (unless PasswordOnce is set).
	Password func() (string, error)
	// PasswordOnce stops at the first wrong password ([ErrWrongPassword])
	// instead of asking again: for a password read from a file, which
	// would only burn the remaining attempts.
	PasswordOnce bool
	// Code returns the verification code mailed to emailMasked; it is
	// called only for a per-recipient link awaiting verification, again
	// after a wrong code while attempts remain (unless CodeOnce is set).
	Code func(emailMasked string) (string, error)
	// CodeOnce stops at the first wrong or malformed code
	// ([ErrVerification]) instead of asking again.
	CodeOnce bool
	// Key returns the end-to-end key (the key alone or a full link) when
	// Link.Key is empty; it is called only for an encrypted transfer.
	Key func() (string, error)
	// KeyProvided reports that the caller holds an end-to-end key for this
	// link (a key file read into Key). Like a non-empty Link.Key, it makes
	// the download fail closed with [ErrIntegrity] when the server serves
	// the transfer unencrypted (downgrade): nothing is downloaded.
	KeyProvided bool
	// Progress, when set, is called as bytes are written.
	Progress func(Progress)
	// Warn, when set, receives the warnings (wrong code or password with
	// attempts left, retries).
	Warn func(string)
}

// Progress reports the bytes written for one file (or the archive).
type Progress struct {
	// File is the relative slash path being written.
	File string
	// Done and Total are bytes of plaintext.
	Done, Total int64
}

// FileResult describes one file of the transfer.
type FileResult struct {
	// ID is the file identifier on the server.
	ID string
	// Path is where the file was written (Output joined with the safe
	// relative path), or, for a skipped file, where it would have been;
	// empty in archive mode.
	Path string
	// Size is the plaintext size.
	Size int64
	// SHA256 is the checked digest of the plaintext (from the server, or
	// from the sealed metadata of an encrypted transfer).
	SHA256 string
	// ScanStatus is the antivirus status ("clean", "not_scanned_too_large",
	// "not_scanned_e2e"...): the caller warns about any other than clean.
	ScanStatus string
	// Skipped reports a file left out by Options.Files.
	Skipped bool
}

// Result describes a finished download.
type Result struct {
	// Sender is the sender address, Message the message (decrypted for an
	// encrypted transfer), both safe for a terminal.
	Sender, Message string
	// ExpiresAt is the expiry of the link.
	ExpiresAt time.Time
	// EndToEnd reports an end-to-end encrypted transfer.
	EndToEnd bool
	// Files lists every file of the transfer, in the order served.
	Files []FileResult
	// Archive is the path of the archive written in archive mode.
	Archive string
}

// copyBufferSize is the read size of a plain download.
const copyBufferSize = 256 << 10

// Run downloads the link of o through c, whose server must be the origin
// of the link. See the package documentation for the flow; the returned
// errors wrap the sentinel errors above or a [*client.Problem], and never
// hold the key, the password, the code or a cookie. Once the page is read,
// the Result is returned with the error too (sender, message, files
// planned), so that the caller can report what was done. Files are written
// one after the other; a part file left by a failure other than an
// integrity check stays on disk for the next run.
func Run(ctx context.Context, c *client.Client, o Options) (*Result, error) {
	if !id.DownloadTokenValid(o.Link.Token) {
		return nil, ErrInvalidLink
	}
	if o.Link.Origin != "" && o.Link.Origin != c.BaseURL() {
		return nil, fmt.Errorf("the link is for another server than %s: %w", c.BaseURL(), client.ErrForeignOrigin)
	}
	if o.Archive && len(o.Files) > 0 {
		return nil, errors.New("the archive holds every file: do not select files")
	}
	if o.Output == "" {
		o.Output = "."
	}
	s := &session{c: c, o: &o, base: apiPrefix + o.Link.Token}
	pt, err := s.page(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.preflight(pt); err != nil {
		return nil, err
	}
	if pt.Locked {
		if pt, err = s.open(ctx, pt); err != nil {
			return nil, err
		}
		if err := s.preflight(pt); err != nil {
			return nil, err
		}
	}
	res := &Result{
		Sender:    sanitizeLine(pt.SenderEmail),
		Message:   sanitizeMessage(pt.Message),
		ExpiresAt: pt.ExpiresAt,
		EndToEnd:  pt.EndToEndEncrypted,
	}
	if err := os.MkdirAll(o.Output, 0o750); err != nil {
		return nil, fmt.Errorf("creating the target directory: %w", err)
	}
	dir, err := safepath.Open(o.Output)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	if pt.EndToEndEncrypted {
		// The plaintext exists only on this machine: keep it private.
		dir.Private = true
		return res, s.e2e(ctx, dir, pt, res)
	}
	if o.Archive {
		return res, s.archive(ctx, dir, pt, res)
	}
	files := make([]entry, len(pt.Files))
	for i, f := range pt.Files {
		files[i] = entry{file: f, name: f.Name, path: f.Path, size: f.Size, sha: f.SHA256}
	}
	if err := s.plan(dir, files, res); err != nil {
		return res, err
	}
	for i := range files {
		if files[i].skip {
			continue
		}
		if err := s.plain(ctx, dir, &files[i]); err != nil {
			return res, err
		}
	}
	return res, nil
}

// errDowngrade is the refusal of a transfer served unencrypted to a
// caller holding an end-to-end key for it.
var errDowngrade = fmt.Errorf("%w: the link carries an end-to-end key but the server serves this transfer unencrypted", ErrIntegrity)

// preflight refuses, before any further request, what cannot succeed or
// must not be attempted: an end-to-end key with a transfer served
// unencrypted (the server would see the files, or serve others), an
// archive or a missing key for an encrypted one. It is called on the page
// before and after the unlock.
func (s *session) preflight(pt *publicTransfer) error {
	if !pt.EndToEndEncrypted {
		if s.o.Link.Key != "" || s.o.KeyProvided {
			return errDowngrade
		}
		return nil
	}
	if s.o.Archive {
		return ErrArchiveE2E
	}
	if s.o.Link.Key == "" && s.o.Key == nil {
		return ErrKeyRequired
	}
	return nil
}

// open verifies the recipient and unlocks the transfer as needed, then
// reads the page again.
func (s *session) open(ctx context.Context, pt *publicTransfer) (*publicTransfer, error) {
	if pt.VerificationRequired && !pt.Verified {
		if err := s.verify(ctx, pt.RecipientEmailMasked); err != nil {
			return nil, err
		}
		var err error
		if pt, err = s.page(ctx); err != nil {
			return nil, err
		}
	}
	if pt.Locked && pt.PasswordProtected {
		if err := s.unlock(ctx); err != nil {
			return nil, err
		}
		var err error
		if pt, err = s.page(ctx); err != nil {
			return nil, err
		}
	}
	if pt.Locked {
		return nil, errors.New("the transfer is still locked after the verification and the password")
	}
	return pt, nil
}

// entry is one file to write: the server file, its name, folder, size and
// digest (plaintext ones for an encrypted transfer), and where it goes.
type entry struct {
	file  publicFile
	index int
	name  string
	path  string
	size  int64
	sha   string
	rel   string
	skip  bool
}

// plan computes the safe path of every file, applies the filter, refuses
// existing targets without Force and fills res.Files.
func (s *session) plan(dir *safepath.Dir, files []entry, res *Result) error {
	af := make([]filename.ArchiveFile, len(files))
	for i, f := range files {
		af[i] = filename.ArchiveFile{Path: f.path, Name: f.name}
	}
	rels := safepath.Entries(af)
	matched := make([]bool, len(s.o.Files))
	for i := range files {
		files[i].index = i
		files[i].rel = rels[i]
		if len(s.o.Files) > 0 {
			files[i].skip = true
			for j, want := range s.o.Files {
				if files[i].matches(want) {
					files[i].skip, matched[j] = false, true
				}
			}
		}
	}
	for j, ok := range matched {
		if !ok {
			return fmt.Errorf("%w: %q", ErrNoMatch, sanitizeLine(s.o.Files[j]))
		}
	}
	for _, f := range files {
		if f.skip {
			continue
		}
		exists, err := dir.Exists(f.rel)
		if err != nil {
			return redactErr(err)
		}
		if exists && !s.o.Force {
			return fmt.Errorf("%w: %s (use --force to replace it)", ErrExists, client.Redact(f.rel))
		}
	}
	res.Files = make([]FileResult, len(files))
	for i, f := range files {
		res.Files[i] = FileResult{
			ID: f.file.ID, Path: filepath.Join(s.o.Output, filepath.FromSlash(f.rel)),
			Size: f.size, SHA256: strings.ToLower(f.sha), ScanStatus: f.file.ScanStatus, Skipped: f.skip,
		}
	}
	return nil
}

// matches reports whether the filter want designates e.
func (e *entry) matches(want string) bool {
	full := e.name
	if e.path != "" {
		full = e.path + "/" + e.name
	}
	return want == e.file.ID || want == e.name || want == full || want == e.rel
}

// plain downloads one file of a transfer without end-to-end encryption,
// resuming from its part file, and checks its SHA-256 before the rename.
func (s *session) plain(ctx context.Context, dir *safepath.Dir, e *entry) error {
	want, err := hex.DecodeString(e.sha)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("%w: the server gave no valid SHA-256 for %s", ErrIntegrity, client.Redact(e.rel))
	}
	part, err := dir.Part(e.rel)
	if err != nil {
		return redactErr(err)
	}
	defer func() { _ = part.Close() }() // keeps the part file for a later run
	h := sha256.New()
	if part.Size() > e.size {
		if err := part.Truncate(0); err != nil {
			return err
		}
	}
	if err := hashPart(part, e.rel, h); err != nil {
		return err
	}
	if e.size == 0 || part.Size() < e.size {
		buf := make([]byte, copyBufferSize)
		if err := s.withRetry(ctx, part, func() error { return s.fetchPlain(ctx, e, part, h, buf) }); err != nil {
			return err
		}
	}
	if got := h.Sum(nil); !equalDigest(got, want) {
		return s.fail(part, fmt.Errorf("%w: SHA-256 of %s differs from the server's", ErrIntegrity, client.Redact(e.rel)))
	}
	return s.commit(part)
}

// fetchPlain sends one request for the rest of a plain file and appends
// what arrives to part. A 200 answer to a range request (file changed,
// If-Range failed) starts the file over.
func (s *session) fetchPlain(ctx context.Context, e *entry, part *safepath.Part, h hash.Hash, buf []byte) error {
	from := part.Size()
	req, err := s.c.NewRequest(ctx, http.MethodGet, e.file.DownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	if from > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-")
		req.Header.Set("If-Range", `"`+strings.ToLower(e.sha)+`"`)
	}
	resp, err := s.c.Do(ctx, req, client.Policy{Anonymous: true})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	start, err := checkRange(resp, from, e.size)
	if err != nil {
		return err
	}
	if start == 0 && from > 0 {
		if err := part.Truncate(0); err != nil {
			return err
		}
		h.Reset()
	}
	return s.copyBody(resp.Body, part, h, buf, e.rel, e.size)
}

// copyBody appends body to part and h until part reaches total bytes.
// A read error is a retryable *client.RequestError; a write error is not.
func (s *session) copyBody(body io.Reader, part *safepath.Part, h io.Writer, buf []byte, rel string, total int64) error {
	r := io.LimitReader(body, total-part.Size())
	for part.Size() < total {
		n, rerr := r.Read(buf)
		if n > 0 {
			if _, err := part.Write(buf[:n]); err != nil {
				return fmt.Errorf("writing %s: %w", client.Redact(rel), redactErr(err))
			}
			_, _ = h.Write(buf[:n]) // neither a hash nor io.Discard fails
			s.progress(rel, part.Size(), total)
		}
		if rerr == io.EOF {
			if part.Size() < total {
				return interrupted(io.ErrUnexpectedEOF)
			}
			return nil
		}
		if rerr != nil {
			return interrupted(rerr)
		}
	}
	return nil
}

// interrupted wraps an error met while reading an answer body as a
// retryable request error.
func interrupted(err error) error {
	return &client.RequestError{Method: http.MethodGet, Path: "download stream", Err: err, Temporary: true}
}

// checkRange checks the status and Content-Range of a file answer to a
// request from byte from of a file of size bytes, and returns the offset
// of the first byte of the body.
func checkRange(resp *http.Response, from, size int64) (int64, error) {
	switch resp.StatusCode {
	case http.StatusOK:
		if resp.ContentLength >= 0 && resp.ContentLength != size {
			return 0, fmt.Errorf("%w: the server sent %d bytes for a file of %d", ErrIntegrity, resp.ContentLength, size)
		}
		return 0, nil
	case http.StatusPartialContent:
		start, total, ok := parseContentRange(resp.Header.Get("Content-Range"))
		if !ok || start != from || total != size {
			return 0, fmt.Errorf("%w: unexpected Content-Range %q", ErrIntegrity, client.Redact(resp.Header.Get("Content-Range")))
		}
		if resp.ContentLength >= 0 && resp.ContentLength != size-from {
			return 0, fmt.Errorf("%w: the server sent %d bytes from offset %d of %d", ErrIntegrity, resp.ContentLength, from, size)
		}
		return start, nil
	default:
		return 0, fmt.Errorf("unexpected HTTP %d for a file download", resp.StatusCode)
	}
}

// parseContentRange parses "bytes start-end/total" with end = total-1.
func parseContentRange(v string) (start, total int64, ok bool) {
	start, end, total, ok := contentRange(v)
	if !ok || end != total-1 {
		return 0, 0, false
	}
	return start, total, true
}

// contentRange parses "bytes start-end/total" with start <= end < total.
func contentRange(v string) (start, end, total int64, ok bool) {
	rest, ok := strings.CutPrefix(v, "bytes ")
	if !ok {
		return 0, 0, 0, false
	}
	rng, tot, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, 0, 0, false
	}
	a, b, ok := strings.Cut(rng, "-")
	if !ok {
		return 0, 0, 0, false
	}
	start, err1 := strconv.ParseInt(a, 10, 64)
	end, err2 := strconv.ParseInt(b, 10, 64)
	total, err3 := strconv.ParseInt(tot, 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || start < 0 || start > end || end >= total {
		return 0, 0, 0, false
	}
	return start, end, total, true
}

// retry reports whether err may be retried after attempt failures, and
// waits the pause of the client policy first.
func (s *session) retry(ctx context.Context, attempt int, err error) bool {
	if ctx.Err() != nil || attempt >= client.DefaultMaxAttempts || !client.IsRetryable(err) {
		return false
	}
	s.warn("download interrupted, resuming: " + client.Redact(err.Error()))
	return s.c.Pause(ctx, attempt, err, client.Policy{}) == nil
}

// commit renames a checked part file to its final path.
func (s *session) commit(part *safepath.Part) error {
	if err := part.Commit(s.o.Force); err != nil {
		return redactErr(err)
	}
	return nil
}

// fail removes part and returns err.
func (s *session) fail(part *safepath.Part, err error) error {
	if aerr := part.Abort(); aerr != nil {
		return errors.Join(err, redactErr(aerr))
	}
	return err
}

// progress reports through Options.Progress.
func (s *session) progress(rel string, done, total int64) {
	if s.o.Progress != nil {
		s.o.Progress(Progress{File: rel, Done: done, Total: total})
	}
}

// archive downloads the server ZIP archive into one file. The archive has
// no digest nor Range support: an interrupted stream starts over, and the
// size received is checked against Content-Length.
func (s *session) archive(ctx context.Context, dir *safepath.Dir, pt *publicTransfer, res *Result) error {
	body := strings.TrimPrefix(s.o.Link.Token, "dl_")
	name := "transfer-" + body[:8] + ".zip"
	rel := safepath.Entries([]filename.ArchiveFile{{Name: name}})[0]
	exists, err := dir.Exists(rel)
	if err != nil {
		return redactErr(err)
	}
	if exists && !s.o.Force {
		return fmt.Errorf("%w: %s (use --force to replace it)", ErrExists, rel)
	}
	for _, f := range pt.Files {
		res.Files = append(res.Files, FileResult{ID: f.ID, Size: f.Size, SHA256: strings.ToLower(f.SHA256), ScanStatus: f.ScanStatus})
	}
	ref := s.base + "/archive" // never a URL taken from the answer
	part, err := dir.Part(rel)
	if err != nil {
		return redactErr(err)
	}
	defer func() { _ = part.Close() }() // keeps the part file for a later run
	buf := make([]byte, copyBufferSize)
	for attempt := 1; ; attempt++ {
		err := s.fetchArchive(ctx, ref, part, rel, buf)
		if err == nil {
			break
		}
		if !s.retry(ctx, attempt, err) {
			return s.fail(part, err)
		}
	}
	if err := part.Commit(s.o.Force); err != nil {
		return redactErr(err)
	}
	res.Archive = filepath.Join(s.o.Output, filepath.FromSlash(rel))
	return nil
}

// fetchArchive streams the archive once into part, from its start.
func (s *session) fetchArchive(ctx context.Context, ref string, part *safepath.Part, rel string, buf []byte) error {
	if err := part.Truncate(0); err != nil {
		return err
	}
	req, err := s.c.NewRequest(ctx, http.MethodGet, ref, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := s.c.Do(ctx, req, client.Policy{Anonymous: true})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.ContentLength < 0 {
		return fmt.Errorf("unexpected archive answer: HTTP %d, length %d", resp.StatusCode, resp.ContentLength)
	}
	return s.copyBody(resp.Body, part, io.Discard, buf, rel, resp.ContentLength)
}

// equalDigest compares two digests.
func equalDigest(a, b []byte) bool {
	return len(a) == len(b) && string(a) == string(b)
}

// hashPart feeds the bytes already in part into h (resume across runs),
// reading them through the file safepath opened.
func hashPart(part *safepath.Part, rel string, h io.Writer) error {
	if _, err := io.Copy(h, io.NewSectionReader(part, 0, part.Size())); err != nil {
		return fmt.Errorf("reading the partial file of %s: %w", client.Redact(rel), redactErr(err))
	}
	return nil
}

// redactErr rewrites err so that its message goes through client.Redact
// (paths and identifiers shortened), keeping it testable with errors.Is.
func redactErr(err error) error {
	if err == nil {
		return nil
	}
	msg := client.Redact(err.Error())
	if msg == err.Error() {
		return err
	}
	return &redacted{msg: msg, err: err}
}

// redacted is an error whose message was redacted.
type redacted struct {
	msg string
	err error
}

func (r *redacted) Error() string { return r.msg }
func (r *redacted) Unwrap() error { return r.err }

// sanitizeMessage makes a message from the server or the sender safe for a
// terminal: valid UTF-8, no hidden character (line feeds and tabs kept).
func sanitizeMessage(s string) string {
	return textsafe.SanitizeMessage(strings.ToValidUTF8(s, "�"))
}

// sanitizeLine is sanitizeMessage on one line: line feeds and tabs become
// spaces.
func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, sanitizeMessage(s))
}
