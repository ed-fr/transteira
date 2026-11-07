package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/safepath"
	"github.com/ed-fr/transteira/internal/tte2"
)

// headerRange asks for the stream header of an encrypted file.
var headerRange = "bytes=0-" + strconv.Itoa(tte2.HeaderSize-1)

// e2e downloads and decrypts the files of an end-to-end encrypted
// transfer.
func (s *session) e2e(ctx context.Context, dir *safepath.Dir, pt *publicTransfer, res *Result) error {
	raw := s.o.Link.Key
	if raw == "" {
		in, err := s.o.Key()
		if err != nil {
			return err
		}
		if raw, err = keyFromInput(in); err != nil {
			return err
		}
	}
	key, err := tte2.DecodeKey(raw)
	if err != nil {
		return errWrongKeyFormat
	}
	files, err := openMetadata(key, pt.Files)
	if err != nil {
		return err
	}
	if pt.EncryptedMessage != "" {
		msg, err := tte2.OpenMessage(key, pt.EncryptedMessage)
		if err != nil {
			return fmt.Errorf("%w: the message of the transfer does not open (altered transfer)", ErrIntegrity)
		}
		res.Message = sanitizeMessage(msg)
	}
	if err := s.plan(dir, files, res); err != nil {
		return err
	}
	for i := range files {
		if files[i].skip {
			continue
		}
		if err := s.encrypted(ctx, dir, &files[i], key); err != nil {
			return err
		}
	}
	return nil
}

// openMetadata opens the sealed metadata of every file, at its position in
// the list served. None opening means a wrong key; some only, or a count
// other than the number of files listed, an altered transfer (a file
// removed, added, moved or swapped by the server). An empty list is an
// altered transfer too: a sender always seals at least one file, and
// without any the key could not be checked.
func openMetadata(key []byte, list []publicFile) ([]entry, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: the encrypted transfer lists no file (altered transfer)", ErrIntegrity)
	}
	files := make([]entry, len(list))
	opened, authFailures := 0, 0
	for i, f := range list {
		m, err := tte2.OpenMetadata(key, i, f.EncryptedMetadata)
		if err != nil {
			if errors.Is(err, tte2.ErrAuth) {
				authFailures++
			}
			continue
		}
		opened++
		if m.Count != len(list) {
			return nil, fmt.Errorf("%w: the transfer lists %d files, the sender sealed %d (altered transfer)", ErrIntegrity, len(list), m.Count)
		}
		files[i] = entry{file: f, name: m.Name, path: m.Path, size: m.Size, sha: m.SHA256}
	}
	switch {
	case opened == len(list):
		return files, nil
	case opened == 0 && authFailures == len(list):
		return nil, ErrWrongKey
	default:
		return nil, fmt.Errorf("%w: %d of %d file descriptions do not open (altered transfer)", ErrIntegrity, len(list)-opened, len(list))
	}
}

// stream is the decryption state of one encrypted file.
type stream struct {
	e     *entry
	key   []byte
	part  *safepath.Part
	h     hash.Hash
	cc    *tte2.ChunkCipher
	count int64  // chunks in the stream
	next  int64  // next chunk to write
	buf   []byte // one sealed chunk
}

// encrypted downloads one file of an end-to-end encrypted transfer,
// decrypting it on the fly into its part file, and checks the plaintext
// size and SHA-256 of the sealed metadata before the rename. An integrity
// failure removes the part file.
func (s *session) encrypted(ctx context.Context, dir *safepath.Dir, e *entry, key []byte) error {
	part, err := dir.Part(e.rel)
	if err != nil {
		return redactErr(err)
	}
	defer func() { _ = part.Close() }() // keeps the part file for a later run
	if err := s.decrypt(ctx, e, key, part); err != nil {
		if errors.Is(err, ErrIntegrity) {
			return s.fail(part, err)
		}
		return err
	}
	return s.commit(part)
}

// decrypt fills part with the plaintext of e and checks it.
func (s *session) decrypt(ctx context.Context, e *entry, key []byte, part *safepath.Part) error {
	st := &stream{e: e, key: key, part: part, h: sha256.New()}
	if part.Size() > e.size {
		if err := part.Truncate(0); err != nil {
			return err
		}
	}
	if part.Size() > 0 {
		if err := s.withRetry(ctx, part, func() error { return s.fetchHeader(ctx, st) }); err != nil {
			return err
		}
		c := int64(st.cc.ChunkSize())
		st.next = part.Size() / c
		if err := part.Truncate(st.next * c); err != nil {
			return err
		}
		if err := hashPart(part, e.rel, st.h); err != nil {
			return err
		}
	}
	if st.cc == nil || st.next < st.count {
		if err := s.withRetry(ctx, part, func() error { return s.fetchChunks(ctx, st) }); err != nil {
			return err
		}
	}
	want, _ := hex.DecodeString(e.sha) // checked by tte2.OpenMetadata
	if part.Size() != e.size || !equalDigest(st.h.Sum(nil), want) {
		return fmt.Errorf("%w: %s does not match the size and SHA-256 sealed by the sender", ErrIntegrity, client.Redact(e.rel))
	}
	return nil
}

// withRetry calls fetch until it succeeds, pausing after each retryable
// failure; only failures in a row, without new bytes in part, count
// against the limit.
func (s *session) withRetry(ctx context.Context, part *safepath.Part, fetch func() error) error {
	last := part.Size()
	for attempt := 1; ; attempt++ {
		err := fetch()
		if err == nil {
			return nil
		}
		if part.Size() > last {
			// New bytes: this failure is the first of a new series.
			last, attempt = part.Size(), 1
		}
		if !s.retry(ctx, attempt, err) {
			return err
		}
	}
}

// request sends a GET for the file of st with the given Range ("" for
// none), conditional on the ciphertext digest.
func (s *session) request(ctx context.Context, st *stream, rng string) (*http.Response, error) {
	req, err := s.c.NewRequest(ctx, http.MethodGet, st.e.file.DownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	if rng != "" {
		req.Header.Set("Range", rng)
		req.Header.Set("If-Range", `"`+strings.ToLower(st.e.file.SHA256)+`"`)
	}
	return s.c.Do(ctx, req, client.Policy{Anonymous: true})
}

// fetchHeader reads the stream header of a file being resumed.
func (s *session) fetchHeader(ctx context.Context, st *stream) error {
	resp, err := s.request(ctx, st, headerRange)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusPartialContent {
		start, end, total, ok := contentRange(resp.Header.Get("Content-Range"))
		if !ok || start != 0 || end != tte2.HeaderSize-1 || total != st.e.file.Size {
			return fmt.Errorf("%w: unexpected Content-Range %q", ErrIntegrity, client.Redact(resp.Header.Get("Content-Range")))
		}
	} else if _, err := checkRange(resp, 0, st.e.file.Size); err != nil {
		return err
	}
	return s.readHeader(resp.Body, st)
}

// readHeader reads and checks the stream header, and sets the cipher of st
// (or checks that the header did not change).
func (s *session) readHeader(body io.Reader, st *stream) error {
	var raw [tte2.HeaderSize]byte
	if _, err := io.ReadFull(body, raw[:]); err != nil {
		return interrupted(err)
	}
	if st.cc != nil {
		if b := st.cc.Header().Bytes(); !bytes.Equal(b[:], raw[:]) {
			return fmt.Errorf("%w: the stream of %s changed", ErrIntegrity, client.Redact(st.e.rel))
		}
		return nil
	}
	h, err := tte2.ParseHeader(raw[:])
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrIntegrity, client.Redact(st.e.rel), err)
	}
	cc, err := tte2.NewChunkCipher(st.key, st.e.index, h)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrIntegrity, client.Redact(st.e.rel), err)
	}
	plain, ok := tte2.PlaintextSize(st.e.file.Size, h.ChunkSize)
	if !ok || plain != st.e.size {
		return fmt.Errorf("%w: the stream size of %s does not match its sealed size", ErrIntegrity, client.Redact(st.e.rel))
	}
	st.cc, st.count = cc, tte2.ChunkCount(plain, h.ChunkSize)
	st.buf = make([]byte, h.ChunkSize+tte2.TagSize)
	return nil
}

// fetchChunks sends one request for the stream from the next chunk on (or
// from its start when the header is not known yet) and decrypts what
// arrives into the part file.
func (s *session) fetchChunks(ctx context.Context, st *stream) error {
	var from int64
	if st.cc != nil {
		from = tte2.ChunkOffset(st.next, st.cc.ChunkSize())
	}
	rng := ""
	if from > 0 {
		rng = "bytes=" + strconv.FormatInt(from, 10) + "-"
	}
	resp, err := s.request(ctx, st, rng)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	start, err := checkRange(resp, from, st.e.file.Size)
	if err != nil {
		return err
	}
	if st.cc == nil || start == 0 {
		// A fresh download, or a full answer to a range request (If-Range
		// failed): the header comes first and must be the known one.
		if err := s.readHeader(resp.Body, st); err != nil {
			return err
		}
		if from > 0 {
			if _, err := io.CopyN(io.Discard, resp.Body, from-tte2.HeaderSize); err != nil {
				return interrupted(err)
			}
		}
	}
	return s.readChunks(resp.Body, st)
}

// readChunks opens the chunks of body, from chunk st.next on, and appends
// their plaintext to the part file.
func (s *session) readChunks(body io.Reader, st *stream) error {
	c := st.cc.ChunkSize()
	for st.next < st.count {
		n := c + tte2.TagSize
		last := st.next == st.count-1
		if last {
			n = int(st.e.file.Size - tte2.ChunkOffset(st.next, c))
		}
		if _, err := io.ReadFull(body, st.buf[:n]); err != nil {
			return interrupted(err)
		}
		plain, err := st.cc.Open(st.buf[:0], uint64(st.next), st.buf[:n], last) //nolint:gosec // G115: next is in [0, count)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrIntegrity, client.Redact(st.e.rel), err)
		}
		if _, err := st.part.Write(plain); err != nil {
			return fmt.Errorf("writing %s: %w", client.Redact(st.e.rel), redactErr(err))
		}
		st.h.Write(plain)
		st.next++
		s.progress(st.e.rel, st.part.Size(), st.e.size)
	}
	return nil
}
