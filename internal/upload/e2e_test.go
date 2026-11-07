package upload

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tte2"
)

// e2eStream returns a valid TTE2 stream of plain bytes of random plaintext
// (chunk size tte2.MinChunkSize), as the browser produces it, and its key.
func e2eStream(t *testing.T, plain int) (stream, key []byte) {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := tte2.NewWriter(&buf, key, 0, tte2.WithChunkSize(tte2.MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(randomBytes(t, plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), key
}

// newE2EUpload creates an end-to-end encrypted transfer of tid with one
// incomplete file of size bytes.
func (ev *env) newE2EUpload(t *testing.T, size int64) upl {
	t.Helper()
	return ev.newTransferE2E(t, ev.a, internal, []int64{size}, time.Time{}, true)[0]
}

// checkE2EComplete checks that the stored file of u is exactly stream and
// that the recipient can decrypt it with key.
func (ev *env) checkE2EComplete(t *testing.T, u upl, stream, key []byte) {
	t.Helper()
	got := ev.decrypt(t, u)
	if !bytes.Equal(got, stream) {
		t.Fatal("stored ciphertext differs from the uploaded stream")
	}
	sum := sha256.Sum256(stream)
	if f := ev.file(t, u); f.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %s, want the SHA-256 of the ciphertext", f.SHA256)
	}
	r, err := tte2.NewReader(bytes.NewReader(got), key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatalf("recipient cannot decrypt: %v", err)
	}
}

// expectE2EFormat fails unless err is ErrE2EFormat wrapping tte2.ErrFormat.
func expectE2EFormat(t *testing.T, err error) {
	t.Helper()
	expectErr(t, err, ErrE2EFormat)
	expectErr(t, err, tte2.ErrFormat)
}

func TestE2EUpload(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		stream, key := e2eStream(t, 150_000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		// Small reads: the header is validated across several slices.
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, &pieceReader{r: bytes.NewReader(stream), n: 5})
		if err != nil || !st.Completed {
			t.Fatalf("Append = %+v, %v", st, err)
		}
		ev.checkE2EComplete(t, u, stream, key)
	})
}

func TestE2EResumeAcrossCheckpoints(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// Resume in the middle of the header (2, 10, 31), at its end (32),
		// after it, and across the checkpoint cadence (1 MiB in env).
		stream, key := e2eStream(t, 1_200_000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		var off int64
		for _, end := range []int64{2, 10, 31, 32, 40, 70_000, 1_100_000} {
			if st := ev.appendOK(t, u, off, stream[off:end]); st.Offset != end {
				t.Fatalf("offset = %d, want %d", st.Offset, end)
			}
			off = end
		}
		ev.appendOK(t, u, off, stream[off:])
		ev.checkE2EComplete(t, u, stream, key)
	})
}

func TestE2EResumedValidatorKeepsHeader(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// The validator restored at offset 10 still checks the rest of the
		// header: a bad chunk size byte is refused after the resume.
		stream, key := e2eStream(t, 1000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		ev.appendOK(t, u, 0, stream[:10])
		bad := bytes.Clone(stream)
		bad[10] ^= 0x40
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 10, bytes.NewReader(bad[10:]))
		expectE2EFormat(t, err)
		if st.Offset != 10 {
			t.Fatalf("offset = %d, want 10", st.Offset)
		}
		ev.appendOK(t, u, 10, stream[10:])
		ev.checkE2EComplete(t, u, stream, key)
	})
}

func TestE2EMalformedFirstByteWritesNothing(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		stream, key := e2eStream(t, 1000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		bad := bytes.Clone(stream)
		bad[0] = 'X'
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, bytes.NewReader(bad))
		expectE2EFormat(t, err)
		expectErr(t, err, tte2.ErrBadHeader)
		if st.Offset != 0 || st.Length != int64(len(stream)) || st.ExpiresAt.IsZero() {
			t.Fatalf("status = %+v", st)
		}
		f := ev.file(t, u)
		if _, err := os.Stat(ev.path(u.tid, f, ".ttef")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file created for a refused first byte: %v", err)
		}
		if got := ev.statusOK(t, u); got.Offset != 0 {
			t.Fatalf("HEAD offset = %d", got.Offset)
		}
		ev.appendOK(t, u, 0, stream)
		ev.checkE2EComplete(t, u, stream, key)
	})
}

func TestE2EMalformedHeaderSliceRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		pos  int // corrupted byte
		read int // bytes per Read of the body (0: one big slice)
		want int64
	}{
		// The whole header is read and judged before the file is created:
		// a bad header byte refuses it, nothing is stored and no file is
		// left on disk, whatever the size of the reads.
		"version, one slice":  {pos: 4, want: 0},
		"reserved, one slice": {pos: 29, want: 0},
		"kind, small reads":   {pos: 5, read: 4, want: 0},
		"salt ok, reserved":   {pos: 30, read: 4, want: 0},
		"chunk size, 3 bytes": {pos: 9, read: 3, want: 0},
	} {
		t.Run(name, func(t *testing.T) {
			run(t, func(t *testing.T, ev *env) {
				stream, key := e2eStream(t, 1000)
				u := ev.newE2EUpload(t, int64(len(stream)))
				bad := bytes.Clone(stream)
				bad[tc.pos] ^= 0x01
				var body io.Reader = bytes.NewReader(bad)
				if tc.read > 0 {
					body = &pieceReader{r: body, n: tc.read}
				}
				st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, body)
				expectE2EFormat(t, err)
				if st.Offset != tc.want {
					t.Fatalf("offset = %d, want %d", st.Offset, tc.want)
				}
				if got := ev.statusOK(t, u); got.Offset != tc.want {
					t.Fatalf("HEAD offset = %d, want %d", got.Offset, tc.want)
				}
				for _, ext := range []string{".ttef", ".ckpt"} {
					if _, err := os.Stat(ev.path(u.tid, ev.file(t, u), ext)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s left on disk: %v", ext, err)
					}
				}
				ev.appendOK(t, u, tc.want, stream[tc.want:])
				ev.checkE2EComplete(t, u, stream, key)
			})
		})
	}
}

func TestE2EDeclaredSizeInvalidForChunkSize(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// A declared size that is not a stream size for the chunk size of
		// the header is refused when the chunk size arrives (bytes 8-11).
		stream, _ := e2eStream(t, 1000)
		// One full chunk then a final chunk of 10 bytes, shorter than its tag.
		u := ev.newE2EUpload(t, tte2.HeaderSize+tte2.MinChunkSize+tte2.TagSize+10)
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, &pieceReader{r: bytes.NewReader(stream), n: 4})
		expectE2EFormat(t, err)
		if st.Offset != 0 { // the header is judged before the file is created
			t.Fatalf("offset = %d, want 0", st.Offset)
		}
	})
}

func TestE2EBadSliceAfterShortFirstPatch(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// A first PATCH that ends inside the header creates the file with
		// the bytes received; a later bad header byte is refused by the
		// session validator and the bytes before it stay.
		stream, key := e2eStream(t, 1000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		ev.appendOK(t, u, 0, stream[:10])
		bad := bytes.Clone(stream)
		bad[29] ^= 0x01
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 10, bytes.NewReader(bad[10:]))
		expectE2EFormat(t, err)
		if st.Offset != 10 {
			t.Fatalf("offset = %d, want 10", st.Offset)
		}
		ev.appendOK(t, u, 10, stream[10:])
		ev.checkE2EComplete(t, u, stream, key)
	})
}

func TestE2EFirstPatchFailsInsideHeader(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// The body fails after 10 header bytes: they are kept and the
		// request reports an interruption.
		stream, key := e2eStream(t, 1000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		boom := errors.New("connection reset")
		body := io.MultiReader(bytes.NewReader(stream[:10]), errReader{boom})
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, body)
		if !errors.Is(err, ErrInterrupted) || !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		if st.Offset != 10 {
			t.Fatalf("offset = %d, want 10", st.Offset)
		}
		ev.appendOK(t, u, 10, stream[10:])
		ev.checkE2EComplete(t, u, stream, key)
	})
}

func TestE2EDeclaredSizeTooSmall(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		for _, size := range []int64{0, 1, tte2.MinFileSize - 1} {
			u := ev.newE2EUpload(t, size)
			_, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, bytes.NewReader(make([]byte, size)))
			expectE2EFormat(t, err)
			f := ev.file(t, u)
			if _, err := os.Stat(ev.path(u.tid, f, ".ttef")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("size %d: file created: %v", size, err)
			}
		}
	})
}

func TestE2EOverflow(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		stream, key := e2eStream(t, 1000)
		u := ev.newE2EUpload(t, int64(len(stream)))
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, bytes.NewReader(append(bytes.Clone(stream), 0)))
		expectErr(t, err, ErrTooLarge)
		if st.Offset != int64(len(stream)) {
			t.Fatalf("offset = %d", st.Offset)
		}
		ev.appendOK(t, u, st.Offset, nil)
		ev.checkE2EComplete(t, u, stream, key)
	})
}

// e2eExtra builds the extra data of an end-to-end encrypted file from a
// hash state and a validator state.
func e2eExtra(sha, vs []byte) []byte {
	b := []byte{e2eExtraTag, 0, 0}
	binary.BigEndian.PutUint16(b[1:], uint16(len(sha)))
	return append(append(b, sha...), vs...)
}

func TestE2ECorruptExtraResets(t *testing.T) {
	// The extra data the test writer substitutes at the resume, given the
	// genuine one (offset 40 of a stream of size bytes).
	cases := map[string]func(t *testing.T, extra []byte, size int64) []byte{
		"ordinary format": func(_ *testing.T, extra []byte, _ int64) []byte {
			n := int(binary.BigEndian.Uint16(extra[1:3]))
			return extra[3 : 3+n]
		},
		"empty":     func(*testing.T, []byte, int64) []byte { return nil },
		"wrong tag": func(_ *testing.T, extra []byte, _ int64) []byte { b := bytes.Clone(extra); b[0] = 0xE3; return b },
		"hash length beyond the end": func(_ *testing.T, extra []byte, _ int64) []byte {
			b := bytes.Clone(extra)
			binary.BigEndian.PutUint16(b[1:3], 0xFFFF)
			return b
		},
		"bad hash state": func(_ *testing.T, extra []byte, _ int64) []byte {
			b := bytes.Clone(extra)
			b[3] = 'x'
			return b
		},
		"no validator state": func(_ *testing.T, extra []byte, _ int64) []byte {
			n := int(binary.BigEndian.Uint16(extra[1:3]))
			return extra[:3+n]
		},
		"corrupt validator state": func(_ *testing.T, extra []byte, _ int64) []byte {
			b := bytes.Clone(extra)
			b[len(b)-1] ^= 0xFF // a reserved header byte of the validator prefix
			return b
		},
		"validator offset differs": func(t *testing.T, extra []byte, size int64) []byte {
			n := int(binary.BigEndian.Uint16(extra[1:3]))
			v, err := tte2.NewValidator(size)
			if err != nil {
				t.Fatal(err)
			}
			vs, _ := v.MarshalBinary() // offset 0, the writer is at 40
			return e2eExtra(extra[3:3+n], vs)
		},
		"validator size differs": func(t *testing.T, extra []byte, size int64) []byte {
			n := int(binary.BigEndian.Uint16(extra[1:3]))
			v, err := tte2.NewValidator(size + 1)
			if err != nil {
				t.Fatal(err)
			}
			vs, _ := v.MarshalBinary()
			return e2eExtra(extra[3:3+n], vs)
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			run(t, func(t *testing.T, ev *env) {
				stream, key := e2eStream(t, 1000)
				size := int64(len(stream))
				u := ev.newE2EUpload(t, size)
				ev.appendOK(t, u, 0, stream[:40])
				before := ev.file(t, u)
				ev.eng.resumeWriter = func(dst io.Writer, dek []byte, tid, fid string, st *crypto.State, n int64) (*crypto.Writer, []byte, error) {
					w, extra, err := crypto.ResumeWriter(dst, dek, tid, fid, st, n)
					if err != nil {
						return w, extra, err
					}
					return w, alter(t, extra, size), nil
				}
				_, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 40, bytes.NewReader(stream[40:]))
				expectErr(t, err, ErrOffsetMismatch)
				if ev.file(t, u).DEKKeyID == before.DEKKeyID {
					t.Fatal("no reset")
				}
				if !strings.Contains(ev.logs.String(), "upload reset") {
					t.Fatal("reset not logged")
				}
				ev.eng.resumeWriter = crypto.ResumeWriter
				ev.appendOK(t, u, 0, stream)
				ev.checkE2EComplete(t, u, stream, key)
			})
		})
	}
}

// captureExtra makes the engine of ev record the extra data of the next
// resumed checkpoint into *got.
func captureExtra(ev *env, got *[]byte) {
	ev.eng.resumeWriter = func(dst io.Writer, dek []byte, tid, fid string, st *crypto.State, n int64) (*crypto.Writer, []byte, error) {
		w, extra, err := crypto.ResumeWriter(dst, dek, tid, fid, st, n)
		*got = bytes.Clone(extra)
		return w, extra, err
	}
}

func TestCheckpointExtraFormats(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// An ordinary file keeps the bare SHA-256 state of 1.0.
		data := randomBytes(t, 3000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data[:1000])
		var extra []byte
		captureExtra(ev, &extra)
		ev.appendOK(t, u, 1000, data[1000:])
		h := sha256.New()
		h.Write(data[:1000])
		want, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
		if !bytes.Equal(extra, want) {
			t.Fatalf("ordinary extra = %x, want the bare SHA-256 state", extra)
		}

		// An end-to-end encrypted file: tag, hash state, validator state.
		stream, _ := e2eStream(t, 1000)
		e := ev.newE2EUpload(t, int64(len(stream)))
		ev.appendOK(t, e, 0, stream[:20])
		captureExtra(ev, &extra)
		ev.appendOK(t, e, 20, stream[20:])
		h = sha256.New()
		h.Write(stream[:20])
		sha, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
		v, err := tte2.NewValidator(int64(len(stream)))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Check(stream[:20]); err != nil {
			t.Fatal(err)
		}
		vs, _ := v.MarshalBinary()
		if want := e2eExtra(sha, vs); !bytes.Equal(extra, want) {
			t.Fatalf("e2e extra = %x, want %x", extra, want)
		}
		if len(extra) > crypto.MaxCheckpointExtra {
			t.Fatalf("extra of %d bytes above crypto.MaxCheckpointExtra", len(extra))
		}
	})
}

func TestOrdinaryFileRefusesE2EExtra(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		data := randomBytes(t, 3000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data[:1000])
		before := ev.file(t, u)
		ev.eng.resumeWriter = func(dst io.Writer, dek []byte, tid, fid string, st *crypto.State, n int64) (*crypto.Writer, []byte, error) {
			w, extra, err := crypto.ResumeWriter(dst, dek, tid, fid, st, n)
			return w, e2eExtra(extra, nil), err
		}
		_, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 1000, bytes.NewReader(data[1000:]))
		expectErr(t, err, ErrOffsetMismatch)
		if ev.file(t, u).DEKKeyID == before.DEKKeyID {
			t.Fatal("no reset")
		}
	})
}

func TestCompleteRequiresCompleteE2EStream(t *testing.T) {
	v, err := tte2.NewValidator(tte2.MinFileSize)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(nil, nil, nil, Options{})
	if _, err := e.complete(t.Context(), "", store.TransferFile{}, &session{v: v}); err == nil {
		t.Fatal("completion of an incomplete end-to-end encrypted stream accepted")
	}
}

func TestE2EHelpers(t *testing.T) {
	if v, err := newE2EValidator(store.TransferFile{Size: 10}); v != nil || err != nil {
		t.Fatalf("ordinary file: %v, %v", v, err)
	}
	expectE2EFormat(t, checkE2EPrefix(tte2.MinFileSize-1, []byte("T")))
	expectE2EFormat(t, checkE2EPrefix(tte2.MinFileSize, []byte("X")))
	if err := checkE2EPrefix(tte2.MinFileSize, []byte("T")); err != nil {
		t.Fatal(err)
	}
}
