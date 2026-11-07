package upload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ed-fr/transteira/internal/tte2"
)

// stateVersion is the format version of the state file.
const stateVersion = 1

// maxStateBytes bounds the state file read (1000 files of 20 GB hold about
// 900 MB of chunk digests at most; real transfers stay far below). A
// variable for the tests.
var maxStateBytes = 1 << 30

// state is the content of the state file (see the package documentation).
// It holds the end-to-end key: never print it.
type state struct {
	Version        int    `json:"version"`
	Identity       string `json:"identity"`
	IdempotencyKey string `json:"idempotencyKey"`
	TransferID     string `json:"transferId,omitempty"`
	// Finalized is set once finalizeTransfer answered.
	Finalized bool `json:"finalized,omitempty"`
	// Link is the link-only download link returned by finalizeTransfer.
	Link string `json:"link,omitempty"`
	// Key is the end-to-end transfer key K and EncryptedMessage the
	// sealed message.
	Key              []byte      `json:"key,omitempty"`
	EncryptedMessage string      `json:"encryptedMessage,omitempty"`
	Files            []fileState `json:"files"`
}

// fileState is the state of one file.
type fileState struct {
	localFile
	SHA256    string `json:"sha256"`
	MediaType string `json:"mediaType,omitempty"`
	UploadURL string `json:"uploadUrl,omitempty"`
	// Salt and ChunkSize form the end-to-end header; CipherSize and
	// CipherSHA256 describe the ciphertext; ChunkDigests concatenates the
	// SHA-256 of every plaintext chunk; Metadata is the sealed metadata.
	Salt         []byte `json:"salt,omitempty"`
	ChunkSize    int    `json:"chunkSize,omitempty"`
	CipherSize   int64  `json:"cipherSize,omitempty"`
	CipherSHA256 string `json:"cipherSha256,omitempty"`
	ChunkDigests []byte `json:"chunkDigests,omitempty"`
	Metadata     string `json:"metadata,omitempty"`
}

// e2e reports whether the state is that of an end-to-end transfer.
func (s *state) e2e() bool { return s.Key != nil }

// header returns the end-to-end header of the file.
func (f *fileState) header() tte2.Header {
	h := tte2.Header{ChunkSize: f.ChunkSize}
	copy(h.Salt[:], f.Salt)
	return h
}

// wireSize returns the size declared to the server.
func (f *fileState) wireSize(e2e bool) int64 {
	if e2e {
		return f.CipherSize
	}
	return f.Size
}

// wireSHA256 returns the expectedSha256 declared to the server.
func (f *fileState) wireSHA256(e2e bool) string {
	if e2e {
		return f.CipherSHA256
	}
	return f.SHA256
}

// newIdempotencyKey returns 32 random hexadecimal characters.
func newIdempotencyKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24
	return hex.EncodeToString(b[:])
}

// validate checks the consistency of a state read from the disk.
func (s *state) validate() error {
	if s.Version != stateVersion || s.IdempotencyKey == "" || len(s.Files) == 0 {
		return errors.New("unexpected content")
	}
	if s.Key != nil && len(s.Key) != tte2.KeySize {
		return errors.New("invalid key")
	}
	for i := range s.Files {
		f := &s.Files[i]
		if f.Size < 0 || f.Path == "" {
			return fmt.Errorf("file %d: invalid", i)
		}
		if !s.e2e() {
			continue
		}
		count := tte2.ChunkCount(f.Size, f.ChunkSize)
		if len(f.Salt) != tte2.SaltSize || count < 0 || int64(len(f.ChunkDigests)) != count*sha256.Size ||
			f.CipherSize != tte2.CiphertextSize(f.Size, f.ChunkSize) || f.Metadata == "" {
			return fmt.Errorf("file %d: invalid end-to-end state", i)
		}
	}
	return nil
}

// matches returns ErrStateMismatch unless the state belongs to the deposit
// identity id and lists exactly files, unchanged.
func (s *state) matches(id string, files []localFile) error {
	if s.Identity != id {
		return fmt.Errorf("%w: the state file belongs to another upload", ErrStateMismatch)
	}
	if len(s.Files) != len(files) {
		return fmt.Errorf("%w: the list of files changed", ErrStateMismatch)
	}
	for i, f := range files {
		if s.Files[i].localFile != f {
			return fmt.Errorf("%w: %s changed", ErrStateMismatch, f.Path)
		}
	}
	return nil
}

// loadState reads the state file at path; a missing file gives (nil, nil).
// The state file must be a regular file, not a symbolic link, and on Unix
// private to the current user (mode without any 0o077 bit, same owner):
// it holds the end-to-end key and the upload URLs, and a state file
// planted by another user could redirect the upload (threat T-337).
func loadState(path string) (*state, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("upload: state file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("upload: the state file %s is not a regular file (symbolic link or other): remove it", path)
	}
	if err := checkStateOwner(path, fi); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0) //nolint:gosec // G304: the state file chosen by the user
	if err != nil {
		return nil, fmt.Errorf("upload: state file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if ofi, err := f.Stat(); err != nil || !os.SameFile(fi, ofi) {
		return nil, fmt.Errorf("upload: the state file %s changed while it was opened", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxStateBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("upload: state file: %w", err)
	}
	var s state
	if len(data) > maxStateBytes {
		err = errors.New("too large")
	} else if err = json.Unmarshal(data, &s); err == nil {
		err = s.validate()
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the state file %s is invalid (%s)", ErrStateMismatch, path, err.Error())
	}
	return &s, nil
}

// save writes the state atomically to path, with mode 0600: a temporary
// file in the same directory (os.CreateTemp creates it with mode 0600),
// synced, then renamed.
func (s *state) save(path string) error {
	data, _ := json.Marshal(s) //nolint:errchkjson // strings, integers, booleans and byte slices: it cannot fail
	tmp, err := os.CreateTemp(filepath.Dir(path), StatePrefix+"*.tmp")
	if err != nil {
		return fmt.Errorf("upload: state file: %w", err)
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("upload: state file: %w", err)
	}
	return nil
}

// cipher returns the chunk cipher of end-to-end file index.
func (s *state) cipher(index int) (*tte2.ChunkCipher, error) {
	cc, err := tte2.NewChunkCipher(s.Key, index, s.Files[index].header())
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}
	return cc, nil
}

// removeState deletes the state file, ignoring a missing one.
func removeState(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("upload: state file: %w", err)
	}
	return nil
}
