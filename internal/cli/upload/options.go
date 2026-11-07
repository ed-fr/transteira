package upload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// Defaults of the zero values of [Options].
const (
	// DefaultChunkSize is the number of bytes sent by one PATCH.
	DefaultChunkSize int64 = 100 << 20
	// DefaultPollInterval is the pause between two getTransfer calls
	// while the antivirus runs.
	DefaultPollInterval = 10 * time.Second
	// StatePrefix starts the name of every state file (and of its
	// temporary file); files with this prefix are never collected.
	StatePrefix = ".transteira-upload-"
	// maxPassword is the longest transfer password the API accepts.
	maxPassword = 1024
	// maxMessageBytes bounds a plaintext message (5000 characters of up to
	// 4 bytes); the server counts characters.
	maxMessageBytes = 5000 * 4
	// maxDownloadsLimit is the largest maxDownloads of the API.
	maxDownloadsLimit = 1000
)

// Progress phases.
const (
	PhaseHash   = "hash"
	PhaseUpload = "upload"
	PhaseScan   = "scan"
)

// Errors returned by [Run], to be tested with errors.Is.
var (
	// ErrRejected: the transfer was rejected (no file could be delivered)
	// or some of its files were withheld (infected or scan_error). It is
	// returned wrapped, together with the [Result].
	ErrRejected = errors.New("upload: transfer rejected")
	// ErrStateMismatch: a file changed since the state file was written
	// (size, modification time, content of an end-to-end chunk, or the
	// server's checksum-mismatch), the state file does not match the
	// options, or it is unreadable. Run again with Restart.
	ErrStateMismatch = errors.New("upload: the files changed since the interrupted upload (use --restart)")
	// ErrInvalidOptions: the options are refused before any request.
	ErrInvalidOptions = errors.New("upload: invalid options")
)

// Options describes one deposit.
type Options struct {
	// Paths are the files and directories to send. Directories are walked
	// in lexical order; the folder of each file, relative to the parent of
	// the directory given, is sent as its path (in the sealed metadata
	// with E2E). Symbolic links and special files are skipped and
	// reported through Warn.
	Paths []string
	// Recipients are the recipient addresses (required unless LinkOnly).
	Recipients []string
	// Sender is the sender address; required with an API token. Empty
	// means the sender of the client configuration.
	Sender string
	// Message is the optional message (sealed with E2E).
	Message string
	// ExpiryDays is 1, 7 or 30.
	ExpiryDays int
	// Password protects the transfer when HasPassword is set or Password
	// is not empty. It is never written to the state file.
	Password    string
	HasPassword bool
	// DeleteAfterFirstDownload, VerifyRecipients, LinkOnly and E2E are the
	// options of createTransfer (deleteAfterFirstDownload,
	// recipientVerification, linkOnly, endToEndEncrypted).
	DeleteAfterFirstDownload, VerifyRecipients, LinkOnly, E2E bool
	// MaxDownloads caps the downloads (1 to 1000); 0 means no limit.
	MaxDownloads int
	// Level is the confidentiality level key and Language the language of
	// the recipients' mail; empty for the defaults of the tenant.
	Level, Language string
	// ChunkSize is the number of bytes per PATCH; 0 means
	// DefaultChunkSize.
	ChunkSize int64
	// StatePath is the state file; empty means
	// ./.transteira-upload-<hex>.json (see the package documentation).
	StatePath string
	// Restart cancels the transfer of an existing state file and starts
	// afresh; NoWait returns after the finalization without waiting for
	// the antivirus.
	Restart, NoWait bool
	// PollInterval is the pause between two getTransfer calls; 0 means
	// DefaultPollInterval.
	PollInterval time.Duration
	// Progress, when set, receives the progress of each phase. During an
	// upload it may be called from a transport goroutine, but never
	// concurrently with itself.
	Progress func(Progress)
	// Warn, when set, receives the warnings (skipped files...). It never
	// receives a secret.
	Warn func(string)
}

// Progress is one progress report.
type Progress struct {
	// Phase is PhaseHash, PhaseUpload or PhaseScan.
	Phase string
	// File is the local relative name of the file ("folder/name") for the
	// hash and upload phases, empty for the scan phase.
	File string
	// Done and Total count bytes of File for the hash and upload phases,
	// and the files whose analysis is over for the scan phase.
	Done, Total int64
}

// FileResult describes one file of the deposit. For an end-to-end
// encrypted transfer, Name, Path, Size and SHA256 are the local plaintext
// values (the server only knows the ciphertext); otherwise SHA256 is the
// one computed by the server.
type FileResult struct {
	Name, Path string
	Size       int64
	SHA256     string
	ScanStatus string
}

// Result is the outcome of a deposit.
type Result struct {
	// TransferID and Status are those of the transfer (Status is
	// "scanning" with NoWait).
	TransferID, Status string
	// Link is the download link of a link-only transfer (returned once by
	// finalizeTransfer), without the key; empty otherwise.
	Link string
	// Key is the transfer key of an end-to-end encrypted transfer: the
	// 43 base64url characters of tte2.EncodeKey, without the "#k=" prefix
	// that a full link adds; empty otherwise. Show it once, never
	// log it.
	Key string
	// ExpiresAt is set once the transfer is available.
	ExpiresAt time.Time
	// Files are the files, in the declared order.
	Files []FileResult
}

// levelPattern is the ConfidentialityLevelKey pattern of the API.
var levelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// normalize validates o and fills its defaults for client c.
func (o Options) normalize(c *client.Client) (Options, error) {
	bad := func(format string, args ...any) (Options, error) {
		return o, fmt.Errorf("%w: "+format, append([]any{ErrInvalidOptions}, args...)...)
	}
	if o.Sender == "" {
		o.Sender = c.Config().Sender
	}
	if o.ChunkSize == 0 {
		o.ChunkSize = DefaultChunkSize
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	o.HasPassword = o.HasPassword || o.Password != ""
	switch {
	case len(o.Paths) == 0:
		return bad("no file to send")
	case o.ExpiryDays != 1 && o.ExpiryDays != 7 && o.ExpiryDays != 30:
		return bad("the expiry must be 1, 7 or 30 days, not %d", o.ExpiryDays)
	case len(o.Recipients) == 0 && !o.LinkOnly:
		return bad("at least one recipient is required (or a link-only transfer)")
	case o.Sender == "" && c.Config().Token != "":
		return bad("a sender address is required with an API token")
	case o.ChunkSize < 0:
		return bad("the chunk size must be positive")
	case o.HasPassword && o.Password == "":
		return bad("the password is empty")
	case len(o.Password) > maxPassword:
		return bad("the password is longer than %d bytes", maxPassword)
	case o.MaxDownloads < 0 || o.MaxDownloads > maxDownloadsLimit:
		return bad("the maximum number of downloads must be between 1 and %d", maxDownloadsLimit)
	case o.VerifyRecipients && o.LinkOnly:
		return bad("recipient verification cannot be combined with a link-only transfer")
	case o.Level != "" && !levelPattern.MatchString(o.Level):
		return bad("invalid confidentiality level key")
	case len(o.Message) > maxMessageBytes:
		return bad("the message is too long")
	}
	return o, nil
}

// identity returns the hexadecimal SHA-256 identifying a deposit: the
// server, the sorted absolute paths given and every option that shapes
// the transfer (the presence of a password, never its value).
func identity(server string, absPaths []string, o Options) string {
	paths := slices.Clone(absPaths)
	slices.Sort(paths)
	id := struct {
		V          int      `json:"v"`
		Server     string   `json:"server"`
		Paths      []string `json:"paths"`
		Recipients []string `json:"recipients"`
		Sender     string   `json:"sender"`
		Message    string   `json:"message"`
		Expiry     int      `json:"expiry"`
		Password   bool     `json:"password"`
		Delete     bool     `json:"delete"`
		Verify     bool     `json:"verify"`
		LinkOnly   bool     `json:"linkOnly"`
		E2E        bool     `json:"e2e"`
		MaxDl      int      `json:"maxDownloads"`
		Level      string   `json:"level"`
		Language   string   `json:"language"`
	}{
		1, server, paths, o.Recipients, o.Sender, o.Message, o.ExpiryDays, o.HasPassword,
		o.DeleteAfterFirstDownload, o.VerifyRecipients, o.LinkOnly, o.E2E, o.MaxDownloads, o.Level, o.Language,
	}
	b, _ := json.Marshal(id) //nolint:errchkjson // strings, integers and booleans only: it cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// defaultStatePath returns the state file of a deposit identity.
func defaultStatePath(id string) string {
	return filepath.Join(".", StatePrefix+id+".json")
}

// absolutePaths returns the absolute, cleaned form of paths.
func absolutePaths(paths []string) ([]string, error) {
	out := make([]string, len(paths))
	for i, p := range paths {
		a, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("upload: %s: %w", p, err)
		}
		out[i] = a
	}
	return out, nil
}
