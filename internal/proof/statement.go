package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/jcs"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

// SchemaVersion is the version of the statement format, signed in every
// statement.
const SchemaVersion = 1

// TimeLayout is the layout of every date of a statement: RFC 3339 in UTC
// with exactly three fractional digits (millisecond precision, the
// precision of the store), for example "2026-11-05T09:30:00.000Z". A fixed
// precision keeps one encoding per instant, so that a statement has a
// single canonical form.
const TimeLayout = "2006-01-02T15:04:05.000Z"

// Statement is the statement signed by the instance: the OpenAPI
// ProofStatement, field for field. It holds no float (sizes are integers
// below 2^53, dates are strings) and no IP address.
type Statement struct {
	// SchemaVersion is always SchemaVersion.
	SchemaVersion int `json:"schemaVersion"`
	// Kind is "deposit" or "delivery".
	Kind store.ProofKind `json:"kind"`
	// InstanceVersion is the version of TransTeira that signed.
	InstanceVersion string `json:"instanceVersion"`
	// Tenant is the entity of the transfer when the statement was signed.
	Tenant StatementTenant `json:"tenant"`
	// TransferID is the transfer ("trf_" + ULID).
	TransferID string `json:"transferId"`
	// SenderEmail is the verified address of the sender.
	SenderEmail string `json:"senderEmail"`
	// Recipients are the recipient addresses, in the sender's order.
	Recipients []string `json:"recipients"`
	// ConfidentialityLevel is the key of the level of the transfer, ""
	// (absent) without level.
	ConfidentialityLevel string `json:"confidentialityLevel,omitempty"`
	// EndToEndEncrypted reports a transfer encrypted in the browser: the
	// file names are then generic and the hashes are those of the
	// ciphertext.
	EndToEndEncrypted bool `json:"endToEndEncrypted"`
	// LinkOnly reports a link-only transfer (since 2.0): no recipient was
	// mailed nor identified, and a download may come from anyone holding
	// the link. Emitted only when true, so that the statements signed
	// before it keep their exact encoding.
	LinkOnly bool `json:"linkOnly,omitempty"`
	// Files are the files of the transfer, by position.
	Files []StatementFile `json:"files"`
	// DepositedAt is when the sender finalized the deposit (TimeLayout).
	DepositedAt string `json:"depositedAt"`
	// ExpiresAt is the expiry of the transfer when the statement was
	// signed (TimeLayout).
	ExpiresAt string `json:"expiresAt"`
	// FirstDownloadedAt is the first download of the transfer, all
	// recipients together (TimeLayout); nil (null) in a deposit statement.
	FirstDownloadedAt *string `json:"firstDownloadedAt"`
	// RecipientDownloads are, in a delivery statement of a transfer with
	// per-recipient links, the first complete downloads: of every
	// recipient who downloaded so far in the overall statement, of the one
	// recipient it is about in a per-recipient statement. Absent
	// otherwise.
	RecipientDownloads []RecipientDownload `json:"recipientDownloads,omitempty"`
	// KeyID is the signing key ("psk_" + ULID).
	KeyID string `json:"keyId"`
}

// StatementTenant is the entity named by a statement.
type StatementTenant struct {
	// Name is the display name of the entity.
	Name string `json:"name"`
	// FQDN is the host name of the entity.
	FQDN string `json:"fqdn"`
}

// StatementFile is one file of a statement.
type StatementFile struct {
	// Name is the name of the file.
	Name string `json:"name"`
	// Path is the folder of the file in the transfer, "" (absent) at the
	// root.
	Path string `json:"path,omitempty"`
	// Size is the size of the clear file, in bytes.
	Size int64 `json:"size"`
	// SHA256 is the SHA-256 of the file (lowercase hexadecimal).
	SHA256 string `json:"sha256"`
	// ScanStatus is the antivirus status of the file (OpenAPI ScanStatus).
	ScanStatus string `json:"scanStatus"`
}

// RecipientDownload is the first complete download of one recipient.
type RecipientDownload struct {
	// Email is the address of the recipient.
	Email string `json:"email"`
	// FirstDownloadedAt is when the recipient's own link completed a
	// download for the first time (TimeLayout).
	FirstDownloadedAt string `json:"firstDownloadedAt"`
}

// FormatTime formats t as a statement date (TimeLayout, UTC, truncated to
// the millisecond).
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format(TimeLayout)
}

// parseTime parses a statement date, strictly in TimeLayout.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || FormatTime(t) != s {
		return time.Time{}, fmt.Errorf("%w: malformed date", ErrInvalidProof)
	}
	return t, nil
}

// Marshal returns the canonical JSON (RFC 8785) of st: the exact bytes
// that are signed.
func (st Statement) Marshal() ([]byte, error) {
	return jcs.Marshal(st)
}

// ParseStatement decodes the canonical JSON of a statement, strictly: the
// input must be canonical (RFC 8785), hold exactly the fields of the
// schema with their exact names, and re-encode to the same bytes; the
// schema version, the kind, the identifiers and the dates are checked. It
// does not check the signature (see [Verify]). Every error matches
// ErrInvalidProof.
func ParseStatement(data []byte) (Statement, error) {
	canonical, err := jcs.Canonicalize(data)
	if err != nil {
		return Statement{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	if !bytes.Equal(canonical, data) {
		return Statement{}, fmt.Errorf("%w: statement is not in canonical form", ErrInvalidProof)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var st Statement
	if err := dec.Decode(&st); err != nil {
		return Statement{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	// encoding/json matches field names case-insensitively and accepts a
	// null for any field: re-encoding must give the input back, so that
	// exactly one encoding of a statement is accepted.
	again, err := st.Marshal()
	if err != nil || !bytes.Equal(again, data) {
		return Statement{}, fmt.Errorf("%w: statement does not follow the schema", ErrInvalidProof)
	}
	if err := st.validate(); err != nil {
		return Statement{}, err
	}
	return st, nil
}

// validate checks the fields of a decoded statement that the schema
// constrains beyond their JSON type.
func (st Statement) validate() error {
	invalid := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalidProof, what) }
	switch {
	case st.SchemaVersion != SchemaVersion:
		return invalid("unsupported schema version")
	case st.Kind != store.ProofDeposit && st.Kind != store.ProofDelivery:
		return invalid("unknown kind")
	case !id.Valid(id.Transfer, st.TransferID):
		return invalid("malformed transfer id")
	case !id.Valid(id.ProofKey, st.KeyID):
		return invalid("malformed key id")
	case st.Kind == store.ProofDeposit && (st.FirstDownloadedAt != nil || st.RecipientDownloads != nil):
		return invalid("a deposit statement holds no download")
	case st.Kind == store.ProofDelivery && st.FirstDownloadedAt == nil:
		return invalid("a delivery statement holds its first download")
	}
	dates := []string{st.DepositedAt, st.ExpiresAt}
	if st.FirstDownloadedAt != nil {
		dates = append(dates, *st.FirstDownloadedAt)
	}
	for _, d := range st.RecipientDownloads {
		dates = append(dates, d.FirstDownloadedAt)
	}
	for _, d := range dates {
		if _, err := parseTime(d); err != nil {
			return err
		}
	}
	return nil
}

// FactTime returns the latest fact a statement attests: its deposit, its
// first download and the first download of each recipient it names. The
// statement was signed after it, so its key was active then. The
// statement must be valid (as returned by [ParseStatement]).
func (st Statement) FactTime() time.Time {
	latest, _ := parseTime(st.DepositedAt)
	later := func(s string) {
		if t, err := parseTime(s); err == nil && t.After(latest) {
			latest = t
		}
	}
	if st.FirstDownloadedAt != nil {
		later(*st.FirstDownloadedAt)
	}
	for _, d := range st.RecipientDownloads {
		later(d.FirstDownloadedAt)
	}
	return latest
}

// newStatement builds the statement of kind kind of the transfer d of
// tenant t, without download facts and without key.
func newStatement(kind store.ProofKind, t *tenant.Tenant, d store.TransferDetails) (Statement, error) {
	if t == nil {
		return Statement{}, errors.New("proof: no tenant")
	}
	deposited := d.FinalizedAt
	if d.Status != store.TransferAvailable || deposited.IsZero() || d.ExpiresAt.IsZero() {
		return Statement{}, fmt.Errorf("%w: transfer not available", ErrNotReady)
	}
	st := Statement{
		SchemaVersion: SchemaVersion, Kind: kind, InstanceVersion: version.Get().Version,
		Tenant:     StatementTenant{Name: t.Name, FQDN: t.FQDN},
		TransferID: d.ID, SenderEmail: d.SenderEmail, Recipients: append([]string{}, d.Recipients...),
		ConfidentialityLevel: d.ConfidentialityLevel, LinkOnly: d.LinkOnly, EndToEndEncrypted: d.E2E,
		Files:       make([]StatementFile, 0, len(d.Files)),
		DepositedAt: FormatTime(deposited), ExpiresAt: FormatTime(d.ExpiresAt),
	}
	for _, f := range d.Files {
		st.Files = append(st.Files, StatementFile{
			Name: f.Name, Path: f.Path, Size: f.Size, SHA256: f.SHA256, ScanStatus: string(f.ScanStatus),
		})
	}
	return st, nil
}
