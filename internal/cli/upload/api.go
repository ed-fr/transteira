package upload

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// API paths and tus constants.
const (
	transfersPath = "/api/v1/transfers"
	tusVersion    = "1.0.0"
	tusType       = "application/offset+octet-stream"
)

// Transfer statuses of the API.
const (
	statusUploading = "uploading"
	statusScanning  = "scanning"
	statusAvailable = "available"
	statusRejected  = "rejected"
	statusExpired   = "expired"
	statusDeleted   = "deleted"
)

// Problem codes handled by the uploader.
const (
	codeUploadIncomplete = "upload-incomplete"
	codeChecksumMismatch = "checksum-mismatch"
)

// errGone marks a transfer or upload that no longer exists (404, 410,
// expired or deleted): nothing is left to resume.
var errGone = errors.New("the transfer no longer exists or its uploads expired: run the command again to start a new transfer")

// createRequest is the TransferCreate body.
type createRequest struct {
	SenderEmail              string            `json:"senderEmail,omitempty"`
	Recipients               []string          `json:"recipients,omitempty"`
	Message                  string            `json:"message,omitempty"`
	ExpiryDays               int               `json:"expiryDays"`
	Password                 string            `json:"password,omitempty"`
	DeleteAfterFirstDownload bool              `json:"deleteAfterFirstDownload,omitempty"`
	Language                 string            `json:"language,omitempty"`
	Files                    []fileDeclaration `json:"files"`
	RecipientVerification    bool              `json:"recipientVerification,omitempty"`
	MaxDownloads             *int              `json:"maxDownloads,omitempty"`
	ConfidentialityLevel     string            `json:"confidentialityLevel,omitempty"`
	LinkOnly                 bool              `json:"linkOnly,omitempty"`
	EncryptedMessage         string            `json:"encryptedMessage,omitempty"`
	EndToEndEncrypted        bool              `json:"endToEndEncrypted,omitempty"`
}

// fileDeclaration is the FileDeclaration schema.
type fileDeclaration struct {
	Name              string `json:"name"`
	Size              int64  `json:"size"`
	MediaType         string `json:"mediaType,omitempty"`
	ExpectedSHA256    string `json:"expectedSha256,omitempty"`
	Path              string `json:"path,omitempty"`
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
}

// transfer is the part of SenderTransfer the uploader reads.
type transfer struct {
	ID          string       `json:"id"`
	Status      string       `json:"status"`
	ExpiresAt   *time.Time   `json:"expiresAt,omitempty"`
	DownloadURL string       `json:"downloadUrl,omitempty"`
	Files       []senderFile `json:"files"`
}

// senderFile is the part of SenderFile the uploader reads.
type senderFile struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256,omitempty"`
	ScanStatus string `json:"scanStatus"`
	UploadURL  string `json:"uploadUrl,omitempty"`
}

// e2eName returns the generic name of file index of an end-to-end
// encrypted transfer: file-1.tte2 for index 0.
func e2eName(index int) string { return fmt.Sprintf("file-%d.tte2", index+1) }

// buildRequest returns the createTransfer body of the state s.
func buildRequest(o Options, s *state) createRequest {
	req := createRequest{
		SenderEmail: o.Sender, Recipients: o.Recipients, ExpiryDays: o.ExpiryDays,
		DeleteAfterFirstDownload: o.DeleteAfterFirstDownload, Language: o.Language,
		RecipientVerification: o.VerifyRecipients, ConfidentialityLevel: o.Level, LinkOnly: o.LinkOnly,
		Files: make([]fileDeclaration, len(s.Files)),
	}
	if o.HasPassword {
		req.Password = o.Password
	}
	if o.MaxDownloads > 0 {
		req.MaxDownloads = &o.MaxDownloads
	}
	e2e := s.e2e()
	if e2e {
		req.EndToEndEncrypted = true
		req.EncryptedMessage = s.EncryptedMessage
	} else {
		req.Message = o.Message
	}
	for i := range s.Files {
		f := &s.Files[i]
		d := fileDeclaration{Size: f.wireSize(e2e), ExpectedSHA256: f.wireSHA256(e2e)}
		if e2e {
			d.Name, d.EncryptedMetadata = e2eName(i), f.Metadata
		} else {
			d.Name, d.MediaType, d.Path = f.Name, f.MediaType, f.Folder
		}
		req.Files[i] = d
	}
	return req
}

// transferPath returns the path of transfer id, with suffix.
func transferPath(id, suffix string) string {
	return transfersPath + "/" + url.PathEscape(id) + suffix
}

// problemOf returns the *client.Problem of err, or nil.
func problemOf(err error) *client.Problem {
	var p *client.Problem
	if errors.As(err, &p) {
		return p
	}
	return nil
}

// isStatus reports whether err is a problem with one of the statuses.
func isStatus(err error, statuses ...int) bool {
	p := problemOf(err)
	if p == nil {
		return false
	}
	for _, s := range statuses {
		if p.Status == s {
			return true
		}
	}
	return false
}

// gone wraps err with errGone when it is a 404 or a 410.
func gone(err error) error {
	if isStatus(err, http.StatusNotFound, http.StatusGone) {
		return fmt.Errorf("upload: %w: %w", errGone, err)
	}
	return err
}

// createTransfer sends createTransfer with the idempotency key of s.
func createTransfer(ctx context.Context, c *client.Client, o Options, s *state) (*transfer, error) {
	var t transfer
	h := http.Header{"Idempotency-Key": {s.IdempotencyKey}}
	if _, err := c.JSON(ctx, http.MethodPost, transfersPath, buildRequest(o, s), &t, h, client.Policy{}); err != nil {
		return nil, err
	}
	if t.ID == "" || len(t.Files) != len(s.Files) {
		return nil, errors.New("upload: unexpected answer to the creation of the transfer")
	}
	return &t, nil
}

// getTransfer reads transfer id.
func getTransfer(ctx context.Context, c *client.Client, id string) (*transfer, error) {
	var t transfer
	if _, err := c.JSON(ctx, http.MethodGet, transferPath(id, ""), nil, &t, nil, client.Policy{}); err != nil {
		return nil, gone(err)
	}
	return &t, nil
}

// cancelTransfer deletes transfer id, ignoring 404, 409 and 410 (already
// gone or no longer cancellable).
func cancelTransfer(ctx context.Context, c *client.Client, id string) error {
	_, err := c.JSON(ctx, http.MethodDelete, transferPath(id, ""), nil, nil, nil, client.Policy{})
	if err != nil && !isStatus(err, http.StatusNotFound, http.StatusConflict, http.StatusGone) {
		return err
	}
	return nil
}

// finalizeTransfer finalizes transfer id.
func finalizeTransfer(ctx context.Context, c *client.Client, id string) (*transfer, error) {
	var t transfer
	if _, err := c.JSON(ctx, http.MethodPost, transferPath(id, "/finalize"), nil, &t, nil, client.Policy{}); err != nil {
		return nil, err
	}
	return &t, nil
}
