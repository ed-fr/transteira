package download

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// apiPrefix is the path of the download operations of the API.
const apiPrefix = "/api/v1/downloads/"

// maxPageBytes caps the JSON of the download page (a long file list with
// sealed metadata of up to 4 KiB each).
const maxPageBytes = 32 << 20

// maxPrompts bounds the prompts of one run (codes and passwords typed in a
// wrong format), so that a script feeding answers cannot loop forever.
const maxPrompts = 5

// maxTries bounds the codes and passwords sent in one run, whatever
// attemptsRemaining a server announces.
const maxTries = 10

// maxPasswordBytes is the longest transfer password the API accepts.
const maxPasswordBytes = 1024

// Problem codes of the API (docs/api/errors.md).
const (
	codePasswordInvalid      = "transfer-password-invalid"
	codeVerificationRequired = "recipient-verification-required"
	codeCodeInvalid          = "verification-code-invalid"
)

// codePattern is the shape of a verification code.
var codePattern = regexp.MustCompile(`^[0-9]{6}$`)

// publicTransfer is the PublicTransfer schema of the API.
type publicTransfer struct {
	SenderEmail          string       `json:"senderEmail"`
	Message              string       `json:"message"`
	EncryptedMessage     string       `json:"encryptedMessage"`
	ExpiresAt            time.Time    `json:"expiresAt"`
	PasswordProtected    bool         `json:"passwordProtected"`
	Locked               bool         `json:"locked"`
	Files                []publicFile `json:"files"`
	VerificationRequired bool         `json:"verificationRequired"`
	Verified             bool         `json:"verified"`
	RecipientEmailMasked string       `json:"recipientEmailMasked"`
	EndToEndEncrypted    bool         `json:"endToEndEncrypted"`
}

// publicFile is the PublicFile schema of the API.
type publicFile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Path              string `json:"path"`
	Size              int64  `json:"size"`
	SHA256            string `json:"sha256"`
	ScanStatus        string `json:"scanStatus"`
	DownloadURL       string `json:"downloadUrl"`
	EncryptedMetadata string `json:"encryptedMetadata"`
}

// challenge is the RecipientVerificationChallenge schema.
type challenge struct {
	EmailMasked string `json:"emailMasked"`
}

// session runs the requests of one download.
type session struct {
	c    *client.Client
	o    *Options
	base string // apiPrefix + token
}

// anonymous is the policy of the page and grant requests: no token, the
// default retries.
var anonymous = client.Policy{Anonymous: true, MaxResponseBytes: maxPageBytes}

// once is the policy of the requests that count an attempt on the server
// (codes, passwords): never sent twice by the client layer.
var once = client.Policy{Anonymous: true, MaxAttempts: 1}

// page reads the download page.
func (s *session) page(ctx context.Context) (*publicTransfer, error) {
	var pt publicTransfer
	if _, err := s.c.JSON(ctx, http.MethodGet, s.base, nil, &pt, nil, anonymous); err != nil {
		return nil, err
	}
	return &pt, nil
}

// verify proves the recipient address: a code is mailed, read through
// Options.Code and confirmed, again while the server allows more attempts
// (once only with Options.CodeOnce).
func (s *session) verify(ctx context.Context, masked string) error {
	if s.o.Code == nil {
		return ErrCodeRequired
	}
	var ch challenge
	res, err := s.c.JSON(ctx, http.MethodPost, s.base+"/verification", map[string]string{"purpose": "download"}, &ch, nil, once)
	if err != nil {
		return fmt.Errorf("requesting a verification code: %w", err)
	}
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	if ch.EmailMasked != "" {
		masked = ch.EmailMasked
	}
	masked = sanitizeLine(masked)
	for bad, tries := 0, 0; ; {
		if tries >= maxTries {
			return fmt.Errorf("%w: too many codes", ErrVerification)
		}
		code, err := s.o.Code(masked)
		if err != nil {
			return err
		}
		code = strings.TrimSpace(code)
		if !codePattern.MatchString(code) {
			if bad++; bad >= maxPrompts || s.o.CodeOnce {
				return fmt.Errorf("%w: the code has 6 digits", ErrVerification)
			}
			s.warn("the verification code has 6 digits")
			continue
		}
		tries++
		_, err = s.c.JSON(ctx, http.MethodPost, s.base+"/verification/confirm", map[string]string{"code": code}, nil, nil, once)
		var p *client.Problem
		switch {
		case err == nil:
			return nil
		case !errors.As(err, &p):
			return err
		case p.Status == http.StatusUnprocessableEntity && p.Code == codeCodeInvalid && remaining(p) > 0 && !s.o.CodeOnce:
			s.warn(fmt.Sprintf("wrong verification code, %d attempt(s) left", remaining(p)))
		default:
			return fmt.Errorf("%w: %w", ErrVerification, err)
		}
	}
}

// unlock opens a password-protected transfer with Options.Password, again
// while the server allows more attempts (once only with
// Options.PasswordOnce).
func (s *session) unlock(ctx context.Context) error {
	if s.o.Password == nil {
		return ErrPasswordRequired
	}
	for tries := 1; ; tries++ {
		if tries > maxTries {
			return fmt.Errorf("%w: too many attempts", ErrWrongPassword)
		}
		pw, err := s.o.Password()
		if err != nil {
			return err
		}
		if pw == "" || len(pw) > maxPasswordBytes {
			return fmt.Errorf("%w: the password must hold 1 to %d bytes", ErrPasswordRequired, maxPasswordBytes)
		}
		_, err = s.c.JSON(ctx, http.MethodPost, s.base+"/unlock", map[string]string{"password": pw}, nil, nil, once)
		var p *client.Problem
		switch {
		case err == nil:
			return nil
		case !errors.As(err, &p):
			return err
		case p.Status == http.StatusUnauthorized && p.Code == codePasswordInvalid && remaining(p) > 0 && !s.o.PasswordOnce:
			s.warn(fmt.Sprintf("wrong password, %d attempt(s) left", remaining(p)))
		case p.Status == http.StatusUnauthorized && p.Code == codePasswordInvalid:
			return fmt.Errorf("%w: %w", ErrWrongPassword, err)
		case p.Status == http.StatusTooManyRequests:
			return fmt.Errorf("%w: try again in %s: %w", ErrTransferLocked, wait(p), err)
		case p.Status == http.StatusUnauthorized && p.Code == codeVerificationRequired:
			return fmt.Errorf("%w: %w", ErrVerification, err)
		default:
			return err
		}
	}
}

// remaining returns the attemptsRemaining member of p, or 0.
func remaining(p *client.Problem) int {
	if p.AttemptsRemaining == nil {
		return 0
	}
	return *p.AttemptsRemaining
}

// wait describes the Retry-After of p.
func wait(p *client.Problem) string {
	if p.RetryAfter <= 0 {
		return "a few minutes"
	}
	return p.RetryAfter.Round(time.Second).String()
}

// warn reports a message through Options.Warn.
func (s *session) warn(msg string) {
	if s.o.Warn != nil {
		s.o.Warn(msg)
	}
}
