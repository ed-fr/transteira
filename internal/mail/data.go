package mail

import "time"

// Names of the built-in templates.
const (
	// TemplateVerificationCode is the e-mail verification code mail
	// (CLAUDE.md section 7); data: [VerificationCodeData].
	TemplateVerificationCode = "verification_code"
	// TemplateInvitation is the external invitation mail (CLAUDE.md
	// section 9); data: [InvitationData].
	TemplateInvitation = "invitation"
	// TemplateTransferNotification is the mail sent to each recipient of an
	// available transfer (CLAUDE.md section 12.2); data:
	// [TransferNotificationData].
	TemplateTransferNotification = "transfer_notification"
	// TemplateTransferConfirmation is the confirmation sent to the sender of
	// an available transfer; data: [TransferConfirmationData].
	TemplateTransferConfirmation = "transfer_confirmation"
	// TemplateFileProblems warns the sender about the files that were not
	// delivered: infected files, deleted (CLAUDE.md section 11), and files
	// that could not be analyzed, withheld under fail-closed; data:
	// [FileProblemsData].
	TemplateFileProblems = "file_problems"
	// TemplateFileNotScanned warns the sender that the antivirus could not
	// analyze files (too large or too complex, or encrypted archives),
	// delivered anyway;
	// data: [FileNotScannedData].
	TemplateFileNotScanned = "file_not_scanned"
	// TemplateFirstDownload tells the sender that the transfer has been
	// downloaded in full for the first time (CLAUDE.md section 12.2), sent
	// once per transfer; data: [FirstDownloadData].
	TemplateFirstDownload = "first_download"
	// TemplateQuotaWarning warns the delegated administrators of an entity
	// that 80 % of its storage quota is used (CLAUDE.md sections 8.5 and
	// 12.2); data: [QuotaAlertData].
	TemplateQuotaWarning = "quota_warning"
	// TemplateQuotaReached tells the delegated administrators of an entity
	// that its storage quota is reached and new deposits are refused until
	// space is freed (CLAUDE.md sections 8.5 and 12.2); data:
	// [QuotaAlertData].
	TemplateQuotaReached = "quota_reached"
)

// QRContentID is the Content-ID of the QR code of the download link, the
// inline part referenced by the transfer_notification template as
// <img src="cid:qr@transteira"> (threat T-87: no remote image), produced by
// the qr_code block.
const QRContentID = "qr@transteira"

// VerificationCodeData is the data of [TemplateVerificationCode].
type VerificationCodeData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Code is the one-time code (6 digits). It is never logged.
	Code string
	// ValidityMinutes is the lifetime of the code (15).
	ValidityMinutes int
}

// InvitationData is the data of [TemplateInvitation].
type InvitationData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// InviterEmail is the verified address of the internal user who invites.
	InviterEmail string
	// Message is the optional free text of the inviter, as plain text. It is
	// HTML-escaped and never turned into links by the templates; the caller
	// limits its length (threat T-18).
	Message string
	// Link is the absolute invitation URL, built from the registered FQDN of
	// the tenant, never from the request Host (threat T-03).
	Link string
	// ExpiresAt is when the unused invitation expires.
	ExpiresAt time.Time
}

// NotScannedReason is why the antivirus could not analyze a delivered
// file; the blocks of the templates show a text for each value below.
type NotScannedReason string

// Reasons for a file not to be scanned.
const (
	// NotScannedTooLarge is a file above the antivirus limits: too large,
	// or too complex (number of files, recursion depth) to be fully
	// analyzed.
	NotScannedTooLarge NotScannedReason = "too_large"
	// NotScannedEncrypted is an encrypted archive, whose content the
	// antivirus cannot read.
	NotScannedEncrypted NotScannedReason = "encrypted"
)

// FileInfo describes one file of a transfer in the transfer mails.
type FileInfo struct {
	// Name is the original file name, as plain text: the blocks escape it
	// and the caller removes control and hidden characters.
	Name string
	// Size is the size in bytes, formatted with [FormatSize].
	Size int64
	// SHA256 is the hexadecimal SHA-256 digest of the clear content.
	SHA256 string
	// NotScanned is why the antivirus could not analyze the delivered file,
	// "" when it was scanned.
	NotScanned NotScannedReason
}

// TransferNotificationData is the data of [TemplateTransferNotification].
type TransferNotificationData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// SenderEmail is the verified address of the sender.
	SenderEmail string
	// Message is the optional free text of the sender, as plain text. It is
	// HTML-escaped and never turned into links by the templates (T-81).
	Message string
	// Link is the absolute download URL, built from the registered FQDN of
	// the tenant. It is the only link of the mail.
	Link string
	// Files lists the files available for download.
	Files []FileInfo
	// ExpiresAt is when the transfer expires.
	ExpiresAt time.Time
	// PasswordRequired tells the recipient that a password protects the
	// transfer and will come through another channel (T-88).
	PasswordRequired bool
	// QR shows the QR code of Link, an inline part of Content-ID
	// [QRContentID] that the caller attaches.
	QR bool
}

// TransferConfirmationData is the data of [TemplateTransferConfirmation].
type TransferConfirmationData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Link is the absolute download URL.
	Link string
	// Recipients lists the addresses the transfer was sent to.
	Recipients []string
	// Files lists the files available for download.
	Files []FileInfo
	// ExpiresAt is when the transfer expires.
	ExpiresAt time.Time
	// PasswordRequired reminds the sender to give the password to the
	// recipients through another channel.
	PasswordRequired bool
	// Withheld lists the files that could not be analyzed and are withheld
	// (never downloadable); SHA256 is not shown.
	Withheld []FileInfo
}

// InfectedFile is a file deleted because the antivirus found it infected.
type InfectedFile struct {
	// Name is the original file name, as plain text.
	Name string
	// Signature is the name of the detected threat, as reported by the
	// antivirus (plain text, bounded by the caller).
	Signature string
}

// FileProblemsData is the data of [TemplateFileProblems]. At least one of
// Infected and Withheld is expected; the subject names the infection when
// there is one.
type FileProblemsData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Infected lists the infected files, deleted.
	Infected []InfectedFile
	// Withheld lists the files that could not be analyzed, withheld for
	// safety (name and size only).
	Withheld []FileInfo
	// Rejected is set when no file could be delivered: the transfer was not
	// sent and no recipient was notified. Otherwise the remaining files were
	// sent.
	Rejected bool
}

// FileNotScannedData is the data of [TemplateFileNotScanned]: every file
// listed has a NotScanned reason.
type FileNotScannedData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Files lists the files the antivirus could not analyze.
	Files []FileInfo
}

// FirstDownloadData is the data of [TemplateFirstDownload]. It names no
// recipient: in V1 a transfer has a single download link, so the download
// cannot be attributed to one recipient.
type FirstDownloadData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Files lists the files of the transfer (name and size; SHA256 and
	// NotScanned are not shown).
	Files []FileInfo
	// DownloadedAt is when the transfer was first downloaded in full,
	// formatted with [FormatDateTime].
	DownloadedAt time.Time
	// DeleteAt is when the transfer is erased, formatted like DownloadedAt,
	// when the sender asked for deletion after the first download; zero
	// when the transfer stays until its expiry.
	DeleteAt time.Time
}

// QuotaAlertData is the data of [TemplateQuotaWarning] and
// [TemplateQuotaReached]. The threshold shown (80 % or 100 %) follows from
// the template. It holds no secret and no personal data.
type QuotaAlertData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// UsedBytes is the storage used by the entity, formatted with
	// [FormatSize].
	UsedBytes int64
	// QuotaBytes is the storage quota of the entity, formatted like
	// UsedBytes. The share of the quota used is computed from both,
	// rounded down; a quota of 0 or less counts as fully used.
	QuotaBytes int64
	// AdminLink is the absolute URL of the administration console, built
	// from the configured admin host, never from a request Host. It carries
	// no token.
	AdminLink string
}
