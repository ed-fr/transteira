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
	// TemplateDiskAlert warns the super administrators, and the optional
	// alert address of the system settings, that the filesystem holding
	// the data directory reached the disk alert threshold (CLAUDE.md
	// sections 12.2 and 19). It is an instance mail sent through the system
	// SMTP server, never a tenant template: the store knows no tenant
	// template key for it, so no entity can customize it; data:
	// [DiskAlertData].
	TemplateDiskAlert = "disk_alert"
	// TemplateAntivirusAlert warns the super administrators, and the
	// optional alert address of the system settings, that clamd has stayed
	// unreachable beyond the grace period of the antivirus alert (decision
	// P10, threat model T-42). Like [TemplateDiskAlert], it is an instance
	// mail sent through the system SMTP server, never a tenant template;
	// data: [AntivirusAlertData].
	TemplateAntivirusAlert = "antivirus_alert"
	// TemplateAntivirusUnavailable tells the delegated administrators of an
	// entity (else the super administrators) that the antivirus has stopped
	// responding while transfers of the entity wait for analysis (tenant
	// template key "antivirus-unavailable"); data:
	// [AntivirusUnavailableData].
	TemplateAntivirusUnavailable = "antivirus_unavailable"
	// TemplateExpiryReminder is the reminder sent the day before the expiry
	// of a transfer to a recipient who has not downloaded it yet (tenant
	// template key "expiry-reminder", threat T-198); data:
	// [ExpiryReminderData].
	TemplateExpiryReminder = "expiry_reminder"
	// TemplateRecipientVerificationCode is the verification code sent to the
	// address of a personal download link before the recipient can download
	// (tenant template key "recipient-verification-code", threat T-144);
	// data: [RecipientVerificationCodeData].
	TemplateRecipientVerificationCode = "recipient_verification_code"
	// TemplateMyTransfersLink is the one-time sign-in link to "My transfers"
	// sent to a sender who asked for it (tenant template key
	// "my-transfers-link"); data: [MyTransfersLinkData].
	TemplateMyTransfersLink = "my_transfers_link"
	// TemplateAbuseAlert warns the delegated administrators that an abuse
	// detection threshold was exceeded or an unusual activity was seen
	// (CLAUDE.md section 15; tenant template key "abuse-alert"); data:
	// [AbuseAlertData].
	TemplateAbuseAlert = "abuse_alert"
	// TemplateAbuseReport tells the delegated administrators that a
	// recipient reported a transfer as abusive (tenant template key
	// "abuse-report"); data: [AbuseReportData].
	TemplateAbuseReport = "abuse_report"
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
	// ConfidentialityLabel is the label of the confidentiality level of the
	// transfer, already localized in the language of the mail; empty shows no
	// level.
	ConfidentialityLabel string
	// ReplyToCreatedAt, when not zero, marks the transfer as a reply from an
	// external recipient to the transfer created at that time (T-223): the
	// mail then warns that the sender comes from outside and proved their
	// address with a code only.
	ReplyToCreatedAt time.Time
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
	// ConfidentialityLabel is the label of the confidentiality level of the
	// transfer, already localized in the language of the mail; empty shows no
	// level.
	ConfidentialityLabel string
	// Withheld lists the files that could not be analyzed and are withheld
	// (never downloadable); SHA256 is not shown.
	Withheld []FileInfo
	// MyTransfersLink is the absolute URL of the "My transfers" page of the
	// entity; empty shows no such line.
	MyTransfersLink string
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

// FirstDownloadData is the data of [TemplateFirstDownload]. It names a
// recipient only for a transfer with one download link per recipient; with
// the single shared link of a V1 transfer the download cannot be attributed.
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
	// RecipientEmail is the address of the recipient who completed the
	// download, for a transfer with one link per recipient; empty with a
	// shared link (the mail then names nobody).
	RecipientEmail string
}

// ExpiryReminderData is the data of [TemplateExpiryReminder].
type ExpiryReminderData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// SenderEmail is the verified address of the sender.
	SenderEmail string
	// Link is the personal absolute download URL of the recipient, built from
	// the registered FQDN of the tenant.
	Link string
	// Files lists the files available for download (name and size).
	Files []FileInfo
	// ExpiresAt is when the transfer expires.
	ExpiresAt time.Time
	// PasswordRequired tells the recipient that a password protects the
	// transfer and comes through another channel.
	PasswordRequired bool
	// VerificationRequired tells the recipient that a code sent to this
	// address will be asked before the download.
	VerificationRequired bool
	// ConfidentialityLabel is the label of the confidentiality level of the
	// transfer, already localized in the language of the mail; empty shows no
	// level.
	ConfidentialityLabel string
}

// RecipientVerificationCodeData is the data of
// [TemplateRecipientVerificationCode].
type RecipientVerificationCodeData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Code is the one-time code (6 digits). It is never logged.
	Code string
	// ValidityMinutes is the lifetime of the code (15).
	ValidityMinutes int
}

// MyTransfersLinkData is the data of [TemplateMyTransfersLink].
type MyTransfersLinkData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Link is the one-time sign-in URL (https://<host>/me#mta_...). It is
	// a secret: it is never logged.
	Link string
	// ValidityMinutes is the lifetime of the link (15).
	ValidityMinutes int
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

// DiskAlertData is the data of [TemplateDiskAlert]. It holds no secret and
// no personal data.
type DiskAlertData struct {
	// UsedBytes is the space used on the filesystem of the data directory,
	// formatted with [FormatSize].
	UsedBytes int64
	// TotalBytes is the size of that filesystem, formatted like UsedBytes.
	// The share used is computed from both, rounded down; a size of 0 or
	// less counts as fully used.
	TotalBytes int64
	// ThresholdPercent is the alert threshold, in percent (50 to 99),
	// shown with at most two decimals.
	ThresholdPercent float64
	// AdminLink is the absolute URL of the administration console, built
	// from the configured admin host, never from a request Host. It carries
	// no token.
	AdminLink string
}

// AntivirusAlertData is the data of [TemplateAntivirusAlert]. It holds no
// secret and no personal data: counts only, no entity, file or address.
type AntivirusAlertData struct {
	// Since is when clamd was first found unreachable, formatted with
	// [FormatDateTime].
	Since time.Time
	// WaitingTransfers is the number of transfers waiting for analysis,
	// across entities.
	WaitingTransfers int
	// Tenants is the number of entities with transfers waiting.
	Tenants int
	// CountUnknown is set when the transfers waiting could not be counted:
	// the mail says so instead of showing WaitingTransfers and Tenants.
	CountUnknown bool
	// AdminLink is the absolute URL of the administration console, built
	// from the configured admin host, never from a request Host. It carries
	// no token.
	AdminLink string
}

// AntivirusUnavailableData is the data of [TemplateAntivirusUnavailable].
// It holds no secret and no personal data.
type AntivirusUnavailableData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Since is when clamd was first found unreachable, formatted with
	// [FormatDateTime].
	Since time.Time
	// WaitingTransfers is the number of transfers of the entity waiting
	// for analysis.
	WaitingTransfers int
	// OperatorsMailed tells whether the super administrators were mailed
	// the instance alert too (system SMTP server configured and recipients
	// reached): the mail says so, or asks to contact the operator of the
	// instance.
	OperatorsMailed bool
	// AdminLink is the absolute URL of the administration console, built
	// from the configured admin host, never from a request Host. It carries
	// no token.
	AdminLink string
}

// Abuse detection rules reported by [TemplateAbuseAlert] (CLAUDE.md section
// 15), the values of [AbuseAlertData.Rule].
const (
	// AbuseRuleDailyBytes: a sender exceeded the daily volume (Value and
	// Threshold are sizes in bytes).
	AbuseRuleDailyBytes = "daily_bytes"
	// AbuseRuleDailyTransfers: a sender exceeded the daily number of
	// transfers.
	AbuseRuleDailyTransfers = "daily_transfers"
	// AbuseRuleRecipients: a transfer has more recipients than allowed.
	AbuseRuleRecipients = "recipients"
	// AbuseRuleUnusualVolume: the volume of a sender is far above its
	// habits (Value is the factor).
	AbuseRuleUnusualVolume = "unusual_volume"
	// AbuseRuleLargeExternal: a large transfer to external addresses (Value
	// and Threshold are sizes in bytes).
	AbuseRuleLargeExternal = "large_external"
	// AbuseRuleOffHours: a transfer sent outside office hours (At is the
	// time).
	AbuseRuleOffHours = "off_hours"
	// AbuseRuleInvitations: an internal user reached its invitation limit.
	AbuseRuleInvitations = "invitations"
	// AbuseRuleExternalQuota: the deposit quota of the external users was
	// reached (counts, or sizes in bytes when AbuseAlertData.Bytes is set).
	AbuseRuleExternalQuota = "external_quota"
)

// Categories of an abuse report, the values of [AbuseReportData.Category].
const (
	AbuseCategoryMalware        = "malware"
	AbuseCategoryPhishing       = "phishing"
	AbuseCategoryIllegalContent = "illegal_content"
	AbuseCategorySpam           = "spam"
	AbuseCategoryUnknownSender  = "unknown_sender"
	AbuseCategoryOther          = "other"
)

// AbuseAlertData is the data of [TemplateAbuseAlert]. It holds the address
// of the sender concerned and no other personal data.
type AbuseAlertData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Rule is the rule that fired, one of the AbuseRule constants. An
	// unknown rule gets a generic sentence.
	Rule string
	// SenderEmail is the verified address of the sender (or inviter)
	// concerned.
	SenderEmail string
	// Value is the measured value: a size in bytes, a count, or the factor
	// of [AbuseRuleUnusualVolume].
	Value float64
	// Threshold is the configured threshold, in the unit of Value (unused by
	// [AbuseRuleUnusualVolume] and [AbuseRuleOffHours]).
	Threshold float64
	// Bytes tells that Value and Threshold of [AbuseRuleExternalQuota] are
	// sizes in bytes rather than counts.
	Bytes bool
	// Blocked tells whether the transfer was refused or only reported.
	Blocked bool
	// Day is the day concerned, as YYYY-MM-DD.
	Day string
	// At is when the event happened; shown by [AbuseRuleOffHours] when set,
	// formatted with [FormatDateTime].
	At time.Time
	// AdminLink is the absolute URL of the audit page of the administration
	// console, built from the configured admin host, never from a request
	// Host. It carries no token.
	AdminLink string
}

// AbuseReportData is the data of [TemplateAbuseReport].
type AbuseReportData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// TransferID is the identifier of the reported transfer.
	TransferID string
	// SenderEmail is the address of the sender of the transfer.
	SenderEmail string
	// Category is one of the AbuseCategory constants; an unknown value is
	// shown as "other".
	Category string
	// Message is the free text of the reporter, as plain text. It is never
	// interpreted: it is quoted in the text body and HTML-escaped in the
	// HTML body, line breaks preserved.
	Message string
	// ReporterEmail is the address of the reporter, "" when unverified.
	ReporterEmail string
	// RecipientIndex is the 1-based number of the recipient whose personal
	// link was used, 0 for a shared link.
	RecipientIndex int
	// AdminLink is the absolute URL of the abuse reports page of the
	// administration console. It carries no token.
	AdminLink string
}
