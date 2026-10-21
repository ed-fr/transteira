// Package notify builds the mails that follow the antivirus analysis of a
// transfer (CLAUDE.md section 12.2):
//
//   - transfer_notification, to each recipient, with the download link, the
//     QR code of that link as an inline PNG (CID, never a remote image:
//     threat T-87), the files with their size, SHA-256 digest and "not
//     scanned" flag (too large or too complex, or encrypted archive), the
//     expiry and, for a protected transfer, the notice that the password
//     comes through another channel (T-88);
//   - transfer_confirmation (listing the withheld files), file_problems
//     (infected files deleted, files that could not be analyzed withheld)
//     and file_not_scanned, to the sender.
//
// A [Notifier] only builds [mail.Job] values, with the SMTP settings of the
// tenant and its password unsealed for the job; the caller enqueues them
// and retries a refused job. Each recipient gets a mail of their own, which
// never reveals the other recipients.
//
// Text coming from users is never trusted: the sender's message keeps only
// its visible characters and is escaped by the templates, never turned into
// a link (T-81); file names and threat names are reduced to one bounded
// line. The only link of a recipient mail is the official download link.
package notify
