// Package secret creates and reads one-time text secrets from the command
// line (transteira-cli secret create and secret read, since 2.3): the
// express secrets of specification section 22.2, and the link secrets of
// 2.1 without passphrase nor file, which share their reading protocol.
//
// The format is docs/architecture/e2e-format.md, section 3.3 and its
// express profile 3.3.9. Every cryptographic operation comes from
// internal/tte2, the reference implementation; this package only drives
// the API calls around it.
//
// # Creating
//
// [Create] checks the text ([CheckText]: 1 to [MaxTextRunes] Unicode code
// points of valid UTF-8, counted as typed), draws a new 256-bit key K from
// crypto/rand for every secret, derives K' without passphrase, seals the
// text, opens its own sealed text again (a verifier never certifies a text
// that cannot be opened) and sends the sealed text, the two verifiers and
// the duration to POST /api/v1/express-secrets. Neither the text nor K
// ever leaves the client (threat T-399). The request is sent once: a
// creation is never retried with the same key (section 3.3.1), and a
// rate-limit answer is reported with its delay instead of waited for. The
// API token of the configuration is sent unless [CreateOptions.Anonymous]
// is set; without a token the creation is anonymous. The server answers the
// secret token; the client composes the link itself,
// https://<host>/s/<token>#k=<key>, on the host of the configured base
// URL. That link is the secret: the caller prints it on the standard
// output only and never logs it (T-406).
//
// [ReadText] and [ReadTextFile] read the text from the standard input or a
// file, never from the command line (T-406). Unless the raw input is asked
// for, a leading UTF-8 byte order mark and one final line break ("\n" or
// "\r\n") are dropped, so that "echo text |" and a file saved by an editor
// give the text as typed in the browser.
//
// # Reading
//
// [ParseLink] accepts only a full secret link with its key fragment. [Read]
// asks the status first (GET /api/v1/secret-links/{token}), which consumes
// nothing: a secret with a passphrase or a file is refused there
// ([ErrUnsupported]), before any reveal, so that it stays readable in a
// browser. It then reveals the secret once (POST .../reveal with the key
// proof and the proof, never retried) and opens the sealed text with
// tte2.OpenSecret. A wrong key is refused by the server before anything is
// consumed ([ErrWrongKey]). Requests carry no Origin nor Sec-Fetch-Site
// header and no API token.
//
// [TerminalSafe] escapes the control and bidirectional characters of a
// revealed text before it is shown on a terminal: an express secret is
// written by an unverified third party (T-397).
//
// # Errors
//
// The problem codes of the server are mapped to sentinel errors
// ([ErrDisabled], [ErrTokenNotAllowed], [ErrRateLimited], [ErrLimitReached],
// [ErrNotFound], [ErrGone]...) whose messages say what to do; the original
// [*client.Problem] stays reachable with errors.As. No error message ever
// quotes the text, the key or the link.
package secret
