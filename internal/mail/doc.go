// Package mail sends the e-mails of TransTeira through the SMTP server of
// each tenant (CLAUDE.md section 12).
//
// It provides:
//
//   - [Settings], the SMTP configuration of a tenant, with three security
//     modes: "none" (internal relay, no TLS, no authentication), "starttls"
//     (mandatory upgrade) and "tls" (implicit TLS);
//   - [Message] and [Build], a strict MIME builder: multipart/alternative
//     text and HTML bodies in quoted-printable, multipart/related inline
//     images (CID), RFC 2047 headers, and validation that makes header
//     injection impossible (threat T-80);
//   - [Sender] and its SMTP implementation [SMTPSender], with bounded
//     timeouts and context cancellation;
//   - [Templates], the embedded French and English templates, rendered by
//     language (see package i18n for the negotiation);
//   - [Queue], a bounded in-memory queue with background workers and one
//     retry, so that HTTP handlers never wait for an SMTP server (T-89).
//
// Message bodies, subjects, verification codes and SMTP passwords are never
// logged; recipients only appear in logs as [AddressHash] pseudonyms.
package mail
