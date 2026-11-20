// Package textproposals builds the proposals of legal notice and privacy
// policy of a tenant (CLAUDE.md sections 16.2 and 20), shown by the setup
// wizard.
//
// A proposal is Markdown in the limited syntax accepted by the legal
// documents (package markup): it is only returned, never stored, and the
// administrator publishes it through the usual legal document endpoints
// after review. Templates are embedded in the binary and chosen only by
// closed enumerations (document kind and language), never by a path built
// from input. The real values of the entity ([Facts]) are inserted
// stripped of hidden characters and escaped for Markdown, so that no value
// can inject a link, a heading, HTML or a "to complete" marker. The
// information TransTeira cannot know (company name, address, host,
// controller, contacts...) is left as markers the administrator must
// replace; [HasPlaceholder] detects the remaining ones.
package textproposals

import (
	"embed"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/textsafe"
)

// Document kinds (OpenAPI LegalDocumentPath values).
const (
	// LegalNotice is the legal notice ("mentions légales").
	LegalNotice = "legal-notice"
	// PrivacyPolicy is the privacy policy.
	PrivacyPolicy = "privacy-policy"
)

// NoticeKey is the translation key of the review warning returned with each
// proposal (OpenAPI TextProposal.notice).
const NoticeKey = "setup.textProposal.reviewNotice"

// ErrUnknown is returned for an unknown document kind or language.
var ErrUnknown = errors.New("textproposals: unknown document or language")

// defaultRetentionMonths is used for a retention of Facts that is not
// positive (12 months, CLAUDE.md section 20).
const defaultRetentionMonths = 12

// Facts are the real values filled in a proposal.
type Facts struct {
	// TenantName is the display name of the entity.
	TenantName string
	// FQDN is the host of the entity.
	FQDN string
	// ValidityDays are the transfer durations offered, for example 1, 7, 30.
	ValidityDays []int
	// VerifiedRetentionMonths is how long an unused verified address is
	// kept, InvitationRetentionMonths how long an unused invitation stays
	// valid, LogRetentionMonths how long the audit and security logs are
	// kept (12 by default each).
	VerifiedRetentionMonths   int
	InvitationRetentionMonths int
	LogRetentionMonths        int
	// AntivirusEnabled tells that the files are scanned by an antivirus.
	AntivirusEnabled bool
	// ExpressOffered tells that the anonymous express secrets are really
	// offered (enabled by the entity and not closed by the instance kill
	// switch).
	ExpressOffered bool
	// SecretsEnabled tells that the one-time secrets module is on.
	SecretsEnabled bool
}

//go:embed templates/*/*.md
var templates embed.FS

// markerPrefixes are the starts of the "to complete" markers of every
// language. The escaped form of a marker (a backslash before the opening
// bracket) contains the plain prefix, so it is detected as well.
var markerPrefixes = []string{"[À compléter", "[To complete"}

// languageTexts are the words and sentences built in code, per language.
type languageTexts struct {
	and, day, days, antivirus, validityMarker string
	// oneTime and express are the optional paragraphs of the one-time
	// secrets and of the express secrets.
	oneTime, express string
}

var texts = map[string]languageTexts{
	"fr": {
		and: "et", day: "jour", days: "jours",
		antivirus:      "Chaque fichier déposé est analysé par un antivirus avant d'être mis à disposition. Un fichier infecté est supprimé.",
		validityMarker: "[À compléter : durées de validité des envois]",
		oneTime:        "Les secrets à usage unique sont chiffrés dans votre navigateur : le service ne voit jamais leur contenu en clair. Un secret est détruit à sa première lecture ou à son expiration.",
		express:        "Les secrets express sont créés sans authentification : le texte est chiffré dans le navigateur de son auteur et l'entité ne peut pas le lire. Il est détruit à la première lecture ou à son expiration, au plus tard au bout de 7 jours. L'adresse IP de son auteur est conservée {{LOG_MONTHS}} mois dans le journal d'audit ; aucune adresse mail n'est collectée.",
	},
	"en": {
		and: "and", day: "day", days: "days",
		antivirus:      "Each uploaded file is scanned by an antivirus before it is made available. An infected file is deleted.",
		validityMarker: "[To complete: validity periods of the transfers]",
		oneTime:        "One-time secrets are encrypted in your browser: the service never sees their content in clear. A secret is destroyed when it is first read or when it expires.",
		express:        "Express secrets are created without authentication: the text is encrypted in the browser of its author and the entity cannot read it. It is destroyed at first read or at expiry, after 7 days at most. The IP address of its author is kept for {{LOG_MONTHS}} months in the audit log; no email address is collected.",
	},
}

// Propose returns the Markdown proposal of document in language (fr or en),
// or [ErrUnknown] for an unknown document or language.
func Propose(document, language string, f Facts) (string, error) {
	if document != LegalNotice && document != PrivacyPolicy {
		return "", ErrUnknown
	}
	tx, ok := texts[language]
	if !ok {
		return "", ErrUnknown
	}
	// Every enumerated pair is embedded, so the read cannot fail.
	raw, _ := templates.ReadFile("templates/" + language + "/" + document + ".md")
	antivirus := ""
	if f.AntivirusEnabled {
		antivirus = tx.antivirus
	}
	oneTime, express := "", ""
	if f.SecretsEnabled {
		oneTime = tx.oneTime
	}
	if f.ExpressOffered {
		express = strings.ReplaceAll(tx.express, "{{LOG_MONTHS}}", months(f.LogRetentionMonths))
	}
	out := strings.NewReplacer(
		"{{SECRETS}}", oneTime,
		"{{EXPRESS}}", express,
		"{{TENANT}}", EscapeValue(f.TenantName),
		"{{FQDN}}", EscapeValue(f.FQDN),
		"{{VALIDITY}}", validity(f.ValidityDays, tx),
		"{{VERIFIED_MONTHS}}", months(f.VerifiedRetentionMonths),
		"{{INVITATION_MONTHS}}", months(f.InvitationRetentionMonths),
		"{{LOG_MONTHS}}", months(f.LogRetentionMonths),
		"{{ANTIVIRUS}}", antivirus,
	).Replace(string(raw))
	// An absent optional paragraph must not leave a run of blank lines.
	for strings.Contains(out, "\n\n\n") {
		out = strings.ReplaceAll(out, "\n\n\n", "\n\n")
	}
	return strings.TrimRight(out, "\n") + "\n", nil
}

// months formats a retention in months, defaultRetentionMonths when not
// positive.
func months(n int) string {
	if n <= 0 {
		n = defaultRetentionMonths
	}
	return strconv.Itoa(n)
}

// validity formats the offered durations ("1, 7 et 30 jours"), sorted and
// without duplicates. Without any positive duration it returns a marker.
func validity(days []int, tx languageTexts) string {
	list := slices.Clone(days)
	slices.Sort(list)
	list = slices.Compact(slices.DeleteFunc(list, func(d int) bool { return d <= 0 }))
	if len(list) == 0 {
		return tx.validityMarker
	}
	parts := make([]string, len(list))
	for i, d := range list {
		parts[i] = strconv.Itoa(d)
	}
	out := parts[0]
	if len(parts) > 1 {
		out = strings.Join(parts[:len(parts)-1], ", ") + " " + tx.and + " " + parts[len(parts)-1]
	}
	if list[len(list)-1] == 1 {
		return out + " " + tx.day
	}
	return out + " " + tx.days
}

// markdownEscaper escapes the punctuation the legal Markdown renderer
// treats as syntax (package markup supports a backslash before each of
// these characters; "{", "}" and "|" are inert there and left as is, since
// the renderer would show the backslash).
var markdownEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"(", `\(`, ")", `\)`, "<", `\<`, ">", `\>`, "#", `\#`, "+", `\+`,
	"-", `\-`, ".", `\.`, "!", `\!`,
)

// EscapeValue makes a free value safe to insert in a proposal: hidden
// characters (control, format, bidirectional, invisible) are removed, line
// breaks and tabs become spaces, and every Markdown-significant character
// is escaped, so that the value renders as plain text (a heading, list
// item, link or HTML in it stays literal). A value that would still form a
// "to complete" marker loses its square brackets.
func EscapeValue(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, textsafe.SanitizeMessage(s))
	s = strings.TrimSpace(s)
	if HasPlaceholder(s) {
		s = strings.NewReplacer("[", "", "]", "").Replace(s)
	}
	return markdownEscaper.Replace(s)
}

// HasPlaceholder reports whether markdown still contains a "to complete"
// marker of any language, in its plain or backslash-escaped form. A legal
// document is done only when no marker remains.
func HasPlaceholder(markdown string) bool {
	for _, p := range markerPrefixes {
		if strings.Contains(markdown, p) {
			return true
		}
	}
	return false
}
