// Package pdf is a minimal and safe PDF 1.7 writer, with a reader that
// extracts the embedded files of a PDF produced by the writer. It serves
// the proofs of deposit and delivery (threat T-303): a few pages of text
// (headings, labeled fields, hashes) and embedded files such as the signed
// statement.
//
// The writer only uses the standard fonts Helvetica, Helvetica-Bold and
// Courier (WinAnsi encoding, no embedding). Every text is converted to
// WinAnsi, stripped of control and bidirectional characters and escaped, so
// that no user-controlled string can produce PDF syntax. The output holds no
// JavaScript, action, annotation, link, form or OpenAction, and is
// deterministic for a given [Document].
//
// The reader is not a general PDF parser. It reads at most a fixed number of
// bytes, tolerates hostile input (bounded depth and object count, no panic,
// memory proportional to the input) and only understands what the writer
// emits: sequentially stored objects, direct or earlier indirect stream
// lengths, and unfiltered embedded file streams.
package pdf

import (
	"errors"
	"time"
)

// Errors returned by [Write] and [ReadAttachments].
var (
	// ErrTooLarge means the input is larger than the allowed limit.
	ErrTooLarge = errors.New("pdf: input too large")
	// ErrMalformed means the input is not a well-formed PDF of the supported
	// shape, or a document to write is invalid (bad or duplicate attachment
	// name).
	ErrMalformed = errors.New("pdf: malformed document")
	// ErrNoAttachments means the PDF holds no embedded file.
	ErrNoAttachments = errors.New("pdf: no attachments")
)

// DefaultMaxPages is the page bound applied when [Document.MaxPages] is 0.
const DefaultMaxPages = 50

// Attachment is a file embedded in the PDF. Name is stored exactly (UTF-16BE
// in /UF); it must be non-empty, valid UTF-8 and unique in the document.
type Attachment struct {
	Name, MIMEType, Description string
	Data                        []byte
}

// BlockKind selects how a [Block] is rendered.
type BlockKind int

// Block kinds.
const (
	// Heading is a large bold line.
	Heading BlockKind = iota
	// Paragraph is body text.
	Paragraph
	// Field is a bold Label followed by the Text value.
	Field
	// Mono is body text in Courier (hashes).
	Mono
	// Spacer is a vertical gap.
	Spacer
)

// Block is one element of the page content. Newlines in Text start a new
// line.
type Block struct {
	Kind        BlockKind
	Label, Text string
}

// Document describes a PDF to write.
type Document struct {
	// Title, Author and Subject go to /Info; Lang (for instance "fr") to the
	// catalog /Lang when it looks like a language tag.
	Title, Author, Subject, Lang string
	// Created is the /CreationDate; the zero value omits it.
	Created time.Time
	// Blocks is the visible content, laid out on A4 portrait pages.
	Blocks []Block
	// Attachments are embedded files, listed by sorted name.
	Attachments []Attachment
	// Footer is printed on each page, followed by "page n/N".
	Footer string
	// MaxPages bounds the page count (0 means [DefaultMaxPages]). Content
	// beyond it is dropped and TruncatedNotice is printed at the end.
	MaxPages        int
	TruncatedNotice string
}
