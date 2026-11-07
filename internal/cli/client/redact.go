package client

import (
	"regexp"
	"strings"
)

// identifierPattern matches a TransTeira identifier or bearer token: a
// lowercase prefix of 2 to 4 letters, an underscore, then 12 characters or
// more of base62. Download links (dl_), upload sessions (upl_), invitations
// (inv_), API tokens (tt_) and the like all match; entity identifiers
// (fil_, trf_) are shortened too, which costs nothing.
var identifierPattern = regexp.MustCompile(`([a-z]{2,4})_([A-Za-z0-9]{4})[A-Za-z0-9]{8,}`)

// Redact makes a URL, a path or a message safe for the verbose log and
// error messages: it drops everything from the first '?' or '#' (query
// strings carry codes, fragments carry end-to-end keys), then cuts every
// identifier or bearer token ("dl_Xk4Lm9Qp...") to its prefix and 4
// characters followed by "…", and finally removes hidden characters.
func Redact(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return printable(identifierPattern.ReplaceAllString(s, "${1}_${2}…"))
}
