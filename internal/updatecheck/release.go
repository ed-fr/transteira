package updatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode"
)

// ReleasePagePrefix is the only prefix of a release URL kept and shown.
const ReleasePagePrefix = "https://github.com/ed-fr/transteira/releases/"

// releasePathPrefix is the path of ReleasePagePrefix.
const releasePathPrefix = "/ed-fr/transteira/releases/"

// MaxReleaseURLLength bounds a release URL kept, in bytes.
const MaxReleaseURLLength = 512

// errParse reports an answer that is not the expected JSON, or a version
// that is not a strict SemVer; never quoted.
var errParse = errors.New("updatecheck: unreadable release")

// Release is what is kept of the latest release reported by GitHub.
type Release struct {
	// Version is the stable SemVer of the release, without a leading "v";
	// "" when the release is a draft or a pre-release, ignored.
	Version string
	// URL is the page of the release, "" unless [FilterReleaseURL] kept
	// it.
	URL string
}

// githubRelease holds the only members read from the answer: tag_name,
// html_url, draft and prerelease. Every other member (name, body, assets,
// author...) is skipped by the decoder, never stored.
type githubRelease struct {
	TagName    *string `json:"tag_name"`
	HTMLURL    *string `json:"html_url"`
	Draft      *bool   `json:"draft"`
	Prerelease *bool   `json:"prerelease"`
}

// ParseRelease reads the answer of GET /repos/{owner}/{repo}/releases/latest
// (at most MaxBody bytes, checked by the caller). It returns errParse
// when body is not a single JSON object, when tag_name is missing or not
// a string, when html_url, draft or prerelease have the wrong type, or
// when tag_name, without one leading "v", is not a strict SemVer of at
// most MaxVersionLength bytes. A draft or a pre-release (flag or SemVer
// suffix) returns a Release without version, which the caller ignores. A
// release URL refused by [FilterReleaseURL] is dropped, the version kept.
func ParseRelease(body []byte) (Release, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var r githubRelease
	if err := dec.Decode(&r); err != nil {
		return Release{}, errParse
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Release{}, errParse // trailing data
	}
	if r.TagName == nil || !isObject(body) {
		return Release{}, errParse
	}
	tag := *r.TagName
	if len(tag) > MaxVersionLength {
		return Release{}, errParse
	}
	v, ok := parseSemver(strings.TrimPrefix(tag, "v"))
	if !ok {
		return Release{}, errParse
	}
	if (r.Draft != nil && *r.Draft) || (r.Prerelease != nil && *r.Prerelease) || len(v.pre) > 0 {
		return Release{}, nil
	}
	out := Release{Version: strings.TrimPrefix(tag, "v")}
	if r.HTMLURL != nil {
		out.URL = FilterReleaseURL(*r.HTMLURL)
	}
	return out, nil
}

// isObject reports whether the JSON document body is an object (the
// decoder accepts null for a struct).
func isObject(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// FilterReleaseURL returns raw when it is the page of a release of the
// project: at most MaxReleaseURLLength bytes, no space nor control
// character, scheme https, host exactly github.com, no port, no user
// information, no query nor fragment, a path starting with
// ReleasePagePrefix's path followed by something, with no "." or ".."
// segment, no empty segment, no backslash and no escaped character. It
// returns "" otherwise: the link is then not shown.
func FilterReleaseURL(raw string) string {
	if len(raw) > MaxReleaseURLLength || !strings.HasPrefix(raw, ReleasePagePrefix) ||
		strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) ||
		strings.ContainsAny(raw, "\\%?#@") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.Port() != "" || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return ""
	}
	rest, ok := strings.CutPrefix(u.Path, releasePathPrefix)
	if !ok || rest == "" {
		return ""
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return ""
		}
	}
	if u.String() != raw {
		return ""
	}
	return raw
}
