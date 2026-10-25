package bigfile

import (
	"encoding/json"
	"fmt"
	"strings"
)

// secretPaths are the API paths whose answers carry a secret (the TOTP
// enrollment secret of the first-run setup, the API token): their bodies are
// never copied into a failure message, which ends up in the test log and the
// report.
var secretPaths = []string{"/admin/setup", "/api-tokens"}

// BodyForLog returns the body of a response to show in a failure message
// (its first 600 bytes), or, for a call on a secret path (what names the
// method and the path), only the code and the title of the RFC 9457
// problem it carries.
func BodyForLog(what string, body []byte) string {
	for _, p := range secretPaths {
		if strings.Contains(what, p) {
			var pb struct {
				Code  string `json:"code"`
				Title string `json:"title"`
			}
			if json.Unmarshal(body, &pb) != nil || (pb.Code == "" && pb.Title == "") {
				return fmt.Sprintf("[body of %d bytes not shown: secret path]", len(body))
			}
			return fmt.Sprintf("problem %q: %q [rest of the body not shown: secret path]", pb.Code, pb.Title)
		}
	}
	if len(body) > 600 {
		body = body[:600]
	}
	return string(body)
}
