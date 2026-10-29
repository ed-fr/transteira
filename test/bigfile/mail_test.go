//go:build bigfile

package bigfile

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// mailTimeout bounds the wait for the recipient mail once the transfer is
// available.
const mailTimeout = 2 * time.Minute

// downloadLinkRE matches the personal download link of a notification mail.
var downloadLinkRE = regexp.MustCompile(`https://[^\s<>"')\]]+/d/[A-Za-z0-9_-]+`)

// mailGet reads a JSON answer of the Mailpit API (plain HTTP on the loopback
// interface, outside Caddy: Mailpit is the test's mail sink, not part of the
// production path).
func (c *client) mailGet(r *run, ref string, out any) {
	r.t.Helper()
	u, err := c.cfg.MailAPI.Parse(ref)
	if err != nil {
		r.fatalf("Mailpit %s: %v", ref, err)
	}
	resp, err := http.Get(u.String())
	if err != nil {
		r.fatalf("Mailpit %s: %v", ref, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		r.fatalf("Mailpit %s: HTTP %d (%v): %.300s", ref, resp.StatusCode, err, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		r.fatalf("Mailpit %s: invalid JSON: %v", ref, err)
	}
}

// recipientLink waits for the notification mail sent to the recipient and
// returns the path of its personal download link (the API never returns
// links: the sender and the admins cannot see them).
func (c *client) recipientLink(r *run, to string) string {
	r.t.Helper()
	var link string
	poll(r, "recipient mail with the download link", mailTimeout, func() bool {
		var found struct {
			Messages []struct{ ID string } `json:"messages"`
		}
		c.mailGet(r, "/api/v1/search?query="+url.QueryEscape(fmt.Sprintf("to:%q", to)), &found)
		for _, m := range found.Messages {
			var msg struct{ Text string }
			c.mailGet(r, "/api/v1/message/"+url.PathEscape(m.ID), &msg)
			if l := downloadLinkRE.FindString(msg.Text); l != "" {
				link = l
				return true
			}
		}
		return false
	})
	u, err := url.Parse(link)
	if err != nil {
		r.fatalf("download link %q: %v", link, err)
	}
	return u.Path
}
