package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Reply to a transfer (V1.1 step 9, CLAUDE.md section 10, threats
// T-222 to T-225).

const (
	// verificationCookieName is the recipient verification cookie.
	verificationCookieName = "__Host-tt_rv"
	// replyNoticeEN is the start of the reply notice of the notification
	// mail (internal/mail labels).
	replyNoticeEN = "This is a reply to the transfer you sent on"
)

// setReplyAllowed turns the replies of tenant A on or off, as its admin
// would.
func (d *depositEnv) setReplyAllowed(t *testing.T, on bool) {
	t.Helper()
	ctx := context.Background()
	tn, err := d.db.Tenants().Get(ctx, d.tenantA.ID)
	if err != nil {
		t.Fatal(err)
	}
	tn.AllowTransferReply = on
	if _, err := d.db.Tenants().Update(ctx, tn); err != nil {
		t.Fatalf("update tenant: %v", err)
	}
}

// post sends a JSON POST of path as the recipient.
func (r *recipient) post(t *testing.T, path, body string) response {
	t.Helper()
	return r.d.do(t, request{method: http.MethodPost, host: r.host, path: path, body: []byte(body), headers: r.headers(nil)})
}

// verifyForReply proves the address email of the link token to the
// recipient with a code (purpose reply) and keeps the verification cookie.
func (r *recipient) verifyForReply(t *testing.T, token, email string) {
	t.Helper()
	r.verifyFor(t, token, email, "reply")
}

// verifyFor proves the address email of the link token to the recipient
// with a code for purpose and keeps the verification cookie. Only a code
// mail sent after the request counts, so that email may have received
// other codes before.
func (r *recipient) verifyFor(t *testing.T, token, email, purpose string) {
	t.Helper()
	seen := map[string]bool{}
	for _, m := range r.d.mp.messagesTo(t, email) {
		seen[m.ID] = true
	}
	mustStatus(t, "startRecipientVerification", r.post(t, pathDownloads+token+"/verification", `{"purpose":"`+purpose+`"}`), http.StatusAccepted)
	msg := r.d.mp.find(t, email, func(m mpMessage) bool {
		return !seen[m.ID] && strings.HasPrefix(m.Subject, "Your verification code")
	})
	m := codeRE.FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("no code in the mail to %s:\n%s", email, msg.Text)
	}
	resp := mustStatus(t, "confirmRecipientVerification", r.post(t, pathDownloads+token+"/verification/confirm", `{"code":"`+m[1]+`"}`), http.StatusNoContent)
	for _, v := range resp.header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(v); err == nil && c.Name == verificationCookieName {
			r.verification = c.Value
		}
	}
	if r.verification == "" {
		t.Fatalf("no %s cookie in %q", verificationCookieName, resp.header.Values("Set-Cookie"))
	}
}

// startReply sends startTransferReply and, on 201, returns the depositor of
// the reply session.
func (r *recipient) startReply(t *testing.T, token string) (*depositor, response) {
	t.Helper()
	resp := r.post(t, pathDownloads+token+"/reply", `{}`)
	if resp.status != http.StatusCreated {
		return nil, resp
	}
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	mustJSON(t, resp.body, &body)
	c := r.d.newDepositor()
	c.ip = r.ip
	for _, v := range resp.header.Values("Set-Cookie") {
		if ck, err := http.ParseSetCookie(v); err == nil && ck.Name == depositCookieName {
			c.cookie = ck.Value
		}
	}
	c.csrf = body.CSRFToken
	if c.cookie == "" {
		t.Fatalf("no deposit cookie in %q", resp.header.Values("Set-Cookie"))
	}
	return c, resp
}

// replyFlags decodes replyAllowed and reply of a download page.
func replyFlags(t *testing.T, resp response) (allowed, reply *bool) {
	t.Helper()
	var v struct {
		ReplyAllowed *bool `json:"replyAllowed"`
		Reply        *bool `json:"reply"`
	}
	mustJSON(t, resp.body, &v)
	return v.ReplyAllowed, v.Reply
}

// replyFeature reports features.transferReply of the public configuration
// of tenant A.
func replyFeature(t *testing.T, d *depositEnv) bool {
	t.Helper()
	cfg := mustStatus(t, "GET /tenant", d.get(t, hostA, pathPublicTenant), http.StatusOK)
	var pub struct {
		Features struct {
			TransferReply bool `json:"transferReply"`
		} `json:"features"`
	}
	mustJSON(t, cfg.body, &pub)
	return pub.Features.TransferReply
}

// TestReplyFlow: a recipient proves their address with a code, replies to
// the sender of a transfer without invitation (the recipients of the
// request are ignored), the original sender is mailed with the reply
// notice, a reply cannot be replied to, and the original transfer
// disappearing before the finalization refuses it (410).
func TestReplyFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.setReplyAllowed(t, true)
		alice, aliceMail := internalSession(t, o.depositEnv, "alice")
		carol := uniqueEmail(t, "carol", "example.net")
		stranger := uniqueEmail(t, "stranger", "example.org")
		orig, token := alice.availableTransfer(t, transferCreate{Recipients: []string{carol}}, uploadedFile{"plans.txt", []byte("the plans")})
		o.secret(token)

		if !replyFeature(t, o.depositEnv) {
			t.Error("features.transferReply is false with the option on")
		}
		rc := o.newRecipient(1)
		if allowed, reply := replyFlags(t, rc.page(t, token)); allowed == nil || !*allowed || reply != nil {
			t.Errorf("page flags = %v %v, want replyAllowed only", allowed, reply)
		}
		// Without proof of the address: 401, nothing opened.
		expectTransferProblem(t, rc.post(t, pathDownloads+token+"/reply", `{}`), http.StatusUnauthorized, "recipient-verification-required")
		rc.verifyForReply(t, token, carol)

		replier, resp := rc.startReply(t, token)
		if replier == nil {
			t.Fatalf("startTransferReply: %d %s", resp.status, resp.body)
		}
		var sess struct {
			Email     string `json:"email"`
			Kind      string `json:"kind"`
			CanInvite bool   `json:"canInvite"`
			Reply     struct {
				Recipient string `json:"recipient"`
			} `json:"reply"`
		}
		mustJSON(t, resp.body, &sess)
		if sess.Email != carol || sess.Kind != "reply" || sess.CanInvite || sess.Reply.Recipient != aliceMail {
			t.Errorf("session = %s", resp.body)
		}
		if strings.Contains(string(resp.body), orig.ID) {
			t.Errorf("session body leaks the original transfer id: %s", resp.body)
		}

		// The recipients of the request are ignored.
		replyTr, replyToken := replier.availableTransfer(t, transferCreate{Recipients: []string{stranger}}, uploadedFile{"answer.txt", []byte("the answer")})
		if len(replyTr.Recipients) != 1 || replyTr.Recipients[0] != aliceMail || replyTr.ReplyToTransferID != orig.ID || replyTr.SenderEmail != carol {
			t.Errorf("reply transfer = %+v", replyTr)
		}
		o.mp.find(t, aliceMail, func(m mpMessage) bool { return strings.Contains(o.mp.content(t, m.ID), replyNoticeEN) })
		if n := len(o.mp.messagesTo(t, stranger)); n != 0 {
			t.Errorf("the ignored recipient got %d mails", n)
		}

		// The admin view tells the origin and the original.
		admin := mustStatus(t, "getTenantTransfer", o.sa.call(t, http.MethodGet, tenantPath(o.tid, "/transfers/"+replyTr.ID), nil), http.StatusOK)
		var av struct {
			Origin            string `json:"origin"`
			ReplyToTransferID string `json:"replyToTransferId"`
		}
		mustJSON(t, admin.body, &av)
		if av.Origin != "reply" || av.ReplyToTransferID != orig.ID {
			t.Errorf("admin view = %s", admin.body)
		}

		// A reply is not replied to: its page offers none and refuses it
		// (without a proved address, as for any link: 401, which tells
		// nothing of the sender; see TestReplyRefusals for a proved one).
		o.secret(replyToken)
		ra := o.newRecipient(2)
		if allowed, reply := replyFlags(t, ra.page(t, replyToken)); allowed == nil || *allowed || reply == nil || !*reply {
			t.Errorf("reply page flags = %v %v, want reply and no replyAllowed", allowed, reply)
		}
		expectTransferProblem(t, ra.post(t, pathDownloads+replyToken+"/reply", `{}`), http.StatusUnauthorized, "recipient-verification-required")
		expectTransferProblem(t, ra.post(t, pathDownloads+replyToken+"/verification", `{"purpose":"reply"}`), http.StatusForbidden, "reply-not-allowed")

		// The original disappearing before the finalization: 410.
		replier2, _ := rc.startReply(t, token)
		if replier2 == nil {
			t.Fatal("second reply session refused")
		}
		pending := replier2.mustCreate(t, oneFile("late.txt", 4))
		replier2.upload(t, pending.Files[0].UploadURL, []byte("late"))
		mustStatus(t, "deleteTransfer", o.sa.deleteTransfer(t, o.tid, orig.ID, ""), http.StatusNoContent)
		expectTransferProblem(t, replier2.finalize(t, pending.ID), http.StatusGone, "transfer-gone")
		expectTransferProblem(t, replier2.createTransfer(t, oneFile("again.txt", 4), ""), http.StatusGone, "transfer-gone")
		expectTransferProblem(t, rc.post(t, pathDownloads+token+"/reply", `{}`), http.StatusGone, "transfer-gone")
	})
}

// TestReplyDisabled: replies are off by default (no feature, no
// replyAllowed, 403 reply-not-allowed), and turning the option off stops
// the replies of an open session at the creation of a transfer.
func TestReplyDisabled(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		so, _ := withScanner(t, serverOptions{})
		d := startDeposit(t, e, so, true)
		alice, _ := internalSession(t, d, "alice")
		carol := uniqueEmail(t, "carol", "example.net")
		_, token := alice.availableTransfer(t, transferCreate{Recipients: []string{carol}}, uploadedFile{"a.txt", []byte("a")})

		rc := d.newRecipient(3)
		if replyFeature(t, d) {
			t.Error("features.transferReply is true by default")
		}
		if allowed, _ := replyFlags(t, rc.page(t, token)); allowed == nil || *allowed {
			t.Errorf("replyAllowed = %v, want false", allowed)
		}
		expectTransferProblem(t, rc.post(t, pathDownloads+token+"/reply", `{}`), http.StatusForbidden, "reply-not-allowed")
		expectTransferProblem(t, rc.post(t, pathDownloads+token+"/verification", `{"purpose":"reply"}`), http.StatusForbidden, "reply-not-allowed")

		// On, a session opens; off again, it can no longer create.
		d.setReplyAllowed(t, true)
		rc.verifyForReply(t, token, carol)
		replier, resp := rc.startReply(t, token)
		if replier == nil {
			t.Fatalf("startTransferReply: %d %s", resp.status, resp.body)
		}
		d.setReplyAllowed(t, false)
		expectTransferProblem(t, replier.createTransfer(t, oneFile("x.txt", 1), ""), http.StatusForbidden, "reply-not-allowed")
	})
}

// TestReplyRefusals: the refusals of a reply over HTTP, each on a fresh
// transfer of alice to carol (the fixtures of TestReplyFlow) whose link
// carol proved for a reply.
func TestReplyRefusals(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.setReplyAllowed(t, true)
		alice, aliceMail := internalSession(t, o.depositEnv, "alice")
		cases := []struct {
			name string
			run  func(t *testing.T, rc *recipient, token, origID string)
		}{
			{"reply to a reply", func(t *testing.T, rc *recipient, token, _ string) {
				replier, resp := rc.startReply(t, token)
				if replier == nil {
					t.Fatalf("startTransferReply: %d %s", resp.status, resp.body)
				}
				// The reply asks its recipient (alice) to prove the address:
				// once proved, the kind of its sender refuses the reply.
				_, replyToken := replier.availableTransfer(t, transferCreate{RecipientVerification: true},
					uploadedFile{"answer.txt", []byte("answer")})
				o.secret(replyToken)
				ra := o.newRecipient(40)
				expectTransferProblem(t, ra.post(t, pathDownloads+replyToken+"/reply", `{}`), http.StatusUnauthorized, "recipient-verification-required")
				ra.verifyFor(t, replyToken, aliceMail, "download")
				expectTransferProblem(t, ra.post(t, pathDownloads+replyToken+"/reply", `{}`), http.StatusForbidden, "reply-not-allowed")
				expectTransferProblem(t, ra.post(t, pathDownloads+replyToken+"/verification", `{"purpose":"reply"}`), http.StatusForbidden, "reply-not-allowed")
			}},
			{"original deleted during the upload", func(t *testing.T, rc *recipient, token, origID string) {
				replier, _ := rc.startReply(t, token)
				if replier == nil {
					t.Fatal("reply session refused")
				}
				pending := replier.mustCreate(t, oneFile("late.txt", 4))
				replier.upload(t, pending.Files[0].UploadURL, []byte("late"))
				mustStatus(t, "deleteTransfer", o.sa.deleteTransfer(t, o.tid, origID, ""), http.StatusNoContent)
				expectTransferProblem(t, replier.finalize(t, pending.ID), http.StatusGone, "transfer-gone")
			}},
			{"option turned off during the session", func(t *testing.T, rc *recipient, token, _ string) {
				replier, _ := rc.startReply(t, token)
				if replier == nil {
					t.Fatal("reply session refused")
				}
				o.setReplyAllowed(t, false)
				defer o.setReplyAllowed(t, true)
				expectTransferProblem(t, replier.createTransfer(t, oneFile("x.txt", 4), ""), http.StatusForbidden, "reply-not-allowed")
				expectTransferProblem(t, rc.post(t, pathDownloads+token+"/reply", `{}`), http.StatusForbidden, "reply-not-allowed")
			}},
			{"external quota", func(t *testing.T, rc *recipient, token, _ string) {
				replier, _ := rc.startReply(t, token)
				if replier == nil {
					t.Fatal("reply session refused")
				}
				prev, err := o.db.AbuseSettings().Get(context.Background(), o.tenantA.ID)
				if err != nil {
					t.Fatal(err)
				}
				limited := prev
				one := int64(1)
				limited.ExternalMaxDailyBytes, limited.BlockOnExceed = &one, true
				if _, err := o.db.AbuseSettings().Put(context.Background(), o.tenantA.ID, limited); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := o.db.AbuseSettings().Put(context.Background(), o.tenantA.ID, prev); err != nil {
						t.Error(err)
					}
				}()
				expectTransferProblem(t, replier.createTransfer(t, oneFile("big.txt", 4), ""), http.StatusForbidden, "abuse-threshold-blocked")
			}},
			{"original sender blocklisted", func(t *testing.T, rc *recipient, token, _ string) {
				entry := o.blockEntry(t, store.BlockEmail, aliceMail)
				defer func() {
					if err := o.db.Blocklist().Delete(context.Background(), o.tenantA.ID, entry); err != nil {
						t.Error(err)
					}
				}()
				expectTransferProblem(t, rc.post(t, pathDownloads+token+"/reply", `{}`), http.StatusForbidden, "reply-not-allowed")
			}},
			{"too many live reply sessions", func(t *testing.T, rc *recipient, token, _ string) {
				for i := range 5 {
					if replier, resp := rc.startReply(t, token); replier == nil {
						t.Fatalf("reply session %d: %d %s", i+1, resp.status, resp.body)
					}
				}
				resp := rc.post(t, pathDownloads+token+"/reply", `{}`)
				expectTransferProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
				if resp.header.Get("Retry-After") == "" {
					t.Error("429 without Retry-After")
				}
			}},
		}
		for i, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				carol := uniqueEmail(t, "carol", "example.net")
				orig, token := alice.availableTransfer(t, transferCreate{Recipients: []string{carol}}, uploadedFile{"plans.txt", []byte("the plans")})
				o.secret(token)
				rc := o.newRecipient(20 + i)
				rc.verifyForReply(t, token, carol)
				tc.run(t, rc, token, orig.ID)
			})
		}
	})
}
