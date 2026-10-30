package integration_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/diskalert"
	"github.com/ed-fr/transteira/internal/keyrotation"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the system operations of the super admin (CLAUDE.md
// sections 4, 12.2, 16.1 and 19; api/openapi.yaml "Admin system"; threat
// model T-154 to T-158): maintenance mode, system settings, disk alert and
// master key rotation from the administration.

// maintenanceMessages are the messages of the maintenance tests.
var maintenanceMessages = map[string]string{
	"fr": "Mise à jour en cours, retour vers 20 h.",
	"en": "Upgrade in progress, back around 8 pm.",
}

// maintenanceDeposit sends a deposit request refused in maintenance mode
// (createTransfer) on tenant A with Accept-Language lang ("" sends none)
// and returns the detail of the 503 maintenance Problem.
func maintenanceDeposit(t *testing.T, s *server, name, lang string) string {
	t.Helper()
	req := depositRequests()[name]
	req.host = hostA
	if lang != "" {
		req.headers = http.Header{"Accept-Language": {lang}}
	}
	p := expectProblem(t, s.do(t, req), http.StatusServiceUnavailable, "maintenance")
	return p.Detail
}

// publicMaintenance sends getPublicTenant on tenant A with Accept-Language
// lang and returns its maintenance members.
func publicMaintenance(t *testing.T, s *server, lang string) publicMaintenanceJSON {
	t.Helper()
	resp := mustStatus(t, "getPublicTenant", s.do(t, request{
		host: hostA, path: pathPublicTenant, headers: http.Header{"Accept-Language": {lang}},
	}), http.StatusOK)
	var p publicMaintenanceJSON
	mustJSON(t, resp.body, &p)
	return p
}

// healthOf returns the /healthz answer.
func healthOf(t *testing.T, s *server) healthBody {
	t.Helper()
	resp := mustStatus(t, "/healthz", s.get(t, "", "/healthz"), http.StatusOK)
	var h healthBody
	mustJSON(t, resp.body, &h)
	return h
}

// TestMaintenanceAdmin: the super admin enables the maintenance mode with
// French and English messages; deposits get 503 with the message of the
// negotiated language, tus uploads a bodyless 503, downloads still work,
// /healthz and the public tenant report it. The choice survives a restart,
// then disabling it reopens the deposits. Both changes are global audit
// events listing the message languages only.
func TestMaintenanceAdmin(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o, _ := withScanner(t, serverOptions{})
		a := startAdmin(t, e, o, true)
		var logs []*watchBuffer
		sa := a.bootstrapUnique(t, adminIP(10))
		alice, _ := internalSession(t, a.depositEnv, "alice")
		content := []byte("downloadable during the maintenance")
		tr, token := alice.availableTransfer(t, transferCreate{}, uploadedFile{name: "notes.txt", content: content})
		rcpt := a.newRecipient(1)

		if st := sa.maintenance(t); st.Enabled || st.Source != "none" || st.AdminEnabled || st.Since != nil || st.Message != nil {
			t.Errorf("initial maintenance = %+v, want off", st)
		}

		// Invalid messages are refused, naming the member.
		for name, c := range map[string]struct {
			message map[string]string
			field   string
		}{
			"unsupported language": {map[string]string{"de": "Wartung"}, "/message/de"},
			"empty message":        {map[string]string{"fr": ""}, "/message/fr"},
			"too long":             {map[string]string{"en": strings.Repeat("a", 501)}, "/message/en"},
			"control character":    {map[string]string{"en": "bell\x07"}, "/message/en"},
			"bidi control":         {map[string]string{"fr": "abc\u202edef"}, "/message/fr"},
		} {
			p := expectTransferProblem(t, sa.setMaintenance(t, map[string]any{"enabled": true, "message": c.message}),
				http.StatusBadRequest, "validation-failed")
			if len(p.Errors) != 1 || p.Errors[0].Field != c.field {
				t.Errorf("%s: errors %+v, want one on %s", name, p.Errors, c.field)
			}
		}
		if st := sa.maintenance(t); st.Enabled {
			t.Fatal("an invalid setMaintenance enabled the maintenance mode")
		}

		on := sa.mustSetMaintenance(t, map[string]any{"enabled": true, "message": maintenanceMessages})
		if !on.Enabled || on.Source != "admin" || !on.AdminEnabled || on.Since == nil || !maps.Equal(on.Message, maintenanceMessages) {
			t.Errorf("setMaintenance(on) = %+v", on)
		}

		effects := func(label string) {
			t.Helper()
			for lang, want := range map[string]string{
				"fr":              maintenanceMessages["fr"],
				"fr-CH, fr;q=0.9": maintenanceMessages["fr"],
				"en-GB":           maintenanceMessages["en"],
				"":                maintenanceMessages["en"], // tenant default
				"de":              maintenanceMessages["en"], // tenant default
				"de, fr;q=0.5":    maintenanceMessages["fr"],
			} {
				for _, op := range []string{"createTransfer", "startDepositSession", "createInvitation"} {
					if got := maintenanceDeposit(t, a.server, op, lang); got != want {
						t.Errorf("%s: %s with Accept-Language %q: detail %q, want %q", label, op, lang, got, want)
					}
				}
			}
			tus := depositRequests()["appendUploadChunk"]
			tus.host = hostA
			resp := a.do(t, tus)
			if resp.status != http.StatusServiceUnavailable || len(resp.body) != 0 || resp.header.Get("Tus-Resumable") != "1.0.0" {
				t.Errorf("%s: tus PATCH = %d %q (Tus-Resumable %q), want a bodyless 503", label, resp.status, resp.body,
					resp.header.Get("Tus-Resumable"))
			}
			expectFile(t, label+": download", rcpt.get(t, filePath(token, tr.Files[0].ID), nil), "notes.txt", content)
			if !healthOf(t, a.server).Maintenance {
				t.Errorf("%s: /healthz does not report the maintenance", label)
			}
			// The language of the message is reported with it (RGAA 8.7).
			for lang, wantLang := range map[string]string{"fr": "fr", "en": "en", "de": "en"} {
				want := maintenanceMessages[wantLang]
				p := publicMaintenance(t, a.server, lang)
				if !p.Maintenance || p.MaintenanceMessage == nil || *p.MaintenanceMessage != want ||
					p.MaintenanceMessageLanguage == nil || *p.MaintenanceMessageLanguage != wantLang {
					t.Errorf("%s: public tenant (%s) = %+v, want maintenance with %q in %q", label, lang, p, want, wantLang)
				}
			}
		}
		effects("enabled")

		// The choice is stored: a restart on the same database keeps it.
		if err := a.stop(); err != nil {
			t.Fatalf("stop: %v\napp log:\n%s", err, a.appLog)
		}
		logs = append(logs, a.appLog)
		a.server = a.restart(t)
		if st := sa.maintenance(t); !st.Enabled || st.Source != "admin" || !st.AdminEnabled || st.Since == nil ||
			*st.Since != *on.Since || !maps.Equal(st.Message, maintenanceMessages) {
			t.Errorf("maintenance after the restart = %+v, want %+v", st, on)
		}
		effects("after the restart")

		off := sa.mustSetMaintenance(t, map[string]any{"enabled": false})
		if off.Enabled || off.Source != "none" || off.AdminEnabled || off.Since != nil || off.Message != nil {
			t.Errorf("setMaintenance(off) = %+v", off)
		}
		alice.mustCreate(t, oneFile("after-maintenance.txt", 4))
		if healthOf(t, a.server).Maintenance {
			t.Error("/healthz still reports the maintenance")
		}
		if p := publicMaintenance(t, a.server, "fr"); p.Maintenance || p.MaintenanceMessage != nil || p.MaintenanceMessageLanguage != nil {
			t.Errorf("public tenant after the maintenance = %+v", p)
		}

		// Global audit events, with the languages only.
		enabled := sa.globalEvents(t, actMaintenanceEnabled)
		if len(enabled) != 1 {
			t.Fatalf("%d %s events, want 1", len(enabled), actMaintenanceEnabled)
		}
		expectGlobalEvent(t, enabled[0], "admin", superName, adminIP(10), "system", "maintenance")
		if langs, _ := json.Marshal(enabled[0].Details["languages"]); string(langs) != `["en","fr"]` || len(enabled[0].Details) != 1 {
			t.Errorf("%s details = %v, want the languages only", actMaintenanceEnabled, enabled[0].Details)
		}
		disabled := sa.globalEvents(t, actMaintenanceDisabled)
		if len(disabled) != 1 {
			t.Fatalf("%d %s events, want 1", len(disabled), actMaintenanceDisabled)
		}
		expectGlobalEvent(t, disabled[0], "admin", superName, adminIP(10), "system", "maintenance")
		if len(disabled[0].Details) != 0 {
			t.Errorf("%s details = %v, want none (no message)", actMaintenanceDisabled, disabled[0].Details)
		}
		for _, r := range a.auditRows(t) {
			for _, m := range maintenanceMessages {
				if strings.Contains(r.details, m) {
					t.Errorf("audit event %s holds a maintenance message: %s", r.action, r.details)
				}
			}
		}

		// MaintenanceUpdate requires enabled: an empty object must not
		// silently disable the mode.
		t.Run("enabled is required", func(t *testing.T) {
			sa.mustSetMaintenance(t, map[string]any{"enabled": true})
			p := expectTransferProblem(t, sa.setMaintenance(t, map[string]any{}), http.StatusBadRequest, "validation-failed")
			expectFieldCode(t, p, "/enabled", "required")
			if st := sa.maintenance(t); !st.Enabled {
				t.Error("setMaintenance with {} disabled the maintenance mode")
			}
			sa.mustSetMaintenance(t, map[string]any{"enabled": false})
		})
		a.expectLogsClean(t, logs)
	})
}

// TestMaintenanceForcedByEnv: TT_MAINTENANCE=true forces the mode (source
// environment); the super admin cannot disable it (409) but may store a
// choice and a message, shown at once.
func TestMaintenanceForcedByEnv(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{maintenance: true}, false)
		sa := a.bootstrapUnique(t, adminIP(10))

		st := sa.maintenance(t)
		if !st.Enabled || st.Source != "environment" || st.AdminEnabled || st.Since == nil || st.Message != nil {
			t.Errorf("forced maintenance = %+v", st)
		}
		if got := maintenanceDeposit(t, a.server, "createTransfer", "fr"); got != "" {
			t.Errorf("detail without message = %q, want none", got)
		}
		expectProblem(t, sa.setMaintenance(t, map[string]any{"enabled": false}), http.StatusConflict, "state-conflict")
		if got := sa.maintenance(t); !maps.Equal(got.Message, st.Message) || got.AdminEnabled || !got.Enabled {
			t.Errorf("maintenance after the refused disable = %+v", got)
		}

		msg := map[string]string{"en": "Forced upgrade.\nBack soon."}
		on := sa.mustSetMaintenance(t, map[string]any{"enabled": true, "message": msg})
		if !on.Enabled || on.Source != "environment" || !on.AdminEnabled || !maps.Equal(on.Message, msg) {
			t.Errorf("setMaintenance(on) while forced = %+v", on)
		}
		if got := maintenanceDeposit(t, a.server, "createTransfer", "fr"); got != msg["en"] {
			t.Errorf("detail = %q, want the English message (only one set)", got)
		}
		expectProblem(t, sa.setMaintenance(t, map[string]any{"enabled": false, "message": msg}), http.StatusConflict, "state-conflict")
		if n := len(sa.globalEvents(t, actMaintenanceEnabled)); n != 1 {
			t.Errorf("%d %s events, want 1", n, actMaintenanceEnabled)
		}
		if n := len(sa.globalEvents(t, actMaintenanceDisabled)); n != 0 {
			t.Errorf("%d %s events, want none (refused)", n, actMaintenanceDisabled)
		}
		a.expectLogsClean(t, nil)
	})
}

// TestSystemSettings: defaults, merge patch (null removes the address),
// bounds, the delegated admin refused, the global statistics following the
// threshold and config.updated events naming the fields, never the
// address.
func TestSystemSettings(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		// A constant fake disk, well under every threshold: the real disk
		// of the machine must not raise the alert.
		quiet := serverOptions{diskAlert: func(o *diskalert.Options) {
			o.Measure = func(string) (uint64, uint64, error) { return diskTotal, diskTotal / 10 * 9, nil }
		}}
		a := startAdmin(t, e, quiet, false)
		sa := a.bootstrapUnique(t, adminIP(10))

		resp := mustStatus(t, "getSystemSettings", sa.call(t, http.MethodGet, pathSystemSettings, nil), http.StatusOK)
		var members map[string]json.RawMessage
		mustJSON(t, resp.body, &members)
		if string(members["alertEmail"]) != "null" || string(members["diskAlertThreshold"]) != "0.85" ||
			string(members["antivirusEngine"]) != `"clamd"` || len(members) != 3 {
			t.Errorf("default settings = %s, want threshold 0.85, alertEmail null and engine clamd", resp.body)
		}

		alert := uniqueEmail(t, "it-admin", "example.com")
		s := sa.mustPatchSettings(t, `{"diskAlertThreshold":0.9,"alertEmail":"`+alert+`"}`)
		if !near(s.DiskAlertThreshold, 0.9) || s.AlertEmail == nil || *s.AlertEmail != alert {
			t.Errorf("patched settings = %+v", s)
		}
		if got := sa.settings(t); !near(got.DiskAlertThreshold, 0.9) || got.AlertEmail == nil || *got.AlertEmail != alert {
			t.Errorf("settings after the patch = %+v", got)
		}
		s = sa.mustPatchSettings(t, `{"alertEmail":null}`)
		if !near(s.DiskAlertThreshold, 0.9) || s.AlertEmail != nil {
			t.Errorf("settings after alertEmail null = %+v, want threshold 0.9 kept and no address", s)
		}
		for _, v := range []float64{0.5, 0.99, 0.95} {
			if s = sa.mustPatchSettings(t, `{"diskAlertThreshold":`+strconv.FormatFloat(v, 'f', -1, 64)+`}`); !near(s.DiskAlertThreshold, v) {
				t.Errorf("threshold %v stored as %v", v, s.DiskAlertThreshold)
			}
		}
		// A patch that changes nothing records nothing.
		sa.mustPatchSettings(t, `{"diskAlertThreshold":0.95}`)

		for _, c := range []struct{ body, field, code string }{
			{`{"diskAlertThreshold":0.49}`, "/diskAlertThreshold", "invalid-format"},
			{`{"diskAlertThreshold":0.995}`, "/diskAlertThreshold", "invalid-format"},
			{`{"diskAlertThreshold":1}`, "/diskAlertThreshold", "invalid-format"},
			{`{"diskAlertThreshold":-0.9}`, "/diskAlertThreshold", "invalid-format"},
			{`{"diskAlertThreshold":"0.9"}`, "/diskAlertThreshold", "invalid-format"},
			{`{"diskAlertThreshold":null}`, "/diskAlertThreshold", "not-nullable"},
			{`{"alertEmail":"not an address"}`, "/alertEmail", "invalid-email"},
			{`{"alertEmail":"Ops <ops@example.com>"}`, "/alertEmail", "invalid-email"},
			{`{"alertEmail":42}`, "/alertEmail", "invalid-format"},
			{`{"unknown":1}`, "/unknown", "invalid-format"},
			{`[]`, "", "invalid-format"},
		} {
			p := expectTransferProblem(t, sa.mergePatch(t, pathSystemSettings, c.body), http.StatusBadRequest, "validation-failed")
			expectFieldCode(t, p, c.field, c.code)
		}
		if got := sa.settings(t); !near(got.DiskAlertThreshold, 0.95) || got.AlertEmail != nil {
			t.Errorf("settings after the refused patches = %+v", got)
		}

		g := sa.globalDisk(t)
		if !near(g.Disk.AlertThreshold, 0.95) || g.Disk.AlertActive || g.Disk.AlertMailConfigured {
			t.Errorf("global stats disk = %+v, want threshold 0.95, no alert, no system mail", g.Disk)
		}

		// The delegated admin reads the maintenance mode and nothing else.
		da := sa.createDelegatedOf(t, "delegate", string(a.tenantA.ID), domainA, adminIP(20))
		expectProblem(t, da.call(t, http.MethodGet, pathSystemSettings, nil), http.StatusForbidden, "forbidden")
		expectProblem(t, da.mergePatch(t, pathSystemSettings, `{"diskAlertThreshold":0.6}`), http.StatusForbidden, "forbidden")
		expectProblem(t, da.call(t, http.MethodGet, pathGlobalStats, nil), http.StatusForbidden, "forbidden")
		expectProblem(t, da.setMaintenance(t, map[string]any{"enabled": true}), http.StatusForbidden, "forbidden")
		expectProblem(t, da.call(t, http.MethodGet, pathMasterKey, nil), http.StatusForbidden, "forbidden")
		expectProblem(t, da.startRotation(t, da.acct.wrongCode(t), ""), http.StatusForbidden, "forbidden")
		if st := da.maintenance(t); st.Enabled || st.Source != "none" {
			t.Errorf("getMaintenance of the delegated admin = %+v", st)
		}
		if got := sa.settings(t); !near(got.DiskAlertThreshold, 0.95) {
			t.Errorf("a delegated admin changed the threshold: %+v", got)
		}
		if n := len(a.logLinesOf(t, "admin_login_failed", adminIP(20), "")); n != 0 {
			t.Errorf("%d admin_login_failed lines for the delegated admin, want none (403 before the code)", n)
		}

		events := sa.globalEvents(t, actConfigUpdated)
		slices.Reverse(events)
		want := [][]string{{"diskAlertThreshold", "alertEmail"}, {"alertEmail"}, {"diskAlertThreshold"}, {"diskAlertThreshold"}, {"diskAlertThreshold"}}
		if len(events) != len(want) {
			t.Fatalf("%d %s events, want %d", len(events), actConfigUpdated, len(want))
		}
		for i, ev := range events {
			expectGlobalEvent(t, ev, "admin", superName, adminIP(10), "system", "")
			fields, _ := json.Marshal(ev.Details["fields"])
			wantFields, _ := json.Marshal(want[i])
			if string(fields) != string(wantFields) || len(ev.Details) != 1 {
				t.Errorf("%s #%d details = %v, want fields %s only", actConfigUpdated, i, ev.Details, wantFields)
			}
			expectNoAddressIn(t, ev)
		}
		for _, r := range a.auditRows(t) {
			if strings.Contains(strings.ToLower(r.details+r.objectID), strings.ToLower(alert)) {
				t.Errorf("audit event %s holds the alert address", r.action)
			}
		}
		if strings.Contains(a.appLog.String(), alert) {
			t.Error("the application log holds the alert address")
		}
		a.expectLogsClean(t, nil)
	})
}

// systemSMTPEnv returns the TT_SYSTEM_SMTP_* variables sending the system
// mails to Mailpit, a plain relay without authentication.
func systemSMTPEnv(mp *mailpit) map[string]string {
	return map[string]string{
		config.EnvSystemSMTPHost:     mp.host,
		config.EnvSystemSMTPPort:     strconv.Itoa(mp.port),
		config.EnvSystemSMTPSecurity: "none",
		config.EnvSystemSMTPFrom:     "transteira@example.com",
	}
}

// diskMails returns the disk alert mails to addr.
func diskMails(t *testing.T, mp *mailpit, addr string) []mpMessage {
	t.Helper()
	var out []mpMessage
	for _, m := range mp.messagesTo(t, addr) {
		if strings.HasPrefix(m.Subject, diskSubjectEN) || strings.HasPrefix(m.Subject, diskSubjectFR) {
			out = append(out, m)
		}
	}
	return out
}

// waitDiskMails waits until addr has received n disk alert mails, all
// with the subject prefix of its language, and fails if it got more.
func waitDiskMails(t *testing.T, mp *mailpit, addr, prefix string, n int) {
	t.Helper()
	eventually(t, strconv.Itoa(n)+" disk alert mails to "+addr, func() bool { return len(diskMails(t, mp, addr)) >= n })
	msgs := diskMails(t, mp, addr)
	if len(msgs) != n {
		t.Errorf("%d disk alert mails to %s, want %d", len(msgs), addr, n)
	}
	for _, m := range msgs {
		if !strings.HasPrefix(m.Subject, prefix) {
			t.Errorf("disk alert mail to %s has the subject %q, want the prefix %q (its language)", addr, m.Subject, prefix)
		}
	}
}

// alertClock is the clock of the disk alert monitors of a test, shared by
// its restarts: the real time moved forward by advance, so that the test
// can pass the minimum interval between two alert mails.
type alertClock struct{ offset atomic.Int64 }

// now implements diskalert.Options.Now.
func (c *alertClock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

// advance moves the clock forward by d.
func (c *alertClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// options wraps the disk alert options opts with the clock.
func (c *alertClock) options(opts func(*diskalert.Options)) func(*diskalert.Options) {
	return func(o *diskalert.Options) {
		opts(o)
		o.Now = c.now
	}
}

// notMailedLog is the log line of a crossing within the minimum interval
// between two alert mails.
const notMailedLog = "disk alert not mailed: an alert mail was sent less than an hour ago"

// TestDiskAlert drives the disk alert with a fake measure: one mail per
// super admin and to the alert address, each in its language, at the
// rising crossing only; nothing more after a restart or in the hysteresis
// band; cleared 5 points under the threshold; raised again afterwards but
// mailed only an hour after the last mail (threshold toggling cannot
// flood, T-157); a threshold change re-evaluates at once.
func TestDiskAlert(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		mp := mailpitEnv(t)
		clock := &alertClock{}
		f1 := newDiskFeed()
		a := startAdmin(t, e, serverOptions{env: systemSMTPEnv(mp), diskAlert: clock.options(f1.options(5 * time.Millisecond))}, false)
		t.Cleanup(f1.close) // before the server stops (cleanups run last in, first out)
		var logs []*watchBuffer
		sa := a.bootstrapUnique(t, adminIP(10))
		execSystem(t, e, `UPDATE admins SET language = 'fr' WHERE id = '`+sa.acct.id+`'`)
		second := sa.promoteSuper(t, "second", adminIP(20)) // default language: English
		alert := uniqueEmail(t, "disk-watch", "example.org")
		// Set by the French super admin: the alert address gets French mails.
		sa.mustPatchSettings(t, `{"alertEmail":"`+alert+`"}`)
		recipients := map[string]string{sa.acct.email: diskSubjectFR, second.acct.email: diskSubjectEN, alert: diskSubjectFR}
		count := func(action string) int { return len(sa.globalEvents(t, action)) }

		f1.step(t, 0.80)
		if n := count(actDiskAlertRaised); n != 0 {
			t.Fatalf("%d %s events at 80 %% (threshold 85 %%), want none", n, actDiskAlertRaised)
		}
		f1.step(t, 0.90)
		raised := sa.globalEvents(t, actDiskAlertRaised)
		if len(raised) != 1 {
			t.Fatalf("%d %s events at 90 %%, want 1", len(raised), actDiskAlertRaised)
		}
		expectGlobalEvent(t, raised[0], "system", "disk", "", "system", "disk")
		if detailNumber(raised[0], "usedPercent") != 90 || detailNumber(raised[0], "thresholdPercent") != 85 {
			t.Errorf("%s details = %v, want usedPercent 90 and thresholdPercent 85", actDiskAlertRaised, raised[0].Details)
		}
		for addr, prefix := range recipients {
			waitDiskMails(t, mp, addr, prefix, 1)
		}
		msg := mp.find(t, alert, func(mpMessage) bool { return true })
		if !strings.Contains(msg.Text, "https://"+adminHost+"/admin") || !strings.Contains(msg.Text, "85") {
			t.Errorf("disk alert mail lacks the admin link or the threshold:\n%s", msg.Text)
		}
		if g := sa.globalDisk(t); !g.Disk.AlertActive || !g.Disk.AlertMailConfigured || !near(g.Disk.AlertThreshold, 0.85) {
			t.Errorf("global stats disk = %+v, want an active alert with system mail", g.Disk)
		}

		// A restart while the disk is still full sends nothing again.
		f1.close()
		f2 := newDiskFeed()
		a.relaunch(t, *a.cfg, serverOptions{diskAlert: clock.options(f2.options(5 * time.Millisecond))}, &logs)
		t.Cleanup(f2.close)
		f2.step(t, 0.90)
		if n := count(actDiskAlertRaised); n != 1 {
			t.Errorf("%d %s events after the restart, want still 1", n, actDiskAlertRaised)
		}
		f2.step(t, 0.82) // in the hysteresis band: still raised
		if n := count(actDiskAlertCleared); n != 0 {
			t.Errorf("%d %s events at 82 %%, want none (cleared under 80 %%)", n, actDiskAlertCleared)
		}
		f2.step(t, 0.79)
		cleared := sa.globalEvents(t, actDiskAlertCleared)
		if len(cleared) != 1 {
			t.Fatalf("%d %s events at 79 %%, want 1", len(cleared), actDiskAlertCleared)
		}
		expectGlobalEvent(t, cleared[0], "system", "disk", "", "system", "disk")
		if g := sa.globalDisk(t); g.Disk.AlertActive {
			t.Error("global stats report an active alert after it cleared")
		}
		// Raised again within the hour of the last mail (and after a
		// restart): audited and logged, not mailed.
		f2.step(t, 0.90)
		if n := count(actDiskAlertRaised); n != 2 {
			t.Errorf("%d %s events after the second crossing, want 2", n, actDiskAlertRaised)
		}
		waitLog(t, a.server, notMailedLog)
		for addr, prefix := range recipients {
			waitDiskMails(t, mp, addr, prefix, 1)
		}

		// A threshold change re-evaluates at once: the interval is an hour,
		// so only the Check of the settings change takes the measures. An
		// hour after the first mail, the next crossing is mailed.
		clock.advance(diskalert.MailInterval)
		f2.close()
		f3 := newDiskFeed()
		a.relaunch(t, *a.cfg, serverOptions{diskAlert: clock.options(f3.options(time.Hour))}, &logs)
		t.Cleanup(f3.close)
		f3.send(t, 0.84) // start-up evaluation: still raised (84 % >= 80 %)
		sa.mustPatchSettings(t, `{"diskAlertThreshold":0.95}`)
		f3.send(t, 0.84)
		eventually(t, "alert cleared by the threshold change", func() bool { return count(actDiskAlertCleared) == 2 })
		sa.mustPatchSettings(t, `{"diskAlertThreshold":0.8}`)
		f3.send(t, 0.84)
		eventually(t, "alert raised by the threshold change", func() bool { return count(actDiskAlertRaised) == 3 })
		raised = sa.globalEvents(t, actDiskAlertRaised)
		if detailNumber(raised[0], "usedPercent") != 84 || detailNumber(raised[0], "thresholdPercent") != 80 {
			t.Errorf("%s details = %v, want usedPercent 84 and thresholdPercent 80", actDiskAlertRaised, raised[0].Details)
		}
		for addr, prefix := range recipients {
			waitDiskMails(t, mp, addr, prefix, 2)
		}
		if g := sa.globalDisk(t); !g.Disk.AlertActive || !near(g.Disk.AlertThreshold, 0.8) {
			t.Errorf("global stats disk = %+v, want an active alert at 0.8", g.Disk)
		}

		// Toggling the threshold at once clears and raises the alert again:
		// every crossing is audited, none mailed within the hour.
		sa.mustPatchSettings(t, `{"diskAlertThreshold":0.95}`)
		f3.send(t, 0.84)
		eventually(t, "alert cleared by the toggle", func() bool { return count(actDiskAlertCleared) == 3 })
		sa.mustPatchSettings(t, `{"diskAlertThreshold":0.8}`)
		f3.send(t, 0.84)
		eventually(t, "alert raised by the toggle", func() bool { return count(actDiskAlertRaised) == 4 })
		waitLog(t, a.server, notMailedLog)
		for addr, prefix := range recipients {
			waitDiskMails(t, mp, addr, prefix, 2)
		}
		a.expectLogsClean(t, logs)
	})
}

// TestDiskAlertWithoutSystemSMTP: without TT_SYSTEM_SMTP_HOST the alert is
// audited, logged and shown in the global statistics, never mailed.
func TestDiskAlertWithoutSystemSMTP(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		mp := mailpitEnv(t)
		f := newDiskFeed()
		a := startAdmin(t, e, serverOptions{diskAlert: f.options(5 * time.Millisecond)}, false)
		t.Cleanup(f.close)
		sa := a.bootstrapUnique(t, adminIP(10))
		f.step(t, 0.90)
		if n := len(sa.globalEvents(t, actDiskAlertRaised)); n != 1 {
			t.Fatalf("%d %s events, want 1", n, actDiskAlertRaised)
		}
		select {
		case <-a.appLog.wait("disk alert not mailed: the system SMTP server"):
		case <-time.After(waitTimeout):
			t.Fatalf("no 'disk alert not mailed' log line\napp log:\n%s", a.appLog)
		}
		if g := sa.globalDisk(t); !g.Disk.AlertActive || g.Disk.AlertMailConfigured {
			t.Errorf("global stats disk = %+v, want an active alert without system mail", g.Disk)
		}
		if n := len(mp.messagesTo(t, sa.acct.email)); n != 0 {
			t.Errorf("%d mails to the super admin without system SMTP, want none", n)
		}
	})
}

// TestMasterKeyRotationAdmin runs the master key rotation from the
// administration: refused without a new key before any TOTP attempt;
// TOTP re-confirmation (the login step burnt, wrong codes locking the
// second factor and ending the session as the login does); background
// rotation followed to its end; 409 while running or once completed,
// before the code is checked (the recovery code stays usable); an
// interruption by the
// shutdown resumed with the same identifier; and the files still
// downloadable, with their SHA-256, after restarts on the switched keys.
func TestMasterKeyRotationAdmin(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		k1, k2, k3 := newKeyFile(t, "sysrot-K1"), newKeyFile(t, "sysrot-K2"), newKeyFile(t, "sysrot-K3")
		o, _ := withScanner(t, serverOptions{env: map[string]string{config.EnvMasterKeyFile: k1.path}})
		a := startAdmin(t, e, o, true)
		var logs []*watchBuffer
		sa := a.bootstrapUnique(t, adminIP(10))
		alice, _ := internalSession(t, a.depositEnv, "alice")
		files := []uploadedFile{{name: "report.bin", content: seededBytes(t, 41, 70_000)}, {name: "data.csv", content: seededBytes(t, 42, 3_000)}}
		tr, token := alice.availableTransfer(t, transferCreate{}, files...)
		rcpt := a.newRecipient(1)
		expectDownloads := func(label string) {
			t.Helper()
			page := rcpt.mustPage(t, token)
			for i, f := range files {
				expectFile(t, label+": "+f.name, rcpt.get(t, filePath(token, tr.Files[i].ID), nil), f.name, f.content)
				if i >= len(page.Files) || page.Files[i].Sha256 != sha256Hex(f.content) {
					t.Errorf("%s: page file %d = %+v, want SHA-256 %s", label, i, page.Files, sha256Hex(f.content))
				}
			}
		}
		expectDownloads("before any rotation")
		batch1 := func(ro *keyrotation.Options) { ro.Rotation.BatchSize = 1 }

		// Without TT_MASTER_KEY_NEW_FILE: 409 before the code is checked,
		// so that even more wrong codes than the lock threshold lock
		// nothing.
		if st := sa.masterKeyStatus(t); st.ActiveKeyID != k1.id || st.NewKeyID != nil || st.RestartRequired || st.LatestRotation != nil {
			t.Errorf("status with K1 alone = %+v", st)
		}
		for range adminauth.TOTPAdminMaxFailures + 1 {
			expectProblem(t, sa.startRotation(t, sa.acct.wrongCode(t), ""), http.StatusConflict, "new-master-key-missing")
		}
		if n := len(a.logLinesOf(t, "admin_login_failed", adminIP(10), "")); n != 0 {
			t.Errorf("%d admin_login_failed lines without a new key, want none", n)
		}

		// Restart with the new key K2.
		cfg := *a.cfg
		cfg.MasterKeyNewFile = k2.path
		a.relaunch(t, cfg, serverOptions{rotation: batch1}, &logs)
		if st := sa.masterKeyStatus(t); st.ActiveKeyID != k1.id || st.NewKeyID == nil || *st.NewKeyID != k2.id || st.RestartRequired || st.LatestRotation != nil {
			t.Errorf("status with K1 and K2 = %+v", st)
		}

		// The code of the step used at the enrollment is burnt (T-60).
		burnt := crypto.TOTPCode(sa.acct.secret, sa.acct.lastStep)
		expectProblem(t, sa.startRotation(t, burnt, ""), http.StatusUnauthorized, "invalid-credentials")

		// Wrong codes lock the second factor of the account, shared with
		// the login; the session is not rotated, and is ended at the 5th
		// failure, like a login session (adminauth.MaxSessionTOTPFailures).
		locker := sa.promoteSuper(t, "locker", adminIP(20))
		for i := 1; i < adminauth.TOTPAdminMaxFailures; i++ {
			resp := locker.startRotation(t, locker.acct.wrongCode(t), "")
			expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
			if _, set := sessionCookie(t, resp); set {
				t.Error("a wrong rotation code changed the session cookie")
			}
		}
		expectRateLimited(t, "5th wrong rotation code", locker.startRotation(t, locker.acct.wrongCode(t), ""))
		locker.expectUnauthenticated(t, "session after 5 wrong rotation codes")
		other := a.client(locker.acct, adminIP(21))
		other.mustLogin(t, stateTOTPRequired)
		expectRateLimited(t, "login second factor while locked", other.verify(t, "", locker.acct.recovery[0]))
		a.waitLogLines(t, "admin_login_failed", adminIP(20), `reason="totp"`, adminauth.TOTPAdminMaxFailures)
		if st := sa.masterKeyStatus(t); st.LatestRotation != nil {
			t.Fatalf("a refused start created rotation %+v", st.LatestRotation)
		}

		// A current code of the next step starts the rotation.
		rot1 := sa.mustStartRotation(t, sa.acct.nextCode(t), "")
		if rot1.FromKeyID != k1.id || rot1.ToKeyID != k2.id || rot1.TotalKeys < 3 {
			t.Errorf("rotation = %+v, want K1 to K2 with at least 3 keys (2 files, 2 TOTP secrets)", rot1)
		}
		sa.waitRotation(t, rot1.ID)
		st := sa.masterKeyStatus(t)
		if !st.RestartRequired || st.ActiveKeyID != k1.id || st.LatestRotation == nil || st.LatestRotation.ID != rot1.ID ||
			st.LatestRotation.Status != "completed" {
			t.Errorf("status after the rotation = %+v, want restartRequired with rotation %s completed", st, rot1.ID)
		}
		// Refused before the code is checked: the recovery code is not
		// consumed, and starts the next rotation below.
		expectProblem(t, sa.startRotation(t, "", sa.acct.recovery[0]), http.StatusConflict, "state-conflict")
		expectProblem(t, sa.call(t, http.MethodGet, pathRotations+"/rot_01JABCM8Q9R0S1T2V3V4W5X6Y7", nil), http.StatusNotFound, "not-found")
		expectDownloads("after the rotation, before the restart")

		// Restart on the switched keys (K2 current, K3 new), then a rotation
		// interrupted by the shutdown after its first batch.
		var (
			reached     = make(chan struct{})
			release     = make(chan struct{})
			reachOnce   sync.Once
			releaseOnce sync.Once
		)
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		hook := func(ro *keyrotation.Options) {
			ro.Rotation.BatchSize = 1
			ro.Rotation.OnProgress = func(store.Rotation) {
				first := false
				reachOnce.Do(func() { first = true; close(reached) })
				if first {
					<-release
				}
			}
		}
		cfg.MasterKeyFile, cfg.MasterKeyNewFile = k2.path, k3.path
		a.relaunch(t, cfg, serverOptions{rotation: hook}, &logs)
		t.Cleanup(unblock) // before the server stops
		// The CSRF token derives from the current master key: fetched again.
		sa.refreshCSRF(t)
		expectDownloads("restarted with K2 and K3")
		if st := sa.masterKeyStatus(t); st.ActiveKeyID != k2.id || st.NewKeyID == nil || *st.NewKeyID != k3.id || st.RestartRequired {
			t.Errorf("status with K2 and K3 = %+v", st)
		}
		rot2 := sa.mustStartRotation(t, "", sa.acct.takeRecovery(t))
		if rot2.ID == rot1.ID || rot2.FromKeyID != k2.id || rot2.ToKeyID != k3.id {
			t.Errorf("second rotation = %+v, want a new rotation from K2 to K3", rot2)
		}
		select {
		case <-reached:
		case <-time.After(waitTimeout):
			t.Fatalf("the rotation did not commit a first batch\napp log:\n%s", a.appLog)
		}
		// Refused while running, before the code is checked: the recovery
		// code resumes the rotation below.
		expectProblem(t, sa.startRotation(t, "", sa.acct.recovery[0]), http.StatusConflict, "state-conflict")
		if r := sa.rotation(t, rot2.ID); r.Status != "running" || r.RewrappedKeys < 1 || r.RewrappedKeys >= r.TotalKeys {
			t.Errorf("rotation after its first batch = %+v", r)
		}
		stopped := make(chan error, 1)
		go func() { stopped <- a.stop() }()
		select {
		case <-a.appLog.wait("waiting for the master key rotation to stop before destroying the master keys"):
		case <-time.After(waitTimeout):
			t.Fatalf("the shutdown does not wait for the rotation\napp log:\n%s", a.appLog)
		}
		unblock()
		if err := <-stopped; err != nil {
			t.Fatalf("stop during the rotation: %v\napp log:\n%s", err, a.appLog)
		}
		if !strings.Contains(a.appLog.String(), "master key rotation interrupted by the shutdown") {
			t.Errorf("no interruption log line\napp log:\n%s", a.appLog)
		}

		// The next start between the same keys resumes the same rotation.
		a.relaunch(t, cfg, serverOptions{rotation: batch1}, &logs)
		if !strings.Contains(a.appLog.String(), "an interrupted master key rotation is waiting") {
			t.Errorf("no start-up warning about the interrupted rotation\napp log:\n%s", a.appLog)
		}
		if st := sa.masterKeyStatus(t); st.LatestRotation == nil || st.LatestRotation.ID != rot2.ID || st.LatestRotation.Status != "running" {
			t.Errorf("status after the interruption = %+v, want rotation %s still running", st, rot2.ID)
		}
		resumed := sa.mustStartRotation(t, "", sa.acct.takeRecovery(t))
		if resumed.ID != rot2.ID || resumed.RewrappedKeys < 1 {
			t.Errorf("resumed rotation = %+v, want %s with its progress", resumed, rot2.ID)
		}
		sa.waitRotation(t, rot2.ID)
		if st := sa.masterKeyStatus(t); !st.RestartRequired {
			t.Errorf("status after the resumed rotation = %+v, want restartRequired", st)
		}

		// Restart with K3 alone: the files and the admin second factor still
		// work.
		cfg.MasterKeyFile, cfg.MasterKeyNewFile = k3.path, ""
		a.relaunch(t, cfg, serverOptions{}, &logs)
		sa.refreshCSRF(t)
		expectDownloads("restarted with K3 alone")
		if st := sa.masterKeyStatus(t); st.ActiveKeyID != k3.id || st.NewKeyID != nil || st.RestartRequired ||
			st.LatestRotation == nil || st.LatestRotation.ID != rot2.ID || st.LatestRotation.Status != "completed" {
			t.Errorf("status with K3 alone = %+v", st)
		}
		// Recovery codes derive their MAC key from the TOTP secret, which
		// was re-wrapped twice.
		a.client(sa.acct, adminIP(11)).signInRecovery(t)

		// Global audit: who started, what completed, no failure.
		started := sa.globalEvents(t, actRotationStarted)
		if len(started) != 3 {
			t.Fatalf("%d %s events, want 3 (K1 to K2, K2 to K3, resumed)", len(started), actRotationStarted)
		}
		for i, id := range []string{rot2.ID, rot2.ID, rot1.ID} {
			expectGlobalEvent(t, started[i], "admin", superName, adminIP(10), "master_key_rotation", id)
		}
		if started[0].Details["resumed"] != true || started[1].Details["resumed"] != false || started[2].Details["from"] != k1.id ||
			started[2].Details["to"] != k2.id {
			t.Errorf("%s details = %v / %v / %v", actRotationStarted, started[0].Details, started[1].Details, started[2].Details)
		}
		completed := sa.globalEvents(t, actRotationCompleted)
		if len(completed) != 2 {
			t.Fatalf("%d %s events, want 2", len(completed), actRotationCompleted)
		}
		for i, id := range []string{rot2.ID, rot1.ID} {
			expectGlobalEvent(t, completed[i], "system", keyrotation.SystemActor, "", "master_key_rotation", id)
		}
		if n := len(sa.globalEvents(t, actRotationFailed)); n != 0 {
			t.Errorf("%d %s events, want none (an interruption is not a failure)", n, actRotationFailed)
		}
		a.expectLogsClean(t, logs, k1, k2, k3)
	})
}
