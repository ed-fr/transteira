package abuse

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// subject is who and what an alert is about.
type subject struct {
	sender     string
	ip         netip.Addr
	transferID string
}

// subjectOf returns the subject of the facts f.
func subjectOf(f Facts) subject {
	return subject{sender: f.SenderEmail, ip: f.ClientIP, transferID: f.TransferID}
}

// at returns the time of f, the clock when zero.
func (d *Detector) at(f Facts) time.Time {
	if f.At.IsZero() {
		return d.now()
	}
	return f.At
}

// CheckCreateTx runs inside the transaction creating the transfer f of
// tenant t (tenant lock held). When the tenant blocks on exceed, it counts
// the activity of the sender for the local day of f.At through
// store.Transfers.SenderActivityTx, plus f itself (not stored yet), and
// returns the first blocking rule exceeded, in the order daily_bytes,
// daily_transfers, recipients (internal senders), external_quota (external
// senders). It returns nil when the creation may proceed, and never writes.
// After an error, the caller must abort the transaction.
func (d *Detector) CheckCreateTx(ctx context.Context, tx *store.ScopedTx, _ *tenant.Tenant, f Facts) (*Block, error) {
	s, err := d.repo.settingsTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !s.BlockOnExceed {
		return nil, nil //nolint:nilnil // no block: the creation proceeds
	}
	start, end, _ := dayWindow(d.at(f), location(s.TimeZone))
	internal := isInternal(f.Kind)
	var fs []finding
	if internal && (s.MaxDailyBytesPerSender != nil || s.MaxDailyTransfersPerSender != nil) {
		b, c, err := d.repo.activityTx(ctx, tx, f.SenderEmail, start, end, internalKinds)
		if err != nil {
			return nil, err
		}
		fs = append(fs, dailyFindings(s, usage{bytes: b + f.Bytes, count: c + 1})...)
	}
	if internal {
		fs = append(fs, recipientsFinding(s, len(f.Recipients))...)
	}
	if isExternal(f.Kind) && (s.ExternalMaxDailyBytes != nil || s.ExternalMaxDailyDeposits != nil) {
		b, c, err := d.repo.activityTx(ctx, tx, f.SenderEmail, start, end, externalKinds)
		if err != nil {
			return nil, err
		}
		fs = append(fs, externalFindings(s, f.Kind, usage{bytes: b + f.Bytes, count: c + 1})...)
	}
	if len(fs) == 0 {
		return nil, nil //nolint:nilnil // no block: the creation proceeds
	}
	x := fs[0]
	return &Block{Rule: x.rule, Value: x.value, Threshold: x.threshold, bytes: x.bytes}, nil
}

// Blocked records the creation of f refused with b by
// [Detector.CheckCreateTx], after the rollback. The first refusal of the
// local day for the sender and the rule writes the audit event (details
// blocked true), publishes the event and mails the administrators; the
// later ones only count in the deduplication row (no audit event, mail or
// event), so that a sender retrying cannot flood the audit log. It is best
// effort: failures are logged, and the context cancellation is ignored.
func (d *Detector) Blocked(ctx context.Context, t *tenant.Tenant, f Facts, b Block) {
	ctx = context.WithoutCancel(ctx)
	s := d.settingsOrDefault(ctx, t.ID)
	_, _, day := dayWindow(d.at(f), location(s.TimeZone))
	d.raise(ctx, t, subjectOf(f), finding{rule: b.Rule, value: b.Value, threshold: b.Threshold, bytes: b.bytes}, true, day)
}

// AfterCreate evaluates every rule for the transfer f of tenant t, already
// committed (so counted by the store), and alerts for each exceeded rule.
// It is best effort: failures are logged, the rules that could be
// evaluated still alert, and the context cancellation is ignored.
func (d *Detector) AfterCreate(ctx context.Context, t *tenant.Tenant, f Facts) {
	ctx = context.WithoutCancel(ctx)
	s, err := d.repo.settings(ctx, t.ID)
	if err != nil {
		d.fail(ctx, t.ID, "read the abuse settings", err)
		return
	}
	loc := location(s.TimeZone)
	at := d.at(f)
	start, end, day := dayWindow(at, loc)
	internal := isInternal(f.Kind)
	var fs []finding
	if internal && (s.MaxDailyBytesPerSender != nil || s.MaxDailyTransfersPerSender != nil || s.UnusualVolumePct != nil) {
		b, c, err := d.repo.activity(ctx, t.ID, f.SenderEmail, start, end, internalKinds)
		if err != nil {
			d.fail(ctx, t.ID, "sum the sender activity", err)
		} else {
			fs = append(fs, dailyFindings(s, usage{bytes: b, count: c})...)
			fs = append(fs, d.unusual(ctx, t.ID, s, f, b, start, loc)...)
		}
	}
	if internal {
		fs = append(fs, recipientsFinding(s, len(f.Recipients))...)
	}
	if isExternal(f.Kind) && (s.ExternalMaxDailyBytes != nil || s.ExternalMaxDailyDeposits != nil) {
		b, c, err := d.repo.activity(ctx, t.ID, f.SenderEmail, start, end, externalKinds)
		if err != nil {
			d.fail(ctx, t.ID, "sum the external activity", err)
		} else {
			fs = append(fs, externalFindings(s, f.Kind, usage{bytes: b, count: c})...)
		}
	}
	if internal && s.LargeExternalTransferBytes != nil && f.Bytes >= *s.LargeExternalTransferBytes {
		domains, err := d.repo.internalDomains(ctx, t.ID)
		if err != nil {
			d.fail(ctx, t.ID, "read the internal domains", err)
		} else {
			fs = append(fs, largeExternalFinding(s, f.Bytes, f.Recipients, domains)...)
		}
	}
	if internal {
		fs = append(fs, offHoursFinding(s, at, loc)...)
	}
	for _, x := range fs {
		d.raise(ctx, t, subjectOf(f), x, false, day)
	}
}

// unusual evaluates the unusual volume rule for the internal sender of f,
// whose volume of the day starting at dayStart is today.
func (d *Detector) unusual(ctx context.Context, tid tenant.ID, s store.AbuseSettings, f Facts, today int64,
	dayStart time.Time, loc *time.Location,
) []finding {
	if !isInternal(f.Kind) || s.UnusualVolumePct == nil || today <= 0 {
		return nil
	}
	history, err := d.repo.history(ctx, tid, f.SenderEmail, historyStart(dayStart, loc))
	if err != nil {
		d.fail(ctx, tid, "list the sender history", err)
		return nil
	}
	return unusualFinding(s, today, history, dayStart, loc)
}

// AfterExtend evaluates the per-sender daily rules after the extension f
// of a transfer of tenant t (f.At: the extension time), which counts the
// transfer in the activity of that day (T-210). Like those rules, it
// applies to internal senders only. It alerts, never blocks, and is best
// effort like [Detector.AfterCreate].
func (d *Detector) AfterExtend(ctx context.Context, t *tenant.Tenant, f Facts) {
	ctx = context.WithoutCancel(ctx)
	s, err := d.repo.settings(ctx, t.ID)
	if err != nil {
		d.fail(ctx, t.ID, "read the abuse settings", err)
		return
	}
	if !isInternal(f.Kind) || (s.MaxDailyBytesPerSender == nil && s.MaxDailyTransfersPerSender == nil) {
		return
	}
	start, end, day := dayWindow(d.at(f), location(s.TimeZone))
	b, c, err := d.repo.activity(ctx, t.ID, f.SenderEmail, start, end, internalKinds)
	if err != nil {
		d.fail(ctx, t.ID, "sum the sender activity", err)
		return
	}
	for _, x := range dailyFindings(s, usage{bytes: b, count: c}) {
		d.raise(ctx, t, subjectOf(f), x, false, day)
	}
}

// InvitationLimit returns the invitations an internal user of tenant tid
// may issue per rolling hour (maxInvitationsPerInviter). It returns the
// error of the store, never a default.
func (d *Detector) InvitationLimit(ctx context.Context, tid tenant.ID) (int, error) {
	s, err := d.repo.settings(ctx, tid)
	if err != nil {
		return 0, err
	}
	return s.MaxInvitationsPerInviter, nil
}

// InvitationLimitReached alerts that inviter, an internal user of tenant
// t, reached the invitation limit limit (rule invitations, deduplicated
// per local day). It is best effort.
func (d *Detector) InvitationLimitReached(ctx context.Context, t *tenant.Tenant, inviter string, limit int) {
	ctx = context.WithoutCancel(ctx)
	s := d.settingsOrDefault(ctx, t.ID)
	_, _, day := dayWindow(d.now(), location(s.TimeZone))
	x := finding{rule: store.AbuseRuleInvitations, value: float64(limit), threshold: float64(limit)}
	d.raise(ctx, t, subject{sender: inviter}, x, false, day)
}

// Reported alerts the administrators of tenant t of the new abuse report
// r: event abuse.reported and mail abuse_report, without deduplication
// (the reports are rate limited when filed). The caller records the audit
// event. It is best effort.
func (d *Detector) Reported(ctx context.Context, t *tenant.Tenant, r store.AbuseReport) {
	ctx = context.WithoutCancel(ctx)
	path := events.AdminPathTenantAbuseReports(string(t.ID))
	addrs := &events.Addresses{Sender: r.SenderEmail}
	data := mail.AbuseReportData{
		TenantName: t.Name, TransferID: r.TransferID, SenderEmail: r.SenderEmail, Category: string(r.Category),
		Message: r.Message, AdminLink: d.adminBase + path,
	}
	if r.ReporterVerified {
		addrs.Reporter, data.ReporterEmail = r.ReporterEmail, r.ReporterEmail
	}
	if r.RecipientPosition != nil {
		data.RecipientIndex = *r.RecipientPosition + 1
	}
	d.events.Publish(events.Event{
		Type: events.AbuseReported, Severity: events.SeverityWarning, OccurredAt: d.now(), TenantID: string(t.ID),
		Addresses: addrs, AdminPath: path,
	})
	d.notify(ctx, t, "abuse report", func(cs []notify.Contact) ([]mail.Job, error) {
		return d.notifier.AbuseReport(ctx, t, data, cs)
	}, slog.String("abuse_report", r.ID))
}

// settingsOrDefault returns the settings of tenant tid, the defaults (UTC)
// after a logged failure.
func (d *Detector) settingsOrDefault(ctx context.Context, tid tenant.ID) store.AbuseSettings {
	s, err := d.repo.settings(ctx, tid)
	if err != nil {
		d.fail(ctx, tid, "read the abuse settings", err)
		return store.DefaultAbuseSettings()
	}
	return s
}

// raise records the exceeded rule x of tenant t about sub. An alert-only
// finding (blocked false) is written to the audit log every time (each one
// is a real transfer); a refusal (blocked true) only the first time of the
// day, the later ones being counted by the deduplication row. Then, the
// first time for the sender, rule, local day day and kind, it publishes the
// event and mails the administrators.
func (d *Detector) raise(ctx context.Context, t *tenant.Tenant, sub subject, x finding, blocked bool, day string) {
	if !blocked {
		d.audit(ctx, t, sub, x, false)
	}
	first, err := d.repo.tryAlert(ctx, t.ID, sub.sender, x.rule, day, blocked, d.now())
	if err != nil {
		d.fail(ctx, t.ID, "record the alert", err)
		if blocked {
			// Without the deduplication row, the refusal is still audited.
			d.audit(ctx, t, sub, x, true)
		}
		return
	}
	if !first {
		return
	}
	if blocked {
		d.audit(ctx, t, sub, x, true)
	}
	typ := events.AbuseThresholdExceeded
	if x.unusual() {
		typ = events.AbuseUnusualActivity
	}
	path := events.AdminPathTenantAudit(string(t.ID))
	d.events.Publish(events.Event{
		Type: typ, Severity: events.SeverityWarning, OccurredAt: d.now(), TenantID: string(t.ID),
		Counts:    map[string]float64{"value": x.value, "threshold": x.threshold},
		Addresses: &events.Addresses{Sender: sub.sender}, AdminPath: path,
	})
	data := mail.AbuseAlertData{
		TenantName: t.Name, Rule: string(x.rule), SenderEmail: sub.sender, Value: x.value, Threshold: x.threshold,
		Bytes: x.bytes, Blocked: blocked, Day: day, At: x.at, AdminLink: d.adminBase + path,
	}
	d.notify(ctx, t, "abuse alert", func(cs []notify.Contact) ([]mail.Job, error) {
		return d.notifier.AbuseAlert(ctx, t, data, cs)
	}, slog.String("abuse_rule", string(x.rule)))
}

// audit records the exceeded rule x of tenant t about sub in the audit
// log: abuse.threshold_exceeded, or abuse.unusual_activity for the
// alert-only behavior rules; details.blocked tells a refusal.
func (d *Detector) audit(ctx context.Context, t *tenant.Tenant, sub subject, x finding, blocked bool) {
	action := audit.ActionAbuseThresholdExceeded
	if x.unusual() {
		action = audit.ActionAbuseUnusualActivity
	}
	details := map[string]any{"rule": string(x.rule), "value": x.value, "threshold": x.threshold, "blocked": blocked}
	objKind, objID := audit.ObjectTenant, string(t.ID)
	if sub.transferID != "" {
		objKind, objID = audit.ObjectTransfer, sub.transferID
		details["transferId"] = sub.transferID
	}
	ev := audit.Event{
		TenantID: t.ID, ActorKind: store.ActorDepositor, Actor: sub.sender, IP: sub.ip, Action: action,
		ObjectKind: objKind, ObjectID: objID, Details: details,
	}
	if err := d.auditor.RecordScoped(ctx, t.ID, ev); err != nil {
		d.fail(ctx, t.ID, "record the audit event", err)
	}
}

// notify mails the administrators of tenant t the mails build returns.
func (d *Detector) notify(ctx context.Context, t *tenant.Tenant, what string,
	build func([]notify.Contact) ([]mail.Job, error), attr slog.Attr,
) {
	contacts, err := d.contacts(ctx, t.ID)
	if err != nil {
		d.fail(ctx, t.ID, "list the administrators to notify", err)
		return
	}
	if len(contacts) == 0 {
		d.logger.WarnContext(ctx, "abuse: no administrator to notify", slog.String("tenant", string(t.ID)), attr)
		return
	}
	jobs, err := build(contacts)
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		d.logger.ErrorContext(ctx, "abuse: no "+what+" sent: the tenant has no SMTP settings, an administrator must configure them",
			slog.String("tenant", string(t.ID)), attr)
		return
	case err != nil:
		d.fail(ctx, t.ID, "build the "+what+" mails", err)
		return
	}
	d.mailer.Send(ctx, jobs, slog.String("tenant", string(t.ID)), attr)
}

// contacts returns the administrators to notify for tenant tid: its
// delegated admins, else the super admins.
func (d *Detector) contacts(ctx context.Context, tid tenant.ID) ([]notify.Contact, error) {
	cs, err := d.repo.tenantContacts(ctx, tid)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		if cs, err = d.repo.superAdminContacts(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]notify.Contact, len(cs))
	for i, c := range cs {
		out[i] = notify.Contact{Email: c.Email, Language: c.Language}
	}
	return out, nil
}

// fail logs a failure about tenant tid.
func (d *Detector) fail(ctx context.Context, tid tenant.ID, what string, err error) {
	d.logger.ErrorContext(ctx, "abuse: failed to "+what, slog.String("tenant", string(tid)),
		slog.String("error", err.Error()))
}
