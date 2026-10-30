package scan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// errOpen reports a failure to open the content of a file that says
// nothing about the content itself (key vault, transient storage error): it
// is retried without counting an attempt.
var errOpen = errors.New("scan: cannot open the content to scan")

// errVerdict reports a scan result without a known verdict, counted like a
// protocol error.
var errVerdict = errors.New("scan: unknown verdict")

// fileOutcome is what happened to one file.
type fileOutcome int

const (
	// fileDone means the final status of the file was recorded, or could
	// not be and will be looked at again by the conclusion.
	fileDone fileOutcome = iota
	// fileRetry means the transfer must be retried later.
	fileRetry
	// fileStop means the worker is shutting down: the file is left as it
	// is.
	fileStop
)

// process analyzes the files of the transfer k that have no final status
// yet, then concludes the transfer. It returns the retry delay of the
// transfer, or 0 when it is done with it (concluded, no longer scanning, or
// shutdown).
func (w *Worker) process(ctx context.Context, k key) time.Duration {
	d, err := w.repo.transfer(ctx, k.tid, k.id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Deleted, or not a transfer of this tenant: nothing to analyze.
		w.log(ctx, slog.LevelWarn, "transfer to analyze not found", k)
		return 0
	case err != nil:
		return w.failed(ctx, k, "load transfer", err)
	}
	if d.Status != store.TransferScanning {
		w.log(ctx, slog.LevelDebug, "transfer no longer scanning", k, slog.String("status", string(d.Status)))
		return 0
	}
	for _, f := range d.Files {
		if final(f.ScanStatus) {
			continue
		}
		switch outcome, retry := w.scanFile(ctx, k, f, d.SenderEmail); outcome {
		case fileRetry:
			return retry
		case fileStop:
			return 0
		}
	}
	// The conclusion is short and idempotent: it is not interrupted by a
	// shutdown. A hold stops it before its commit and before its mails.
	return w.conclude(context.WithoutCancel(ctx), k)
}

// final reports whether s is a final scan status.
func final(s store.ScanStatus) bool {
	return s.Deliverable() || s == store.ScanInfected || s == store.ScanError
}

// failed handles a failure that is neither a clamd outage nor specific to
// the content of a file (database, key vault, storage, removal): it is
// logged and the transfer is retried with backoff, without counting an
// attempt, unless the worker is shutting down.
func (w *Worker) failed(ctx context.Context, k key, op string, err error) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	retry := w.retryTransfer(k)
	w.log(ctx, slog.LevelError, "antivirus processing failed, will retry", k,
		slog.String("op", op), slog.Duration("retry_in", retry), slog.Any("error", err))
	return retry
}

// scanFile analyzes the file f of the transfer k, sent by sender, and
// records its final status. When the instance antivirus is disabled
// (Options.Disabled), no engine is contacted: the file is recorded
// not_scanned_disabled at once.
func (w *Worker) scanFile(ctx context.Context, k key, f store.TransferFile, sender string) (fileOutcome, time.Duration) {
	if w.opts.Disabled {
		return w.record(context.WithoutCancel(ctx), k, f, store.ScanNotScannedDisabled, "", "")
	}
	if err := w.repo.setScanning(ctx, k.tid, f.ID); err != nil {
		return w.dbFailure(ctx, k, "set file scanning", err)
	}
	res, err := w.scanContent(ctx, k.tid, f)
	if ctx.Err() != nil {
		// Shutdown: the file stays scanning, no attempt is counted.
		return fileStop, 0
	}
	// The result is recorded even if a shutdown starts meanwhile.
	wctx := context.WithoutCancel(ctx)
	if err == nil {
		status, signature, verr := w.verdict(ctx, res)
		if verr == nil {
			return w.record(wctx, k, f, status, signature, sender)
		}
		err = verr
	}
	switch {
	case errors.Is(err, errOpen):
		return w.dbFailure(ctx, k, "open file", err)
	case errors.Is(err, antivirus.ErrUnavailable) && !errors.Is(err, antivirus.ErrConnectionLost):
		return fileRetry, w.clamdDown(ctx)
	case errors.Is(err, antivirus.ErrConnectionLost):
		// clamd dropped the connection on this content. It always counts
		// against the file, so that a content crashing clamd reaches
		// scan_error instead of stalling every analysis; a real clamd
		// restart costs the file in flight one attempt. The ping only
		// chooses the delay: the shared outage backoff when clamd does not
		// answer (the outage warning then names the file), the transfer's
		// own backoff otherwise.
		retry := func() time.Duration { return w.retryTransfer(k) }
		if perr := w.scanner.Ping(ctx); perr != nil {
			retry = func() time.Duration {
				return w.clamdDown(ctx, slog.String("tenant", k.tid.String()), slog.String("transfer", k.id),
					slog.String("file", f.ID))
			}
		} else {
			w.clamdUp(ctx)
		}
		return w.fileError(wctx, k, f, err, retry)
	}
	return w.fileError(wctx, k, f, err, func() time.Duration { return w.retryTransfer(k) })
}

// verdict maps a scan result to the status of the file. A result without a
// known verdict is an error, counted like a protocol error.
func (w *Worker) verdict(ctx context.Context, res antivirus.Result) (store.ScanStatus, string, error) {
	switch res.Verdict {
	case antivirus.Clean:
		w.clamdUp(ctx)
		return store.ScanClean, "", nil
	case antivirus.Infected:
		w.clamdUp(ctx)
		return store.ScanInfected, res.Signature, nil
	case antivirus.Unscannable:
		w.clamdUp(ctx)
		return store.ScanNotScannedEncrypted, "", nil
	case antivirus.TooLarge:
		switch res.Detail {
		case antivirus.DetailClientLimit:
			// Decided without contacting clamd.
		case antivirus.DetailStreamLimit:
			w.clamdUp(ctx)
			w.streamLimitHit(ctx)
		default:
			w.clamdUp(ctx)
		}
		return store.ScanNotScannedTooLarge, "", nil
	}
	return "", "", fmt.Errorf("%w %v", errVerdict, res.Verdict)
}

// streamLimitHit logs, once per worker, that clamd refused a stream below
// the client limit: StreamMaxLength (and MaxScanSize, MaxFileSize) should be
// aligned on TT_CLAMAV_MAX_SCAN_BYTES, otherwise files are delivered without
// analysis that could have been analyzed.
func (w *Worker) streamLimitHit(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.streamLimitWarned {
		return
	}
	w.streamLimitWarned = true
	w.logger.LogAttrs(ctx, slog.LevelWarn,
		"clamd refused a file below TT_CLAMAV_MAX_SCAN_BYTES: align StreamMaxLength, MaxScanSize and MaxFileSize on it")
}

// fileError counts a failure specific to the content of the file f; at
// Options.MaxFileErrors the file gets scan_error, otherwise the transfer is
// retried after the delay retry returns.
func (w *Worker) fileError(ctx context.Context, k key, f store.TransferFile, err error, retry func() time.Duration) (fileOutcome, time.Duration) {
	n, cerr := w.repo.countAttempt(ctx, k.tid, f.ID)
	if cerr != nil {
		return w.dbFailure(ctx, k, "count scan attempt", cerr)
	}
	w.log(ctx, slog.LevelWarn, "file analysis failed", k,
		slog.String("file", f.ID), slog.Int("attempt", n), slog.Int("max_attempts", w.opts.MaxFileErrors),
		slog.Any("error", err))
	if n < w.opts.MaxFileErrors {
		return fileRetry, retry()
	}
	return w.record(ctx, k, f, store.ScanError, "", "")
}

// record writes the final status of the file f, sent by sender ("" when
// the status is not infected). A signature the store
// refuses is dropped rather than losing the verdict. Any other refusal of a
// malformed or conflicting result is not retried: it is logged and the
// conclusion, which reloads the transfer, decides.
func (w *Worker) record(ctx context.Context, k key, f store.TransferFile, status store.ScanStatus, signature, sender string) (fileOutcome, time.Duration) {
	err := w.repo.setResult(ctx, k.tid, f.ID, status, signature, w.now())
	if errors.Is(err, store.ErrInvalid) && signature != "" {
		w.log(ctx, slog.LevelWarn, "signature refused by the store, recorded without it", k, slog.String("file", f.ID))
		err = w.repo.setResult(ctx, k.tid, f.ID, status, "", w.now())
	}
	switch {
	case errors.Is(err, store.ErrInvalid), errors.Is(err, store.ErrConflict):
		return w.refused(ctx, k, f, status, err)
	case err != nil:
		return w.dbFailure(ctx, k, "record scan result", err)
	}
	w.forgetRefusals(f.ID)
	w.log(ctx, slog.LevelInfo, "file analyzed", k, slog.String("file", f.ID), slog.String("status", string(status)))
	w.recorded(ctx, k, f, status, signature, sender)
	return fileDone, 0
}

// notScannedReasons are the reasons of file.not_scanned, by status.
var notScannedReasons = map[store.ScanStatus]string{
	store.ScanNotScannedTooLarge:  audit.NotScannedTooLarge,
	store.ScanNotScannedEncrypted: audit.NotScannedEncrypted,
	store.ScanNotScannedDisabled:  audit.NotScannedDisabled,
}

// recorded follows the final status of the file f once committed: an
// infected file counts a virus detection, records file.infected and
// publishes virus.detected (with the address of sender; one event per
// infected file, counts files = 1), a file accepted without analysis
// records file.not_scanned.
func (w *Worker) recorded(ctx context.Context, k key, f store.TransferFile, status store.ScanStatus, signature, sender string) {
	ev := audit.Event{
		ActorKind: store.ActorSystem, Actor: SystemActor, ObjectKind: audit.ObjectFile, ObjectID: f.ID,
		Details: map[string]any{"transferId": k.id},
	}
	switch reason, ok := notScannedReasons[status]; {
	case status == store.ScanInfected:
		if w.usage != nil {
			w.usage.VirusDetected(k.tid, w.now())
		}
		ev.Action = audit.ActionFileInfected
		if signature != "" {
			ev.Details["signature"] = signature
		}
		w.events.Publish(events.Event{
			Type: events.VirusDetected, Severity: events.SeverityCritical, OccurredAt: w.now(),
			TenantID: string(k.tid), Counts: map[string]float64{"files": 1},
			Addresses: &events.Addresses{Sender: sender}, AdminPath: events.AdminPathTenantAudit(string(k.tid)),
		})
	case ok:
		ev.Action = audit.ActionFileNotScanned
		ev.Details["reason"] = reason
	default:
		return
	}
	w.recordAudit(ctx, k, ev)
}

// recordAudit records ev for the transfer k, best effort: a failure is
// logged. A signature name the audit refuses as personal data (an at sign)
// is dropped rather than losing the event.
func (w *Worker) recordAudit(ctx context.Context, k key, ev audit.Event) {
	if w.audit == nil {
		return
	}
	err := w.audit.RecordScoped(ctx, k.tid, ev)
	if errors.Is(err, audit.ErrPersonalDetail) {
		delete(ev.Details, "signature")
		err = w.audit.RecordScoped(ctx, k.tid, ev)
	}
	if err != nil {
		w.log(ctx, slog.LevelError, "audit write failed", k, slog.String("action", string(ev.Action)),
			slog.String("file", ev.ObjectID), slog.Any("error", err))
	}
}

// maxRefusals is the number of passes on which the store may refuse the
// result of a file before the worker withholds it.
const maxRefusals = 2

// refused handles a result the store refused as malformed or conflicting.
// The first refusal is logged and left to the conclusion, which reloads the
// transfer (a file that is in fact final is concluded normally, and one
// that is not is retried). When the file is refused again on a later pass,
// it is withheld under fail-closed: scan_error is recorded instead, the
// safest status, never delivered. If even that is refused, the transfer is
// released with an error line and left scanning, so never delivered; the
// start-up sweep tries it again.
func (w *Worker) refused(ctx context.Context, k key, f store.TransferFile, status store.ScanStatus, err error) (fileOutcome, time.Duration) {
	w.log(ctx, slog.LevelError, "scan result not recorded", k,
		slog.String("file", f.ID), slog.String("status", string(status)), slog.Any("error", err))
	if w.countRefusal(f.ID) < maxRefusals {
		return fileDone, 0
	}
	w.forgetRefusals(f.ID)
	if status != store.ScanError {
		if serr := w.repo.setResult(ctx, k.tid, f.ID, store.ScanError, "", w.now()); serr == nil {
			w.log(ctx, slog.LevelWarn, "file withheld: the store kept refusing its scan result", k, slog.String("file", f.ID))
			return fileDone, 0
		}
	}
	w.log(ctx, slog.LevelError, "transfer left scanning: the store keeps refusing a scan result", k, slog.String("file", f.ID))
	return fileStop, 0
}

// countRefusal counts a refusal of the result of the file fileID and
// returns the count.
func (w *Worker) countRefusal(fileID string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refusals[fileID]++
	return w.refusals[fileID]
}

// forgetRefusals drops the refusal count of the file fileID.
func (w *Worker) forgetRefusals(fileID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.refusals, fileID)
}

// dbFailure maps a failure of a file step to its outcome.
func (w *Worker) dbFailure(ctx context.Context, k key, op string, err error) (fileOutcome, time.Duration) {
	if retry := w.failed(ctx, k, op, err); retry > 0 {
		return fileRetry, retry
	}
	return fileStop, 0
}

// scanContent streams the plaintext of the stored file f to the scanner:
// the ciphertext is read from disk and decrypted on the fly, never
// buffered (T-44). A missing stored file or an unreadable header is
// specific to the content (antivirus.ErrSource, like a decryption failure
// during the stream); a key vault or other storage failure is transient
// (errOpen).
func (w *Worker) scanContent(ctx context.Context, tid tenant.ID, f store.TransferFile) (antivirus.Result, error) {
	dek, err := w.vault.Open(ctx, tid, crypto.PurposeDEK, f.DEKKeyID)
	if err != nil {
		return antivirus.Result{}, fmt.Errorf("%w: data key: %w", errOpen, err)
	}
	defer clear(dek)
	file, _, err := w.files.OpenRead(tid, f.StorageName)
	switch {
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return antivirus.Result{}, fmt.Errorf("%w: stored file: %w", antivirus.ErrSource, err)
	case err != nil:
		return antivirus.Result{}, fmt.Errorf("%w: stored file: %w", errOpen, err)
	}
	defer func() { _ = file.Close() }()
	r, err := crypto.NewReader(file, dek, tid.String(), f.ID)
	if err != nil {
		return antivirus.Result{}, fmt.Errorf("%w: header: %w", antivirus.ErrSource, err)
	}
	return w.scanner.Scan(ctx, r, f.Size)
}

// conclude ends the analysis of the transfer k: it erases the infected
// files, then makes the transfer available with its download link and sends
// the mails, or rejects it when no file can be delivered. It skips a
// transfer that is no longer scanning and retries one with a file not final
// yet. Every step can be replayed after a failure.
func (w *Worker) conclude(ctx context.Context, k key) time.Duration {
	t, err := w.repo.tenant(ctx, k.tid)
	if err != nil {
		return w.failed(ctx, k, "load tenant", err)
	}
	d, err := w.repo.transfer(ctx, k.tid, k.id)
	if err != nil {
		return w.failed(ctx, k, "load transfer", err)
	}
	if d.Status != store.TransferScanning {
		w.log(ctx, slog.LevelDebug, "transfer no longer scanning", k, slog.String("status", string(d.Status)))
		return 0
	}
	var erase []store.TransferFile
	deliverable, infected, withheld := 0, 0, 0
	for _, f := range d.Files {
		switch {
		case f.ScanStatus.Deliverable():
			deliverable++
		case f.ScanStatus == store.ScanInfected:
			infected++
			// A key already destroyed means a previous pass erased the
			// file; an orphan left on disk by a failed removal is
			// unreadable and reconciled by the cleanup task.
			if f.DEKKeyID != "" {
				erase = append(erase, f)
			}
		case f.ScanStatus == store.ScanError:
			withheld++
		default:
			retry := w.retryTransfer(k)
			w.log(ctx, slog.LevelWarn, "file not analyzed yet, will retry", k,
				slog.String("file", f.ID), slog.Duration("retry_in", retry))
			return retry
		}
	}
	if len(erase) > 0 {
		if err := w.remover.RemoveFiles(ctx, k.tid, erase); err != nil {
			return w.failed(ctx, k, "erase infected files", err)
		}
		w.log(ctx, slog.LevelInfo, "infected files erased", k, slog.Int("count", len(erase)))
	}
	if w.held(k) {
		// Being erased or edited: neither available nor rejected; the
		// last release queues it again when it is still scanning.
		w.log(ctx, slog.LevelInfo, "transfer held: analysis stopped before its conclusion", k)
		return 0
	}
	if deliverable == 0 {
		if err := w.repo.reject(ctx, k.tid, k.id); err != nil {
			return w.failed(ctx, k, "reject transfer", err)
		}
		w.log(ctx, slog.LevelWarn, "transfer rejected: no deliverable file", k,
			slog.Int("infected", infected), slog.Int("scan_error", withheld))
		w.notifyRejected(ctx, k, t, d)
		return 0
	}
	// A shared transfer (created before 1.1) gets one token for every
	// recipient; a transfer with one link per recipient gets one token per
	// recipient (P27), each mailed to its recipient only.
	perRecipient := d.LinkMode == store.LinkModePerRecipient
	n := 1
	if perRecipient {
		n = len(d.Recipients)
	}
	tokens := make([]string, n)
	for i := range tokens {
		var err error
		if tokens[i], err = w.newToken(); err != nil {
			return w.failed(ctx, k, "generate download token", err)
		}
	}
	now := w.now()
	links, err := w.repo.makeAvailable(ctx, k.tid, k.id, perRecipient, tokens, now)
	if err != nil {
		return w.failed(ctx, k, "make transfer available", err)
	}
	w.log(ctx, slog.LevelInfo, "transfer available", k, slog.Int("files", deliverable),
		slog.Int("infected", infected), slog.Int("scan_error", withheld))
	// The mails show the expiry the store just set, counted from now.
	d.ExpiresAt = now.Add(time.Duration(d.ExpiryDays) * 24 * time.Hour)
	if perRecipient {
		w.notifyAvailable(ctx, k, t, d, "", recipientLinks(t, links, tokens))
	} else {
		w.notifyAvailable(ctx, k, t, d, id.DownloadURL(t.FQDN, tokens[0]), nil)
	}
	return 0
}

// recipientLinks pairs the links just created with their raw tokens (by
// the SHA-256 of the token) and returns the download URL of each
// recipient, built from the registered FQDN of tenant t, in position order.
func recipientLinks(t *tenant.Tenant, links []store.RecipientLink, tokens []string) []notify.RecipientLink {
	byHash := make(map[[sha256.Size]byte]string, len(tokens))
	for _, tok := range tokens {
		byHash[sha256.Sum256([]byte(tok))] = tok
	}
	out := make([]notify.RecipientLink, 0, len(links))
	for _, l := range links {
		var h [sha256.Size]byte
		if copy(h[:], l.TokenHash) != sha256.Size {
			continue
		}
		if tok, ok := byHash[h]; ok {
			out = append(out, notify.RecipientLink{Email: l.Email, Link: id.DownloadURL(t.FQDN, tok)})
		}
	}
	return out
}

// held reports whether k is held.
func (w *Worker) held(k key) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holds[k] != nil
}

// log writes a line about the transfer k.
func (w *Worker) log(ctx context.Context, level slog.Level, msg string, k key, attrs ...slog.Attr) {
	attrs = append([]slog.Attr{slog.String("tenant", k.tid.String()), slog.String("transfer", k.id)}, attrs...)
	w.logger.LogAttrs(ctx, level, msg, attrs...)
}
