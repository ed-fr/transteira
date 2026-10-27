// Package scan is the antivirus worker of TransTeira (CLAUDE.md sections 11
// and 12.2, threat model T-41 to T-46 and T-110, decision P10). It takes the
// finalized transfers, which wait in the scanning status, to their final
// status:
//
//   - available, with a download link, the mails to the recipients and the
//     confirmation to the sender (plus the "file problems" and "file not
//     scanned" alerts when they apply);
//   - rejected, when no file can be delivered (every file infected or in
//     scan_error), with an alert to the sender and nothing to the
//     recipients.
//
// # Inputs
//
// [Worker.Enqueue] is called after each finalization (transfer
// Options.OnFinalized); it never blocks and ignores a transfer already
// queued, being processed or waiting for a retry. [Worker.Start] also sweeps
// the transfers still scanning, across tenants (the only system query of the
// package), so that a transfer whose analysis was interrupted by a restart
// is resumed.
//
// # Processing
//
// Options.Workers workers each process one transfer at a time, one file at a
// time; a transfer is never processed by two workers at once. Each file still
// pending or scanning is marked scanning, then its stored ciphertext is
// decrypted on the fly and streamed to clamd: what is analyzed is exactly what
// will be served (T-44), the plaintext never touches the disk and is never
// buffered. Its final status is written once, at the end of its analysis:
// clean, infected with the signature, not_scanned_too_large (above the
// client limit, refused by clamd, or with parts skipped past clamd's archive
// limits), not_scanned_encrypted (an encrypted archive clamd cannot look
// inside), or scan_error. The deliverable statuses are those of
// store.ScanStatus.Deliverable.
//
// # Failures
//
// The antivirus is fail-closed (P10). When clamd cannot be reached, the
// file stays scanning and the transfer is retried after a delay that starts
// at Options.RetryMin and doubles up to Options.RetryMax, shared by every
// transfer during the incident; one warning is logged when the incident
// starts and one line when clamd answers again. Deps.Outage, when set, is
// told of every failure and of the recovery, so that package avalert
// alerts the administrators when the outage lasts. When clamd drops the
// connection in the middle of an exchange, the failure always counts
// against the file, so that a content crashing clamd reaches scan_error
// instead of stalling every analysis (a real clamd restart costs the file in
// flight one attempt); clamd is pinged only to choose the delay: the shared
// outage backoff, whose warning names the file, when it does not answer.
//
// Only failures specific to the content are counted against a file: an
// unexpected clamd reply, an analysis that does not complete in time
// (antivirus.ErrTimeout), a dropped connection, a missing stored file, and a content that cannot be read or decrypted
// (antivirus.ErrSource). The file gets scan_error at the
// Options.MaxFileErrors-th one and is never delivered. Any other failure
// (database, key vault, transient storage error) is retried with the same
// backoff without counting an attempt. A result the store refuses as
// malformed or conflicting is logged and left to the conclusion; refused
// again on a later pass, the file is withheld (scan_error), or, if even that
// is refused, the transfer is left scanning with an error line. A shutdown
// never counts an attempt and leaves the file as it was; statuses are
// written in their own transactions, so that no file is left half-recorded.
// When clamd refuses as too large a stream the client sent, its limits are
// below TT_CLAMAV_MAX_SCAN_BYTES: one warning asks to align them.
//
// # End of a transfer
//
// A transfer is concluded only when every file has a final status. The data
// keys of the infected files are destroyed and their files removed
// (cryptographic erasure, T-110: the key first); their rows stay, with the
// infected status, for the information of the sender. A transfer with a
// deliverable file gets, in one transaction, a "dl_" token of 256 bits whose
// SHA-256 is stored and whose raw value is sealed by the key vault (purpose
// secret), then becomes available; its expiry restarts from that moment.
// The link (id.DownloadURL) is built from the FQDN stored for the tenant
// (T-03), never from a request. The mails are built after the commit with
// the SMTP settings of the transfer's tenant and enqueued; a full queue or
// an open circuit is retried for Options.MailRetryFor. A mail that cannot be
// sent never changes the status of the transfer. Logs never hold an address
// or a token.
//
// # Holds
//
// [Worker.Hold] keeps a transfer away from the worker while an
// administrator or a GDPR erasure deletes it (lifecycle EraseTransfer,
// intent lifecycle.HoldForErase) or a GDPR erasure removes one of its
// recipients (lifecycle.HoldForEdit): an analysis in progress is canceled,
// without counting an attempt and without concluding or sending any mail,
// and Hold returns once it has stopped; a queued transfer, or one waiting
// for a retry, is dropped; [Worker.Enqueue] and the sweeps ignore it. Holds
// are counted per transfer. When the last one is released, the transfer is
// queued again if it is still scanning in the database.
//
// A conclusion that was already committing when the hold arrived may still
// make the transfer available or reject it. Whether a hold is present is
// checked again under the worker lock right before its mails are queued.
// Under an erasure hold, the mails are dropped: the holder erases the
// transfer. Under edit holds only, they are deferred: the last release
// rebuilds them from the current state of the transfer (its remaining
// recipients, its download link unsealed from the database) and queues
// them when it is still available, or still rejected. An erasure hold
// taken meanwhile cancels the deferred mails.
//
// # Audit and usage
//
// Once its status is committed, an infected file records file.infected
// (details: transfer ID and signature name) and counts one virus detection
// for the statistics (Deps.Usage); a file accepted without analysis records
// file.not_scanned (details: transfer ID and reason, too_large or
// encrypted). The actor is the system ([SystemActor]). The audit is best
// effort: a failure is logged, never returned, and never changes a status.
package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of [Options].
const (
	// DefaultWorkers is the default number of workers (TT_SCAN_WORKERS).
	DefaultWorkers = 2
	// DefaultRetryMin is the first retry delay.
	DefaultRetryMin = 30 * time.Second
	// DefaultRetryMax is the longest retry delay.
	DefaultRetryMax = 10 * time.Minute
	// DefaultMaxFileErrors is the number of file-specific failures that
	// gives a file the scan_error status.
	DefaultMaxFileErrors = 3
)

// ErrStarted is returned by [Worker.Start] when the worker was already
// started.
var ErrStarted = errors.New("scan: worker already started")

// Scanner analyzes a content of size bytes and checks that clamd answers.
// *antivirus.Client implements it.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error)
	Ping(ctx context.Context) error
}

// Vault opens the data keys of the files, seals the download tokens and
// unseals them for the mails deferred by a hold. *masterkey.Vault
// implements it.
type Vault interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
	SealTx(ctx context.Context, tx *store.ScopedTx, p crypto.Purpose, plaintext []byte) (string, error)
}

// Files opens the stored encrypted files. *storage.Store implements it.
type Files interface {
	OpenRead(tid tenant.ID, name string) (*os.File, int64, error)
}

// Remover erases files: their data keys in one transaction first, then the
// files on disk, keeping the rows. *upload.Engine implements it.
type Remover interface {
	RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error
}

// Notifier builds the mails that follow the analysis. *notify.Notifier
// implements it.
type Notifier interface {
	RecipientJobs(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, link string) ([]mail.Job, error)
	SenderConfirmation(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, link string) (mail.Job, error)
	FileProblems(ctx context.Context, t *tenant.Tenant, tr notify.TransferView) (mail.Job, error)
	FileNotScanned(ctx context.Context, t *tenant.Tenant, tr notify.TransferView) (mail.Job, error)
}

// MailQueue queues the mails without blocking. *mail.Queue implements it.
type MailQueue interface {
	Enqueue(job mail.Job) error
}

// AuditWriter records audit events in the scope of a tenant.
// *audit.Writer implements it.
type AuditWriter interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// UsageCounter counts the virus detections of the statistics, in memory,
// without blocking.
type UsageCounter interface {
	VirusDetected(tid tenant.ID, at time.Time)
}

// OutageObserver is told when clamd cannot be reached and when it answers
// again, for the antivirus alert (decision P10). Its methods are called
// with the worker lock held: they must not block nor call the worker.
// *avalert.Monitor implements it.
type OutageObserver interface {
	// ClamdDown reports a failure to reach clamd: every one, not only the
	// first of an outage, so that the observer can start a new outage
	// after closing one itself.
	ClamdDown()
	// ClamdUp reports its end: clamd answered again.
	ClamdUp()
}

// SystemActor is the actor (store.ActorSystem) of the audit events the
// worker records.
const SystemActor = "antivirus"

// Deps are the components the worker relies on. Every field is required,
// except Audit, Usage and Outage.
type Deps struct {
	// DB stores the transfers.
	DB *store.DB
	// Vault holds the data keys and seals the download tokens.
	Vault Vault
	// Files gives access to the encrypted files.
	Files Files
	// Scanner is the clamd client.
	Scanner Scanner
	// Remover erases the infected files.
	Remover Remover
	// Notifier builds the mails.
	Notifier Notifier
	// Mail is the mail queue.
	Mail MailQueue
	// Audit records file.infected and file.not_scanned; nil records
	// nothing.
	Audit AuditWriter
	// Usage counts the virus detections; nil counts nothing.
	Usage UsageCounter
	// Outage is told when clamd becomes unreachable and answers again;
	// nil tells nobody.
	Outage OutageObserver
	// Events receives the virus.detected events, one per infected file
	// (counts files = 1); nil publishes nothing.
	Events events.Publisher
}

// Options tunes a [Worker]. Zero values select the defaults.
type Options struct {
	// Workers is the number of workers (DefaultWorkers).
	Workers int
	// RetryMin is the first retry delay (DefaultRetryMin).
	RetryMin time.Duration
	// RetryMax is the longest retry delay (DefaultRetryMax).
	RetryMax time.Duration
	// MaxFileErrors is the number of file-specific failures giving
	// scan_error (DefaultMaxFileErrors).
	MaxFileErrors int
	// MailRetryFor is how long mails refused by the queue are retried
	// (mail.DefaultRetryFor when <= 0). They are retried with the
	// RetryMin and RetryMax backoff.
	MailRetryFor time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the operational logs, without any address or token
	// (nil discards).
	Logger *slog.Logger
}

// key identifies a transfer and its tenant.
type key struct {
	tid tenant.ID
	id  string
}

// task is a unit of work: a transfer to process.
type task struct {
	k key
}

// holdState tracks the holds of a held transfer ([Worker.Hold]).
type holdState struct {
	// count is the number of holds in progress.
	count int
	// erase is the number of them taken for an erasure.
	erase int
	// pending is set when the mails of a conclusion were deferred under
	// edit holds: the last release sends them.
	pending bool
}

// run is a transfer being processed.
type run struct {
	// cancel cancels its processing, for a hold.
	cancel context.CancelFunc
	// done is closed once the processing has returned and its task ended.
	done chan struct{}
	// held is set when a hold canceled it.
	held bool
}

// Worker is the antivirus worker. Create it with [New], start it with
// [Worker.Start] and stop it with [Worker.Close]. It is safe for concurrent
// use; one Worker must serve the whole instance, since it holds the
// per-transfer locks.
type Worker struct {
	repo     repo
	vault    Vault
	files    Files
	scanner  Scanner
	remover  Remover
	notifier Notifier
	audit    AuditWriter
	usage    UsageCounter
	observer OutageObserver
	events   events.Publisher
	mails    *mail.Retrier
	opts     Options
	logger   *slog.Logger
	now      func() time.Time
	newToken func() (string, error)
	// sweepLimit is the page size of the store's sweep: a page this long
	// means more transfers may be waiting.
	sweepLimit int

	mu      sync.Mutex
	changed *sync.Cond
	fifo    []task
	// known holds the transfers queued, being processed or waiting for a
	// retry: the in-process lock of each transfer.
	known   map[key]bool
	retries map[key]int
	// runs holds the transfers being processed.
	runs map[key]*run
	// holds tracks the holds of each held transfer ([Worker.Hold]).
	holds   map[key]*holdState
	timers  map[*time.Timer]task
	running int
	// released counts the transfers released, for the sweep.
	released uint64
	started  bool
	closed   bool
	// outage is set while clamd is unreachable; nextProbe is when the
	// transfers of the incident are retried, after outageDelay.
	outage      bool
	outageDelay time.Duration
	nextProbe   time.Time
	// streamLimitWarned is set once the misaligned clamd limit was logged.
	streamLimitWarned bool
	// refusals counts, per file, the passes on which the store refused
	// its scan result.
	refusals map[string]int

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New returns a stopped worker over deps.
func New(deps Deps, opts Options) *Worker {
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}
	if opts.RetryMin <= 0 {
		opts.RetryMin = DefaultRetryMin
	}
	if opts.RetryMax < opts.RetryMin {
		opts.RetryMax = max(DefaultRetryMax, opts.RetryMin)
	}
	if opts.MaxFileErrors <= 0 {
		opts.MaxFileErrors = DefaultMaxFileErrors
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	w := &Worker{
		repo: storeRepo{db: deps.DB, vault: deps.Vault}, vault: deps.Vault, files: deps.Files,
		scanner: deps.Scanner, remover: deps.Remover, notifier: deps.Notifier,
		audit: deps.Audit, usage: deps.Usage, observer: deps.Outage, events: events.OrDiscard(deps.Events),
		mails: mail.NewRetrier(deps.Mail, mail.RetryOptions{
			For: opts.MailRetryFor, Min: opts.RetryMin, Max: opts.RetryMax, Now: opts.Now, Logger: opts.Logger,
		}),
		opts: opts, logger: opts.Logger, now: opts.Now, newToken: id.NewDownloadToken,
		sweepLimit: store.ScanSweepLimit,
		known:      map[key]bool{}, retries: map[key]int{}, timers: map[*time.Timer]task{},
		runs: map[key]*run{}, holds: map[key]*holdState{},
		refusals: map[string]int{},
	}
	w.changed = sync.NewCond(&w.mu)
	return w
}

// Enqueue asks for the analysis of the transfer transferID of tenant tid.
// It never blocks. A transfer already queued, being processed or waiting
// for a retry is ignored, and so is a held transfer ([Worker.Hold]) and any
// transfer once the worker is closed (the start-up sweep resumes it). Its
// signature matches transfer Options.OnFinalized.
func (w *Worker) Enqueue(tid tenant.ID, transferID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enqueueLocked(key{tid: tid, id: transferID})
}

// enqueueLocked queues k unless it is known, held or the worker is closed,
// and reports whether it was queued. w.mu must be held.
func (w *Worker) enqueueLocked(k key) bool {
	if w.closed || w.known[k] || w.holds[k] != nil {
		return false
	}
	w.known[k] = true
	w.fifo = append(w.fifo, task{k: k})
	w.changed.Broadcast()
	return true
}

// Start launches the workers, then sweeps the transfers still scanning and
// queues them. When the sweep returns a full page, the next pages are swept
// in the background once the first ones were processed. The workers stop
// when ctx is done or [Worker.Close] is called. Start returns the error of
// the first sweep (the workers keep running and the queued transfers are
// processed), or ErrStarted when called twice.
func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return ErrStarted
	}
	w.started = true
	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.mu.Unlock()
	context.AfterFunc(ctx, w.shutdown)
	for range w.opts.Workers {
		w.wg.Go(func() { w.loop(ctx) })
	}
	released := w.releasedCount()
	full, added, err := w.sweepOnce(ctx)
	if err != nil {
		return err
	}
	if full {
		w.wg.Go(func() { w.sweepRest(ctx, added, released) })
	}
	return nil
}

// Close stops the workers: an analysis in progress is abandoned, leaving its
// file scanning without counting an attempt, and nothing more is started.
// Pending retries are dropped (the start-up sweep resumes their transfers;
// mails waiting for a retry are lost and logged). Close waits for the
// workers to return, at most until ctx is done, and returns ctx.Err() then.
// Calling it more than once, or before Start, is harmless.
func (w *Worker) Close(ctx context.Context) error {
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	} else {
		w.shutdown()
	}
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	mailErr := w.mails.Close(ctx)
	select {
	case <-done:
		return mailErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// shutdown marks the worker closed, stops the retry timers and wakes the
// idle workers.
func (w *Worker) shutdown() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	for timer := range w.timers {
		timer.Stop()
	}
	clear(w.timers)
	w.changed.Broadcast()
}

// loop runs tasks until the worker is closed.
func (w *Worker) loop(ctx context.Context) {
	for {
		t, tctx, ok := w.next(ctx)
		if !ok {
			return
		}
		w.finishTask(t, w.process(tctx, t.k))
	}
}

// next waits for a task and registers it as running, with a context
// derived from ctx that a hold cancels; it returns false once the worker is
// closed.
func (w *Worker) next(ctx context.Context) (task, context.Context, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.fifo) == 0 && !w.closed {
		w.changed.Wait()
	}
	if w.closed {
		return task{}, nil, false
	}
	t := w.fifo[0]
	w.fifo[0] = task{}
	w.fifo = w.fifo[1:]
	w.running++
	tctx, cancel := context.WithCancel(ctx)
	w.runs[t.k] = &run{cancel: cancel, done: make(chan struct{})}
	return t, tctx, true
}

// finishTask ends a task: a transfer is retried after retry when it is
// positive and the transfer is not held, released otherwise; a hold waiting
// for it is woken.
func (w *Worker) finishTask(t task, retry time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running--
	defer w.changed.Broadcast()
	r := w.runs[t.k]
	delete(w.runs, t.k)
	r.cancel()
	close(r.done)
	if r.held && !w.closed && w.holds[t.k] == nil {
		// The holds that canceled it gave up before it stopped: it is
		// processed again.
		w.forgetLocked(t.k)
		w.enqueueLocked(t.k)
		return
	}
	if retry > 0 && !w.closed && w.holds[t.k] == nil {
		w.scheduleLocked(task{k: t.k}, retry)
		return
	}
	w.forgetLocked(t.k)
}

// forgetLocked releases the in-process lock of k. w.mu must be held.
func (w *Worker) forgetLocked(k key) {
	delete(w.known, k)
	delete(w.retries, k)
	w.released++
}

// Hold keeps the transfer trfID of tenant tid away from the worker until
// the returned release function is called (see the package documentation):
// an analysis in progress is canceled and Hold waits for it to stop,
// without counting an attempt, concluding or sending any mail; a queued
// transfer, or one waiting for a retry, is dropped; Enqueue and the sweeps
// ignore it meanwhile. intent decides the mails of a conclusion that
// committed meanwhile: dropped under lifecycle.HoldForErase, deferred to
// the last release under lifecycle.HoldForEdit only. Holds are counted:
// the transfer stays held until every release was called. The last release
// queues the transfer again when it is still scanning in the database (a
// failure to read it queues it anyway: the processing checks the status),
// and sends the deferred mails. release may be called more than once,
// never waits for the worker, and does nothing more once the worker is
// closed. When ctx is done before the analysis has stopped, Hold releases
// its hold and returns ctx.Err(). Hold works on a stopped or closed
// worker. Its signature matches lifecycle.Holder.
func (w *Worker) Hold(ctx context.Context, tid tenant.ID, trfID string, intent lifecycle.HoldIntent) (release func(), err error) {
	k := key{tid: tid, id: trfID}
	erase := intent == lifecycle.HoldForErase
	w.mu.Lock()
	h := w.holds[k]
	if h == nil {
		h = &holdState{}
		w.holds[k] = h
	}
	h.count++
	if erase {
		// The erasure decides: mails deferred by an edit are canceled.
		h.erase++
		h.pending = false
	}
	r := w.runs[k]
	if r != nil {
		r.held = true
		r.cancel()
	} else {
		w.dropLocked(k)
	}
	w.mu.Unlock()
	rctx := context.WithoutCancel(ctx)
	release = sync.OnceFunc(func() { w.release(rctx, k, erase) })
	if r != nil {
		select {
		case <-r.done:
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}

// dropLocked removes k, which is not running, from the queue and from the
// retry timers. w.mu must be held.
func (w *Worker) dropLocked(k key) {
	if !w.known[k] {
		return
	}
	w.fifo = slices.DeleteFunc(w.fifo, func(t task) bool { return t.k == k })
	for timer, t := range w.timers {
		if t.k == k {
			timer.Stop()
			delete(w.timers, timer)
		}
	}
	w.forgetLocked(k)
	w.changed.Broadcast()
}

// release ends one hold of k (an erasure hold when erase is set); the last
// one queues k again when it is still scanning, and sends its deferred
// mails when it is still available or rejected.
func (w *Worker) release(ctx context.Context, k key, erase bool) {
	w.mu.Lock()
	h := w.holds[k]
	h.count--
	if erase {
		h.erase--
	}
	last := h.count == 0
	pending := last && h.pending
	if last {
		delete(w.holds, k)
	}
	closed := w.closed
	w.mu.Unlock()
	if !last {
		return
	}
	if closed {
		if pending {
			w.log(ctx, slog.LevelWarn, "worker closed: deferred notification mails not sent", k)
		}
		return
	}
	d, err := w.repo.transfer(ctx, k.tid, k.id)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return
	case err != nil:
		if pending {
			w.log(ctx, slog.LevelError, "held transfer not read on release: deferred notification mails not sent", k,
				slog.Any("error", err))
		}
		w.log(ctx, slog.LevelWarn, "held transfer not read on release, queued anyway", k, slog.Any("error", err))
	case d.Status == store.TransferScanning:
	case pending:
		w.sendDeferred(ctx, k, d)
		return
	default:
		return
	}
	w.Enqueue(k.tid, k.id)
}

// holdMailsLocked reports whether the mails of the transfer k must not be
// queued now because k is held: under an erasure hold they are dropped,
// under edit holds only they are marked pending for the last release.
// w.mu must be held.
func (w *Worker) holdMailsLocked(ctx context.Context, k key) bool {
	h := w.holds[k]
	switch {
	case h == nil:
		return false
	case h.erase > 0:
		w.log(ctx, slog.LevelInfo, "transfer held for erasure: no mail sent", k)
	default:
		h.pending = true
		w.log(ctx, slog.LevelInfo, "transfer held for an edit: mails deferred to the release", k)
	}
	return true
}

// scheduleLocked arms the retry timer of t. w.mu must be held and the
// worker open.
func (w *Worker) scheduleLocked(t task, delay time.Duration) {
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if _, ok := w.timers[timer]; !ok {
			return // stopped by shutdown
		}
		delete(w.timers, timer)
		w.fifo = append(w.fifo, t)
		w.changed.Broadcast()
	})
	w.timers[timer] = t
}

// backoff returns the n-th retry delay: RetryMin doubled n-1 times, at most
// RetryMax.
func (w *Worker) backoff(n int) time.Duration {
	return mail.Backoff(w.opts.RetryMin, w.opts.RetryMax, n)
}

// retryTransfer returns the next retry delay of the transfer k after a
// failure that is not a clamd outage.
func (w *Worker) retryTransfer(k key) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.retries[k]++
	return w.backoff(w.retries[k])
}

// clamdDown records that clamd is unreachable and returns when to retry:
// every transfer of the incident is retried at the same probe time, whose
// delay doubles each time a probe fails. The first failure of an incident
// logs one warning, naming culprit (the tenant, transfer and file IDs of a
// content that dropped the connection) when given, so that the operator can
// find a file crashing clamd. Every failure, not only the first, is
// reported to the outage observer.
func (w *Worker) clamdDown(ctx context.Context, culprit ...slog.Attr) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	switch {
	case !w.outage:
		w.outage = true
		w.outageDelay = w.opts.RetryMin
		w.nextProbe = now.Add(w.outageDelay)
		w.logger.LogAttrs(ctx, slog.LevelWarn,
			"antivirus unavailable: files stay unavailable until clamd answers again",
			append([]slog.Attr{slog.Duration("retry_in", w.outageDelay)}, culprit...)...)
	case !now.Before(w.nextProbe):
		w.outageDelay = min(2*w.outageDelay, w.opts.RetryMax)
		w.nextProbe = now.Add(w.outageDelay)
	}
	if w.observer != nil {
		w.observer.ClamdDown()
	}
	return max(w.nextProbe.Sub(now), time.Millisecond)
}

// clamdUp ends a clamd outage, logging it once and telling the outage
// observer.
func (w *Worker) clamdUp(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.outage {
		return
	}
	w.outage = false
	w.logger.LogAttrs(ctx, slog.LevelInfo, "antivirus available again")
	if w.observer != nil {
		w.observer.ClamdUp()
	}
}

// sweepOnce queues the transfers still scanning and reports whether the
// page was full and how many transfers it queued (the others were already
// known).
func (w *Worker) sweepOnce(ctx context.Context) (full bool, added int, err error) {
	page, err := w.repo.sweep(ctx)
	if err != nil {
		return false, 0, err
	}
	w.mu.Lock()
	for _, tt := range page {
		if w.enqueueLocked(key{tid: tt.TenantID, id: tt.TransferID}) {
			added++
		}
	}
	w.mu.Unlock()
	w.logger.LogAttrs(ctx, slog.LevelInfo, "antivirus sweep",
		slog.Int("scanning", len(page)), slog.Int("queued", added))
	return len(page) >= w.sweepLimit, added, nil
}

// sweepRest sweeps the pages following a full one, until a page is not
// full. The transfers of a page stay scanning until processed, so the next
// sweep waits until the queue is idle (only retries pending); when the
// previous sweep queued nothing (every transfer of the page was waiting for
// a retry), it waits until a transfer is released instead, so that it never
// spins.
func (w *Worker) sweepRest(ctx context.Context, added int, released uint64) {
	for {
		ok := false
		if added > 0 {
			ok = w.waitIdle()
		} else {
			ok = w.waitRelease(released)
		}
		if !ok {
			return
		}
		released = w.releasedCount()
		full, n, err := w.sweepOnce(ctx)
		if err != nil {
			w.logger.LogAttrs(ctx, slog.LevelError, "antivirus sweep failed", slog.Any("error", err))
			return
		}
		if !full {
			return
		}
		added = n
	}
}

// releasedCount returns the number of transfers released so far.
func (w *Worker) releasedCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.released
}

// waitIdle waits until no task is queued or running; it returns false when
// the worker closes.
func (w *Worker) waitIdle() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for (len(w.fifo) > 0 || w.running > 0) && !w.closed {
		w.changed.Wait()
	}
	return !w.closed
}

// waitRelease waits until a transfer is released after the count since; it
// returns false when the worker closes.
func (w *Worker) waitRelease(since uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.released == since && !w.closed {
		w.changed.Wait()
	}
	return !w.closed
}
