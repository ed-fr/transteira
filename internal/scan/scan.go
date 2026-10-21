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
// starts and one line when clamd answers again. When clamd drops the
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
package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
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
	// DefaultMailRetryFor is how long refused mails are retried.
	DefaultMailRetryFor = time.Hour
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

// Vault opens the data keys of the files and seals the download tokens.
// *masterkey.Vault implements it.
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

// Deps are the components the worker relies on. Every field is required.
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
	// (DefaultMailRetryFor).
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

// task is a unit of work: a transfer to process, or a batch of mails to
// enqueue again when mails is set.
type task struct {
	k     key
	mails *mailBatch
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
	mail     MailQueue
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
	if opts.MailRetryFor <= 0 {
		opts.MailRetryFor = DefaultMailRetryFor
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	w := &Worker{
		repo: storeRepo{db: deps.DB, vault: deps.Vault}, vault: deps.Vault, files: deps.Files,
		scanner: deps.Scanner, remover: deps.Remover, notifier: deps.Notifier, mail: deps.Mail,
		opts: opts, logger: opts.Logger, now: opts.Now, newToken: id.NewDownloadToken,
		sweepLimit: store.ScanSweepLimit,
		known:      map[key]bool{}, retries: map[key]int{}, timers: map[*time.Timer]task{},
		refusals: map[string]int{},
	}
	w.changed = sync.NewCond(&w.mu)
	return w
}

// Enqueue asks for the analysis of the transfer transferID of tenant tid.
// It never blocks. A transfer already queued, being processed or waiting
// for a retry is ignored, and so is any transfer once the worker is closed
// (the start-up sweep resumes it). Its signature matches transfer
// Options.OnFinalized.
func (w *Worker) Enqueue(tid tenant.ID, transferID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enqueueLocked(key{tid: tid, id: transferID})
}

// enqueueLocked queues k unless it is known or the worker is closed, and
// reports whether it was queued. w.mu must be held.
func (w *Worker) enqueueLocked(k key) bool {
	if w.closed || w.known[k] {
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
	context.AfterFunc(ctx, func() { w.shutdown(context.WithoutCancel(ctx)) })
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
		w.shutdown(ctx)
	}
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// shutdown marks the worker closed, stops the retry timers and wakes the
// idle workers.
func (w *Worker) shutdown(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	for timer, t := range w.timers {
		timer.Stop()
		if t.mails != nil {
			w.logDroppedMails(ctx, t.mails)
		}
	}
	clear(w.timers)
	w.changed.Broadcast()
}

// loop runs tasks until the worker is closed.
func (w *Worker) loop(ctx context.Context) {
	for {
		t, ok := w.next()
		if !ok {
			return
		}
		if t.mails != nil {
			w.sendMails(ctx, t.mails)
			w.finishTask(t, 0)
			continue
		}
		w.finishTask(t, w.process(ctx, t.k))
	}
}

// next waits for a task; it returns false once the worker is closed.
func (w *Worker) next() (task, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.fifo) == 0 && !w.closed {
		w.changed.Wait()
	}
	if w.closed {
		return task{}, false
	}
	t := w.fifo[0]
	w.fifo[0] = task{}
	w.fifo = w.fifo[1:]
	w.running++
	return t, true
}

// finishTask ends a task: a transfer is retried after retry when it is
// positive, released otherwise.
func (w *Worker) finishTask(t task, retry time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running--
	defer w.changed.Broadcast()
	if t.mails != nil {
		return
	}
	if retry > 0 && !w.closed {
		w.scheduleLocked(task{k: t.k}, retry)
		return
	}
	delete(w.known, t.k)
	delete(w.retries, t.k)
	w.released++
}

// schedule queues t after delay. Mail batches are not deduplicated.
func (w *Worker) schedule(ctx context.Context, t task, delay time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.logDroppedMails(ctx, t.mails)
		return
	}
	w.scheduleLocked(t, delay)
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

// logDroppedMails logs the mails of b lost because the worker closed.
func (w *Worker) logDroppedMails(ctx context.Context, b *mailBatch) {
	w.log(ctx, slog.LevelError, "notification mails dropped at shutdown", b.k,
		slog.Int("count", len(b.jobs)))
}

// backoff returns the n-th retry delay: RetryMin doubled n-1 times, at most
// RetryMax.
func (w *Worker) backoff(n int) time.Duration {
	d := w.opts.RetryMin
	for i := 1; i < n && d < w.opts.RetryMax; i++ {
		d *= 2
	}
	return min(d, w.opts.RetryMax)
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
// find a file crashing clamd.
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
	return max(w.nextProbe.Sub(now), time.Millisecond)
}

// clamdUp ends a clamd outage, logging it once.
func (w *Worker) clamdUp(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.outage {
		return
	}
	w.outage = false
	w.logger.LogAttrs(ctx, slog.LevelInfo, "antivirus available again")
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
