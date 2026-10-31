package updatecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/version"
)

// Defaults of [Options].
const (
	// DefaultInterval separates two background checks.
	DefaultInterval = 24 * time.Hour
	// DefaultJitter is the largest random delay added to the interval,
	// so that the instances do not all call GitHub at the same time.
	DefaultJitter = time.Hour
	// DefaultStartDelay is the shortest delay between the start and the
	// first background check; a random delay of up to as much again is
	// added.
	DefaultStartDelay = 5 * time.Minute
	// DefaultManualInterval separates two checks asked by a super admin,
	// for the whole instance.
	DefaultManualInterval = time.Minute
)

// Errors of the service.
var (
	// ErrDisabled reports a manual check while TT_UPDATE_CHECK is false.
	ErrDisabled = errors.New("updatecheck: the update check is disabled")
	// ErrClosed reports a check asked after [Service.Close].
	ErrClosed = errors.New("updatecheck: closed")
	// ErrStarted reports a second [Service.Start].
	ErrStarted = errors.New("updatecheck: already started")
)

// RateLimitError reports a manual check asked less than
// Options.ManualInterval after the previous one.
type RateLimitError struct {
	// RetryAfter is the delay before the next manual check is accepted.
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("updatecheck: a check was asked too recently, retry in %s", e.RetryAfter.Round(time.Second))
}

// Store keeps the outcome of the last check (*store.SystemState).
type Store interface {
	Get(ctx context.Context, key string) (store.SystemStateValue, error)
	Put(ctx context.Context, key string, value []byte) error
}

// Compile-time check that the store repository fits.
var _ Store = (*store.SystemState)(nil)

// Options configure a [Service]. Zero values take the defaults.
type Options struct {
	// Enabled is TT_UPDATE_CHECK: false makes no connection and writes
	// nothing.
	Enabled bool
	// Current is the running version (version.Get().Version when "").
	Current string
	// Interval separates two background checks (DefaultInterval).
	Interval time.Duration
	// Jitter is the largest random delay added to Interval
	// (DefaultJitter).
	Jitter time.Duration
	// StartDelay is the shortest delay before the first background check
	// (DefaultStartDelay).
	StartDelay time.Duration
	// ManualInterval separates two manual checks (DefaultManualInterval).
	ManualInterval time.Duration
	// Logger receives the outcome of the checks (slog.Default when nil).
	Logger *slog.Logger
	// Now is the clock (time.Now when nil).
	Now func() time.Time

	// client holds the seams of the HTTP client (tests); its zero value
	// is the production client.
	client clientOptions
	// random returns a random duration in [0, n] (crypto/rand when nil).
	random func(n time.Duration) time.Duration
}

// Status is the outcome of the last check, as shown to the super admin.
type Status struct {
	// Enabled is TT_UPDATE_CHECK.
	Enabled bool
	// LatestVersion is the latest stable release found, "" before the
	// first successful check.
	LatestVersion string
	// ReleaseURL is the page of that release, "" when unknown or refused
	// by [FilterReleaseURL].
	ReleaseURL string
	// UpdateAvailable reports LatestVersion strictly greater than the
	// running version.
	UpdateAvailable bool
	// CheckedAt is the last successful check, the zero time before the
	// first one.
	CheckedAt time.Time
	// LastError is the outcome of the last attempt.
	LastError Category
}

// state is the JSON document stored under store.SystemStateUpdateCheck.
type state struct {
	LatestVersion *string    `json:"latestVersion"`
	ReleaseURL    *string    `json:"releaseUrl"`
	CheckedAt     *time.Time `json:"checkedAt"`
	LastError     Category   `json:"lastError"`
}

// flight is a check in progress, shared by every caller asking for one
// meanwhile.
type flight struct {
	done chan struct{}
	st   state
}

// Service runs the update checks and serves their outcome. It is safe for
// concurrent use.
type Service struct {
	st                                   Store
	client                               *client
	enabled                              bool
	current                              string
	interval, jitter, startDelay, manual time.Duration
	logger                               *slog.Logger
	now                                  func() time.Time
	random                               func(time.Duration) time.Duration

	// base bounds every check; cancel stops them at Close.
	base   context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	inflight   *flight
	lastManual time.Time
	started    bool
	closed     bool
}

// New returns a service over st applying opts. It makes no connection:
// see [Service.Start] and [Service.CheckNow].
func New(st Store, opts Options) *Service {
	if opts.Current == "" {
		opts.Current = version.Get().Version
	}
	opts.Interval = orDefault(opts.Interval, DefaultInterval)
	opts.Jitter = orDefault(opts.Jitter, DefaultJitter)
	opts.StartDelay = orDefault(opts.StartDelay, DefaultStartDelay)
	opts.ManualInterval = orDefault(opts.ManualInterval, DefaultManualInterval)
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.random == nil {
		opts.random = cryptoRandom
	}
	c := opts.client
	if c.url == "" {
		c.url = ReleasesURL
	}
	if c.userAgent == "" {
		c.userAgent = "TransTeira/" + opts.Current
	}
	c.timeout = orDefault(c.timeout, Timeout)
	if c.proxy == nil {
		c.proxy = http.ProxyFromEnvironment
	}
	s := &Service{
		st: st, client: newClient(c), enabled: opts.Enabled, current: opts.Current,
		interval: opts.Interval, jitter: opts.Jitter, startDelay: opts.StartDelay, manual: opts.ManualInterval,
		logger: opts.Logger, now: opts.Now, random: opts.random,
	}
	s.base, s.cancel = context.WithCancel(context.Background())
	return s
}

// orDefault returns d, or def when d is not positive.
func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// cryptoRandom returns a uniform random duration in [0, n] (0 when n is
// not positive). crypto/rand is the only source allowed in the project.
func cryptoRandom(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)+1))
	if err != nil {
		return n / 2 // never happens (crypto/rand does not fail)
	}
	return time.Duration(v.Int64())
}

// Enabled reports TT_UPDATE_CHECK.
func (s *Service) Enabled() bool { return s.enabled }

// Status returns the outcome of the last check, for an authenticated super
// admin only (adminauth.ErrUnauthenticated or adminauth.ErrForbidden
// otherwise). When the check is disabled, it reads nothing and returns a
// disabled status without version. A stored value that does not pass the
// rules of the package reads as "never checked".
func (s *Service) Status(ctx context.Context, p adminauth.Principal) (Status, error) {
	if err := requireSuperAdmin(p); err != nil {
		return Status{}, err
	}
	if !s.enabled {
		return Status{LastError: CategoryNone}, nil
	}
	st, _, err := s.load(ctx)
	if err != nil {
		return Status{}, err
	}
	return s.status(st), nil
}

// CheckNow runs a check at once for an authenticated super admin (the
// errors of Status otherwise) and returns its outcome; a failure of the check is reported
// in Status.LastError, not as an error. It returns ErrDisabled when the
// check is disabled, a *RateLimitError when the previous manual check is
// less than Options.ManualInterval old, whoever asked, and ErrClosed after
// Close. A check already running is joined rather than doubled. It waits
// at most until ctx is done; the check itself is bounded by [Timeout].
func (s *Service) CheckNow(ctx context.Context, p adminauth.Principal) (Status, error) {
	if err := requireSuperAdmin(p); err != nil {
		return Status{}, err
	}
	if !s.enabled {
		return Status{}, ErrDisabled
	}
	s.mu.Lock()
	now := s.now()
	if elapsed := now.Sub(s.lastManual); !s.lastManual.IsZero() && elapsed >= 0 && elapsed < s.manual {
		s.mu.Unlock()
		return Status{}, &RateLimitError{RetryAfter: s.manual - elapsed}
	}
	s.lastManual = now
	s.mu.Unlock()
	st, err := s.run(ctx)
	if err != nil {
		return Status{}, err
	}
	return s.status(st), nil
}

// requireSuperAdmin checks that p is an authenticated session of a super
// admin (adminauth.ErrUnauthenticated or adminauth.ErrForbidden
// otherwise), again after the handler (defense in depth).
func requireSuperAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// status renders st, computing UpdateAvailable from the running version.
func (s *Service) status(st state) Status {
	out := Status{Enabled: true, LastError: st.LastError}
	if st.LatestVersion != nil {
		out.LatestVersion = *st.LatestVersion
		out.UpdateAvailable = Newer(out.LatestVersion, s.current)
	}
	if st.ReleaseURL != nil {
		out.ReleaseURL = *st.ReleaseURL
	}
	if st.CheckedAt != nil {
		out.CheckedAt = *st.CheckedAt
	}
	return out
}

// load reads and revalidates the stored outcome, and returns the time of
// the last attempt (the zero time when never). A missing or invalid value
// reads as never checked.
func (s *Service) load(ctx context.Context) (state, time.Time, error) {
	v, err := s.st.Get(ctx, store.SystemStateUpdateCheck)
	if errors.Is(err, store.ErrNotFound) {
		return neverChecked(), time.Time{}, nil
	}
	if err != nil {
		return state{}, time.Time{}, err
	}
	st, ok := decodeState(v.Value)
	if !ok {
		s.logger.WarnContext(ctx, "updatecheck: the stored outcome is invalid and is ignored")
		return neverChecked(), v.UpdatedAt, nil
	}
	return st, v.UpdatedAt, nil
}

// neverChecked is the state before the first check.
func neverChecked() state { return state{LastError: CategoryNone} }

// decodeState decodes and revalidates a stored outcome (T-248): strict
// JSON (no unknown member, no trailing data), a known lastError, a stable
// version of at most MaxVersionLength bytes, a release URL accepted by
// FilterReleaseURL and only with a version, a non-zero checkedAt.
func decodeState(raw []byte) (state, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var st state
	if err := dec.Decode(&st); err != nil || dec.More() || !isObject(raw) {
		return state{}, false
	}
	switch {
	case !st.LastError.valid(),
		st.LatestVersion != nil && !StableVersion(*st.LatestVersion),
		st.ReleaseURL != nil && (st.LatestVersion == nil || FilterReleaseURL(*st.ReleaseURL) == ""),
		st.CheckedAt != nil && st.CheckedAt.IsZero():
		return state{}, false
	}
	return st, true
}

// run starts a check, or joins the one in progress, and waits for its
// outcome at most until ctx is done.
func (s *Service) run(ctx context.Context) (state, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return state{}, ErrClosed
	}
	f := s.inflight
	if f == nil {
		f = &flight{done: make(chan struct{})}
		s.inflight = f
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			f.st = s.check(s.base)
			s.mu.Lock()
			s.inflight = nil
			s.mu.Unlock()
			close(f.done)
		}()
	}
	s.mu.Unlock()
	select {
	case <-f.done:
		return f.st, nil
	case <-ctx.Done():
		return state{}, ctx.Err()
	}
}

// check asks GitHub for the latest release and records the outcome: on
// success the release found (a draft or pre-release keeps the previous
// one) and the date; on failure only the category, the last good result
// being kept. A failure to read or write the database is logged.
func (s *Service) check(ctx context.Context) state {
	prev, _, err := s.load(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "updatecheck: failed to read the last outcome", slog.String("error", err.Error()))
		prev = neverChecked()
	}
	rel, category := s.client.fetch(ctx)
	if ctx.Err() != nil {
		return prev // closed meanwhile: nothing is recorded
	}
	next := prev
	next.LastError = category
	if category == CategoryNone {
		now := s.now().UTC().Truncate(time.Second)
		next.CheckedAt = &now
		if rel.Version != "" {
			next.LatestVersion = &rel.Version
			next.ReleaseURL = nil
			if rel.URL != "" {
				next.ReleaseURL = &rel.URL
			}
		}
	}
	value, _ := json.Marshal(next) // a state always marshals
	if err := s.st.Put(ctx, store.SystemStateUpdateCheck, value); err != nil {
		s.logger.ErrorContext(ctx, "updatecheck: failed to record the outcome", slog.String("error", err.Error()))
	}
	out := s.status(next)
	if category == CategoryNone {
		s.logger.InfoContext(ctx, "updatecheck: checked for a newer release",
			slog.String("latest_version", out.LatestVersion), slog.Bool("update_available", out.UpdateAvailable))
	} else {
		s.logger.WarnContext(ctx, "updatecheck: the check for a newer release failed",
			slog.String("category", string(category)))
	}
	return next
}

// Start runs the background checks until [Service.Close]: the first one
// at least Options.StartDelay after now and no sooner than
// Options.Interval after the last attempt recorded, then one every
// Options.Interval plus a random jitter. It does nothing when the check is
// disabled. ctx is not used for the cancellation: Close stops the loop. It
// returns ErrStarted when already started and ErrClosed once closed.
func (s *Service) Start(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrClosed
	case s.started:
		return ErrStarted
	}
	s.started = true
	if !s.enabled {
		return nil
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.loop()
	}()
	return nil
}

// loop waits for each check time and runs the check, until Close.
func (s *Service) loop() {
	delay := s.firstDelay()
	for {
		timer := time.NewTimer(delay)
		select {
		case <-s.base.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if _, err := s.run(s.base); err != nil {
			return // closed
		}
		delay = s.interval + s.random(s.jitter)
	}
}

// firstDelay returns the delay before the first background check: at
// least StartDelay (plus up to as much again at random), and the time
// left until Interval (plus jitter) after the last attempt recorded,
// capped at Interval plus Jitter when the clock went back.
func (s *Service) firstDelay() time.Duration {
	least := s.startDelay + s.random(s.startDelay)
	_, last, err := s.load(s.base)
	if err != nil || last.IsZero() {
		return least
	}
	d := last.Add(s.interval + s.random(s.jitter)).Sub(s.now())
	d = min(d, s.interval+s.jitter)
	return max(d, least)
}

// Close stops the background checks and cancels a check in progress, and
// waits for them at most until ctx is done (returning ctx.Err() then).
// Later checks return ErrClosed. Calling it more than once is harmless.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
