package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// withSecrets returns the run function of a task that first runs base, then
// secrets, whatever the outcome of base: the failures are returned joined.
func withSecrets(base func(context.Context) error, secrets func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		return errors.Join(base(ctx), secrets(ctx))
	}
}

// sweepSecrets runs one sweep of the store (limited to
// store.SecretSweepLimit secrets per call) until it reports nothing more
// due or makes no progress, removes the files of the secrets it ended, then
// scrubs the database when any key was destroyed. fn is the sweep, name its
// name in the logs. It returns the ended secrets.
func (s *Sweeper) sweepSecrets(ctx context.Context, name string,
	fn func(ctx context.Context) ([]store.EndedSecret, bool, error),
) ([]store.EndedSecret, error) {
	var all []store.EndedSecret
	var sweepErr error
	for {
		if err := ctx.Err(); err != nil {
			sweepErr = err
			break
		}
		ended, more, err := fn(ctx)
		all = append(all, ended...)
		if err != nil {
			sweepErr = fmt.Errorf("lifecycle: %s secrets: %w", name, err)
			break
		}
		// A full page of secrets that all changed meanwhile would be listed
		// again for ever: stop, the next run goes on.
		if !more || len(ended) == 0 {
			break
		}
	}
	if len(all) > 0 {
		for _, e := range all {
			s.removeSecretFile(ctx, e.Secret.TenantID, e.RemovedFile)
		}
		s.scrub(context.WithoutCancel(ctx))
		s.logger.InfoContext(ctx, "lifecycle: secrets swept", slog.String("sweep", name), slog.Int("secrets", len(all)))
	}
	return all, sweepErr
}

// removeSecretFile removes the file name of a secret of tid ("" is none).
// The key of the file is destroyed already, so a failure leaves only
// unreadable ciphertext: it is logged, not retried (the row is gone).
func (s *Sweeper) removeSecretFile(ctx context.Context, tid tenant.ID, name string) {
	if name == "" {
		return
	}
	if err := s.files.RemoveSecretFile(tid, name); err != nil {
		s.logger.WarnContext(ctx, "lifecycle: secret file left on disk",
			slog.String("tenant", string(tid)), slog.Any("error", err))
	}
}

// purgePendingSecrets deletes the secrets left pending since
// store.SecretPendingRetention (a creation that never completed).
func (s *Sweeper) purgePendingSecrets(ctx context.Context) error {
	_, err := s.sweepSecrets(ctx, "purge pending", func(ctx context.Context) ([]store.EndedSecret, bool, error) {
		return s.repo.purgePendingSecrets(ctx, s.now(), store.SecretSweepLimit)
	})
	return err
}

// expireSecrets expires the active secrets past their expiry and calls
// Options.SecretExpired with each of them, once its keys and file are gone.
func (s *Sweeper) expireSecrets(ctx context.Context) error {
	ended, err := s.sweepSecrets(ctx, "expire", func(ctx context.Context) ([]store.EndedSecret, bool, error) {
		return s.repo.expireSecrets(ctx, s.now(), store.SecretSweepLimit)
	})
	for _, e := range ended {
		s.recordSecretExpired(ctx, e.Secret)
		if s.secretExpired != nil {
			s.secretExpired(ctx, e)
		}
	}
	return err
}

// recordSecretExpired records secret.expired for sec, by the system actor.
// A failure is logged: the secret is expired already.
func (s *Sweeper) recordSecretExpired(ctx context.Context, sec store.Secret) {
	ev := audit.Event{
		TenantID: sec.TenantID, ActorKind: store.ActorSystem, Actor: SystemActor, Action: audit.ActionSecretExpired,
		ObjectKind: audit.ObjectSecret, ObjectID: sec.ID,
	}
	if err := s.repo.audit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "lifecycle: audit write failed", slog.String("action", string(audit.ActionSecretExpired)),
			slog.String("tenant", string(sec.TenantID)), slog.Any("error", err))
	}
}

// eraseTenantSecrets deletes every secret of tid with its keys, removes
// their files, and returns how many files the store reported. The tenant
// directory goes anyway; the removal is for the files of a directory
// that a later step could not delete.
func (s *Sweeper) eraseTenantSecrets(ctx context.Context, tid tenant.ID) (int, error) {
	files, err := s.repo.deleteTenantSecrets(ctx, tid)
	for _, name := range files {
		s.removeSecretFile(ctx, tid, name)
	}
	return len(files), err
}
