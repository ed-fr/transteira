package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ed-fr/transteira/internal/tenant"
)

// KindSecretFile is a stored file of a one-time secret
// (<tenantID>/secrets/<name>), listed by [Store.ListSecretFiles] only.
const KindSecretFile Kind = KindAsset + 1

// secretPath returns the path of the secret file name of tid, relative to
// the data directory.
func secretPath(tid tenant.ID, name string) string {
	return filepath.Join(string(tid), secretsDir, name)
}

// ensureSecretsDir creates the tenant directory and its secrets
// subdirectory if they do not exist.
func (s *Store) ensureSecretsDir(tid tenant.ID) error {
	if err := s.ensureTenantDir(tid); err != nil {
		return err
	}
	err := s.ops.mkdir(filepath.Join(string(tid), secretsDir), DirMode)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return wrap("create secrets directory", "", err)
	}
	return nil
}

// CreateSecretFile creates, for writing, the file name of a one-time secret
// of tenant tid (<tenantID>/secrets/<name>), creating the directories on
// demand. An existing file of that name (the leftover of an interrupted
// upload, whose key is gone) is truncated: the caller serializes the
// uploads of a secret (store.Secrets.UploadFile refuses a concurrent one).
func (s *Store) CreateSecretFile(tid tenant.ID, name string) (*os.File, error) {
	if err := check(tid, name); err != nil {
		return nil, err
	}
	if err := s.ensureSecretsDir(tid); err != nil {
		return nil, err
	}
	f, err := s.ops.openFile(secretPath(tid, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, FileMode)
	if err != nil {
		return nil, wrap("create secret file", name, err)
	}
	return f, nil
}

// OpenSecretFile opens the file name of a one-time secret of tenant tid for
// reading and returns its size. It fails with ErrNotFound when the file is
// missing and with ErrInvalid when it is not a regular file.
func (s *Store) OpenSecretFile(tid tenant.ID, name string) (*os.File, int64, error) {
	if err := check(tid, name); err != nil {
		return nil, 0, err
	}
	f, info, err := s.openRegular("open secret file", secretPath(tid, name), name, os.O_RDONLY)
	if err != nil {
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// ListSecretFiles returns the entries of the secrets subdirectory of tenant
// tid, in directory order: a regular file with a well-formed storage name
// is a KindSecretFile, anything else a KindUnknown (reported, never
// followed nor removed). A missing directory yields an empty list; a
// directory replaced by a symbolic link or another entry is refused with
// ErrInvalid. An entry removed while it runs is omitted.
func (s *Store) ListSecretFiles(tid tenant.ID) ([]Entry, error) {
	if tid.Validate() != nil {
		return nil, fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	dir := filepath.Join(string(tid), secretsDir)
	info, err := s.ops.lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, wrap("list secret files", "", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("storage: list secret files: %w: secrets directory is not a directory", ErrInvalid)
	}
	entries, err := s.readDirChecked(dir, info)
	if errors.Is(err, ErrNotFound) { // removed since lstat
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		file := e.Name()
		fi, err := s.ops.lstat(filepath.Join(dir, file))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, wrap("list secret files", "", err)
		}
		ent := Entry{Name: file, File: file, Kind: KindUnknown, ModTime: fi.ModTime(), Size: fi.Size()}
		if fi.Mode().IsRegular() && ValidName(file) {
			ent.Kind = KindSecretFile
		}
		out = append(out, ent)
	}
	return out, nil
}
