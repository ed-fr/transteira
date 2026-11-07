package upload

import (
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"strings"
)

// localFile is one file to send, as found on the disk.
type localFile struct {
	// Path is the absolute path.
	Path string `json:"path"`
	// Name is the base name and Folder the relative folder ("a/b"), empty
	// for a file given directly.
	Name   string `json:"name"`
	Folder string `json:"folder,omitempty"`
	// Size and ModTime (Unix nanoseconds) come from the walk.
	Size    int64 `json:"size"`
	ModTime int64 `json:"modTime"`
}

// display returns "folder/name".
func (f localFile) display() string {
	if f.Folder == "" {
		return f.Name
	}
	return f.Folder + "/" + f.Name
}

// collect walks the absolute paths and returns the regular files to send,
// in order: each argument in turn, directories in lexical order. Symbolic
// links, special files and duplicates are skipped and reported through
// warn; state files (StatePrefix) are skipped silently.
func collect(paths []string, warn func(string)) ([]localFile, error) {
	var files []localFile
	seen := map[string]bool{}
	add := func(path, folder string, info fs.FileInfo) {
		switch {
		case strings.HasPrefix(info.Name(), StatePrefix):
		case info.Mode()&fs.ModeSymlink != 0:
			warn(fmt.Sprintf("skipping the symbolic link %s", path))
		case !info.Mode().IsRegular():
			warn(fmt.Sprintf("skipping %s: not a regular file", path))
		case seen[path]:
			warn(fmt.Sprintf("skipping %s: already listed", path))
		default:
			seen[path] = true
			files = append(files, localFile{
				Path: path, Name: info.Name(), Folder: folder,
				Size: info.Size(), ModTime: info.ModTime().UnixNano(),
			})
		}
	}
	for _, root := range paths {
		info, err := os.Lstat(root)
		if err != nil {
			return nil, fmt.Errorf("upload: %w", err)
		}
		if !info.IsDir() {
			add(root, "", info)
			continue
		}
		parent := filepath.Dir(root)
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			add(path, folderOf(parent, path), info)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("upload: %w", err)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: no regular file to send", ErrInvalidOptions)
	}
	return files, nil
}

// folderOf returns the folder of path relative to parent, a prefix of
// path, with "/" separators: "" for a file directly in parent.
func folderOf(parent, path string) string {
	rel := strings.TrimLeft(path[len(parent):], string(filepath.Separator))
	folder := filepath.ToSlash(filepath.Dir(rel))
	if folder == "." {
		return ""
	}
	return folder
}

// mediaType guesses the media type of a file name from its extension,
// without parameters, or returns "".
func mediaType(name string) string {
	t, _, _ := strings.Cut(mime.TypeByExtension(filepath.Ext(name)), ";")
	return strings.TrimSpace(t)
}

// checkUnchanged returns ErrStateMismatch when the file at f.Path no
// longer has the size and modification time of f.
func checkUnchanged(f localFile) error {
	info, err := os.Stat(f.Path)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	if info.Size() != f.Size || info.ModTime().UnixNano() != f.ModTime {
		return fmt.Errorf("%w: %s was modified", ErrStateMismatch, f.Path)
	}
	return nil
}
