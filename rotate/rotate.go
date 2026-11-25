// Package rotate provides size-based rotating and channel-specific writers.
package rotate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Config controls rotation. Zero values select the documented defaults.
type Config struct {
	MaxSizeBytes  int64
	MaxFiles      int
	TotalCapBytes int64
}

// Writer appends records to a file, rotating before a write that exceeds the limit.
type Writer struct {
	mu     sync.Mutex
	path   string
	cfg    Config
	file   *os.File
	size   int64
	failed error
}

// New opens path for appending and constructs a rotating writer.
func New(path string, cfg Config) (*Writer, error) {
	if cfg.MaxSizeBytes == 0 {
		cfg.MaxSizeBytes = 8 << 20
	}
	if cfg.MaxFiles == 0 {
		cfg.MaxFiles = 5
	}
	if cfg.TotalCapBytes == 0 {
		cfg.TotalCapBytes = 64 << 20
	}
	if cfg.MaxSizeBytes < 0 || cfg.MaxFiles < 0 || cfg.TotalCapBytes < 0 {
		return nil, errors.New("rotate: negative configuration")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	w := &Writer{path: path, cfg: cfg, file: f, size: s.Size()}
	if err := w.pruneExtra(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if w.failed != nil {
		n, err := w.file.Write(p)
		w.size += int64(n)
		return n, errors.Join(w.failed, err)
	}
	if w.size > 0 && w.size+int64(len(p)) > w.cfg.MaxSizeBytes {
		if err := w.rotate(); err != nil {
			w.failed = err
			n, e := w.file.Write(p)
			w.size += int64(n)
			return n, errors.Join(err, e)
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	if err == nil {
		err = w.cap()
	}
	return n, err
}
func (w *Writer) rotate() error {
	if err := w.pruneExtra(); err != nil {
		return err
	}
	// Stage the active file first; retain its open descriptor on failure.
	tmp := w.path + ".rotate-tmp"
	if _, err := os.Lstat(tmp); err == nil {
		return fmt.Errorf("rotate: staging file exists: %s", tmp)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := os.Rename(w.path, tmp); err != nil {
		return err
	}
	rollback := func(err error) error { return errors.Join(err, os.Rename(tmp, w.path)) }
	for i := w.cfg.MaxFiles; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		if i == w.cfg.MaxFiles {
			if err := os.Remove(src); err != nil && !errors.Is(err, os.ErrNotExist) {
				return rollback(err)
			}
			continue
		}
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		if err := os.Rename(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return rollback(err)
		}
	}
	if err := os.Rename(tmp, w.path+".1"); err != nil {
		return rollback(err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = os.Rename(w.path+".1", w.path)
		return err
	}
	old := w.file
	w.file = f
	w.size = 0
	_ = old.Close()
	syncDir(filepath.Dir(w.path))
	return nil
}
func (w *Writer) pruneExtra() error {
	entries, err := os.ReadDir(filepath.Dir(w.path))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		n, ok := parseChain(entry.Name(), filepath.Base(w.path))
		if ok && n > w.cfg.MaxFiles {
			if err := os.Remove(filepath.Join(filepath.Dir(w.path), entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
func syncDir(path string) {
	d, err := os.Open(path)
	if err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
func (w *Writer) cap() error {
	total := w.size
	sizes := make([]int64, w.cfg.MaxFiles+1)
	for i := 1; i <= w.cfg.MaxFiles; i++ {
		s, e := os.Stat(fmt.Sprintf("%s.%d", w.path, i))
		if e == nil {
			sizes[i] = s.Size()
			total += s.Size()
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	for i := w.cfg.MaxFiles; i >= 1 && total > w.cfg.TotalCapBytes; i-- {
		if sizes[i] > 0 {
			if err := os.Remove(fmt.Sprintf("%s.%d", w.path, i)); err != nil {
				return err
			}
			total -= sizes[i]
		}
	}
	return nil
}

// Flush syncs the active file.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return os.ErrClosed
	}
	return w.file.Sync()
}

// Close syncs and closes the active file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return os.ErrClosed
	}
	err := errors.Join(w.file.Sync(), w.file.Close())
	w.file = nil
	return err
}

// parseChain parses a canonical positive archive suffix.
func parseChain(name, base string) (int, bool) {
	prefix := base + "."
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	suffix := strings.TrimPrefix(name, prefix)
	n, err := strconv.Atoi(suffix)
	return n, err == nil && n > 0 && strconv.Itoa(n) == suffix
}

var _ io.WriteCloser = (*Writer)(nil)
