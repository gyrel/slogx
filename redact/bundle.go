package redact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// FileStats records the number of uncompressed bytes and findings for an entry.
type FileStats struct {
	Path       string
	Bytes      int64
	Violations int
}

// BundleGuard scans all regular files in a zip or gzip-compressed tar archive.
// The caller must treat any error as a failed verification. The input and each
// uncompressed member are bounded to avoid unbounded allocation.
//
//nolint:gocognit,gocyclo,cyclop,nestif,funlen // Archive formats require distinct validation and error handling.
func BundleGuard(r io.Reader, opts Options) ([]Violation, []FileStats, error) {
	const limit = 64 << 20
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > limit {
		return nil, nil, errors.New("archive exceeds size limit")
	}
	var violations []Violation
	var stats []FileStats
	total := int64(0)
	scan := func(name string, src io.Reader) error {
		b, e := io.ReadAll(io.LimitReader(src, limit+1))
		if e != nil {
			return e
		}
		total += int64(len(b))
		if len(b) > limit || total > limit {
			return errors.New("uncompressed archive exceeds size limit")
		}
		found := Scan(b, opts)
		for i := range found {
			found[i].Path = name
		}
		violations = append(violations, found...)
		stats = append(stats, FileStats{Path: name, Bytes: int64(len(b)), Violations: len(found)})
		return nil
	}
	if len(data) >= 4 && (string(data[:4]) == "PK\x03\x04" || string(data[:4]) == "PK\x05\x06") {
		zr, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			return nil, nil, e
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if !f.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("unsupported archive entry %q", f.Name)
			}
			rc, e := f.Open()
			if e != nil {
				return nil, nil, e
			}
			e = scan(f.Name, rc)
			closeErr := rc.Close()
			if e != nil {
				return nil, nil, e
			}
			if closeErr != nil {
				return nil, nil, closeErr
			}
		}
		return violations, stats, nil
	}
	gz, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return nil, nil, e
	}
	defer gz.Close()
	expanded := &io.LimitedReader{R: gz, N: limit + 1}
	tr := tar.NewReader(expanded)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, nil, e
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, '\x00':
			if e = scan(h.Name, tr); e != nil {
				return nil, nil, e
			}
		default:
			return nil, nil, fmt.Errorf("unsupported archive entry %q", h.Name)
		}
	}
	// Consume the gzip trailer so checksum failures cannot be ignored.
	n, e := io.Copy(io.Discard, expanded)
	if e != nil {
		return nil, nil, e
	}
	if n > limit || expanded.N == 0 {
		return nil, nil, errors.New("archive trailer exceeds size limit")
	}
	return violations, stats, nil
}
