// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// OSFileReader reads mounted secret files from the operating system.
//
// The reader requires an absolute path to a regular file, checks the context
// before opening the file, and reads through a bounded reader. It never writes,
// truncates, renames, or changes permissions, so a file owned by Docker,
// Kubernetes, systemd, or Vault is never modified by agh-cli.
type OSFileReader struct{}

// MaxCredentialFileSize is the largest mounted secret file the reader accepts.
//
// The limit bounds the memory a hostile or misconfigured mount can make the
// process allocate, and it is far above any AdGuard Home password. A file
// exactly at the limit is accepted; a larger file is rejected before its
// contents are read.
const MaxCredentialFileSize = 64 << 10

// NewOSFileReader creates a mounted secret file reader.
//
// Returns:
//   - *OSFileReader: reader for absolute, regular secret files.
func NewOSFileReader() *OSFileReader {
	return &OSFileReader{}
}

// Read returns the exact bytes of an absolute, regular secret file.
//
// Parameters:
//   - ctx: context checked before the file is inspected.
//   - filePath: absolute path of the mounted secret file.
//
// Returns:
//   - []byte: the exact file bytes, including any trailing newline.
//   - error: a wrapped ErrFileNotAbsolute, ErrFileNotFound, ErrFileNotRegular,
//     ErrFileTooLarge, or ErrFileUnreadable error. The error carries the path and
//     never the file contents.
func (*OSFileReader) Read(ctx context.Context, filePath string) ([]byte, error) {
	err := ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("read credential file %q: %w", filePath, err)
	}

	if !filepath.IsAbs(filePath) {
		return nil, fmt.Errorf("read credential file %q: %w", filePath, ErrFileNotAbsolute)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("read credential file %q: %w", filePath, pathError(err))
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"read credential file %q: %w: mode is %s",
			filePath,
			ErrFileNotRegular,
			info.Mode(),
		)
	}

	if info.Size() > MaxCredentialFileSize {
		return nil, fmt.Errorf(
			"read credential file %q: %w",
			filePath,
			sizeError(info.Size()),
		)
	}

	data, err := readCredentialFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return data, nil
}

// pathError classifies an operating system path error.
//
// The operating system message carries the path, which is configuration rather
// than secret material, and never the file contents.
//
// Parameters:
//   - err: error returned while inspecting or opening the file.
//
// Returns:
//   - error: ErrFileNotFound when the file is absent, or ErrFileUnreadable.
func pathError(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrFileNotFound, err)
	}

	return fmt.Errorf("%w: %w", ErrFileUnreadable, err)
}

// readCredentialFile reads a credential file through a bounded reader.
//
// The reader never buffers more than one byte beyond MaxCredentialFileSize, so a
// file that grew, or that reported a size it does not have, is still rejected
// instead of being loaded into memory in full.
//
// Parameters:
//   - filePath: absolute path of the mounted secret file.
//
// Returns:
//   - []byte: the exact file bytes.
//   - error: a wrapped ErrFileNotFound, ErrFileTooLarge, or ErrFileUnreadable
//     error carrying the path but never the file contents.
func readCredentialFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("read credential file %q: %w", filePath, pathError(err))
	}

	defer func() {
		_ = file.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(file, MaxCredentialFileSize+1))
	if err != nil {
		return nil, fmt.Errorf(
			"read credential file %q: %w: %w",
			filePath,
			ErrFileUnreadable,
			err,
		)
	}

	if len(data) > MaxCredentialFileSize {
		return nil, fmt.Errorf(
			"read credential file %q: %w",
			filePath,
			sizeError(int64(len(data))),
		)
	}

	return data, nil
}

// sizeError reports a mounted secret file that exceeds the size limit.
//
// Parameters:
//   - size: observed file size in bytes.
//
// Returns:
//   - error: ErrFileTooLarge naming the observed size and the limit.
func sizeError(size int64) error {
	return fmt.Errorf(
		"%w: %d bytes exceeds the %d byte limit",
		ErrFileTooLarge,
		size,
		MaxCredentialFileSize,
	)
}
