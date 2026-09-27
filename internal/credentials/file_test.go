// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pathProvider prepares the path handed to the file reader under test.
type pathProvider func(t *testing.T) string

// secretFileMode is the mode of a mounted secret file created by a test.
const secretFileMode fs.FileMode = 0o600

// unreadableFileMode is the mode of a file a test makes unreadable.
const unreadableFileMode fs.FileMode = 0o000

// TestOSFileReaderPreservesExactBytes verifies that the reader returns the file
// bytes without trimming or normalizing them.
func TestOSFileReaderPreservesExactBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		contents string
	}{
		{
			name:     "password with trailing newline",
			contents: "secret\n",
		},
		{
			name:     "password without trailing newline",
			contents: "secret",
		},
		{
			name:     "empty file",
			contents: "",
		},
		{
			name:     "unicode password",
			contents: "p\u00e4ssw\u00f6rd-\U0001f510-caf\u00e9-\u65e5\u672c\u8a9e\n",
		},
		{
			name:     "password with interior newline",
			contents: "first\nsecond",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secretPath := writeSecretFile(t, test.contents)

			data, err := NewOSFileReader().Read(t.Context(), secretPath)

			require.NoError(t, err)
			assert.Equal(t, test.contents, string(data))
		})
	}
}

// TestOSFileReaderRejectsUnusablePaths verifies that a relative path and a path
// that is not a readable regular file are rejected.
func TestOSFileReaderRejectsUnusablePaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		prepare       pathProvider
		expectedError error
	}{
		{
			name:          "relative path",
			prepare:       staticSecretPath("secrets/agh-cli-default"),
			expectedError: ErrFileNotAbsolute,
		},
		{
			name:          "empty path",
			prepare:       staticSecretPath(""),
			expectedError: ErrFileNotAbsolute,
		},
		{
			name:          "directory",
			prepare:       temporaryDirectory,
			expectedError: ErrFileNotRegular,
		},
		{
			name:          "dangling symbolic link",
			prepare:       danglingSymlinkPath,
			expectedError: ErrFileNotFound,
		},
		{
			name:          "unreadable file",
			prepare:       unreadableFilePath,
			expectedError: ErrFileUnreadable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			data, err := NewOSFileReader().Read(t.Context(), test.prepare(t))

			require.ErrorIs(t, err, test.expectedError)
			assert.Nil(t, data)
			assert.NotContains(t, err2String(err), testSecret)
		})
	}
}

// TestOSFileReaderRejectsOversizedFile verifies that a file above the size limit
// is rejected without being read into memory.
func TestOSFileReaderRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	secretPath := writeSecretFile(t, strings.Repeat(testSecret, MaxCredentialFileSize))

	data, err := NewOSFileReader().Read(t.Context(), secretPath)

	require.ErrorIs(t, err, ErrFileTooLarge)
	assert.Nil(t, data)
	assert.NotContains(t, err2String(err), testSecret)
}

// TestReadCredentialFileRejectsOversizedContent verifies that the bounded reader
// rejects a file whose real length exceeds the limit.
func TestReadCredentialFileRejectsOversizedContent(t *testing.T) {
	t.Parallel()

	secretPath := writeSecretFile(t, strings.Repeat("a", MaxCredentialFileSize+1))

	data, err := readCredentialFile(secretPath)

	require.ErrorIs(t, err, ErrFileTooLarge)
	assert.Nil(t, data)
}

// TestReadCredentialFileAcceptsLimitSizeFile verifies that a file exactly at the
// size limit is accepted.
func TestReadCredentialFileAcceptsLimitSizeFile(t *testing.T) {
	t.Parallel()

	secretPath := writeSecretFile(t, strings.Repeat("a", MaxCredentialFileSize))

	data, err := readCredentialFile(secretPath)

	require.NoError(t, err)
	assert.Len(t, data, MaxCredentialFileSize)
}

// TestReadCredentialFileRejectsAbsentFile verifies that an open failure is
// classified before any content is read.
func TestReadCredentialFileRejectsAbsentFile(t *testing.T) {
	t.Parallel()

	data, err := readCredentialFile(danglingSymlinkPath(t))

	require.ErrorIs(t, err, ErrFileNotFound)
	assert.Nil(t, data)
}

// TestReadCredentialFileRejectsUnreadableEntry verifies that a read failure on
// an opened entry is reported instead of returning a partial secret.
func TestReadCredentialFileRejectsUnreadableEntry(t *testing.T) {
	t.Parallel()

	data, err := readCredentialFile(t.TempDir())

	require.ErrorIs(t, err, ErrFileUnreadable)
	assert.Nil(t, data)
}

// TestOSFileReaderChecksContextBeforeOpeningFile verifies that a done context
// stops the read before the filesystem is touched.
func TestOSFileReaderChecksContextBeforeOpeningFile(t *testing.T) {
	t.Parallel()

	secretPath := writeSecretFile(t, testSecret)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	data, err := NewOSFileReader().Read(ctx, secretPath)

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, data)
}

// TestOSFileReaderLeavesMountedFileUntouched verifies that a read never changes
// the mode, size, or contents of the mounted secret file.
func TestOSFileReaderLeavesMountedFileUntouched(t *testing.T) {
	t.Parallel()

	secretPath := writeSecretFile(t, testSecret)

	before, err := os.Stat(secretPath)
	require.NoError(t, err)

	_, err = NewOSFileReader().Read(t.Context(), secretPath)
	require.NoError(t, err)

	after, err := os.Stat(secretPath)
	require.NoError(t, err)

	assert.Equal(t, before.Mode(), after.Mode())
	assert.Equal(t, before.Size(), after.Size())

	contents, err := os.ReadFile(secretPath)
	require.NoError(t, err)
	assert.Equal(t, testSecret, string(contents))
}

// TestPathError verifies that operating system path errors are classified.
func TestPathError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		err           error
		expectedError error
	}{
		{
			name:          "absent file",
			err:           fs.ErrNotExist,
			expectedError: ErrFileNotFound,
		},
		{
			name:          "permission denied",
			err:           fs.ErrPermission,
			expectedError: ErrFileUnreadable,
		},
		{
			name:          "symbolic link loop",
			err:           errors.New("too many levels of symbolic links"),
			expectedError: ErrFileUnreadable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := pathError(test.err)

			require.ErrorIs(t, err, test.expectedError)
			assert.ErrorIs(t, err, test.err)
		})
	}
}

// TestSizeError verifies that an oversized file error names the limit.
func TestSizeError(t *testing.T) {
	t.Parallel()

	err := sizeError(MaxCredentialFileSize + 1)

	require.ErrorIs(t, err, ErrFileTooLarge)
	assert.ErrorContains(t, err, strconv.Itoa(MaxCredentialFileSize))
}

// danglingSymlinkPath returns a symbolic link whose target does not exist.
//
// Parameters:
//   - t: test handle used to create the link.
//
// Returns:
//   - string: absolute path of the dangling symbolic link.
func danglingSymlinkPath(t *testing.T) string {
	t.Helper()

	link := filepath.Join(t.TempDir(), "dangling")
	target := filepath.Join(t.TempDir(), "absent")

	err := os.Symlink(target, link)
	if err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}

	return link
}

// staticSecretPath returns a fixed path without touching the filesystem.
//
// Parameters:
//   - filePath: path returned to the reader under test.
//
// Returns:
//   - pathProvider: provider of the fixed path.
func staticSecretPath(filePath string) pathProvider {
	return func(t *testing.T) string {
		t.Helper()

		return filePath
	}
}

// temporaryDirectory returns an absolute path of an existing directory.
//
// Parameters:
//   - t: test handle used to create the directory.
//
// Returns:
//   - string: absolute path of the directory.
func temporaryDirectory(t *testing.T) string {
	t.Helper()

	return t.TempDir()
}

// unreadableFilePath returns a path of a file the process cannot read.
//
// Parameters:
//   - t: test handle used to create the file.
//
// Returns:
//   - string: absolute path of the unreadable file.
func unreadableFilePath(t *testing.T) string {
	t.Helper()

	secretPath := writeSecretFile(t, testSecret)

	err := os.Chmod(secretPath, unreadableFileMode)
	if err != nil {
		t.Skipf("file modes are unavailable: %v", err)
	}

	_, err = NewOSFileReader().Read(t.Context(), secretPath)
	if err == nil {
		t.Skip("the platform does not enforce the file mode")
	}

	return secretPath
}

// writeSecretFile writes one mounted secret file and returns its path.
//
// Parameters:
//   - t: test handle used to create the file.
//   - contents: exact file contents.
//
// Returns:
//   - string: absolute path of the created file.
func writeSecretFile(t *testing.T, contents string) string {
	t.Helper()

	secretPath := filepath.Join(t.TempDir(), "agh-cli-default")
	require.NoError(t, os.WriteFile(secretPath, []byte(contents), secretFileMode))

	return secretPath
}
