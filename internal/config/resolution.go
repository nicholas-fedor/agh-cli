// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Resolution is the outcome of resolving which configuration file a run uses.
//
// The path is always usable as a write destination, so a run with no
// configuration yet still knows where the first write belongs. Exists reports
// whether the file held content worth reading, which is false both when the file
// is absent and when it is blank, because a blank document carries nothing to
// read and is replaced by the first write.
type Resolution struct {
	// Path is the resolved configuration file path.
	Path string
	// Exists reports whether the file existed and held content to read.
	Exists bool
}

// localDir is the current-directory entry of the default search path.
//
// It lets a project pin its own configuration, and it is the only search entry
// that survives an unresolvable per-user configuration root.
const localDir = "."

// UserDir returns the per-user agh-cli configuration directory.
//
// Returns:
//   - string: absolute path of the per-user configuration directory.
//   - error: a wrapped error when the per-user configuration root is
//     unavailable.
func UserDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}

	return filepath.Join(root, DefaultConfigDirName), nil
}

// UserPath returns the per-user agh-cli configuration file path.
//
// Returns:
//   - string: absolute path of the per-user configuration file.
//   - error: a wrapped error when the per-user configuration root is
//     unavailable.
func UserPath() (string, error) {
	dir, err := UserDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config path: %w", err)
	}

	return filepath.Join(dir, DefaultConfigFileName), nil
}

// SearchPaths returns the default configuration file locations in priority
// order.
//
// The per-user location comes first, so a configuration created by the quickstart
// keeps applying no matter which directory the command runs from. The current
// directory is the fallback, which lets a project pin its own configuration. An
// unresolvable per-user root drops that entry instead of failing, leaving only
// the current directory.
//
// Each entry is an absolute candidate file, not a directory, so resolution can
// inspect it directly and a reported path is never ambiguous about which
// directory it refers to.
//
// Returns:
//   - []string: ordered absolute candidate configuration file paths.
func SearchPaths() []string {
	paths := make([]string, 0, 2)

	dir, err := UserDir()
	if err == nil {
		paths = append(paths, filepath.Join(dir, DefaultConfigFileName))
	}

	local, localErr := filepath.Abs(filepath.Join(localDir, DefaultConfigFileName))
	if localErr != nil {
		return paths
	}

	return append(paths, local)
}

// Resolve decides which configuration file a run uses.
//
// Resolution happens once per run, and the run loads the file it names with
// [Load]. Nothing else searches, because a second search could choose another
// file and make an explicit path behave differently from the default.
//
// An explicit path is used as given. A missing file is not an error, because the
// first write creates it, and a directory or another non-regular file is refused
// because it can never be a configuration document. Without an explicit path the
// default search locations are walked in order and the first file with content
// wins.
//
// Parameters:
//   - explicit: an operator-supplied path, or an empty string to search.
//
// Returns:
//   - Resolution: the path to use and whether it holds content to read.
//   - error: a wrapped error when an explicit path is not a usable file.
func Resolve(explicit string) (Resolution, error) {
	if explicit == "" {
		resolution, err := resolveSearch()
		if err != nil {
			return Resolution{}, fmt.Errorf("%w", err)
		}

		return resolution, nil
	}

	resolution, err := inspect(explicit)
	if err != nil {
		return Resolution{}, fmt.Errorf("%w", err)
	}

	return resolution, nil
}

// resolveSearch walks the default search locations in order and takes the
// first file that holds content.
//
// Returns:
//   - Resolution: the first readable configuration, otherwise the per-user
//     write target.
//   - error: a wrapped error when a search location exists but cannot be read.
func resolveSearch() (Resolution, error) {
	for _, path := range SearchPaths() {
		resolution, err := inspect(path)
		if err != nil {
			return Resolution{}, fmt.Errorf("%w", err)
		}

		// A location that simply has no file yet is not a failure, so the search
		// continues to the next one.
		if !resolution.Exists {
			continue
		}

		return resolution, nil
	}

	resolution, err := inspect(perUserWritePath())
	if err != nil {
		return Resolution{}, fmt.Errorf("%w", err)
	}

	return resolution, nil
}

// inspect decides whether one path holds a configuration document.
//
// The returned error already names the path, so it is passed through without
// adding a second mention of the same file.
//
// Parameters:
//   - path: filesystem path to inspect.
//
// Returns:
//   - Resolution: the path with its content state.
//   - error: a wrapped error when the path exists but is not a usable file.
func inspect(path string) (Resolution, error) {
	hasContent, err := HasContent(path)
	if err != nil {
		return Resolution{}, fmt.Errorf("%w", err)
	}

	return Resolution{Path: path, Exists: hasContent}, nil
}

// perUserWritePath returns the per-user path, or a bare name when the platform
// reports no configuration root.
//
// Returns:
//   - string: the per-user configuration path.
func perUserWritePath() string {
	userPath, err := UserPath()
	if err != nil {
		return DefaultConfigFileName
	}

	return userPath
}
