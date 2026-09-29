// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
)

// ErrConfigNotRegular indicates that a configuration path exists but is not a
// regular file, so it can never be a configuration document.
var ErrConfigNotRegular = fmt.Errorf(
	"config path is not a regular file: %w",
	fs.ErrInvalid,
)

// ErrConfigUnreadable indicates that a configuration path exists but cannot be
// inspected.
var ErrConfigUnreadable = fmt.Errorf("config file is unreadable: %w", fs.ErrPermission)

// HasContent reports whether the configuration document at path exists and holds
// content worth reading.
//
// A document whose bytes are entirely whitespace is empty, whatever produced the
// whitespace. YAML forbids a tab as indentation, so a file holding only a tab is
// a parse error rather than an empty document; reporting it as empty is what
// keeps a stray tab from blocking every command. A file holding only a comment
// does have content, and is parsed normally.
//
// A path that is absent is reported as having no content rather than as an
// error, because the first write creates the file. A path that exists but cannot
// be inspected is an error, so a permissions problem is never mistaken for an
// empty document.
//
// Parameters:
//   - path: filesystem path of the YAML configuration file.
//
// Returns:
//   - bool: true when the file exists and holds content.
//   - error: a wrapped error when the path exists but is not a readable regular
//     file.
func HasContent(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, fmt.Errorf("inspect config %q: %w", path, ErrConfigUnreadable)
	}

	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("inspect config %q: %w", path, ErrConfigNotRegular)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("inspect config %q: %w", path, ErrConfigUnreadable)
	}

	return len(bytes.TrimSpace(data)) > 0, nil
}
