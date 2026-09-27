// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
)

// FileReader reads a credential from a read-only mounted secret file.
//
// A file source is not a second credential store. The file belongs to Docker,
// Kubernetes, systemd, Vault, or another external system, and agh-cli opens it
// read-only without ever writing, truncating, renaming, or changing its
// permissions. Docker and Kubernetes normally mount secrets below
// /run/secrets, so the mount and the container user are part of the trust
// boundary.
type FileReader interface {
	// Read returns the exact bytes of a mounted secret file.
	//
	// Implementations must not trim or normalize the returned bytes, because a
	// trailing newline is part of the stored secret when the external system
	// writes one.
	//
	// Parameters:
	//   - ctx: context checked before the file is opened.
	//   - path: absolute path of the mounted secret file.
	//
	// Returns:
	//   - []byte: the exact file bytes.
	//   - error: a project-owned error when the file is unusable. The error
	//     carries the path and never the file contents.
	Read(ctx context.Context, path string) ([]byte, error)
}

// EnvReader reads a credential from the process environment.
//
// Headless systems, SSH sessions, and containers have no operating system
// credential store session, so an instance may name an environment variable
// instead. An implementation returns the value of exactly the requested variable
// and never falls back to another source.
type EnvReader interface {
	// Lookup returns the value of one environment variable.
	//
	// Parameters:
	//   - name: environment variable name.
	//
	// Returns:
	//   - string: the variable value, or an empty string when it is unset.
	//   - bool: true when the variable is set, including when it is set to an
	//     empty value.
	Lookup(name string) (string, bool)
}

// External secret source errors.
var (
	// ErrFileNotAbsolute indicates that a file source path is relative.
	ErrFileNotAbsolute = errors.New("credential file path must be absolute")
	// ErrFileNotFound indicates that a mounted secret file is absent.
	ErrFileNotFound = errors.New("credential file does not exist")
	// ErrFileNotRegular indicates that a file source path is a directory, device,
	// socket, or another entry that is not a regular file.
	ErrFileNotRegular = errors.New("credential file is not a regular file")
	// ErrFileTooLarge indicates that a mounted secret file exceeds
	// MaxCredentialFileSize.
	ErrFileTooLarge = errors.New("credential file exceeds the size limit")
	// ErrFileUnreadable indicates that a mounted secret file cannot be opened or
	// read.
	ErrFileUnreadable = errors.New("credential file cannot be read")
	// ErrEnvUnset indicates that the configured credential environment variable
	// is not set. An unset variable is an error rather than a fallback.
	ErrEnvUnset = errors.New("credential environment variable is not set")
)
