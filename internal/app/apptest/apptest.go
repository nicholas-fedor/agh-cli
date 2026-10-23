// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apptest provides helpers for tests that execute commands against a
// configuration file.
//
// A command reads its configuration from the context the root command attaches
// it to. These helpers build that context from a document or a file, so a test
// can execute one command without the root command and without process-wide
// state.
package apptest

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// Context returns a test context carrying the configuration document.
//
// The document is written to a private configuration file under the test's
// temporary directory, so a command that writes the configuration changes only
// that file.
//
// Parameters:
//   - document: complete YAML configuration document.
//
// Returns:
//   - [context.Context]: test context carrying the loaded configuration.
func Context(t *testing.T, document string) context.Context {
	t.Helper()

	path := filepath.Join(t.TempDir(), app.DefaultConfigFileName)

	err := os.WriteFile(path, []byte(document), 0o600)
	if err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	return FileContext(t, path)
}

// FileContext returns a test context carrying the configuration file at path.
//
// The file is resolved and loaded as the root command does, so a missing or
// blank file is an empty configuration that the first write creates.
//
// Parameters:
//   - path: configuration file to load.
//
// Returns:
//   - [context.Context]: test context carrying the loaded configuration.
func FileContext(t *testing.T, path string) context.Context {
	t.Helper()

	resolution, err := app.ResolveConfigPath(path)
	if err != nil {
		t.Fatalf("resolve test configuration: %v", err)
	}

	runConfig, err := app.LoadRunConfig(resolution, io.Discard)
	if err != nil {
		t.Fatalf("load test configuration: %v", err)
	}

	return app.WithRunConfig(t.Context(), runConfig)
}
