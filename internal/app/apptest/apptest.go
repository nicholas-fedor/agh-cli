// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apptest provides helpers for tests that execute commands against a
// configuration file.
//
// A command reads its configuration from the context the root command attaches
// it to. These helpers build that context from a document or a file, so a test
// can execute one command without the root command and without process-wide
// state.
//
// Every context carries a credential store, so a command under test never
// reaches the host credential store. The default store is a generated mock with
// no expectations, which fails the test on any call. A test that exercises the
// store supplies its own through [StoreContext].
package apptest

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
)

// Context returns a test context carrying the configuration document and a
// credential store that fails the test on any call.
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

	return StoreContext(t, document, mockCredentials.NewMockStore(t))
}

// StoreContext returns a test context carrying the configuration document and
// the supplied credential store.
//
// Parameters:
//   - document: complete YAML configuration document.
//   - store: credential store the commands under test read and write.
//
// Returns:
//   - [context.Context]: test context carrying the loaded configuration and the
//     store.
func StoreContext(t *testing.T, document string, store credentials.Store) context.Context {
	t.Helper()

	path := filepath.Join(t.TempDir(), config.DefaultConfigFileName)

	err := os.WriteFile(path, []byte(document), 0o600)
	if err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	return app.WithCredentialStore(loadFile(t, path), store)
}

// FileContext returns a test context carrying the configuration file at path
// and a credential store that fails the test on any call.
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

	return app.WithCredentialStore(loadFile(t, path), mockCredentials.NewMockStore(t))
}

// loadFile resolves and loads the configuration file at path as the root
// command does.
//
// Parameters:
//   - path: configuration file to load.
//
// Returns:
//   - [context.Context]: test context carrying the loaded configuration.
func loadFile(t *testing.T, path string) context.Context {
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
