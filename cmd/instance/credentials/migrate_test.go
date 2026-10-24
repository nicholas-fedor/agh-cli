// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
)

// legacyDocument configures one instance with a legacy plaintext password.
const legacyDocument = "instances:\n" +
	"  default:\n" +
	"    host: adguard.example\n" +
	"    username: admin\n" +
	"    password: " + testSecret + "\n"

// TestRunMigratePreviewsWithoutWriting verifies that a dry run reports the change
// and writes neither the store nor the configuration.
func TestRunMigratePreviewsWithoutWriting(t *testing.T) {
	t.Parallel()

	path, store := migrationFixture(t)

	run := runCredentials(migrationContext(t, path, store), t, migrateCommandName, "--"+dryRunFlagName)

	require.NoError(t, run.err)
	assert.Equal(t,
		"would migrate \"default\" to keyring key \"default\"\n"+
			"backend: keyring\n"+
			"service: agh-cli\n"+
			"nothing was written: 1 credential(s) would be migrated\n",
		run.out,
	)
	assert.Contains(t, readFile(t, path), "password: "+testSecret)
}

// TestRunMigrateMovesThePassword verifies that a real run stores the password,
// removes it from the configuration, and never prints it.
func TestRunMigrateMovesThePassword(t *testing.T) {
	t.Parallel()

	path, store := migrationFixture(t)
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, testKeyringKey, testSecret).Return(nil).Once()

	run := runCredentials(migrationContext(t, path, store), t, migrateCommandName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, "migrated \"default\" to keyring key \"default\"")
	assert.Contains(t, run.out, "configuration updated: 1 credential(s) migrated")
	assert.NotContains(t, run.out+run.errOut, testSecret)
	assert.NotContains(t, readFile(t, path), testSecret)
}

// TestRunMigrateReportsStoreFailure verifies that a failed store write is
// reported, keeps the plaintext password, and never prints it.
func TestRunMigrateReportsStoreFailure(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("keyring is locked")

	path, store := migrationFixture(t)
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, testKeyringKey, testSecret).Return(storeErr).Once()

	run := runCredentials(migrationContext(t, path, store), t, migrateCommandName)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "migrate credentials")
	assert.Contains(t, run.out, "failed to migrate \"default\"")
	assert.NotContains(t, run.out+run.errOut+run.err.Error(), testSecret)
	assert.Contains(t, readFile(t, path), "password: "+testSecret)
}

// TestRunMigrateRejectsPositionalArguments verifies the published arity.
func TestRunMigrateRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	path, store := migrationFixture(t)

	run := runCredentials(migrationContext(t, path, store), t, migrateCommandName, testInstanceName)

	require.Error(t, run.err)
}

// migrationFixture writes the legacy document and returns a store that reports
// no credential under the migrated key.
//
// Returns:
//   - string: path of the configuration file.
//   - *mockCredentials.MockStore: the store, ready for write expectations.
func migrationFixture(t *testing.T) (string, *mockCredentials.MockStore) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(legacyDocument), 0o600))

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Maybe()
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, testKeyringKey).
		Return("", credentials.ErrNotFound).Maybe()

	return path, store
}

// migrationContext returns a context carrying the configuration file and store.
//
// Parameters:
//   - path: configuration file to load.
//   - store: credential store the migration reads and writes.
//
// Returns:
//   - [context.Context]: context carrying both.
func migrationContext(t *testing.T, path string, store credentials.Store) context.Context {
	t.Helper()

	return app.WithCredentialStore(apptest.FileContext(t, path), store)
}

// readFile returns the content of a file.
//
// Parameters:
//   - path: file to read.
//
// Returns:
//   - string: the file content.
func readFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return string(data)
}
