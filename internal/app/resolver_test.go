// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// viperLock serializes the tests that read or write process-global Viper state.
var viperLock sync.Mutex

// lockViper isolates process-global Viper state for one test.
//
// The production resolver reads the credential namespace from Viper, so a test
// that inspects it must not observe another test's value. The global instance is
// reset before the test and after it, and the lock is released last.
func lockViper(t *testing.T) {
	t.Helper()

	viperLock.Lock()
	t.Cleanup(viperLock.Unlock)

	viper.Reset()
	t.Cleanup(viper.Reset)
}

// TestCredentialServiceUsesDefaultNamespace verifies an unset or empty namespace
// resolves to the default, because the credential namespace must never be empty.
func TestCredentialServiceUsesDefaultNamespace(t *testing.T) {
	t.Parallel()
	lockViper(t)

	assert.Equal(t, credentials.DefaultService, credentialService())

	viper.Set(viperCredentialServiceKey, "")

	assert.Equal(t, credentials.DefaultService, credentialService())
}

// TestCredentialServiceUsesConfiguredNamespace verifies the namespace comes from
// the loaded configuration, so a custom namespace is honored everywhere.
func TestCredentialServiceUsesConfiguredNamespace(t *testing.T) {
	t.Parallel()
	lockViper(t)
	viper.Set(viperCredentialServiceKey, "agh-cli-custom")

	assert.Equal(t, "agh-cli-custom", credentialService())
}

// TestNewCredentialResolverComposesProductionDependencies verifies the production
// resolver serves the process environment and mounted secret files through the
// operating system readers.
//
// Construction itself never probes the credential store, so this test also proves
// that assembling the resolver succeeds in a headless environment that has no
// credential store session. The test is serial because t.Setenv forbids a parallel
// test.
func TestNewCredentialResolverComposesProductionDependencies(t *testing.T) {
	lockViper(t)
	t.Setenv("AGH_CLI_TEST_PASSWORD", "environment-secret")

	secretPath := filepath.Join(t.TempDir(), "agh-secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("file-secret\n"), 0o600))

	resolver := NewCredentialResolver()
	require.NotNil(t, resolver)

	var _ instance.CredentialResolver = resolver

	fromEnv, err := resolver.Resolve(t.Context(), instance.Config{
		Name:       "scoped",
		Host:       "scoped.example.com",
		Scheme:     "https",
		Username:   "admin",
		Password:   "",
		Credential: &instance.CredentialRef{Source: instance.EnvSource, Env: "AGH_CLI_TEST_PASSWORD"},
	})

	require.NoError(t, err)
	assert.Equal(t, "environment-secret", fromEnv.Password)

	fromFile, err := resolver.Resolve(t.Context(), instance.Config{
		Name:       "mounted",
		Host:       "mounted.example.com",
		Scheme:     "https",
		Username:   "admin",
		Password:   "",
		Credential: &instance.CredentialRef{Source: instance.FileSource, Path: secretPath},
	})

	require.NoError(t, err)
	assert.Equal(t, "file-secret\n", fromFile.Password)
}

// TestNewCredentialResolverKeepsLegacyPlaintext verifies the production resolver
// leaves a configuration without a credential reference untouched, so an existing
// plaintext setup keeps working.
func TestNewCredentialResolverKeepsLegacyPlaintext(t *testing.T) {
	t.Parallel()
	lockViper(t)

	resolved, err := NewCredentialResolver().Resolve(t.Context(), instance.Config{
		Name:       "legacy",
		Host:       "legacy.example.com",
		Scheme:     "https",
		Username:   "admin",
		Password:   "legacy-secret",
		Credential: nil,
	})

	require.NoError(t, err)
	assert.Equal(t, "legacy-secret", resolved.Password)
}

// TestManagementFactoriesUseProductionResolver verifies every default management
// constructor binds the production resolver, the injectable constructors keep
// accepting a caller-supplied resolver, and a nil resolver stays pass-through.
func TestManagementFactoriesUseProductionResolver(t *testing.T) {
	t.Parallel()
	lockViper(t)

	store := mockCredentials.NewMockStore(t)
	supplied := credentials.NewResolver(
		"agh-cli-supplied",
		store,
		mockCredentials.NewMockFileReader(t),
		mockCredentials.NewMockEnvReader(t),
	)

	assert.NotNil(t, NewClientManagement().resolve)
	assert.NotNil(t, NewFilteringManagement().resolve)
	assert.NotNil(t, NewRewriteManagement().resolve)
	assert.Same(t, supplied, NewClientManagementWithResolver(supplied).resolve)
	assert.Same(t, supplied, NewFilteringManagementWithResolver(supplied).resolve)
	assert.Same(t, supplied, NewRewriteManagementWithResolver(supplied).resolve)

	client := &ClientManagement{}
	filtering := &FilteringManagement{}
	rewrite := &RewriteManagement{}

	assert.Nil(t, client.resolve)
	assert.Nil(t, filtering.resolve)
	assert.Nil(t, rewrite.resolve)
}
