// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// keyringHomeDocument is a configuration whose only instance reads its password
// from an explicit keyring key.
const keyringHomeDocument = "instances:\n" +
	"  home:\n" +
	"    host: " + testAlphaHost + "\n" +
	"    username: admin\n" +
	"    credential:\n" +
	"      source: keyring\n" +
	"      key: adguard-admin\n"

// TestSelectTargetsResolveExplicitCredentialSource verifies both target
// selection paths serve an explicit keyring source through the shared catalog
// resolution.
func TestSelectTargetsResolveExplicitCredentialSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// name identifies the subtest.
		name string
		// selectTargets applies one target selection path to the configuration.
		selectTargets func(
			context.Context,
			Selection,
			instance.CredentialResolver,
		) ([]execution.Target[instance.Config], error)
	}{
		{name: "selection order", selectTargets: selectTargets},
		{name: "configured order", selectTargets: selectOrderedTargets},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := mockCredentials.NewMockStore(t)
			store.EXPECT().
				Get(mock.Anything, "agh-cli", "adguard-admin").
				Return("keyring-secret", nil).
				Once()

			resolver := credentials.NewResolver(
				"agh-cli",
				store,
				mockCredentials.NewMockFileReader(t),
				mockCredentials.NewMockEnvReader(t),
			)

			ctx := runContext(t, keyringHomeDocument)

			selected, err := test.selectTargets(ctx, Selection{Names: nil, All: true}, resolver)

			require.NoError(t, err)
			require.Len(t, selected, 1)
			assert.Equal(t, "keyring-secret", selected[0].Value.Password)

			unresolved, err := test.selectTargets(ctx, Selection{Names: nil, All: true}, nil)

			require.NoError(t, err)
			require.Len(t, unresolved, 1)
			assert.Empty(t, unresolved[0].Value.Password)
		})
	}
}

// TestSelectTargetsReportCredentialFailure verifies an unreadable configured
// source fails the selection and names the instance.
func TestSelectTargetsReportCredentialFailure(t *testing.T) {
	t.Parallel()

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "adguard-admin").
		Return("", credentials.ErrStoreUnavailable).
		Once()

	resolver := credentials.NewResolver(
		"agh-cli",
		store,
		mockCredentials.NewMockFileReader(t),
		mockCredentials.NewMockEnvReader(t),
	)

	_, err := selectTargets(runContext(t, keyringHomeDocument), Selection{Names: nil, All: true}, resolver)

	require.ErrorIs(t, err, credentials.ErrStoreUnavailable)
	assert.ErrorContains(t, err, "home")
}

// TestStatusPasswordUsesRunConfig verifies that the credential use cases work on
// the configuration the run loaded, through the store the run attached.
func TestStatusPasswordUsesRunConfig(t *testing.T) {
	t.Parallel()

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Maybe()

	ctx := WithCredentialStore(runContext(t,
		"instances:\n"+
			"  default:\n    host: "+testConfigHost+"\n    password: "+testLegacyPassword+"\n",
	), store)

	// A legacy plaintext instance is decided from the configuration alone, so
	// this inspection never reads the store.
	report, err := StatusPassword(ctx, []string{"default"})

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, instance.PlaintextSource, report.Instances[0].Source)
	assert.NotContains(t, report.Service, testLegacyPassword)
}

// TestSetPasswordWritesTheRunStore verifies that a password reaches the store the
// run attached and that the instance is pointed at it.
func TestSetPasswordWritesTheRunStore(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances:\n  default:\n    host: "+testConfigHost+"\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, "default").Return("", credentials.ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, "default", "fresh-secret").Return(nil).Once()

	ctx := WithCredentialStore(contextWithConfigFile(t.Context(), t, configPath), store)

	result, err := SetPassword(ctx, "default", "", "fresh-secret")

	require.NoError(t, err)
	assert.Equal(t, "default", result.Key)
	assert.Contains(t, readTestConfig(t, configPath), "source: keyring")
	assert.NotContains(t, readTestConfig(t, configPath), "fresh-secret")
}

// TestUsernameUseCasesRewriteTheRunConfig verifies that a username is recorded,
// reported, and cleared in the configuration the run loaded.
func TestUsernameUseCasesRewriteTheRunConfig(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances:\n  default:\n    host: "+testConfigHost+"\n")
	ctx := WithCredentialStore(contextWithConfigFile(t.Context(), t, configPath), mockCredentials.NewMockStore(t))

	_, err := SetUsername(ctx, "default", "operator")
	require.NoError(t, err)
	assert.Contains(t, readTestConfig(t, configPath), "username: operator")

	report, err := StatusUsername(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, []credentials.UsernameStatus{{Instance: "default", Username: "operator"}}, report.Instances)

	_, err = ClearUsername(ctx, "default")
	require.NoError(t, err)
	assert.NotContains(t, readTestConfig(t, configPath), "operator")
}

// TestCredentialUseCasesRequireRunConfig verifies that no credential use case
// runs without a loaded configuration.
func TestCredentialUseCasesRequireRunConfig(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	_, migrateErr := MigrateCredentials(ctx, credentials.MigrationRequest{DryRun: true})
	_, setErr := SetPassword(ctx, "default", "", "secret")
	_, clearErr := ClearPassword(ctx, "default")
	_, clearAllErr := ClearAllPasswords(ctx)
	_, statusErr := StatusPassword(ctx, nil)
	_, setUsernameErr := SetUsername(ctx, "default", "operator")
	_, clearUsernameErr := ClearUsername(ctx, "default")
	_, statusUsernameErr := StatusUsername(ctx, nil)

	for _, err := range []error{
		migrateErr, setErr, clearErr, clearAllErr, statusErr, setUsernameErr, clearUsernameErr, statusUsernameErr,
	} {
		require.ErrorIs(t, err, ErrNoRunConfig)
	}
}

// TestCredentialStoreDefaultsToSystemStore verifies that a run without an
// attached store uses the operating system credential store, and that an
// attached store replaces it. Building the system store never contacts it.
func TestCredentialStoreDefaultsToSystemStore(t *testing.T) {
	t.Parallel()

	assert.IsType(t, &credentials.SystemStore{}, credentialStore(t.Context()))

	store := mockCredentials.NewMockStore(t)

	assert.Same(t, store, credentialStore(WithCredentialStore(t.Context(), store)))
}
