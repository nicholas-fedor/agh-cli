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

// TestNewCredentialsCoordinatorUsesRunConfig verifies that the coordinator
// works on the configuration the run loaded.
func TestNewCredentialsCoordinatorUsesRunConfig(t *testing.T) {
	t.Parallel()

	ctx := runContext(t,
		"instances:\n"+
			"  default:\n    host: "+testConfigHost+"\n    password: "+testLegacyPassword+"\n",
	)

	coordinator, err := NewCredentialsCoordinator(ctx)
	require.NoError(t, err)
	require.NotNil(t, coordinator)

	// A legacy plaintext instance is decided from the configuration alone, so
	// this inspection never probes the operating system credential store.
	report, statusErr := coordinator.StatusPassword(t.Context(), []string{"default"})

	require.NoError(t, statusErr)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, instance.PlaintextSource, report.Instances[0].Source)
	assert.NotEmpty(t, report.Instances[0].Presence)
	assert.NotContains(t, report.Service, testLegacyPassword)
}

// TestNewCredentialsCoordinatorRequiresRunConfig verifies that a coordinator is
// never built without a loaded configuration.
func TestNewCredentialsCoordinatorRequiresRunConfig(t *testing.T) {
	t.Parallel()

	coordinator, err := NewCredentialsCoordinator(t.Context())

	require.ErrorIs(t, err, ErrNoRunConfig)
	assert.Nil(t, coordinator)
}
