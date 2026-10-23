// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TestCredentialsMigrateStoresBeforeClearingPlaintext verifies the credential
// store write precedes the plaintext removal, that the file is written once, and
// that the saved file carries no password.
func TestCredentialsMigrateStoresBeforeClearingPlaintext(t *testing.T) {
	t.Parallel()

	local := newConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").RunAndReturn(
		func(context.Context, string, string, string) error {
			// The plaintext password must still be configured while the store
			// write runs, so a failed write cannot lose it.
			assert.Equal(t, "alpha-secret", local.Instances()[alphaInstance].Password)

			return nil
		},
	).Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", zuluInstance, "zulu-secret").
		Return(nil).
		Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{})

	require.NoError(t, err)
	assert.Equal(t, 1, local.saves)
	assert.True(t, report.Saved)
	assert.False(t, report.DryRun)
	assert.Equal(t, []MigrationResult{
		{Instance: alphaInstance, Key: alphaInstance, Migrated: true},
		{Instance: zuluInstance, Key: zuluInstance, Migrated: true},
	}, report.Results)

	migrated := local.Instances()[alphaInstance]
	require.NotNil(t, migrated.Credential)
	assert.Equal(t, instance.KeyringSource, migrated.Credential.Source)
	assert.Equal(t, alphaInstance, migrated.Credential.Key)
	assert.Empty(t, migrated.Password)
	assert.NotContains(t, local.file(t), "alpha-secret")
	assert.NotContains(t, local.file(t), "zulu-secret")
}

// TestCredentialsMigrateReportsPartialOutcome verifies a failed store write
// leaves its plaintext password in place, still migrates the other instances, and
// reports a non-zero outcome.
func TestCredentialsMigrateReportsPartialOutcome(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("secret service locked")
	local := newConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(wantErr).Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", zuluInstance, "zulu-secret").
		Return(nil).
		Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{})

	require.ErrorIs(t, err, ErrPartialMigration)
	assert.True(t, report.Saved)
	require.NoError(t, report.Err)
	require.Len(t, report.Results, 2)
	require.ErrorIs(t, report.Results[0].Err, wantErr)
	assert.False(t, report.Results[0].Migrated)
	require.NoError(t, report.Results[1].Err)
	assert.True(t, report.Results[1].Migrated)

	failed := local.Instances()[alphaInstance]
	assert.Equal(t, "alpha-secret", failed.Password)
	assert.Nil(t, failed.Credential)
	assert.Contains(t, local.file(t), "alpha-secret")
	assert.Empty(t, local.Instances()[zuluInstance].Password)
}

// TestCredentialsMigrateSaveFailureLeavesPlaintextOnDisk verifies a failed
// configuration write is reported, keeps every password on disk, and stays safe to
// repeat.
func TestCredentialsMigrateSaveFailureLeavesPlaintextOnDisk(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")
	local := newConfig(t, plaintextConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", zuluInstance, "zulu-secret").
		Return(nil).
		Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{})

	require.ErrorIs(t, err, wantErr)
	assert.False(t, report.Saved)
	assert.Equal(t, 1, local.saves)
	require.Error(t, report.Err)
	require.Len(t, report.Results, 2)
	assert.True(t, report.Results[0].Migrated)
	assert.Contains(t, local.file(t), "alpha-secret")
	assert.Contains(t, local.file(t), "zulu-secret")
}

// TestCredentialsMigrateDryRunWritesNothing verifies a preview touches neither
// the credential store nor the configuration file.
func TestCredentialsMigrateDryRunWritesNothing(t *testing.T) {
	t.Parallel()

	local := newConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{DryRun: true})

	require.NoError(t, err)
	assert.True(t, report.DryRun)
	assert.False(t, report.Saved)
	assert.Equal(t, 0, local.saves)
	assert.Equal(t, []MigrationResult{
		{Instance: alphaInstance, Key: alphaInstance, DryRun: true},
		{Instance: zuluInstance, Key: zuluInstance, DryRun: true},
	}, report.Results)
	assert.Equal(t, "alpha-secret", local.Instances()[alphaInstance].Password)
	assert.NotContains(t, local.file(t), "source: keyring")
}

// TestCredentialsMigrateProbesStoreBeforeAnyWrite verifies an unavailable store
// aborts the migration before a single secret is offered to it.
func TestCredentialsMigrateProbesStoreBeforeAnyWrite(t *testing.T) {
	t.Parallel()

	local := newConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", ErrStoreUnavailable).
		Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{})

	require.ErrorIs(t, err, ErrStoreUnavailable)
	assert.Empty(t, report.Results)
	assert.Equal(t, 0, local.saves)
	assert.Equal(t, "alpha-secret", local.Instances()[alphaInstance].Password)
}

// TestCredentialsMigrateSkipsNonLegacyInstances verifies an explicit source and a
// missing password are both left untouched, so a configured source is never
// changed silently.
func TestCredentialsMigrateSkipsNonLegacyInstances(t *testing.T) {
	t.Parallel()

	local := newConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n"+
			"  stored:\n    host: stored.example.com\n"+
			"    credential:\n      source: keyring\n      key: admin\n"+
			"  explicit:\n    host: explicit.example.com\n"+
			"    password: explicit-secret\n"+
			"    credential:\n      source: plaintext\n"+
			"  empty:\n    host: empty.example.com\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{DryRun: true})

	require.NoError(t, err)
	assert.Empty(t, report.Results)
	assert.Equal(t, "explicit-secret", local.Instances()["explicit"].Password)
}

// TestCredentialsMigrateRefusesKeyInUse verifies a legacy password is not
// written under a key another instance already reads, so the migration never
// replaces that instance's password and the candidate keeps its plaintext one.
func TestCredentialsMigrateRefusesKeyInUse(t *testing.T) {
	t.Parallel()

	local := newConfig(t, "credentials:\n  service: agh-cli\n"+
		"instances:\n"+
		"  "+alphaInstance+":\n    host: alpha.example.com\n    password: alpha-secret\n"+
		"  "+zuluInstance+":\n    host: zulu.example.com\n"+
		"    credential:\n      source: keyring\n      key: "+alphaInstance+"\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("zulu-secret", nil).Once()

	report, err := NewManager(store, local).Migrate(t.Context(), MigrationRequest{DryRun: false})

	require.ErrorIs(t, err, ErrPartialMigration)
	require.Len(t, report.Results, 1)
	require.ErrorIs(t, report.Results[0].Err, ErrCredentialKeyInUse)
	assert.False(t, report.Results[0].Migrated)
	assert.NotContains(t, report.Results[0].Err.Error(), "secret")
	assert.Equal(t, "alpha-secret", local.Instances()[alphaInstance].Password)
	assert.Nil(t, local.Instances()[alphaInstance].Credential)
}
