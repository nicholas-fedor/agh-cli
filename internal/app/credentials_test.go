// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// fakeCredentialConfig wraps a loaded configuration manager so a test can count
// persistence attempts and force a save failure without a filesystem error.
type fakeCredentialConfig struct {
	*config.Manager

	// path is the configuration file the manager writes to.
	path string
	// saveErr is returned by Save when it is set.
	saveErr error
	// saves counts the Save calls made by the coordinator.
	saves int
}

// fakeCredentialConfig satisfies the credential configuration contract.
var _ CredentialConfig = (*fakeCredentialConfig)(nil)

// Save records the attempt and honors a forced failure.
func (c *fakeCredentialConfig) Save() error {
	c.saves++

	if c.saveErr != nil {
		return c.saveErr
	}

	return c.Manager.Save()
}

// file returns the current contents of the configuration file.
func (c *fakeCredentialConfig) file(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(c.path)
	require.NoError(t, err)

	return string(data)
}

// newCredentialConfig writes a configuration file and loads it into a fake.
//
// Parameters:
//   - t: test context and temporary directory provider.
//   - body: complete YAML configuration document.
//
// Returns:
//   - *fakeCredentialConfig: loaded configuration with a counted save.
func newCredentialConfig(t *testing.T, body string) *fakeCredentialConfig {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	manager, err := config.Load(path)
	require.NoError(t, err)

	return &fakeCredentialConfig{Manager: manager, path: path}
}

// plaintextConfig returns a configuration with two legacy plaintext instances.
func plaintextConfig() string {
	return "credentials:\n  service: agh-cli\n" +
		"instances:\n" +
		"  alpha:\n    host: alpha.example.com\n    username: admin\n" +
		"    password: alpha-secret\n" +
		"  zulu:\n    host: zulu.example.com\n    password: zulu-secret\n"
}

// TestCredentialsMigrateStoresBeforeClearingPlaintext verifies the credential
// store write precedes the plaintext removal, that the file is written once, and
// that the saved file carries no password.
func TestCredentialsMigrateStoresBeforeClearingPlaintext(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", credentials.ErrNotFound).Once()
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

	report, err := NewCredentials(store, local).Migrate(t.Context(), MigrationRequest{})

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
	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", credentials.ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(wantErr).Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", zuluInstance, "zulu-secret").
		Return(nil).
		Once()

	report, err := NewCredentials(store, local).Migrate(t.Context(), MigrationRequest{})

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

// TestCredentialsSetPasswordKeepsKeySharedByAnotherInstance verifies a rollback
// does not delete a key another instance still references. A key is not exclusive
// to one instance, so removing the entry this use case wrote would destroy a
// working password belonging to a different instance.
func TestCredentialsSetPasswordKeepsKeySharedByAnotherInstance(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")

	// alpha carries no reference of its own, while zulu already points at the
	// key this use case is about to write. The written instance therefore does not
	// reference the key, but the key is still reachable through zulu.
	local := newCredentialConfig(t, "credentials:\n  service: agh-cli\n"+
		"instances:\n"+
		"  "+alphaInstance+":\n    host: alpha.example.com\n    username: admin\n"+
		"  "+zuluInstance+":\n    host: zulu.example.com\n    username: admin\n"+
		"    credential:\n      source: keyring\n      key: "+alphaInstance+"\n")

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("old", nil).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()

	// No Delete is expected: zulu still references the key, so removing it would
	// break zulu.
	_, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.ErrorIs(t, err, wantErr)
	require.NotErrorIs(t, err, ErrOrphanedCredential)
	assert.Contains(t, err.Error(), "was replaced")
}

// TestCredentialsSetPasswordRemovesNewCredentialWhenConfigSaveFails verifies a
// store write whose configuration write failed is undone. The configuration
// still points at nothing, so leaving the entry behind would create a secret no
// command reports and no command uses.
func TestCredentialsSetPasswordRemovesNewCredentialWhenConfigSaveFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")
	local := newCredentialConfig(t, plaintextConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", credentials.ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()
	store.EXPECT().Delete(mock.Anything, "agh-cli", alphaInstance).Return(nil).Once()

	_, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.ErrorIs(t, err, wantErr)
	require.NotErrorIs(t, err, ErrOrphanedCredential)
	assert.Contains(t, err.Error(), "was removed again")
}

// TestCredentialsSetPasswordOrphansKeyThatNoInstanceReferences verifies the
// orphan test is the configuration, not the store. Here the store already holds
// an entry at the written key, so the write replaced it, yet no instance
// references that key. Nothing can reach the entry, so it is removed again and
// reported as an orphan.
func TestCredentialsSetPasswordOrphansKeyThatNoInstanceReferences(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")

	// alpha carries no credential reference, so the entry written under its own
	// name is unreachable even though the store already holds one.
	local := newCredentialConfig(t, plaintextConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("old", nil).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()
	store.EXPECT().
		Delete(mock.Anything, "agh-cli", alphaInstance).
		Return(errors.New("store locked")).
		Once()

	_, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.ErrorIs(t, err, wantErr)
	require.ErrorIs(t, err, ErrOrphanedCredential)
	assert.Contains(t, err.Error(), "no configured instance references it")
}

// TestCredentialsSetPasswordReportsOrphanWhenRollbackFails verifies a rollback
// that cannot complete is reported with the key, so the leftover entry is
// discoverable instead of invisible.
func TestCredentialsSetPasswordReportsOrphanWhenRollbackFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")

	local := newCredentialConfig(t, plaintextConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", credentials.ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()
	store.EXPECT().
		Delete(mock.Anything, "agh-cli", alphaInstance).
		Return(errors.New("store locked")).
		Once()

	_, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.ErrorIs(t, err, wantErr)
	require.ErrorIs(t, err, ErrOrphanedCredential)
	assert.Contains(t, err.Error(), alphaInstance)
}

// TestCredentialsSetPasswordKeepsReferencedCredentialWhenConfigSaveFails
// verifies a key the configuration already referenced is not deleted. The file
// on disk still points at that key, so removing the entry would leave a live
// reference to nothing. The leftover is not an orphan, and the failure says so.
func TestCredentialsSetPasswordKeepsReferencedCredentialWhenConfigSaveFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")

	local := newCredentialConfig(t, keyringConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("old-secret", nil).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()

	_, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.ErrorIs(t, err, wantErr)
	require.NotErrorIs(t, err, ErrOrphanedCredential)
	assert.Contains(t, err.Error(), "was replaced")
	assert.Contains(t, err.Error(), alphaInstance)
}

// TestCredentialsMigrateSaveFailureLeavesPlaintextOnDisk verifies a failed
// configuration write is reported, keeps every password on disk, and stays safe to
// repeat.
func TestCredentialsMigrateSaveFailureLeavesPlaintextOnDisk(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")
	local := newCredentialConfig(t, plaintextConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("", credentials.ErrNotFound).Once()
	store.EXPECT().Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").Return(nil).Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", zuluInstance, "zulu-secret").
		Return(nil).
		Once()

	report, err := NewCredentials(store, local).Migrate(t.Context(), MigrationRequest{})

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

	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()

	report, err := NewCredentials(store, local).Migrate(t.Context(), MigrationRequest{DryRun: true})

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

	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrStoreUnavailable).
		Once()

	report, err := NewCredentials(store, local).Migrate(t.Context(), MigrationRequest{})

	require.ErrorIs(t, err, credentials.ErrStoreUnavailable)
	assert.Empty(t, report.Results)
	assert.Equal(t, 0, local.saves)
	assert.Equal(t, "alpha-secret", local.Instances()[alphaInstance].Password)
}

// TestCredentialsMigrateSkipsNonLegacyInstances verifies an explicit source and a
// missing password are both left untouched, so a configured source is never
// changed silently.
func TestCredentialsMigrateSkipsNonLegacyInstances(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n"+
			"  stored:\n    host: stored.example.com\n"+
			"    credential:\n      source: keyring\n      key: admin\n"+
			"  explicit:\n    host: explicit.example.com\n"+
			"    password: explicit-secret\n"+
			"    credential:\n      source: plaintext\n"+
			"  empty:\n    host: empty.example.com\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()

	report, err := NewCredentials(store, local).Migrate(t.Context(), MigrationRequest{DryRun: true})

	require.NoError(t, err)
	assert.Empty(t, report.Results)
	assert.Equal(t, "explicit-secret", local.Instances()["explicit"].Password)
}

// TestCredentialsSetResolvesCredentialKey verifies the key precedence of set: an
// explicit key wins, a configured keyring key is reused, and an instance without
// either falls back to its name.
func TestCredentialsSetResolvesCredentialKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// name identifies the subtest.
		name string
		// credential is the raw instance credential stanza, or an empty string.
		credential string
		// key is the explicit key requested by the caller.
		key string
		// wantKey is the expected credential key.
		wantKey string
	}{
		{
			name:    "instance name default",
			wantKey: alphaInstance,
		},
		{
			name:       "configured keyring key reused",
			credential: "    credential:\n      source: keyring\n      key: adguard-admin\n",
			wantKey:    "adguard-admin",
		},
		{
			name:       "explicit key wins",
			credential: "    credential:\n      source: keyring\n      key: adguard-admin\n",
			key:        "rotation-key",
			wantKey:    "rotation-key",
		},
		{
			name:    "explicit key without configured source",
			key:     "rotation-key",
			wantKey: "rotation-key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			local := newCredentialConfig(t,
				"credentials:\n  service: agh-cli\n"+
					"instances:\n  alpha:\n    host: alpha.example.com\n"+
					test.credential)

			store := mockCredentials.NewMockStore(t)
			store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
			store.EXPECT().
				Get(mock.Anything, "agh-cli", test.wantKey).
				Return("", credentials.ErrNotFound).
				Once()
			store.EXPECT().
				Set(mock.Anything, "agh-cli", test.wantKey, "new-secret").
				Return(nil).
				Once()

			result, err := NewCredentials(store, local).SetPassword(
				t.Context(),
				alphaInstance,
				test.key,
				"new-secret",
			)

			require.NoError(t, err)
			assert.Equal(t, PasswordSetResult{
				Instance: alphaInstance,
				Backend:  credentials.KeyringBackend,
				Service:  "agh-cli",
				Key:      test.wantKey,
				Replaced: false,
				Saved:    true,
			}, result)
			assert.Equal(t, 1, local.saves)

			stored := local.Instances()[alphaInstance]
			require.NotNil(t, stored.Credential)
			assert.Equal(t, instance.KeyringSource, stored.Credential.Source)
			assert.Equal(t, test.wantKey, stored.Credential.Key)
			assert.Empty(t, stored.Password)
		})
	}
}

// TestCredentialsSetReportsReplacedCredential verifies a rotation is detected
// before the write and that the stored value never appears in the result.
func TestCredentialsSetReportsReplacedCredential(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("previous-secret", nil).
		Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", alphaInstance, "new-secret").
		Return(nil).
		Once()

	result, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"new-secret",
	)

	require.NoError(t, err)
	assert.True(t, result.Replaced)
	assert.True(t, result.Saved)
	assert.NotContains(t, fmt.Sprintf("%+v", result), "new-secret")
	assert.NotContains(t, fmt.Sprintf("%+v", result), "previous-secret")
}

// TestCredentialsSetRejectsUnknownInstance verifies a credential key belonging to
// no configured instance is refused, so the store cannot collect orphan secrets.
func TestCredentialsSetRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, plaintextConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		"missing",
		"",
		"new-secret",
	)

	require.ErrorIs(t, err, config.ErrInstanceNotFound)
	assert.Empty(t, result)
}

// TestCredentialsSetReportsStoreFailure verifies a rejected write is reported
// without the secret.
func TestCredentialsSetReportsStoreFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("platform set: locked")
	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrNotFound).
		Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", alphaInstance, "new-secret").
		Return(wantErr).
		Once()

	_, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"new-secret",
	)

	require.ErrorIs(t, err, wantErr)
	assert.NotContains(t, err.Error(), "new-secret")
	assert.Equal(t, 0, local.saves)
	assert.Equal(t, "alpha-secret", local.Instances()[alphaInstance].Password)
	assert.Nil(t, local.Instances()[alphaInstance].Credential)
}

// TestCredentialsSetUsernameRecordsConfiguration verifies a username is written
// to the configuration file and the credential store is never consulted.
func TestCredentialsSetUsernameRecordsConfiguration(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewCredentials(store, local).SetUsername(alphaInstance, "new-admin")

	require.NoError(t, err)
	assert.Equal(t, alphaInstance, result.Instance)
	assert.Equal(t, "new-admin", result.Username)
	assert.True(t, result.Saved)
	assert.Equal(t, 1, local.saves)
	assert.Equal(t, "new-admin", local.Instances()[alphaInstance].Username)
	assert.Contains(t, local.file(t), "username: new-admin")
}

// TestCredentialsSetUsernameKeepsCredentialReference verifies changing a
// username does not detach the instance from its credential source, because the
// username and the password are managed independently.
func TestCredentialsSetUsernameKeepsCredentialReference(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	_, err := NewCredentials(store, local).SetUsername(alphaInstance, "new-admin")

	require.NoError(t, err)

	cfg := local.Instances()[alphaInstance]
	require.NotNil(t, cfg.Credential)
	assert.Equal(t, instance.KeyringSource, cfg.Credential.Source)
	assert.Equal(t, alphaInstance, cfg.Credential.Key)
}

// TestCredentialsSetUsernameRejectsUnknownInstance verifies a username is only
// recorded for a configured instance.
func TestCredentialsSetUsernameRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewCredentials(store, local).SetUsername("missing", "new-admin")

	require.ErrorIs(t, err, config.ErrInstanceNotFound)
	assert.Empty(t, result)
	assert.Equal(t, 0, local.saves)
}

// TestCredentialsSetUsernameReportsSaveFailure verifies a failed configuration
// write is reported even though the in-memory change was accepted.
func TestCredentialsSetUsernameReportsSaveFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("disk full")
	local := newCredentialConfig(t, keyringConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)

	_, err := NewCredentials(store, local).SetUsername(alphaInstance, "new-admin")

	require.ErrorIs(t, err, wantErr)
}

// TestCredentialsClearUsernameRemovesOnlyUsername verifies clearing a username
// leaves a stored credential reference in place, so a working password survives.
func TestCredentialsClearUsernameRemovesOnlyUsername(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewCredentials(store, local).ClearUsername(alphaInstance)

	require.NoError(t, err)
	assert.Equal(t, alphaInstance, result.Instance)
	assert.Empty(t, result.Username)
	assert.True(t, result.Saved)
	assert.Equal(t, 1, local.saves)
	assert.Empty(t, local.Instances()[alphaInstance].Username)
	require.NotNil(t, local.Instances()[alphaInstance].Credential)
	assert.Equal(t, instance.KeyringSource, local.Instances()[alphaInstance].Credential.Source)
}

// TestCredentialsClearUsernameIsIdempotent verifies repeating the clear is safe,
// because an instance without a username is already in the target state.
func TestCredentialsClearUsernameIsIdempotent(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, "credentials:\n  service: agh-cli\n"+
		"instances:\n  alpha:\n    host: alpha.example.com\n    password: alpha-secret\n")
	store := mockCredentials.NewMockStore(t)

	coordinator := NewCredentials(store, local)

	first, err := coordinator.ClearUsername(alphaInstance)
	require.NoError(t, err)

	second, err := coordinator.ClearUsername(alphaInstance)
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Empty(t, local.Instances()[alphaInstance].Username)
}

// TestCredentialsClearUsernameRejectsUnknownInstance verifies the clear names a
// configured instance.
func TestCredentialsClearUsernameRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewCredentials(store, local).ClearUsername("missing")

	require.ErrorIs(t, err, config.ErrInstanceNotFound)
	assert.Empty(t, result)
	assert.Equal(t, 0, local.saves)
}

// TestCredentialsStatusUsernameReportsUsername verifies the username read path
// reports the configured value, because a username is configuration rather than a
// secret. The credential store is never consulted to answer it.
func TestCredentialsStatusUsernameReportsUsername(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	report, err := NewCredentials(store, local).StatusUsername([]string{alphaInstance})

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, alphaInstance, report.Instances[0].Instance)
	assert.Equal(t, "admin", report.Instances[0].Username)
}

// TestCredentialsStatusUsernameOmitsUnsetUsername verifies an instance without a
// username reports an empty value rather than a placeholder.
func TestCredentialsStatusUsernameOmitsUnsetUsername(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, "credentials:\n  service: agh-cli\n"+
		"instances:\n  alpha:\n    host: alpha.example.com\n    password: alpha-secret\n")
	store := mockCredentials.NewMockStore(t)

	report, err := NewCredentials(store, local).StatusUsername([]string{alphaInstance})

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Empty(t, report.Instances[0].Username)
}

// TestCredentialsStatusUsernameRejectsUnknownInstance verifies the read path names
// a configured instance.
func TestCredentialsStatusUsernameRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	_, err := NewCredentials(store, local).StatusUsername([]string{"missing"})

	require.ErrorIs(t, err, config.ErrInstanceNotFound)
}

// TestCredentialsStatusPasswordOmitsUsername verifies the password report carries
// no username, because the two halves of instance authentication are reported
// separately.
func TestCredentialsStatusPasswordOmitsUsername(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("alpha-secret", nil).
		Once()

	report, err := NewCredentials(store, local).StatusPassword(
		t.Context(),
		[]string{alphaInstance},
	)

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, alphaInstance, report.Instances[0].Instance)
	assert.Equal(t, instance.KeyringSource, report.Instances[0].Source)
}

// keyringConfig returns a configuration whose instances already reference the
// credential store.
func keyringConfig() string {
	return "credentials:\n  service: agh-cli\n" +
		"instances:\n" +
		"  alpha:\n    host: alpha.example.com\n    username: admin\n" +
		"    credential:\n      source: keyring\n      key: " + alphaInstance + "\n" +
		"  zulu:\n    host: zulu.example.com\n    username: admin\n" +
		"    credential:\n      source: keyring\n      key: " + zuluInstance + "\n"
}

// TestCredentialsClearRemovesReferenceAfterDeletingEntry verifies the credential
// store entry is deleted before the configuration reference is dropped, so the
// configuration never stops pointing at a secret that still exists.
func TestCredentialsClearRemovesReferenceAfterDeletingEntry(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("stored-secret", nil).
		Once()
	store.EXPECT().Delete(mock.Anything, "agh-cli", alphaInstance).RunAndReturn(
		func(context.Context, string, string) error {
			// The reference must still be configured while the entry is deleted.
			require.NotNil(t, local.Instances()[alphaInstance].Credential)

			return nil
		},
	).Once()

	result, err := NewCredentials(store, local).ClearPassword(t.Context(), alphaInstance)

	require.NoError(t, err)
	assert.Equal(t, PasswordClearResult{
		Instance: alphaInstance,
		Service:  "agh-cli",
		Key:      alphaInstance,
		Removed:  true,
		Saved:    true,
	}, result)
	assert.Equal(t, 1, local.saves)
	assert.Nil(t, local.Instances()[alphaInstance].Credential)
	assert.NotNil(t, local.Instances()[zuluInstance].Credential)
	assert.NotContains(t, local.file(t), "source: keyring\n      key: "+alphaInstance)
}

// TestCredentialsClearTreatsAbsentCredentialAsCleared verifies clearing an absent
// credential succeeds without a delete, so a repeated clear stays safe and the
// reference is still removed.
func TestCredentialsClearTreatsAbsentCredentialAsCleared(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrNotFound).
		Once()

	result, err := NewCredentials(store, local).ClearPassword(t.Context(), alphaInstance)

	require.NoError(t, err)
	assert.Equal(t, PasswordClearResult{
		Instance: alphaInstance,
		Service:  "agh-cli",
		Key:      alphaInstance,
		Removed:  false,
		Saved:    true,
	}, result)
	assert.Nil(t, local.Instances()[alphaInstance].Credential)
	assert.Equal(t, 1, local.saves)
}

// TestCredentialsClearIsIdempotent verifies clearing twice converges, so a
// repeated clear never fails and never reports a removal the second time.
func TestCredentialsClearIsIdempotent(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("stored-secret", nil).
		Once()
	store.EXPECT().Delete(mock.Anything, "agh-cli", alphaInstance).Return(nil).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrNotFound).
		Once()

	coordinator := NewCredentials(store, local)

	first, err := coordinator.ClearPassword(t.Context(), alphaInstance)
	require.NoError(t, err)
	assert.True(t, first.Removed)
	assert.True(t, first.Saved)

	second, err := coordinator.ClearPassword(t.Context(), alphaInstance)
	require.NoError(t, err)
	assert.False(t, second.Removed)
	assert.True(t, second.Saved)
	assert.Equal(t, 2, local.saves)
}

// TestCredentialsClearSaveFailureKeepsReferenceOnDisk verifies a failed
// configuration write is reported while the file keeps its credential reference,
// and that a repeated clear converges.
func TestCredentialsClearSaveFailureKeepsReferenceOnDisk(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")
	local := newCredentialConfig(t, keyringConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("stored-secret", nil).
		Once()
	store.EXPECT().Delete(mock.Anything, "agh-cli", alphaInstance).Return(nil).Once()

	result, err := NewCredentials(store, local).ClearPassword(t.Context(), alphaInstance)

	require.ErrorIs(t, err, wantErr)
	assert.True(t, result.Removed)
	assert.False(t, result.Saved)
	assert.Contains(t, local.file(t), "source: keyring")

	local.saveErr = nil

	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrNotFound).
		Once()

	retry, err := NewCredentials(store, local).ClearPassword(t.Context(), alphaInstance)

	require.NoError(t, err)
	assert.False(t, retry.Removed)
	assert.True(t, retry.Saved)
	assert.NotContains(t, local.file(t), "source: keyring\n      key: "+alphaInstance)
}

// TestCredentialsSetStoresBeforeUpdatingConfig verifies the credential store write
// happens before the configuration changes, that the instance ends up referencing
// the resolved key without a password, and that the file is written once.
func TestCredentialsSetStoresBeforeUpdatingConfig(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, plaintextConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrNotFound).
		Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").
		RunAndReturn(func(context.Context, string, string, string) error {
			// The instance must still be legacy while the store write runs, so a
			// failed write cannot lose the plaintext password.
			pending := local.Instances()[alphaInstance]
			assert.Equal(t, "alpha-secret", pending.Password)
			assert.Nil(t, pending.Credential)

			return nil
		}).
		Once()

	result, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.NoError(t, err)
	assert.Equal(t, PasswordSetResult{
		Instance: alphaInstance,
		Backend:  credentials.KeyringBackend,
		Service:  "agh-cli",
		Key:      alphaInstance,
		Replaced: false,
		Saved:    true,
	}, result)
	assert.Equal(t, 1, local.saves)

	migrated := local.Instances()[alphaInstance]
	require.NotNil(t, migrated.Credential)
	assert.Equal(t, instance.KeyringSource, migrated.Credential.Source)
	assert.Equal(t, alphaInstance, migrated.Credential.Key)
	assert.Empty(t, migrated.Password)
	assert.NotContains(t, local.file(t), "alpha-secret")
	assert.NotContains(t, local.file(t), "username: admin\n    password:")
	assert.Contains(t, local.file(t), "source: keyring\n      key: "+alphaInstance)
	// The untouched instance keeps its own legacy password.
	assert.Contains(t, local.file(t), "password: zulu-secret")
}

// TestCredentialsSetSaveFailureLeavesPlaintextOnDisk verifies a failed
// configuration write keeps the plaintext password on disk, reports the failure
// without the secret, and converges when repeated.
func TestCredentialsSetSaveFailureLeavesPlaintextOnDisk(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read-only filesystem")
	local := newCredentialConfig(t, plaintextConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("", credentials.ErrNotFound).
		Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").
		Return(nil).
		Once()
	// The new entry is rolled back, because the configuration still points at
	// nothing and an unreferenced secret is worse than no write at all.
	store.EXPECT().
		Delete(mock.Anything, "agh-cli", alphaInstance).
		Return(nil).
		Once()

	result, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.ErrorIs(t, err, wantErr)
	assert.NotContains(t, err.Error(), "alpha-secret")
	assert.False(t, result.Replaced)
	assert.False(t, result.Saved)
	assert.Equal(t, 1, local.saves)
	assert.Contains(t, local.file(t), "alpha-secret")

	local.saveErr = nil

	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("alpha-secret", nil).
		Once()
	store.EXPECT().
		Set(mock.Anything, "agh-cli", alphaInstance, "alpha-secret").
		Return(nil).
		Once()

	retry, err := NewCredentials(store, local).SetPassword(
		t.Context(),
		alphaInstance,
		"",
		"alpha-secret",
	)

	require.NoError(t, err)
	assert.True(t, retry.Replaced)
	assert.True(t, retry.Saved)
	assert.Equal(t, 2, local.saves)
	assert.NotContains(t, local.file(t), "alpha-secret")
}

// TestCredentialsClearRefusesExternalCredentialSource verifies clearing an
// environment or mounted-file instance is refused with the project-owned error
// before the credential store or the configuration is touched.
//
// The store mock records no call, so any store access fails the test, and the
// configuration is compared against its pre-clear state.
func TestCredentialsClearRefusesExternalCredentialSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// name identifies the subtest.
		name string
		// instance is the instance name under test.
		instance string
		// stanza is the credential reference the instance declares.
		stanza string
		// wantSource is the source named in the reported error.
		wantSource instance.CredentialSource
		// wantStanza is the serialized reference that must survive.
		wantStanza string
	}{
		{
			name:       "environment source",
			instance:   "scoped",
			stanza:     "    credential:\n      source: env\n      env: AGH_CLI_PASSWORD\n",
			wantSource: instance.EnvSource,
			wantStanza: "source: env",
		},
		{
			name:       "mounted file source",
			instance:   "mounted",
			stanza:     "    credential:\n      source: file\n      path: /run/secrets/agh\n",
			wantSource: instance.FileSource,
			wantStanza: "path: /run/secrets/agh",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			local := newCredentialConfig(t,
				"credentials:\n  service: agh-cli\n"+
					"instances:\n  "+test.instance+":\n"+
					"    host: "+test.instance+".example.com\n"+
					test.stanza)
			before := local.file(t)

			// No store expectation is registered, so any store call fails.
			store := mockCredentials.NewMockStore(t)

			result, err := NewCredentials(store, local).ClearPassword(t.Context(), test.instance)

			require.ErrorIs(t, err, ErrExternalCredentialSource)
			require.ErrorContains(t, err, string(test.wantSource))
			require.ErrorContains(t, err, test.instance)
			assert.Empty(t, result)
			assert.Equal(t, 0, local.saves)
			assert.Equal(t, before, local.file(t))

			unchanged := local.Instances()[test.instance]
			require.NotNil(t, unchanged.Credential)
			assert.Equal(t, test.wantSource, unchanged.Credential.Source)
		})
	}
}

// TestCredentialsClearAllowsManagedCredentialSources verifies a keyring, an
// explicit plaintext instance, and a legacy instance without a credential
// reference stay clearable after the external-source guard.
func TestCredentialsClearAllowsManagedCredentialSources(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n"+
			"  "+alphaInstance+":\n    host: alpha.example.com\n"+
			"    credential:\n      source: keyring\n      key: "+alphaInstance+"\n"+
			"  explicit:\n    host: explicit.example.com\n"+
			"    credential:\n      source: plaintext\n"+
			"  legacy:\n    host: legacy.example.com\n    password: legacy-secret\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("stored-secret", nil).
		Once()
	store.EXPECT().Delete(mock.Anything, "agh-cli", alphaInstance).Return(nil).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "explicit").
		Return("", credentials.ErrNotFound).
		Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "legacy").
		Return("", credentials.ErrNotFound).
		Once()

	coordinator := NewCredentials(store, local)

	keyring, err := coordinator.ClearPassword(t.Context(), alphaInstance)
	require.NoError(t, err)
	assert.True(t, keyring.Removed)
	assert.True(t, keyring.Saved)

	explicit, err := coordinator.ClearPassword(t.Context(), "explicit")
	require.NoError(t, err)
	assert.False(t, explicit.Removed)
	assert.True(t, explicit.Saved)

	legacy, err := coordinator.ClearPassword(t.Context(), "legacy")
	require.NoError(t, err)
	assert.Equal(t, "legacy", legacy.Key)
	assert.False(t, legacy.Removed)
	assert.True(t, legacy.Saved)

	assert.Equal(t, 3, local.saves)
	assert.Nil(t, local.Instances()[alphaInstance].Credential)
	assert.Nil(t, local.Instances()["explicit"].Credential)
	assert.Equal(t, "legacy-secret", local.Instances()["legacy"].Password)
}

// TestCredentialsClearAllStaysInsideService verifies a service-wide clear is
// scoped to the configured namespace and leaves the configuration alone.
func TestCredentialsClearAllStaysInsideService(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, keyringConfig())

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().DeleteAll(mock.Anything, "agh-cli").Return(nil).Once()

	result, err := NewCredentials(store, local).ClearAllPasswords(t.Context())

	require.NoError(t, err)
	assert.Equal(t, PasswordClearResult{Service: "agh-cli", Removed: true, All: true}, result)
	assert.Equal(t, 0, local.saves)
	require.NotNil(t, local.Instances()[alphaInstance].Credential)
}

// TestCredentialsClearRejectsUnknownInstance verifies clearing an unconfigured
// instance is refused before the store is touched.
func TestCredentialsClearRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, plaintextConfig())
	store := mockCredentials.NewMockStore(t)

	_, err := NewCredentials(store, local).ClearPassword(t.Context(), "missing")

	require.ErrorIs(t, err, config.ErrInstanceNotFound)
}

// TestCredentialsStatusReportsPresencePerNamedInstance verifies status reports the
// backend, the service, and per-instance presence without enumerating the store or
// returning a secret.
func TestCredentialsStatusReportsPresencePerNamedInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n"+
			"  legacy:\n    host: legacy.example.com\n    password: legacy-secret\n"+
			"  bare:\n    host: bare.example.com\n"+
			"  stored:\n    host: stored.example.com\n"+
			"    credential:\n      source: keyring\n      key: stored-key\n"+
			"  missing:\n    host: missing.example.com\n"+
			"    credential:\n      source: keyring\n      key: missing-key\n"+
			"  mounted:\n    host: mounted.example.com\n"+
			"    credential:\n      source: file\n      path: /run/secrets/agh\n"+
			"  scoped:\n    host: scoped.example.com\n"+
			"    credential:\n      source: env\n      env: AGH_CLI_PASSWORD\n"+
			"  anonymous:\n    host: anonymous.example.com\n"+
			"    credential:\n      source: none\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "stored-key").
		Return("keyring-secret", nil).
		Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "missing-key").
		Return("", credentials.ErrNotFound).
		Once()

	result, err := NewCredentials(store, local).StatusPassword(t.Context(), nil)

	require.NoError(t, err)
	assert.True(t, result.Available)
	assert.Equal(t, credentials.KeyringBackend, result.Backend)
	assert.Equal(t, "agh-cli", result.Service)
	assert.Equal(t, []PasswordStatus{
		{Instance: "legacy", Source: instance.PlaintextSource, Presence: PresencePresent},
		{Instance: "bare", Source: instance.PlaintextSource, Presence: PresenceAbsent},
		{
			Instance: "stored",
			Source:   instance.KeyringSource,
			Target:   "stored-key",
			Presence: PresencePresent,
		},
		{
			Instance: "missing",
			Source:   instance.KeyringSource,
			Target:   "missing-key",
			Presence: PresenceAbsent,
		},
		{
			Instance: "mounted",
			Source:   instance.FileSource,
			Target:   "/run/secrets/agh",
			Presence: PresenceUnknown,
		},
		{
			Instance: "scoped",
			Source:   instance.EnvSource,
			Target:   "AGH_CLI_PASSWORD",
			Presence: PresenceUnknown,
		},
		{Instance: "anonymous", Source: instance.NoneSource, Presence: PresenceAbsent},
	}, result.Instances)

	reported := fmt.Sprintf("%+v", result)
	assert.NotContains(t, reported, "legacy-secret")
	assert.NotContains(t, reported, "keyring-secret")
}

// TestCredentialsStatusReportsUnavailableStore verifies a failed probe leaves
// presence unknown instead of reporting an absent credential.
func TestCredentialsStatusReportsUnavailableStore(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n  stored:\n    host: stored.example.com\n"+
			"    credential:\n      source: keyring\n      key: stored-key\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "stored-key").
		Return("", credentials.ErrStoreUnavailable).
		Once()

	result, err := NewCredentials(store, local).StatusPassword(t.Context(), []string{"stored"})

	require.NoError(t, err)
	assert.False(t, result.Available)
	require.Len(t, result.Instances, 1)
	assert.Equal(t, PresenceUnknown, result.Instances[0].Presence)
	assert.ErrorIs(t, result.Instances[0].Err, credentials.ErrStoreUnavailable)
}

// TestCredentialsStatusRejectsUnknownInstance verifies a requested name outside the
// configuration is refused before the store is read.
func TestCredentialsStatusRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t, plaintextConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewCredentials(store, local).StatusPassword(t.Context(), []string{"missing"})

	require.ErrorIs(t, err, config.ErrInstanceNotFound)
	assert.Empty(t, result.Instances)
}

// TestCredentialsUsesConfiguredService verifies the configured namespace is used
// instead of the default one.
func TestCredentialsUsesConfiguredService(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t,
		"credentials:\n  service: agh-cli-custom\n"+
			"instances:\n  alpha:\n    host: alpha.example.com\n"+
			"    password: alpha-secret\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().DeleteAll(mock.Anything, "agh-cli-custom").Return(nil).Once()

	result, err := NewCredentials(store, local).ClearAllPasswords(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "agh-cli-custom", result.Service)
}

// TestCredentialsFallsBackToDefaultService verifies an empty configured namespace
// resolves to the default one, because the namespace must never be empty.
func TestCredentialsFallsBackToDefaultService(t *testing.T) {
	t.Parallel()

	local := newCredentialConfig(t,
		"credentials:\n  service: \"\"\n"+
			"instances:\n  alpha:\n    host: alpha.example.com\n"+
			"    password: alpha-secret\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().DeleteAll(mock.Anything, credentials.DefaultService).Return(nil).Once()

	result, err := NewCredentials(store, local).ClearAllPasswords(t.Context())

	require.NoError(t, err)
	assert.Equal(t, credentials.DefaultService, result.Service)
}

// TestCredentialsReportsStoreFailures verifies an unusable store is reported for
// every write and clear instead of being reported as an absent credential.
func TestCredentialsReportsStoreFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// name identifies the subtest.
		name string
		// expect registers the credential store expectations.
		expect func(*mockCredentials.MockStore)
		// run applies one use case that must fail.
		run func(context.Context, *Credentials) error
	}{
		{
			name: "set probe failure",
			expect: func(store *mockCredentials.MockStore) {
				store.EXPECT().
					Get(mock.Anything, "agh-cli", alphaInstance).
					Return("", credentials.ErrStoreUnavailable).
					Once()
			},
			run: func(ctx context.Context, coordinator *Credentials) error {
				_, err := coordinator.SetPassword(ctx, alphaInstance, "", "new-secret")

				return err
			},
		},
		{
			name: "clear delete failure",
			expect: func(store *mockCredentials.MockStore) {
				store.EXPECT().
					Get(mock.Anything, "agh-cli", alphaInstance).
					Return("stored-secret", nil).
					Once()
				store.EXPECT().
					Delete(mock.Anything, "agh-cli", alphaInstance).
					Return(errors.New("platform delete: locked")).
					Once()
			},
			run: func(ctx context.Context, coordinator *Credentials) error {
				_, err := coordinator.ClearPassword(ctx, alphaInstance)

				return err
			},
		},
		{
			name: "clear all failure",
			expect: func(store *mockCredentials.MockStore) {
				store.EXPECT().
					DeleteAll(mock.Anything, "agh-cli").
					Return(errors.New("platform delete all: locked")).
					Once()
			},
			run: func(ctx context.Context, coordinator *Credentials) error {
				_, err := coordinator.ClearAllPasswords(ctx)

				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			local := newCredentialConfig(t, plaintextConfig())
			store := mockCredentials.NewMockStore(t)
			test.expect(store)

			err := test.run(t.Context(), NewCredentials(store, local))

			require.Error(t, err)
			assert.NotContains(t, err.Error(), "alpha-secret")
		})
	}
}

// TestManagementCatalogsResolveExplicitCredentialSource verifies the client,
// filtering, and rewrite selection paths all serve an explicit keyring source
// through the shared catalog resolution.
func TestManagementCatalogsResolveExplicitCredentialSource(t *testing.T) {
	t.Parallel()

	raw := instance.Source{
		"home": map[string]any{
			"host":     testAlphaHost,
			"username": "admin",
			"credential": map[string]any{
				"source": "keyring",
				"key":    "adguard-admin",
			},
		},
	}

	tests := []struct {
		// name identifies the subtest.
		name string
		// select applies one management selection path to the raw mapping.
		selectConfig func(
			context.Context,
			instance.CredentialResolver,
		) ([]instance.Config, error)
	}{
		{
			name: "client",
			selectConfig: func(
				ctx context.Context,
				resolve instance.CredentialResolver,
			) ([]instance.Config, error) {
				targets, err := clientTargets(
					ctx,
					ClientSelection{Instances: raw, All: true},
					resolve,
				)
				if err != nil {
					return nil, err
				}

				configs := make([]instance.Config, 0, len(targets))
				for _, target := range targets {
					configs = append(configs, target.Value)
				}

				return configs, nil
			},
		},
		{
			name: "filtering",
			selectConfig: func(
				ctx context.Context,
				resolve instance.CredentialResolver,
			) ([]instance.Config, error) {
				return filteringSelectedConfigs(
					ctx,
					FilteringSelection{Instances: raw, All: true},
					resolve,
				)
			},
		},
		{
			name: "rewrite",
			selectConfig: func(
				ctx context.Context,
				resolve instance.CredentialResolver,
			) ([]instance.Config, error) {
				return rewriteSelectedConfigs(
					ctx,
					RewriteSelection{Instances: raw, All: true},
					resolve,
				)
			},
		},
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

			selected, err := test.selectConfig(t.Context(), resolver)

			require.NoError(t, err)
			require.Len(t, selected, 1)
			assert.Equal(t, "keyring-secret", selected[0].Password)

			unresolved, err := test.selectConfig(t.Context(), nil)

			require.NoError(t, err)
			require.Len(t, unresolved, 1)
			assert.Empty(t, unresolved[0].Password)
		})
	}
}

// TestManagementCatalogsReportCredentialFailure verifies an unreadable configured
// source fails the selection and names the instance.
func TestManagementCatalogsReportCredentialFailure(t *testing.T) {
	t.Parallel()

	raw := instance.Source{
		"home": map[string]any{
			"host": testAlphaHost,
			"credential": map[string]any{
				"source": "keyring",
				"key":    "adguard-admin",
			},
		},
	}

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

	_, err := clientTargets(
		t.Context(),
		ClientSelection{Instances: raw, All: true},
		resolver,
	)

	require.ErrorIs(t, err, credentials.ErrStoreUnavailable)
	assert.ErrorContains(t, err, "home")
}
