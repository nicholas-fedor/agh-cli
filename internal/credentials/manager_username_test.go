// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TestCredentialsSetUsernameRecordsConfiguration verifies a username is written
// to the configuration file and the credential store is never consulted.
func TestCredentialsSetUsernameRecordsConfiguration(t *testing.T) {
	t.Parallel()

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewManager(store, local).SetUsername(alphaInstance, "new-admin")

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

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	_, err := NewManager(store, local).SetUsername(alphaInstance, "new-admin")

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

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewManager(store, local).SetUsername("missing", "new-admin")

	require.ErrorIs(t, err, instance.ErrUnknownInstance)
	assert.Empty(t, result)
	assert.Equal(t, 0, local.saves)
}

// TestCredentialsSetUsernameReportsSaveFailure verifies a failed configuration
// write is reported even though the in-memory change was accepted.
func TestCredentialsSetUsernameReportsSaveFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("disk full")
	local := newConfig(t, keyringConfig())

	local.saveErr = wantErr

	store := mockCredentials.NewMockStore(t)

	_, err := NewManager(store, local).SetUsername(alphaInstance, "new-admin")

	require.ErrorIs(t, err, wantErr)
}

// TestCredentialsClearUsernameRemovesOnlyUsername verifies clearing a username
// leaves a stored credential reference in place, so a working password survives.
func TestCredentialsClearUsernameRemovesOnlyUsername(t *testing.T) {
	t.Parallel()

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewManager(store, local).ClearUsername(alphaInstance)

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

	local := newConfig(t, "credentials:\n  service: agh-cli\n"+
		"instances:\n  alpha:\n    host: alpha.example.com\n    password: alpha-secret\n")
	store := mockCredentials.NewMockStore(t)

	coordinator := NewManager(store, local)

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

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewManager(store, local).ClearUsername("missing")

	require.ErrorIs(t, err, instance.ErrUnknownInstance)
	assert.Empty(t, result)
	assert.Equal(t, 0, local.saves)
}

// TestCredentialsStatusUsernameReportsUsername verifies the username read path
// reports the configured value, because a username is configuration rather than a
// secret. The credential store is never consulted to answer it.
func TestCredentialsStatusUsernameReportsUsername(t *testing.T) {
	t.Parallel()

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	report, err := NewManager(store, local).StatusUsername([]string{alphaInstance})

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, alphaInstance, report.Instances[0].Instance)
	assert.Equal(t, "admin", report.Instances[0].Username)
}

// TestCredentialsStatusUsernameOmitsUnsetUsername verifies an instance without a
// username reports an empty value rather than a placeholder.
func TestCredentialsStatusUsernameOmitsUnsetUsername(t *testing.T) {
	t.Parallel()

	local := newConfig(t, "credentials:\n  service: agh-cli\n"+
		"instances:\n  alpha:\n    host: alpha.example.com\n    password: alpha-secret\n")
	store := mockCredentials.NewMockStore(t)

	report, err := NewManager(store, local).StatusUsername([]string{alphaInstance})

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Empty(t, report.Instances[0].Username)
}

// TestCredentialsStatusUsernameRejectsUnknownInstance verifies the read path names
// a configured instance.
func TestCredentialsStatusUsernameRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)

	_, err := NewManager(store, local).StatusUsername([]string{"missing"})

	require.ErrorIs(t, err, instance.ErrUnknownInstance)
}

// TestCredentialsStatusPasswordOmitsUsername verifies the password report carries
// no username, because the two halves of instance authentication are reported
// separately.
func TestCredentialsStatusPasswordOmitsUsername(t *testing.T) {
	t.Parallel()

	local := newConfig(t, keyringConfig())
	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", alphaInstance).
		Return("alpha-secret", nil).
		Once()

	report, err := NewManager(store, local).StatusPassword(
		t.Context(),
		[]string{alphaInstance},
	)

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, alphaInstance, report.Instances[0].Instance)
	assert.Equal(t, instance.KeyringSource, report.Instances[0].Source)
}
