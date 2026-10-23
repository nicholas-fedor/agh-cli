// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TestCredentialsStatusReportsPresencePerNamedInstance verifies status reports the
// backend, the service, and per-instance presence without enumerating the store or
// returning a secret.
func TestCredentialsStatusReportsPresencePerNamedInstance(t *testing.T) {
	t.Parallel()

	local := newConfig(t,
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
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "stored-key").
		Return("keyring-secret", nil).
		Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "missing-key").
		Return("", ErrNotFound).
		Once()

	result, err := NewManager(store, local).StatusPassword(t.Context(), nil)

	require.NoError(t, err)
	assert.True(t, result.Available)
	assert.Equal(t, KeyringBackend, result.Backend)
	assert.Equal(t, "agh-cli", result.Service)
	assert.Equal(t, []PasswordStatus{
		{Instance: "legacy", Source: instance.PlaintextSource, Presence: PresencePresent},
		{Instance: "bare", Source: instance.PlaintextSource, Presence: PresenceAbsent},
		{
			Instance:   "stored",
			Source:     instance.KeyringSource,
			Target:     "stored-key",
			TargetKind: "key",
			Presence:   PresencePresent,
		},
		{
			Instance:   "missing",
			Source:     instance.KeyringSource,
			Target:     "missing-key",
			TargetKind: "key",
			Presence:   PresenceAbsent,
		},
		{
			Instance:   "mounted",
			Source:     instance.FileSource,
			Target:     "/run/secrets/agh",
			TargetKind: "path",
			Presence:   PresenceUnknown,
		},
		{
			Instance:   "scoped",
			Source:     instance.EnvSource,
			Target:     "AGH_CLI_PASSWORD",
			TargetKind: "variable",
			Presence:   PresenceUnknown,
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

	local := newConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n  stored:\n    host: stored.example.com\n"+
			"    credential:\n      source: keyring\n      key: stored-key\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().
		Get(mock.Anything, "agh-cli", "stored-key").
		Return("", ErrStoreUnavailable).
		Once()

	result, err := NewManager(store, local).StatusPassword(t.Context(), []string{"stored"})

	require.NoError(t, err)
	assert.False(t, result.Available)
	require.Len(t, result.Instances, 1)
	assert.Equal(t, PresenceUnknown, result.Instances[0].Presence)
	assert.ErrorIs(t, result.Instances[0].Err, ErrStoreUnavailable)
}

// TestCredentialsStatusRejectsUnknownInstance verifies a requested name outside the
// configuration is refused before the store is read.
func TestCredentialsStatusRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	local := newConfig(t, plaintextConfig())
	store := mockCredentials.NewMockStore(t)

	result, err := NewManager(store, local).StatusPassword(t.Context(), []string{"missing"})

	require.ErrorIs(t, err, instance.ErrUnknownInstance)
	assert.Empty(t, result.Instances)
}

// TestCredentialsStatusResolvesDefaultKeyringKey verifies a keyring reference
// without a key is inspected under the instance name, the key every other
// keyring operation uses.
func TestCredentialsStatusResolvesDefaultKeyringKey(t *testing.T) {
	t.Parallel()

	local := newConfig(t, "instances:\n"+
		"  "+alphaInstance+":\n    host: alpha.example.com\n    credential:\n      source: keyring\n")

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(KeyringBackend).Once()
	store.EXPECT().Get(mock.Anything, "agh-cli", alphaInstance).Return("alpha-secret", nil).Once()

	report, err := NewManager(store, local).StatusPassword(t.Context(), nil)

	require.NoError(t, err)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, alphaInstance, report.Instances[0].Target)
	assert.Equal(t, PresencePresent, report.Instances[0].Presence)
}
