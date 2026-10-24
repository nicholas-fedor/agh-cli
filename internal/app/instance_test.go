// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

const (
	// InstanceTestDefaultName identifies the default instance-listing test target.
	instanceTestDefaultName = "default"
	// InstanceTestAlphaHost identifies the alpha instance-listing test host.
	instanceTestAlphaHost = "instance-alpha.example.com"
	// InstanceTestDefaultHost identifies the default instance-listing test host.
	instanceTestDefaultHost = "instance-default.example.com"
	// InstanceTestZuluHost identifies the zulu instance-listing test host.
	instanceTestZuluHost = "instance-zulu.example.com"
)

// TestListInstancesPreservesSelectionOrder verifies application-level resolution order.
func TestListInstancesPreservesSelectionOrder(t *testing.T) {
	t.Parallel()

	ctx := runContext(t, "instances:\n"+
		"  "+zuluInstance+":\n    host: "+instanceTestZuluHost+"\n"+
		"  "+instanceTestDefaultName+":\n    host: "+instanceTestDefaultHost+"\n"+
		"  "+alphaInstance+":\n    host: "+instanceTestAlphaHost+"\n")

	configs, err := ListInstances(ctx, InstanceListRequest{All: true})

	require.NoError(t, err)
	assert.Equal(
		t,
		[]instance.ID{alphaInstance, instanceTestDefaultName, zuluInstance},
		instanceConfigIdentities(configs),
	)
}

// TestListInstancesUsesDefault verifies implicit selection semantics.
func TestListInstancesUsesDefault(t *testing.T) {
	t.Parallel()

	ctx := runContext(t, instancesDocument(map[string]string{
		zuluInstance:            instanceTestZuluHost,
		instanceTestDefaultName: instanceTestDefaultHost,
	}))

	configs, err := ListInstances(ctx, InstanceListRequest{All: false})

	require.NoError(t, err)
	assert.Equal(t, []instance.ID{instanceTestDefaultName}, instanceConfigIdentities(configs))
}

// TestListInstancesKeepsNamesAsWritten verifies an instance name is selected
// exactly as the file writes it, with no folding to another case.
func TestListInstancesKeepsNamesAsWritten(t *testing.T) {
	t.Parallel()

	ctx := runContext(t, instancesDocument(map[string]string{"Home": instanceTestDefaultHost}))

	configs, err := ListInstances(ctx, InstanceListRequest{All: true})

	require.NoError(t, err)
	assert.Equal(t, []instance.ID{"Home"}, instanceConfigIdentities(configs))
}

// TestListInstancesPreservesResolutionErrors verifies error causes survive app wrapping.
func TestListInstancesPreservesResolutionErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		wantErr  error
	}{
		{
			name:     "no instances",
			document: "",
			wantErr:  instance.ErrEmptyCatalog,
		},
		{
			name: "ambiguous implicit selection",
			document: instancesDocument(map[string]string{
				alphaInstance: instanceTestAlphaHost,
				zuluInstance:  instanceTestZuluHost,
			}),
			wantErr: instance.ErrTargetSelection,
		},
		{
			name:     "invalid catalog entry",
			document: "instances:\n  " + instanceTestDefaultName + ":\n    scheme: https\n",
			wantErr:  instance.ErrMissingHost,
		},
		{
			name:     "undecodable instance",
			document: "instances:\n  " + instanceTestDefaultName + ": https\n",
			wantErr:  instance.ErrInvalidConfig,
		},
		{
			name: "names that differ only by case",
			document: instancesDocument(map[string]string{
				"home": instanceTestAlphaHost,
				"Home": instanceTestZuluHost,
			}),
			wantErr: instance.ErrConflictingInstance,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ListInstances(runContext(t, test.document), InstanceListRequest{All: false})

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestListInstancesRequiresRunConfig verifies a context without a loaded
// configuration is refused rather than read as an empty configuration.
func TestListInstancesRequiresRunConfig(t *testing.T) {
	t.Parallel()

	_, err := ListInstances(t.Context(), InstanceListRequest{All: true})

	require.ErrorIs(t, err, ErrNoRunConfig)
}

// TestAddInstanceCreatesConfiguration verifies that adding the first instance
// creates the configuration file.
func TestAddInstanceCreatesConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), config.DefaultConfigFileName)

	err := AddInstance(contextWithConfigFile(t.Context(), t, configPath), InstanceAddRequest{
		Name:   "default",
		Host:   testConfigHost,
		Scheme: "http",
	})

	require.NoError(t, err)

	written := readTestConfig(t, configPath)

	assert.Contains(t, written, "  default:")
	assert.Contains(t, written, "    host: "+testConfigHost)
	assert.Contains(t, written, "    scheme: http")
}

// TestAddInstanceStoresNoCredentials verifies an added instance is written
// without authentication details, because the credential workflow owns both the
// username and the password.
func TestAddInstanceStoresNoCredentials(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), config.DefaultConfigFileName)

	err := AddInstance(contextWithConfigFile(t.Context(), t, configPath), InstanceAddRequest{
		Name: "default",
		Host: testConfigHost,
	})

	require.NoError(t, err)

	manager, loadErr := config.Load(configPath)
	require.NoError(t, loadErr)

	cfg := manager.Instances()["default"]

	assert.Empty(t, cfg.Username)
	assert.Empty(t, cfg.Password)
	assert.Nil(t, cfg.Credential)
}

// TestAddInstanceKeepsExistingInstances verifies that an add preserves the
// instances already on disk.
func TestAddInstanceKeepsExistingInstances(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances:\n  default:\n    host: "+testConfigHost+"\n")

	err := AddInstance(contextWithConfigFile(t.Context(), t, configPath), InstanceAddRequest{
		Name: "alpha",
		Host: testConfigHost,
	})

	require.NoError(t, err)

	manager, loadErr := config.Load(configPath)
	require.NoError(t, loadErr)
	assert.ElementsMatch(t, []string{"default", "alpha"}, manager.OrderedNames())
}

// TestAddInstanceRejectsDuplicate verifies that a duplicate name is refused
// before the file is rewritten.
func TestAddInstanceRejectsDuplicate(t *testing.T) {
	t.Parallel()

	document := "instances:\n  default:\n    host: " + testConfigHost + "\n"
	configPath := writeTestConfig(t, document)

	err := AddInstance(contextWithConfigFile(t.Context(), t, configPath), InstanceAddRequest{
		Name: "default",
		Host: testConfigHost,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Equal(t, document, readTestConfig(t, configPath))
}

// TestRemoveInstanceDeletesEntry verifies that removal rewrites the file and
// keeps the remaining instances. Neither instance kept its password in the
// credential store, so the store is never contacted.
func TestRemoveInstanceDeletesEntry(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"  default:\n    host: "+testConfigHost+"\n",
	)

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		mockCredentials.NewMockStore(t),
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.NoError(t, err)
	assert.Equal(t, InstanceRemoveResult{Instance: "alpha", Service: credentials.DefaultService}, result)

	written := readTestConfig(t, configPath)

	assert.NotContains(t, written, "  alpha:")
	assert.Contains(t, written, "  default:")
}

// TestRemoveInstanceDeletesStoredCredential verifies that removal takes the
// password agh-cli stored for the instance with it, so removing an instance never
// leaves its secret behind in the operating system credential store.
func TestRemoveInstanceDeletesStoredCredential(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: keyring\n      key: alpha-key\n",
	)

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Get(mock.Anything, "agh-cli", "alpha-key").Return("stored-secret", nil).Once()
	store.EXPECT().Delete(mock.Anything, "agh-cli", "alpha-key").Return(nil).Once()

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.NoError(t, err)
	assert.Equal(t, InstanceRemoveResult{
		Instance: "alpha",
		Service:  "agh-cli",
		Key:      "alpha-key",
		Removed:  true,
	}, result)
	assert.NotContains(t, readTestConfig(t, configPath), "  alpha:")
}

// TestRemoveInstanceDefaultsEmptyKeyToInstanceName verifies that an instance
// whose keyring key is the implicit default is reached under its own name. The
// configuration manager holds the raw document, so the keyring key default is
// resolved here rather than read from the file.
func TestRemoveInstanceDefaultsEmptyKeyToInstanceName(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: keyring\n",
	)

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, "alpha").Return("s", nil).Once()
	store.EXPECT().Delete(mock.Anything, credentials.DefaultService, "alpha").Return(nil).Once()

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.NoError(t, err)
	assert.True(t, result.Removed)
	assert.Equal(t, "alpha", result.Key)
}

// TestRemoveInstanceKeepsCredentialSharedByAnotherInstance verifies that a key
// another instance still reads survives the removal. A key is not exclusive to
// one instance, so deleting it would leave that instance without a password.
func TestRemoveInstanceKeepsCredentialSharedByAnotherInstance(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: keyring\n      key: shared\n"+
			"  zulu:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: keyring\n      key: shared\n",
	)

	store := mockCredentials.NewMockStore(t)

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.NoError(t, err)
	assert.Equal(t, InstanceRemoveResult{
		Instance: "alpha",
		Service:  credentials.DefaultService,
		Key:      "shared",
		Shared:   true,
	}, result)

	written := readTestConfig(t, configPath)

	assert.NotContains(t, written, "  alpha:")
	assert.Contains(t, written, "  zulu:")
}

// TestRemoveInstanceTreatsAbsentCredentialAsRemoved verifies that a credential
// the store no longer holds is not an error, so a repeated removal converges.
func TestRemoveInstanceTreatsAbsentCredentialAsRemoved(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: keyring\n",
	)

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, "alpha").
		Return("", credentials.ErrNotFound).
		Once()

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.NoError(t, err)
	assert.False(t, result.Removed)
	assert.Equal(t, "alpha", result.Key)
	assert.NotContains(t, readTestConfig(t, configPath), "  alpha:")
}

// TestRemoveInstanceKeepsInstanceWhenCredentialDeleteFails verifies that a
// refusal to delete the credential keeps the instance. Removing the
// configuration entry first would strand a secret no command reports.
func TestRemoveInstanceKeepsInstanceWhenCredentialDeleteFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("secret service locked")

	document := "instances:\n" +
		"  alpha:\n    host: " + testConfigHost + "\n" +
		"    credential:\n      source: keyring\n"
	configPath := writeTestConfig(t, document)

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, "alpha").Return("s", nil).Once()
	store.EXPECT().Delete(mock.Anything, credentials.DefaultService, "alpha").Return(wantErr).Once()

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.ErrorIs(t, err, wantErr)
	assert.Contains(t, err.Error(), "leaving the instance configured")
	assert.False(t, result.Removed)
	assert.Equal(t, document, readTestConfig(t, configPath))
}

// TestRemoveInstanceReportsUnreadableStore verifies that an unusable credential
// store is reported before the configuration entry is removed.
func TestRemoveInstanceReportsUnreadableStore(t *testing.T) {
	t.Parallel()

	document := "instances:\n" +
		"  alpha:\n    host: " + testConfigHost + "\n" +
		"    credential:\n      source: keyring\n"
	configPath := writeTestConfig(t, document)

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, "alpha").
		Return("", credentials.ErrStoreUnavailable).
		Once()

	_, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.ErrorIs(t, err, credentials.ErrStoreUnavailable)
	assert.Equal(t, document, readTestConfig(t, configPath))
}

// TestRemoveInstanceKeepsCredentialOfExternalSource verifies that a password
// agh-cli does not own is never deleted. A mounted secret file, an environment
// variable, and a plaintext password all resolve outside the credential store, so
// the store is left untouched and a host without one is never blocked.
func TestRemoveInstanceKeepsCredentialOfExternalSource(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  mounted:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: file\n      path: /run/secrets/agh-cli/admin\n"+
			"  legacy:\n    host: "+testConfigHost+"\n    password: "+testLegacyPassword+"\n",
	)

	for _, name := range []string{"mounted", "legacy"} {
		result, err := removeWithStore(
			contextWithConfigFile(t.Context(), t, configPath),
			mockCredentials.NewMockStore(t),
			InstanceRemoveRequest{Name: name},
		)

		require.NoError(t, err)
		assert.Equal(t, InstanceRemoveResult{
			Instance: name,
			Service:  credentials.DefaultService,
		}, result)
	}

	written := readTestConfig(t, configPath)

	assert.NotContains(t, written, "  mounted:")
	assert.NotContains(t, written, "  legacy:")
}

// TestRemoveInstanceRejectsUnknown verifies that an unknown name is refused
// before the file is rewritten, and before the credential store is contacted: an
// instance that is not configured cannot own a credential.
func TestRemoveInstanceRejectsUnknown(t *testing.T) {
	t.Parallel()

	document := "instances:\n  default:\n    host: " + testConfigHost + "\n"
	configPath := writeTestConfig(t, document)

	_, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		mockCredentials.NewMockStore(t),
		InstanceRemoveRequest{Name: "zulu"},
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Equal(t, document, readTestConfig(t, configPath))
}

// TestRemoveInstanceNamesTheInstance verifies that the production removal names
// the instance it could not remove. The run carries a store with no
// expectations, so the test fails on any store call and can never reach the
// host store.
func TestRemoveInstanceNamesTheInstance(t *testing.T) {
	t.Parallel()

	document := "instances:\n  default:\n    host: " + testConfigHost + "\n"
	configPath := writeTestConfig(t, document)
	ctx := WithCredentialStore(contextWithConfigFile(t.Context(), t, configPath), mockCredentials.NewMockStore(t))

	_, err := RemoveInstance(ctx, InstanceRemoveRequest{Name: "zulu"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), `remove "zulu"`)
	assert.Equal(t, document, readTestConfig(t, configPath))
}

// TestRemoveInstanceKeepsInstanceWhenConfigurationWriteFails verifies the
// retryable state of a failed configuration write. The credential is already
// gone, so the instance is left in the file pointing at a key the store no longer
// holds, and repeating the command converges.
//
// A read-only directory is how the write is refused, so the test is skipped where
// that mode does not deny a write.
func TestRemoveInstanceKeepsInstanceWhenConfigurationWriteFails(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("Windows emulates permission bits instead of enforcing POSIX modes")
	}

	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict the root user")
	}

	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"    credential:\n      source: keyring\n",
	)
	documentDirectory := filepath.Dir(configPath)
	require.NoError(t, os.Chmod(documentDirectory, 0o500))

	// The temporary directory is removed after this test, so the write permission
	// is restored first.
	t.Cleanup(func() { assert.NoError(t, os.Chmod(documentDirectory, 0o700)) })

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, "alpha").Return("s", nil).Once()
	store.EXPECT().Delete(mock.Anything, credentials.DefaultService, "alpha").Return(nil).Once()

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		store,
		InstanceRemoveRequest{Name: "alpha"},
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "write configuration")
	assert.True(t, result.Removed)
	assert.Contains(t, readTestConfig(t, configPath), "  alpha:")
}

// TestAddInstanceRefusesCaseConflict verifies an added name cannot differ from a
// configured name only by letter case, and the file is left as it was.
func TestAddInstanceRefusesCaseConflict(t *testing.T) {
	t.Parallel()

	document := "instances:\n  home:\n    host: " + testConfigHost + "\n"
	configPath := writeTestConfig(t, document)

	err := AddInstance(contextWithConfigFile(t.Context(), t, configPath), InstanceAddRequest{
		Name: "Home",
		Host: testConfigHost,
	})

	require.ErrorIs(t, err, instance.ErrConflictingInstance)
	assert.Equal(t, document, readTestConfig(t, configPath))
}

// TestAddInstanceRequiresRunConfig verifies an add without a loaded
// configuration is refused instead of writing to a guessed location.
func TestAddInstanceRequiresRunConfig(t *testing.T) {
	t.Parallel()

	err := AddInstance(t.Context(), InstanceAddRequest{Name: "default", Host: testConfigHost})

	require.ErrorIs(t, err, ErrNoRunConfig)
}

// TestRemoveInstanceRemovesUndecodableInstance verifies an instance whose stanza
// cannot be decoded is still removable, without contacting the credential store.
func TestRemoveInstanceRemovesUndecodableInstance(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+testConfigHost+"\n"+
			"  broken: https\n",
	)

	result, err := removeWithStore(
		contextWithConfigFile(t.Context(), t, configPath),
		mockCredentials.NewMockStore(t),
		InstanceRemoveRequest{Name: "broken"},
	)

	require.NoError(t, err)
	assert.False(t, result.Removed)
	assert.NotContains(t, readTestConfig(t, configPath), "broken")
	assert.Contains(t, readTestConfig(t, configPath), "  alpha:")
}

// TestRemoveInstanceRequiresRunConfig verifies a removal without a loaded
// configuration is refused before the credential store is touched.
func TestRemoveInstanceRequiresRunConfig(t *testing.T) {
	t.Parallel()

	_, err := removeWithStore(
		t.Context(),
		mockCredentials.NewMockStore(t),
		InstanceRemoveRequest{Name: "default"},
	)

	require.ErrorIs(t, err, ErrNoRunConfig)
}

// instanceConfigIdentities returns configuration identities in selection order.
//
// Parameters:
//   - configs: resolved instance configurations.
//
// Returns:
//   - []instance.ID: identities in selection order.
func instanceConfigIdentities(configs []instance.Config) []instance.ID {
	identities := make([]instance.ID, 0, len(configs))
	for _, cfg := range configs {
		identities = append(identities, cfg.Identity())
	}

	return identities
}
