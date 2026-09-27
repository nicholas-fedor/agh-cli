// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// factoryTestConfigName is the configuration file name used by the factory
// tests.
const factoryTestConfigName = "config.yaml"

// factoryTestPassword is the legacy plaintext password used by the factory
// tests.
const factoryTestPassword = "legacy-plaintext-password"

// factoryTestHost is the instance host used by the factory tests.
const factoryTestHost = "factory.example.com"

// userConfigDirEnv selects the per-user configuration root on Unix.
const userConfigDirEnv = "XDG_CONFIG_HOME"

// userConfigHomeEnv supplies the per-user configuration root on Unix.
const userConfigHomeEnv = "HOME"

// TestConfigPathFallsBackToUserConfigPath verifies the path used when no
// configuration file was resolved. Viper resolves nothing exactly when no
// configuration file exists yet, so the per-user path is the destination of the
// first write rather than a file in the working directory.
func TestConfigPathFallsBackToUserConfigPath(t *testing.T) {
	lockViper(t)

	configRoot := t.TempDir()
	t.Setenv(userConfigHomeEnv, configRoot)
	t.Setenv(userConfigDirEnv, configRoot)

	expected := filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName)

	assert.Equal(t, expected, ConfigPath())
}

// TestConfigPathFallsBackToBareNameWithoutUserConfigRoot verifies the last
// resort when the operating system reports no per-user configuration root.
func TestConfigPathFallsBackToBareNameWithoutUserConfigRoot(t *testing.T) {
	lockViper(t)

	t.Setenv(userConfigHomeEnv, "")
	t.Setenv(userConfigDirEnv, "")

	assert.Equal(t, DefaultConfigFileName, ConfigPath())
}

// TestUserConfigPathUsesUserConfigDirectory verifies the per-user path follows
// the configuration root rather than a hardcoded home path.
func TestUserConfigPathUsesUserConfigDirectory(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(userConfigHomeEnv, configRoot)
	t.Setenv(userConfigDirEnv, configRoot)

	userPath, err := UserConfigPath()

	require.NoError(t, err)
	assert.Equal(
		t,
		filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName),
		userPath,
	)
}

// TestUserConfigPathReportsUnavailableRoot verifies an unavailable root is
// reported rather than silently reduced to a relative path.
func TestUserConfigPathReportsUnavailableRoot(t *testing.T) {
	t.Setenv(userConfigHomeEnv, "")
	t.Setenv(userConfigDirEnv, "")

	userPath, err := UserConfigPath()

	require.Error(t, err)
	assert.Empty(t, userPath)
	assert.Contains(t, err.Error(), "resolve user config path")
}

// TestConfigSearchPathsPreferUserConfigDirectory verifies the per-user directory
// outranks the current directory, so a configuration created by the quickstart
// keeps applying from any working directory.
func TestConfigSearchPathsPreferUserConfigDirectory(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(userConfigHomeEnv, configRoot)
	t.Setenv(userConfigDirEnv, configRoot)

	expected := []string{filepath.Join(configRoot, DefaultConfigDirName), localConfigDir}

	assert.Equal(t, expected, ConfigSearchPaths())
}

// TestConfigSearchPathsKeepCurrentDirectoryWhenRootUnavailable verifies an
// unresolvable root leaves the current directory as the only search path instead
// of failing the command.
func TestConfigSearchPathsKeepCurrentDirectoryWhenRootUnavailable(t *testing.T) {
	t.Setenv(userConfigHomeEnv, "")
	t.Setenv(userConfigDirEnv, "")

	assert.Equal(t, []string{localConfigDir}, ConfigSearchPaths())
}

// TestConfigPathUsesResolvedFile verifies that the resolved Viper path wins.
func TestConfigPathUsesResolvedFile(t *testing.T) {
	t.Parallel()

	lockViper(t)

	configPath := writeFactoryConfig(t, "instances: {}\n")
	viper.SetConfigFile(configPath)

	assert.Equal(t, configPath, ConfigPath())
}

// TestLoadConfigReadsInstances verifies that a loaded configuration exposes its
// instances and its default credential service.
func TestLoadConfigReadsInstances(t *testing.T) {
	t.Parallel()

	configPath := writeFactoryConfig(t, "instances:\n  default:\n    host: "+factoryTestHost+"\n")

	manager, err := LoadConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, manager)
	assert.Equal(t, []string{"default"}, manager.OrderedNames())
	assert.NotEmpty(t, manager.Credentials().Service)
}

// TestLoadConfigAcceptsAbsentFile verifies that the first write creates the
// configuration instead of failing.
func TestLoadConfigAcceptsAbsentFile(t *testing.T) {
	t.Parallel()

	manager, err := LoadConfig(filepath.Join(t.TempDir(), factoryTestConfigName))

	require.NoError(t, err)
	assert.Empty(t, manager.OrderedNames())
}

// TestLoadConfigReportsUnreadableFile verifies that the failing path is named.
func TestLoadConfigReportsUnreadableFile(t *testing.T) {
	t.Parallel()

	_, err := LoadConfig(t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "load config")
}

// TestAddInstanceCreatesConfiguration verifies that adding the first instance
// creates the configuration file.
func TestAddInstanceCreatesConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), factoryTestConfigName)

	err := AddInstance(InstanceAddRequest{
		ConfigPath: configPath,
		Name:       "default",
		Host:       factoryTestHost,
		Scheme:     "http",
		Username:   "admin",
		Password:   factoryTestPassword,
	})

	require.NoError(t, err)

	written := readFactoryConfig(t, configPath)

	assert.Contains(t, written, "  default:")
	assert.Contains(t, written, "    host: "+factoryTestHost)
	assert.Contains(t, written, "    scheme: http")
	assert.Contains(t, written, "    username: admin")
	assert.Contains(t, written, "    password: "+factoryTestPassword)
}

// TestAddInstanceKeepsExistingInstances verifies that an add preserves the
// instances already on disk.
func TestAddInstanceKeepsExistingInstances(t *testing.T) {
	t.Parallel()

	configPath := writeFactoryConfig(t, "instances:\n  default:\n    host: "+factoryTestHost+"\n")

	err := AddInstance(InstanceAddRequest{
		ConfigPath: configPath,
		Name:       "alpha",
		Host:       factoryTestHost,
	})

	require.NoError(t, err)

	manager, loadErr := LoadConfig(configPath)
	require.NoError(t, loadErr)
	assert.ElementsMatch(t, []string{"default", "alpha"}, manager.OrderedNames())
}

// TestAddInstanceRejectsDuplicate verifies that a duplicate name is refused
// before the file is rewritten.
func TestAddInstanceRejectsDuplicate(t *testing.T) {
	t.Parallel()

	document := "instances:\n  default:\n    host: " + factoryTestHost + "\n"
	configPath := writeFactoryConfig(t, document)

	err := AddInstance(InstanceAddRequest{
		ConfigPath: configPath,
		Name:       "default",
		Host:       factoryTestHost,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Equal(t, document, readFactoryConfig(t, configPath))
}

// TestAddInstanceReportsUnreadableFile verifies that a load failure is reported
// through the add.
func TestAddInstanceReportsUnreadableFile(t *testing.T) {
	t.Parallel()

	err := AddInstance(InstanceAddRequest{
		ConfigPath: t.TempDir(),
		Name:       "default",
		Host:       factoryTestHost,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read configuration")
}

// TestRemoveInstanceDeletesEntry verifies that removal rewrites the file and
// keeps the remaining instances.
func TestRemoveInstanceDeletesEntry(t *testing.T) {
	t.Parallel()

	configPath := writeFactoryConfig(t,
		"instances:\n"+
			"  alpha:\n    host: "+factoryTestHost+"\n"+
			"  default:\n    host: "+factoryTestHost+"\n",
	)

	err := RemoveInstance(InstanceRemoveRequest{ConfigPath: configPath, Name: "alpha"})

	require.NoError(t, err)

	written := readFactoryConfig(t, configPath)

	assert.NotContains(t, written, "  alpha:")
	assert.Contains(t, written, "  default:")
}

// TestRemoveInstanceRejectsUnknown verifies that an unknown name is refused
// before the file is rewritten.
func TestRemoveInstanceRejectsUnknown(t *testing.T) {
	t.Parallel()

	document := "instances:\n  default:\n    host: " + factoryTestHost + "\n"
	configPath := writeFactoryConfig(t, document)

	err := RemoveInstance(InstanceRemoveRequest{ConfigPath: configPath, Name: "zulu"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Equal(t, document, readFactoryConfig(t, configPath))
}

// TestRemoveInstanceReportsUnreadableFile verifies that a load failure is
// reported through the removal.
func TestRemoveInstanceReportsUnreadableFile(t *testing.T) {
	t.Parallel()

	err := RemoveInstance(InstanceRemoveRequest{ConfigPath: t.TempDir(), Name: "default"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read configuration")
}

// TestNewCredentialsCoordinatorUsesResolvedFile verifies that the coordinator
// reads the configuration resolved by Viper.
func TestNewCredentialsCoordinatorUsesResolvedFile(t *testing.T) {
	t.Parallel()

	lockViper(t)

	configPath := writeFactoryConfig(t,
		"instances:\n"+
			"  default:\n    host: "+factoryTestHost+"\n    password: "+factoryTestPassword+"\n",
	)
	viper.SetConfigFile(configPath)

	coordinator, err := NewCredentialsCoordinator()
	require.NoError(t, err)
	require.NotNil(t, coordinator)

	// A legacy plaintext instance is decided from the configuration alone, so
	// this inspection never probes the operating system credential store.
	report, statusErr := coordinator.Status(t.Context(), []string{"default"})

	require.NoError(t, statusErr)
	require.Len(t, report.Instances, 1)
	assert.Equal(t, instance.PlaintextSource, report.Instances[0].Source)
	assert.NotEmpty(t, report.Instances[0].Presence)
	assert.NotContains(t, report.Service, factoryTestPassword)
}

// TestNewCredentialsCoordinatorReportsUnreadableFile verifies that a coordinator
// is never built over an unreadable configuration.
func TestNewCredentialsCoordinatorReportsUnreadableFile(t *testing.T) {
	t.Parallel()

	lockViper(t)

	viper.SetConfigFile(t.TempDir())

	coordinator, err := NewCredentialsCoordinator()

	require.Error(t, err)
	assert.Nil(t, coordinator)
	assert.Contains(t, err.Error(), "create credential coordinator")
}

// writeFactoryConfig writes a configuration document for the factory tests.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - document: complete configuration file contents.
//
// Returns:
//   - string: path of the written configuration file.
func writeFactoryConfig(t *testing.T, document string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), factoryTestConfigName)
	require.NoError(t, os.WriteFile(configPath, []byte(document), 0o600))

	return configPath
}

// readFactoryConfig returns the raw configuration file contents.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - configPath: path of the configuration file to read.
//
// Returns:
//   - string: the configuration file contents.
func readFactoryConfig(t *testing.T, configPath string) string {
	t.Helper()

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	return string(data)
}
