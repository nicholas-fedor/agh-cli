// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/config"
)

// windowsOS is the value [runtime.GOOS] reports for Microsoft Windows, where
// [os.UserConfigDir] reads the roaming application data directory.
const windowsOS = "windows"

// darwinOS is the value [runtime.GOOS] reports for macOS, where
// [os.UserConfigDir] ignores XDG_CONFIG_HOME and reads the home directory.
const darwinOS = "darwin"

// userConfigDirEnv names the XDG configuration root variable, which
// [os.UserConfigDir] reads on Unix systems other than macOS.
const userConfigDirEnv = "XDG_CONFIG_HOME"

// userConfigHomeEnv names the home directory variable, which [os.UserConfigDir]
// reads on macOS and, as a fallback, on other Unix systems.
const userConfigHomeEnv = "HOME"

// windowsUserConfigEnv names the roaming application data variable, which
// [os.UserConfigDir] reads on Windows.
const windowsUserConfigEnv = "AppData"

// TestUserConfigPathUsesUserConfigDirectory verifies the per-user path follows
// the configuration root rather than a hardcoded home path.
//
//nolint:paralleltest // The test isolates the configuration root through the process environment.
func TestUserConfigPathUsesUserConfigDirectory(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)

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
//
//nolint:paralleltest // The test isolates the configuration root through the process environment.
func TestUserConfigPathReportsUnavailableRoot(t *testing.T) {
	clearUserConfigRoot(t)

	userPath, err := UserConfigPath()

	require.Error(t, err)
	assert.Empty(t, userPath)
	assert.Contains(t, err.Error(), "resolve user config path")
}

// TestConfigSearchPathsPreferUserConfigDirectory verifies the per-user directory
// outranks the current directory, so a configuration created by the quickstart
// keeps applying from any working directory.
func TestConfigSearchPathsPreferUserConfigDirectory(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)

	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	expected := []string{
		filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName),
		filepath.Join(workingDirectory, DefaultConfigFileName),
	}

	assert.Equal(t, expected, ConfigSearchPaths())
}

// TestConfigSearchPathsKeepCurrentDirectoryWhenRootUnavailable verifies an
// unresolvable root leaves the current directory as the only search path instead
// of failing the command.
func TestConfigSearchPathsKeepCurrentDirectoryWhenRootUnavailable(t *testing.T) {
	clearUserConfigRoot(t)

	workingDirectory := t.TempDir()

	t.Chdir(workingDirectory)

	assert.Equal(
		t,
		[]string{filepath.Join(workingDirectory, DefaultConfigFileName)},
		ConfigSearchPaths(),
	)
}

// TestResolveConfigPathTreatsBlankFileAsAbsent verifies a document with no
// content is not read, so a stray tab cannot block the first write, while its
// path remains the destination.
func TestResolveConfigPathTreatsBlankFileAsAbsent(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), DefaultConfigFileName)
	require.NoError(t, os.WriteFile(configPath, []byte("\t"), 0o600))

	resolution, err := ResolveConfigPath(configPath)

	require.NoError(t, err)
	assert.Equal(t, configPath, resolution.Path)
	assert.False(t, resolution.Exists)
}

// TestResolveConfigPathReadsContentFile verifies a file with content is read.
func TestResolveConfigPathReadsContentFile(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances: {}\n")

	resolution, err := ResolveConfigPath(configPath)

	require.NoError(t, err)
	assert.Equal(t, configPath, resolution.Path)
	assert.True(t, resolution.Exists)
}

// TestResolveConfigPathAcceptsMissingFile verifies a missing explicit file is not
// an error, because the first write creates it.
func TestResolveConfigPathAcceptsMissingFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "absent", DefaultConfigFileName)

	resolution, err := ResolveConfigPath(configPath)

	require.NoError(t, err)
	assert.Equal(t, configPath, resolution.Path)
	assert.False(t, resolution.Exists)
}

// TestResolveConfigPathRejectsDirectory verifies a directory is refused by name
// rather than surfacing an opaque configuration-type error.
func TestResolveConfigPathRejectsDirectory(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	_, err := ResolveConfigPath(directory)

	require.ErrorIs(t, err, config.ErrConfigNotRegular)
	assert.Contains(t, err.Error(), strconv.Quote(directory))
}

// TestResolveConfigPathSearchesInOrder verifies the per-user location wins over
// the current directory, and the current directory is used when the per-user file
// is absent.
func TestResolveConfigPathSearchesInOrder(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	userConfig := filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName)
	require.NoError(t, os.MkdirAll(filepath.Dir(userConfig), 0o700))
	require.NoError(t, os.WriteFile(userConfig, []byte("instances: {}\n"), 0o600))

	resolution, err := ResolveConfigPath("")

	require.NoError(t, err)
	assert.Equal(t, userConfig, resolution.Path)
	assert.True(t, resolution.Exists)
}

// TestResolveConfigPathFallsBackToCurrentDirectory verifies the current
// directory is searched when no per-user configuration exists.
func TestResolveConfigPathFallsBackToCurrentDirectory(t *testing.T) {
	isolateUserConfigRoot(t)

	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	localConfig := filepath.Join(workingDirectory, DefaultConfigFileName)
	require.NoError(t, os.WriteFile(localConfig, []byte("instances: {}\n"), 0o600))

	resolution, err := ResolveConfigPath("")

	require.NoError(t, err)
	assert.Equal(t, localConfig, resolution.Path)
	assert.True(t, resolution.Exists)
}

// TestResolveConfigPathSearchMissUsesPerUserWriteTarget verifies a search miss
// resolves to the per-user path so the first write has a destination.
func TestResolveConfigPathSearchMissUsesPerUserWriteTarget(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)
	t.Chdir(t.TempDir())

	resolution, err := ResolveConfigPath("")

	require.NoError(t, err)
	assert.Equal(
		t,
		filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName),
		resolution.Path,
	)
	assert.False(t, resolution.Exists)
}

// TestResolveConfigPathReportsBrokenSearchLocation verifies a search location
// that exists but cannot be read is reported rather than skipped. Silently
// falling through to a later location would use a file the operator did not
// expect, which is the failure the single resolution point exists to prevent.
func TestResolveConfigPathReportsBrokenSearchLocation(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)
	workingDirectory := t.TempDir()

	t.Chdir(workingDirectory)

	// The per-user location holds a directory where the file belongs, which can
	// never be a configuration document.
	blocked := filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName)
	require.NoError(t, os.MkdirAll(blocked, 0o700))

	_, err := ResolveConfigPath("")

	require.ErrorIs(t, err, config.ErrConfigNotRegular)
	assert.Contains(t, err.Error(), strconv.Quote(blocked))
}

// TestResolveConfigPathContinuesPastAbsentLocations verifies the search moves on
// when a location simply has no file yet, because a missing file is created on
// first write rather than reported.
func TestResolveConfigPathContinuesPastAbsentLocations(t *testing.T) {
	isolateUserConfigRoot(t)

	workingDirectory := t.TempDir()

	t.Chdir(workingDirectory)

	localConfig := filepath.Join(workingDirectory, DefaultConfigFileName)
	require.NoError(t, os.WriteFile(localConfig, []byte("instances: {}\n"), 0o600))

	resolution, err := ResolveConfigPath("")

	require.NoError(t, err)
	assert.Equal(t, localConfig, resolution.Path)
	assert.True(t, resolution.Exists)
}

// userConfigRootEnv returns the environment variable that [os.UserConfigDir]
// reads on the given platform.
//
// The variable is platform-specific. On macOS, XDG_CONFIG_HOME is ignored and
// the path derives from the home directory, while Windows reads the roaming
// application data directory. A test that sets the wrong variable resolves the
// real user configuration root instead of the isolated one.
//
// Parameters:
//   - goos: value [runtime.GOOS] reported for the running test.
//
// Returns:
//   - string: name of the environment variable that selects the configuration
//     root.
func userConfigRootEnv(goos string) string {
	switch goos {
	case windowsOS:
		return windowsUserConfigEnv
	case darwinOS:
		return userConfigHomeEnv
	default:
		return userConfigDirEnv
	}
}

// isolateUserConfigRoot points the per-user configuration root at a temporary
// directory so a test never reads or writes the real user configuration.
//
// The returned value is what [os.UserConfigDir] reports afterwards, which keeps
// assertions correct on every platform without repeating the platform table.
//
// Returns:
//   - string: configuration root [os.UserConfigDir] reports.
func isolateUserConfigRoot(t *testing.T) string {
	t.Helper()

	t.Setenv(userConfigRootEnv(runtime.GOOS), t.TempDir())

	root, err := os.UserConfigDir()
	require.NoError(t, err)

	return root
}

// clearUserConfigRoot empties the variable that [os.UserConfigDir] reads on the
// host platform, so the root is reported as unavailable.
//
// The home directory is cleared as well because [os.UserConfigDir] falls back to
// it on Unix systems that do not honor XDG_CONFIG_HOME.
func clearUserConfigRoot(t *testing.T) {
	t.Helper()

	t.Setenv(userConfigRootEnv(runtime.GOOS), "")
	t.Setenv(userConfigHomeEnv, "")
}

// TestResolveConfigPathFallsBackToBareNameWithoutUserConfigRoot verifies the
// last resort when the operating system reports no per-user configuration root.
func TestResolveConfigPathFallsBackToBareNameWithoutUserConfigRoot(t *testing.T) {
	clearUserConfigRoot(t)
	t.Chdir(t.TempDir())

	resolution, err := ResolveConfigPath("")

	require.NoError(t, err)
	assert.Equal(t, ConfigResolution{Path: DefaultConfigFileName, Exists: false}, resolution)
}

// TestLoadRunConfigReadsResolvedFile verifies the run configuration serves the
// instances and the credential namespace of the file it loaded, with instance
// names exactly as the file writes them.
func TestLoadRunConfigReadsResolvedFile(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"credentials:\n  service: agh-cli-custom\n"+
			"instances:\n  Home:\n    host: "+testConfigHost+"\n",
	)

	resolution, err := ResolveConfigPath(configPath)
	require.NoError(t, err)

	var warnings strings.Builder

	runConfig, err := LoadRunConfig(resolution, &warnings)
	require.NoError(t, err)

	ctx := WithRunConfig(t.Context(), runConfig)

	manager, err := configFrom(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"Home"}, manager.OrderedNames())
	assert.Equal(t, "agh-cli-custom", credentialService(ctx))
	assert.Empty(t, warnings.String())
}

// TestLoadRunConfigWarnsAboutMissingFile verifies a missing file loads as an
// empty configuration and is reported as a warning naming the file.
func TestLoadRunConfigWarnsAboutMissingFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), DefaultConfigFileName)

	var warnings strings.Builder

	runConfig, err := LoadRunConfig(ConfigResolution{Path: configPath, Exists: false}, &warnings)
	require.NoError(t, err)

	manager, err := configFrom(WithRunConfig(t.Context(), runConfig))
	require.NoError(t, err)
	assert.Empty(t, manager.OrderedNames())
	assert.Contains(t, warnings.String(), "no configuration file at "+configPath)
}

// TestLoadRunConfigWarnsAboutInstanceProblems verifies a problem with one
// instance is a warning naming it, never a load failure, so the instance can
// still be removed.
func TestLoadRunConfigWarnsAboutInstanceProblems(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances:\n  broken: https\n  hostless:\n    Host: x\n")

	var warnings strings.Builder

	_, err := LoadRunConfig(ConfigResolution{Path: configPath, Exists: true}, &warnings)

	require.NoError(t, err)
	assert.Contains(t, warnings.String(), configPath)
	assert.Contains(t, warnings.String(), "broken: ")
	assert.Contains(t, warnings.String(), "hostless: unknown field")
}

// TestLoadRunConfigNamesUnreadableFile verifies a file that cannot be parsed is
// reported with its path, because an operator must know which file failed.
func TestLoadRunConfigNamesUnreadableFile(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances: [\n")

	_, err := LoadRunConfig(ConfigResolution{Path: configPath, Exists: true}, io.Discard)

	require.Error(t, err)
	assert.Contains(t, err.Error(), strconv.Quote(configPath))
}

// TestLoadRunConfigRefusesUnsupportedFormat verifies a path naming another
// format is refused, so a write never puts YAML into it.
func TestLoadRunConfigRefusesUnsupportedFormat(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.toml")

	_, err := LoadRunConfig(ConfigResolution{Path: configPath, Exists: false}, io.Discard)

	require.ErrorIs(t, err, config.ErrUnsupportedFormat)
	assert.Contains(t, err.Error(), strconv.Quote(configPath))
}

// TestConfigFromRequiresRunConfig verifies a context without a loaded
// configuration is reported rather than read as an empty configuration.
func TestConfigFromRequiresRunConfig(t *testing.T) {
	t.Parallel()

	_, err := configFrom(t.Context())

	require.ErrorIs(t, err, ErrNoRunConfig)
}
