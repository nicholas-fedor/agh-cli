// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestUserPathUsesUserConfigDirectory verifies the per-user path follows
// the configuration root rather than a hardcoded home path.
//
//nolint:paralleltest // The test isolates the configuration root through the process environment.
func TestUserPathUsesUserConfigDirectory(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)

	userPath, err := UserPath()

	require.NoError(t, err)
	assert.Equal(
		t,
		filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName),
		userPath,
	)
}

// TestUserPathReportsUnavailableRoot verifies an unavailable root is
// reported rather than silently reduced to a relative path.
//
//nolint:paralleltest // The test isolates the configuration root through the process environment.
func TestUserPathReportsUnavailableRoot(t *testing.T) {
	clearUserConfigRoot(t)

	userPath, err := UserPath()

	require.Error(t, err)
	assert.Empty(t, userPath)
	assert.Contains(t, err.Error(), "resolve user config path")
}

// TestSearchPathsPreferUserConfigDirectory verifies the per-user directory
// outranks the current directory, so a configuration created by the quickstart
// keeps applying from any working directory.
func TestSearchPathsPreferUserConfigDirectory(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)

	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	expected := []string{
		filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName),
		filepath.Join(workingDirectory, DefaultConfigFileName),
	}

	assert.Equal(t, expected, SearchPaths())
}

// TestSearchPathsKeepCurrentDirectoryWhenRootUnavailable verifies an
// unresolvable root leaves the current directory as the only search path instead
// of failing the command.
func TestSearchPathsKeepCurrentDirectoryWhenRootUnavailable(t *testing.T) {
	clearUserConfigRoot(t)

	workingDirectory := t.TempDir()

	t.Chdir(workingDirectory)

	assert.Equal(
		t,
		[]string{filepath.Join(workingDirectory, DefaultConfigFileName)},
		SearchPaths(),
	)
}

// TestResolveTreatsBlankFileAsAbsent verifies a document with no
// content is not read, so a stray tab cannot block the first write, while its
// path remains the destination.
func TestResolveTreatsBlankFileAsAbsent(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), DefaultConfigFileName)
	require.NoError(t, os.WriteFile(configPath, []byte("\t"), 0o600))

	resolution, err := Resolve(configPath)

	require.NoError(t, err)
	assert.Equal(t, configPath, resolution.Path)
	assert.False(t, resolution.Exists)
}

// TestResolveReadsContentFile verifies a file with content is read.
func TestResolveReadsContentFile(t *testing.T) {
	t.Parallel()

	configPath := writeResolutionConfig(t, "instances: {}\n")

	resolution, err := Resolve(configPath)

	require.NoError(t, err)
	assert.Equal(t, configPath, resolution.Path)
	assert.True(t, resolution.Exists)
}

// TestResolveAcceptsMissingFile verifies a missing explicit file is not
// an error, because the first write creates it.
func TestResolveAcceptsMissingFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "absent", DefaultConfigFileName)

	resolution, err := Resolve(configPath)

	require.NoError(t, err)
	assert.Equal(t, configPath, resolution.Path)
	assert.False(t, resolution.Exists)
}

// TestResolveRejectsDirectory verifies a directory is refused by name
// rather than surfacing an opaque configuration-type error.
func TestResolveRejectsDirectory(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	_, err := Resolve(directory)

	require.ErrorIs(t, err, ErrConfigNotRegular)
	assert.Contains(t, err.Error(), strconv.Quote(directory))
}

// TestResolveSearchesInOrder verifies the per-user location wins over
// the current directory, and the current directory is used when the per-user file
// is absent.
func TestResolveSearchesInOrder(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	userConfig := filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName)
	require.NoError(t, os.MkdirAll(filepath.Dir(userConfig), 0o700))
	require.NoError(t, os.WriteFile(userConfig, []byte("instances: {}\n"), 0o600))

	// A valid file in the current directory must not shadow the per-user one.
	localConfig := filepath.Join(workingDirectory, DefaultConfigFileName)
	require.NoError(t, os.WriteFile(localConfig, []byte("instances: {}\n"), 0o600))

	resolution, err := Resolve("")

	require.NoError(t, err)
	assert.Equal(t, userConfig, resolution.Path)
	assert.True(t, resolution.Exists)
}

// TestResolveFallsBackToCurrentDirectory verifies the current
// directory is searched when no per-user configuration exists.
func TestResolveFallsBackToCurrentDirectory(t *testing.T) {
	isolateUserConfigRoot(t)

	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	localConfig := filepath.Join(workingDirectory, DefaultConfigFileName)
	require.NoError(t, os.WriteFile(localConfig, []byte("instances: {}\n"), 0o600))

	resolution, err := Resolve("")

	require.NoError(t, err)
	assert.Equal(t, localConfig, resolution.Path)
	assert.True(t, resolution.Exists)
}

// TestResolveSearchMissUsesPerUserWriteTarget verifies a search miss
// resolves to the per-user path so the first write has a destination.
func TestResolveSearchMissUsesPerUserWriteTarget(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)
	t.Chdir(t.TempDir())

	resolution, err := Resolve("")

	require.NoError(t, err)
	assert.Equal(
		t,
		filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName),
		resolution.Path,
	)
	assert.False(t, resolution.Exists)
}

// TestResolveReportsBrokenSearchLocation verifies a search location
// that exists but cannot be read is reported rather than skipped. Silently
// falling through to a later location would use a file the operator did not
// expect, which is the failure the single resolution point exists to prevent.
func TestResolveReportsBrokenSearchLocation(t *testing.T) {
	configRoot := isolateUserConfigRoot(t)
	workingDirectory := t.TempDir()

	t.Chdir(workingDirectory)

	// The per-user location holds a directory where the file belongs, which can
	// never be a configuration document.
	blocked := filepath.Join(configRoot, DefaultConfigDirName, DefaultConfigFileName)
	require.NoError(t, os.MkdirAll(blocked, 0o700))

	_, err := Resolve("")

	require.ErrorIs(t, err, ErrConfigNotRegular)
	assert.Contains(t, err.Error(), strconv.Quote(blocked))
}

// TestResolveContinuesPastAbsentLocations verifies the search moves on
// when a location simply has no file yet, because a missing file is created on
// first write rather than reported.
func TestResolveContinuesPastAbsentLocations(t *testing.T) {
	isolateUserConfigRoot(t)

	workingDirectory := t.TempDir()

	t.Chdir(workingDirectory)

	localConfig := filepath.Join(workingDirectory, DefaultConfigFileName)
	require.NoError(t, os.WriteFile(localConfig, []byte("instances: {}\n"), 0o600))

	resolution, err := Resolve("")

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

// TestResolveFallsBackToBareNameWithoutUserConfigRoot verifies the
// last resort when the operating system reports no per-user configuration root.
func TestResolveFallsBackToBareNameWithoutUserConfigRoot(t *testing.T) {
	clearUserConfigRoot(t)
	t.Chdir(t.TempDir())

	resolution, err := Resolve("")

	require.NoError(t, err)
	assert.Equal(t, Resolution{Path: DefaultConfigFileName, Exists: false}, resolution)
}

// writeResolutionConfig writes a configuration document to a private file.
//
// Parameters:
//   - document: complete configuration document.
//
// Returns:
//   - string: path of the written configuration file.
func writeResolutionConfig(t *testing.T, document string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, document)

	return path
}
