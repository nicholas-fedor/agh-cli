// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// windowsOS is the value [runtime.GOOS] reports for Microsoft Windows, where
// POSIX permission bits are emulated instead of enforced.
const windowsOS = "windows"

// TestLoadPreservesInstanceOrder verifies configuration ownership and file
// order for loaded instances.
func TestLoadPreservesInstanceOrder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	give := []byte("instances:\n  zulu:\n    host: zulu.example.com\n  alpha:\n    host: alpha.example.com\n")

	err := os.WriteFile(path, give, 0o600)
	require.NoError(t, err)

	manager, err := Load(path)

	require.NoError(t, err)
	assert.Equal(t, []string{"zulu", "alpha"}, manager.OrderedNames())
	assert.Equal(t, instance.Config{
		Name:       "zulu",
		Host:       "zulu.example.com",
		Scheme:     "",
		Username:   "",
		Password:   "",
		Credential: nil,
	}, manager.Instances()["zulu"])
}

// TestLoadRejectsInvalidInstanceMap verifies malformed mappings return errors.
func TestLoadRejectsInvalidInstanceMap(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte("instances: invalid\n"), 0o600)
	require.NoError(t, err)

	_, err = Load(path)

	require.ErrorIs(t, err, ErrInvalidInstanceMap)
}

// TestLoadRejectsDuplicateInstances verifies catalog identity uniqueness during
// configuration loading.
func TestLoadRejectsDuplicateInstances(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	give := []byte(
		"instances:\n  home:\n    host: first.example.com\n  home:\n    host: second.example.com\n",
	)
	err := os.WriteFile(path, give, 0o600)
	require.NoError(t, err)

	_, err = Load(path)

	require.ErrorIs(t, err, ErrDuplicateInstance)
}

// TestManagerMutationsUseInstanceConfiguration verifies in-memory instance
// mutation values and defaulting.
func TestManagerMutationsUseInstanceConfiguration(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	err = manager.Add("home", "home.example.com", "", "admin", "secret")
	require.NoError(t, err)
	assert.Equal(t, instance.Config{
		Name:       "home",
		Host:       "home.example.com",
		Scheme:     "https",
		Username:   "admin",
		Password:   "secret",
		Credential: nil,
	}, manager.Instances()["home"])

	err = manager.Add("home", "other.example.com", "", "", "")
	require.ErrorIs(t, err, ErrInstanceAlreadyExists)

	err = manager.Remove("home")
	require.NoError(t, err)
	assert.Empty(t, manager.Instances())

	err = manager.Remove("home")
	require.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestSaveKeepsLegacyPlaintextPassword verifies a configuration without a
// credential reference still round-trips its plaintext password unchanged.
func TestSaveKeepsLegacyPlaintextPassword(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	give := "instances:\n" +
		"  home:\n" +
		"    host: home.example.com\n" +
		"    username: admin\n" +
		"    password: legacy-secret\n"
	writeConfigFile(t, path, give)

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	assert.Equal(t, give, readConfigFile(t, path))
}

// TestSaveOmitsEmptyOptionalInstanceFields verifies empty credentials and the
// default scheme stay out of a written configuration.
func TestSaveOmitsEmptyOptionalInstanceFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)

	require.NoError(t, manager.Add("home", "home.example.com", "https", "", ""))
	require.NoError(t, manager.Save())

	assert.Equal(
		t,
		"instances:\n  home:\n    host: home.example.com\n",
		readConfigFile(t, path),
	)
}

// TestSaveSkipsInstancesAbsentFromOrder verifies serialization follows
// nameOrder rather than the instance map.
func TestSaveSkipsInstancesAbsentFromOrder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)

	require.NoError(t, manager.Add("home", "home.example.com", "", "", ""))

	manager.data.Instances["orphan"] = instance.Config{
		Name:       "orphan",
		Host:       "orphan.example.com",
		Scheme:     "https",
		Username:   "",
		Password:   "",
		Credential: nil,
	}

	require.NoError(t, manager.Save())

	give := readConfigFile(t, path)
	assert.NotContains(t, give, "orphan")
	assert.Contains(t, give, "home")
}

// TestSaveCreatesConfigWithPrivateMode verifies a configuration created from
// nothing is readable only by its owner.
func TestSaveCreatesConfigWithPrivateMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	requireFileMode(t, path, configFileMode)
}

// TestSaveTightensExistingConfigMode verifies a pre-existing world-readable
// configuration is tightened instead of keeping its old permissions.
func TestSaveTightensExistingConfigMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "instances: {}\n")
	require.NoError(t, os.Chmod(path, 0o644))

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	requireFileMode(t, path, configFileMode)
}

// TestSaveLeavesNoTemporaryFiles verifies the atomic replacement does not leak
// a temporary copy of a credential-carrying configuration.
func TestSaveLeavesNoTemporaryFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)

	require.NoError(t, manager.Add("home", "home.example.com", "", "admin", "secret"))
	require.NoError(t, manager.Save())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "config.yaml", entries[0].Name())
}

// TestSaveCreatesMissingConfigDirectory verifies a save into an absent
// per-user configuration directory creates it, because the first write of a
// fresh install has no directory to reuse.
func TestSaveCreatesMissingConfigDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), DefaultConfigDirName)
	path := filepath.Join(dir, DefaultConfigFileName)

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", "", "admin", "secret"))

	require.NoError(t, manager.Save())

	requireFileMode(t, dir, configDirMode)
	requireFileMode(t, path, configFileMode)
	assert.Contains(t, readConfigFile(t, path), "home.example.com")
}

// TestSaveKeepsExistingConfigDirectoryMode verifies a save leaves a directory
// the operator created alone, because a save must not renumber a path the
// operator manages.
func TestSaveKeepsExistingConfigDirectoryMode(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), DefaultConfigDirName)
	require.NoError(t, os.Mkdir(dir, 0o750))

	path := filepath.Join(dir, DefaultConfigFileName)
	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	requireFileMode(t, dir, 0o750)
}

// TestWriteFileAtomicReportsUnusableConfigDirectory verifies a save names the
// directory it could not create and writes nothing, when a path component is a
// regular file rather than a directory.
func TestWriteFileAtomicReportsUnusableConfigDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory\n"), configFileMode))

	err := writeFileAtomic(filepath.Join(blocked, DefaultConfigFileName), []byte("instances:\n"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create config dir")

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	require.Len(t, entries, 1)
	assert.Equal(t, "blocked", entries[0].Name())
}

// writeConfigFile writes initial configuration contents for a test.
//
// Parameters:
//   - t: test context.
//   - path: destination file path.
//   - contents: complete file contents.
func writeConfigFile(t *testing.T, path, contents string) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte(contents), configFileMode))
}

// readConfigFile reads written configuration contents for a test.
//
// Parameters:
//   - t: test context.
//   - path: source file path.
//
// Returns:
//   - string: complete file contents.
func readConfigFile(t *testing.T, path string) string {
	t.Helper()

	contents, err := os.ReadFile(path)
	require.NoError(t, err)

	return string(contents)
}

// requireFileMode asserts the permission bits of one file.
//
// The assertion is skipped on Windows, which reports emulated permission bits
// rather than the POSIX mode a configuration file is written with. The saving
// behavior under test still runs on every platform.
//
// Parameters:
//   - t: test context.
//   - path: file to inspect.
//   - want: expected permission bits.
func requireFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	if runtime.GOOS == windowsOS {
		t.Skip("Windows emulates permission bits instead of enforcing POSIX modes")
	}

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, want, info.Mode().Perm())
}
