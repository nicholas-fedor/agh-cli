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
	"go.yaml.in/yaml/v4"

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

	err = manager.Add("home", "home.example.com", "")
	require.NoError(t, err)
	assert.Equal(t, instance.Config{
		Name:       "home",
		Host:       "home.example.com",
		Scheme:     "https",
		Username:   "",
		Password:   "",
		Credential: nil,
	}, manager.Instances()["home"])

	err = manager.Add("home", "other.example.com", "")
	require.ErrorIs(t, err, ErrInstanceAlreadyExists)

	err = manager.Remove("home")
	require.NoError(t, err)
	assert.Empty(t, manager.Instances())

	err = manager.Remove("home")
	require.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestAddStoresNoCredentials verifies an added instance carries no
// authentication details, because the credential workflow owns both.
func TestAddStoresNoCredentials(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))

	cfg := manager.Instances()["home"]

	assert.Empty(t, cfg.Username)
	assert.Empty(t, cfg.Password)
	assert.Nil(t, cfg.Credential)
}

// TestSetUsernameRecordsUsernameIndependently verifies a username is recorded on
// its own, so changing it leaves the stored credential and the scheme alone.
func TestSetUsernameRecordsUsernameIndependently(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))
	require.NoError(t, manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
	}))

	require.NoError(t, manager.SetUsername("home", "admin"))

	cfg := manager.Instances()["home"]

	assert.Equal(t, "admin", cfg.Username)
	assert.Equal(t, "https", cfg.Scheme)
	assert.Equal(t, "home.example.com", cfg.Host)
	require.NotNil(t, cfg.Credential)
	assert.Equal(t, instance.KeyringSource, cfg.Credential.Source)
	assert.Equal(t, "home", cfg.Credential.Key)
}

// TestSetUsernameReplacesExistingUsername verifies a username can be changed in
// place.
func TestSetUsernameReplacesExistingUsername(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))

	require.NoError(t, manager.SetUsername("home", "first"))
	require.NoError(t, manager.SetUsername("home", "second"))

	assert.Equal(t, "second", manager.Instances()["home"].Username)
}

// TestSetUsernameRejectsUnknownInstance verifies the change names a configured
// instance.
func TestSetUsernameRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	err = manager.SetUsername("absent", "admin")

	require.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestClearUsernameRemovesOnlyUsername verifies clearing a username leaves a
// stored credential reference and a legacy plaintext password in place, because
// the username and the password are managed independently.
func TestClearUsernameRemovesOnlyUsername(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))
	require.NoError(t, manager.SetUsername("home", "admin"))
	require.NoError(t, manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
	}))

	require.NoError(t, manager.ClearUsername("home"))

	cfg := manager.Instances()["home"]
	assert.Empty(t, cfg.Username)
	require.NotNil(t, cfg.Credential)
	assert.Equal(t, instance.KeyringSource, cfg.Credential.Source)
	assert.Equal(t, "home", cfg.Credential.Key)
}

// TestClearUsernameIsIdempotent verifies repeating the clear is safe, because an
// instance without a username is already in the target state.
func TestClearUsernameIsIdempotent(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))

	require.NoError(t, manager.ClearUsername("home"))
	require.NoError(t, manager.ClearUsername("home"))

	assert.Empty(t, manager.Instances()["home"].Username)
}

// TestClearUsernameRejectsUnknownInstance verifies the change names a configured
// instance.
func TestClearUsernameRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	err = manager.ClearUsername("absent")

	require.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestSavePersistsUsernameWithoutCredential verifies a username survives a save
// while the configuration records no password.
func TestSavePersistsUsernameWithoutCredential(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))
	require.NoError(t, manager.SetUsername("home", "admin"))
	require.NoError(t, manager.Save())

	assert.Equal(
		t,
		"instances:\n  home:\n    host: home.example.com\n    username: admin\n",
		readConfigFile(t, path),
	)
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

	require.NoError(t, manager.Add("home", "home.example.com", "https"))
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

	require.NoError(t, manager.Add("home", "home.example.com", ""))

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

	require.NoError(t, manager.Add("home", "home.example.com", ""))
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
	require.NoError(t, manager.Add("home", "home.example.com", ""))

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

// TestSaveWritesThroughSymlinkedConfig verifies a symlinked configuration keeps
// its link and that the file it names receives the change. A rename onto the
// literal link path would replace the link instead and leave the real file
// untouched, which silently sends the change to a file the operator does not
// read.
func TestSaveWritesThroughSymlinkedConfig(t *testing.T) {
	t.Parallel()

	realPath := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, realPath, "instances:\n  a:\n    host: a.example.com\n")

	linkPath := filepath.Join(t.TempDir(), DefaultConfigFileName)
	err := os.Symlink(realPath, linkPath)
	if err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	manager, err := Load(linkPath)
	require.NoError(t, err)
	require.NoError(t, manager.Add("b", "b.example.com", ""))
	require.NoError(t, manager.Save())

	info, err := os.Lstat(linkPath)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the configuration link was replaced")

	assert.Contains(t, readConfigFile(t, realPath), "b.example.com")
}

// TestSaveUsesDanglingSymlinkPath verifies a symlink whose target does not exist
// is used as given, so the link is repaired rather than failing the write.
func TestSaveUsesDanglingSymlinkPath(t *testing.T) {
	t.Parallel()

	linkPath := filepath.Join(t.TempDir(), DefaultConfigFileName)
	err := os.Symlink(filepath.Join(t.TempDir(), "absent.yaml"), linkPath)
	if err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	manager, err := Load(linkPath)
	require.NoError(t, err)
	require.NoError(t, manager.Add("a", "a.example.com", ""))
	require.NoError(t, manager.Save())

	assert.Contains(t, readConfigFile(t, linkPath), "a.example.com")
}

// TestSavePreservesForeignFields verifies a top-level key agh-cli does not own
// survives a save. A configuration that carries an annotation, or a key another
// tool reads, must not lose it on the next write.
func TestSavePreservesForeignFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "my_setting: keep-me\ninstances:\n"+
		"  home:\n    host: home.example.com\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Add("second", "second.example.com", ""))
	require.NoError(t, manager.Save())

	written := readConfigFile(t, path)

	assert.Contains(t, written, "my_setting: keep-me")
	assert.Contains(t, written, "second.example.com")

	// A second cycle must not drop the key either, so the ordering the writer
	// chose is stable.
	reloaded, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, reloaded.Add("third", "third.example.com", ""))
	require.NoError(t, reloaded.Save())

	assert.Contains(t, readConfigFile(t, path), "my_setting: keep-me")
	assert.Contains(t, readConfigFile(t, path), "third.example.com")
}

// TestSavePreservesForeignScalarStyles verifies a foreign scalar keeps the value
// it was written with.
//
// Writing a decoded scalar as text would corrupt each of these: a quoted value
// containing a colon would produce a broken document, an empty value would
// become a null, a value opening with a number sign would become a comment, and
// a literal block would collapse onto one line.
//
// The comparison is on the decoded value rather than the bytes, because the YAML
// encoder is free to reindent a block scalar. The value is what the next reader
// of the file sees, and reindenting it keeps the document valid.
func TestSavePreservesForeignScalarStyles(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		key     string
		foreign string
	}{
		"quoted colon":  {"quoted", "quoted: \"key: value\"\n"},
		"empty string":  {"blank", "blank: \"\"\n"},
		"hash prefixed": {"tag", "tag: \"#not-a-comment\"\n"},
		"block scalar":  {"literal", "literal: |\n  first line\n  second line\n"},
		"folded scalar": {"folded", "folded: >\n  folded text\n"},
		"star prefixed": {"star", "star: \"*not-an-alias\"\n"},
		"bool looking":  {"looks_bool", "looks_bool: \"true\"\n"},
		"leading digit": {"numeric", "numeric: \"0755\"\n"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), DefaultConfigFileName)
			document := tc.foreign + "instances: {}\n"
			writeConfigFile(t, path, document)

			original := decodeForeignValue(t, document, tc.key)

			manager, err := Load(path)
			require.NoError(t, err)
			require.NoError(t, manager.Add("home", "home.example.com", ""))
			require.NoError(t, manager.Save())

			// A second cycle proves the document is still valid YAML and that the
			// value is not degraded on the way through.
			reloaded, err := Load(path)
			require.NoError(t, err, "the saved document must remain parseable")
			assert.Equal(t, []string{"home"}, reloaded.OrderedNames())

			require.NoError(t, reloaded.Add("second", "second.example.com", ""))
			require.NoError(t, reloaded.Save())

			written := readConfigFile(t, path)
			assert.Equal(t, original, decodeForeignValue(t, written, tc.key))
			assert.Contains(t, written, "second.example.com")
		})
	}
}

// decodeForeignValue reads one top-level key out of a configuration document.
//
// Parameters:
//   - t: active test requiring the document to be readable.
//   - document: complete configuration document.
//   - key: top-level key whose value is read.
//
// Returns:
//   - any: the decoded value, or nil when the key is absent.
func decodeForeignValue(t *testing.T, document, key string) any {
	t.Helper()

	var decoded map[string]any

	require.NoError(t, yaml.Unmarshal([]byte(document), &decoded))
	require.Contains(t, decoded, key, "the foreign key must survive the write")

	return decoded[key]
}

// TestSavePreservesForeignMappingAndSequence verifies a foreign key holding a
// nested mapping or a sequence is re-emitted as valid YAML rather than flattened
// onto the key line.
func TestSavePreservesForeignMappingAndSequence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "labels:\n  env: prod\n  team: dns\n"+
		"hosts:\n  - one.example.com\n  - two.example.com\ninstances: {}\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))
	require.NoError(t, manager.Save())

	reloaded, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, []string{"home"}, reloaded.OrderedNames())

	written := readConfigFile(t, path)

	assert.Contains(t, written, "  env: prod")
	assert.Contains(t, written, "  - one.example.com")
	assert.Contains(t, written, "home.example.com")
}

// TestSaveLeavesOwnedFieldsUnchanged verifies a configuration without foreign keys
// serializes exactly as before, so the preservation adds no output to the common
// case.
func TestSaveLeavesOwnedFieldsUnchanged(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "credentials:\n  service: agh-cli\ninstances:\n"+
		"  home:\n    host: home.example.com\n    username: admin\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	assert.Equal(
		t,
		"credentials:\n  service: agh-cli\ninstances:\n"+
			"  home:\n    host: home.example.com\n    username: admin\n",
		readConfigFile(t, path),
	)
}

// TestValidationProblemsReportsUnusableInstances verifies an invalid instance is
// reported by name without failing the load, because refusing the load would
// make the broken instance impossible to remove.
func TestValidationProblemsReportsUnusableInstances(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "instances:\n"+
		"  good:\n    host: good.example.com\n"+
		"  broken:\n    host: broken.example.com\n    credential:\n      source: bogus\n"+
		"  hostless:\n    host: \"\"\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, []string{"good", "broken", "hostless"}, manager.OrderedNames())

	problems := manager.ValidationProblems()

	require.Len(t, problems, 2)
	assert.Equal(t, "broken", problems[0].Instance)
	assert.Contains(t, problems[0].Err.Error(), "invalid credential source")
	assert.Equal(t, "hostless", problems[1].Instance)
	assert.Contains(t, problems[1].Err.Error(), "no host")
}

// TestValidationProblemsReportsNoneForValidConfig verifies a healthy
// configuration produces no problems, so the warning stays silent.
func TestValidationProblemsReportsNoneForValidConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "instances:\n  home:\n    host: home.example.com\n")

	manager, err := Load(path)
	require.NoError(t, err)

	assert.Nil(t, manager.ValidationProblems())
}

// TestLoadAcceptsBlankDocument verifies a file with no content is treated as an
// empty configuration, so a stray tab cannot block the first write. A tab is the
// case that matters, because YAML forbids it as indentation and would otherwise
// reject a file that is visually empty.
func TestLoadAcceptsBlankDocument(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"zero bytes":      "",
		"single newline":  "\n",
		"blank lines":     "\n\n\n",
		"spaces":          "   ",
		"trailing tab":    "\t",
		"newline and tab": "\n\t",
		"mixed blanks":    "\n\n  \n\t\n",
	}

	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), DefaultConfigFileName)
			require.NoError(t, os.WriteFile(path, []byte(contents), configFileMode))

			manager, err := Load(path)

			require.NoError(t, err)
			assert.Empty(t, manager.OrderedNames())
			assert.Nil(t, manager.ValidationProblems())
		})
	}
}

// TestLoadReadsCommentOnlyDocument verifies a document holding only a comment has
// content and is parsed, so a comment is not treated as blank.
func TestLoadReadsCommentOnlyDocument(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "# managed by hand\n")

	manager, err := Load(path)
	require.NoError(t, err)
	assert.Empty(t, manager.OrderedNames())
}

// TestLoadRejectsDirectoryPath verifies a directory is refused by name rather
// than surfacing an opaque configuration-type error.
func TestLoadRejectsDirectoryPath(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	_, err := Load(directory)

	require.ErrorIs(t, err, ErrConfigNotRegular)
	assert.Contains(t, err.Error(), directory)
}

// TestHasContentSeparatesAbsentBlankAndRead verifies the content predicate
// separates the three states configuration resolution depends on.
func TestHasContentSeparatesAbsentBlankAndRead(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	hasContent, err := HasContent(filepath.Join(dir, "absent.yaml"))
	require.NoError(t, err)
	assert.False(t, hasContent, "an absent file has no content")

	blank := filepath.Join(dir, "blank.yaml")
	require.NoError(t, os.WriteFile(blank, []byte("\t"), configFileMode))

	hasContent, err = HasContent(blank)
	require.NoError(t, err)
	assert.False(t, hasContent, "a blank file has no content")

	full := filepath.Join(dir, "full.yaml")
	require.NoError(t, os.WriteFile(full, []byte("instances: {}\n"), configFileMode))

	hasContent, err = HasContent(full)
	require.NoError(t, err)
	assert.True(t, hasContent, "a file with content is read")
}

// TestHasContentRejectsDirectory verifies a directory is refused rather than
// reported as a blank configuration.
func TestHasContentRejectsDirectory(t *testing.T) {
	t.Parallel()

	_, err := HasContent(t.TempDir())

	require.ErrorIs(t, err, ErrConfigNotRegular)
}

// TestSaveRefusesChangedConfig verifies a save refuses to overwrite a
// configuration that changed after it was read, so a concurrent editor or a
// second agh-cli process cannot have its change discarded silently.
func TestSaveRefusesChangedConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	writeConfigFile(t, path, "instances:\n  home:\n    host: home.example.com\n")

	manager, err := Load(path)
	require.NoError(t, err)

	// An external writer replaces the file between the load and the save.
	writeConfigFile(t, path, "instances:\n  external:\n    host: external.example.com\n")

	err = manager.Add("added", "added.example.com", "")
	require.NoError(t, err)

	err = manager.Save()

	require.ErrorIs(t, err, ErrConfigChanged)
	assert.NotContains(t, readConfigFile(t, path), "added.example.com")
	assert.Contains(t, readConfigFile(t, path), "external.example.com")
}

// TestSaveAcceptsSecondWriteFromSameManager verifies a manager may save twice.
// The first save changes the file, which must not read as an external change on
// the second.
func TestSaveAcceptsSecondWriteFromSameManager(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Add("first", "first.example.com", ""))
	require.NoError(t, manager.Save())

	require.NoError(t, manager.Add("second", "second.example.com", ""))
	require.NoError(t, manager.Save())

	written := readConfigFile(t, path)

	assert.Contains(t, written, "first.example.com")
	assert.Contains(t, written, "second.example.com")
}

// TestSaveOverwritesConfigThatAppearedAfterLoad verifies a file created between
// the load and the save is a first write, not a change this run must respect. A
// bootstrap run loads an absent file and then creates it, and refusing that
// would make a fresh install impossible.
func TestSaveOverwritesConfigThatAppearedAfterLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultConfigFileName)

	manager, err := Load(path)
	require.NoError(t, err)

	writeConfigFile(t, path, "instances:\n  appeared:\n    host: appeared.example.com\n")

	require.NoError(t, manager.Add("added", "added.example.com", ""))

	err = manager.Save()

	require.NoError(t, err)
	assert.Contains(t, readConfigFile(t, path), "added.example.com")
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
