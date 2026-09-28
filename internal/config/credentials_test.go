// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TestLoadReadsCredentialService verifies the top-level credentials mapping
// supplies the credential store service.
func TestLoadReadsCredentialService(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "credentials:\n  service: agh-cli-custom\ninstances: {}\n")

	manager, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, CredentialsSettings{Service: "agh-cli-custom"}, manager.Credentials())
}

// TestLoadDefaultsCredentialService verifies a configuration without a
// credentials mapping reports the default service.
func TestLoadDefaultsCredentialService(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "instances:\n  home:\n    host: home.example.com\n")

	manager, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, CredentialsSettings{Service: DefaultCredentialService}, manager.Credentials())
}

// TestLoadKeepsDefaultServiceForEmptyService verifies an empty service never
// replaces the default namespace, because the service must stay non-empty.
func TestLoadKeepsDefaultServiceForEmptyService(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "credentials:\n  service: \"\"\ninstances: {}\n")

	manager, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, CredentialsSettings{Service: DefaultCredentialService}, manager.Credentials())
}

// TestLoadRejectsInvalidCredentialsMapping verifies a credentials value that is
// not a complete mapping is rejected.
func TestLoadRejectsInvalidCredentialsMapping(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"scalar":   "credentials: agh-cli\n",
		"sequence": "credentials:\n  - agh-cli\n",
	}

	for name, give := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfigFile(t, path, give)

			_, err := Load(path)

			require.ErrorIs(t, err, ErrInvalidCredentialsMap)
		})
	}
}

// TestLoadRejectsNonScalarCredentialService verifies a service that is not a
// string is rejected instead of silently defaulting.
func TestLoadRejectsNonScalarCredentialService(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "credentials:\n  service:\n    - agh-cli\n")

	_, err := Load(path)

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidCredentialsMap)
}

// TestLoadIgnoresUnknownCredentialsKeys verifies an unrecognized credentials
// key does not prevent the service from loading.
func TestLoadIgnoresUnknownCredentialsKeys(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "credentials:\n  unknown: value\n  service: agh-cli\n")

	manager, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, CredentialsSettings{Service: "agh-cli"}, manager.Credentials())
}

// TestLoadReadsInstanceCredentialReferences verifies per-instance credential
// stanzas decode for every supported source.
func TestLoadReadsInstanceCredentialReferences(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		credential string
		want       *instance.CredentialRef
	}{
		"keyring with key": {
			credential: "    credential:\n      source: keyring\n      key: adguard-admin\n",
			want: &instance.CredentialRef{
				Source: instance.KeyringSource,
				Key:    "adguard-admin",
				Path:   "",
				Env:    "",
			},
		},
		"keyring without key": {
			credential: "    credential:\n      source: keyring\n",
			want: &instance.CredentialRef{
				Source: instance.KeyringSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
		},
		"file": {
			credential: "    credential:\n      source: file\n      path: /run/secrets/agh\n",
			want: &instance.CredentialRef{
				Source: instance.FileSource,
				Key:    "",
				Path:   "/run/secrets/agh",
				Env:    "",
			},
		},
		"environment": {
			credential: "    credential:\n      source: env\n      env: AGH_CLI_PASSWORD\n",
			want: &instance.CredentialRef{
				Source: instance.EnvSource,
				Key:    "",
				Path:   "",
				Env:    "AGH_CLI_PASSWORD",
			},
		},
		"none": {
			credential: "    credential:\n      source: none\n",
			want: &instance.CredentialRef{
				Source: instance.NoneSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfigFile(t, path,
				"instances:\n  home:\n    host: home.example.com\n"+test.credential)

			manager, err := Load(path)
			require.NoError(t, err)

			cfg := manager.Instances()["home"]
			assert.Equal(t, test.want, cfg.Credential)
		})
	}
}

// TestLoadRejectsNonMappingCredentialStanza verifies a mistyped credential
// stanza is rejected instead of falling back to the plaintext password.
func TestLoadRejectsNonMappingCredentialStanza(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"instances:\n  home:\n    host: home.example.com\n    credential: keyring\n")

	_, err := Load(path)

	require.Error(t, err)
}

// TestSaveWritesCredentialsStanzaBeforeInstances verifies a loaded credentials
// mapping is written above the instances it applies to.
func TestSaveWritesCredentialsStanzaBeforeInstances(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"credentials:\n  service: agh-cli-custom\ninstances:\n  home:\n    host: home.example.com\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	assert.Equal(t,
		"credentials:\n  service: agh-cli-custom\n"+
			"instances:\n  home:\n    host: home.example.com\n",
		readConfigFile(t, path),
	)
}

// TestSaveOmitsCredentialsStanzaWhenAbsent verifies a configuration without a
// credentials mapping does not gain one, so legacy files round-trip unchanged.
func TestSaveOmitsCredentialsStanzaWhenAbsent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)

	require.NoError(t, manager.Add("home", "home.example.com", ""))
	require.NoError(t, manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
		Path:   "",
		Env:    "",
	}))
	require.NoError(t, manager.Save())

	give := readConfigFile(t, path)
	assert.NotContains(t, give, "credentials:")
	assert.Equal(t, DefaultCredentialService, manager.Credentials().Service)
}

// TestSaveRoundTripsCredentialSource verifies a loaded credential reference
// survives a save and load cycle unchanged.
func TestSaveRoundTripsCredentialSource(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n  home:\n"+
			"    host: home.example.com\n"+
			"    username: admin\n"+
			"    credential:\n      source: keyring\n      key: adguard-admin\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	reloaded, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, manager.Credentials(), reloaded.Credentials())
	assert.Equal(t, manager.Instances(), reloaded.Instances())
	assert.Equal(t, manager.OrderedNames(), reloaded.OrderedNames())
}

// TestSaveWritesCredentialFieldsInStableOrder verifies the credential stanza
// always serializes as source, key, path, env.
func TestSaveWritesCredentialFieldsInStableOrder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	manager, err := Load(path)
	require.NoError(t, err)

	require.NoError(t, manager.Add("home", "home.example.com", ""))
	require.NoError(t, manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "adguard-admin",
		Path:   "/run/secrets/agh",
		Env:    "AGH_CLI_PASSWORD",
	}))
	require.NoError(t, manager.Save())

	assert.Equal(t,
		"instances:\n"+
			"  home:\n"+
			"    host: home.example.com\n"+
			"    credential:\n"+
			"      source: keyring\n"+
			"      key: adguard-admin\n"+
			"      path: /run/secrets/agh\n"+
			"      env: AGH_CLI_PASSWORD\n",
		readConfigFile(t, path),
	)
}

// TestSaveWritesSingleCredentialFieldPerSource verifies a source serializes
// only the field it consumes.
func TestSaveWritesSingleCredentialFieldPerSource(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ref  instance.CredentialRef
		want string
	}{
		"keyring": {
			ref: instance.CredentialRef{
				Source: instance.KeyringSource,
				Key:    "home",
				Path:   "",
				Env:    "",
			},
			want: "    credential:\n      source: keyring\n      key: home\n",
		},
		"file": {
			ref: instance.CredentialRef{
				Source: instance.FileSource,
				Key:    "",
				Path:   "/run/secrets/agh",
				Env:    "",
			},
			want: "    credential:\n      source: file\n      path: /run/secrets/agh\n",
		},
		"environment": {
			ref: instance.CredentialRef{
				Source: instance.EnvSource,
				Key:    "",
				Path:   "",
				Env:    "AGH_CLI_PASSWORD",
			},
			want: "    credential:\n      source: env\n      env: AGH_CLI_PASSWORD\n",
		},
		"none": {
			ref: instance.CredentialRef{
				Source: instance.NoneSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
			want: "    credential:\n      source: none\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "config.yaml")
			manager, err := Load(path)
			require.NoError(t, err)

			require.NoError(t, manager.Add("home", "home.example.com", ""))
			require.NoError(t, manager.SetCredential("home", test.ref))
			require.NoError(t, manager.Save())

			assert.Contains(t, readConfigFile(t, path), test.want)
		})
	}
}

// TestSaveOmitsPasswordForCredentialInstance verifies a migrated instance never
// serializes its password again, even while the secret is still in memory.
func TestSaveOmitsPasswordForCredentialInstance(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"instances:\n  home:\n    host: home.example.com\n    password: legacy-secret\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "legacy-secret", manager.Instances()["home"].Password)

	err = manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
		Path:   "",
		Env:    "",
	})
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	give := readConfigFile(t, path)
	assert.NotContains(t, give, "password")
	assert.NotContains(t, give, "legacy-secret")
	assert.Equal(t,
		"instances:\n"+
			"  home:\n"+
			"    host: home.example.com\n"+
			"    credential:\n"+
			"      source: keyring\n"+
			"      key: home\n",
		give,
	)

	// Clearing the plaintext password is a separate, later step and must not
	// change what the configuration file contains.
	require.NoError(t, manager.ClearLegacyPassword("home"))
	require.NoError(t, manager.Save())
	assert.Equal(t, give, readConfigFile(t, path))
}

// TestSaveWritesPasswordOnlyForSourcesThatReadIt verifies an explicit plaintext
// source keeps its password, and that no other credential source can smuggle a
// secret back into the configuration file.
func TestSaveWritesPasswordOnlyForSourcesThatReadIt(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		source instance.CredentialSource
		want   string
	}{
		"plaintext": {source: instance.PlaintextSource, want: "    password: legacy-secret\n"},
		"keyring":   {source: instance.KeyringSource, want: ""},
		"file":      {source: instance.FileSource, want: ""},
		"env":       {source: instance.EnvSource, want: ""},
		"none":      {source: instance.NoneSource, want: ""},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfigFile(t, path,
				"instances:\n  home:\n    host: home.example.com\n    password: legacy-secret\n")

			manager, err := Load(path)
			require.NoError(t, err)

			err = manager.SetCredential("home", instance.CredentialRef{
				Source: test.source,
				Key:    "home",
				Path:   "/run/secrets/agh",
				Env:    "AGH_CLI_PASSWORD",
			})
			require.NoError(t, err)
			require.NoError(t, manager.Save())

			give := readConfigFile(t, path)
			assert.Contains(t, give, "      source: "+string(test.source)+"\n")

			if test.want == "" {
				assert.NotContains(t, give, "password:")
				assert.NotContains(t, give, "legacy-secret")

				return
			}

			assert.Contains(t, give, test.want)
		})
	}
}

// TestSaveRoundTripsPlaintextSourcePassword verifies an explicit plaintext
// source survives a save and load cycle, so the written configuration stays
// valid instead of losing the password its source requires.
func TestSaveRoundTripsPlaintextSourcePassword(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"instances:\n  home:\n    host: home.example.com\n"+
			"    username: admin\n    password: legacy-secret\n")

	manager, err := Load(path)
	require.NoError(t, err)

	err = manager.SetCredential("home", instance.CredentialRef{
		Source: instance.PlaintextSource,
		Key:    "",
		Path:   "",
		Env:    "",
	})
	require.NoError(t, err)
	require.NoError(t, manager.Save())

	assert.Equal(t,
		"instances:\n"+
			"  home:\n"+
			"    host: home.example.com\n"+
			"    username: admin\n"+
			"    credential:\n"+
			"      source: plaintext\n"+
			"    password: legacy-secret\n",
		readConfigFile(t, path),
	)

	reloaded, err := Load(path)
	require.NoError(t, err)

	cfg := reloaded.Instances()["home"]
	require.NotNil(t, cfg.Credential)
	assert.Equal(t, instance.PlaintextSource, cfg.Credential.Source)
	assert.Equal(t, "legacy-secret", cfg.Password)

	// A saved plaintext source must remain loadable as a valid instance, which
	// requires the password the source reads.
	validated, err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, instance.PlaintextSource, validated.Credential.Source)
}

// TestSetCredentialStoresIndependentCopy verifies a later change to the
// caller's reference does not reach the manager.
func TestSetCredentialStoresIndependentCopy(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	require.NoError(t, manager.Add("home", "home.example.com", ""))

	ref := instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
		Path:   "",
		Env:    "",
	}
	require.NoError(t, manager.SetCredential("home", ref))

	ref.Key = "mutated"

	stored := manager.Instances()["home"].Credential
	require.NotNil(t, stored)
	assert.Equal(t, "home", stored.Key)
}

// TestSetCredentialKeepsExistingPassword verifies storing a reference leaves
// the in-memory password untouched.
func TestSetCredentialKeepsExistingPassword(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "instances:\n"+
		"  home:\n"+
		"    host: home.example.com\n"+
		"    username: admin\n"+
		"    password: legacy-secret\n")

	manager, err := Load(path)
	require.NoError(t, err)

	err = manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
		Path:   "",
		Env:    "",
	})
	require.NoError(t, err)

	assert.Equal(t, "legacy-secret", manager.Instances()["home"].Password)
}

// TestSetCredentialRejectsUnknownInstance verifies the mutator reports a
// missing instance.
func TestSetCredentialRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	err = manager.SetCredential("absent", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "absent",
		Path:   "",
		Env:    "",
	})

	require.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestClearCredentialRemovesStanzaAndRetainsInstance verifies clearing the
// reference drops the credential stanza from a saved file while the rest of the
// instance survives.
func TestClearCredentialRemovesStanzaAndRetainsInstance(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n  home:\n"+
			"    host: home.example.com\n"+
			"    username: admin\n"+
			"    credential:\n      source: keyring\n      key: adguard-admin\n")

	manager, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, manager.ClearCredential("home"))

	cfg := manager.Instances()["home"]
	assert.Nil(t, cfg.Credential)
	assert.Equal(t, "admin", cfg.Username)
	assert.Equal(t, "home.example.com", cfg.Host)

	require.NoError(t, manager.Save())

	assert.Equal(t,
		"credentials:\n  service: agh-cli\n"+
			"instances:\n  home:\n"+
			"    host: home.example.com\n"+
			"    username: admin\n",
		readConfigFile(t, path),
	)

	reloaded, err := Load(path)
	require.NoError(t, err)

	saved := reloaded.Instances()["home"]
	assert.Nil(t, saved.Credential)
	assert.Equal(t, "admin", saved.Username)

	validated, err := saved.Validate()
	require.NoError(t, err)
	assert.Nil(t, validated.Credential)
}

// TestClearCredentialRestoresLegacyPasswordSerialization verifies a cleared
// instance writes its plaintext password again, because a configuration without
// a stanza is a legacy configuration.
func TestClearCredentialRestoresLegacyPasswordSerialization(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"instances:\n  home:\n    host: home.example.com\n    password: legacy-secret\n")

	manager, err := Load(path)
	require.NoError(t, err)

	err = manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
		Path:   "",
		Env:    "",
	})
	require.NoError(t, err)
	require.NoError(t, manager.Save())
	assert.NotContains(t, readConfigFile(t, path), "legacy-secret")

	require.NoError(t, manager.ClearCredential("home"))
	require.NoError(t, manager.Save())

	assert.Equal(t,
		"instances:\n"+
			"  home:\n"+
			"    host: home.example.com\n"+
			"    password: legacy-secret\n",
		readConfigFile(t, path),
	)
}

// TestClearCredentialKeepsLegacyInstanceUnchanged verifies clearing an instance
// that never had a credential reference leaves its file byte-identical.
func TestClearCredentialKeepsLegacyInstanceUnchanged(t *testing.T) {
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
	require.NoError(t, manager.ClearCredential("home"))
	require.NoError(t, manager.Save())

	assert.Equal(t, give, readConfigFile(t, path))
}

// TestClearCredentialIsIdempotent verifies repeating the call is safe, both for
// an instance that had a reference and for one that never did.
func TestClearCredentialIsIdempotent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path,
		"instances:\n  home:\n    host: home.example.com\n"+
			"    credential:\n      source: env\n      env: AGH_CLI_PASSWORD\n")

	manager, err := Load(path)
	require.NoError(t, err)

	require.NoError(t, manager.ClearCredential("home"))
	require.NoError(t, manager.ClearCredential("home"))
	require.NoError(t, manager.ClearCredential("home"))

	assert.True(t, manager.Exists("home"))
	assert.Nil(t, manager.Instances()["home"].Credential)
}

// TestClearCredentialRejectsUnknownInstance verifies the mutator reports a
// missing instance instead of creating one.
func TestClearCredentialRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	err = manager.ClearCredential("absent")

	require.ErrorIs(t, err, ErrInstanceNotFound)
	assert.False(t, manager.Exists("absent"))
}

// TestClearPasswordKeepsCredentialReference verifies clearing the plaintext
// password does not drop the credential source.
func TestClearPasswordKeepsCredentialReference(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "instances:\n"+
		"  home:\n"+
		"    host: home.example.com\n"+
		"    username: admin\n"+
		"    password: legacy-secret\n")

	manager, err := Load(path)
	require.NoError(t, err)

	err = manager.SetCredential("home", instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    "home",
		Path:   "",
		Env:    "",
	})
	require.NoError(t, err)
	require.NoError(t, manager.ClearLegacyPassword("home"))

	cfg := manager.Instances()["home"]
	assert.Empty(t, cfg.Password)
	assert.Equal(t, "admin", cfg.Username)
	require.NotNil(t, cfg.Credential)
	assert.Equal(t, instance.KeyringSource, cfg.Credential.Source)
}

// TestClearPasswordRejectsUnknownInstance verifies the mutator reports a
// missing instance.
func TestClearPasswordRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	manager, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	err = manager.ClearLegacyPassword("absent")

	require.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestLoadRejectsUnreadableConfig verifies a configuration that cannot be read
// is reported instead of silently treated as empty.
func TestLoadRejectsUnreadableConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not restrict the root user")
	}

	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, "instances:\n")
	require.NoError(t, os.Chmod(path, 0o000))

	_, err := Load(path)

	require.Error(t, err)
}
