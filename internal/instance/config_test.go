// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adguardHost is the host used by configuration parsing tests.
const adguardHost = "adguard.example.com"

// unknownSource is a credential source that is not supported.
const unknownSource = "vault"

// customKey is an explicit keyring key used by credential tests.
const customKey = "adguard-production-admin"

// relativeSecretPath is a mounted-secret path that is not absolute.
const relativeSecretPath = "secrets/agh-cli-default"

// secretPath is the absolute mounted-secret path used by credential tests.
const secretPath = "/run/secrets/agh-cli-default"

// secretEnv is the environment variable name used by credential tests.
const secretEnv = "AGH_CLI_DEFAULT_PASSWORD"

// testPassword is the plaintext password used by credential tests.
const testPassword = "secret"

// placeheldPassword is a placeholder that credential errors must never carry.
const placeheldPassword = "must-not-appear-in-errors"

// homeConfig returns an unvalidated home instance with the given credential
// reference.
//
// Parameters:
//   - ref: credential reference, or nil to omit it.
//   - password: plaintext password, or an empty string to omit it.
//
// Returns:
//   - Config: unvalidated instance configuration.
func homeConfig(ref *CredentialRef, password string) Config {
	return Config{
		Name:       "home",
		Host:       adguardHost,
		Scheme:     "",
		Username:   "",
		Password:   password,
		Credential: ref,
	}
}

// TestConfigValidateAppliesDefaults verifies defaults and name-derived identity.
func TestConfigValidateAppliesDefaults(t *testing.T) {
	t.Parallel()

	give := homeConfig(nil, "secret")

	give.Username = "admin"

	cfg, err := give.Validate()

	require.NoError(t, err)
	assert.Equal(t, Config{
		Name:       "home",
		Host:       adguardHost,
		Scheme:     defaultScheme,
		Username:   "admin",
		Password:   "secret",
		Credential: nil,
	}, cfg)
	assert.Equal(t, ID("home"), cfg.Identity())
}

// TestConfigValidateRejectsMissingHost verifies host validation.
func TestConfigValidateRejectsMissingHost(t *testing.T) {
	t.Parallel()

	give := homeConfig(nil, "")

	give.Host = ""

	_, err := give.Validate()

	require.ErrorIs(t, err, ErrMissingHost)
}

// TestConfigValidateRejectsMissingName verifies name validation.
func TestConfigValidateRejectsMissingName(t *testing.T) {
	t.Parallel()

	give := homeConfig(nil, "")

	give.Name = ""

	_, err := give.Validate()

	require.ErrorIs(t, err, ErrMissingName)
}

// TestConfigValidateCredentialSources verifies normalization of every supported
// credential source.
func TestConfigValidateCredentialSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		give     *CredentialRef
		want     *CredentialRef
	}{
		{
			name:     "no reference keeps the legacy password",
			password: testPassword,
			give:     nil,
			want:     nil,
		},
		{
			name: "keyring defaults an empty key to the instance name",
			give: &CredentialRef{Source: KeyringSource},
			want: &CredentialRef{Source: KeyringSource, Key: "home"},
		},
		{
			name: "keyring keeps an explicit key",
			give: &CredentialRef{Source: KeyringSource, Key: customKey},
			want: &CredentialRef{Source: KeyringSource, Key: customKey},
		},
		{
			name: "file requires an absolute path",
			give: &CredentialRef{Source: FileSource, Path: secretPath},
			want: &CredentialRef{Source: FileSource, Path: secretPath},
		},
		{
			name: "env requires a variable name",
			give: &CredentialRef{Source: EnvSource, Env: secretEnv},
			want: &CredentialRef{Source: EnvSource, Env: secretEnv},
		},
		{
			name:     "plaintext uses the configured password",
			password: testPassword,
			give:     &CredentialRef{Source: PlaintextSource},
			want:     &CredentialRef{Source: PlaintextSource},
		},
		{
			name: "none sends no authentication",
			give: &CredentialRef{Source: NoneSource},
			want: &CredentialRef{Source: NoneSource},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := homeConfig(test.give, test.password).Validate()

			require.NoError(t, err)
			assert.Equal(t, test.want, cfg.Credential)
		})
	}
}

// TestConfigValidateRejectsInvalidCredential verifies strict per-source
// validation.
func TestConfigValidateRejectsInvalidCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		give     *CredentialRef
		wantErr  error
	}{
		{
			name:    "unknown source",
			give:    &CredentialRef{Source: unknownSource},
			wantErr: ErrInvalidCredentialSource,
		},
		{
			name:    "empty source",
			give:    &CredentialRef{Key: customKey},
			wantErr: ErrInvalidCredentialSource,
		},
		{
			name:    "keyring rejects a file path",
			give:    &CredentialRef{Source: KeyringSource, Key: customKey, Path: secretPath},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "keyring rejects an environment variable",
			give:    &CredentialRef{Source: KeyringSource, Env: secretEnv},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "file rejects a key",
			give:    &CredentialRef{Source: FileSource, Key: customKey, Path: secretPath},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "file requires a path",
			give:    &CredentialRef{Source: FileSource},
			wantErr: ErrInvalidCredentialPath,
		},
		{
			name:    "file requires an absolute path",
			give:    &CredentialRef{Source: FileSource, Path: relativeSecretPath},
			wantErr: ErrInvalidCredentialPath,
		},
		{
			name:    "file rejects an environment variable",
			give:    &CredentialRef{Source: FileSource, Path: secretPath, Env: secretEnv},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "env requires a variable name",
			give:    &CredentialRef{Source: EnvSource},
			wantErr: ErrInvalidCredentialEnv,
		},
		{
			name:    "env rejects a key",
			give:    &CredentialRef{Source: EnvSource, Key: customKey, Env: secretEnv},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "plaintext requires a password",
			give:    &CredentialRef{Source: PlaintextSource},
			wantErr: ErrMissingPassword,
		},
		{
			name:     "plaintext rejects a key",
			password: testPassword,
			give:     &CredentialRef{Source: PlaintextSource, Key: customKey},
			wantErr:  ErrUnusedCredentialField,
		},
		{
			name:    "none rejects a key",
			give:    &CredentialRef{Source: NoneSource, Key: customKey},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "none rejects a file path",
			give:    &CredentialRef{Source: NoneSource, Path: secretPath},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "none rejects an environment variable",
			give:    &CredentialRef{Source: NoneSource, Env: secretEnv},
			wantErr: ErrUnusedCredentialField,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := homeConfig(test.give, test.password).Validate()

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestConfigValidateCredentialErrorStaysSecretFree verifies that a credential
// error names the offending field without carrying the configured password.
func TestConfigValidateCredentialErrorStaysSecretFree(t *testing.T) {
	t.Parallel()

	_, err := homeConfig(
		&CredentialRef{Source: PlaintextSource, Env: secretEnv},
		placeheldPassword,
	).Validate()

	require.ErrorIs(t, err, ErrUnusedCredentialField)
	assert.NotContains(t, err.Error(), placeheldPassword)
	require.ErrorContains(t, err, envFieldName)
}

// TestIDConflictsWith verifies that only distinct identities equal under case
// folding conflict.
func TestIDConflictsWith(t *testing.T) {
	t.Parallel()

	assert.True(t, ID("Home").ConflictsWith("home"))
	assert.False(t, ID("home").ConflictsWith("home"))
	assert.False(t, ID("home").ConflictsWith("office"))
}

// TestConfigValidateCopiesCredential verifies that normalization never mutates
// the caller's credential reference.
func TestConfigValidateCopiesCredential(t *testing.T) {
	t.Parallel()

	ref := &CredentialRef{Source: KeyringSource}

	validated, err := Config{
		Name:       "home",
		Host:       adguardHost,
		Scheme:     defaultScheme,
		Username:   "",
		Password:   "",
		Credential: ref,
	}.Validate()

	require.NoError(t, err)
	assert.NotSame(t, ref, validated.Credential)
	assert.Equal(t, "home", validated.Credential.Key)
	assert.Empty(t, ref.Key)
}
