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

// passwordKey is the raw instance password key.
const passwordKey = "password"

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

// rawInstance returns a raw instance mapping with the given credential stanza.
//
// Parameters:
//   - stanza: credential stanza fields, or nil to omit the stanza.
//   - password: plaintext password, or an empty string to omit it.
//
// Returns:
//   - map[string]any: raw instance mapping.
func rawInstance(stanza map[string]any, password string) map[string]any {
	raw := map[string]any{hostKey: adguardHost}

	if password != "" {
		raw[passwordKey] = password
	}

	if stanza != nil {
		raw[credentialFieldName] = stanza
	}

	return raw
}

// TestConfigFromMap verifies defaults and mapping-derived identity.
func TestConfigFromMap(t *testing.T) {
	t.Parallel()

	give := map[string]any{
		"host":     adguardHost,
		"username": "admin",
		"password": "secret",
	}

	cfg, err := ConfigFromMap("home", give)

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

// TestConfigFromMapRejectsMissingHost verifies host validation.
func TestConfigFromMapRejectsMissingHost(t *testing.T) {
	t.Parallel()

	_, err := ConfigFromMap("home", map[string]any{})

	require.ErrorIs(t, err, ErrMissingHost)
}

// TestConfigFromMapRejectsMissingName verifies mapping-derived name validation.
func TestConfigFromMapRejectsMissingName(t *testing.T) {
	t.Parallel()

	_, err := ConfigFromMap("", map[string]any{hostKey: adguardHost})

	require.ErrorIs(t, err, ErrMissingName)
}

// TestConfigFromMapCredentialSources verifies decoding and normalization of every
// supported credential source.
func TestConfigFromMapCredentialSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		stanza   map[string]any
		want     *CredentialRef
	}{
		{
			name:     "no stanza keeps the legacy password",
			password: testPassword,
			want:     nil,
		},
		{
			name:   "keyring defaults an empty key to the instance name",
			stanza: map[string]any{sourceFieldName: string(KeyringSource)},
			want:   &CredentialRef{Source: KeyringSource, Key: "home"},
		},
		{
			name: "keyring keeps an explicit key",
			stanza: map[string]any{
				sourceFieldName: string(KeyringSource),
				keyFieldName:    customKey,
			},
			want: &CredentialRef{Source: KeyringSource, Key: customKey},
		},
		{
			name: "file requires an absolute path",
			stanza: map[string]any{
				sourceFieldName: string(FileSource),
				pathFieldName:   secretPath,
			},
			want: &CredentialRef{Source: FileSource, Path: secretPath},
		},
		{
			name: "env requires a variable name",
			stanza: map[string]any{
				sourceFieldName: string(EnvSource),
				envFieldName:    secretEnv,
			},
			want: &CredentialRef{Source: EnvSource, Env: secretEnv},
		},
		{
			name:     "plaintext uses the configured password",
			password: testPassword,
			stanza:   map[string]any{sourceFieldName: string(PlaintextSource)},
			want:     &CredentialRef{Source: PlaintextSource},
		},
		{
			name:   "none sends no authentication",
			stanza: map[string]any{sourceFieldName: string(NoneSource)},
			want:   &CredentialRef{Source: NoneSource},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := ConfigFromMap("home", rawInstance(test.stanza, test.password))

			require.NoError(t, err)
			assert.Equal(t, test.want, cfg.Credential)
		})
	}
}

// TestConfigFromMapRejectsInvalidCredential verifies strict per-source validation.
func TestConfigFromMapRejectsInvalidCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		stanza   map[string]any
		wantErr  error
	}{
		{
			name:    "unknown source",
			stanza:  map[string]any{sourceFieldName: unknownSource},
			wantErr: ErrInvalidCredentialSource,
		},
		{
			name:    "empty source",
			stanza:  map[string]any{keyFieldName: customKey},
			wantErr: ErrInvalidCredentialSource,
		},
		{
			name: "keyring rejects a file path",
			stanza: map[string]any{
				sourceFieldName: string(KeyringSource),
				keyFieldName:    customKey,
				pathFieldName:   secretPath,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name: "keyring rejects an environment variable",
			stanza: map[string]any{
				sourceFieldName: string(KeyringSource),
				envFieldName:    secretEnv,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name: "file rejects a key",
			stanza: map[string]any{
				sourceFieldName: string(FileSource),
				keyFieldName:    customKey,
				pathFieldName:   secretPath,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "file requires a path",
			stanza:  map[string]any{sourceFieldName: string(FileSource)},
			wantErr: ErrInvalidCredentialPath,
		},
		{
			name: "file requires an absolute path",
			stanza: map[string]any{
				sourceFieldName: string(FileSource),
				pathFieldName:   relativeSecretPath,
			},
			wantErr: ErrInvalidCredentialPath,
		},
		{
			name: "file rejects an environment variable",
			stanza: map[string]any{
				sourceFieldName: string(FileSource),
				pathFieldName:   secretPath,
				envFieldName:    secretEnv,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "env requires a variable name",
			stanza:  map[string]any{sourceFieldName: string(EnvSource)},
			wantErr: ErrInvalidCredentialEnv,
		},
		{
			name: "env rejects a key",
			stanza: map[string]any{
				sourceFieldName: string(EnvSource),
				keyFieldName:    customKey,
				envFieldName:    secretEnv,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name:    "plaintext requires a password",
			stanza:  map[string]any{sourceFieldName: string(PlaintextSource)},
			wantErr: ErrMissingPassword,
		},
		{
			name:     "plaintext rejects a key",
			password: testPassword,
			stanza: map[string]any{
				sourceFieldName: string(PlaintextSource),
				keyFieldName:    customKey,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name: "none rejects a key",
			stanza: map[string]any{
				sourceFieldName: string(NoneSource),
				keyFieldName:    customKey,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name: "none rejects a file path",
			stanza: map[string]any{
				sourceFieldName: string(NoneSource),
				pathFieldName:   secretPath,
			},
			wantErr: ErrUnusedCredentialField,
		},
		{
			name: "none rejects an environment variable",
			stanza: map[string]any{
				sourceFieldName: string(NoneSource),
				envFieldName:    secretEnv,
			},
			wantErr: ErrUnusedCredentialField,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ConfigFromMap("home", rawInstance(test.stanza, test.password))

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestConfigFromMapRejectsNonMappingCredential verifies that a mistyped stanza is
// rejected instead of silently falling back to the plaintext password.
func TestConfigFromMapRejectsNonMappingCredential(t *testing.T) {
	t.Parallel()

	for _, give := range []any{"keyring", []any{KeyringSource}, 42} {
		_, err := ConfigFromMap("home", map[string]any{
			hostKey:             adguardHost,
			credentialFieldName: give,
		})

		require.ErrorIs(t, err, ErrInvalidConfig)
	}
}

// TestConfigFromMapCredentialErrorStaysSecretFree verifies that a credential
// error names the offending field without carrying the configured password.
func TestConfigFromMapCredentialErrorStaysSecretFree(t *testing.T) {
	t.Parallel()

	_, err := ConfigFromMap("home", rawInstance(map[string]any{
		sourceFieldName: string(PlaintextSource),
		envFieldName:    secretEnv,
	}, placeheldPassword))

	require.ErrorIs(t, err, ErrUnusedCredentialField)
	assert.NotContains(t, err.Error(), placeheldPassword)
	require.ErrorContains(t, err, envFieldName)
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
