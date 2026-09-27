// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// instanceName is the instance identifier used by resolver tests.
const instanceName = "default"

// secretPath is the absolute mounted-secret path used by resolver tests.
const secretPath = "/run/secrets/agh-cli-default"

// secretEnv is the environment variable name used by resolver tests.
const secretEnv = "AGH_CLI_DEFAULT_PASSWORD"

// unknownSource is a credential source that the resolver does not support.
const unknownSource = "vault"

// TestResolverResolveReadsConfiguredSource verifies that each supported source
// supplies the password and that no other source is consulted.
func TestResolverResolveReadsConfiguredSource(t *testing.T) {
	t.Parallel()

	legacyPassword := "legacy-password"

	tests := []struct {
		name               string
		credential         *instance.CredentialRef
		password           string
		expectedPassword   string
		expectedError      error
		expectedStoreCalls []storeCall
		expectedFileCalls  []string
		expectedEnvCalls   []string
	}{
		{
			name:               "no credential reference keeps the legacy password",
			credential:         nil,
			password:           legacyPassword,
			expectedPassword:   legacyPassword,
			expectedError:      nil,
			expectedStoreCalls: nil,
			expectedFileCalls:  nil,
			expectedEnvCalls:   nil,
		},
		{
			name: "keyring source reads the configured key",
			credential: &instance.CredentialRef{
				Source: instance.KeyringSource,
				Key:    "adguard-production-admin",
				Path:   "",
				Env:    "",
			},
			password:           legacyPassword,
			expectedPassword:   testSecret,
			expectedError:      nil,
			expectedStoreCalls: []storeCall{{service: testService, key: "adguard-production-admin", secret: ""}},
			expectedFileCalls:  nil,
			expectedEnvCalls:   nil,
		},
		{
			name: "keyring source defaults an empty key to the instance name",
			credential: &instance.CredentialRef{
				Source: instance.KeyringSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
			password:           legacyPassword,
			expectedPassword:   testSecret,
			expectedError:      nil,
			expectedStoreCalls: []storeCall{{service: testService, key: instanceName, secret: ""}},
			expectedFileCalls:  nil,
			expectedEnvCalls:   nil,
		},
		{
			name: "file source preserves the exact file bytes",
			credential: &instance.CredentialRef{
				Source: instance.FileSource,
				Key:    "",
				Path:   secretPath,
				Env:    "",
			},
			password:           legacyPassword,
			expectedPassword:   testSecret + "\n",
			expectedError:      nil,
			expectedStoreCalls: nil,
			expectedFileCalls:  []string{secretPath},
			expectedEnvCalls:   nil,
		},
		{
			name: "environment source reads only the configured variable",
			credential: &instance.CredentialRef{
				Source: instance.EnvSource,
				Key:    "",
				Path:   "",
				Env:    secretEnv,
			},
			password:           legacyPassword,
			expectedPassword:   testSecret,
			expectedError:      nil,
			expectedStoreCalls: nil,
			expectedFileCalls:  nil,
			expectedEnvCalls:   []string{secretEnv},
		},
		{
			name: "plaintext source keeps the configuration password",
			credential: &instance.CredentialRef{
				Source: instance.PlaintextSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
			password:           legacyPassword,
			expectedPassword:   legacyPassword,
			expectedError:      nil,
			expectedStoreCalls: nil,
			expectedFileCalls:  nil,
			expectedEnvCalls:   nil,
		},
		{
			name: "none source clears the password without a lookup",
			credential: &instance.CredentialRef{
				Source: instance.NoneSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
			password:           legacyPassword,
			expectedPassword:   "",
			expectedError:      nil,
			expectedStoreCalls: nil,
			expectedFileCalls:  nil,
			expectedEnvCalls:   nil,
		},
		{
			name: "unknown source is rejected",
			credential: &instance.CredentialRef{
				Source: unknownSource,
				Key:    "",
				Path:   "",
				Env:    "",
			},
			password:           legacyPassword,
			expectedPassword:   legacyPassword,
			expectedError:      instance.ErrInvalidCredentialSource,
			expectedStoreCalls: nil,
			expectedFileCalls:  nil,
			expectedEnvCalls:   nil,
		},
	}

	for index := range tests {
		t.Run(tests[index].name, func(t *testing.T) {
			t.Parallel()

			test := &tests[index]

			provider := newFakeProvider()

			provider.store(testService, instanceName, testSecret)
			provider.store(testService, "adguard-production-admin", testSecret)

			files := &fakeFileReader{data: map[string][]byte{secretPath: []byte(testSecret + "\n")}}
			env := &fakeEnvReader{values: map[string]string{secretEnv: testSecret}}

			resolver := NewResolver(testService, newSystemStoreWithProvider(provider), files, env)

			resolved, err := resolver.Resolve(t.Context(), instance.Config{
				Name:       instanceName,
				Host:       "adguard.example.com",
				Scheme:     "https",
				Username:   "admin",
				Password:   test.password,
				Credential: test.credential,
			})

			if test.expectedError != nil {
				require.ErrorIs(t, err, test.expectedError)
				assert.Equal(t, test.password, resolved.Password)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expectedPassword, resolved.Password)
			}

			assert.Equal(t, test.expectedStoreCalls, provider.calls)
			assert.Equal(t, test.expectedFileCalls, files.calls)
			assert.Equal(t, test.expectedEnvCalls, env.calls)
		})
	}
}

// TestResolverResolveDoesNotFallBack verifies that a failed explicit source is
// an error even when another source could supply a password.
func TestResolverResolveDoesNotFallBack(t *testing.T) {
	t.Parallel()

	credential := &instance.CredentialRef{
		Source: instance.KeyringSource,
		Key:    instanceName,
		Path:   "",
		Env:    "",
	}

	provider := newFakeProvider()
	env := &fakeEnvReader{values: map[string]string{secretEnv: testSecret}}
	files := &fakeFileReader{data: map[string][]byte{secretPath: []byte(testSecret)}}

	resolver := NewResolver(
		testService,
		newSystemStoreWithProvider(provider),
		files,
		env,
	)

	cfg := instance.Config{
		Name:       instanceName,
		Host:       "adguard.example.com",
		Scheme:     "https",
		Username:   "admin",
		Password:   "legacy-password",
		Credential: credential,
	}

	resolved, err := resolver.Resolve(t.Context(), cfg)

	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, cfg.Password, resolved.Password)
	assert.Equal(t, resolved, cfg)
	assert.Empty(t, files.calls)
	assert.Empty(t, env.calls)
}

// TestResolverResolveEnvSourceRequiresVariable verifies that an unset or
// unnamed environment variable is an error rather than a fallback.
func TestResolverResolveEnvSourceRequiresVariable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		env           string
		expectedError error
	}{
		{
			name:          "unset variable",
			env:           "AGH_CLI_MISSING_PASSWORD",
			expectedError: ErrEnvUnset,
		},
		{
			name:          "unnamed variable",
			env:           "",
			expectedError: instance.ErrInvalidCredentialEnv,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			provider := newFakeProvider()
			provider.store(testService, instanceName, testSecret)

			resolver := NewResolver(
				testService,
				newSystemStoreWithProvider(provider),
				&fakeFileReader{},
				&fakeEnvReader{values: map[string]string{}},
			)

			resolved, err := resolver.Resolve(t.Context(), instance.Config{
				Name:     instanceName,
				Host:     "adguard.example.com",
				Scheme:   "https",
				Username: "admin",
				Password: "legacy-password",
				Credential: &instance.CredentialRef{
					Source: instance.EnvSource,
					Key:    "",
					Path:   "",
					Env:    test.env,
				},
			})

			require.ErrorIs(t, err, test.expectedError)
			assert.Equal(t, "legacy-password", resolved.Password)
			assert.NotContains(t, err2String(err), testSecret)
		})
	}
}

// TestResolverResolveFileSourceRequiresReadableFile verifies that a mounted
// secret file failure is reported without reading another source.
func TestResolverResolveFileSourceRequiresReadableFile(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()
	provider.store(testService, instanceName, testSecret)

	files := &fakeFileReader{failure: fmt.Errorf("%w: %q", ErrFileNotFound, secretPath)}

	resolver := NewResolver(
		testService,
		newSystemStoreWithProvider(provider),
		files,
		&fakeEnvReader{values: map[string]string{secretEnv: testSecret}},
	)

	resolved, err := resolver.Resolve(t.Context(), instance.Config{
		Name:     instanceName,
		Host:     "adguard.example.com",
		Scheme:   "https",
		Username: "admin",
		Password: "legacy-password",
		Credential: &instance.CredentialRef{
			Source: instance.FileSource,
			Key:    "",
			Path:   secretPath,
			Env:    "",
		},
	})

	require.ErrorIs(t, err, ErrFileNotFound)
	assert.Equal(t, "legacy-password", resolved.Password)
	assert.Empty(t, provider.calls)
}

// TestResolverPropagatesClassifiedStoreFailure verifies that a credential store
// failure reaches the caller classified, without substituting another source.
func TestResolverPropagatesClassifiedStoreFailure(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()

	provider.failure = errors.New("the collection is locked")

	resolver := NewResolver(
		testService,
		newSystemStoreWithProvider(provider),
		&fakeFileReader{},
		&fakeEnvReader{values: map[string]string{secretEnv: testSecret}},
	)

	resolved, err := resolver.Resolve(t.Context(), instance.Config{
		Name:     instanceName,
		Host:     "adguard.example.com",
		Scheme:   "https",
		Username: "admin",
		Password: "",
		Credential: &instance.CredentialRef{
			Source: instance.KeyringSource,
			Key:    instanceName,
			Path:   "",
			Env:    "",
		},
	})

	require.ErrorIs(t, err, ErrStoreFailure)
	require.ErrorContains(t, err, "the collection is locked")
	assert.Empty(t, resolved.Password)
	assert.NotContains(t, err2String(err), testSecret)
}

// TestResolverResolveLeavesInputUnchanged verifies that resolution returns a
// value copy and never mutates the caller's configuration.
func TestResolverResolveLeavesInputUnchanged(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()
	provider.store(testService, instanceName, testSecret)

	resolver := NewResolver(
		testService,
		newSystemStoreWithProvider(provider),
		&fakeFileReader{},
		&fakeEnvReader{values: map[string]string{}},
	)

	cfg := instance.Config{
		Name:     instanceName,
		Host:     "adguard.example.com",
		Scheme:   "https",
		Username: "admin",
		Password: "legacy-password",
		Credential: &instance.CredentialRef{
			Source: instance.KeyringSource,
			Key:    instanceName,
			Path:   "",
			Env:    "",
		},
	}

	resolved, err := resolver.Resolve(t.Context(), cfg)
	require.NoError(t, err)

	assert.Equal(t, testSecret, resolved.Password)
	assert.Equal(t, "legacy-password", cfg.Password)
	assert.Equal(t, instanceName, cfg.Name)
}

// TestNewResolverDefaultsService verifies that an empty service namespace uses
// the default namespace.
func TestNewResolverDefaultsService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		service         string
		expectedService string
	}{
		{
			name:            "configured service",
			service:         "agh-cli-prod",
			expectedService: "agh-cli-prod",
		},
		{
			name:            "empty service",
			service:         "",
			expectedService: DefaultService,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			provider := newFakeProvider()
			provider.store(test.expectedService, instanceName, testSecret)

			resolver := NewResolver(
				test.service,
				newSystemStoreWithProvider(provider),
				&fakeFileReader{},
				&fakeEnvReader{values: map[string]string{}},
			)

			resolved, err := resolver.Resolve(t.Context(), instance.Config{
				Name:     instanceName,
				Host:     "adguard.example.com",
				Scheme:   "https",
				Username: "admin",
				Password: "",
				Credential: &instance.CredentialRef{
					Source: instance.KeyringSource,
					Key:    instanceName,
					Path:   "",
					Env:    "",
				},
			})

			require.NoError(t, err)
			assert.Equal(t, testSecret, resolved.Password)
			assert.Equal(t, []storeCall{
				{service: test.expectedService, key: instanceName, secret: ""},
			}, provider.calls)
		})
	}
}

// TestResolverResolvePropagatesContextCancellation verifies that a canceled
// context stops a keyring read before the credential store is called.
func TestResolverResolvePropagatesContextCancellation(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()
	provider.store(testService, instanceName, testSecret)

	resolver := NewResolver(
		testService,
		newSystemStoreWithProvider(provider),
		&fakeFileReader{},
		&fakeEnvReader{values: map[string]string{}},
	)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	resolved, err := resolver.Resolve(ctx, instance.Config{
		Name:     instanceName,
		Host:     "adguard.example.com",
		Scheme:   "https",
		Username: "admin",
		Password: "",
		Credential: &instance.CredentialRef{
			Source: instance.KeyringSource,
			Key:    instanceName,
			Path:   "",
			Env:    "",
		},
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, resolved.Password)
	assert.Empty(t, provider.calls)
}

// TestResolverResolveRejectsUnavailableStore verifies that an unavailable
// credential store is reported instead of falling back to the plaintext
// password.
func TestResolverResolveRejectsUnavailableStore(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()

	provider.failure = keyring.ErrUnsupportedPlatform

	resolver := NewResolver(
		testService,
		newSystemStoreWithProvider(provider),
		&fakeFileReader{},
		&fakeEnvReader{values: map[string]string{}},
	)

	_, err := resolver.Resolve(t.Context(), instance.Config{
		Name:     instanceName,
		Host:     "adguard.example.com",
		Scheme:   "https",
		Username: "admin",
		Password: "legacy-password",
		Credential: &instance.CredentialRef{
			Source: instance.KeyringSource,
			Key:    instanceName,
			Path:   "",
			Env:    "",
		},
	})

	require.ErrorIs(t, err, ErrStoreUnavailable)
	assert.ErrorContains(t, err, instanceName)
}
