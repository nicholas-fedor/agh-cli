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
)

// storeCase is one credential store case shared by the store operation tests.
type storeCase struct {
	// name is the subtest name.
	name string
	// service is the credential store namespace of the operation.
	service string
	// key is the credential key of the operation.
	key string
	// seeded stores testSecret before the operation when it is true.
	seeded bool
	// failure is the platform error the operation reports.
	failure error
	// expectedSecret is the secret a successful read returns.
	expectedSecret string
	// expectedError is the project sentinel the operation must report.
	expectedError error
}

// provider returns a provider prepared for the case.
//
// Returns:
//   - *fakeProvider: provider holding the seeded secret and configured failure.
func (c storeCase) provider() *fakeProvider {
	provider := newFakeProvider()

	if c.seeded {
		provider.store(c.service, c.key, testSecret)
	}

	provider.failure = c.failure

	return provider
}

// TestSystemStoreBackend verifies the backend name reported by status output.
func TestSystemStoreBackend(t *testing.T) {
	t.Parallel()

	assert.Equal(t, KeyringBackend, NewSystemStore().Backend())
}

// TestSystemStoreGet verifies credential reads, project-owned error mapping,
// and identity validation.
func TestSystemStoreGet(t *testing.T) {
	t.Parallel()

	tests := []storeCase{
		{
			name:           "stored credential",
			service:        testService,
			key:            testKey,
			seeded:         true,
			failure:        nil,
			expectedSecret: testSecret,
			expectedError:  nil,
		},
		{
			name:           "absent credential",
			service:        testService,
			key:            testKey,
			seeded:         false,
			failure:        nil,
			expectedSecret: "",
			expectedError:  ErrNotFound,
		},
		{
			name:           "wrapped not found",
			service:        testService,
			key:            testKey,
			seeded:         false,
			failure:        fmt.Errorf("search item: %w", keyring.ErrNotFound),
			expectedSecret: "",
			expectedError:  ErrNotFound,
		},
		{
			name:           "unclassified platform failure",
			service:        testService,
			key:            testKey,
			seeded:         false,
			failure:        errors.New("org.freedesktop.secrets was not provided"),
			expectedSecret: "",
			expectedError:  ErrStoreFailure,
		},
		{
			name:           "unsupported platform",
			service:        testService,
			key:            testKey,
			seeded:         false,
			failure:        keyring.ErrUnsupportedPlatform,
			expectedSecret: "",
			expectedError:  ErrStoreUnavailable,
		},
		{
			name:           "empty service",
			service:        "",
			key:            testKey,
			seeded:         false,
			failure:        nil,
			expectedSecret: "",
			expectedError:  ErrInvalidIdentity,
		},
		{
			name:           "empty key",
			service:        testService,
			key:            "",
			seeded:         false,
			failure:        nil,
			expectedSecret: "",
			expectedError:  ErrInvalidIdentity,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runStoreGetCase(t, test)
		})
	}
}

// runStoreGetCase performs one credential read case.
//
// Parameters:
//   - t: test handle used for assertions.
//   - test: case describing the identity, the platform behavior, and the
//     expected result.
func runStoreGetCase(t *testing.T, test storeCase) {
	t.Helper()

	provider := test.provider()
	store := newSystemStoreWithProvider(provider)

	secret, err := store.Get(t.Context(), test.service, test.key)

	if test.expectedError != nil {
		require.ErrorIs(t, err, test.expectedError)
		assert.Empty(t, secret)

		return
	}

	require.NoError(t, err)
	assert.Equal(t, test.expectedSecret, secret)
	assert.Equal(t, storeCall{
		service: test.service,
		key:     test.key,
		secret:  "",
	}, provider.calls[len(provider.calls)-1])
}

// TestSystemStoreSet verifies credential writes, error mapping, and the
// redaction of a platform error that repeats the secret.
func TestSystemStoreSet(t *testing.T) {
	t.Parallel()

	tests := []storeCase{
		{
			name:          "stored secret",
			service:       testService,
			key:           testKey,
			failure:       nil,
			expectedError: nil,
		},
		{
			name:          "secret too large",
			service:       testService,
			key:           testKey,
			failure:       keyring.ErrSetDataTooBig,
			expectedError: ErrTooLarge,
		},
		{
			name:          "unclassified platform failure",
			service:       testService,
			key:           testKey,
			failure:       errors.New("collection is locked"),
			expectedError: ErrStoreFailure,
		},
		{
			name:          "empty identity",
			service:       testService,
			key:           "",
			failure:       nil,
			expectedError: ErrInvalidIdentity,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runStoreSetCase(t, test)
		})
	}
}

// runStoreSetCase performs one credential write case.
//
// Parameters:
//   - t: test handle used for assertions.
//   - test: case describing the identity, the platform behavior, and the
//     expected result.
func runStoreSetCase(t *testing.T, test storeCase) {
	t.Helper()

	provider := test.provider()
	store := newSystemStoreWithProvider(provider)

	err := store.Set(t.Context(), test.service, test.key, testSecret)

	if test.expectedError != nil {
		require.ErrorIs(t, err, test.expectedError)
		assert.NotContains(t, err2String(err), testSecret)

		return
	}

	require.NoError(t, err)
	require.Len(t, provider.calls, 1)
	assert.Equal(t, storeCall{
		service: test.service,
		key:     test.key,
		secret:  testSecret,
	}, provider.calls[0])
}

// TestSystemStoreSetRedactsSecretFromPlatformError verifies that a platform
// error repeating the secret is redacted while the failure stays matchable.
func TestSystemStoreSetRedactsSecretFromPlatformError(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()

	provider.failure = fmt.Errorf("write rejected value %q", testSecret)

	store := newSystemStoreWithProvider(provider)

	err := store.Set(t.Context(), testService, testKey, testSecret)

	require.ErrorIs(t, err, ErrStoreFailure)
	assert.NotContains(t, err2String(err), testSecret)
	assert.ErrorContains(t, err, "redacted")
}

// TestSystemStoreDelete verifies credential removal and error mapping.
func TestSystemStoreDelete(t *testing.T) {
	t.Parallel()

	tests := []storeCase{
		{
			name:          "removed stored credential",
			service:       testService,
			key:           testKey,
			seeded:        true,
			failure:       nil,
			expectedError: nil,
		},
		{
			name:          "absent credential is tolerated",
			service:       testService,
			key:           testKey,
			seeded:        false,
			failure:       nil,
			expectedError: nil,
		},
		{
			name:          "platform reports an absent credential",
			service:       testService,
			key:           testKey,
			seeded:        false,
			failure:       keyring.ErrNotFound,
			expectedError: ErrNotFound,
		},
		{
			name:          "unclassified platform failure",
			service:       testService,
			key:           testKey,
			seeded:        false,
			failure:       errors.New("dbus is unavailable"),
			expectedError: ErrStoreFailure,
		},
		{
			name:          "empty service",
			service:       "",
			key:           testKey,
			seeded:        false,
			failure:       nil,
			expectedError: ErrInvalidIdentity,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runStoreDeleteCase(t, test)
		})
	}
}

// runStoreDeleteCase performs one credential removal case.
//
// Parameters:
//   - t: test handle used for assertions.
//   - test: case describing the identity, the platform behavior, and the
//     expected result.
func runStoreDeleteCase(t *testing.T, test storeCase) {
	t.Helper()

	provider := test.provider()
	store := newSystemStoreWithProvider(provider)

	err := store.Delete(t.Context(), test.service, test.key)

	if test.expectedError != nil {
		require.ErrorIs(t, err, test.expectedError)
		assert.NotContains(t, err2String(err), testSecret)

		return
	}

	require.NoError(t, err)

	_, ok := provider.secrets[test.service][test.key]
	assert.False(t, ok)
}

// TestSystemStoreDeleteAll verifies service-wide removal and identity
// validation.
func TestSystemStoreDeleteAll(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider()
	provider.store(testService, testKey, testSecret)
	provider.store("other-service", testKey, testSecret)

	store := newSystemStoreWithProvider(provider)

	require.NoError(t, store.DeleteAll(t.Context(), testService))
	assert.Empty(t, provider.secrets[testService])
	assert.Len(t, provider.secrets["other-service"], 1)

	err := store.DeleteAll(t.Context(), "")
	require.ErrorIs(t, err, ErrInvalidIdentity)

	provider.failure = errors.New("dbus is unavailable")

	err = store.DeleteAll(t.Context(), testService)
	require.ErrorIs(t, err, ErrStoreFailure)
}

// TestSystemStoreChecksContextBeforePlatformCall verifies that every method
// stops before the platform call once the context is done.
func TestSystemStoreChecksContextBeforePlatformCall(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	provider := newFakeProvider()
	store := newSystemStoreWithProvider(provider)

	_, getErr := store.Get(ctx, testService, testKey)
	require.ErrorIs(t, getErr, context.Canceled)

	setErr := store.Set(ctx, testService, testKey, testSecret)
	require.ErrorIs(t, setErr, context.Canceled)

	deleteErr := store.Delete(ctx, testService, testKey)
	require.ErrorIs(t, deleteErr, context.Canceled)

	deleteAllErr := store.DeleteAll(ctx, testService)
	require.ErrorIs(t, deleteAllErr, context.Canceled)

	assert.Empty(t, provider.calls)
}

// TestWrapStoreError verifies the platform error classification table.
func TestWrapStoreError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		secret        string
		err           error
		expectedError error
	}{
		{
			name:          "not found",
			secret:        "",
			err:           keyring.ErrNotFound,
			expectedError: ErrNotFound,
		},
		{
			name:          "set data too big",
			secret:        "",
			err:           keyring.ErrSetDataTooBig,
			expectedError: ErrTooLarge,
		},
		{
			name:          "unsupported platform",
			secret:        "",
			err:           keyring.ErrUnsupportedPlatform,
			expectedError: ErrStoreUnavailable,
		},
		{
			name:          "unclassified failure",
			secret:        "",
			err:           errors.New("the collection is locked"),
			expectedError: ErrStoreFailure,
		},
		{
			name:          "empty secret never redacts",
			secret:        "",
			err:           errors.New("an empty credential is rejected"),
			expectedError: ErrStoreFailure,
		},
		{
			name:          "repeated secret is redacted",
			secret:        testSecret,
			err:           errors.New("rejected " + testSecret),
			expectedError: ErrStoreFailure,
		},
		{
			name:          "repeated secret in unsupported platform",
			secret:        testSecret,
			err:           fmt.Errorf("%w: %s", keyring.ErrUnsupportedPlatform, testSecret),
			expectedError: ErrStoreUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := wrapStoreError(test.secret, test.err)

			require.ErrorIs(t, err, test.expectedError)
			assert.NotContains(t, err2String(err), testSecret)
		})
	}
}

// TestWrapStoreErrorKeepsPlatformDetail verifies that a safe platform message
// survives for diagnosis.
func TestWrapStoreErrorKeepsPlatformDetail(t *testing.T) {
	t.Parallel()

	const platformMessage = "org.freedesktop.secrets was not provided by any service files"

	err := wrapStoreError("", errors.New(platformMessage))

	require.ErrorIs(t, err, ErrStoreFailure)
	assert.ErrorContains(t, err, platformMessage)
}

// err2String renders an error for assertions that inspect its message.
//
// Parameters:
//   - err: error to render, possibly nil.
//
// Returns:
//   - string: the error message, or an empty string when err is nil.
func err2String(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
