// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// integrationServicePrefix namespaces the credentials written by the round-trip
// test so that a real credential store is never polluted by another service.
const integrationServicePrefix = "agh-cli-integration-test"

// integrationKey is the credential key used by the round-trip test.
const integrationKey = "default"

// integrationSecret is the secret written by the round-trip test.
const integrationSecret = "integration-secret-value"

// rotatedSecret is the replacement secret written by the round-trip test.
const rotatedSecret = "rotated-secret-value"

// integrationTimeout bounds one credential store round trip. The platform
// credential store is synchronous, so the timeout guards against a provider that
// never answers rather than bounding the store itself.
const integrationTimeout = 30 * time.Second

// TestSystemStoreRealBackendRoundTrip exercises the operating system credential
// store through set, get, overwrite, and delete.
//
// The test runs only when the platform store is usable. A headless host without
// a Secret Service session, such as a CI runner, skips instead of failing, and
// the skip happens before any credential is written.
func TestSystemStoreRealBackendRoundTrip(t *testing.T) {
	t.Parallel()

	store := NewSystemStore()
	service := integrationServicePrefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()

	seedErr := store.Set(ctx, service, integrationKey, integrationSecret)
	if seedErr != nil {
		skipUnavailableStore(t, seedErr)

		return
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), integrationTimeout)
		defer cleanupCancel()

		_ = store.DeleteAll(cleanupCtx, service)
	})

	secret, err := store.Get(ctx, service, integrationKey)
	require.NoError(t, err)
	assert.Equal(t, integrationSecret, secret)

	require.NoError(t, store.Set(ctx, service, integrationKey, rotatedSecret))

	secret, err = store.Get(ctx, service, integrationKey)
	require.NoError(t, err)
	assert.Equal(t, rotatedSecret, secret)

	require.NoError(t, store.Delete(ctx, service, integrationKey))

	_, err = store.Get(ctx, service, integrationKey)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestResolverRealBackendRoundTrip resolves an instance credential from the
// operating system credential store.
//
// The test runs only when the platform store is usable and skips before any
// credential is written.
func TestResolverRealBackendRoundTrip(t *testing.T) {
	t.Parallel()

	store := NewSystemStore()
	service := integrationServicePrefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()

	seedErr := store.Set(ctx, service, integrationKey, integrationSecret)
	if seedErr != nil {
		skipUnavailableStore(t, seedErr)

		return
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), integrationTimeout)
		defer cleanupCancel()

		_ = store.DeleteAll(cleanupCtx, service)
	})

	resolver := NewResolver(service, store, NewOSFileReader(), NewOSEnvReader())

	resolved, err := resolver.Resolve(ctx, instance.Config{
		Name:     integrationKey,
		Host:     "adguard.example.com",
		Scheme:   "https",
		Username: "admin",
		Password: "",
		Credential: &instance.CredentialRef{
			Source: instance.KeyringSource,
			Key:    integrationKey,
			Path:   "",
			Env:    "",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, integrationSecret, resolved.Password)
}

// TestOSFileReaderRealMountedSecret reads a secret file exactly as a container
// mount would provide it.
func TestOSFileReaderRealMountedSecret(t *testing.T) {
	t.Parallel()

	secretPath := writeSecretFile(t, integrationSecret+"\n")

	data, err := NewOSFileReader().Read(t.Context(), secretPath)

	require.NoError(t, err)
	assert.Equal(t, integrationSecret+"\n", string(data))
}

// TestOSEnvReaderRealEnvironment reads a variable exported by the caller.
func TestOSEnvReaderRealEnvironment(t *testing.T) {
	t.Parallel()

	existing, hasExisting := firstEnvironmentEntry(t)
	if !hasExisting {
		return
	}

	value, ok := NewOSEnvReader().Lookup(existing.name)

	assert.True(t, ok)
	assert.Equal(t, existing.value, value)
}

// skipUnavailableStore skips a test when the platform credential store is
// unusable.
//
// Parameters:
//   - t: test handle used to report the reason.
//   - err: error returned by the seeding write.
func skipUnavailableStore(t *testing.T, err error) {
	t.Helper()

	t.Skipf("the operating system credential store is unavailable: %v", err)
}
