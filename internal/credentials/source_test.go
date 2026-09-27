// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zalando/go-keyring"
)

// storeCall records the arguments of one credential store operation.
type storeCall struct {
	// service is the credential store namespace of the call.
	service string
	// key is the credential key of the call.
	key string
	// secret is the secret of a write call.
	secret string
}

// fakeProvider is an in-memory keyringProvider for unit tests.
//
// The fake stands in for the process-global provider of the operating system
// credential store, so that error mapping is testable without mutating that
// global state.
type fakeProvider struct {
	// secrets holds the stored values keyed by service and credential key.
	secrets map[string]map[string]string
	// calls records every platform operation in call order.
	calls []storeCall
	// failure is returned by every platform operation when it is set.
	failure error
}

// fakeFileReader is an in-memory FileReader for unit tests.
type fakeFileReader struct {
	// data holds the file contents keyed by path.
	data map[string][]byte
	// calls records the paths passed to Read in call order.
	calls []string
	// failure is returned by every read when it is set.
	failure error
}

// environmentEntry is one variable defined by the test process.
type environmentEntry struct {
	// name is the environment variable name.
	name string
	// value is the environment variable value.
	value string
}

// fakeEnvReader is an in-memory EnvReader for unit tests.
type fakeEnvReader struct {
	// values holds the variable values keyed by name.
	values map[string]string
	// calls records the names passed to Lookup in call order.
	calls []string
}

// testService is the credential store namespace used by unit tests.
const testService = "agh-cli"

// testKey is the credential key used by unit tests.
const testKey = "default"

// testSecret is the secret value used by unit tests.
const testSecret = "s3cr3t-value"

// envProbePrefix is the namespace searched for a variable the test process does
// not define.
const envProbePrefix = "AGH_CLI_CREDENTIALS_PROBE_"

// newFakeProvider creates an empty in-memory credential store provider.
//
// Returns:
//   - *fakeProvider: provider without stored secrets.
func newFakeProvider() *fakeProvider {
	return &fakeProvider{
		secrets: make(map[string]map[string]string),
		calls:   nil,
		failure: nil,
	}
}

// Delete removes the secret stored for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - error: the configured failure, or nil.
func (f *fakeProvider) Delete(service, key string) error {
	f.calls = append(f.calls, storeCall{service: service, key: key, secret: ""})

	if f.failure != nil {
		return f.failure
	}

	delete(f.secrets[service], key)

	return nil
}

// DeleteAll removes every secret stored under a service.
//
// Parameters:
//   - service: credential store namespace.
//
// Returns:
//   - error: the configured failure, or nil.
func (f *fakeProvider) DeleteAll(service string) error {
	f.calls = append(f.calls, storeCall{service: service, key: "", secret: ""})

	if f.failure != nil {
		return f.failure
	}

	delete(f.secrets, service)

	return nil
}

// Get returns the secret stored for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - string: the stored secret.
//   - error: the configured failure, keyring.ErrNotFound, or nil.
func (f *fakeProvider) Get(service, key string) (string, error) {
	f.calls = append(f.calls, storeCall{service: service, key: key, secret: ""})

	if f.failure != nil {
		return "", f.failure
	}

	secret, ok := f.secrets[service][key]
	if !ok {
		return "", keyring.ErrNotFound
	}

	return secret, nil
}

// Set stores a secret for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//   - secret: secret to store.
//
// Returns:
//   - error: the configured failure, or nil.
func (f *fakeProvider) Set(service, key, secret string) error {
	f.calls = append(f.calls, storeCall{service: service, key: key, secret: secret})

	if f.failure != nil {
		return f.failure
	}

	f.store(service, key, secret)

	return nil
}

// Read returns the configured file contents.
//
// Parameters:
//   - ctx: context checked before the contents are served.
//   - filePath: mounted secret file path.
//
// Returns:
//   - []byte: the configured file contents.
//   - error: the configured failure, or nil.
func (f *fakeFileReader) Read(ctx context.Context, filePath string) ([]byte, error) {
	f.calls = append(f.calls, filePath)

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	if f.failure != nil {
		return nil, f.failure
	}

	return f.data[filePath], nil
}

// Lookup returns the configured variable value.
//
// Parameters:
//   - name: environment variable name.
//
// Returns:
//   - string: the configured value.
//   - bool: true when the variable is configured.
func (f *fakeEnvReader) Lookup(name string) (string, bool) {
	f.calls = append(f.calls, name)

	value, ok := f.values[name]

	return value, ok
}

// TestOSEnvReaderLookup verifies that the environment reader serves exactly the
// requested variable.
func TestOSEnvReaderLookup(t *testing.T) {
	t.Parallel()

	reader := NewOSEnvReader()

	existing, hasExisting := firstEnvironmentEntry(t)
	if hasExisting {
		value, ok := reader.Lookup(existing.name)
		assert.True(t, ok)
		assert.Equal(t, existing.value, value)
	}

	unset := unusedEnvironmentName(t)

	value, ok := reader.Lookup(unset)
	assert.False(t, ok)
	assert.Empty(t, value)
}

// firstEnvironmentEntry returns one variable defined by the test process.
//
// Parameters:
//   - t: test handle used to skip an empty environment.
//
// Returns:
//   - environmentEntry: name and value of one defined variable.
//   - bool: true when the environment defines at least one variable.
func firstEnvironmentEntry(t *testing.T) (environmentEntry, bool) {
	t.Helper()

	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if found {
			return environmentEntry{name: name, value: value}, true
		}
	}

	t.Skip("test process has no environment variables")

	return environmentEntry{}, false
}

// unusedEnvironmentName returns an environment variable name that is not set.
//
// Parameters:
//   - t: test handle used to report the bounded search.
//
// Returns:
//   - string: an environment variable name that is not set.
func unusedEnvironmentName(t *testing.T) string {
	t.Helper()

	for index := range 4 {
		name := envProbePrefix + strconv.Itoa(index)
		if _, ok := os.LookupEnv(name); !ok {
			return name
		}
	}

	t.Skip("no unused probe variable name is available")

	return ""
}

// store records a stored secret for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//   - secret: secret to store.
func (f *fakeProvider) store(service, key, secret string) {
	if _, ok := f.secrets[service]; !ok {
		f.secrets[service] = make(map[string]string)
	}

	f.secrets[service][key] = secret
}
