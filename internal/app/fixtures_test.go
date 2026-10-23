// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/config"
)

const (
	// AlphaInstance identifies the alphabetically first shared test instance.
	alphaInstance = "alpha"
	// BadInstance identifies the shared test instance that fails an operation.
	badInstance = "bad"
	// GoodInstance identifies the shared test instance that completes an operation.
	goodInstance = "good"
	// ZuluInstance identifies the alphabetically last shared test instance.
	zuluInstance = "zulu"
	// TestAlphaHost is the alphabetically first shared test host.
	testAlphaHost = "alpha.example.com"
	// TestBadHost is the shared test host that fails an operation.
	testBadHost = "bad.example.com"
	// TestGoodHost is the shared test host that completes an operation.
	testGoodHost = "good.example.com"
	// TestZuluHost is the alphabetically last shared test host.
	testZuluHost = "zulu.example.com"
	// TestClientName identifies the client used in app tests.
	testClientName = "desk"
	// TestClientID identifies the client used in app tests.
	testClientID = "192.0.2.10"
	// AddedClientMessage is the expected add success message.
	addedClientMessage = "Added client " + testClientName
)

// testLegacyPassword is the legacy plaintext password used by configuration
// tests.
const testLegacyPassword = "legacy-plaintext-password"

// testConfigHost is the instance host used by configuration tests.
const testConfigHost = "config.example.com"

// testInstancesContext returns a context carrying the shared test instances.
//
// Returns:
//   - [context.Context]: test context carrying the shared test instances.
func testInstancesContext(t *testing.T) context.Context {
	t.Helper()

	return runContext(t, instancesDocument(map[string]string{
		alphaInstance: testAlphaHost,
		badInstance:   testBadHost,
		goodInstance:  testGoodHost,
		zuluInstance:  testZuluHost,
	}))
}

// instancesDocument returns a configuration document declaring one instance per
// entry, in name order.
//
// Parameters:
//   - hosts: instance hosts keyed by instance name.
//
// Returns:
//   - string: the configuration document.
func instancesDocument(hosts map[string]string) string {
	var document strings.Builder

	_, _ = document.WriteString("instances:\n")

	for _, name := range slices.Sorted(maps.Keys(hosts)) {
		_, _ = fmt.Fprintf(&document, "  %s:\n    host: %s\n", name, hosts[name])
	}

	return document.String()
}

// runContext returns a test context carrying the configuration document.
//
// Parameters:
//   - document: complete configuration document.
//
// Returns:
//   - [context.Context]: test context carrying the loaded configuration.
func runContext(t *testing.T, document string) context.Context {
	t.Helper()

	return contextWithConfig(t.Context(), t, document)
}

// contextWithConfig returns a copy of ctx carrying the configuration document.
//
// Parameters:
//   - ctx: parent context.
//   - document: complete configuration document.
//
// Returns:
//   - [context.Context]: ctx carrying the loaded configuration.
func contextWithConfig(ctx context.Context, t *testing.T, document string) context.Context {
	t.Helper()

	return contextWithConfigFile(ctx, t, writeTestConfig(t, document))
}

// contextWithConfigFile returns a copy of ctx carrying the configuration file.
//
// Parameters:
//   - ctx: parent context.
//   - path: configuration file to load.
//
// Returns:
//   - [context.Context]: ctx carrying the loaded configuration.
func contextWithConfigFile(ctx context.Context, t *testing.T, path string) context.Context {
	t.Helper()

	resolution, err := ResolveConfigPath(path)
	require.NoError(t, err)

	runConfig, err := LoadRunConfig(resolution, io.Discard)
	require.NoError(t, err)

	return WithRunConfig(ctx, runConfig)
}

// writeTestConfig writes a configuration document to a private file.
//
// Parameters:
//   - document: complete configuration document.
//
// Returns:
//   - string: path of the written configuration file.
func writeTestConfig(t *testing.T, document string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), config.DefaultConfigFileName)
	require.NoError(t, os.WriteFile(path, []byte(document), 0o600))

	return path
}

// readTestConfig returns the raw configuration file contents.
//
// Parameters:
//   - configPath: path of the configuration file to read.
//
// Returns:
//   - string: the configuration file contents.
func readTestConfig(t *testing.T, configPath string) string {
	t.Helper()

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	return string(data)
}
