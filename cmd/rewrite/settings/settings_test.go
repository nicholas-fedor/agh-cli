// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"bytes"
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteSettingsFlagExpectation describes one expected flag registration.
type rewriteSettingsFlagExpectation struct {
	// shorthand is the expected one-letter shorthand.
	shorthand string
	// def is the expected default value rendered by pflag.
	def string
}

// rewriteSettingsCommandTestInstance names the single HTTP test instance.
const rewriteSettingsCommandTestInstance = "test"

// Command and flag names asserted by settings construction tests.
const (
	// SettingsCommandGet names the get subcommand.
	SettingsCommandGet = "get"
	// SettingsCommandUpdate names the update subcommand.
	SettingsCommandUpdate = "update"
	// SettingsFlagAll names the shared --all flag.
	SettingsFlagAll = "all"
	// SettingsFlagEnabled names the --enabled flag of settings updates.
	SettingsFlagEnabled = "enabled"
	// SettingsFlagInstance names the shared --instance flag.
	SettingsFlagInstance = "instance"
	// SettingsDefaultDisabled renders the pflag default of a disabled bool flag.
	SettingsDefaultDisabled = "false"
	// SettingsDefaultEnabled renders the pflag default of an enabled bool flag.
	SettingsDefaultEnabled = "true"
	// SettingsDefaultEmptyList renders the pflag default of an empty string slice.
	SettingsDefaultEmptyList = "[]"
	// SettingsArgAll is the CLI argument targeting every instance.
	SettingsArgAll = "--all"
)

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := NewCommand()
	second := NewCommand()

	firstGet := requireSettingsSubcommand(t, first, SettingsCommandGet)
	secondGet := requireSettingsSubcommand(t, second, SettingsCommandGet)
	firstUpdate := requireSettingsSubcommand(t, first, SettingsCommandUpdate)
	secondUpdate := requireSettingsSubcommand(t, second, SettingsCommandUpdate)

	assert.NotSame(t, firstGet, secondGet)
	assert.NotSame(t, firstUpdate, secondUpdate)

	require.NoError(t, firstGet.Flags().Set(SettingsFlagAll, SettingsDefaultEnabled))
	require.NoError(t, firstUpdate.Flags().Set(SettingsFlagEnabled, SettingsDefaultDisabled))

	assert.True(t, firstGet.Flags().Changed(SettingsFlagAll))
	assert.False(t, secondGet.Flags().Changed(SettingsFlagAll))

	allFlag, err := secondGet.Flags().GetBool(SettingsFlagAll)
	require.NoError(t, err)
	assert.False(t, allFlag)

	enabled, err := secondUpdate.Flags().GetBool(SettingsFlagEnabled)
	require.NoError(t, err)
	assert.True(t, enabled)
}

// TestNewCommandBindsDocumentedFlags verifies that every subcommand registers
// exactly the documented flags, shorthands, and defaults.
func TestNewCommandBindsDocumentedFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		// name identifies the subcommand under test.
		name string
		// wantFlags maps flag names to their expected shorthand and default.
		wantFlags map[string]rewriteSettingsFlagExpectation
	}{
		{
			name: SettingsCommandGet,
			wantFlags: map[string]rewriteSettingsFlagExpectation{
				SettingsFlagAll:      {shorthand: "a", def: SettingsDefaultDisabled},
				SettingsFlagInstance: {shorthand: "i", def: SettingsDefaultEmptyList},
			},
		},
		{
			name: SettingsCommandUpdate,
			wantFlags: map[string]rewriteSettingsFlagExpectation{
				SettingsFlagAll:      {shorthand: "a", def: SettingsDefaultDisabled},
				SettingsFlagEnabled:  {shorthand: "e", def: SettingsDefaultEnabled},
				SettingsFlagInstance: {shorthand: "i", def: SettingsDefaultEmptyList},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			command := requireSettingsSubcommand(t, NewCommand(), testCase.name)

			assert.Equal(
				t,
				slices.Sorted(maps.Keys(testCase.wantFlags)),
				registeredFlagNames(command),
			)

			for flagName, expected := range testCase.wantFlags {
				flag := command.Flags().Lookup(flagName)
				require.NotNilf(t, flag, "flag %q is not registered", flagName)
				assert.Equal(t, expected.shorthand, flag.Shorthand)
				assert.Equal(t, expected.def, flag.DefValue)
			}
		})
	}
}

// TestNewCommandExecutionUsesFreshContext verifies that a later execution never
// observes a context left behind on an earlier command tree.
func TestNewCommandExecutionUsesFreshContext(t *testing.T) {
	t.Parallel()

	observed := make([]error, 0, 2)

	first := NewCommand()
	recordSettingsContext(t, first, &observed)
	first.SetArgs([]string{SettingsCommandGet})

	cancelable, cancel := context.WithCancel(t.Context())
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := NewCommand()
	recordSettingsContext(t, second, &observed)
	second.SetArgs([]string{SettingsCommandGet})

	require.NoError(t, second.Execute())

	require.Len(t, observed, 2)
	assert.NoError(t, observed[0])
	assert.NoError(t, observed[1])
}

// TestNewCommandRepeatedExecutionReadsSettings verifies that repeatedly
// constructing and executing the command tree reads every target instance.
//
//nolint:paralleltest // The test mutates the process-global Viper instance.
func TestNewCommandRepeatedExecutionReadsSettings(t *testing.T) {
	server := newRewriteSettingsServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/rewrite/settings", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`{"enabled":true}`))
		assert.NoError(t, err)
	})
	resetRewriteSettingsCommandState(t, server.Listener.Addr().String())

	for range 2 {
		command := NewCommand()
		output := &bytes.Buffer{}
		command.SetOut(output)
		command.SetErr(io.Discard)
		command.SetArgs([]string{SettingsCommandGet, SettingsArgAll})

		require.NoError(t, command.Execute())
		assert.Contains(t, output.String(), `"enabled":true`)
	}
}

// TestRunRewriteSettingsGetUsesAppOutput verifies settings retrieval output.
//
//nolint:paralleltest // The test mutates the process-global Viper instance.
func TestRunRewriteSettingsGetUsesAppOutput(t *testing.T) {
	server := newRewriteSettingsServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/rewrite/settings", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`{"enabled":false}`))
		assert.NoError(t, err)
	})
	resetRewriteSettingsCommandState(t, server.Listener.Addr().String())

	command := newRewriteSettingsCommand(t)
	output := &bytes.Buffer{}
	command.SetOut(output)

	require.NoError(t, runRewriteSettingsGet(command, nil, testSettingsFlagValues()))
	assert.Contains(t, output.String(), `"enabled":false`)
}

// TestRunRewriteSettingsUpdateUsesAppOutput verifies explicit false update wiring.
//
//nolint:paralleltest // The test mutates the process-global Viper instance.
func TestRunRewriteSettingsUpdateUsesAppOutput(t *testing.T) {
	server := newRewriteSettingsServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/control/rewrite/settings/update", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	resetRewriteSettingsCommandState(t, server.Listener.Addr().String())

	command := newRewriteSettingsCommand(t)
	output := &bytes.Buffer{}
	command.SetOut(output)

	require.NoError(t, runRewriteSettingsUpdate(command, nil, testSettingsFlagValues()))
	assert.Contains(t, output.String(), "Rewrite settings updated: enabled=false")
}

// registeredFlagNames returns every flag name registered on a command.
//
// Parameters:
//   - command: Command whose local flags are inspected.
//
// Returns:
//   - []string: The registered flag names in sorted order.
func registeredFlagNames(command *cobra.Command) []string {
	names := make([]string, 0)

	command.Flags().VisitAll(func(flag *pflag.Flag) {
		names = append(names, flag.Name)
	})

	slices.Sort(names)

	return names
}

// newRewriteSettingsServer starts an HTTP test server for settings command tests.
//
// Parameters:
//   - handler: Request handler served by the test server.
//
// Returns:
//   - [httptest.Server]: The started HTTP test server.
func newRewriteSettingsServer(
	t *testing.T,
	handler http.HandlerFunc,
) *httptest.Server {
	t.Helper()

	server := httptest.NewTestServer(t, handler)
	server.Start()

	return server
}

// resetRewriteSettingsCommandState resets globals and configures one HTTP test instance.
//
// Parameters:
//   - host: Address of the HTTP test server backing the test instance.
func resetRewriteSettingsCommandState(t *testing.T, host string) {
	t.Helper()

	viper.Reset()

	viper.Set("instances", map[string]any{
		rewriteSettingsCommandTestInstance: map[string]any{
			"host":   host,
			"scheme": "http",
		},
	})
	t.Cleanup(func() {
		viper.Reset()
	})
}

// newRewriteSettingsCommand returns a command bound to the test context.
//
// Parameters:
//   - t: Testing handle bound to the command context.
//
// Returns:
//   - *cobra.Command: The command receiving settings output.
func newRewriteSettingsCommand(t *testing.T) *cobra.Command {
	t.Helper()

	command := &cobra.Command{}
	command.SetContext(t.Context())

	return command
}

// testSettingsFlagValues returns the flag values shared by run-function tests.
//
// Returns:
//   - *flagValues: Values targeting the single test instance with rewrites disabled.
func testSettingsFlagValues() *flagValues {
	return &flagValues{all: true}
}

// requireSettingsSubcommand returns the named subcommand of a command tree.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree that owns the subcommand.
//   - name: Subcommand name to look up.
//
// Returns:
//   - *cobra.Command: The located subcommand.
func requireSettingsSubcommand(
	t *testing.T,
	command *cobra.Command,
	name string,
) *cobra.Command {
	t.Helper()

	for _, subcommand := range command.Commands() {
		if subcommand.Name() == name {
			return subcommand
		}
	}

	require.FailNowf(t, "missing subcommand", "subcommand %q is not registered", name)

	return nil
}

// recordSettingsContext replaces the get command body with a context probe.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree whose get command is replaced.
//   - observed: Collector receiving the observed context error per execution.
func recordSettingsContext(t *testing.T, command *cobra.Command, observed *[]error) {
	t.Helper()

	getCommand := requireSettingsSubcommand(t, command, SettingsCommandGet)

	getCommand.RunE = func(cmd *cobra.Command, _ []string) error {
		*observed = append(*observed, cmd.Context().Err())

		return nil
	}
}
