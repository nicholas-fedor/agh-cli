// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package wildcard

import (
	"bytes"
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteWildcardFlagExpectation describes one expected flag registration.
type rewriteWildcardFlagExpectation struct {
	// shorthand is the expected one-letter shorthand.
	shorthand string
	// def is the expected default value rendered by pflag.
	def string
}

const (
	// RewriteWildcardCommandTestInstance names the single HTTP test instance.
	rewriteWildcardCommandTestInstance = "test"
	// RewriteWildcardCommandTestRule is the explicit rule served by the first list.
	rewriteWildcardCommandTestRule = `{"domain":"example.com","answer":"192.0.2.1","enabled":true}`
	// RewriteWildcardCommandTestWildcardRule is the wildcard rule added by the first list.
	rewriteWildcardCommandTestWildcardRule = `{"domain":"*.example.com","answer":"192.0.2.1","enabled":true}`
	// RewriteWildcardCommandTestDomain is the zone domain exercised by wildcard tests.
	RewriteWildcardCommandTestDomain = "example.com"
	// WildcardCommandAdd names the add subcommand.
	WildcardCommandAdd = "add"
	// WildcardCommandRemove names the remove subcommand.
	WildcardCommandRemove = "remove"
	// WildcardFlagAll names the shared --all flag.
	WildcardFlagAll = "all"
	// WildcardFlagInstance names the shared --instance flag.
	WildcardFlagInstance = "instance"
	// WildcardDefaultDisabled renders the pflag default of a disabled bool flag.
	WildcardDefaultDisabled = "false"
	// WildcardDefaultEnabled renders the pflag default of an enabled bool flag.
	WildcardDefaultEnabled = "true"
	// WildcardDefaultEmptyList renders the pflag default of an empty string slice.
	WildcardDefaultEmptyList = "[]"
	// WildcardArgAll is the CLI argument targeting every instance.
	WildcardArgAll = "--all"
)

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := NewCommand()
	second := NewCommand()

	firstAdd := requireWildcardSubcommand(t, first, WildcardCommandAdd)
	secondAdd := requireWildcardSubcommand(t, second, WildcardCommandAdd)
	firstRemove := requireWildcardSubcommand(t, first, WildcardCommandRemove)
	secondRemove := requireWildcardSubcommand(t, second, WildcardCommandRemove)

	assert.NotSame(t, firstAdd, secondAdd)
	assert.NotSame(t, firstRemove, secondRemove)

	require.NoError(t, firstAdd.Flags().Set(WildcardFlagAll, WildcardDefaultEnabled))
	require.NoError(t, firstRemove.Flags().Set(WildcardFlagInstance, "first"))

	assert.True(t, firstAdd.Flags().Changed(WildcardFlagAll))
	assert.False(t, secondAdd.Flags().Changed(WildcardFlagAll))

	allFlag, err := secondAdd.Flags().GetBool(WildcardFlagAll)
	require.NoError(t, err)
	assert.False(t, allFlag)

	names, err := secondRemove.Flags().GetStringSlice(WildcardFlagInstance)
	require.NoError(t, err)
	assert.Empty(t, names)
}

// TestNewCommandBindsDocumentedFlags verifies that every subcommand registers
// exactly the documented flags, shorthands, and defaults.
func TestNewCommandBindsDocumentedFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		// name identifies the subcommand under test.
		name string
		// wantFlags maps flag names to their expected shorthand and default.
		wantFlags map[string]rewriteWildcardFlagExpectation
	}{
		{
			name: WildcardCommandAdd,
			wantFlags: map[string]rewriteWildcardFlagExpectation{
				WildcardFlagAll:      {shorthand: "a", def: WildcardDefaultDisabled},
				WildcardFlagInstance: {shorthand: "i", def: WildcardDefaultEmptyList},
			},
		},
		{
			name: WildcardCommandRemove,
			wantFlags: map[string]rewriteWildcardFlagExpectation{
				WildcardFlagAll:      {shorthand: "a", def: WildcardDefaultDisabled},
				WildcardFlagInstance: {shorthand: "i", def: WildcardDefaultEmptyList},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			command := requireWildcardSubcommand(t, NewCommand(), testCase.name)

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
	recordWildcardContext(t, first, &observed)
	first.SetArgs([]string{WildcardCommandAdd, RewriteWildcardCommandTestDomain})

	cancelable, cancel := context.WithCancel(t.Context())
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := NewCommand()
	recordWildcardContext(t, second, &observed)
	second.SetArgs([]string{WildcardCommandAdd, RewriteWildcardCommandTestDomain})

	require.NoError(t, second.Execute())

	require.Len(t, observed, 2)
	assert.NoError(t, observed[0])
	assert.NoError(t, observed[1])
}

// TestNewCommandRepeatedExecutionAppliesWildcardRules verifies that repeatedly
// constructing and executing the command tree mutates every target instance.
//
//nolint:paralleltest // The test mutates the process-global Viper instance.
func TestNewCommandRepeatedExecutionAppliesWildcardRules(t *testing.T) {
	var listCalls atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(
			"[" + rewriteWildcardCommandTestRule +
				"," + rewriteWildcardCommandTestWildcardRule + "]",
		))
		assert.NoError(t, err)

		if r.Method == http.MethodGet {
			listCalls.Add(1)
		}
	}))
	server.Start()

	resetWildcardCommandState(t, server.Listener.Addr().String())

	for range 2 {
		command := NewCommand()
		output := &bytes.Buffer{}
		command.SetOut(output)
		command.SetErr(io.Discard)
		command.SetArgs([]string{WildcardCommandAdd, WildcardArgAll, RewriteWildcardCommandTestDomain})

		require.NoError(t, command.Execute())
		assert.Contains(t, output.String(), "Added wildcard rewrite rules for example.com")
	}

	assert.Equal(t, int32(2), listCalls.Load())
}

// TestRunWildcardRewriteCommandsUseAppOutput verifies wildcard command wiring.
//
//nolint:paralleltest // The test mutates the process-global Viper instance.
func TestRunWildcardRewriteCommandsUseAppOutput(t *testing.T) {
	var listCalls atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			assert.Equal(t, "/control/rewrite/list", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")

			if listCalls.Add(1) == 1 {
				_, err := w.Write([]byte("[" + rewriteWildcardCommandTestRule + "]"))
				assert.NoError(t, err)

				return
			}

			_, err := w.Write([]byte(
				"[" + rewriteWildcardCommandTestRule +
					"," + rewriteWildcardCommandTestWildcardRule + "]",
			))
			assert.NoError(t, err)
		case http.MethodPost:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	server.Start()

	resetWildcardCommandState(t, server.Listener.Addr().String())

	addCommand := newWildcardCommand(t)
	addOutput := &bytes.Buffer{}
	addCommand.SetOut(addOutput)
	require.NoError(t, runWildcardAdd(addCommand, []string{RewriteWildcardCommandTestDomain}, testWildcardFlagValues()))

	deleteCommand := newWildcardCommand(t)
	deleteOutput := &bytes.Buffer{}
	deleteCommand.SetOut(deleteOutput)
	require.NoError(t, runWildcardDelete(
		deleteCommand,
		[]string{RewriteWildcardCommandTestDomain},
		testWildcardFlagValues(),
	))

	assert.Equal(t, int32(2), listCalls.Load())
	assert.Contains(t, addOutput.String(), "Added wildcard rewrite rules for example.com")
	assert.Contains(t, deleteOutput.String(), "Removed wildcard rewrite rules for example.com")
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

// resetWildcardCommandState resets globals and configures one HTTP test instance.
//
// Parameters:
//   - host: Address of the HTTP test server backing the test instance.
func resetWildcardCommandState(t *testing.T, host string) {
	t.Helper()

	viper.Reset()

	viper.Set("instances", map[string]any{
		rewriteWildcardCommandTestInstance: map[string]any{
			"host":   host,
			"scheme": "http",
		},
	})
	t.Cleanup(func() {
		viper.Reset()
	})
}

// newWildcardCommand returns a command bound to the test context.
//
// Parameters:
//   - t: Testing handle bound to the command context.
//
// Returns:
//   - *cobra.Command: The command receiving wildcard command output.
func newWildcardCommand(t *testing.T) *cobra.Command {
	t.Helper()

	command := &cobra.Command{}
	command.SetContext(t.Context())

	return command
}

// testWildcardFlagValues returns the flag values shared by run-function tests.
//
// Returns:
//   - *flagValues: Values targeting the single test instance.
func testWildcardFlagValues() *flagValues {
	return &flagValues{all: true}
}

// requireWildcardSubcommand returns the named subcommand of a command tree.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree that owns the subcommand.
//   - name: Subcommand name to look up.
//
// Returns:
//   - *cobra.Command: The located subcommand.
func requireWildcardSubcommand(
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

// recordWildcardContext replaces the add command body with a context probe.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree whose add command is replaced.
//   - observed: Collector receiving the observed context error per execution.
func recordWildcardContext(t *testing.T, command *cobra.Command, observed *[]error) {
	t.Helper()

	addCommand := requireWildcardSubcommand(t, command, WildcardCommandAdd)

	addCommand.RunE = func(cmd *cobra.Command, _ []string) error {
		*observed = append(*observed, cmd.Context().Err())

		return nil
	}
}
