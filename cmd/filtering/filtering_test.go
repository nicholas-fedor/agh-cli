// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// filteringFailingWriter returns a deterministic output failure.
type filteringFailingWriter struct {
	// err is returned without writing any bytes.
	err error
}

// filteringExpectedFlag describes one published flag of a filtering subcommand.
type filteringExpectedFlag struct {
	// Shorthand is the published one-letter shorthand.
	Shorthand string
	// Usage is the published help text.
	Usage string
	// Default is the published default rendering.
	Default string
	// ValueType is the published flag value type.
	ValueType string
	// Name is the published flag name.
	Name string
}

// filteringSubcommandSyntax describes the published syntax of one subcommand.
type filteringSubcommandSyntax struct {
	// Flags lists every published flag of the subcommand.
	Flags []filteringExpectedFlag
	// Short is the published one-line description.
	Short string
	// Use is the published invocation syntax.
	Use string
}

// filteringSyntaxCase pairs one subcommand with its published syntax.
type filteringSyntaxCase struct {
	// expected is the published syntax the subcommand must expose.
	expected filteringSubcommandSyntax
	// sub is the subcommand name resolved from a fresh filtering command.
	sub string
	// name labels the subtest.
	name string
}

const (
	// FilteringCommandAlphaInstance identifies the first rendering result.
	filteringCommandAlphaInstance = "alpha"
	// FilteringCommandZuluInstance identifies the second rendering result.
	filteringCommandZuluInstance = "zulu"
	// FilteringCommandAddedMessage identifies the add-URL success message.
	filteringCommandAddedMessage = "Added filter URL filters"
	// FilteringCommandBoolType identifies the published pflag boolean type.
	filteringCommandBoolType = "bool"
	// FilteringCommandAllFlagArg is the published long form of the --all flag.
	filteringCommandAllFlagArg = "--all"
	// FilteringCommandInstanceFlagArg is the published long form of the
	// --instance flag.
	filteringCommandInstanceFlagArg = "--instance"
	// FilteringCommandStatusName identifies the status subcommand.
	filteringCommandStatusName = "status"
	// FilteringCommandConfigName identifies the config subcommand.
	filteringCommandConfigName = "config"
	// FilteringCommandAddURLName identifies the add-url subcommand.
	filteringCommandAddURLName = "add-url"
	// FilteringCommandRemoveURLName identifies the remove-url subcommand.
	filteringCommandRemoveURLName = "remove-url"
)

// TestFilteringConfigFromFlagsPreservesFalseAndZero verifies flag-to-app shaping.
func TestFilteringConfigFromFlagsPreservesFalseAndZero(t *testing.T) {
	t.Parallel()

	command := filteringCommand(t, filteringCommandConfigName)
	require.NoError(t, command.ParseFlags([]string{"--enabled=false", "--interval=0"}))

	enabled, interval, err := filteringConfigFromFlags(command)

	require.NoError(t, err)
	assert.False(t, enabled)
	assert.Zero(t, interval)
}

// TestFilteringURLFromFlagsPreservesEmptyAndFalse verifies argument-to-app shaping.
func TestFilteringURLFromFlagsPreservesEmptyAndFalse(t *testing.T) {
	t.Parallel()

	command := filteringCommand(t, filteringCommandAddURLName)
	require.NoError(t, command.ParseFlags([]string{"--whitelist=false"}))

	whitelist, err := filteringURLFromFlags(command)

	require.NoError(t, err)
	assert.False(t, whitelist)
}

// TestNewCommandPreservesSubcommandSyntax verifies the published CLI surface.
func TestNewCommandPreservesSubcommandSyntax(t *testing.T) {
	t.Parallel()

	for _, test := range filteringSyntaxCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			command := filteringCommand(t, test.sub)

			assert.Equal(t, test.expected.Use, command.Use)
			assert.Equal(t, test.expected.Short, command.Short)
			assertFilteringFlagSyntax(t, command, test.expected.Flags)
		})
	}
}

// TestNewCommandReturnsIndependentSubcommands verifies that repeated construction
// yields separate commands whose parsed flag state cannot leak into a later
// construction or execution.
func TestNewCommandReturnsIndependentSubcommands(t *testing.T) {
	t.Parallel()

	first := filteringCommand(t, filteringCommandStatusName)
	second := filteringCommand(t, filteringCommandStatusName)

	require.NotSame(t, first, second)
	require.NoError(t, first.ParseFlags(
		filteringAllInstancesArguments(filteringCommandAlphaInstance),
	))

	all, err := second.Flags().GetBool(filteringAllFlag)
	require.NoError(t, err)

	names, err := second.Flags().GetStringSlice(filteringInstanceFlag)
	require.NoError(t, err)

	assert.False(t, all)
	assert.Empty(t, names)
}

// TestCurrentFilteringSelectionReadsExecutedCommandFlags verifies that each
// execution resolves instances from its own command state instead of state left
// behind by an earlier execution.
func TestCurrentFilteringSelectionReadsExecutedCommandFlags(t *testing.T) {
	t.Parallel()

	first := filteringCommand(t, filteringCommandAddURLName)
	second := filteringCommand(t, filteringCommandRemoveURLName)

	require.NoError(t, first.ParseFlags(
		filteringAllInstancesArguments(filteringCommandAlphaInstance),
	))
	require.NoError(t, second.ParseFlags(
		filteringNamedInstancesArguments(filteringCommandZuluInstance),
	))

	firstSelection, err := currentFilteringSelection(first)
	require.NoError(t, err)

	secondSelection, err := currentFilteringSelection(second)
	require.NoError(t, err)

	assert.True(t, firstSelection.All)
	assert.Equal(t, []string{filteringCommandAlphaInstance}, firstSelection.Names)
	assert.False(t, secondSelection.All)
	assert.Equal(t, []string{filteringCommandZuluInstance}, secondSelection.Names)
}

// TestCurrentFilteringSelectionDefaultsToUnscopedSelection verifies that a
// freshly constructed command selects neither explicit names nor every instance.
func TestCurrentFilteringSelectionDefaultsToUnscopedSelection(t *testing.T) {
	t.Parallel()

	command := filteringCommand(t, filteringCommandStatusName)

	selection, err := currentFilteringSelection(command)

	require.NoError(t, err)
	assert.False(t, selection.All)
	assert.Empty(t, selection.Names)
}

// TestCurrentFilteringSelectionRejectsMissingFlags verifies flag lookup failures.
func TestCurrentFilteringSelectionRejectsMissingFlags(t *testing.T) {
	t.Parallel()

	_, err := currentFilteringSelection(&cobra.Command{})

	require.ErrorContains(t, err, "parse instance flag")
}

// TestWriteFilteringStatuses verifies command-owned status rendering and order.
func TestWriteFilteringStatuses(t *testing.T) {
	t.Parallel()

	filters := []app.FilteringSubscription{{
		Enabled:    false,
		Name:       "filters",
		RulesCount: 0,
		URL:        "https://filters.example/list.txt",
	}}
	allowlists := []app.FilteringSubscription{}
	var output bytes.Buffer

	command := &cobra.Command{}
	command.SetOut(&output)

	err := writeFilteringStatuses(command, []app.FilteringStatusResult{
		{
			Filters:          &filters,
			WhitelistFilters: &allowlists,
			Instance:         filteringCommandAlphaInstance,
			Index:            0,
			InstanceCount:    2,
		},
		{Instance: filteringCommandZuluInstance, Index: 1, InstanceCount: 2},
	})

	require.NoError(t, err)
	assert.Contains(t, output.String(), "Instance: alpha")
	assert.Contains(t, output.String(), "filters")
	assert.Contains(t, output.String(), "disabled")
	assert.Contains(t, output.String(), "Instance: zulu")
	assert.Less(t, strings.Index(output.String(), "alpha"), strings.Index(output.String(), "zulu"))
}

// TestWriteFilteringMutationResults verifies success-message wiring.
func TestWriteFilteringMutationResults(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	command := &cobra.Command{}
	command.SetOut(&output)

	err := writeFilteringMutationResults(command, []app.FilteringMutationResult{
		{Instance: filteringCommandAlphaInstance, Message: filteringCommandAddedMessage},
	})

	require.NoError(t, err)
	assert.Equal(t, "[alpha] Added filter URL filters\n", output.String())
}

// TestWriteFilteringMutationResultsPreservesWriterErrors verifies output failures.
func TestWriteFilteringMutationResultsPreservesWriterErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("write failed")
	command := &cobra.Command{}
	command.SetOut(filteringFailingWriter{err: wantErr})

	err := writeFilteringMutationResults(command, []app.FilteringMutationResult{
		{Instance: filteringCommandAlphaInstance, Message: filteringCommandAddedMessage},
	})

	require.ErrorIs(t, err, wantErr)
}

// Write returns the configured rendering error.
//
// Parameters:
//   - _: Output bytes intentionally ignored.
//
// Returns:
//   - int: The number of bytes written, always zero.
//   - error: The configured rendering error.
func (writer filteringFailingWriter) Write(_ []byte) (int, error) {
	return 0, writer.err
}

// filteringCommand returns a freshly constructed filtering subcommand.
//
// Parameters:
//   - t: Test context used to report resolution failures.
//   - name: Subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The freshly constructed subcommand.
func filteringCommand(t *testing.T, name string) *cobra.Command {
	t.Helper()

	command, _, err := NewCommand().Find([]string{name})
	require.NoError(t, err)

	return command
}

// filteringSelectionFlagSyntax returns the selection flags shared by every
// filtering subcommand.
//
// Returns:
//   - []filteringExpectedFlag: The published shared selection flags.
func filteringSelectionFlagSyntax() []filteringExpectedFlag {
	return []filteringExpectedFlag{
		{
			Name:      filteringAllFlag,
			Shorthand: "a",
			Usage:     "target all instances",
			Default:   "false",
			ValueType: filteringCommandBoolType,
		},
		{
			Name:      filteringInstanceFlag,
			Shorthand: "i",
			Usage:     "target instance name(s)",
			Default:   "[]",
			ValueType: "stringSlice",
		},
	}
}

// filteringSyntaxCases returns the published syntax of every filtering subcommand.
//
// Returns:
//   - []filteringSyntaxCase: One case per published subcommand.
func filteringSyntaxCases() []filteringSyntaxCase {
	selection := filteringSelectionFlagSyntax()

	return []filteringSyntaxCase{
		{
			name: "status",
			sub:  filteringCommandStatusName,
			expected: filteringSubcommandSyntax{
				Use:   filteringCommandStatusName,
				Short: "Get filtering status",
				Flags: filteringFlags(nil, selection),
			},
		},
		{
			name: "config",
			sub:  filteringCommandConfigName,
			expected: filteringSubcommandSyntax{
				Use:   filteringCommandConfigName,
				Short: "Update filtering configuration",
				Flags: filteringFlags([]filteringExpectedFlag{
					{
						Name:      "enabled",
						Shorthand: "e",
						Usage:     "enable filtering",
						Default:   "true",
						ValueType: filteringCommandBoolType,
					},
					{
						Name:      "interval",
						Shorthand: "n",
						Usage:     "update interval hours",
						Default:   "0",
						ValueType: "int32",
					},
				}, selection),
			},
		},
		{
			name: "add-url",
			sub:  filteringCommandAddURLName,
			expected: filteringSubcommandSyntax{
				Use:   "add-url <name> <url>",
				Short: "Add a filter URL",
				Flags: filteringFlags([]filteringExpectedFlag{
					{
						Name:      "whitelist",
						Shorthand: "w",
						Usage:     "add to whitelist",
						Default:   "false",
						ValueType: filteringCommandBoolType,
					},
				}, selection),
			},
		},
		{
			name: "remove-url",
			sub:  filteringCommandRemoveURLName,
			expected: filteringSubcommandSyntax{
				Use:   "remove-url <url>",
				Short: "Remove a filter URL",
				Flags: filteringFlags(nil, selection),
			},
		},
	}
}

// filteringAllInstancesArguments renders arguments selecting every instance.
//
// Parameters:
//   - names: Instance names selected explicitly alongside the --all flag.
//
// Returns:
//   - []string: Flag arguments parsed by a filtering subcommand.
func filteringAllInstancesArguments(names ...string) []string {
	return slices.Concat(
		[]string{filteringCommandAllFlagArg},
		filteringNamedInstancesArguments(names...),
	)
}

// filteringNamedInstancesArguments renders arguments selecting explicit instances.
//
// Parameters:
//   - names: Instance names selected explicitly.
//
// Returns:
//   - []string: Flag arguments parsed by a filtering subcommand.
func filteringNamedInstancesArguments(names ...string) []string {
	arguments := make([]string, 0, 2*len(names))

	for _, name := range names {
		arguments = append(arguments, filteringCommandInstanceFlagArg, name)
	}

	return arguments
}

// filteringFlags assembles the published flags of one subcommand.
//
// Parameters:
//   - command: Command-specific flags published before the shared flags.
//   - shared: Selection flags shared by every filtering subcommand.
//
// Returns:
//   - []filteringExpectedFlag: The assembled published flag descriptions.
func filteringFlags(
	command []filteringExpectedFlag,
	shared []filteringExpectedFlag,
) []filteringExpectedFlag {
	return append(slices.Clone(command), shared...)
}

// assertFilteringFlagSyntax verifies the published flag set of one command.
//
// Parameters:
//   - t: Test context used to report assertion failures.
//   - command: Command whose local flags are verified.
//   - expected: Published flag descriptions.
func assertFilteringFlagSyntax(
	t *testing.T,
	command *cobra.Command,
	expected []filteringExpectedFlag,
) {
	t.Helper()

	registered := make([]string, 0, len(expected))

	command.Flags().VisitAll(func(flag *pflag.Flag) {
		registered = append(registered, flag.Name)
	})

	expectedNames := make([]string, 0, len(expected))
	for _, want := range expected {
		expectedNames = append(expectedNames, want.Name)
	}

	slices.Sort(registered)
	slices.Sort(expectedNames)

	require.Equal(t, expectedNames, registered)

	for _, want := range expected {
		flag := command.Flags().Lookup(want.Name)
		require.NotNilf(t, flag, "flag %q is not registered", want.Name)
		assert.Equal(t, want.Shorthand, flag.Shorthand)
		assert.Equal(t, want.Usage, flag.Usage)
		assert.Equal(t, want.Default, flag.DefValue)
		assert.Equal(t, want.ValueType, flag.Value.Type())
	}
}
