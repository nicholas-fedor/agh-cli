// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// clientExpectedFlag describes one published flag of a client subcommand.
type clientExpectedFlag struct {
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

// clientSubcommandSyntax describes the published syntax of one subcommand.
type clientSubcommandSyntax struct {
	// Flags lists every published flag of the subcommand.
	Flags []clientExpectedFlag
	// Short is the published one-line description.
	Short string
	// Use is the published invocation syntax.
	Use string
}

// clientSyntaxCase pairs one subcommand with its published syntax.
type clientSyntaxCase struct {
	// expected is the published syntax the subcommand must expose.
	expected clientSubcommandSyntax
	// sub is the subcommand name resolved from a fresh client command.
	sub string
	// name labels the subtest.
	name string
}

const (
	// ClientCommandListName identifies the list subcommand.
	clientCommandListName = "list"
	// ClientCommandAddName identifies the add subcommand.
	clientCommandAddName = "add"
	// ClientCommandDeleteName identifies the delete subcommand.
	clientCommandDeleteName = "delete"
	// ClientCommandUpdateName identifies the update subcommand.
	clientCommandUpdateName = "update"
	// ClientCommandAlphaInstance names the first targeted instance.
	clientCommandAlphaInstance = "alpha"
	// ClientCommandZuluInstance names the second targeted instance.
	clientCommandZuluInstance = "zulu"
	// ClientCommandBoolType identifies the published pflag boolean type.
	clientCommandBoolType = "bool"
	// ClientCommandAllArg is the published long form of the --all flag.
	clientCommandAllArg = "--all"
	// ClientCommandInstanceArg is the published long form of the --instance
	// flag.
	clientCommandInstanceArg = "--instance"
	// ClientCommandAllShorthand is the published --all shorthand.
	clientCommandAllShorthand = "a"
	// ClientCommandInstanceShorthand is the published --instance shorthand.
	clientCommandInstanceShorthand = "i"
	// ClientCommandIDShorthand is the published --id shorthand.
	clientCommandIDShorthand = "I"
	// ClientCommandGlobalShorthand is the published --use-global shorthand.
	clientCommandGlobalShorthand = "g"
	// ClientCommandFilteringShorthand is the published --filtering shorthand.
	clientCommandFilteringShorthand = "f"
	// ClientCommandParentalShorthand is the published --parental shorthand.
	clientCommandParentalShorthand = "p"
	// ClientCommandSafebrowsingShorthand is the published --safebrowsing
	// shorthand.
	clientCommandSafebrowsingShorthand = "s"
	// ClientCommandListClientName names a configured client in list responses
	// and in mutation arguments.
	clientCommandListClientName = "desk"
	// ClientCommandListAutoClientName names a discovered client in list
	// responses.
	clientCommandListAutoClientName = "laptop"
	// ClientCommandListClientsPath is the clients status endpoint.
	clientCommandListClientsPath = "/control/clients"
	// ClientCommandListClientsPayload is a clients status response carrying one
	// configured and one automatically discovered client.
	clientCommandListClientsPayload = `{"clients":[{"name":"desk"}],` +
		`"auto_clients":[{"name":"laptop","ip":"192.0.2.20"}]}`
	// ClientCommandFalseDefault is the published rendering of a false boolean
	// flag default.
	clientCommandFalseDefault = "false"
)

// TestClientMutationFromFlagsPreservesFalse verifies explicit false flag wiring.
func TestClientMutationFromFlagsPreservesFalse(t *testing.T) {
	t.Parallel()

	command := newClientAddCommand()
	require.NoError(t, command.ParseFlags([]string{
		"--id=192.0.2.10",
		"--use-global=false",
		"--filtering=false",
		"--parental=true",
		"--safebrowsing=false",
	}))

	mutation, err := clientMutationFromFlags(command)

	require.NoError(t, err)
	assert.Equal(t, app.ClientMutation{
		IDs:                 []string{"192.0.2.10"},
		UseGlobalSettings:   false,
		FilteringEnabled:    false,
		ParentalEnabled:     true,
		SafebrowsingEnabled: false,
	}, mutation)
}

// TestClientMutationFromFlagsPreservesPublishedDefaults verifies that a freshly
// constructed command keeps the documented mutation defaults.
func TestClientMutationFromFlagsPreservesPublishedDefaults(t *testing.T) {
	t.Parallel()

	mutation, err := clientMutationFromFlags(newClientUpdateCommand())

	require.NoError(t, err)
	assert.Equal(t, app.ClientMutation{
		IDs:               []string{},
		UseGlobalSettings: true,
	}, mutation)
}

// TestClientMutationFromFlagsRejectsMissingFlags verifies that a command without
// the mutation flags reports the missing flag instead of a zero request.
func TestClientMutationFromFlagsRejectsMissingFlags(t *testing.T) {
	t.Parallel()

	mutation, err := clientMutationFromFlags(newClientDeleteCommand())

	require.ErrorContains(t, err, "parse id flag")
	assert.Equal(t, app.ClientMutation{}, mutation)
}

// TestNewCommandPreservesSubcommandSyntax verifies the published CLI surface.
func TestNewCommandPreservesSubcommandSyntax(t *testing.T) {
	t.Parallel()

	for _, test := range clientSyntaxCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			command := clientCommand(t, test.sub)

			assert.Equal(t, test.expected.Use, command.Use)
			assert.Equal(t, test.expected.Short, command.Short)
			assertClientFlagSyntax(t, command, test.expected.Flags)
		})
	}
}

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct subcommands whose bound flag values never leak between trees.
//
// A constructor that registered the documented flags on one shared command would
// redefine them on the second construction, and a constructor that reused shared
// bound values would report the previously parsed selection.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	firstList := clientCommand(t, clientCommandListName)
	firstAdd := clientCommand(t, clientCommandAddName)
	secondList := clientCommand(t, clientCommandListName)
	secondAdd := clientCommand(t, clientCommandAddName)

	assert.NotSame(t, firstList, secondList)
	assert.NotSame(t, firstAdd, secondAdd)

	require.NoError(t, firstList.Flags().Set(clientAllFlag, "true"))
	require.NoError(t, firstList.Flags().Set(clientInstanceFlag, clientCommandAlphaInstance))
	require.NoError(t, firstAdd.Flags().Set(clientIDFlag, "192.0.2.10"))
	require.NoError(t, firstAdd.Flags().Set(clientFilteringFlag, "true"))

	assert.True(t, firstList.Flags().Changed(clientAllFlag))
	assert.False(t, secondList.Flags().Changed(clientAllFlag))
	assert.False(t, secondAdd.Flags().Changed(clientIDFlag))

	all, err := secondList.Flags().GetBool(clientAllFlag)
	require.NoError(t, err)

	names, err := secondList.Flags().GetStringSlice(clientInstanceFlag)
	require.NoError(t, err)

	ids, err := secondAdd.Flags().GetStringArray(clientIDFlag)
	require.NoError(t, err)

	assert.False(t, all)
	assert.Empty(t, names)
	assert.Empty(t, ids)
}

// TestNewCommandExecutionUsesFreshContext verifies that a later execution never
// observes a context left behind on an earlier command tree.
func TestNewCommandExecutionUsesFreshContext(t *testing.T) {
	t.Parallel()

	observed := make([]error, 0, 2)

	first := NewCommand()
	recordClientContext(t, first, &observed)
	first.SetArgs([]string{clientCommandListName})

	cancelable, cancel := context.WithCancel(t.Context())
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := NewCommand()
	recordClientContext(t, second, &observed)
	second.SetArgs([]string{clientCommandListName})

	require.NoError(t, second.Execute())

	require.ErrorIs(t, cancelable.Err(), context.Canceled)
	require.Len(t, observed, 2)
	assert.NoError(t, observed[0])
	assert.NoError(t, observed[1])
}

// TestNewCommandRepeatedConstructionKeepsSelectionDefaults verifies that every
// freshly constructed subcommand starts from an unscoped selection.
func TestNewCommandRepeatedConstructionKeepsSelectionDefaults(t *testing.T) {
	t.Parallel()

	for range 3 {
		for _, name := range []string{
			clientCommandListName,
			clientCommandAddName,
			clientCommandDeleteName,
			clientCommandUpdateName,
		} {
			command := clientCommand(t, name)

			all, err := command.Flags().GetBool(clientAllFlag)
			require.NoError(t, err)

			names, err := command.Flags().GetStringSlice(clientInstanceFlag)
			require.NoError(t, err)

			assert.False(t, all)
			assert.Empty(t, names)
		}
	}
}

// TestWriteClientList verifies command-owned rendering receives app-shaped results.
func TestWriteClientList(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	command := &cobra.Command{}
	command.SetOut(&output)
	command.SetErr(&output)

	err := writeClientList(command, []app.ClientListResult{
		{
			Instance:      clientCommandAlphaInstance,
			Index:         0,
			InstanceCount: 2,
		},
		{Instance: clientCommandZuluInstance, Index: 1, InstanceCount: 2},
	})

	require.NoError(t, err)
	assert.Contains(t, output.String(), "Instance: alpha")
	assert.Contains(t, output.String(), "NAME")
	assert.Contains(t, output.String(), "Instance: zulu")
}

// TestWriteClientMutationResults verifies success-message wiring.
func TestWriteClientMutationResults(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	command := &cobra.Command{}
	command.SetOut(&output)
	command.SetErr(&output)
	writeClientMutationResults(command, []app.ClientMutationResult{
		{Instance: clientCommandAlphaInstance, Message: "Updated client desk"},
	})

	assert.Equal(t, "[alpha] Updated client desk\n", output.String())
}

// clientCommand returns a freshly constructed client subcommand.
//
// Parameters:
//   - t: Test context used to report resolution failures.
//   - name: Subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The freshly constructed subcommand.
func clientCommand(t *testing.T, name string) *cobra.Command {
	t.Helper()

	command, _, err := NewCommand().Find([]string{name})
	require.NoError(t, err)

	return command
}

// recordClientContext replaces the list command body with a context probe.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree whose list command is replaced.
//   - observed: Collector receiving the observed context error per execution.
func recordClientContext(t *testing.T, command *cobra.Command, observed *[]error) {
	t.Helper()

	for _, subcommand := range command.Commands() {
		if subcommand.Name() != clientCommandListName {
			continue
		}

		subcommand.RunE = func(cmd *cobra.Command, _ []string) error {
			*observed = append(*observed, cmd.Context().Err())

			return nil
		}

		return
	}

	require.FailNow(t, "missing subcommand", "list is not registered")
}

// clientSelectionFlagSyntax returns the selection flags shared by every client
// subcommand.
//
// Returns:
//   - []clientExpectedFlag: The published shared selection flags.
func clientSelectionFlagSyntax() []clientExpectedFlag {
	return []clientExpectedFlag{
		{
			Name:      clientAllFlag,
			Shorthand: clientCommandAllShorthand,
			Usage:     "target all instances",
			Default:   clientCommandFalseDefault,
			ValueType: clientCommandBoolType,
		},
		{
			Name:      clientInstanceFlag,
			Shorthand: clientCommandInstanceShorthand,
			Usage:     "target instance name(s)",
			Default:   "[]",
			ValueType: "stringSlice",
		},
	}
}

// clientMutationFlagSyntax returns the mutation flags shared by the add and
// update subcommands.
//
// Returns:
//   - []clientExpectedFlag: The published shared mutation flags.
func clientMutationFlagSyntax() []clientExpectedFlag {
	return []clientExpectedFlag{
		{
			Name:      clientUseGlobalFlag,
			Shorthand: clientCommandGlobalShorthand,
			Usage:     "use global settings",
			Default:   "true",
			ValueType: clientCommandBoolType,
		},
		{
			Name:      clientFilteringFlag,
			Shorthand: clientCommandFilteringShorthand,
			Usage:     "enable filtering",
			Default:   clientCommandFalseDefault,
			ValueType: clientCommandBoolType,
		},
		{
			Name:      clientParentalFlag,
			Shorthand: clientCommandParentalShorthand,
			Usage:     "enable parental control",
			Default:   clientCommandFalseDefault,
			ValueType: clientCommandBoolType,
		},
		{
			Name:      clientSafebrowsingFlag,
			Shorthand: clientCommandSafebrowsingShorthand,
			Usage:     "enable safebrowsing",
			Default:   clientCommandFalseDefault,
			ValueType: clientCommandBoolType,
		},
		{
			Name:      clientIDFlag,
			Shorthand: clientCommandIDShorthand,
			Usage:     "client IDs (IP, CIDR, MAC, or ClientID)",
			Default:   "[]",
			ValueType: "stringArray",
		},
	}
}

// clientFlags assembles the published flags of one subcommand.
//
// Parameters:
//   - command: Command-specific flags published before the shared flags.
//   - shared: Selection flags shared by every client subcommand.
//
// Returns:
//   - []clientExpectedFlag: The assembled published flag descriptions.
func clientFlags(
	command []clientExpectedFlag,
	shared []clientExpectedFlag,
) []clientExpectedFlag {
	assembled := make([]clientExpectedFlag, 0, len(command)+len(shared))

	assembled = append(assembled, command...)

	return append(assembled, shared...)
}

// clientSyntaxCases returns the published syntax of every client subcommand.
//
// Returns:
//   - []clientSyntaxCase: The published subcommand syntax cases.
func clientSyntaxCases() []clientSyntaxCase {
	shared := clientSelectionFlagSyntax()
	mutation := clientMutationFlagSyntax()

	return []clientSyntaxCase{
		{
			name: "list",
			sub:  clientCommandListName,
			expected: clientSubcommandSyntax{
				Use:   "list",
				Short: "List clients",
				Flags: shared,
			},
		},
		{
			name: "add",
			sub:  clientCommandAddName,
			expected: clientSubcommandSyntax{
				Use:   "add <name>",
				Short: "Add a client",
				Flags: clientFlags(mutation, shared),
			},
		},
		{
			name: "delete",
			sub:  clientCommandDeleteName,
			expected: clientSubcommandSyntax{
				Use:   "delete <name>",
				Short: "Delete a client",
				Flags: shared,
			},
		},
		{
			name: "update",
			sub:  clientCommandUpdateName,
			expected: clientSubcommandSyntax{
				Use:   "update <name>",
				Short: "Update a client",
				Flags: clientFlags(mutation, shared),
			},
		},
	}
}

// assertClientFlagSyntax verifies the published flag set of one command.
//
// Parameters:
//   - t: Test context used to report assertion failures.
//   - command: Command whose local flags are verified.
//   - expected: Published flag descriptions.
func assertClientFlagSyntax(
	t *testing.T,
	command *cobra.Command,
	expected []clientExpectedFlag,
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

	assert.ElementsMatch(t, expectedNames, registered)

	for _, want := range expected {
		flag := command.Flags().Lookup(want.Name)
		require.NotNilf(t, flag, "flag %q is not registered", want.Name)
		assert.Equal(t, want.Shorthand, flag.Shorthand)
		assert.Equal(t, want.Usage, flag.Usage)
		assert.Equal(t, want.Default, flag.DefValue)
		assert.Equal(t, want.ValueType, flag.Value.Type())
	}
}
