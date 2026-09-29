// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// instanceFlagExpectation describes one expected flag registration.
type instanceFlagExpectation struct {
	// def is the expected default value rendered by pflag.
	def string
	// shorthand is the expected one-letter shorthand.
	shorthand string
}

// instanceCommandSyntax describes the published syntax of one subcommand.
type instanceCommandSyntax struct {
	// Flags lists every published flag of the subcommand.
	Flags map[string]instanceFlagExpectation
	// Short is the published one-line description.
	Short string
	// Use is the published invocation syntax.
	Use string
	// Name is the subcommand name.
	Name string
}

// instanceRun captures the rendered result of one command execution.
type instanceRun struct {
	// out is the rendered command output.
	out string
	// errOut is the rendered error output, including usage and notices.
	errOut string
	// err is the execution error, or nil when the command succeeded.
	err error
}

// instanceConfigEntry pairs one configured instance name with its host value.
type instanceConfigEntry struct {
	// host is the configured instance host.
	host string
	// name is the configured instance name.
	name string
}

const (
	// InstanceListName identifies the list subcommand.
	InstanceListName = "list"
	// InstanceAddName identifies the add subcommand.
	InstanceAddName = "add"
	// InstanceRemoveName identifies the remove subcommand.
	InstanceRemoveName = "remove"
	// InstanceCredentialsName identifies the credentials subcommand group.
	InstanceCredentialsName = "credentials"
	// InstanceContextProbeName identifies the context probe subcommand.
	InstanceContextProbeName = "context-probe"
	// InstanceAllFlag is the published long form of the --all flag.
	InstanceAllFlag = "--all"
	// InstanceAllFlagName names the --all flag.
	InstanceAllFlagName = "all"
	// InstanceSchemeFlagName names the --scheme flag.
	InstanceSchemeFlagName = "scheme"
	// InstancePasswordFlagName names a flag that must never be published by a
	// credential or add command.
	InstancePasswordFlagName = "password"
	// InstanceUsernameFlagName names a flag that must never be published by the
	// add command.
	InstanceUsernameFlagName = "username"
	// InstanceAddedHost is the host recorded by the add test.
	InstanceAddedHost = "command-added.example.com"
	// InstanceAddedScheme is the scheme recorded by the add test.
	InstanceAddedScheme = "http"
	// InstanceConfigFileName is the configuration file name used by command tests.
	InstanceConfigFileName = "config.yaml"
	// InstanceUsernameReplacement names the username command in the add help
	// text.
	InstanceUsernameReplacement = "credentials username set"
	// InstancePasswordReplacement names the password command in the add help
	// text.
	InstancePasswordReplacement = "credentials password set"
)

// instanceCommandMutex serializes the command tests that mutate the
// process-global Viper instance, so parallel execution never observes
// configuration state written by another test.
var instanceCommandMutex sync.Mutex

// TestNewCommandPreservesSubcommandSyntax verifies the published CLI surface.
func TestNewCommandPreservesSubcommandSyntax(t *testing.T) {
	t.Parallel()

	syntaxes := []instanceCommandSyntax{
		{
			Name:  InstanceListName,
			Use:   InstanceListName,
			Short: "List configured instances",
			Flags: map[string]instanceFlagExpectation{
				InstanceAllFlagName: {def: "false", shorthand: "a"},
			},
		},
		{
			Name:  InstanceAddName,
			Use:   "add <instance> <host>",
			Short: "Add a new instance configuration",
			Flags: map[string]instanceFlagExpectation{
				InstanceSchemeFlagName: {def: instanceCommandHTTPScheme, shorthand: "s"},
			},
		},
		{
			Name:  InstanceRemoveName,
			Use:   "remove <instance>",
			Short: "Remove an instance configuration and its stored password",
			Flags: map[string]instanceFlagExpectation{},
		},
		{
			Name:  InstanceCredentialsName,
			Use:   InstanceCredentialsName,
			Short: "Manage instance authentication",
			Flags: map[string]instanceFlagExpectation{},
		},
	}

	for _, syntax := range syntaxes {
		t.Run(syntax.Name, func(t *testing.T) {
			t.Parallel()

			command := requireInstanceSubcommand(t, NewCommand(), syntax.Name)

			assert.Equal(t, syntax.Use, command.Use)
			assert.Equal(t, syntax.Short, command.Short)

			for flagName, expected := range syntax.Flags {
				flag := command.Flags().Lookup(flagName)
				require.NotNil(t, flag)
				assert.Equal(t, expected.shorthand, flag.Shorthand)
				assert.Equal(t, expected.def, flag.DefValue)
			}
		})
	}
}

// TestNewCommandAddPublishesNoCredentialFlags verifies that adding an instance
// cannot carry authentication details on the command line. Both belong to the
// credential workflow, so neither is published.
func TestNewCommandAddPublishesNoCredentialFlags(t *testing.T) {
	t.Parallel()

	add := requireInstanceSubcommand(t, NewCommand(), InstanceAddName)

	assert.Nil(t, add.Flags().Lookup(InstanceUsernameFlagName))
	assert.Nil(t, add.Flags().Lookup(InstancePasswordFlagName))
	assert.Nil(t, add.Flags().Lookup("u"))
	assert.Nil(t, add.Flags().Lookup("p"))
}

// TestNewCommandAddNamesCredentialCommands verifies the add help points at the
// commands that configure authentication.
func TestNewCommandAddNamesCredentialCommands(t *testing.T) {
	t.Parallel()

	add := requireInstanceSubcommand(t, NewCommand(), InstanceAddName)

	help := flattenHelp(add.Long)

	assert.Contains(t, help, InstanceUsernameReplacement)
	assert.Contains(t, help, InstancePasswordReplacement)
}

// flattenHelp collapses the line breaks of a wrapped help string, so an
// assertion about a command path does not depend on where the text wraps.
//
// Parameters:
//   - help: the wrapped help text.
//
// Returns:
//   - string: the help text with runs of whitespace collapsed to one space.
func flattenHelp(help string) string {
	return strings.Join(strings.Fields(help), " ")
}

// TestNewCommandCredentialsRegistersLeaves verifies that the credentials group
// separates the two halves of instance authentication and keeps the whole-instance
// migration at the group level.
func TestNewCommandCredentialsRegistersLeaves(t *testing.T) {
	t.Parallel()

	group := requireInstanceSubcommand(t, NewCommand(), InstanceCredentialsName)

	leaves := []string{"migrate", "username", "password"}

	for _, leaf := range leaves {
		require.NotNil(t, group.Commands(), "credentials group has no subcommands")
		require.NotNil(t, requireInstanceSubcommand(t, group, leaf), leaf)
	}

	usernameGroup := requireInstanceSubcommand(t, group, "username")
	assert.Equal(t, "set <instance> <username>",
		requireInstanceSubcommand(t, usernameGroup, "set").Use)
	assert.Equal(t, "status [instance]",
		requireInstanceSubcommand(t, usernameGroup, "status").Use)
	assert.Equal(t, "clear <instance>",
		requireInstanceSubcommand(t, usernameGroup, "clear").Use)

	passwordGroup := requireInstanceSubcommand(t, group, "password")
	assert.Equal(t, "set <instance>",
		requireInstanceSubcommand(t, passwordGroup, "set").Use)
	assert.Equal(t, "status [instance]",
		requireInstanceSubcommand(t, passwordGroup, "status").Use)
	assert.Equal(t, "clear <instance>",
		requireInstanceSubcommand(t, passwordGroup, "clear").Use)
}

// TestNewCommandSetPublishesNoPasswordFlag verifies that the credential write
// path cannot receive a secret from the command line.
func TestNewCommandSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	group := requireInstanceSubcommand(t, NewCommand(), InstanceCredentialsName)
	passwordGroup := requireInstanceSubcommand(t, group, "password")
	set := requireInstanceSubcommand(t, passwordGroup, "set")

	assert.Nil(t, set.Flags().Lookup(InstancePasswordFlagName))
	assert.NotNil(t, set.Flags().Lookup("key"))
	assert.NotNil(t, set.Flags().Lookup("yes"))
}

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := NewCommand()
	second := NewCommand()

	firstList := requireInstanceSubcommand(t, first, InstanceListName)
	secondList := requireInstanceSubcommand(t, second, InstanceListName)
	firstAdd := requireInstanceSubcommand(t, first, InstanceAddName)
	secondAdd := requireInstanceSubcommand(t, second, InstanceAddName)
	firstSet := requireInstanceSubcommand(
		t,
		requireInstanceSubcommand(
			t,
			requireInstanceSubcommand(t, first, InstanceCredentialsName),
			"password",
		),
		"set",
	)
	secondSet := requireInstanceSubcommand(
		t,
		requireInstanceSubcommand(
			t,
			requireInstanceSubcommand(t, second, InstanceCredentialsName),
			"password",
		),
		"set",
	)

	require.NotSame(t, first, second)
	require.NotSame(t, firstList, secondList)
	require.NotSame(t, firstAdd, secondAdd)
	require.NotSame(t, firstSet, secondSet)

	require.NoError(t, firstList.Flags().Set(InstanceAllFlagName, "true"))
	require.NoError(t, firstAdd.Flags().Set(InstanceSchemeFlagName, InstanceAddedScheme))
	require.NoError(t, firstSet.Flags().Set("key", "leaked"))

	all, err := secondList.Flags().GetBool(InstanceAllFlagName)
	require.NoError(t, err)
	assert.False(t, all)
	assert.False(t, secondList.Flags().Changed(InstanceAllFlagName))

	scheme, err := secondAdd.Flags().GetString(InstanceSchemeFlagName)
	require.NoError(t, err)
	assert.Equal(t, instanceCommandHTTPScheme, scheme)

	key, err := secondSet.Flags().GetString("key")
	require.NoError(t, err)
	assert.Empty(t, key)
}

// TestNewCommandExecutionUsesFreshContext verifies that a later execution never
// observes a context left behind on an earlier command tree.
func TestNewCommandExecutionUsesFreshContext(t *testing.T) {
	t.Parallel()

	observed := make([]error, 0, 2)

	first := NewCommand()
	recordInstanceContext(first, &observed)
	first.SetArgs([]string{InstanceContextProbeName})

	cancelable, cancel := context.WithCancel(t.Context())
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := NewCommand()
	recordInstanceContext(second, &observed)
	second.SetArgs([]string{InstanceContextProbeName})

	require.NoError(t, second.Execute())

	require.Len(t, observed, 2)
	assert.NoError(t, observed[0])
	assert.NoError(t, observed[1])
}

// TestNewCommandRepeatedExecutionKeepsFlagState verifies that repeatedly
// constructing and executing the command tree never reuses flag state, so an
// earlier --all value cannot leak into a later execution.
func TestNewCommandRepeatedExecutionKeepsFlagState(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	viper.Set("instances", map[string]any{
		instanceCommandDefaultName: map[string]any{
			instanceCommandHostKey: instanceCommandDefaultHost,
		},
		instanceCommandAlphaName: map[string]any{
			instanceCommandHostKey: instanceCommandAlphaHost,
		},
	})

	selected := runInstanceCommand(t, []string{InstanceListName, InstanceAllFlag})
	require.NoError(t, selected.err)
	assert.Equal(t, "alpha\ndefault\n", selected.out)

	scoped := runInstanceCommand(t, []string{InstanceListName})
	require.NoError(t, scoped.err)
	assert.Equal(t, "default\n", scoped.out)
}

// TestNewCommandAddPersistsFlagValues verifies that every construction binds the
// add flags to the executed command and writes them to the configuration.
func TestNewCommandAddPersistsFlagValues(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(
		t,
		instanceConfigEntry{
			name: instanceCommandDefaultName,
			host: instanceCommandDefaultHost,
		},
	)

	useConfigFile(t, configPath)

	run := runInstanceCommand(t, []string{
		InstanceAddName,
		instanceCommandAlphaName,
		InstanceAddedHost,
		"--" + InstanceSchemeFlagName, InstanceAddedScheme,
	})

	require.NoError(t, run.err)
	assert.Equal(t, "Instance \""+instanceCommandAlphaName+"\" added\n", run.out)

	written := readInstanceConfig(t, configPath)

	assert.Contains(t, written, "  "+instanceCommandAlphaName+":")
	assert.Contains(t, written, "    host: "+InstanceAddedHost)
	assert.Contains(t, written, "    scheme: "+InstanceAddedScheme)
	assert.Contains(t, written, "  "+instanceCommandDefaultName+":")
}

// TestNewCommandAddStoresNoCredentials verifies that an added instance is
// written without a username or password, because both are owned by the
// credential workflow.
func TestNewCommandAddStoresNoCredentials(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(t)
	useConfigFile(t, configPath)

	run := runInstanceCommand(t, []string{
		InstanceAddName,
		instanceCommandAlphaName,
		InstanceAddedHost,
	})

	require.NoError(t, run.err)

	written := readInstanceConfig(t, configPath)

	assert.NotContains(t, written, "username:")
	assert.NotContains(t, written, "password:")
	assert.NotContains(t, written, "credential:")
}

// TestNewCommandAddRejectsCredentialFlags verifies that a caller still passing a
// credential flag is refused by name rather than silently ignored.
func TestNewCommandAddRejectsCredentialFlags(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(t)
	useConfigFile(t, configPath)

	for _, flagName := range []string{InstanceUsernameFlagName, InstancePasswordFlagName} {
		run := runInstanceCommand(t, []string{
			InstanceAddName,
			instanceCommandAlphaName,
			InstanceAddedHost,
			"--" + flagName, "value",
		})

		require.Error(t, run.err, flagName)
		assert.Contains(t, run.err.Error(), "unknown flag: --"+flagName)
		assert.NotContains(t, readInstanceConfig(t, configPath), instanceCommandAlphaName)
	}
}

// TestNewCommandRemoveDeletesConfiguredInstance verifies that removal targets the
// configuration file resolved by the executed command.
func TestNewCommandRemoveDeletesConfiguredInstance(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(
		t,
		instanceConfigEntry{name: instanceCommandAlphaName, host: InstanceAddedHost},
		instanceConfigEntry{
			name: instanceCommandDefaultName,
			host: instanceCommandDefaultHost,
		},
	)

	useConfigFile(t, configPath)

	run := runInstanceCommand(
		t,
		[]string{InstanceRemoveName, instanceCommandAlphaName},
	)

	require.NoError(t, run.err)
	assert.Equal(t, "Instance \""+instanceCommandAlphaName+"\" removed\n", run.out)

	written := readInstanceConfig(t, configPath)

	assert.NotContains(t, written, "  "+instanceCommandAlphaName+":")
	assert.Contains(t, written, "  "+instanceCommandDefaultName+":")
}

// TestNewCommandAddRejectsDuplicateInstance verifies that the moved
// configuration logic still reports a duplicate instance.
func TestNewCommandAddRejectsDuplicateInstance(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(t, instanceConfigEntry{
		name: instanceCommandAlphaName,
		host: InstanceAddedHost,
	})

	useConfigFile(t, configPath)

	run := runInstanceCommand(t, []string{
		InstanceAddName,
		instanceCommandAlphaName,
		InstanceAddedHost,
	})

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "already exists")
}

// TestNewCommandRemoveRejectsUnknownInstance verifies that the moved
// configuration logic still reports an unknown instance.
func TestNewCommandRemoveRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(t)
	useConfigFile(t, configPath)

	run := runInstanceCommand(
		t,
		[]string{InstanceRemoveName, instanceCommandZuluName},
	)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "not found")
}

// TestInstanceRemoveReportsCredentialOutcome verifies the rendered outcome of a
// removal, so the operator learns whether the stored password went with the
// instance. An instance that kept no credential in the store reports one line.
func TestInstanceRemoveReportsCredentialOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		result app.InstanceRemoveResult
		want   string
		name   string
	}{
		{
			name:   "removed credential",
			result: app.InstanceRemoveResult{Key: "alpha", Service: "agh-cli", Removed: true},
			want: "Instance \"alpha\" removed\n" +
				"Removed credential for instance \"alpha\" with key \"alpha\" " +
				"from service \"agh-cli\".\n",
		},
		{
			name:   "absent credential",
			result: app.InstanceRemoveResult{Key: "alpha", Service: "agh-cli"},
			want: "Instance \"alpha\" removed\n" +
				"No stored credential for instance \"alpha\" with key \"alpha\" " +
				"in service \"agh-cli\".\n",
		},
		{
			name:   "credential shared with another instance",
			result: app.InstanceRemoveResult{Key: "shared", Service: "agh-cli", Shared: true},
			want: "Instance \"alpha\" removed\n" +
				"Kept credential with key \"shared\" in service \"agh-cli\": another " +
				"configured instance still reads its password through it.\n",
		},
		{
			name:   "credential owned by another system",
			result: app.InstanceRemoveResult{Service: "agh-cli"},
			want:   "Instance \"alpha\" removed\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// The command reads the resolved configuration path, which lives in
			// the process-global Viper instance the other command tests write.
			lockInstanceCommandState(t)

			result := test.result

			result.Instance = "alpha"

			run := runInstanceRemoveCommand(t, stubRemoval(result, nil), "alpha")

			require.NoError(t, run.err)
			assert.Equal(t, test.want, run.out)
		})
	}
}

// TestInstanceRemoveUsesResolvedConfigurationPath verifies that the command
// removes from the file the executed run resolved rather than from a path of its
// own.
func TestInstanceRemoveUsesResolvedConfigurationPath(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(t, instanceConfigEntry{
		name: instanceCommandAlphaName,
		host: InstanceAddedHost,
	})
	useConfigFile(t, configPath)

	observed := make([]app.InstanceRemoveRequest, 0, 1)
	remove := func(_ context.Context, request app.InstanceRemoveRequest) (app.InstanceRemoveResult, error) {
		observed = append(observed, request)

		return app.InstanceRemoveResult{Instance: request.Name}, nil
	}

	run := runInstanceRemoveCommand(t, remove, instanceCommandAlphaName)

	require.NoError(t, run.err)
	require.Len(t, observed, 1)
	assert.Equal(t, configPath, observed[0].ConfigPath)
	assert.Equal(t, instanceCommandAlphaName, observed[0].Name)
}

// TestInstanceRemoveReportsFailure verifies that a refusal from the use case is
// surfaced rather than reported as a completed removal.
func TestInstanceRemoveReportsFailure(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)

	wantErr := errors.New("credential store unavailable")
	run := runInstanceRemoveCommand(t, stubRemoval(app.InstanceRemoveResult{}, wantErr), "alpha")

	require.ErrorIs(t, run.err, wantErr)
	assert.Contains(t, run.err.Error(), "remove instance")
	assert.NotContains(t, run.out, "removed")
}

// TestInstanceRemoveReportsCredentialRemovedWithFailure verifies that a removal
// whose credential was deleted before the configuration write failed says so.
// The instance stays configured while its password is already gone, and the
// operator cannot infer that state from the error alone.
func TestInstanceRemoveReportsCredentialRemovedWithFailure(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)

	wantErr := errors.New(`write configuration: write config: permission denied`)
	run := runInstanceRemoveCommand(
		t,
		stubRemoval(
			app.InstanceRemoveResult{
				Instance: "alpha",
				Service:  "agh-cli",
				Key:      "alpha-key",
				Removed:  true,
			},
			wantErr,
		),
		"alpha",
	)

	require.ErrorIs(t, run.err, wantErr)
	assert.Contains(t, run.err.Error(), "remove instance")
	assert.Contains(
		t,
		run.out,
		"Removed credential for instance \"alpha\" with key \"alpha-key\" from "+
			"service \"agh-cli\".",
	)
	assert.Contains(t, run.out, "Instance \"alpha\" remains configured")
	assert.NotContains(t, run.out, "Instance \"alpha\" removed")
}

// stubRemoval builds an instance removal returning a fixed outcome.
//
// Parameters:
//   - result: outcome reported by the removal.
//   - err: failure reported by the removal.
//
// Returns:
//   - removal: instance removal used by the command under test.
func stubRemoval(result app.InstanceRemoveResult, err error) removal {
	return func(_ context.Context, _ app.InstanceRemoveRequest) (app.InstanceRemoveResult, error) {
		return result, err
	}
}

// runInstanceRemove executes a remove command bound to an injected removal.
//
// Parameters:
//   - t: active test requiring command construction and error assertions.
//   - remove: instance removal used by the command.
//   - args: command line arguments passed to the remove command.
//
// Returns:
//   - instanceRun: the rendered output streams and the execution error.
func runInstanceRemoveCommand(
	t *testing.T,
	remove removal,
	args ...string,
) instanceRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := newInstanceRemoveCommand(remove)
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetArgs(args)

	runErr := command.Execute()

	return instanceRun{
		out:    output.String(),
		errOut: errorsOut.String(),
		err:    runErr,
	}
}

// lockInstanceCommandState serializes one test against the other tests that
// mutate the process-global Viper instance.
//
// Parameters:
//   - t: active test requiring serialized configuration state.
func lockInstanceCommandState(t *testing.T) {
	t.Helper()

	instanceCommandMutex.Lock()
	t.Cleanup(instanceCommandMutex.Unlock)
}

// resetInstanceCommandState isolates package-level command state for one test.
//
// Parameters:
//   - t: active test requiring Viper isolation.
func resetInstanceCommandState(t *testing.T) {
	t.Helper()

	viper.Reset()

	t.Cleanup(viper.Reset)
}

// runInstanceCommand executes one freshly constructed instance command tree.
//
// Parameters:
//   - t: active test requiring command construction and error assertions.
//   - args: command line arguments passed to the instance command.
//
// Returns:
//   - instanceRun: the rendered output streams and the execution error.
func runInstanceCommand(t *testing.T, args []string) instanceRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := NewCommand()
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetArgs(args)

	err := command.Execute()

	return instanceRun{
		out:    output.String(),
		errOut: errorsOut.String(),
		err:    err,
	}
}

// writeInstanceConfig writes a configuration file for the given instances.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - entries: configured instances in file order.
//
// Returns:
//   - string: path of the written configuration file.
func writeInstanceConfig(t *testing.T, entries ...instanceConfigEntry) string {
	t.Helper()

	lines := make([]string, 0, 1+2*len(entries))

	// An empty mapping keeps the file loadable, because a bare key parses as a
	// null scalar rather than a mapping.
	if len(entries) == 0 {
		lines = append(lines, "instances: {}")
	}

	if len(entries) > 0 {
		lines = append(lines, "instances:")
	}

	for _, entry := range entries {
		lines = append(lines, "  "+entry.name+":", "    host: "+entry.host)
	}

	configPath := filepath.Join(t.TempDir(), InstanceConfigFileName)
	require.NoError(t, os.WriteFile(configPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	return configPath
}

// readInstanceConfig returns the raw configuration file contents.
//
// The command tests read the document as text instead of decoding it, so they
// observe exactly what an operator sees in the file and never depend on the
// configuration package the command layer must not import.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - configPath: path of the configuration file to read.
//
// Returns:
//   - string: the configuration file contents.
func readInstanceConfig(t *testing.T, configPath string) string {
	t.Helper()

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	return string(data)
}

// useConfigFile points the global Viper instance at the given configuration file.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - configPath: path of the configuration file to read.
func useConfigFile(t *testing.T, configPath string) {
	t.Helper()

	// Mirrors the root pre-run: publish the resolution, then read the file.
	app.PublishConfigResolution(app.ConfigResolution{Path: configPath, Exists: true})
	viper.SetConfigFile(configPath)
	require.NoError(t, viper.ReadInConfig())
}

// requireInstanceSubcommand resolves one subcommand of a constructed parent.
//
// Parameters:
//   - t: active test requiring command resolution.
//   - parent: command owning the subcommand.
//   - name: subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The resolved subcommand.
func requireInstanceSubcommand(
	t *testing.T,
	parent *cobra.Command,
	name string,
) *cobra.Command {
	t.Helper()

	command, _, findErr := parent.Find([]string{name})
	require.NoError(t, findErr)
	require.Equal(t, name, command.Name())

	return command
}

// recordInstanceContext attaches a probe subcommand recording the context error
// observed during execution.
//
// Parameters:
//   - command: command tree receiving the probe subcommand.
//   - observed: collects the context error reported by each probe execution.
func recordInstanceContext(command *cobra.Command, observed *[]error) {
	probeCommand := &cobra.Command{
		Use: InstanceContextProbeName,
		RunE: func(cmd *cobra.Command, _ []string) error {
			*observed = append(*observed, cmd.Context().Err())

			return nil
		},
	}

	command.AddCommand(probeCommand)
}
