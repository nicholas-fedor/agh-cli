// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// InstancePasswordFlagName names the deprecated --password flag.
	InstancePasswordFlagName = "password"
	// InstanceUsernameFlagName names the --username flag.
	InstanceUsernameFlagName = "username"
	// InstanceAddedHost is the host recorded by the add test.
	InstanceAddedHost = "command-added.example.com"
	// InstanceAddedScheme is the scheme recorded by the add test.
	InstanceAddedScheme = "http"
	// InstanceAddedUsername is the username recorded by the add test.
	InstanceAddedUsername = "admin"
	// InstanceAddedPassword is the password recorded by the add test.
	InstanceAddedPassword = "secret"
	// InstanceConfigFileName is the configuration file name used by command tests.
	InstanceConfigFileName = "config.yaml"
	// InstanceDeprecationMarker is the help marker of the deprecated password
	// flag.
	InstanceDeprecationMarker = "deprecated"
	// InstanceDeprecationReplacement names the replacement command in the help
	// text of the deprecated password flag.
	InstanceDeprecationReplacement = "agh-cli instance credentials set"
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
			Use:   "add <name> <host>",
			Short: "Add a new instance configuration",
			Flags: map[string]instanceFlagExpectation{
				InstanceSchemeFlagName:   {def: instanceCommandHTTPScheme, shorthand: "s"},
				InstanceUsernameFlagName: {def: "", shorthand: "u"},
				InstancePasswordFlagName: {def: "", shorthand: "p"},
			},
		},
		{
			Name:  InstanceRemoveName,
			Use:   "remove <name>",
			Short: "Remove an instance configuration",
			Flags: map[string]instanceFlagExpectation{},
		},
		{
			Name:  InstanceCredentialsName,
			Use:   InstanceCredentialsName,
			Short: "Manage stored instance credentials",
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

// TestNewCommandMarksPasswordFlagDeprecated verifies that the legacy password
// flag stays published while its help names the replacement workflow.
func TestNewCommandMarksPasswordFlagDeprecated(t *testing.T) {
	t.Parallel()

	add := requireInstanceSubcommand(t, NewCommand(), InstanceAddName)

	flag := add.Flags().Lookup(InstancePasswordFlagName)
	require.NotNil(t, flag)

	assert.Contains(t, flag.Usage, InstanceDeprecationMarker)
	assert.Contains(t, flag.Usage, InstanceDeprecationReplacement)
	assert.Contains(t, add.Long, InstanceDeprecationReplacement)
}

// TestNewCommandCredentialsRegistersLeaves verifies that the credentials group
// exposes the four documented use cases.
func TestNewCommandCredentialsRegistersLeaves(t *testing.T) {
	t.Parallel()

	group := requireInstanceSubcommand(t, NewCommand(), InstanceCredentialsName)

	leaves := []string{"set", "clear", "status", "migrate"}

	for _, leaf := range leaves {
		require.NotNil(t, group.Commands(), "credentials group has no subcommands")
		require.NotNil(t, requireInstanceSubcommand(t, group, leaf), leaf)
	}
}

// TestNewCommandSetPublishesNoPasswordFlag verifies that the credential write
// path cannot receive a secret from the command line.
func TestNewCommandSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	group := requireInstanceSubcommand(t, NewCommand(), InstanceCredentialsName)
	set := requireInstanceSubcommand(t, group, "set")

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
		requireInstanceSubcommand(t, first, InstanceCredentialsName),
		"set",
	)
	secondSet := requireInstanceSubcommand(
		t,
		requireInstanceSubcommand(t, second, InstanceCredentialsName),
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
		"--username", InstanceAddedUsername,
		"--" + InstancePasswordFlagName, InstanceAddedPassword,
	})

	require.NoError(t, run.err)
	assert.Equal(t, "Instance \""+instanceCommandAlphaName+"\" added\n", run.out)

	written := readInstanceConfig(t, configPath)

	assert.Contains(t, written, "  "+instanceCommandAlphaName+":")
	assert.Contains(t, written, "    host: "+InstanceAddedHost)
	assert.Contains(t, written, "    scheme: "+InstanceAddedScheme)
	assert.Contains(t, written, "    username: "+InstanceAddedUsername)
	assert.Contains(t, written, "    password: "+InstanceAddedPassword)
	assert.Contains(t, written, "  "+instanceCommandDefaultName+":")
}

// TestNewCommandAddWarnsAboutDeprecatedPassword verifies that the legacy flag
// still works and that the notice reaches the error stream, never the command
// output a script parses.
func TestNewCommandAddWarnsAboutDeprecatedPassword(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	configPath := writeInstanceConfig(t)
	useConfigFile(t, configPath)

	run := runInstanceCommand(t, []string{
		InstanceAddName,
		instanceCommandAlphaName,
		InstanceAddedHost,
		"--" + InstancePasswordFlagName, InstanceAddedPassword,
	})

	require.NoError(t, run.err)
	assert.Equal(t, "Instance \""+instanceCommandAlphaName+"\" added\n", run.out)
	assert.NotContains(t, run.out, InstanceAddedPassword)
	assert.Contains(t, run.errOut, InstanceDeprecationMarker)
	assert.Contains(t, run.errOut, InstanceDeprecationReplacement)
	assert.NotContains(t, run.errOut, InstanceAddedPassword)
}

// TestNewCommandAddOmitsNoticeWithoutPassword verifies that the deprecation
// notice is silent for the supported workflow.
func TestNewCommandAddOmitsNoticeWithoutPassword(t *testing.T) {
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
	assert.Empty(t, run.errOut)
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
