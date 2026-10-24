// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
)

// commandRun captures the rendered result of one command execution.
type commandRun struct {
	// err is the execution error.
	err error
	// out is the command output stream.
	out string
	// errOut is the command error stream.
	errOut string
}

// usernameCommandName is the published name of the username command.
const usernameCommandName = "username"

// setCommandName is the published name of the set subcommand.
const setCommandName = "set"

// statusCommandName is the published name of the status subcommand.
const statusCommandName = "status"

// clearCommandName is the published name of the clear subcommand.
const clearCommandName = "clear"

// jsonFlagName is the published name of the machine-readable report flag.
const jsonFlagName = "json"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testUsername is the administrator username used by the command tests.
const testUsername = "admin"

// usernameDocument configures one instance with a username and one without.
const usernameDocument = "instances:\n" +
	"  default:\n" +
	"    host: a.example\n" +
	"    username: " + testUsername + "\n" +
	"  spare:\n" +
	"    host: b.example\n"

// TestNewCommandPreservesLeafSyntax verifies the published CLI surface of the
// username command group.
func TestNewCommandPreservesLeafSyntax(t *testing.T) {
	t.Parallel()

	group := NewCommand()

	assert.Equal(t, usernameCommandName, group.Use)
	assert.Equal(t, "Manage the administrator username of an instance", group.Short)

	expected := map[string]string{
		setCommandName:    "set <instance> <username>",
		statusCommandName: "status [instance]",
		clearCommandName:  "clear <instance>",
	}

	for name, use := range expected {
		assert.Equal(t, use, requireLeaf(t, group, name).Use)
	}
}

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := requireLeaf(t, NewCommand(), setCommandName)
	second := requireLeaf(t, NewCommand(), setCommandName)

	assert.NotSame(t, first, second)
}

// TestSetPublishesNoPasswordFlag verifies the username group offers no secret
// input, because a username is configuration rather than a secret.
func TestSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	set := requireLeaf(t, NewCommand(), setCommandName)

	assert.Nil(t, set.Flags().Lookup("password"))
	assert.Nil(t, set.Flags().ShorthandLookup("p"))
}

// TestNewCommandRequiresLoadedConfiguration verifies that a command run without
// a loaded configuration fails.
func TestNewCommandRequiresLoadedConfiguration(t *testing.T) {
	t.Parallel()

	run := runUsername(t.Context(), t, statusCommandName)

	require.ErrorIs(t, run.err, app.ErrNoRunConfig)
}

// TestRunSetRecordsUsername verifies that the username is written to the
// configuration file and reported. The username never reaches the store.
func TestRunSetRecordsUsername(t *testing.T) {
	t.Parallel()

	ctx, path := fileContext(t)

	run := runUsername(ctx, t, setCommandName, "spare", "operator")

	require.NoError(t, run.err)
	assert.Equal(t, "Username for instance \"spare\" set to \"operator\".\n", run.out)
	assert.Contains(t, readFile(t, path), "username: operator")
}

// TestRunSetRejectsUnknownInstance verifies that an unknown instance is named.
func TestRunSetRejectsUnknownInstance(t *testing.T) {
	t.Parallel()

	ctx, _ := fileContext(t)

	run := runUsername(ctx, t, setCommandName, "nope", "operator")

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), `set username for "nope"`)
	assert.NotContains(t, run.out, "set to")
}

// TestRunClearRemovesUsername verifies that the username is removed from the
// configuration file and reported.
func TestRunClearRemovesUsername(t *testing.T) {
	t.Parallel()

	ctx, path := fileContext(t)

	run := runUsername(ctx, t, clearCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Equal(t, "Username for instance \"default\" cleared.\n", run.out)
	assert.NotContains(t, readFile(t, path), "username:")
}

// TestRunStatusReportsUsernames verifies the text report over every instance.
func TestRunStatusReportsUsernames(t *testing.T) {
	t.Parallel()

	ctx, _ := fileContext(t)

	run := runUsername(ctx, t, statusCommandName)

	require.NoError(t, run.err)
	assert.Equal(t, "instance \"default\": username \"admin\"\ninstance \"spare\": (unset)\n", run.out)
}

// TestRunStatusReportsUsernamesInJSON verifies that --json selects the
// machine-readable report for a named instance.
func TestRunStatusReportsUsernamesInJSON(t *testing.T) {
	t.Parallel()

	ctx, _ := fileContext(t)

	run := runUsername(ctx, t, statusCommandName, testInstanceName, "--"+jsonFlagName)

	require.NoError(t, run.err)

	var report map[string][]map[string]string

	require.NoError(t, json.Unmarshal([]byte(run.out), &report))
	assert.Equal(t, []map[string]string{{"instance": testInstanceName, "username": testUsername}}, report["instances"])
}

// TestRunCommandsRejectWrongArity verifies the published argument arity of every
// leaf.
func TestRunCommandsRejectWrongArity(t *testing.T) {
	t.Parallel()

	for name, args := range map[string][]string{
		"set without username": {setCommandName, testInstanceName},
		"clear without name":   {clearCommandName},
		"status with two":      {statusCommandName, testInstanceName, "spare"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, _ := fileContext(t)

			require.Error(t, runUsername(ctx, t, args...).err)
		})
	}
}

// fileContext writes the username document and returns a context carrying it.
//
// Returns:
//   - [context.Context]: context carrying the configuration and a store that
//     fails the test on any call.
//   - string: path of the configuration file.
func fileContext(t *testing.T) (context.Context, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(usernameDocument), 0o600))

	return apptest.FileContext(t, path), path
}

// readFile returns the content of a file.
//
// Parameters:
//   - path: file to read.
//
// Returns:
//   - string: the file content.
func readFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return string(data)
}

// runUsername executes one freshly constructed username command tree.
//
// Parameters:
//   - ctx: context carrying the configuration and the credential store.
//   - args: command line arguments passed to the username command.
//
// Returns:
//   - commandRun: the rendered output streams and the execution error.
//
//nolint:contextcheck // The command reads the context passed to ExecuteContext.
func runUsername(ctx context.Context, t *testing.T, args ...string) commandRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := NewCommand()
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetArgs(args)

	err := command.ExecuteContext(ctx)

	return commandRun{err: err, out: output.String(), errOut: errorsOut.String()}
}

// requireLeaf resolves one subcommand of the username group.
//
// Parameters:
//   - group: username command owning the subcommand.
//   - name: subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The resolved subcommand.
func requireLeaf(t *testing.T, group *cobra.Command, name string) *cobra.Command {
	t.Helper()

	command, _, err := group.Find([]string{name})
	require.NoError(t, err)
	require.Equal(t, name, command.Name())

	return command
}
