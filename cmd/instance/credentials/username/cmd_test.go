// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// fakeCoordinator records the username requests and returns the configured
// outcomes.
type fakeCoordinator struct {
	// setResult is the outcome returned by SetUsername.
	setResult app.UsernameResult
	// setErr is the error returned by SetUsername.
	setErr error
	// clearResult is the outcome returned by ClearUsername.
	clearResult app.UsernameResult
	// clearErr is the error returned by ClearUsername.
	clearErr error
	// report is the outcome returned by StatusUsername.
	report app.UsernameReport
	// statusErr is the error returned by StatusUsername.
	statusErr error
	// name records the instance name handed to a use case.
	name string
	// names records the instance names handed to StatusUsername.
	names []string
	// username records the username handed to SetUsername.
	username string
	// sets counts the SetUsername calls made by the command.
	sets int
	// clears counts the ClearUsername calls made by the command.
	clears int
}

// commandRun captures the rendered result of one command execution.
type commandRun struct {
	// out is the command output stream.
	out string
	// errOut is the command error stream.
	errOut string
	// err is the execution error.
	err error
}

// usernameCommandName is the published name of the username command.
const usernameCommandName = "username"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testUsername is the administrator username used by the command tests.
const testUsername = "admin"

// errTestFactory is the coordinator construction failure the command tests inject.
var errTestFactory = errors.New("no configuration file")

// ClearUsername records the request and returns the configured outcome.
func (f *fakeCoordinator) ClearUsername(name string) (app.UsernameResult, error) {
	f.clears++

	f.name = name

	return f.clearResult, f.clearErr
}

// SetUsername records the request and returns the configured outcome.
func (f *fakeCoordinator) SetUsername(
	name, username string,
) (app.UsernameResult, error) {
	f.sets++

	f.name = name

	f.username = username

	return f.setResult, f.setErr
}

// StatusUsername records the request and returns the configured outcome.
func (f *fakeCoordinator) StatusUsername(names []string) (app.UsernameReport, error) {
	f.names = names

	return f.report, f.statusErr
}

// testStreams builds input seams over an injected coordinator.
//
// The username commands never read a secret, so the seams carry no terminal
// reader. The field stays present so the tree matches the production shape.
//
// Parameters:
//   - store: coordinator returned by the command.
//
// Returns:
//   - *streams: test dependencies for the username commands.
func testStreams(store coordinator) *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return store, nil
		},
	}
}

// runUsername executes one freshly constructed username command tree.
//
// Parameters:
//   - t: active test requiring command construction.
//   - s: input seams and username coordinator factory.
//   - args: command line arguments passed to the username command.
//
// Returns:
//   - commandRun: the rendered output streams and the execution error.
func runUsername(t *testing.T, s *streams, args ...string) commandRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := newCommandGroup(s)
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetIn(strings.NewReader(""))
	command.SetArgs(args)

	err := command.Execute()

	return commandRun{
		out:    output.String(),
		errOut: errorsOut.String(),
		err:    err,
	}
}

// requireLeaf resolves one subcommand of the username group.
//
// Parameters:
//   - t: active test requiring command resolution.
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

	first := NewCommand()
	second := NewCommand()

	assert.NotSame(t, first, second)
	assert.NotSame(t, requireLeaf(t, first, setCommandName),
		requireLeaf(t, second, setCommandName))
}

// TestSetPublishesNoPasswordFlag verifies the username group offers no secret
// input, because a username is configuration rather than a secret.
func TestSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	set := requireLeaf(t, NewCommand(), setCommandName)

	assert.Nil(t, set.Flags().Lookup("password"))
	assert.Nil(t, set.Flags().Lookup("p"))
}

// TestStatusMachineReadableFlagIsBound verifies the machine-readable report flag
// is published.
func TestStatusMachineReadableFlagIsBound(t *testing.T) {
	t.Parallel()

	status := requireLeaf(t, NewCommand(), statusCommandName)

	flag := status.Flags().Lookup(jsonFlagName)
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

// TestNewCommandRejectsProductionConfigurationError verifies a coordinator
// failure names the failing step.
func TestNewCommandRejectsProductionConfigurationError(t *testing.T) {
	t.Parallel()

	group := newCommandGroup(&streams{
		coordinator: func() (coordinator, error) {
			return nil, errTestFactory
		},
	})

	group.SetOut(io.Discard)
	group.SetErr(io.Discard)
	group.SetArgs([]string{statusCommandName})

	err := group.Execute()

	require.ErrorIs(t, err, errTestFactory)
	assert.Contains(t, err.Error(), "build credential coordinator")
}

// TestRunSetRecordsUsername verifies the command hands the instance name and the
// username to the coordinator unchanged, and confirms the result.
func TestRunSetRecordsUsername(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	run := runUsername(t, testStreams(store), setCommandName, testInstanceName, testUsername)

	require.NoError(t, run.err)
	assert.Equal(t, 1, store.sets)
	assert.Equal(t, testInstanceName, store.name)
	assert.Equal(t, testUsername, store.username)
	assert.Contains(t, run.out, testInstanceName)
	assert.Contains(t, run.out, testUsername)
}

// TestRunSetRequiresInstanceAndUsername verifies the published argument arity.
func TestRunSetRequiresInstanceAndUsername(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	run := runUsername(t, testStreams(store), setCommandName)

	require.Error(t, run.err)
	assert.Equal(t, 0, store.sets)
}

// TestRunSetReportsCoordinatorFailure verifies a refused change surfaces as an
// error and prints no confirmation.
func TestRunSetReportsCoordinatorFailure(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{setErr: errTestFactory}
	run := runUsername(t, testStreams(store), setCommandName, testInstanceName, testUsername)

	require.ErrorIs(t, run.err, errTestFactory)
	assert.NotContains(t, run.out, "Username for instance")
}

// TestRunClearRemovesUsername verifies the command confirms the removal.
func TestRunClearRemovesUsername(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	run := runUsername(t, testStreams(store), clearCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Equal(t, 1, store.clears)
	assert.Equal(t, testInstanceName, store.name)
	assert.Contains(t, run.out, "cleared")
}

// TestRunClearRequiresInstance verifies the published argument arity.
func TestRunClearRequiresInstance(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	run := runUsername(t, testStreams(store), clearCommandName)

	require.Error(t, run.err)
	assert.Equal(t, 0, store.clears)
}

// TestRunClearReportsCoordinatorFailure verifies a refused clear surfaces as an
// error and prints no confirmation.
func TestRunClearReportsCoordinatorFailure(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{clearErr: errTestFactory}
	run := runUsername(t, testStreams(store), clearCommandName, testInstanceName)

	require.ErrorIs(t, run.err, errTestFactory)
	assert.NotContains(t, run.out, "cleared")
}

// TestRunStatusReportsUsernameInText verifies the text report names the configured
// username, so an operator can confirm which identity is configured.
func TestRunStatusReportsUsernameInText(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.UsernameReport{
			Instances: []app.UsernameStatus{
				{Instance: testInstanceName, Username: testUsername},
			},
		},
	}

	run := runUsername(t, testStreams(store), statusCommandName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, testInstanceName)
	assert.Contains(t, run.out, testUsername)
}

// TestRunStatusLabelsUnsetUsername verifies an instance without a username is
// labeled, so an empty value is not mistaken for a configured identity.
func TestRunStatusLabelsUnsetUsername(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.UsernameReport{
			Instances: []app.UsernameStatus{
				{Instance: testInstanceName, Username: ""},
			},
		},
	}

	run := runUsername(t, testStreams(store), statusCommandName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, unsetLabel)
}

// TestRunStatusReportsUsernameInJSON verifies the machine-readable report carries
// the username.
func TestRunStatusReportsUsernameInJSON(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.UsernameReport{
			Instances: []app.UsernameStatus{
				{Instance: testInstanceName, Username: testUsername},
			},
		},
	}

	run := runUsername(t, testStreams(store), statusCommandName, "--"+jsonFlagName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, "\"username\": \""+testUsername+"\"")
}

// TestRunStatusOmitsUnsetUsernameFromJSON verifies the machine-readable report
// omits an unconfigured username.
func TestRunStatusOmitsUnsetUsernameFromJSON(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.UsernameReport{
			Instances: []app.UsernameStatus{
				{Instance: testInstanceName, Username: ""},
			},
		},
	}

	run := runUsername(t, testStreams(store), statusCommandName, "--"+jsonFlagName)

	require.NoError(t, run.err)
	assert.NotContains(t, run.out, "username")
}

// TestRunStatusSelectsNamedInstance verifies a single instance is inspected by
// name, and that no argument reports every instance.
func TestRunStatusSelectsNamedInstance(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store)

	run := runUsername(t, seams, statusCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Equal(t, []string{testInstanceName}, store.names)

	run = runUsername(t, seams, statusCommandName)

	require.NoError(t, run.err)
	assert.Empty(t, store.names)
}

// TestRunStatusForwardsCoordinatorFailure verifies an unknown instance reaches the
// operator.
func TestRunStatusForwardsCoordinatorFailure(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{statusErr: errTestFactory}
	run := runUsername(t, testStreams(store), statusCommandName, "absent")

	require.ErrorIs(t, run.err, errTestFactory)
	assert.Contains(t, run.err.Error(), "report username status")
}

// TestRunStatusRejectsExtraArguments verifies the published argument arity.
func TestRunStatusRejectsExtraArguments(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	run := runUsername(t, testStreams(store), statusCommandName, "one", "two")

	require.Error(t, run.err)
	assert.Empty(t, store.names)
}
