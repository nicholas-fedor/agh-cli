// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// fakeCoordinator records the password requests and returns the configured
// outcomes.
type fakeCoordinator struct {
	// setResult is the outcome returned by SetPassword.
	setResult app.PasswordSetResult
	// setErr is the error returned by SetPassword.
	setErr error
	// clearResult is the outcome returned by ClearPassword and
	// ClearAllPasswords.
	clearResult app.PasswordClearResult
	// clearErr is the error returned by ClearPassword.
	clearErr error
	// clearAllResult is the outcome returned by ClearAllPasswords.
	clearAllResult app.PasswordClearResult
	// clearAllErr is the error returned by ClearAllPasswords.
	clearAllErr error
	// passwordReport is the outcome returned by StatusPassword.
	passwordReport app.PasswordReport
	// statusErr is the error returned by StatusPassword.
	statusErr error
	// secret records the secret handed to SetPassword.
	secret string
	// key records the credential key handed to SetPassword.
	key string
	// name records the instance name handed to a use case.
	name string
	// names records the instance names handed to StatusPassword.
	names []string
	// clears counts the ClearPassword calls made by the command.
	clears int
	// clearAlls counts the ClearAllPasswords calls made by the command.
	clearAlls int
	// sets counts the SetPassword calls made by the command.
	sets int
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

// passwordCommandName is the published name of the password command.
const passwordCommandName = "password"

// setCommandName is the published name of the set subcommand.
const setCommandName = "set"

// clearCommandName is the published name of the clear subcommand.
const clearCommandName = "clear"

// statusCommandName is the published name of the status subcommand.
const statusCommandName = "status"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testSecret is the password used by the command tests.
const testSecret = "s3cr3t-adguard-password"

// testService is the credential store namespace used by the command tests.
const testService = "agh-cli"

// testKeyringKey is the credential key used by the command tests.
const testKeyringKey = "default"

// testBackend is the credential store backend name used by the command tests.
const testBackend = "keyring"

// testCredentialFile is the mounted-secret path used by the command tests.
const testCredentialFile = "/run/secrets/adguard"

// testCredentialEnv is the environment variable name used by the command tests.
const testCredentialEnv = "ADGUARD_PASSWORD"

// errTestFactory is the coordinator construction failure the command tests inject.
var errTestFactory = errors.New("no configuration file")

// ClearAllPasswords records the request and returns the configured outcome.
func (f *fakeCoordinator) ClearAllPasswords(
	_ context.Context,
) (app.PasswordClearResult, error) {
	f.clearAlls++

	return f.clearAllResult, f.clearAllErr
}

// ClearPassword records the request and returns the configured outcome.
func (f *fakeCoordinator) ClearPassword(
	_ context.Context,
	name string,
) (app.PasswordClearResult, error) {
	f.clears++

	f.name = name

	return f.clearResult, f.clearErr
}

// SetPassword records the request, including the secret, and returns the
// configured outcome.
func (f *fakeCoordinator) SetPassword(
	_ context.Context,
	name, key, secret string,
) (app.PasswordSetResult, error) {
	f.sets++

	f.name = name

	f.key = key

	f.secret = secret

	return f.setResult, f.setErr
}

// StatusPassword records the request and returns the configured outcome.
func (f *fakeCoordinator) StatusPassword(
	_ context.Context,
	names []string,
) (app.PasswordReport, error) {
	f.names = names

	return f.passwordReport, f.statusErr
}

// testStreams builds input seams over an injected coordinator.
//
// The terminal probe and the hidden reader are fakes, so the tests exercise both
// input shapes without a controlling terminal.
//
// Parameters:
//   - store: coordinator returned by the command.
//   - terminal: reports whether the command input is a terminal.
//   - secret: secret returned by the hidden reader.
//
// Returns:
//   - *streams: test dependencies for the password commands.
func testStreams(store coordinator, terminal bool, secret string) *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return store, nil
		},
		isTerminal: func(io.Reader) bool {
			return terminal
		},
		readPassword: func(io.Reader) ([]byte, error) {
			return []byte(secret), nil
		},
	}
}

// runPassword executes one freshly constructed password command tree.
//
// Parameters:
//   - t: active test requiring command construction.
//   - s: input seams and password coordinator factory.
//   - input: standard input supplied to the command.
//   - args: command line arguments passed to the password command.
//
// Returns:
//   - commandRun: the rendered output streams and the execution error.
func runPassword(
	t *testing.T,
	s *streams,
	input string,
	args ...string,
) commandRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := newCommandGroup(s)
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetIn(strings.NewReader(input))
	command.SetArgs(args)

	err := command.Execute()

	return commandRun{
		out:    output.String(),
		errOut: errorsOut.String(),
		err:    err,
	}
}

// requireLeaf resolves one subcommand of the password group.
//
// Parameters:
//   - t: active test requiring command resolution.
//   - group: password command owning the subcommand.
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
// password command group.
func TestNewCommandPreservesLeafSyntax(t *testing.T) {
	t.Parallel()

	group := NewCommand()

	assert.Equal(t, passwordCommandName, group.Use)
	assert.Equal(t, "Manage the stored password of an instance", group.Short)

	expected := map[string]string{
		setCommandName:    "set <instance>",
		clearCommandName:  "clear <instance>",
		statusCommandName: "status [instance]",
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

// TestSetPublishesNoPasswordFlag verifies that a secret can never reach the
// command output a script parses.
func TestSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	set := requireLeaf(t, NewCommand(), setCommandName)

	assert.Nil(t, set.Flags().Lookup("password"))
	assert.Nil(t, set.Flags().Lookup("p"))
}

// TestSetFlagShorthandMatchesDocumentation verifies the documented shorthand.
func TestSetFlagShorthandMatchesDocumentation(t *testing.T) {
	t.Parallel()

	set := requireLeaf(t, NewCommand(), setCommandName)

	yes := set.Flags().Lookup(yesFlagName)
	require.NotNil(t, yes)
	assert.Equal(t, "y", yes.Shorthand)

	key := set.Flags().Lookup(keyFlagName)
	require.NotNil(t, key)
	assert.Empty(t, key.Shorthand)
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

	group.SetOut(&bytes.Buffer{})
	group.SetErr(&bytes.Buffer{})
	group.SetArgs([]string{statusCommandName})

	err := group.Execute()

	require.ErrorIs(t, err, errTestFactory)
	assert.Contains(t, err.Error(), "build credential coordinator")
}
