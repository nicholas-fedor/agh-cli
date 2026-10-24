// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	mockCredentials "github.com/nicholas-fedor/agh-cli/internal/credentials/mocks"
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

// terminalInput is command input that acts as a terminal.
//
// Its reader supplies the confirmation answer, and its hidden line is what the
// hidden password prompt reads.
type terminalInput struct {
	// Reader supplies the confirmation answer.
	io.Reader

	// hidden is the line the hidden prompt reads.
	hidden string
}

// passwordCommandName is the published name of the password command.
const passwordCommandName = "password"

// setCommandName is the published name of the set subcommand.
const setCommandName = "set"

// clearCommandName is the published name of the clear subcommand.
const clearCommandName = "clear"

// statusCommandName is the published name of the status subcommand.
const statusCommandName = "status"

// allFlagName is the published name of the service-wide selection flag.
const allFlagName = "all"

// jsonFlagName is the published name of the machine-readable report flag.
const jsonFlagName = "json"

// keyFlagName is the published name of the credential key override flag.
const keyFlagName = "key"

// yesFlagName is the published name of the confirmation skip flag.
const yesFlagName = "yes"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testSecret is the password used by the command tests.
const testSecret = "s3cr3t-adguard-password"

// keyringDocument configures one instance whose password lives in the store.
const keyringDocument = "instances:\n" +
	"  default:\n" +
	"    host: adguard.example\n" +
	"    credential:\n" +
	"      source: keyring\n" +
	"      key: default\n"

// legacyDocument configures one instance that declares no credential source.
const legacyDocument = "instances:\n" +
	"  default:\n" +
	"    host: adguard.example\n"

// envDocument configures one instance whose password lives in the environment.
const envDocument = "instances:\n" +
	"  default:\n" +
	"    host: adguard.example\n" +
	"    credential:\n" +
	"      source: env\n" +
	"      env: ADGUARD_PASSWORD\n"

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
	assert.NotSame(t, requireLeaf(t, first, setCommandName), requireLeaf(t, second, setCommandName))
}

// TestSetPublishesNoPasswordFlag verifies that a secret can never be passed as
// an argument, where it would reach shell history and process listings.
func TestSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	set := requireLeaf(t, NewCommand(), setCommandName)

	assert.Nil(t, set.Flags().Lookup("password"))
	assert.Nil(t, set.Flags().ShorthandLookup("p"))
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

// TestNewCommandRequiresLoadedConfiguration verifies that a command run without
// a loaded configuration fails before any credential store is built or read.
func TestNewCommandRequiresLoadedConfiguration(t *testing.T) {
	t.Parallel()

	run := runPassword(t.Context(), t, nil, statusCommandName)

	require.ErrorIs(t, run.err, app.ErrNoRunConfig)
}

// storeContext returns a command context carrying the document and a store that
// expects only the calls a test configures.
//
// Parameters:
//   - document: complete configuration document.
//
// Returns:
//   - [context.Context]: context carrying the configuration and the store.
//   - *mockCredentials.MockStore: the store, ready for expectations.
func storeContext(t *testing.T, document string) (context.Context, *mockCredentials.MockStore) {
	t.Helper()

	store := mockCredentials.NewMockStore(t)
	store.EXPECT().Backend().Return(credentials.KeyringBackend).Maybe()

	return apptest.StoreContext(t, document, store), store
}

// runPassword executes one freshly constructed password command tree.
//
// Parameters:
//   - ctx: context carrying the configuration and the credential store.
//   - input: standard input supplied to the command, or nil for none.
//   - args: command line arguments passed to the password command.
//
// Returns:
//   - commandRun: the rendered output streams and the execution error.
//
//nolint:contextcheck // The command reads the context passed to ExecuteContext.
func runPassword(ctx context.Context, t *testing.T, input io.Reader, args ...string) commandRun {
	t.Helper()

	if input == nil {
		input = &bytes.Buffer{}
	}

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := NewCommand()
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetIn(input)
	command.SetArgs(args)

	err := command.ExecuteContext(ctx)

	return commandRun{err: err, out: output.String(), errOut: errorsOut.String()}
}

// requireLeaf resolves one subcommand of the password group.
//
// Parameters:
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

// expectStoredAbsent configures the store to report no credential under key.
//
// Parameters:
//   - store: store receiving the expectation.
//   - key: credential key that holds nothing.
func expectStoredAbsent(store *mockCredentials.MockStore, key string) {
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, key).Return("", credentials.ErrNotFound).Once()
}

// IsTerminal reports that the input is a terminal.
//
// Returns:
//   - bool: always true.
func (terminalInput) IsTerminal() bool {
	return true
}

// ReadHidden returns the configured hidden line.
//
// Returns:
//   - []byte: the configured hidden line.
//   - error: always nil.
func (i terminalInput) ReadHidden() ([]byte, error) {
	return []byte(i.hidden), nil
}
