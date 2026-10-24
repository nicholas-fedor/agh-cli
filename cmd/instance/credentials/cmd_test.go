// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// fakeCoordinator records the migration request and returns the configured
// commandRun captures the rendered result of one command execution.
type commandRun struct {
	// out is the command output stream.
	out string
	// errOut is the command error stream.
	errOut string
	// err is the execution error.
	err error
}

// credentialsCommandName is the published name of the credentials command.
const credentialsCommandName = "credentials"

// migrateCommandName is the published name of the migrate subcommand.
const migrateCommandName = "migrate"

// dryRunFlagName is the published name of the migration preview flag.
const dryRunFlagName = "dry-run"

// usernameCommandName is the published name of the username subcommand group.
const usernameCommandName = "username"

// passwordCommandName is the published name of the password subcommand group.
const passwordCommandName = "password"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testSecret is the password used by the command tests.
const testSecret = "s3cr3t-adguard-password"

// testKeyringKey is the credential key used by the command tests.
const testKeyringKey = "default"

// runCredentials executes one freshly constructed credentials command tree.
//
// Parameters:
//   - ctx: context carrying the configuration and the credential store.
//   - args: command line arguments passed to the credentials command.
//
// Returns:
//   - commandRun: the rendered output streams and the execution error.
//
//nolint:contextcheck // The command reads the context passed to ExecuteContext.
func runCredentials(ctx context.Context, t *testing.T, args ...string) commandRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := NewCommand()
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetArgs(args)

	err := command.ExecuteContext(ctx)

	return commandRun{out: output.String(), errOut: errorsOut.String(), err: err}
}

// requireLeaf resolves one subcommand of the credentials group.
//
// Parameters:
//   - t: active test requiring command resolution.
//   - group: credentials command owning the subcommand.
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

// TestNewCommandPreservesGroupSyntax verifies the published CLI surface of the
// credentials command group.
func TestNewCommandPreservesGroupSyntax(t *testing.T) {
	t.Parallel()

	group := NewCommand()

	assert.Equal(t, credentialsCommandName, group.Use)
	assert.Equal(t, "Manage instance authentication", group.Short)

	migrate := requireLeaf(t, group, migrateCommandName)
	assert.Equal(t, "migrate", migrate.Use)

	assert.Equal(t, "username", requireLeaf(t, group, usernameCommandName).Use)
	assert.Equal(t, "password", requireLeaf(t, group, passwordCommandName).Use)
}

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := NewCommand()
	second := NewCommand()

	assert.NotSame(t, first, second)
	assert.NotSame(t, requireLeaf(t, first, migrateCommandName),
		requireLeaf(t, second, migrateCommandName))
}

// TestMigrateDryRunFlagIsBound verifies the migration preview flag is published.
func TestMigrateDryRunFlagIsBound(t *testing.T) {
	t.Parallel()

	migrate := requireLeaf(t, NewCommand(), migrateCommandName)

	flag := migrate.Flags().Lookup(dryRunFlagName)
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

// TestNewCommandRequiresLoadedConfiguration verifies that a migration run
// without a loaded configuration fails.
func TestNewCommandRequiresLoadedConfiguration(t *testing.T) {
	t.Parallel()

	run := runCredentials(t.Context(), t, migrateCommandName, "--"+dryRunFlagName)

	require.ErrorIs(t, run.err, app.ErrNoRunConfig)
}
