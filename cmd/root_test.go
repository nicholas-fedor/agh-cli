// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

const (
	// RootConfigFlagName names the persistent configuration flag.
	RootConfigFlagName = "config"
	// RootConfigFlagShorthand is the published configuration flag shorthand.
	RootConfigFlagShorthand = "c"
	// RootContextProbeName identifies the context probe subcommand.
	RootContextProbeName = "context-probe"
	// RootVersionName identifies the version subcommand.
	RootVersionName = "version"
	// RootInstanceName identifies the instance subcommand.
	RootInstanceName = "instance"
	// RootInstanceAddName identifies the instance add subcommand.
	RootInstanceAddName = "add"
	// RootUsernameFlagName names the username flag of instance add.
	RootUsernameFlagName = "username"
	// RootAddUsername is the username passed to instance add.
	RootAddUsername = "admin"
	// RootUserConfigHomeEnv supplies the per-user configuration root when the
	// dedicated variable is absent.
	RootUserConfigHomeEnv = "HOME"
	// RootUserConfigDirEnv selects the per-user configuration root on Unix.
	RootUserConfigDirEnv = "XDG_CONFIG_HOME"
	// RootConfigDirMode is the permission mode of a created per-user
	// configuration directory.
	RootConfigDirMode = 0o700
	// RootRepeatedExecutions counts repeated root command executions.
	RootRepeatedExecutions = 2
	// RootConfigInstanceName identifies the configured instance in test data.
	RootConfigInstanceName = "test"
	// RootConfigHost identifies the configured host in test data.
	RootConfigHost = "127.0.0.1"
	// RootConfigScheme identifies the configured scheme in test data.
	RootConfigScheme = "https"
	// RootValidConfigFileName names the valid configuration file.
	RootValidConfigFileName = "custom.yaml"
	// RootMalformedConfigFileName names the malformed configuration file.
	RootMalformedConfigFileName = "invalid.yaml"
	// RootMalformedConfigContents is the unreadable configuration payload.
	RootMalformedConfigContents = "instances: ["
	// RootUsage is the published root invocation syntax.
	RootUsage = "agh-cli"
	// RootShort is the published root description.
	RootShort = "CLI for managing multiple AdGuard Home instances"
	// RootLong is the published root long description.
	RootLong = "A Go CLI that provides CRUD operations for interacting with " +
		"multiple AdGuard Home instances simultaneously."
)

// TestRootCommandPrefersUserConfigOverWorkingDirectory verifies the per-user
// configuration outranks one in the current directory, so a command launched
// from the home directory cannot silently shadow the configuration the
// quickstart created.
func TestRootCommandPrefersUserConfigOverWorkingDirectory(t *testing.T) {
	workingDirectory := t.TempDir()
	configRoot := t.TempDir()

	t.Chdir(workingDirectory)
	t.Setenv(RootUserConfigHomeEnv, configRoot)
	t.Setenv(RootUserConfigDirEnv, configRoot)

	userDirectory := filepath.Join(configRoot, app.DefaultConfigDirName)
	require.NoError(t, os.Mkdir(userDirectory, RootConfigDirMode))

	userConfig := writeRootConfigFile(
		t,
		userDirectory,
		app.DefaultConfigFileName,
	)
	writeRootConfigFile(t, workingDirectory, app.DefaultConfigFileName)

	resetRootConfigState(t)

	command := newRootCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{RootVersionName})

	require.NoError(t, command.ExecuteContext(t.Context()))
	assert.Equal(t, userConfig, viper.ConfigFileUsed())
}

// TestRootCommandWritesFirstConfigToUserDirectory verifies the first write of a
// fresh install creates the per-user configuration file, because the current
// directory is not a configuration location the quickstart documents.
func TestRootCommandWritesFirstConfigToUserDirectory(t *testing.T) {
	workingDirectory := t.TempDir()
	configRoot := t.TempDir()

	t.Chdir(workingDirectory)
	t.Setenv(RootUserConfigHomeEnv, configRoot)
	t.Setenv(RootUserConfigDirEnv, configRoot)

	resetRootConfigState(t)

	command := newRootCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{
		RootInstanceName, RootInstanceAddName,
		RootConfigInstanceName, RootConfigHost,
		"--" + RootUsernameFlagName, RootAddUsername,
	})

	require.NoError(t, command.ExecuteContext(t.Context()))

	userConfig := filepath.Join(
		configRoot,
		app.DefaultConfigDirName,
		app.DefaultConfigFileName,
	)

	assert.FileExists(t, userConfig)
	assert.NoFileExists(t, filepath.Join(workingDirectory, app.DefaultConfigFileName))
	assert.Contains(t, readRootConfigFile(t, userConfig), RootConfigHost)
}

// TestRootCommandHonorsConfigFlag verifies that --config selects the requested file.
func TestRootCommandHonorsConfigFlag(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	configPath := writeRootConfigFile(t, workingDirectory, RootValidConfigFileName)

	resetRootConfigState(t)

	command := newRootCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--" + RootConfigFlagName, configPath, RootVersionName})

	require.NoError(t, command.ExecuteContext(t.Context()))
	assert.Equal(t, configPath, viper.ConfigFileUsed())
}

// TestRootCommandRejectsMalformedConfig verifies that an explicit invalid file
// stops execution.
func TestRootCommandRejectsMalformedConfig(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	configPath := writeRootMalformedConfig(t, workingDirectory)

	resetRootConfigState(t)

	command := newRootCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--" + RootConfigFlagName, configPath, RootVersionName})

	err := command.ExecuteContext(t.Context())
	require.Error(t, err)
	assert.ErrorContains(t, err, "read config")
}

// TestExecuteContextWrapsExecutionFailure verifies that the public entry point
// builds a fresh root command and wraps its execution failure.
func TestExecuteContextWrapsExecutionFailure(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	configPath := writeRootMalformedConfig(t, workingDirectory)

	resetRootConfigState(t)
	setRootProcessArgs(t, "--"+RootConfigFlagName, configPath, RootVersionName)

	err := ExecuteContext(t.Context())
	require.Error(t, err)
	require.ErrorContains(t, err, "execute root command")
	require.ErrorContains(t, err, "read config")
}

// TestExecuteWrapsExecutionFailure verifies that the background-context entry
// point builds a fresh root command and wraps its execution failure.
func TestExecuteWrapsExecutionFailure(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	configPath := writeRootMalformedConfig(t, workingDirectory)

	resetRootConfigState(t)
	setRootProcessArgs(t, "--"+RootConfigFlagName, configPath, RootVersionName)

	err := Execute()
	require.Error(t, err)
	require.ErrorContains(t, err, "execute root command")
	require.ErrorContains(t, err, "read config")
}

// TestExecuteContextPropagatesCancellation verifies that command handlers
// receive cancellation through a freshly constructed root command.
func TestExecuteContextPropagatesCancellation(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	resetRootConfigState(t)

	command := newRootCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.AddCommand(rootContextProbeCommand())
	command.SetArgs([]string{RootContextProbeName})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.ErrorIs(t, command.ExecuteContext(ctx), context.Canceled)
}

// TestNewRootCommandPreservesPublishedSyntax verifies the published root command
// surface, including its persistent flag and subcommand set.
func TestNewRootCommandPreservesPublishedSyntax(t *testing.T) {
	t.Parallel()

	command := newRootCommand()

	assert.Equal(t, RootUsage, command.Use)
	assert.Equal(t, RootShort, command.Short)
	assert.Equal(t, RootLong, command.Long)

	configFlag := command.PersistentFlags().Lookup(RootConfigFlagName)
	require.NotNil(t, configFlag)
	assert.Equal(t, RootConfigFlagShorthand, configFlag.Shorthand)
	assert.Empty(t, configFlag.DefValue)

	for _, name := range []string{
		"client", "filtering", RootInstanceName, "rewrite", RootVersionName,
	} {
		assert.Equal(t, name, requireRootSubcommand(t, command, name).Name())
	}
}

// TestNewRootCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct trees whose flag values never leak between executions.
func TestNewRootCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := newRootCommand()
	second := newRootCommand()

	require.NotSame(t, first, second)
	require.NotSame(
		t,
		requireRootSubcommand(t, first, RootInstanceName),
		requireRootSubcommand(t, second, RootInstanceName),
	)

	require.NoError(
		t,
		first.PersistentFlags().Set(RootConfigFlagName, "first.yaml"),
	)

	configValue, err := second.PersistentFlags().GetString(RootConfigFlagName)
	require.NoError(t, err)
	assert.Empty(t, configValue)
	assert.False(t, second.PersistentFlags().Changed(RootConfigFlagName))
}

// TestNewRootCommandRepeatedExecutionReadsConfigFlag verifies that repeatedly
// constructing and executing the root command re-registers its persistent flag
// without redefining it or reusing an earlier configuration path.
func TestNewRootCommandRepeatedExecutionReadsConfigFlag(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	configPath := writeRootConfigFile(t, workingDirectory, RootValidConfigFileName)

	resetRootConfigState(t)

	for range RootRepeatedExecutions {
		command := newRootCommand()
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{"--" + RootConfigFlagName, configPath, RootVersionName})

		require.NoError(t, command.ExecuteContext(t.Context()))
		assert.Equal(t, configPath, viper.ConfigFileUsed())
	}
}

// TestNewRootCommandRepeatedExecutionUsesFreshContext verifies that a later
// execution never observes a context left behind on an earlier tree.
func TestNewRootCommandRepeatedExecutionUsesFreshContext(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("HOME", workingDirectory)

	resetRootConfigState(t)

	observed := make([]error, 0, RootRepeatedExecutions)

	first := newRootCommand()
	first.SetOut(io.Discard)
	first.SetErr(io.Discard)
	recordRootContextObservation(first, &observed)
	first.SetArgs([]string{RootContextProbeName})

	cancelable, cancel := context.WithCancel(t.Context())
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := newRootCommand()
	second.SetOut(io.Discard)
	second.SetErr(io.Discard)
	recordRootContextObservation(second, &observed)
	second.SetArgs([]string{RootContextProbeName})

	require.NoError(t, second.Execute())

	require.Len(t, observed, RootRepeatedExecutions)
	assert.NoError(t, observed[0])
	assert.NoError(t, observed[1])
}

// resetRootConfigState isolates the process-global Viper state for one test.
//
// Parameters:
//   - t: active test requiring Viper isolation.
func resetRootConfigState(t *testing.T) {
	t.Helper()

	viper.Reset()

	t.Cleanup(viper.Reset)
}

// setRootProcessArgs replaces the process arguments observed by ExecuteContext.
//
// Parameters:
//   - t: active test requiring process argument isolation.
//   - args: arguments that follow the program name.
func setRootProcessArgs(t *testing.T, args ...string) {
	t.Helper()

	previous := os.Args

	os.Args = append([]string{RootUsage}, args...)

	t.Cleanup(func() {
		os.Args = previous
	})
}

// readRootConfigFile reads a written configuration file for a test.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - configPath: path of the configuration file to read.
//
// Returns:
//   - string: the configuration file contents.
func readRootConfigFile(t *testing.T, configPath string) string {
	t.Helper()

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	return string(data)
}

// writeRootConfigFile writes a minimal valid configuration file.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - directory: destination directory of the configuration file.
//   - name: configuration file name.
//
// Returns:
//   - string: path of the written configuration file.
func writeRootConfigFile(t *testing.T, directory, name string) string {
	t.Helper()

	contents := "instances:\n" +
		"  " + RootConfigInstanceName + ":\n" +
		"    host: " + RootConfigHost + "\n" +
		"    scheme: " + RootConfigScheme + "\n"

	configPath := filepath.Join(directory, name)
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))

	return configPath
}

// writeRootMalformedConfig writes an unreadable configuration file.
//
// Parameters:
//   - t: active test requiring the configuration file.
//   - directory: destination directory of the configuration file.
//
// Returns:
//   - string: path of the written configuration file.
func writeRootMalformedConfig(t *testing.T, directory string) string {
	t.Helper()

	configPath := filepath.Join(directory, RootMalformedConfigFileName)
	require.NoError(
		t,
		os.WriteFile(configPath, []byte(RootMalformedConfigContents), 0o600),
	)

	return configPath
}

// rootContextProbeCommand builds a probe subcommand failing with the context
// error observed during execution.
//
// Returns:
//   - *cobra.Command: The probe subcommand.
func rootContextProbeCommand() *cobra.Command {
	return &cobra.Command{
		Use: RootContextProbeName,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Context().Err()
		},
	}
}

// requireRootSubcommand resolves one subcommand of a constructed root command.
//
// Parameters:
//   - t: active test requiring command resolution.
//   - parent: command owning the subcommand.
//   - name: subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The resolved subcommand.
func requireRootSubcommand(
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

// recordRootContextObservation attaches a probe subcommand recording the context
// error observed during execution.
//
// Parameters:
//   - parent: command tree receiving the probe subcommand.
//   - observed: collects the context error reported by each probe execution.
func recordRootContextObservation(parent *cobra.Command, observed *[]error) {
	probeCommand := &cobra.Command{
		Use: RootContextProbeName,
		RunE: func(cmd *cobra.Command, _ []string) error {
			*observed = append(*observed, cmd.Context().Err())

			return nil
		},
	}

	parent.AddCommand(probeCommand)
}
