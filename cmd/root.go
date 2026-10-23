// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/cmd/client"
	"github.com/nicholas-fedor/agh-cli/cmd/filtering"
	"github.com/nicholas-fedor/agh-cli/cmd/instance"
	"github.com/nicholas-fedor/agh-cli/cmd/rewrite"
	"github.com/nicholas-fedor/agh-cli/cmd/version"
	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newRootCommand creates the root command with fresh subcommands and flags.
//
// The constructor is stored as a function value so that Execute and
// ExecuteContext build a new tree from one shared definition on every call. The
// configuration path is bound to the constructed command, so repeated
// construction never shares flag state between executions.
var newRootCommand = func() *cobra.Command {
	var cfgFile string

	rootCmd := &cobra.Command{
		Use:   "agh-cli",
		Short: "CLI for managing multiple AdGuard Home instances",
		Long: `A Go CLI that provides CRUD operations for interacting with
multiple AdGuard Home instances simultaneously.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return initConfig(cmd, cfgFile)
		},
	}

	rootCmd.PersistentFlags().StringVarP(
		&cfgFile,
		"config",
		"c",
		"",
		"Path to config file",
	)

	// Register subcommands.
	rootCmd.AddCommand(
		client.NewCommand(),
		filtering.NewCommand(),
		instance.NewCommand(),
		rewrite.NewCommand(),
		version.NewCommand(),
	)

	return rootCmd
}

// NewRootCommand creates a fresh root command tree for callers that need to
// inspect or document the CLI without executing it.
//
// Returns:
//   - *cobra.Command: a new root command with all subcommands and flags registered.
func NewRootCommand() *cobra.Command {
	return newRootCommand()
}

// Execute creates the root command and executes it.
//
// Returns:
//   - error: non-nil when the root command execution fails.
func Execute() error {
	err := newRootCommand().Execute()
	if err != nil {
		return fmt.Errorf("execute root command: %w", err)
	}

	return nil
}

// ExecuteContext creates the root command and executes it with context.
//
// Parameters:
//   - ctx: context controlling command execution.
//
// Returns:
//   - error: non-nil when the root command execution fails.
func ExecuteContext(ctx context.Context) error {
	err := newRootCommand().ExecuteContext(ctx)
	if err != nil {
		return fmt.Errorf("execute root command: %w", err)
	}

	return nil
}

// initConfig resolves and loads the configuration for the run, then attaches it
// to the command context.
//
// The configuration file is resolved and loaded once, here, so that every later
// read and every write of the run agree on one file. Resolution decides between
// an explicit path and the default search locations, and a blank document is
// treated as no configuration so the first write creates it.
//
// A file that cannot be read is fatal and names the path, because an operator
// must know which file failed. A file that does not exist and an instance that
// cannot be used are warnings, written to the command's error stream.
//
// Parameters:
//   - cmd: command being executed, whose context receives the configuration.
//   - cfgFile: explicit configuration file path, or an empty value that selects
//     the default configuration locations.
//
// Returns:
//   - error: non-nil when the configuration cannot be resolved or loaded.
func initConfig(cmd *cobra.Command, cfgFile string) error {
	resolution, err := app.ResolveConfigPath(cfgFile)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}

	runConfig, err := app.LoadRunConfig(resolution, cmd.ErrOrStderr())
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	cmd.SetContext(app.WithRunConfig(cmd.Context(), runConfig))

	return nil
}
