// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

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
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return initConfig(cfgFile)
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

// initConfig reads the Viper configuration.
//
// The configuration file is resolved once, here, and the outcome is published so
// that every later read and every write agree on one file. Resolution decides
// between an explicit path and the default search locations, and a blank
// document is treated as no configuration so the first write creates it.
//
// A file that cannot be read is fatal and names the path, because an operator
// must know which file failed. A file that does not exist is a warning, since
// the first write creates it.
//
// Parameters:
//   - cfgFile: explicit configuration file path, or an empty value that selects
//     the default configuration locations.
//
// Returns:
//   - error: non-nil when the configuration cannot be resolved or read.
func initConfig(cfgFile string) error {
	resolution, err := app.ResolveConfigPath(cfgFile)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}

	app.PublishConfigResolution(resolution)

	if !resolution.Exists {
		_, writeErr := fmt.Fprintf(
			os.Stderr,
			"Warning: no configuration file at %s; one will be created on first write\n",
			resolution.Path,
		)
		if writeErr != nil {
			return fmt.Errorf("write config warning: %w", writeErr)
		}

		return nil
	}

	viper.SetConfigFile(resolution.Path)

	err = viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("read config %q: %w", resolution.Path, err)
	}

	return nil
}
