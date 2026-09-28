// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
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

// configFileStem is the configuration file name looked up in every default
// search path.
const configFileStem = "config"

// configFileType is the configuration format of the files found in the default
// search paths.
const configFileType = "yaml"

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

// registerConfigSearchPaths points Viper at the default configuration locations.
//
// The per-user configuration directory is registered before the current
// directory, so a configuration created by the quickstart keeps applying
// regardless of the working directory.
func registerConfigSearchPaths() {
	viper.SetConfigName(configFileStem)
	viper.SetConfigType(configFileType)

	for _, path := range app.ConfigSearchPaths() {
		viper.AddConfigPath(path)
	}
}

// initConfig reads the Viper configuration.
//
// An explicit path is used as given. Otherwise the default search paths are
// registered and an absent file is a warning rather than a failure, because the
// first write creates it.
//
// Parameters:
//   - cfgFile: explicit configuration file path, or an empty value that selects
//     the default configuration locations.
//
// Returns:
//   - error: non-nil when the configuration cannot be read.
func initConfig(cfgFile string) error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		registerConfigSearchPaths()
	}

	err := viper.ReadInConfig()
	if err != nil {
		if configErr, ok := errors.AsType[viper.ConfigFileNotFoundError](err); ok {
			_, writeErr := fmt.Fprintf(os.Stderr, "Warning: could not read config: %v\n", configErr)
			if writeErr != nil {
				return fmt.Errorf("write config warning: %w", writeErr)
			}

			return nil
		}

		return fmt.Errorf("read config: %w", err)
	}

	return nil
}
