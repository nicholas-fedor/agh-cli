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
	"github.com/nicholas-fedor/agh-cli/internal/flags"
)

// newRootCommand creates the root command with fresh subcommands and flags.
//
// The constructor is stored as a function value so that Execute and
// ExecuteContext build a new tree from one shared definition on every call. The
// configuration path is bound to the constructed command, so repeated
// construction never shares flag state between executions.
var newRootCommand = func() *cobra.Command {
	common := new(flags.CommonFlags)

	rootCmd := &cobra.Command{
		Use:   "agh-cli",
		Short: "CLI for managing multiple AdGuard Home instances",
		Long: `A Go CLI that provides CRUD operations for interacting with
multiple AdGuard Home instances simultaneously.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := app.PrepareRun(cmd.Context(), common.Config, cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			cmd.SetContext(ctx)

			return nil
		},
	}

	common.Bind(rootCmd.PersistentFlags())

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
