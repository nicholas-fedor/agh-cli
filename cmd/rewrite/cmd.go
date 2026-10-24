// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/cmd/rewrite/settings"
	"github.com/nicholas-fedor/agh-cli/cmd/rewrite/wildcard"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
)

// NewCommand creates the rewrite command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The rewrite command.
func NewCommand() *cobra.Command {
	rewriteCmd := &cobra.Command{
		Use:   "rewrite",
		Short: "DNS rewrite rule operations",
		Long: `Create, read, update, and delete DNS rewrite rules on one or more
AdGuard Home instances.`,
	}

	// Register subcommands.
	rewriteCmd.AddCommand(
		newRewriteListCommand(),
		newRewriteAddCommand(),
		newRewriteDeleteCommand(),
		newRewriteUpdateCommand(),
		newRewriteDiffCommand(),
		settings.NewCommand(),
		wildcard.NewCommand(),
	)

	return rewriteCmd
}

// newRewriteRuleCommand creates a rewrite rule command, which takes a domain
// and an answer and the rule state flags.
//
// Parameters:
//   - use: Published invocation syntax of the subcommand.
//   - short: Published one-line description of the subcommand.
//   - run: Run function bound to the flag values of this command.
//
// Returns:
//   - *cobra.Command: The command with its own flag values.
func newRewriteRuleCommand(
	use string,
	short string,
	run func(*cobra.Command, []string, *flags.RewriteRuleFlags) error,
) *cobra.Command {
	values := new(flags.RewriteRuleFlags)

	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}
