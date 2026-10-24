// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package wildcard

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/flags"
)

// NewCommand creates the rewrite wildcard command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The wildcard command.
func NewCommand() *cobra.Command {
	wildcardCmd := &cobra.Command{
		Use:   "wildcard",
		Short: "Wildcard rewrite rule operations",
		Long: `Add or remove wildcard rewrite entries across one or more
AdGuard Home instances.`,
	}

	// Register subcommands.
	wildcardCmd.AddCommand(newWildcardAddCommand(), newWildcardRemoveCommand())

	return wildcardCmd
}

// newWildcardZoneCommand creates a wildcard zone command, which takes one zone
// and the instance-selection flags.
//
// Parameters:
//   - use: Published invocation syntax of the subcommand.
//   - short: Published one-line description of the subcommand.
//   - run: Run function bound to the flag values of this command.
//
// Returns:
//   - *cobra.Command: The command with its own flag values.
func newWildcardZoneCommand(
	use string,
	short string,
	run func(*cobra.Command, []string, *flags.InstanceSelection) error,
) *cobra.Command {
	values := new(flags.InstanceSelection)

	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}
