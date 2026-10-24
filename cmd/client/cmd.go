// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/flags"
)

// NewCommand creates the client command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The client command.
func NewCommand() *cobra.Command {
	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "Client operations",
		Long:  `Manage AdGuard Home clients including listing, adding, updating, and deleting.`,
	}

	// Register subcommands.
	clientCmd.AddCommand(
		newClientListCommand(),
		newClientAddCommand(),
		newClientDeleteCommand(),
		newClientUpdateCommand(),
	)

	return clientCmd
}

// newClientMutationCommand creates a client mutation command, which takes one
// client name and the client settings flags.
//
// Parameters:
//   - use: Published invocation syntax of the subcommand.
//   - short: Published one-line description of the subcommand.
//   - run: Run function bound to the flag values of this command.
//
// Returns:
//   - *cobra.Command: The command with its own flag values.
func newClientMutationCommand(
	use string,
	short string,
	run func(*cobra.Command, []string, *flags.ClientMutationFlags) error,
) *cobra.Command {
	values := new(flags.ClientMutationFlags)

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
