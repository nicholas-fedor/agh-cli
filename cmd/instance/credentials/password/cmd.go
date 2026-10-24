// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the password command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The password command.
func NewCommand() *cobra.Command {
	passwordCmd := &cobra.Command{
		Use:   "password",
		Short: "Manage the stored password of an instance",
		Long: `Store, inspect, and remove the AdGuard Home administrator password
of a configured instance in the operating system credential store. The
password is a secret, so it is never an argument and no command prints
it. The username is configuration and is managed separately by 'agh-cli
instance credentials username'.`,
	}

	// Register subcommands.
	passwordCmd.AddCommand(
		newSetCommand(),
		newClearCommand(),
		newStatusCommand(),
	)

	return passwordCmd
}
