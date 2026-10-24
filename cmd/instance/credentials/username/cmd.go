// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the username command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The username command.
func NewCommand() *cobra.Command {
	usernameCmd := &cobra.Command{
		Use:   "username",
		Short: "Manage the administrator username of an instance",
		Long: `Manage the AdGuard Home administrator username of a configured
instance. The username is configuration rather than a secret, so it is
stored in the configuration file and is independent of the password:
changing the username leaves a stored password untouched, and storing a
password leaves the username untouched.`,
	}

	// Register subcommands.
	usernameCmd.AddCommand(
		newSetCommand(),
		newStatusCommand(),
		newClearCommand(),
	)

	return usernameCmd
}
