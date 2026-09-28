// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials"
)

// flagValues stores the flag values bound to one instance command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type flagValues struct {
	// all holds the --all flag value.
	all bool
	// scheme holds the --scheme flag value.
	scheme string
}

// NewCommand creates the instance command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The instance command.
func NewCommand() *cobra.Command {
	instanceCmd := &cobra.Command{
		Use:   "instance",
		Short: "Manage configured AdGuard Home instances",
		Long: `List, add, and remove AdGuard Home instance configurations, and
manage the credentials those instances use.`,
	}

	// Register subcommands.
	instanceCmd.AddCommand(
		newInstanceListCommand(),
		newInstanceAddCommand(),
		newInstanceRemoveCommand(),
		credentials.NewCommand(),
	)

	return instanceCmd
}
