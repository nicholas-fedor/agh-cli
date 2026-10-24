// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the rewrite settings command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The settings command.
func NewCommand() *cobra.Command {
	settingsCmd := &cobra.Command{
		Use:   "settings",
		Short: "Rewrite settings operations",
		Long:  `Get or update rewrite settings across one or more AdGuard Home instances.`,
	}

	// Register subcommands.
	settingsCmd.AddCommand(
		newRewriteSettingsGetCommand(),
		newRewriteSettingsUpdateCommand(),
	)

	return settingsCmd
}
