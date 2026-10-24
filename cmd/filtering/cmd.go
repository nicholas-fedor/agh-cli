// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the filtering command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The filtering command.
func NewCommand() *cobra.Command {
	filteringCmd := &cobra.Command{
		Use:   "filtering",
		Short: "Filtering operations",
		Long:  `Manage AdGuard Home filtering configuration, rules, and filter URLs.`,
	}

	// Register subcommands.
	filteringCmd.AddCommand(
		newFilteringStatusCommand(),
		newFilteringConfigCommand(),
		newFilteringAddURLCommand(),
		newFilteringRemoveURLCommand(),
	)

	return filteringCmd
}
