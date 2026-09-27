// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// flagValues stores the flag values bound to one settings command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type flagValues struct {
	// names holds the --instance flag values.
	names []string
	// all holds the --all flag value.
	all bool
	// enabled holds the --enabled flag value.
	enabled bool
}

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

// selection captures active Cobra and Viper selection state.
//
// Returns:
//   - app.RewriteSelection: The instance selection taken from flags and configuration.
//   - error: An error when the configured instances cannot be read.
func (values *flagValues) selection() (app.RewriteSelection, error) {
	instances, err := app.InstanceSource()
	if err != nil {
		return app.RewriteSelection{}, fmt.Errorf(
			"resolve rewrite settings instance selection: %w",
			err,
		)
	}

	return app.RewriteSelection{
		Instances:  instances,
		Names:      slices.Clone(values.names),
		ConfigPath: viper.ConfigFileUsed(),
		All:        values.all,
	}, nil
}
