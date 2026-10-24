// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newStatusCommand creates the username status command.
//
// Returns:
//   - *cobra.Command: The status command.
func newStatusCommand() *cobra.Command {
	values := new(flags.ReportFlags)

	command := &cobra.Command{
		Use:   "status [instance]",
		Short: "Report the administrator username of a configured instance",
		Long: `Report the configured AdGuard Home administrator username. With no
argument every configured instance is reported in configuration order.
A username is configuration rather than a secret, so reporting it is
safe; use 'agh-cli instance credentials password status' for the password
side.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runStatus reports the configured username of the selected instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: an optional instance name.
//   - values: Bound flag values selecting the output format.
//
// Returns:
//   - error: a wrapped error when no configuration is loaded, an instance is
//     unknown, or the report cannot be written.
func runStatus(cmd *cobra.Command, args []string, values *flags.ReportFlags) error {
	report, err := app.StatusUsername(cmd.Context(), args)
	if err != nil {
		return fmt.Errorf("report username status: %w", err)
	}

	if values.JSON {
		err = output.WriteUsernameStatusJSON(cmd.OutOrStdout(), report)
	} else {
		err = output.WriteUsernameStatusText(cmd.OutOrStdout(), report)
	}

	if err != nil {
		return fmt.Errorf("write username status: %w", err)
	}

	return nil
}
