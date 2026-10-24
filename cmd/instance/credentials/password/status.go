// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newStatusCommand creates the password status command and binds its flags.
//
// The command reports presence only. There is intentionally no command that
// prints a stored secret, so an operator can inspect an instance safely in a
// shared terminal or a captured log.
//
// Returns:
//   - *cobra.Command: The status command with its own flag values.
func newStatusCommand() *cobra.Command {
	values := new(flags.ReportFlags)

	command := &cobra.Command{
		Use:   "status [instance]",
		Short: "Report stored credential presence",
		Long: `Report the credential store backend, its availability, and the
configured credential source and presence of one instance, or of every
configured instance. A stored secret is never reported.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runStatus reports credential presence for the selected instances.
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
	result, err := app.StatusPassword(cmd.Context(), args)
	if err != nil {
		return fmt.Errorf("report credential status: %w", err)
	}

	if values.JSON {
		err = output.WritePasswordStatusJSON(cmd.OutOrStdout(), result)
	} else {
		err = output.WritePasswordStatusText(cmd.OutOrStdout(), result)
	}

	if err != nil {
		return fmt.Errorf("write credential status: %w", err)
	}

	return nil
}
