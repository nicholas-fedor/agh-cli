// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newRewriteSettingsUpdateCommand creates the update command and binds its flags.
//
// Returns:
//   - *cobra.Command: The update command with its own flag values.
func newRewriteSettingsUpdateCommand() *cobra.Command {
	values := new(flags.RewriteSettingsFlags)

	command := &cobra.Command{
		Use:   "update",
		Short: "Update rewrite settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteSettingsUpdate(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runRewriteSettingsUpdate updates settings across selected instances.
//
// Parameters:
//   - cmd: Cobra command providing output and context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or the mutation
//     output fails.
func runRewriteSettingsUpdate(
	cmd *cobra.Command,
	_ []string,
	values *flags.RewriteSettingsFlags,
) error {
	results, updateErr := app.NewRewriteManagement(cmd.Context()).UpdateSettings(
		cmd.Context(),
		values.Selection(),
		values.Enabled,
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	updateErr = errors.Join(updateErr, outputErr)
	if updateErr != nil {
		return fmt.Errorf("update rewrite settings: %w", updateErr)
	}

	return nil
}
