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

// newRewriteSettingsGetCommand creates the get command and binds its flags.
//
// Returns:
//   - *cobra.Command: The get command with its own flag values.
func newRewriteSettingsGetCommand() *cobra.Command {
	values := new(flags.InstanceSelection)

	command := &cobra.Command{
		Use:   "get",
		Short: "Get rewrite settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteSettingsGet(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runRewriteSettingsGet retrieves rewrite settings from selected instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or the settings
//     output fails.
func runRewriteSettingsGet(cmd *cobra.Command, _ []string, values *flags.InstanceSelection) error {
	results, getErr := app.NewRewriteManagement(cmd.Context()).GetSettings(
		cmd.Context(),
		values.Selection(),
	)
	outputErr := output.WriteRewriteSettings(cmd.OutOrStdout(), results)

	getErr = errors.Join(getErr, outputErr)
	if getErr != nil {
		return fmt.Errorf("get rewrite settings: %w", getErr)
	}

	return nil
}
