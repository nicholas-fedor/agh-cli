// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newRewriteSettingsUpdateCommand creates the update command and binds its flags.
//
// Returns:
//   - *cobra.Command: The update command with its own flag values.
func newRewriteSettingsUpdateCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "update",
		Short: "Update rewrite settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteSettingsUpdate(cmd, args, values)
		},
	}

	command.Flags().BoolVarP(&values.enabled, "enabled", "e", true, "enable rewrites")
	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

	return command
}

// runRewriteSettingsUpdate updates settings across selected instances.
//
// Parameters:
//   - cmd: Cobra command context and settings flag access.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or the mutation
//     output fails.
func runRewriteSettingsUpdate(
	cmd *cobra.Command,
	_ []string,
	values *flagValues,
) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	results, updateErr := app.NewRewriteManagement().UpdateSettings(
		cmd.Context(),
		selection,
		values.enabled,
	)
	outputErr := writeRewriteSettingsMutationResults(cmd, results)

	updateErr = errors.Join(updateErr, outputErr)
	if updateErr != nil {
		return fmt.Errorf("update rewrite settings: %w", updateErr)
	}

	return nil
}

// writeRewriteSettingsMutationResults renders every successful mutation result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered messages.
//   - results: Per-instance mutation results to render.
//
// Returns:
//   - error: Joined errors from every failed message write.
func writeRewriteSettingsMutationResults(
	cmd *cobra.Command,
	results []app.RewriteMutationResult,
) error {
	writer := cmd.OutOrStdout()
	errs := make([]error, 0, len(results))

	for _, result := range results {
		_, err := fmt.Fprintf(writer, "[%s] %s\n", result.Instance, result.Message)
		if err != nil {
			errs = append(errs, fmt.Errorf("write instance %q result: %w", result.Instance, err))
		}
	}

	return errors.Join(errs...)
}
