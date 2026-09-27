// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newRewriteSettingsGetCommand creates the get command and binds its flags.
//
// Returns:
//   - *cobra.Command: The get command with its own flag values.
func newRewriteSettingsGetCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "get",
		Short: "Get rewrite settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteSettingsGet(cmd, args, values)
		},
	}

	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

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
func runRewriteSettingsGet(cmd *cobra.Command, _ []string, values *flagValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	results, getErr := app.NewRewriteManagement().GetSettings(
		cmd.Context(),
		selection,
	)
	outputErr := writeRewriteSettingsResults(cmd, results)

	getErr = errors.Join(getErr, outputErr)
	if getErr != nil {
		return fmt.Errorf("get rewrite settings: %w", getErr)
	}

	return nil
}

// writeRewriteSettingsResults renders every successful settings result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered settings lines.
//   - results: Per-instance settings results to render.
//
// Returns:
//   - error: Joined errors from every failed settings write.
func writeRewriteSettingsResults(
	cmd *cobra.Command,
	results []app.RewriteSettingsResult,
) error {
	writer := cmd.OutOrStdout()
	errs := make([]error, 0, len(results))

	for _, result := range results {
		_, err := fmt.Fprintf(
			writer,
			"[%s] {\"enabled\":%t}\n",
			result.Instance,
			result.Enabled,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("write instance %q settings: %w", result.Instance, err))
		}
	}

	return errors.Join(errs...)
}
