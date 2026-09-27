// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newFilteringConfigCommand creates the filtering config command.
//
// Returns:
//   - *cobra.Command: A fresh config command owning its selection flags.
func newFilteringConfigCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "config",
		Short: "Update filtering configuration",
		RunE:  runFilteringConfig,
	}

	command.Flags().BoolP("enabled", "e", true, "enable filtering")
	command.Flags().Int32P("interval", "n", 0, "update interval hours")
	registerFilteringSelectionFlags(command)

	return command
}

// runFilteringConfig updates filtering configuration across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//
// Returns:
//   - error: An error when flag parsing or a per-instance request fails.
func runFilteringConfig(cmd *cobra.Command, _ []string) error {
	selection, err := currentFilteringSelection(cmd)
	if err != nil {
		return fmt.Errorf("parse filtering flags: %w", err)
	}

	enabled, interval, err := filteringConfigFromFlags(cmd)
	if err != nil {
		return fmt.Errorf("parse filtering flags: %w", err)
	}

	results, operationErr := app.NewFilteringManagement().UpdateConfig(
		cmd.Context(),
		selection,
		enabled,
		interval,
	)
	outputErr := writeFilteringMutationResults(cmd, results)

	err = errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("update filtering config: %w", err)
	}

	return nil
}

// filteringConfigFromFlags preserves explicit configuration flag values.
//
// Parameters:
//   - cmd: Cobra command providing the filtering configuration flags.
//
// Returns:
//   - bool: The explicit enabled flag value.
//   - int64: The explicit update interval in hours.
//   - error: An error when a flag cannot be retrieved.
func filteringConfigFromFlags(cmd *cobra.Command) (bool, int64, error) {
	enabled, err := cmd.Flags().GetBool("enabled")
	if err != nil {
		return false, 0, fmt.Errorf("parse enabled flag: %w", err)
	}

	interval, err := cmd.Flags().GetInt32("interval")
	if err != nil {
		return false, 0, fmt.Errorf("parse interval flag: %w", err)
	}

	return enabled, int64(interval), nil
}
