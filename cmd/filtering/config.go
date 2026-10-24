// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newFilteringConfigCommand creates the filtering config command.
//
// Returns:
//   - *cobra.Command: A fresh config command owning its selection flags.
func newFilteringConfigCommand() *cobra.Command {
	values := new(flags.FilteringConfigFlags)

	command := &cobra.Command{
		Use:   "config",
		Short: "Update filtering configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFilteringConfig(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runFilteringConfig updates filtering configuration across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the instances and the configuration.
//
// Returns:
//   - error: An error when a per-instance request or the result output fails.
func runFilteringConfig(cmd *cobra.Command, _ []string, values *flags.FilteringConfigFlags) error {
	results, operationErr := app.NewFilteringManagement(cmd.Context()).UpdateConfig(
		cmd.Context(),
		values.Selection(),
		values.Enabled,
		values.IntervalHours(),
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("update filtering config: %w", err)
	}

	return nil
}
