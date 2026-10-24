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

// newFilteringStatusCommand creates the filtering status command.
//
// Returns:
//   - *cobra.Command: A fresh status command owning its selection flags.
func newFilteringStatusCommand() *cobra.Command {
	values := new(flags.InstanceSelection)

	command := &cobra.Command{
		Use:   "status",
		Short: "Get filtering status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFilteringStatus(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runFilteringStatus retrieves filtering status across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a per-instance request or the status output fails.
func runFilteringStatus(cmd *cobra.Command, _ []string, values *flags.InstanceSelection) error {
	results, operationErr := app.NewFilteringManagement(cmd.Context()).Status(
		cmd.Context(),
		values.Selection(),
	)
	outputErr := output.WriteFilteringStatuses(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("get filtering status: %w", err)
	}

	return nil
}
