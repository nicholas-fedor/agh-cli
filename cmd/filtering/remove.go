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

// newFilteringRemoveURLCommand creates the remove-url command.
//
// Returns:
//   - *cobra.Command: A fresh remove-url command owning its selection flags.
func newFilteringRemoveURLCommand() *cobra.Command {
	values := new(flags.InstanceSelection)

	command := &cobra.Command{
		Use:   "remove-url <url>",
		Short: "Remove a filter URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFilteringRemoveURL(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runFilteringRemoveURL removes a filter URL from one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Filter URL argument.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a per-instance request or the result output fails.
func runFilteringRemoveURL(cmd *cobra.Command, args []string, values *flags.InstanceSelection) error {
	results, operationErr := app.NewFilteringManagement(cmd.Context()).RemoveURL(
		cmd.Context(),
		values.Selection(),
		args[0],
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("remove filtering URL: %w", err)
	}

	return nil
}
