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

// newFilteringAddURLCommand creates the add-url command.
//
// Returns:
//   - *cobra.Command: A fresh add-url command owning its selection flags.
func newFilteringAddURLCommand() *cobra.Command {
	values := new(flags.FilteringAddURLFlags)

	command := &cobra.Command{
		Use:   "add-url <name> <url>",
		Short: "Add a filter URL",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFilteringAddURL(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runFilteringAddURL adds a filter URL to one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Filter name and URL arguments.
//   - values: Bound flag values selecting the instances and the list kind.
//
// Returns:
//   - error: An error when a per-instance request or the result output fails.
func runFilteringAddURL(cmd *cobra.Command, args []string, values *flags.FilteringAddURLFlags) error {
	results, operationErr := app.NewFilteringManagement(cmd.Context()).AddURL(
		cmd.Context(),
		values.Selection(),
		args[0],
		args[1],
		values.Whitelist,
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("run filtering add-url: %w", err)
	}

	return nil
}
