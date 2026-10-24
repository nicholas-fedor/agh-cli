// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newClientListCommand creates the list command and binds its flags.
//
// Returns:
//   - *cobra.Command: The list command with its own flag values.
func newClientListCommand() *cobra.Command {
	values := new(flags.InstanceSelection)

	command := &cobra.Command{
		Use:   "list",
		Short: "List clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientList(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runClientList lists clients across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or output operation
//     fails.
func runClientList(cmd *cobra.Command, _ []string, values *flags.InstanceSelection) error {
	results, operationErr := app.NewClientManagement(cmd.Context()).List(cmd.Context(), values.Selection())
	outputErr := output.WriteClientList(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("list clients: %w", err)
	}

	return nil
}
