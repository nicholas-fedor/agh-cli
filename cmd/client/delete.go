// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newClientDeleteCommand creates the delete command and binds its flags.
//
// Returns:
//   - *cobra.Command: The delete command with its own flag values.
func newClientDeleteCommand() *cobra.Command {
	values := &selectionValues{}

	command := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientDelete(cmd, args, values)
		},
	}

	registerClientSelectionFlags(command, values)

	return command
}

// runClientDelete removes a client from one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Client name argument.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection or per-instance request fails.
func runClientDelete(cmd *cobra.Command, args []string, values *selectionValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select client instances: %w", err)
	}

	results, operationErr := app.NewClientManagement().Delete(
		cmd.Context(),
		selection,
		args[0],
	)
	writeClientMutationResults(cmd, results)

	if operationErr != nil {
		return fmt.Errorf("run client delete: %w", operationErr)
	}

	return nil
}
