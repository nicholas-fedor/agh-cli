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

// newClientUpdateCommand creates the update command and binds its flags.
//
// Returns:
//   - *cobra.Command: The update command with its own flag values.
func newClientUpdateCommand() *cobra.Command {
	return newClientMutationCommand("update <name>", "Update a client", runClientUpdate)
}

// runClientUpdate updates an existing client across one or more instances.
//
// Parameters:
//   - cmd: Cobra command providing output and context.
//   - args: Client name argument.
//   - values: Bound flag values selecting the instances and client settings.
//
// Returns:
//   - error: An error when a per-instance request or the result output fails.
func runClientUpdate(cmd *cobra.Command, args []string, values *flags.ClientMutationFlags) error {
	results, operationErr := app.NewClientManagement(cmd.Context()).Update(
		cmd.Context(),
		values.Selection(),
		values.Settings(args[0]),
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("run client update: %w", err)
	}

	return nil
}
