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

// newClientAddCommand creates the add command and binds its flags.
//
// Returns:
//   - *cobra.Command: The add command with its own flag values.
func newClientAddCommand() *cobra.Command {
	return newClientMutationCommand("add <name>", "Add a client", runClientAdd)
}

// runClientAdd adds a new client configuration across one or more instances.
//
// Parameters:
//   - cmd: Cobra command providing output and context.
//   - args: Client name argument.
//   - values: Bound flag values selecting the instances and client settings.
//
// Returns:
//   - error: An error when a per-instance request or the result output fails.
func runClientAdd(cmd *cobra.Command, args []string, values *flags.ClientMutationFlags) error {
	results, operationErr := app.NewClientManagement(cmd.Context()).Add(
		cmd.Context(),
		values.Selection(),
		values.Settings(args[0]),
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err := errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("run client add: %w", err)
	}

	return nil
}
