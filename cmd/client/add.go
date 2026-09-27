// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newClientAddCommand creates the add command and binds its flags.
//
// Returns:
//   - *cobra.Command: The add command with its own flag values.
func newClientAddCommand() *cobra.Command {
	return newClientMutationCommand("Add a client", "add <name>", runClientAdd)
}

// runClientAdd adds a new client configuration to one or more instances.
//
// Parameters:
//   - cmd: Cobra command context and mutation flag access.
//   - args: Client name argument.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when flag parsing or a per-instance request fails.
func runClientAdd(cmd *cobra.Command, args []string, values *selectionValues) error {
	err := runClientMutation(
		cmd,
		args,
		values,
		func(
			management *app.ClientManagement,
			ctx context.Context,
			selection app.ClientSelection,
			request app.ClientMutation,
		) ([]app.ClientMutationResult, error) {
			return management.Add(ctx, selection, request)
		},
	)
	if err != nil {
		return fmt.Errorf("run client add: %w", err)
	}

	return nil
}
