// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newClientUpdateCommand creates the update command and binds its flags.
//
// Returns:
//   - *cobra.Command: The update command with its own flag values.
func newClientUpdateCommand() *cobra.Command {
	return newClientMutationCommand("Update a client", "update <name>", runClientUpdate)
}

// runClientUpdate updates an existing client across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context and mutation flag access.
//   - args: Client name argument.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when flag parsing or a per-instance request fails.
func runClientUpdate(cmd *cobra.Command, args []string, values *selectionValues) error {
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
			return management.Update(ctx, selection, request)
		},
	)
	if err != nil {
		return fmt.Errorf("run client update: %w", err)
	}

	return nil
}
