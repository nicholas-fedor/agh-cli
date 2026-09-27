// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newInstanceRemoveCommand creates the instance remove command.
//
// Returns:
//   - *cobra.Command: The remove command.
func newInstanceRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an instance configuration",
		Long: `Remove an instance configuration. The stored credential of the ` +
			`instance is kept, so clear it separately with ` +
			`'agh-cli instance credentials clear'.`,
		Args: cobra.ExactArgs(1),
		RunE: runInstanceRemove,
	}
}

// runInstanceRemove removes an instance configuration.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Positional arguments where args[0] is the instance name.
//
// Returns:
//   - error: non-nil when config loading, removal, or saving fails.
func runInstanceRemove(cmd *cobra.Command, args []string) error {
	removeErr := app.RemoveInstance(app.InstanceRemoveRequest{
		ConfigPath: app.ConfigPath(),
		Name:       args[0],
	})
	if removeErr != nil {
		return fmt.Errorf("remove instance: %w", removeErr)
	}

	cmd.Printf("Instance %q removed\n", args[0])

	return nil
}
