// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newInstanceRemoveCommand creates the instance remove command.
//
// Returns:
//   - *cobra.Command: The remove command.
func newInstanceRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <instance>",
		Short: "Remove an instance configuration and its stored password",
		Long: `Remove an instance configuration and the password it kept in the
operating system credential store. A mounted secret file, an environment
variable, and a password kept in the configuration file belong to the
operator or to another system, so nothing is deleted for them.`,
		Args: cobra.ExactArgs(1),
		RunE: runInstanceRemove,
	}
}

// runInstanceRemove removes an instance configuration and its stored password.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Positional arguments where args[0] is the instance name.
//
// Returns:
//   - error: non-nil when config loading, removal, or saving fails.
func runInstanceRemove(cmd *cobra.Command, args []string) error {
	result, removeErr := app.RemoveInstance(cmd.Context(), app.InstanceRemoveRequest{
		Name: args[0],
	})
	if removeErr != nil {
		outputErr := output.WriteFailedInstanceRemoval(cmd.OutOrStdout(), result)

		return fmt.Errorf("remove instance: %w", errors.Join(removeErr, outputErr))
	}

	err := output.WriteInstanceRemoval(cmd.OutOrStdout(), result)
	if err != nil {
		return fmt.Errorf("remove instance: %w", err)
	}

	return nil
}
